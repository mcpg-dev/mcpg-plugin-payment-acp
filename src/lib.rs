//! # mcpg-plugin-payment-acp
//!
//! Agentic Commerce Protocol (ACP) plugin for the MCPG gateway.
//!
//! Enables AI agents to complete purchases through merchants implementing
//! the OpenAI/Stripe Agentic Checkout specification. The plugin manages
//! REST-based checkout sessions, handles payment handler negotiation,
//! enforces ACP's idempotency contract, and supports 3D Secure flows.
//!
//! ## How it works
//!
//! 1. First tool call (no session) → POST /checkout_sessions → Challenge
//! 2. Agent returns with session + payment data → POST /complete → Allow
//! 3. Optional: update address/fulfillment, 3DS authentication flows
//!
//! ## _meta keys
//!
//! - `acp/checkout_session` — session ID (client → gateway)
//! - `acp/payment_data` — payment instrument + billing (client → gateway)
//! - `acp/update` — session update data (client → gateway)
//! - `acp/authentication_result` — 3DS result (client → gateway)
//! - `acp/order` — order data (gateway → client)

pub mod checkout;
pub mod handlers;

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use mcpg_plugin_protocol::{
    GateDecision, PluginClass, PluginContext, PluginManifest, ToolGatePlugin, async_trait,
    payment::{PaymentAwarePlugin, PaymentCapability, PaymentCategory, PaymentProtocol},
};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

/// Stable ownership key for a checkout session. An authenticated caller
/// is keyed by subject (+issuer); an anonymous caller falls back to its
/// MCP session id so a different connection cannot address its session.
/// Used to prevent cross-principal checkout IDOR.
fn checkout_owner_key(ctx: &PluginContext) -> String {
    match ctx.identity.subject_id.as_deref() {
        Some(s) if !s.is_empty() => {
            format!("sub:{}|{}", s, ctx.identity.issuer.as_deref().unwrap_or(""))
        }
        _ => format!("sess:{}", ctx.session_id.as_deref().unwrap_or("anon")),
    }
}

use crate::checkout::{AcpCheckoutSession, AcpSessionStatus};

const PLUGIN_ID: &str = "dev.mcpg.payment.acp";

// ---------------------------------------------------------------------------
// Config types (operator-facing)
// ---------------------------------------------------------------------------

/// Top-level ACP protocol configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpProtocolConfig {
    /// Default ACP API version header.
    #[serde(default = "default_api_version")]
    pub default_api_version: String,

    /// Session TTL in seconds. Default: 3600.
    #[serde(default = "default_session_ttl")]
    pub session_ttl_ms: u64,

    /// HTTP timeout in seconds. Default: 30.
    #[serde(default = "default_http_timeout")]
    pub http_timeout_ms: u64,

    /// Maximum retries for 5xx or 409. Default: 3.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Optional signing key env var for JWS request signing.
    #[serde(default)]
    pub signing_key_env: Option<String>,
}

fn default_api_version() -> String {
    "2026-01-30".into()
}
fn default_session_ttl() -> u64 {
    3600
}
fn default_http_timeout() -> u64 {
    30
}
fn default_max_retries() -> u32 {
    3
}

/// Per-tool ACP configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpToolConfig {
    /// Merchant's ACP checkout base URL.
    pub merchant_base_url: String,

    /// Bearer token value for authentication. The operator populates this
    /// from `${env.X}` / `cred://…`, which the gateway substitutes to the
    /// literal token at config load; the plugin reads it directly.
    pub auth_token: String,

    /// ACP API version (overrides default).
    #[serde(default)]
    pub api_version: Option<String>,

    /// Agent capabilities declared to the merchant.
    #[serde(default)]
    pub agent_capabilities: Option<AgentCapabilities>,

    /// Whether to enable delegate payment flow.
    #[serde(default)]
    pub enable_delegate_payment: bool,

    /// Item mapping from tool arguments to ACP line items.
    #[serde(default)]
    pub item_mapping: Option<Value>,
}

/// Agent capabilities for ACP negotiation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCapabilities {
    #[serde(default)]
    pub interventions: InterventionCapabilities,
}

/// Intervention capabilities (3DS, etc).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionCapabilities {
    /// Supported intervention types (e.g., ["3ds"]).
    #[serde(default)]
    pub supported: Vec<String>,

    /// Display context for authentication UI.
    #[serde(default = "default_display_context")]
    pub display_context: String,
}

fn default_display_context() -> String {
    "webview".into()
}

/// Operator config wire layout: `{ "config": ProtocolConfig, "tools": {
/// name: ToolConfig } }`. The derived `Default` (no `config`, no `tools`)
/// is the empty/absent-block fallback used by the fail-closed parser and
/// maps to a DISABLED plugin, matching the historical empty-config
/// behavior.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireConfig {
    #[serde(default)]
    config: Option<AcpProtocolConfig>,
    #[serde(default)]
    tools: BTreeMap<String, AcpToolConfig>,
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

// Payment codes live outside the MCP-reserved JSON-RPC range
// (-32000..-32099) to avoid collision with future spec assignments.

/// JSON-RPC error code for ACP checkout required.
const ACP_CHECKOUT_REQUIRED_CODE: i32 = -33055;
/// JSON-RPC error code for ACP checkout creation failure.
const ACP_CHECKOUT_CREATE_FAILED_CODE: i32 = -33056;
/// JSON-RPC error code for ACP checkout completion failure.
const ACP_CHECKOUT_COMPLETE_FAILED_CODE: i32 = -33057;

/// ACP Commerce Plugin.
///
/// Manages REST-based checkout sessions with ACP-compatible merchants
/// (OpenAI/Stripe ecosystem), including payment handler negotiation,
/// idempotency enforcement, and 3DS authentication flows.
pub struct AcpCommercePlugin {
    manifest: PluginManifest,
    enabled: bool,

    /// Tools configured for ACP commerce.
    tool_configs: BTreeMap<String, AcpToolConfig>,

    /// Active checkout sessions. Key: session_id.
    sessions: DashMap<String, AcpCheckoutSession>,

    /// HTTP client for merchant REST API calls.
    http_client: reqwest::blocking::Client,

    /// Default API version header.
    default_api_version: String,

    /// Session TTL.
    session_ttl: Duration,

    /// Max retries for transient failures.
    _max_retries: u32,
}

impl std::fmt::Debug for AcpCommercePlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcpCommercePlugin")
            .field("enabled", &self.enabled)
            .field("tool_configs", &self.tool_configs)
            .finish()
    }
}

impl AcpCommercePlugin {
    /// Create a disabled (no-op) plugin.
    pub fn disabled() -> Self {
        Self {
            manifest: Self::make_manifest(),
            enabled: false,
            tool_configs: BTreeMap::new(),
            sessions: DashMap::new(),
            http_client: reqwest::blocking::Client::new(),
            default_api_version: default_api_version(),
            session_ttl: Duration::from_secs(3600),
            _max_retries: 3,
        }
    }

    /// Create from protocol config and per-tool configs.
    pub fn from_config(
        config: &AcpProtocolConfig,
        tool_configs: BTreeMap<String, AcpToolConfig>,
    ) -> Result<Self> {
        if tool_configs.is_empty() {
            return Ok(Self::disabled());
        }

        // Validate each tool has required fields
        for (name, cfg) in &tool_configs {
            if cfg.merchant_base_url.is_empty() {
                return Err(anyhow::anyhow!(
                    "ACP: merchant_base_url is required for tool '{}'",
                    name,
                ));
            }
            if cfg.auth_token.is_empty() {
                return Err(anyhow::anyhow!(
                    "ACP: auth_token is required for tool '{}'",
                    name,
                ));
            }
        }

        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(config.http_timeout_ms))
            .build()
            .unwrap_or_default();

        Ok(Self {
            manifest: Self::make_manifest(),
            enabled: true,
            tool_configs,
            sessions: DashMap::new(),
            http_client,
            default_api_version: config.default_api_version.clone(),
            session_ttl: Duration::from_millis(config.session_ttl_ms),
            _max_retries: config.max_retries,
        })
    }

    fn make_manifest() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            name: "Agentic Commerce Protocol (ACP)".into(),
            plugin_class: PluginClass::ToolGate,
            protocol_version: "1.0".into(),
            // ACP merchant API + Stripe payment API are outbound HTTP.
            license: None,
            required_capabilities: Vec::new(), // host-derived from declare_plugin! capabilities (typed)
            tags: Vec::new(),
            provides: Vec::new(),
            provides_schemes: Vec::new(),
            module_path_prefix: ::std::module_path!()
                .split("::")
                .next()
                .unwrap_or("")
                .to_owned(),
            backend_profile: None,
        }
    }

    /// SDK macro factory: parses operator config JSON. Layout:
    /// `{ "config": ProtocolConfig, "tools": { name: ToolConfig } }`.
    ///
    /// Fails CLOSED on a present-but-malformed config block (the factory
    /// panics, which the `declare_plugin!` `make` slot turns into a boot
    /// rejection). An empty / absent block (`""` / `"{}"` / `"null"`)
    /// still yields the disabled default, and a structurally-valid config
    /// that fails the post-parse runtime checks (missing `config`, invalid
    /// merchant fields) still degrades to DISABLED as before.
    pub fn from_config_json(config_json: &str) -> Self {
        let wire: WireConfig = mcpg_plugin_sdk::fail_closed_config!(config_json, WireConfig);
        match wire.config {
            Some(cfg) => Self::from_config(&cfg, wire.tools).unwrap_or_else(|err| {
                tracing::error!(
                    error = %err,
                    "payment-acp: config compile failed; loading as DISABLED"
                );
                Self::disabled()
            }),
            None => {
                tracing::warn!(
                    "payment-acp: config JSON missing top-level `config`; loading as DISABLED"
                );
                Self::disabled()
            }
        }
    }

    /// Get the auth token for a tool, read from its resolved config value.
    fn get_auth_token(&self, tool_config: &AcpToolConfig) -> Result<String> {
        if tool_config.auth_token.is_empty() {
            return Err(anyhow::anyhow!("ACP auth token not set"));
        }
        Ok(tool_config.auth_token.clone())
    }

    /// Get the API version for a tool.
    fn api_version<'a>(&'a self, tool_config: &'a AcpToolConfig) -> &'a str {
        tool_config
            .api_version
            .as_deref()
            .unwrap_or(&self.default_api_version)
    }

    /// Create a checkout session with the merchant.
    fn create_checkout_session(
        &self,
        tool_name: &str,
        tool_config: &AcpToolConfig,
        arguments: &Value,
    ) -> Result<AcpCheckoutSession> {
        let auth_token = self.get_auth_token(tool_config)?;
        let api_version = self.api_version(tool_config);

        // Build request body
        let mut body = serde_json::json!({});

        // Map tool arguments to items if mapping is configured
        if let Some(mapping) = &tool_config.item_mapping {
            body["items"] = mapping.clone();
        } else if let Some(args) = arguments.as_object() {
            // Pass arguments as items context
            if !args.is_empty() {
                body["tool_arguments"] = arguments.clone();
            }
        }

        // Add agent capabilities
        if let Some(caps) = &tool_config.agent_capabilities {
            body["capabilities"] = serde_json::json!({
                "interventions": {
                    "supported": caps.interventions.supported,
                    "display_context": caps.interventions.display_context,
                }
            });
        }

        let idempotency_key = uuid::Uuid::new_v4().to_string();
        let url = format!(
            "{}/checkout_sessions",
            tool_config.merchant_base_url.trim_end_matches('/')
        );

        let response = handlers::call_merchant(
            &self.http_client,
            &url,
            reqwest::Method::POST,
            &body,
            &idempotency_key,
            &auth_token,
            api_version,
        )?;

        match response {
            handlers::MerchantResponse::Success { body, replayed } => {
                if replayed {
                    warn!(
                        tool_name = %tool_name,
                        "ACP create_checkout returned idempotent replay"
                    );
                }

                info!(
                    tool_name = %tool_name,
                    merchant = %tool_config.merchant_base_url,
                    session_id = body.get("id").and_then(|v| v.as_str()).unwrap_or("?"),
                    "ACP checkout session created"
                );

                AcpCheckoutSession::from_response(body, tool_config.merchant_base_url.clone())
                    .ok_or_else(|| anyhow::anyhow!("ACP response missing session ID"))
            }
            handlers::MerchantResponse::RetryAfter(secs) => Err(anyhow::anyhow!(
                "ACP create_checkout returned 409, retry after {}s",
                secs,
            )),
            handlers::MerchantResponse::ClientError { status, body } => {
                let summary = handlers::summarize_acp_error(&body);
                Err(anyhow::anyhow!(
                    "ACP create_checkout returned HTTP {}: {}",
                    status,
                    summary,
                ))
            }
        }
    }

    /// Complete a checkout session.
    fn complete_checkout(
        &self,
        session: &mut AcpCheckoutSession,
        tool_config: &AcpToolConfig,
        payment_data: &Value,
        authentication_result: Option<&Value>,
    ) -> Result<Value> {
        let auth_token = self.get_auth_token(tool_config)?;
        let api_version = self.api_version(tool_config);
        let idempotency_key = session.get_or_create_idempotency_key("complete");

        let mut body = serde_json::json!({
            "payment_data": payment_data,
        });

        if let Some(auth_result) = authentication_result {
            body["authentication_result"] = auth_result.clone();
        }

        let url = format!(
            "{}/checkout_sessions/{}/complete",
            tool_config.merchant_base_url.trim_end_matches('/'),
            session.session_id,
        );

        let response = handlers::call_merchant(
            &self.http_client,
            &url,
            reqwest::Method::POST,
            &body,
            &idempotency_key,
            &auth_token,
            api_version,
        )?;

        match response {
            handlers::MerchantResponse::Success { body, .. } => {
                session.update_from_response(body.clone());

                // Check if 3DS is required
                if session.status == AcpSessionStatus::AuthenticationRequired {
                    return Err(anyhow::anyhow!("3DS_REQUIRED"));
                }

                info!(
                    session_id = %session.session_id,
                    status = ?session.status,
                    "ACP checkout completed"
                );

                Ok(body)
            }
            handlers::MerchantResponse::RetryAfter(secs) => Err(anyhow::anyhow!(
                "ACP complete returned 409, retry after {}s",
                secs,
            )),
            handlers::MerchantResponse::ClientError { status, body } => {
                let summary = handlers::summarize_acp_error(&body);
                Err(anyhow::anyhow!(
                    "ACP complete returned HTTP {}: {}",
                    status,
                    summary,
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SyncToolGate (cdylib path) + async ToolGatePlugin (gateway path-dep)
// ---------------------------------------------------------------------------

impl SyncToolGate for AcpCommercePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn evaluate_pre(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        meta: Option<&Value>,
        config: &Value,
    ) -> GateDecision {
        // Plugin-scoped span so traces from the ACP commerce gate
        // attribute back to dev.mcpg.payment.acp.
        let _span = tracing::info_span!(
            "acp_payment_evaluate_pre",
            plugin_id = PLUGIN_ID,
            tool = %ctx.tool_name,
        )
        .entered();
        let started = std::time::Instant::now();
        let decision = self.evaluate_pre_inner(ctx, arguments, meta, config);
        let outcome = match &decision {
            GateDecision::Allow { .. } => "allow",
            GateDecision::Deny { .. } => "deny",
            GateDecision::Challenge { .. } => "challenge",
            GateDecision::PendingApproval { .. } => "pending_approval",
        };
        metrics::counter!(
            "mcpg_payment_acp_evaluations_total",
            "outcome" => outcome,
        )
        .increment(1);
        metrics::histogram!("mcpg_payment_acp_evaluate_ms")
            .record(started.elapsed().as_millis() as f64);
        decision
    }

    fn evaluate_post(
        &self,
        _ctx: &PluginContext,
        _arguments: &Value,
        _result: &Value,
        _duration_ms: u64,
        _config: &Value,
    ) -> GateDecision {
        GateDecision::allow()
    }
}

impl AcpCommercePlugin {
    fn evaluate_pre_inner(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        meta: Option<&Value>,
        _config: &Value,
    ) -> GateDecision {
        if !self.enabled {
            return GateDecision::allow();
        }
        // Payment gating applies to tool calls only — non-tool surfaces
        // are never charged.
        if ctx.surface != "tool" {
            return GateDecision::allow();
        }

        let tool_config = match self.tool_configs.get(&ctx.tool_name) {
            Some(cfg) => cfg.clone(),
            None => return GateDecision::allow(),
        };

        // Check for existing checkout session reference
        let session_ref = meta
            .and_then(|m| m.get("acp/checkout_session"))
            .and_then(|v| v.as_str());

        match session_ref {
            None => {
                // No session — create one
                match self.create_checkout_session(&ctx.tool_name, &tool_config, arguments) {
                    Ok(mut session) => {
                        // Stamp the creating principal so only they can
                        // address this session later (IDOR guard).
                        session.owner = checkout_owner_key(ctx);
                        let challenge_data = session.build_challenge_data();
                        let session_id = session.session_id.clone();
                        self.sessions.insert(session_id, session);

                        GateDecision::Challenge {
                            http_status: 402,
                            code: ACP_CHECKOUT_REQUIRED_CODE,
                            message: format!("ACP checkout required for tool '{}'", ctx.tool_name,),
                            challenge_data,
                        }
                    }
                    Err(e) => {
                        warn!(
                            tool_name = %ctx.tool_name,
                            error = %e,
                            "ACP checkout session creation failed"
                        );
                        GateDecision::Deny {
                            http_status: 500,
                            code: ACP_CHECKOUT_CREATE_FAILED_CODE,
                            message: format!("ACP checkout creation failed: {}", e),
                            error_data: None,
                        }
                    }
                }
            }
            Some(session_id) => {
                // Session exists
                let mut session_entry = match self.sessions.get_mut(session_id) {
                    Some(entry) => entry,
                    None => {
                        return GateDecision::Deny {
                            http_status: 404,
                            code: ACP_CHECKOUT_COMPLETE_FAILED_CODE,
                            message: format!(
                                "ACP checkout session '{}' not found or expired",
                                session_id,
                            ),
                            error_data: None,
                        };
                    }
                };

                // Ownership check: a different principal must not be
                // able to read or complete someone else's checkout by
                // guessing its session id. Respond as "not found" so the
                // session's existence isn't leaked to a non-owner.
                if session_entry.owner != checkout_owner_key(ctx) {
                    drop(session_entry);
                    warn!(
                        session_id = %session_id,
                        tool_name = %ctx.tool_name,
                        "ACP checkout session access denied: caller is not the owner"
                    );
                    return GateDecision::Deny {
                        http_status: 404,
                        code: ACP_CHECKOUT_COMPLETE_FAILED_CODE,
                        message: format!(
                            "ACP checkout session '{}' not found or expired",
                            session_id,
                        ),
                        error_data: None,
                    };
                }

                // Check expiry
                if session_entry.is_expired(self.session_ttl) {
                    drop(session_entry);
                    self.sessions.remove(session_id);
                    return GateDecision::Deny {
                        http_status: 410,
                        code: ACP_CHECKOUT_COMPLETE_FAILED_CODE,
                        message: format!("ACP checkout session '{}' expired", session_id),
                        error_data: None,
                    };
                }

                // Check for payment data
                let payment_data = meta.and_then(|m| m.get("acp/payment_data"));
                let auth_result = meta.and_then(|m| m.get("acp/authentication_result"));

                match payment_data {
                    Some(pd) => {
                        // Complete checkout
                        match self.complete_checkout(
                            &mut session_entry,
                            &tool_config,
                            pd,
                            auth_result,
                        ) {
                            Ok(_body) => {
                                // SECURITY (payment bypass): a non-error HTTP
                                // response is NOT proof of settlement. Only
                                // grant the tool call once the merchant has
                                // reported the checkout `completed`. Any other
                                // status — not_ready_for_payment / in_progress
                                // / ready_for_payment, or a missing status
                                // (which parses as NotReadyForPayment) — must
                                // re-challenge, never Allow. (3DS is already
                                // handled below via the 3DS_REQUIRED arm.)
                                if !session_entry.is_settled() {
                                    let observed = session_entry.status.clone();
                                    let challenge_data = session_entry.build_challenge_data();
                                    warn!(
                                        session_id = %session_id,
                                        status = ?observed,
                                        "ACP completion did not reach `completed`; withholding Allow"
                                    );
                                    return GateDecision::Challenge {
                                        http_status: 402,
                                        code: ACP_CHECKOUT_REQUIRED_CODE,
                                        message: format!(
                                            "ACP checkout '{}' not settled (status {:?}); \
                                             payment not confirmed",
                                            session_id, observed,
                                        ),
                                        challenge_data,
                                    };
                                }

                                let order_meta = session_entry.build_order_meta();
                                let sid = session_id.to_owned();
                                drop(session_entry);
                                self.sessions.remove(&sid);

                                GateDecision::allow_with_metadata(order_meta)
                            }
                            Err(e) if e.to_string().contains("3DS_REQUIRED") => {
                                // 3DS authentication required
                                let challenge_data = session_entry.build_challenge_data();
                                GateDecision::Challenge {
                                    http_status: 402,
                                    code: ACP_CHECKOUT_REQUIRED_CODE,
                                    message: "3D Secure authentication required".into(),
                                    challenge_data,
                                }
                            }
                            Err(e) => {
                                warn!(
                                    session_id = %session_id,
                                    error = %e,
                                    "ACP checkout completion failed"
                                );
                                let challenge_data = session_entry.build_challenge_data();
                                GateDecision::Challenge {
                                    http_status: 402,
                                    code: ACP_CHECKOUT_REQUIRED_CODE,
                                    message: format!("ACP checkout completion failed: {}", e,),
                                    challenge_data,
                                }
                            }
                        }
                    }
                    None => {
                        // No payment data — check for session update
                        let update_data = meta.and_then(|m| m.get("acp/update"));
                        if update_data.is_some() {
                            // Session updates (address, fulfillment) are not re-applied before re-challenge.
                        }

                        let challenge_data = session_entry.build_challenge_data();
                        GateDecision::Challenge {
                            http_status: 402,
                            code: ACP_CHECKOUT_REQUIRED_CODE,
                            message: format!(
                                "ACP checkout session '{}' awaiting payment",
                                session_id,
                            ),
                            challenge_data,
                        }
                    }
                }
            }
        }
    }
}

#[async_trait]
impl ToolGatePlugin for AcpCommercePlugin {
    fn manifest(&self) -> &PluginManifest {
        SyncToolGate::manifest(self)
    }

    async fn evaluate_pre_dispatch(
        &self,
        ctx: &PluginContext,
        arguments: &Value,
        meta: Option<&Value>,
        config: &Value,
    ) -> GateDecision {
        SyncToolGate::evaluate_pre(self, ctx, arguments, meta, config)
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        tool_gate as gate {
            inner_name: "",
            plugin_type: AcpCommercePlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| AcpCommercePlugin::from_config_json(cfg),
        }
    ],
}

// ---------------------------------------------------------------------------
// PaymentAwarePlugin implementation
// ---------------------------------------------------------------------------

impl PaymentAwarePlugin for AcpCommercePlugin {
    fn payment_capabilities(&self) -> Vec<PaymentCapability> {
        vec![PaymentCapability {
            protocol: PaymentProtocol::Acp,
            methods: vec!["checkout".into()],
            supports_sessions: true,
            supports_commerce: true,
            meta_prefix: "acp/".into(),
        }]
    }

    fn credential_meta_keys(&self) -> Vec<String> {
        vec![
            "acp/checkout_session".into(),
            "acp/payment_data".into(),
            "acp/authentication_result".into(),
        ]
    }

    fn payment_category(&self) -> PaymentCategory {
        PaymentCategory::Commerce
    }

    fn configured_tools(&self) -> Vec<String> {
        self.tool_configs.keys().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::PluginClass;

    fn test_ctx(tool_name: &str) -> PluginContext {
        PluginContext {
            surface: "tool".to_owned(),
            request_id: "req-1".into(),
            session_id: None,
            tool_name: tool_name.into(),
            identity: mcpg_plugin_protocol::PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: std::collections::BTreeMap::new(),
            },
            transport: "http".into(),
        }
    }

    #[test]
    fn empty_config_yields_disabled_default() {
        // Empty / absent config block opts out — yields the disabled
        // default rather than failing closed.
        for blank in ["", "{}", "null", "   "] {
            let plugin = AcpCommercePlugin::from_config_json(blank);
            assert!(
                !plugin.enabled,
                "blank config {blank:?} should yield a disabled plugin"
            );
        }
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn malformed_config_fails_closed() {
        // A present-but-unparseable operator config must refuse the plugin
        // (fail closed), not silently degrade to defaults.
        let _ = AcpCommercePlugin::from_config_json("not json");
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn unknown_top_level_key_fails_closed() {
        // A stray / typo'd key at the wire-config level must be a parse
        // error (deny_unknown_fields) so the fail-closed parser refuses the
        // plugin at boot rather than silently ignoring it. Security-critical
        // payment config: a typo must NOT pass.
        let _ = AcpCommercePlugin::from_config_json(r#"{ "config": {}, "toolz": {} }"#);
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn unknown_protocol_config_key_fails_closed() {
        // A stray / typo'd key inside the nested `config` (AcpProtocolConfig)
        // block must likewise fail closed.
        let _ = AcpCommercePlugin::from_config_json(
            r#"{ "config": { "session_ttl_ms": 1000, "bogus_key": 1 } }"#,
        );
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn unknown_tool_config_key_fails_closed() {
        // A stray / typo'd key inside a per-tool (AcpToolConfig) block must
        // also fail closed.
        let _ = AcpCommercePlugin::from_config_json(
            r#"{ "config": {}, "tools": { "buy": {
                "merchant_base_url": "https://m.example.com",
                "auth_token": "ACP_TOKEN",
                "typo_field": true
            } } }"#,
        );
    }

    #[test]
    fn disabled_plugin_allows() {
        let plugin = AcpCommercePlugin::disabled();
        let decision = plugin.evaluate_pre(
            &test_ctx("any"),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(decision.is_allow());
    }

    #[test]
    fn unconfigured_tool_allows() {
        let config = AcpProtocolConfig {
            default_api_version: "2026-01-30".into(),
            session_ttl_ms: 3600,
            http_timeout_ms: 30,
            max_retries: 3,
            signing_key_env: None,
        };
        let mut tools = BTreeMap::new();
        tools.insert(
            "buy_thing".to_owned(),
            AcpToolConfig {
                merchant_base_url: "https://m.example.com".into(),
                auth_token: "ACP_TOKEN".into(),
                api_version: None,
                agent_capabilities: None,
                enable_delegate_payment: false,
                item_mapping: None,
            },
        );
        let plugin = AcpCommercePlugin::from_config(&config, tools).unwrap();
        let decision = plugin.evaluate_pre(
            &test_ctx("free_tool"),
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(decision.is_allow());
    }

    #[test]
    fn session_not_found_denied() {
        let config = AcpProtocolConfig {
            default_api_version: "2026-01-30".into(),
            session_ttl_ms: 3600,
            http_timeout_ms: 5,
            max_retries: 3,
            signing_key_env: None,
        };
        let mut tools = BTreeMap::new();
        tools.insert(
            "buy_thing".to_owned(),
            AcpToolConfig {
                merchant_base_url: "https://m.example.com".into(),
                auth_token: "ACP_TOKEN".into(),
                api_version: None,
                agent_capabilities: None,
                enable_delegate_payment: false,
                item_mapping: None,
            },
        );
        let plugin = AcpCommercePlugin::from_config(&config, tools).unwrap();

        let meta = serde_json::json!({
            "acp/checkout_session": "nonexistent"
        });
        let decision = plugin.evaluate_pre(
            &test_ctx("buy_thing"),
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        );

        match decision {
            GateDecision::Deny { code, message, .. } => {
                assert_eq!(code, ACP_CHECKOUT_COMPLETE_FAILED_CODE);
                assert!(message.contains("not found"), "got: {message}");
            }
            other => panic!("expected Deny, got: {:?}", other),
        }
    }

    fn test_ctx_with_subject(tool_name: &str, subject: &str) -> PluginContext {
        let mut ctx = test_ctx(tool_name);
        ctx.identity.kind = "verified".into();
        ctx.identity.trust_level = "verified".into();
        ctx.identity.subject_id = Some(subject.into());
        ctx
    }

    fn configured_plugin() -> AcpCommercePlugin {
        let config = AcpProtocolConfig {
            default_api_version: "2026-01-30".into(),
            session_ttl_ms: 3_600_000,
            http_timeout_ms: 5,
            max_retries: 3,
            signing_key_env: None,
        };
        let mut tools = BTreeMap::new();
        tools.insert(
            "buy_thing".to_owned(),
            AcpToolConfig {
                merchant_base_url: "https://m.example.com".into(),
                auth_token: "ACP_TOKEN".into(),
                api_version: None,
                agent_capabilities: None,
                enable_delegate_payment: false,
                item_mapping: None,
            },
        );
        AcpCommercePlugin::from_config(&config, tools).unwrap()
    }

    /// Regression: a checkout session created by one principal
    /// must not be readable or completable by another principal who supplies
    /// the merchant session id. The non-owner gets an opaque "not found"; the
    /// owner passes the ownership gate.
    #[test]
    fn checkout_session_idor_denied_for_non_owner() {
        let plugin = configured_plugin();

        // Alice creates the session (insert directly with her ownership key).
        let alice = test_ctx_with_subject("buy_thing", "alice");
        let mut session = crate::checkout::AcpCheckoutSession::from_response(
            serde_json::json!({ "id": "cs_owned", "status": "ready_for_payment" }),
            "https://m.example.com".into(),
        )
        .unwrap();
        session.owner = checkout_owner_key(&alice);
        plugin.sessions.insert("cs_owned".to_owned(), session);

        let meta = serde_json::json!({ "acp/checkout_session": "cs_owned" });

        // Bob (different principal) is denied as "not found".
        let bob = test_ctx_with_subject("buy_thing", "bob");
        match plugin.evaluate_pre(
            &bob,
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        ) {
            GateDecision::Deny { code, message, .. } => {
                assert_eq!(code, ACP_CHECKOUT_COMPLETE_FAILED_CODE);
                assert!(message.contains("not found"), "got: {message}");
            }
            other => panic!("non-owner must be denied, got: {other:?}"),
        }
        // The session still exists and is untouched (bob's access didn't remove it).
        assert!(plugin.sessions.contains_key("cs_owned"));

        // Alice (owner) passes the ownership gate.
        match plugin.evaluate_pre(
            &alice,
            &serde_json::json!({}),
            Some(&meta),
            &serde_json::json!({}),
        ) {
            GateDecision::Challenge { code, .. } => assert_eq!(code, ACP_CHECKOUT_REQUIRED_CODE),
            other => panic!("owner must pass the ownership gate, got: {other:?}"),
        }
    }

    #[test]
    fn manifest_is_correct() {
        let plugin = AcpCommercePlugin::disabled();
        let m = SyncToolGate::manifest(&plugin);
        assert_eq!(m.id, "dev.mcpg.payment.acp");
        assert_eq!(m.plugin_class, PluginClass::ToolGate);
    }

    #[test]
    fn payment_aware_capabilities() {
        let plugin = AcpCommercePlugin::disabled();
        let caps = plugin.payment_capabilities();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].protocol, PaymentProtocol::Acp);
        assert!(caps[0].supports_sessions);
        assert!(caps[0].supports_commerce);
    }

    #[test]
    fn payment_aware_category() {
        let plugin = AcpCommercePlugin::disabled();
        assert_eq!(plugin.payment_category(), PaymentCategory::Commerce);
    }

    #[test]
    fn empty_tools_creates_disabled() {
        let config = AcpProtocolConfig {
            default_api_version: "2026-01-30".into(),
            session_ttl_ms: 3600,
            http_timeout_ms: 30,
            max_retries: 3,
            signing_key_env: None,
        };
        let plugin = AcpCommercePlugin::from_config(&config, BTreeMap::new()).unwrap();
        assert!(!plugin.enabled);
    }

    #[test]
    fn missing_merchant_url_rejected() {
        let config = AcpProtocolConfig {
            default_api_version: "2026-01-30".into(),
            session_ttl_ms: 3600,
            http_timeout_ms: 30,
            max_retries: 3,
            signing_key_env: None,
        };
        let mut tools = BTreeMap::new();
        tools.insert(
            "bad_tool".to_owned(),
            AcpToolConfig {
                merchant_base_url: "".into(),
                auth_token: "TOKEN".into(),
                api_version: None,
                agent_capabilities: None,
                enable_delegate_payment: false,
                item_mapping: None,
            },
        );
        let err = AcpCommercePlugin::from_config(&config, tools).unwrap_err();
        assert!(err.to_string().contains("merchant_base_url"), "got: {err}");
    }

    #[test]
    fn missing_auth_token_rejected() {
        let config = AcpProtocolConfig {
            default_api_version: "2026-01-30".into(),
            session_ttl_ms: 3600,
            http_timeout_ms: 30,
            max_retries: 3,
            signing_key_env: None,
        };
        let mut tools = BTreeMap::new();
        tools.insert(
            "bad_tool".to_owned(),
            AcpToolConfig {
                merchant_base_url: "https://m.example.com".into(),
                auth_token: "".into(),
                api_version: None,
                agent_capabilities: None,
                enable_delegate_payment: false,
                item_mapping: None,
            },
        );
        let err = AcpCommercePlugin::from_config(&config, tools).unwrap_err();
        assert!(err.to_string().contains("auth_token"), "got: {err}");
    }

    /// Error codes must not collide with the MCP-reserved JSON-RPC range.
    #[test]
    fn acp_codes_outside_mcp_reserved_range() {
        for code in [
            ACP_CHECKOUT_REQUIRED_CODE,
            ACP_CHECKOUT_CREATE_FAILED_CODE,
            ACP_CHECKOUT_COMPLETE_FAILED_CODE,
        ] {
            assert!(
                !(-32099..=-32000).contains(&code),
                "ACP error code {} collides with MCP reserved range [-32099, -32000]",
                code
            );
        }
    }
}
