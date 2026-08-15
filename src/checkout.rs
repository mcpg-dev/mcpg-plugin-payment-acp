//! Checkout session management for ACP commerce plugin.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Checkout session state
// ---------------------------------------------------------------------------

/// Status of an ACP checkout session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcpSessionStatus {
    /// Session not ready for payment yet.
    NotReadyForPayment,
    /// Session ready for payment submission.
    ReadyForPayment,
    /// 3DS or other authentication is required.
    AuthenticationRequired,
    /// Payment in progress.
    InProgress,
    /// Session completed.
    Completed,
    /// Session canceled.
    Canceled,
}

/// An active ACP checkout session.
#[derive(Debug)]
pub struct AcpCheckoutSession {
    /// Merchant-assigned session ID.
    pub session_id: String,
    /// Ownership key of the principal that created this session. Only
    /// that principal may address it later (IDOR guard). Set by the
    /// gate after construction; empty until then.
    pub owner: String,
    /// Current session status.
    pub status: AcpSessionStatus,
    /// Merchant base URL.
    pub merchant_base_url: String,
    /// Full session response (last known state).
    pub last_response: Value,
    /// Available payment handlers.
    pub payment_handlers: Vec<AcpPaymentHandler>,
    /// 3DS authentication metadata (if required).
    pub authentication_metadata: Option<Value>,
    /// Session creation time.
    pub created_at: std::time::Instant,
    /// Idempotency keys used for this session.
    pub idempotency_keys: HashMap<String, String>,
}

/// A payment handler from the merchant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcpPaymentHandler {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub requires_delegate_payment: bool,
    #[serde(default)]
    pub requires_pci_compliance: bool,
    #[serde(default)]
    pub psp: String,
    #[serde(default)]
    pub config: Value,
    #[serde(default)]
    pub instrument_schemas: Vec<String>,
    #[serde(default)]
    pub display_order: Option<i32>,
}

impl AcpCheckoutSession {
    /// Create from a merchant response.
    pub fn from_response(response: Value, merchant_base_url: String) -> Option<Self> {
        let session_id = response.get("id").and_then(|v| v.as_str())?.to_owned();

        let status = response
            .get("status")
            .and_then(|v| v.as_str())
            .map(parse_status)
            .unwrap_or(AcpSessionStatus::NotReadyForPayment);

        let payment_handlers = extract_payment_handlers(&response);

        Some(Self {
            session_id,
            owner: String::new(),
            status,
            merchant_base_url,
            last_response: response,
            payment_handlers,
            authentication_metadata: None,
            created_at: std::time::Instant::now(),
            idempotency_keys: HashMap::new(),
        })
    }

    /// Update with a new response.
    pub fn update_from_response(&mut self, response: Value) {
        if let Some(status_str) = response.get("status").and_then(|v| v.as_str()) {
            self.status = parse_status(status_str);
        }
        if let Some(auth) = response.get("authentication_metadata") {
            self.authentication_metadata = Some(auth.clone());
        }
        self.payment_handlers = extract_payment_handlers(&response);
        self.last_response = response;
    }

    /// Check if the session has expired.
    pub fn is_expired(&self, ttl: std::time::Duration) -> bool {
        self.created_at.elapsed() >= ttl
    }

    /// Has the merchant reported this checkout as settled (paid)?
    ///
    /// This is the security gate for granting the tool call: only a
    /// `Completed` status counts. Every other status — including a
    /// missing status, which parses as `NotReadyForPayment` — means
    /// payment is NOT confirmed and the call must be re-challenged,
    /// never allowed.
    pub fn is_settled(&self) -> bool {
        self.status == AcpSessionStatus::Completed
    }

    /// Get or create an idempotency key for an operation.
    pub fn get_or_create_idempotency_key(&mut self, operation: &str) -> String {
        self.idempotency_keys
            .entry(operation.to_owned())
            .or_insert_with(|| uuid::Uuid::new_v4().to_string())
            .clone()
    }

    /// Build challenge data to return to the client.
    pub fn build_challenge_data(&self) -> Value {
        let mut data = serde_json::json!({
            "protocol": "acp",
            "httpStatus": 402,
            "checkout_session": self.last_response,
        });

        if !self.payment_handlers.is_empty() {
            data["available_handlers"] =
                serde_json::to_value(&self.payment_handlers).unwrap_or(Value::Array(vec![]));
        }

        if self.status == AcpSessionStatus::AuthenticationRequired {
            data["authentication_required"] = Value::Bool(true);
            if let Some(auth) = &self.authentication_metadata {
                data["authentication_metadata"] = auth.clone();
            }
        }

        data
    }

    /// Build order metadata for a completed session.
    ///
    /// Emits only the merchant's real `order` object. It must NOT
    /// fabricate a synthetic `{status:"completed"}` receipt — a receipt
    /// has to reflect the merchant's actual settlement, not a
    /// gateway-invented success. The gate only calls this after it has
    /// confirmed `status == Completed`, so a missing `order` here means a
    /// malformed merchant completion; emit a bare session reference (no
    /// invented status field) rather than claim a settlement we can't see.
    pub fn build_order_meta(&self) -> Value {
        let order = self
            .last_response
            .get("order")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({ "checkout_session_id": self.session_id }));

        serde_json::json!({
            "acp/order": order
        })
    }
}

/// Extract payment handlers from a merchant response.
fn extract_payment_handlers(response: &Value) -> Vec<AcpPaymentHandler> {
    response
        .pointer("/capabilities/payment/handlers")
        .and_then(|h| h.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|h| serde_json::from_value(h.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Parse an ACP status string.
fn parse_status(s: &str) -> AcpSessionStatus {
    match s {
        "not_ready_for_payment" => AcpSessionStatus::NotReadyForPayment,
        "ready_for_payment" => AcpSessionStatus::ReadyForPayment,
        "authentication_required" => AcpSessionStatus::AuthenticationRequired,
        "in_progress" => AcpSessionStatus::InProgress,
        "completed" => AcpSessionStatus::Completed,
        "canceled" | "cancelled" => AcpSessionStatus::Canceled,
        _ => AcpSessionStatus::NotReadyForPayment,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_from_response() {
        let response = serde_json::json!({
            "id": "cs_abc123",
            "status": "ready_for_payment",
            "line_items": [{ "name": "Widget", "total": 2999 }],
            "totals": [{ "type": "total", "amount": 3249 }],
            "capabilities": {
                "payment": {
                    "handlers": [{
                        "id": "stripe_card",
                        "name": "dev.acp.tokenized.card",
                        "psp": "stripe",
                        "config": { "publishable_key": "pk_test_xxx" }
                    }]
                }
            }
        });

        let session = AcpCheckoutSession::from_response(
            response,
            "https://merchant.example.com/agentic_commerce".into(),
        )
        .unwrap();

        assert_eq!(session.session_id, "cs_abc123");
        assert_eq!(session.status, AcpSessionStatus::ReadyForPayment);
        assert_eq!(session.payment_handlers.len(), 1);
        assert_eq!(session.payment_handlers[0].psp, "stripe");
    }

    #[test]
    fn session_update() {
        let mut session = AcpCheckoutSession::from_response(
            serde_json::json!({
                "id": "cs_1",
                "status": "not_ready_for_payment"
            }),
            "https://m.example.com".into(),
        )
        .unwrap();

        session.update_from_response(serde_json::json!({
            "id": "cs_1",
            "status": "ready_for_payment",
            "capabilities": {
                "payment": {
                    "handlers": [{
                        "id": "gpay",
                        "name": "com.google.pay",
                        "psp": "google"
                    }]
                }
            }
        }));

        assert_eq!(session.status, AcpSessionStatus::ReadyForPayment);
        assert_eq!(session.payment_handlers.len(), 1);
    }

    #[test]
    fn authentication_required_challenge() {
        let mut session = AcpCheckoutSession::from_response(
            serde_json::json!({
                "id": "cs_1",
                "status": "authentication_required"
            }),
            "https://m.example.com".into(),
        )
        .unwrap();

        session.authentication_metadata = Some(serde_json::json!({
            "directory_server": "visa"
        }));

        let data = session.build_challenge_data();
        assert_eq!(data["authentication_required"], true);
        assert_eq!(data["authentication_metadata"]["directory_server"], "visa");
    }

    #[test]
    fn order_meta() {
        let mut session = AcpCheckoutSession::from_response(
            serde_json::json!({
                "id": "cs_1",
                "status": "completed",
                "order": {
                    "id": "order_xyz",
                    "permalink_url": "https://m.example.com/orders/xyz"
                }
            }),
            "https://m.example.com".into(),
        )
        .unwrap();
        session.status = AcpSessionStatus::Completed;

        let meta = session.build_order_meta();
        assert_eq!(meta["acp/order"]["id"], "order_xyz");
    }

    #[test]
    fn idempotency_keys() {
        let mut session = AcpCheckoutSession::from_response(
            serde_json::json!({ "id": "cs_1", "status": "ready_for_payment" }),
            "https://m.example.com".into(),
        )
        .unwrap();

        let key1 = session.get_or_create_idempotency_key("complete");
        let key2 = session.get_or_create_idempotency_key("complete");
        assert_eq!(key1, key2, "same operation should reuse key");

        let key3 = session.get_or_create_idempotency_key("update");
        assert_ne!(
            key1, key3,
            "different operations should have different keys"
        );
    }

    #[test]
    fn parse_all_statuses() {
        assert_eq!(
            parse_status("not_ready_for_payment"),
            AcpSessionStatus::NotReadyForPayment
        );
        assert_eq!(
            parse_status("ready_for_payment"),
            AcpSessionStatus::ReadyForPayment
        );
        assert_eq!(
            parse_status("authentication_required"),
            AcpSessionStatus::AuthenticationRequired
        );
        assert_eq!(parse_status("in_progress"), AcpSessionStatus::InProgress);
        assert_eq!(parse_status("completed"), AcpSessionStatus::Completed);
        assert_eq!(parse_status("canceled"), AcpSessionStatus::Canceled);
        assert_eq!(parse_status("cancelled"), AcpSessionStatus::Canceled);
        assert_eq!(
            parse_status("unknown"),
            AcpSessionStatus::NotReadyForPayment
        );
    }

    #[test]
    fn session_expiry() {
        let session = AcpCheckoutSession::from_response(
            serde_json::json!({ "id": "cs_1", "status": "ready_for_payment" }),
            "https://m.example.com".into(),
        )
        .unwrap();
        assert!(!session.is_expired(std::time::Duration::from_secs(3600)));
        assert!(session.is_expired(std::time::Duration::from_millis(0)));
    }

    fn mk(status_json: Value) -> AcpCheckoutSession {
        AcpCheckoutSession::from_response(status_json, "https://m.example.com".into()).unwrap()
    }

    // SECURITY (payment bypass): the completion gate grants the tool call
    // only when the merchant reports `completed`. A non-error HTTP response
    // with any other status — or no status — is NOT proof of payment.
    #[test]
    fn only_completed_is_settled() {
        for s in [
            "not_ready_for_payment",
            "ready_for_payment",
            "authentication_required",
            "in_progress",
            "canceled",
        ] {
            let sess = mk(serde_json::json!({ "id": "cs", "status": s }));
            assert!(!sess.is_settled(), "status {s:?} must NOT be settled");
        }
        // Missing status parses as NotReadyForPayment → not settled.
        let no_status = mk(serde_json::json!({ "id": "cs" }));
        assert!(
            !no_status.is_settled(),
            "missing status must NOT be settled"
        );
        let done = mk(serde_json::json!({ "id": "cs", "status": "completed" }));
        assert!(done.is_settled());
    }

    // A non-error completion response that omits `order` must NOT be turned
    // into a fabricated `{status:"completed"}` receipt.
    #[test]
    fn order_meta_does_not_fabricate_completed_status() {
        let sess = mk(serde_json::json!({ "id": "cs_77", "status": "completed" }));
        let meta = sess.build_order_meta();
        let order = &meta["acp/order"];
        assert_eq!(order["checkout_session_id"], "cs_77");
        assert!(
            order.get("status").is_none(),
            "build_order_meta must not invent a status field: {order}"
        );
    }
}
