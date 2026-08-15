//! Merchant HTTP request handling for ACP plugin.
//!
//! Encapsulates the HTTP communication with ACP merchants including
//! idempotency key management and response parsing.

use anyhow::{Context, Result};
use serde_json::Value;

/// Response from an ACP merchant API call.
#[derive(Debug)]
pub enum MerchantResponse {
    /// Successful response (200 or 201).
    Success {
        body: Value,
        /// Whether this was an idempotent replay.
        replayed: bool,
    },
    /// Merchant returned 409 — request in flight, retry after delay.
    RetryAfter(u64),
    /// Client error (4xx).
    ClientError { status: u16, body: Value },
}

/// Call an ACP merchant endpoint.
///
/// Handles standard ACP HTTP conventions: Authorization, API-Version,
/// Idempotency-Key, Content-Type, and response parsing.
pub fn call_merchant(
    http_client: &reqwest::blocking::Client,
    url: &str,
    method: reqwest::Method,
    body: &Value,
    idempotency_key: &str,
    auth_token: &str,
    api_version: &str,
) -> Result<MerchantResponse> {
    let response = http_client
        .request(method, url)
        .header("Authorization", format!("Bearer {}", auth_token))
        .header("API-Version", api_version)
        .header("Idempotency-Key", idempotency_key)
        .header("Content-Type", "application/json")
        .json(body)
        .send()
        .context("ACP merchant request failed")?;

    mcpg_plugin_protocol::security::check_response_remote_addr(response.remote_addr(), false)
        .map_err(|e| anyhow::anyhow!("ACP merchant SSRF blocked: {e}"))?;

    let status = response.status().as_u16();

    match status {
        200 | 201 => {
            let replayed = response
                .headers()
                .get("Idempotent-Replayed")
                .and_then(|v| v.to_str().ok())
                .map(|v| v == "true")
                .unwrap_or(false);
            let body: Value = response
                .json()
                .context("ACP merchant response parse error")?;
            Ok(MerchantResponse::Success { body, replayed })
        }
        409 => {
            let retry_after = response
                .headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(1);
            Ok(MerchantResponse::RetryAfter(retry_after))
        }
        422 => {
            let body: Value = response.json().unwrap_or(Value::Null);
            let code = body.get("code").and_then(|c| c.as_str()).unwrap_or("");
            if code == "idempotency_conflict" {
                Err(anyhow::anyhow!(
                    "idempotency conflict: key reused with different body"
                ))
            } else {
                Ok(MerchantResponse::ClientError { status, body })
            }
        }
        400..=499 => {
            let body: Value = response.json().unwrap_or(Value::Null);
            Ok(MerchantResponse::ClientError { status, body })
        }
        500..=599 => Err(anyhow::anyhow!(
            "ACP merchant server error: HTTP {}",
            status
        )),
        _ => Err(anyhow::anyhow!("ACP unexpected HTTP status: {}", status)),
    }
}

/// Map ACP error messages to a human-readable summary.
pub fn summarize_acp_error(body: &Value) -> String {
    let error_type = body
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown");
    let code = body
        .get("code")
        .and_then(|c| c.as_str())
        .unwrap_or("unknown");
    let message = body
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("no details");
    let param = body.get("param").and_then(|p| p.as_str());

    match param {
        Some(p) => format!("{}/{}: {} (field: {})", error_type, code, message, p),
        None => format!("{}/{}: {}", error_type, code, message),
    }
}

/// Check whether an ACP error indicates a recoverable/retryable condition.
pub fn is_recoverable_error(body: &Value) -> bool {
    let code = body.get("code").and_then(|c| c.as_str()).unwrap_or("");

    matches!(
        code,
        "out_of_stock" | "payment_declined" | "requires_sign_in" | "requires_3ds" | "missing"
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_error_with_param() {
        let body = serde_json::json!({
            "type": "invalid_request",
            "code": "invalid",
            "message": "quantity must be positive",
            "param": "$.line_items[0].quantity"
        });
        let summary = summarize_acp_error(&body);
        assert!(summary.contains("invalid_request"));
        assert!(summary.contains("quantity must be positive"));
        assert!(summary.contains("$.line_items[0].quantity"));
    }

    #[test]
    fn summarize_error_without_param() {
        let body = serde_json::json!({
            "type": "invalid_request",
            "code": "missing",
            "message": "payment data is required"
        });
        let summary = summarize_acp_error(&body);
        assert!(!summary.contains("field:"));
    }

    #[test]
    fn recoverable_errors() {
        assert!(is_recoverable_error(
            &serde_json::json!({"code": "out_of_stock"})
        ));
        assert!(is_recoverable_error(
            &serde_json::json!({"code": "payment_declined"})
        ));
        assert!(is_recoverable_error(
            &serde_json::json!({"code": "requires_3ds"})
        ));
        assert!(!is_recoverable_error(
            &serde_json::json!({"code": "invalid"})
        ));
        assert!(!is_recoverable_error(
            &serde_json::json!({"code": "idempotency_conflict"})
        ));
    }
}
