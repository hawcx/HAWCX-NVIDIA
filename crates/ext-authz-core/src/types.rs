//! The middleware ↔ verifier wire contract.
//!
//! **Illustrative transport.** This HTTP/JSON round trip is a dependency-free stand-in for
//! RFC 0009's gRPC `EvaluateHttpRequest` / `HttpRequestResult`. The field *shape* below is
//! what transfers to a real integration, not the HTTP wire format.
//!
//! One round trip per outbound request:
//!
//! ```text
//! middleware ── POST /v1/authorize  AuthorizeRequest  ──▶  verifier (guard service)
//! middleware ◀──    200 OK         AuthorizeResponse  ──   verifier
//! ```
//!
//! Contract rules:
//!
//! * The verifier answers **200** with a JSON `AuthorizeResponse` for every decision,
//!   allow or deny. Non-200 / transport failures are *verifier errors*, handled by the
//!   middleware's fail policy — they are never treated as a verdict.
//! * `decision` is binary. `reason_code` is a stable SCREAMING_SNAKE_CASE string;
//!   verifiers may extend the set, and the middleware treats codes as opaque.
//! * Allow verdicts MUST NOT be cached by the caller: single-use credentials make
//!   every request its own authorization event.
//! * `credentials` carries only the operator-configured forward list (the token
//!   header), never the request body. The body is represented by `body_sha256` /
//!   `canonical_request_hash` only.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Wire-contract version carried in every request.
pub const WIRE_VERSION: &str = "1";

/// What is about to egress — everything the verifier needs to bind a decision to the
/// action, and nothing it doesn't (no raw body, no non-credential headers).
///
/// `deny_unknown_fields`: the descriptor is security-bearing, so a verifier rejects a
/// request carrying fields it does not recognize rather than silently ignoring them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestDescriptor {
    pub method: String,
    pub scheme: String,
    pub authority: String,
    pub path: String,
    #[serde(default)]
    pub query: String,
    /// Lowercase hex SHA-256 of the request body (64 hex chars).
    pub body_sha256: String,
    /// Advisory only: the body length in bytes. NOT part of `crh_v1` and NOT
    /// authorization-bearing — the verifier never sees the body, so a verifier MUST
    /// NOT make decisions on this value. Present for logging/metrics convenience.
    pub body_len: u64,
    /// Lowercase hex `crh_v1` (see [`crate::hash`], 64 hex chars). The verifier MUST
    /// recompute this from the fields above and reject on mismatch (`CRH_MISMATCH`) or
    /// on a malformed descriptor (`DESCRIPTOR_MALFORMED`).
    pub canonical_request_hash: String,
}

/// Who is acting — the proxy-attested execution context.
///
/// The authorization SUBJECT is the durable `agent_id` — it survives sandbox respawn. The
/// `sandbox_id` is the runtime/workload the action executes in: attested context and an
/// optional constraint, but NOT the principal. This is the distinction that lets a grant, a
/// revocation, or an audit trail follow the *agent* rather than a disposable sandbox.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireContext {
    /// The durable agent principal — the authorization subject (survives respawn).
    pub agent_id: String,
    /// The human the agent is acting for (OIDC subject), when applicable — the mandate's
    /// "on behalf of". When the token binds one, the verifier requires it to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    /// The enrolled agent class whose mandate/scope applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_class: Option<String>,
    /// The runtime sandbox/workload the action executes in — attested context and optional
    /// constraint, NOT the authorization principal. Ephemeral: changes on respawn.
    pub sandbox_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_name: Option<String>,
    /// The policy endpoint rule that attached this middleware to the request.
    pub endpoint_rule: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub received_at_unix_ms: i64,
}

/// The middleware → verifier request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeRequest {
    pub version: String,
    pub request: RequestDescriptor,
    pub context: WireContext,
    /// Lowercased header name → value, restricted to the configured forward list
    /// (by default just the per-action token header).
    #[serde(default)]
    pub credentials: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

/// The verifier → middleware verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    pub decision: Decision,
    /// Stable machine-parseable code (see [`reason`]); flows into the audit event.
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Verifier-side audit handle (e.g. a receipt id) for cross-system correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// Opaque structured evidence for the audit sink; never raw sensitive values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<serde_json::Value>,
}

/// Known reason codes. The set is extensible; unknown codes are passed through to the
/// audit sink verbatim.
pub mod reason {
    // Emitted by the middleware itself (no verifier round trip, or verifier failure).
    pub const TOKEN_MISSING: &str = "TOKEN_MISSING";
    /// More than one instance of the token header was present — refused rather than
    /// guessing which one to authorize (duplicate credential headers are a smuggling
    /// primitive).
    pub const TOKEN_AMBIGUOUS: &str = "TOKEN_AMBIGUOUS";
    pub const REQUEST_TOO_LARGE: &str = "REQUEST_TOO_LARGE";
    pub const VERIFIER_UNAVAILABLE: &str = "VERIFIER_UNAVAILABLE";
    pub const VERIFIER_TIMEOUT: &str = "VERIFIER_TIMEOUT";
    pub const VERIFIER_MALFORMED_RESPONSE: &str = "VERIFIER_MALFORMED_RESPONSE";

    // Emitted by a verifier (the demo verifier's set; real verifiers may extend).
    /// The request used a wire-contract version this verifier does not implement.
    pub const UNSUPPORTED_VERSION: &str = "UNSUPPORTED_VERSION";
    /// The canonical allow code. A verifier signals "authorized" with this exact code;
    /// it is not just one verifier's choice of spelling.
    pub const OK: &str = "OK";
    pub const TOKEN_MALFORMED: &str = "TOKEN_MALFORMED";
    pub const TOKEN_SIGNATURE_INVALID: &str = "TOKEN_SIGNATURE_INVALID";
    pub const TOKEN_EXPIRED: &str = "TOKEN_EXPIRED";
    pub const TOKEN_REPLAYED: &str = "TOKEN_REPLAYED";
    /// The token's bound agent principal != the acting agent (or its on-behalf-of human).
    /// The principal check binds the *durable agent*, not the ephemeral sandbox.
    pub const AGENT_MISMATCH: &str = "AGENT_MISMATCH";
    /// The agent principal has been revoked (applies across all of its sandboxes).
    pub const AGENT_REVOKED: &str = "AGENT_REVOKED";
    /// The acting sandbox/workload is outside the token's optional workload selector.
    pub const WORKLOAD_MISMATCH: &str = "WORKLOAD_MISMATCH";
    pub const INTENT_MISMATCH: &str = "INTENT_MISMATCH";
    pub const CRH_MISMATCH: &str = "CRH_MISMATCH";
    /// The descriptor could not be canonicalized at all (e.g. `body_sha256` is not
    /// 32-byte hex, or `canonical_request_hash` is not well-formed). Distinct from
    /// `CRH_MISMATCH`, which is a well-formed hash that simply does not match.
    pub const DESCRIPTOR_MALFORMED: &str = "DESCRIPTOR_MALFORMED";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip() {
        let req = AuthorizeRequest {
            version: WIRE_VERSION.into(),
            request: RequestDescriptor {
                method: "POST".into(),
                scheme: "https".into(),
                authority: "api.github.com".into(),
                path: "/repos/acme/widgets/issues".into(),
                query: "state=open".into(),
                body_sha256: "ab".repeat(32),
                body_len: 17,
                canonical_request_hash: "cd".repeat(32),
            },
            context: WireContext {
                agent_id: "agt-1".into(),
                sandbox_id: "sbx-1".into(),
                endpoint_rule: "github-api".into(),
                received_at_unix_ms: 1_700_000_000_000,
                ..Default::default()
            },
            credentials: [("x-hawcx-haap-token".to_string(), "tok".to_string())].into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: AuthorizeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.request, req.request);

        let resp = AuthorizeResponse {
            decision: Decision::Deny,
            reason_code: reason::TOKEN_REPLAYED.into(),
            message: Some("jti already consumed".into()),
            receipt_id: Some("r-1".into()),
            evidence: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"deny\""));
        let back: AuthorizeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.decision, Decision::Deny);
    }
}
