//! Operator-facing middleware configuration.
//!
//! Maps onto the `middleware_configs` policy block proposed in NVIDIA/OpenShell#1694
//! (see `policy-example.yaml` at the workspace root). Two orthogonal knobs govern
//! degraded behavior:
//!
//! * `mode`: `enforce` (verdicts block) vs `observe` (never block; log the would-be
//!   verdict — rollout/canary mode).
//! * `fail`: `closed` (verifier unreachable ⇒ deny; the #1733 secure default) vs
//!   `open` (verifier unreachable ⇒ pass, audited as degraded).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Enforce,
    Observe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailPolicy {
    Closed,
    Open,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtAuthzConfig {
    /// The verifier's authorize endpoint, e.g. `http://127.0.0.1:18443/v1/authorize`.
    ///
    /// The per-action credential crosses this link, and the verifier dispenses ALLOW
    /// verdicts, so in production this MUST be a mutually-authenticated, confidential
    /// channel — a unix-domain socket with restrictive filesystem permissions, or mTLS.
    /// A plaintext `http://` endpoint on a non-loopback host exposes every credential
    /// in flight and lets anything that can occupy the address forge ALLOWs;
    /// [`crate::ExtAuthzConfig`] consumers should reject or loudly warn on that shape
    /// (the example middleware warns at construction).
    pub verifier_url: String,
    #[serde(default = "d_mode")]
    pub mode: Mode,
    #[serde(default = "d_fail")]
    pub fail: FailPolicy,
    /// End-to-end budget for the verifier round trip (connect + request + response).
    #[serde(default = "d_timeout_ms")]
    pub timeout_ms: u64,
    /// Request header carrying the per-action credential. Matched case-insensitively.
    #[serde(default = "d_token_header")]
    pub token_header: String,
    /// Additional request headers (lowercase) forwarded to the verifier, e.g.
    /// `x-request-id` for correlation. The token header is always forwarded.
    #[serde(default)]
    pub forward_headers: Vec<String>,
    /// Strip the token header before the request egresses upstream (the credential is
    /// for the verifier, not the destination). Default: true. Setting this `false`
    /// leaks the per-action credential to the destination API — only do so when the
    /// upstream is the credential's intended audience.
    #[serde(default = "d_true")]
    pub strip_token_header: bool,
    /// Maximum body size the middleware will buffer to hash. Larger requests are
    /// denied with `REQUEST_TOO_LARGE` (intent binding requires the body hash).
    #[serde(default = "d_max_body")]
    pub max_body_bytes: usize,
}

fn d_mode() -> Mode {
    Mode::Enforce
}
fn d_fail() -> FailPolicy {
    FailPolicy::Closed
}
fn d_timeout_ms() -> u64 {
    100
}
/// Default header carrying the per-action credential. Single source of truth so the
/// middleware and a reference verifier agree on the name.
pub const DEFAULT_TOKEN_HEADER: &str = "x-hawcx-haap-token";

fn d_token_header() -> String {
    DEFAULT_TOKEN_HEADER.to_string()
}
fn d_true() -> bool {
    true
}
fn d_max_body() -> usize {
    1024 * 1024
}

impl ExtAuthzConfig {
    /// Lowercase the header names once, at load time.
    pub fn normalized(mut self) -> Self {
        self.token_header = self.token_header.to_ascii_lowercase();
        for h in &mut self.forward_headers {
            *h = h.to_ascii_lowercase();
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_enforce_fail_closed() {
        let cfg: ExtAuthzConfig =
            serde_json::from_str(r#"{ "verifier_url": "http://127.0.0.1:18443/v1/authorize" }"#)
                .unwrap();
        assert_eq!(cfg.mode, Mode::Enforce);
        assert_eq!(cfg.fail, FailPolicy::Closed);
        assert_eq!(cfg.timeout_ms, 100);
        assert_eq!(cfg.token_header, "x-hawcx-haap-token");
        assert!(cfg.strip_token_header);
        assert_eq!(cfg.max_body_bytes, 1024 * 1024);
    }

    #[test]
    fn normalized_lowercases_headers() {
        let cfg = ExtAuthzConfig {
            verifier_url: "http://x/".into(),
            mode: Mode::Enforce,
            fail: FailPolicy::Closed,
            timeout_ms: 100,
            token_header: "X-Hawcx-HAAP-Token".into(),
            forward_headers: vec!["X-Request-ID".into()],
            strip_token_header: true,
            max_body_bytes: 10,
        }
        .normalized();
        assert_eq!(cfg.token_header, "x-hawcx-haap-token");
        assert_eq!(cfg.forward_headers, vec!["x-request-id"]);
    }
}
