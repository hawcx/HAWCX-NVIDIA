//! ext-authz-middleware — an external-authorization ("ext-authz") egress middleware for
//! OpenShell sandboxes, written against the v1 egress hook stage proposed in
//! NVIDIA/OpenShell#1733: **after network/L7 policy, before credential injection and
//! upstream forwarding**.
//!
//! What it does, per outbound request:
//!
//! 1. extracts the per-action credential from a configured request header
//!    (token-opaque: this crate never parses or validates the token itself);
//! 2. computes the canonical request hash (`crh_v1`) over the request **as it will
//!    egress** — which is why this middleware must be ordered *after* any
//!    content-mutating middleware (e.g. Privacy Guard) and *before* credential
//!    injection;
//! 3. sends one `AuthorizeRequest` to the configured out-of-process verifier
//!    ("guard service") with a strict timeout;
//! 4. enforces the verdict — `allow` continues (stripping the token header so the
//!    credential never reaches the upstream API), `deny` blocks the request with a
//!    structured reason; verifier failure follows the configured fail policy
//!    (fail-closed by default);
//! 5. emits a structured audit event — decision, reason code, receipt id, the request
//!    digest — never the token value, never raw body bytes.
//!
//! ### Mapping to the proposed OpenShell interfaces
//!
//! NVIDIA/OpenShell#1694 sketches `L7Middleware::process_request(ctx, req, headers,
//! client) -> MiddlewareAction{Forward|Passthrough}`. This crate keeps the same
//! request-scoped, async, one-shot shape but adds the variant an authorizer (and
//! Privacy Guard's `block`) needs: [`Decision::Deny`] with a structured verdict. In a
//! #1694-shaped host, `Continue` maps to `Passthrough`/`Forward` (with the token
//! header removed) and `Deny` is the missing enforcement variant; buffering the body
//! from the stream to hash it mirrors what the sigv4 signed-body path (PR #1638)
//! already does.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ext_authz_core::types::{
    reason, AuthorizeRequest, AuthorizeResponse, RequestDescriptor, WireContext, WIRE_VERSION,
};
use ext_authz_core::{
    canonical_request_hash, sha256_bytes, CanonicalRequestParts, Decision as WireDecision,
    ExtAuthzConfig, FailPolicy, Mode,
};
use serde::Serialize;

/// Proxy-attested execution context for one request.
#[derive(Debug, Clone, Copy)]
pub struct RequestContext<'a> {
    /// The durable agent principal the gateway attests — the authorization subject.
    /// Survives sandbox respawn; this is what the verdict binds to.
    pub agent_id: &'a str,
    /// The human the agent acts for (OIDC subject), when applicable.
    pub on_behalf_of: Option<&'a str>,
    /// The enrolled agent class whose mandate/scope applies.
    pub agent_class: Option<&'a str>,
    /// The runtime sandbox/workload — attested execution context, NOT the principal.
    pub sandbox_id: &'a str,
    pub sandbox_name: Option<&'a str>,
    /// The policy endpoint rule that attached this middleware.
    pub endpoint_rule: &'a str,
    pub policy_revision: Option<&'a str>,
    pub request_id: Option<&'a str>,
}

/// The outbound request at the egress hook, post-mutation, pre-credential-injection.
#[derive(Debug, Clone, Copy)]
pub struct EgressRequest<'a> {
    pub method: &'a str,
    pub scheme: &'a str,
    /// `host[:port]` exactly as it will be dialed.
    pub authority: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    /// Header name (any case) → value. Values are assumed UTF-8 for this example.
    pub headers: &'a [(String, String)],
    /// The buffered request body (see `max_body_bytes`).
    pub body: &'a [u8],
}

/// A structured denial — the enforcement variant the merged #1733/#1694 action type
/// needs (`MiddlewareAction` in #1694 is `Forward`/`Passthrough` only).
#[derive(Debug, Clone, Serialize)]
pub struct DenyVerdict {
    /// Suggested status for the synthesized response to the sandbox:
    /// 403 for authorization denials, 503 for fail-closed infrastructure denials.
    pub http_status: u16,
    pub reason_code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    pub evidence: serde_json::Value,
}

/// The middleware's decision for one request.
#[derive(Debug, Clone)]
pub enum Decision {
    /// Let the request continue to the next stage (credential injection), after
    /// removing `strip_headers` (lowercase names) from it. The host MUST remove *every*
    /// instance of each name, matched case-insensitively, before the request egresses —
    /// a surviving duplicate would leak the per-action credential upstream.
    Continue { strip_headers: Vec<String> },
    /// Block the request; the proxy should synthesize an error response to the
    /// sandbox and MUST NOT forward upstream.
    Deny(DenyVerdict),
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Continue { .. })
    }
}

/// One structured audit line per request. Contains digests and codes — never the
/// credential value, never raw body bytes (#1733: "audit evidence ... without storing
/// raw sensitive values").
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub ts_unix_ms: i64,
    pub middleware: &'static str,
    /// The durable agent principal (the authorization subject).
    pub agent_id: String,
    /// The runtime sandbox/workload where it executed — context, not the subject.
    pub sandbox_id: String,
    pub endpoint_rule: String,
    pub method: String,
    pub authority: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_request_hash: Option<String>,
    /// The effective decision (what the proxy should do).
    pub decision: &'static str, // "allow" | "deny"
    /// False in observe mode: verdicts are logged, not enforced.
    pub enforced: bool,
    /// Observe mode only: the verifier (or local check) would have denied.
    pub would_deny: bool,
    pub reason_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_latency_ms: Option<f64>,
    /// True when the verifier was unreachable and the fail policy decided.
    pub degraded: bool,
}

/// The request-scoped egress middleware hook this example is written against — the
/// seam to adapt to the final `rfc/0005-sandbox-egress-middleware` interface.
pub trait EgressMiddleware: Send + Sync {
    fn name(&self) -> &str;
    fn on_request<'a>(
        &'a self,
        ctx: &'a RequestContext<'a>,
        req: &'a EgressRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = (Decision, AuditEvent)> + Send + 'a>>;
}

/// External-authorization middleware: one verifier round trip per request.
pub struct ExtAuthzMiddleware {
    cfg: ExtAuthzConfig,
    client: reqwest::Client,
}

enum VerifierOutcome {
    Verdict(AuthorizeResponse),
    Timeout,
    Unavailable(String),
    Malformed(String),
}

impl ExtAuthzMiddleware {
    pub fn new(cfg: ExtAuthzConfig) -> anyhow::Result<Self> {
        let cfg = cfg.normalized();
        warn_on_unsafe_config(&cfg);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { cfg, client })
    }

    pub fn config(&self) -> &ExtAuthzConfig {
        &self.cfg
    }

    /// Evaluate one request. Infallible by design: every internal failure resolves
    /// through the mode/fail policy into an explicit `Decision`.
    pub async fn evaluate(
        &self,
        ctx: &RequestContext<'_>,
        req: &EgressRequest<'_>,
    ) -> (Decision, AuditEvent) {
        let mut audit = AuditEvent {
            ts_unix_ms: unix_ms(),
            middleware: "ext-authz",
            agent_id: ctx.agent_id.to_string(),
            sandbox_id: ctx.sandbox_id.to_string(),
            endpoint_rule: ctx.endpoint_rule.to_string(),
            method: req.method.to_ascii_uppercase(),
            authority: req.authority.to_string(),
            path: req.path.to_string(),
            canonical_request_hash: None,
            decision: "deny",
            enforced: matches!(self.cfg.mode, Mode::Enforce),
            would_deny: false,
            reason_code: String::new(),
            receipt_id: None,
            verifier_latency_ms: None,
            degraded: false,
        };

        // 1. Local preconditions (no verifier round trip needed to know the answer).
        let token = match find_token_header(req.headers, &self.cfg.token_header) {
            HeaderLookup::One(t) => t,
            HeaderLookup::None => {
                return self.resolve_local_deny(
                    audit,
                    reason::TOKEN_MISSING,
                    format!("request carries no `{}` header", self.cfg.token_header),
                );
            }
            HeaderLookup::Many => {
                // Duplicate credential headers are never legitimate and are a classic
                // request-smuggling primitive — refuse rather than first-match.
                return self.resolve_local_deny(
                    audit,
                    reason::TOKEN_AMBIGUOUS,
                    format!(
                        "request carries multiple `{}` headers; refusing to guess which to authorize",
                        self.cfg.token_header
                    ),
                );
            }
        };
        if req.body.len() > self.cfg.max_body_bytes {
            return self.resolve_local_deny(
                audit,
                reason::REQUEST_TOO_LARGE,
                format!(
                    "body is {} bytes; max_body_bytes={} (intent binding requires hashing the body)",
                    req.body.len(),
                    self.cfg.max_body_bytes
                ),
            );
        }

        // 2. Bind to the bytes that egress.
        let body_sha = sha256_bytes(req.body);
        let crh = canonical_request_hash(&CanonicalRequestParts {
            method: req.method,
            scheme: req.scheme,
            authority: req.authority,
            path: req.path,
            query: req.query,
            body_sha256: body_sha,
        });
        let crh_hex = hex::encode(crh);
        audit.canonical_request_hash = Some(crh_hex.clone());

        // 3. One verifier round trip.
        let wire = AuthorizeRequest {
            version: WIRE_VERSION.to_string(),
            request: RequestDescriptor {
                method: req.method.to_ascii_uppercase(),
                scheme: req.scheme.to_ascii_lowercase(),
                authority: req.authority.to_string(),
                path: req.path.to_string(),
                query: req.query.to_string(),
                body_sha256: hex::encode(body_sha),
                body_len: req.body.len() as u64,
                canonical_request_hash: crh_hex,
            },
            context: WireContext {
                agent_id: ctx.agent_id.to_string(),
                on_behalf_of: ctx.on_behalf_of.map(str::to_string),
                agent_class: ctx.agent_class.map(str::to_string),
                sandbox_id: ctx.sandbox_id.to_string(),
                sandbox_name: ctx.sandbox_name.map(str::to_string),
                endpoint_rule: ctx.endpoint_rule.to_string(),
                policy_revision: ctx.policy_revision.map(str::to_string),
                request_id: ctx.request_id.map(str::to_string),
                received_at_unix_ms: unix_ms(),
            },
            credentials: {
                let mut creds = std::collections::BTreeMap::new();
                creds.insert(self.cfg.token_header.clone(), token.to_string());
                for name in &self.cfg.forward_headers {
                    if name != &self.cfg.token_header {
                        if let Some(v) = find_header(req.headers, name) {
                            creds.insert(name.clone(), v.to_string());
                        }
                    }
                }
                creds
            },
        };

        let started = Instant::now();
        let outcome = self.call_verifier(&wire).await;
        audit.verifier_latency_ms = Some(started.elapsed().as_secs_f64() * 1000.0);

        // 4. Resolve through mode + fail policy.
        match outcome {
            VerifierOutcome::Verdict(v) => {
                audit.reason_code = v.reason_code.clone();
                audit.receipt_id = v.receipt_id.clone();
                match v.decision {
                    WireDecision::Allow => {
                        audit.decision = "allow";
                        (self.continue_decision(), audit)
                    }
                    WireDecision::Deny => self.resolve_verdict_deny(audit, v),
                }
            }
            VerifierOutcome::Timeout => self.resolve_verifier_failure(
                audit,
                reason::VERIFIER_TIMEOUT,
                format!("verifier did not answer within {}ms", self.cfg.timeout_ms),
            ),
            VerifierOutcome::Unavailable(e) => self.resolve_verifier_failure(
                audit,
                reason::VERIFIER_UNAVAILABLE,
                format!("verifier unreachable: {e}"),
            ),
            VerifierOutcome::Malformed(e) => self.resolve_verifier_failure(
                audit,
                reason::VERIFIER_MALFORMED_RESPONSE,
                format!("verifier protocol error: {e}"),
            ),
        }
    }

    async fn call_verifier(&self, wire: &AuthorizeRequest) -> VerifierOutcome {
        match self
            .client
            .post(&self.cfg.verifier_url)
            .json(wire)
            .send()
            .await
        {
            Err(e) if e.is_timeout() => VerifierOutcome::Timeout,
            Err(e) => VerifierOutcome::Unavailable(redact_err(&e)),
            Ok(resp) => {
                let status = resp.status();
                if status != reqwest::StatusCode::OK {
                    return VerifierOutcome::Malformed(format!("http status {status}"));
                }
                match resp.json::<AuthorizeResponse>().await {
                    Ok(v) => VerifierOutcome::Verdict(v),
                    Err(e) if e.is_timeout() => VerifierOutcome::Timeout,
                    Err(e) => VerifierOutcome::Malformed(redact_err(&e)),
                }
            }
        }
    }

    fn continue_decision(&self) -> Decision {
        let strip_headers = if self.cfg.strip_token_header {
            vec![self.cfg.token_header.clone()]
        } else {
            vec![]
        };
        Decision::Continue { strip_headers }
    }

    /// A denial decided by the middleware itself, before any verifier round trip.
    fn resolve_local_deny(
        &self,
        mut audit: AuditEvent,
        code: &str,
        message: String,
    ) -> (Decision, AuditEvent) {
        audit.reason_code = code.to_string();
        match self.cfg.mode {
            Mode::Enforce => {
                audit.decision = "deny";
                (
                    Decision::Deny(DenyVerdict {
                        http_status: 403,
                        reason_code: code.to_string(),
                        message,
                        receipt_id: None,
                        evidence: serde_json::json!({ "source": "middleware-local" }),
                    }),
                    audit,
                )
            }
            Mode::Observe => {
                audit.decision = "allow";
                audit.would_deny = true;
                (self.continue_decision(), audit)
            }
        }
    }

    /// A deny verdict returned by the verifier.
    fn resolve_verdict_deny(
        &self,
        mut audit: AuditEvent,
        v: AuthorizeResponse,
    ) -> (Decision, AuditEvent) {
        match self.cfg.mode {
            Mode::Enforce => {
                audit.decision = "deny";
                (
                    Decision::Deny(DenyVerdict {
                        http_status: 403,
                        reason_code: v.reason_code,
                        message: v.message.unwrap_or_else(|| "denied by verifier".into()),
                        receipt_id: v.receipt_id,
                        evidence: v.evidence.unwrap_or(serde_json::json!({})),
                    }),
                    audit,
                )
            }
            Mode::Observe => {
                audit.decision = "allow";
                audit.would_deny = true;
                (self.continue_decision(), audit)
            }
        }
    }

    /// The verifier could not produce a verdict: apply the fail policy.
    fn resolve_verifier_failure(
        &self,
        mut audit: AuditEvent,
        code: &str,
        message: String,
    ) -> (Decision, AuditEvent) {
        audit.reason_code = code.to_string();
        audit.degraded = true;
        match (self.cfg.mode, self.cfg.fail) {
            (Mode::Enforce, FailPolicy::Closed) => {
                audit.decision = "deny";
                (
                    Decision::Deny(DenyVerdict {
                        http_status: 503,
                        reason_code: code.to_string(),
                        message,
                        receipt_id: None,
                        evidence: serde_json::json!({ "fail_policy": "closed" }),
                    }),
                    audit,
                )
            }
            (Mode::Enforce, FailPolicy::Open) | (Mode::Observe, _) => {
                audit.decision = "allow";
                audit.would_deny = matches!(self.cfg.mode, Mode::Observe);
                (self.continue_decision(), audit)
            }
        }
    }
}

impl EgressMiddleware for ExtAuthzMiddleware {
    fn name(&self) -> &str {
        "ext-authz"
    }

    fn on_request<'a>(
        &'a self,
        ctx: &'a RequestContext<'a>,
        req: &'a EgressRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = (Decision, AuditEvent)> + Send + 'a>> {
        Box::pin(self.evaluate(ctx, req))
    }
}

/// Result of a case-insensitive token-header lookup, distinguishing "exactly one"
/// from "more than one" so duplicates can be refused instead of silently first-matched.
enum HeaderLookup<'a> {
    None,
    One(&'a str),
    Many,
}

/// Case-insensitive lookup for the credential header. Duplicate instances resolve to
/// [`HeaderLookup::Many`] — the caller refuses them rather than authorizing one value
/// while a different one might egress.
fn find_token_header<'a>(headers: &'a [(String, String)], name_lower: &str) -> HeaderLookup<'a> {
    let mut found: Option<&str> = None;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case(name_lower) {
            if found.is_some() {
                return HeaderLookup::Many;
            }
            found = Some(v.as_str());
        }
    }
    match found {
        Some(v) => HeaderLookup::One(v),
        None => HeaderLookup::None,
    }
}

/// Case-insensitive single-header lookup (first match wins). Used only for advisory
/// forward headers (e.g. `x-request-id`), where a duplicate is harmless.
fn find_header<'a>(headers: &'a [(String, String)], name_lower: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name_lower))
        .map(|(_, v)| v.as_str())
}

/// Surface deployment footguns at construction. These are security-relevant defaults
/// inverted; we warn rather than fail, since an operator may have a deliberate reason.
fn warn_on_unsafe_config(cfg: &ExtAuthzConfig) {
    if is_plaintext_non_loopback(&cfg.verifier_url) {
        tracing::warn!(
            verifier_url = %cfg.verifier_url,
            "ext-authz verifier_url is plaintext http:// on a non-loopback host: the \
             per-action credential crosses this link in the clear and any peer that can \
             occupy the address can forge ALLOWs. Use a unix socket or mTLS."
        );
    }
    if !cfg.strip_token_header {
        tracing::warn!(
            "ext-authz strip_token_header=false: the per-action credential will be \
             forwarded to the upstream destination."
        );
    }
}

/// Best-effort check that a verifier URL is plaintext `http://` to a non-loopback host.
/// Errs toward warning: a host it cannot classify as loopback is treated as non-loopback.
fn is_plaintext_non_loopback(url: &str) -> bool {
    let rest = match url.strip_prefix("http://") {
        Some(r) => r,
        None => return false, // https://, unix socket, etc.
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    // Drop any `user@` userinfo before reading the host.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(after_bracket) = authority.strip_prefix('[') {
        after_bracket.split(']').next().unwrap_or(after_bracket) // [ipv6]:port
    } else {
        authority.split(':').next().unwrap_or(authority) // host:port
    };
    // Classify loopback by parsing, not by prefix: `127.evil.com` is NOT loopback (it
    // won't parse as an IPv4 address), while the whole 127.0.0.0/8 block is.
    let is_loopback = host == "localhost"
        || host == "::1"
        || host
            .parse::<std::net::Ipv4Addr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    !is_loopback
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// reqwest error Display strings can embed full URLs; classify by kind instead so
/// audit lines stay terse and URL-free.
fn redact_err(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timeout".into()
    } else if e.is_connect() {
        "connect error".into()
    } else if e.is_decode() {
        "decode error".into()
    } else if let Some(status) = e.status() {
        format!("http status {status}")
    } else if e.is_body() {
        "body error".into()
    } else {
        "request error".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_lookup_distinguishes_none_one_many() {
        let none: Vec<(String, String)> = vec![];
        assert!(matches!(
            find_token_header(&none, "x-tok"),
            HeaderLookup::None
        ));

        let one = vec![("X-Tok".to_string(), "v".to_string())];
        assert!(matches!(
            find_token_header(&one, "x-tok"),
            HeaderLookup::One("v")
        ));

        // Two instances (different case) -> ambiguous, never first-match.
        let many = vec![
            ("X-Tok".to_string(), "a".to_string()),
            ("x-tok".to_string(), "b".to_string()),
        ];
        assert!(matches!(
            find_token_header(&many, "x-tok"),
            HeaderLookup::Many
        ));
    }

    #[test]
    fn plaintext_non_loopback_is_flagged_but_safe_transports_are_not() {
        // Plaintext to a routable/non-loopback host: flagged.
        assert!(is_plaintext_non_loopback(
            "http://verifier.internal:8443/v1/authorize"
        ));
        assert!(is_plaintext_non_loopback("http://10.0.0.5/v1/authorize"));

        // Loopback forms: not flagged.
        assert!(!is_plaintext_non_loopback(
            "http://127.0.0.1:18443/v1/authorize"
        ));
        assert!(!is_plaintext_non_loopback(
            "http://localhost:18443/v1/authorize"
        ));
        assert!(!is_plaintext_non_loopback(
            "http://[::1]:18443/v1/authorize"
        ));

        // https and non-http transports: not this check's concern.
        assert!(!is_plaintext_non_loopback(
            "https://verifier.internal/v1/authorize"
        ));
        assert!(!is_plaintext_non_loopback("unix:/run/authz.sock"));
    }
}
