//! A reference HAAP-shaped per-action verifier ("guard service").
//!
//! It runs a HAAP-shaped verification cascade in miniature over the demo token. The step
//! order below is this reference's own; in particular it deliberately consumes the
//! single-use `jti` LAST. Real HAAP performs atomic `jti` consumption as part of its
//! canonical §9.1 RS verification cascade, whose exact step ordering differs — the
//! jti-last shape here is a demo hardening choice, not a transcription of §9.1. Steps, in
//! execution order:
//!
//! 1. signature (HMAC) -> `TOKEN_SIGNATURE_INVALID` / `TOKEN_MALFORMED`
//! 2. wire version -> `UNSUPPORTED_VERSION`
//! 3. expiry -> `TOKEN_EXPIRED`
//! 4. descriptor canonicalization + crh recompute -> `DESCRIPTOR_MALFORMED` / `CRH_MISMATCH`
//! 5. principal binding — the DURABLE AGENT (+ on-behalf-of, + not revoked) -> `AGENT_MISMATCH` / `AGENT_REVOKED`
//! 6. workload constraint (optional; sandbox is context, pinned only if the mandate asks) -> `WORKLOAD_MISMATCH`
//! 7. coarse scope (method / authority / path prefix) -> `INTENT_MISMATCH`
//! 8. exact intent (crh binding, when the token carries one) -> `INTENT_MISMATCH`
//! 9. single-use jti consumption -> `TOKEN_REPLAYED`
//!
//! If every step passes: ALLOW (`OK`) + a receipt id.
//!
//! Design notes:
//!
//! * **The principal is the durable agent, not the sandbox** (step 5). A grant follows the
//!   agent across respawns; the sandbox is attested *context*, bound only as an optional
//!   workload constraint (step 6). Revocation (`AGENT_REVOKED`) therefore applies to the
//!   agent across every sandbox it runs in — impossible if the principal were the sandbox.
//! * **jti is consumed last in this demo** (step 9), so a forged, stale, or out-of-scope token can't
//!   burn a victim's nonce. The trade-off is at-most-once delivery: if the ALLOW
//!   response is lost (the middleware times out), the nonce is already spent and the
//!   legitimate retry sees `TOKEN_REPLAYED`. A production verifier makes consumption
//!   idempotent keyed on `(jti, crh)` — retrying the *same* action re-allows, while a
//!   *different* action on that jti still fails.
//! * **The crh recompute** (step 4) defends against an internally inconsistent
//!   descriptor and against tampering on the middleware↔verifier link. It does NOT
//!   re-observe the body: the middleware is the only component that sees the egressing
//!   bytes and is trusted to measure `body_sha256`. The recompute binds the
//!   *descriptor*; the middleware's position in the chain is what binds the descriptor
//!   to reality. A descriptor that cannot be canonicalized is a hard deny — never an
//!   in-band sentinel that could equal a real hash.
//! * **The replay store is an in-memory, unbounded `HashSet`** — demo-only. A real
//!   verifier needs a TTL-bounded, shared (cross-replica), persistent store keyed to
//!   token lifetime (cf. HAAP §9.1 atomic single-use consumption).

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::DefaultBodyLimit, extract::State, routing::post, Json, Router};
use ext_authz_core::hash::normalize_authority;
use ext_authz_core::types::{reason, AuthorizeRequest, AuthorizeResponse, Decision, WIRE_VERSION};
use ext_authz_core::{canonical_request_hash, CanonicalRequestParts};

use crate::token::{self, VerifyError};

/// Upper bound on the `AuthorizeRequest` body the verifier will buffer. The descriptor
/// is small (a few hundred bytes); this caps a memory-exhaustion vector from any peer
/// that can reach the endpoint.
const MAX_AUTHORIZE_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct VerifierState {
    pub key: Arc<Vec<u8>>,
    pub seen_jti: Arc<Mutex<HashSet<String>>>,
    /// Revoked durable agent principals. Demo-only (in-memory); a real verifier consults
    /// the AS revocation snapshot. Keyed on the AGENT, so revocation applies across every
    /// sandbox the agent runs in — impossible if the principal were the sandbox.
    pub revoked_agents: Arc<Mutex<HashSet<String>>>,
}

impl VerifierState {
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key: Arc::new(key),
            seen_jti: Arc::new(Mutex::new(HashSet::new())),
            revoked_agents: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Revoke a durable agent principal (demo admin operation).
    pub fn revoke_agent(&self, agent_id: &str) {
        self.revoked_agents
            .lock()
            .unwrap()
            .insert(agent_id.to_string());
    }
}

pub fn router(state: VerifierState) -> Router {
    Router::new()
        .route("/v1/authorize", post(authorize))
        .route("/v1/revoke/:agent_id", post(revoke))
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(MAX_AUTHORIZE_BODY_BYTES))
        .with_state(state)
}

/// Demo admin endpoint: revoke an agent principal (real HAAP: AS revocation, §31).
///
/// DEMO-ONLY and intentionally UNAUTHENTICATED. A production verifier MUST authenticate and
/// authorize this state-changing route — and separate it from the data-plane
/// `/v1/authorize` surface — or any peer that can reach the verifier could revoke any agent
/// (a denial-of-service). This is the control-plane analogue of the authorize channel's
/// mutual-auth transport requirement.
async fn revoke(
    State(st): State<VerifierState>,
    axum::extract::Path(agent_id): axum::extract::Path<String>,
) -> axum::http::StatusCode {
    st.revoke_agent(&agent_id);
    axum::http::StatusCode::NO_CONTENT
}

fn deny(code: &str, msg: &str) -> Json<AuthorizeResponse> {
    Json(AuthorizeResponse {
        decision: Decision::Deny,
        reason_code: code.into(),
        message: Some(msg.into()),
        receipt_id: None,
        evidence: Some(serde_json::json!({ "verifier": "demo" })),
    })
}

async fn authorize(
    State(st): State<VerifierState>,
    Json(req): Json<AuthorizeRequest>,
) -> Json<AuthorizeResponse> {
    // The reference verifier reads the credential under the wire-contract default header
    // (`DEFAULT_TOKEN_HEADER`). A deployment that overrides the middleware's `token_header`
    // must configure the verifier with the same name; otherwise every request arrives with
    // no recognized credential and is denied `TOKEN_MALFORMED` (fail-safe, not fail-open).
    // The demo pins both sides to the default.
    let token = match req.credentials.get(ext_authz_core::DEFAULT_TOKEN_HEADER) {
        Some(t) => t,
        None => return deny(reason::TOKEN_MALFORMED, "no token in credentials"),
    };

    // 1. signature
    let claims = match token::verify(token, &st.key) {
        Ok(c) => c,
        Err(VerifyError::BadSignature) => {
            return deny(reason::TOKEN_SIGNATURE_INVALID, "HMAC mismatch")
        }
        Err(VerifyError::Malformed) => return deny(reason::TOKEN_MALFORMED, "undecodable token"),
    };

    // 2. wire version
    if req.version != WIRE_VERSION {
        return deny(
            reason::UNSUPPORTED_VERSION,
            "unsupported wire-contract version",
        );
    }

    // 3. expiry
    if now_ms() > claims.exp_unix_ms {
        return deny(reason::TOKEN_EXPIRED, "token exp in the past");
    }

    // 4. descriptor canonicalization + crh recompute. A descriptor that cannot be
    //    canonicalized at all is a hard DESCRIPTOR_MALFORMED — never an in-band sentinel
    //    that could collide with a real hash. A well-formed hash that simply differs is
    //    CRH_MISMATCH.
    match recompute_crh(&req) {
        None => {
            return deny(
                reason::DESCRIPTOR_MALFORMED,
                "descriptor hashes are not lowercase 32-byte hex",
            )
        }
        Some(h) if h == req.request.canonical_request_hash => {}
        Some(_) => {
            return deny(
                reason::CRH_MISMATCH,
                "descriptor does not hash to the sent crh",
            )
        }
    }

    // 5. principal binding — the DURABLE AGENT, not the ephemeral sandbox. A grant follows
    //    the agent across respawns; the sandbox is context (step 6), not the subject.
    if claims.agent_id != req.context.agent_id {
        return deny(reason::AGENT_MISMATCH, "token agent != acting agent");
    }
    if st.revoked_agents.lock().unwrap().contains(&claims.agent_id) {
        return deny(reason::AGENT_REVOKED, "agent principal has been revoked");
    }
    if let Some(obo) = &claims.on_behalf_of {
        if req.context.on_behalf_of.as_deref() != Some(obo.as_str()) {
            return deny(
                reason::AGENT_MISMATCH,
                "token on-behalf-of != acting on-behalf-of",
            );
        }
    }

    // 6. workload constraint (optional) — the sandbox is attested context; bind it only if
    //    the token's mandate pins a workload selector.
    if let Some(sel) = &claims.workload_selector {
        if !req.context.sandbox_id.starts_with(sel.as_str()) {
            return deny(
                reason::WORKLOAD_MISMATCH,
                "acting sandbox outside token workload selector",
            );
        }
    }

    // 7. coarse scope (method, authority, path prefix)
    if !claims
        .scope
        .method
        .eq_ignore_ascii_case(&req.request.method)
        || !authority_in_scope(
            &req.request.scheme,
            &req.request.authority,
            &claims.scope.authority,
        )
        || !path_in_scope(&req.request.path, &claims.scope.path_prefix)
    {
        return deny(reason::INTENT_MISMATCH, "request outside token scope");
    }

    // 8. intent (exact crh binding, when the token carries one)
    if let Some(bound) = &claims.crh {
        if bound != &req.request.canonical_request_hash {
            return deny(reason::INTENT_MISMATCH, "request crh != token-bound crh");
        }
    }

    // 9. single-use consumption — only after everything else passes, so a forged,
    //    stale, or out-of-scope token can't burn a victim's nonce.
    {
        let mut seen = st.seen_jti.lock().unwrap();
        if !seen.insert(claims.jti.clone()) {
            return deny(reason::TOKEN_REPLAYED, "jti already consumed");
        }
    }

    Json(AuthorizeResponse {
        decision: Decision::Allow,
        reason_code: reason::OK.into(),
        message: None,
        receipt_id: Some(format!("rcpt-{}", &claims.jti)),
        evidence: Some(serde_json::json!({
            "verifier": "demo",
            "agent_id": claims.agent_id,
            // "exact" = bound to this request's crh; "coarse" = scope-only (body/path
            // under the prefix are unbound). Surfaced so coarse grants are auditable.
            "binding": if claims.crh.is_some() { "exact" } else { "coarse" },
            "bound_crh": claims.crh,
            "scope": { "method": claims.scope.method, "authority": claims.scope.authority },
        })),
    })
}

/// Canonicalize the descriptor and return its `crh_v1` hex, or `None` if the descriptor
/// cannot be canonicalized (e.g. `body_sha256` is not 32-byte hex). Returning `None`
/// rather than a sentinel string keeps a malformed descriptor out of the hash value
/// space, so the equality gate can never be satisfied by a crafted "matching" sentinel.
fn recompute_crh(req: &AuthorizeRequest) -> Option<String> {
    let body = decode_lower_hex_32(&req.request.body_sha256)?;
    decode_lower_hex_32(&req.request.canonical_request_hash)?;
    Some(hex::encode(canonical_request_hash(
        &CanonicalRequestParts {
            method: &req.request.method,
            scheme: &req.request.scheme,
            authority: &req.request.authority,
            path: &req.request.path,
            query: &req.request.query,
            body_sha256: body,
        },
    )))
}

fn decode_lower_hex_32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    (hex::encode(out) == s).then_some(out)
}

fn authority_in_scope(
    request_scheme: &str,
    request_authority: &str,
    scope_authority: &str,
) -> bool {
    let scheme = request_scheme.to_ascii_lowercase();
    normalize_authority(&scheme, request_authority) == normalize_authority(&scheme, scope_authority)
}

fn path_in_scope(request_path: &str, scope_prefix: &str) -> bool {
    let path = if request_path.is_empty() {
        "/"
    } else {
        request_path
    };
    let prefix = if scope_prefix.is_empty() {
        "/"
    } else {
        scope_prefix
    };

    if prefix == "/" {
        return path.starts_with('/');
    }
    path == prefix
        || if prefix.ends_with('/') {
            path.starts_with(prefix)
        } else {
            path.strip_prefix(prefix)
                .map(|rest| rest.starts_with('/'))
                .unwrap_or(false)
        }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{mint, Claims, Scope, DEMO_KEY};
    use ext_authz_core::sha256_bytes;
    use ext_authz_core::types::{RequestDescriptor, WireContext};

    const AGT: &str = "agt-1";
    const SBX: &str = "sbx-1";
    const AUTH: &str = "api.github.com";

    fn coarse_token() -> String {
        token_with_scope(
            "j-coarse",
            Scope {
                method: "POST".into(),
                authority: AUTH.into(),
                path_prefix: "/".into(),
            },
            None,
        )
    }

    fn token_with_scope(jti: &str, scope: Scope, crh: Option<String>) -> String {
        mint(
            &Claims {
                jti: jti.into(),
                agent_id: AGT.into(),
                on_behalf_of: None,
                workload_selector: None,
                scope,
                crh,
                exp_unix_ms: i64::MAX,
            },
            DEMO_KEY,
        )
    }

    fn wire(token: String, path: &str, body_sha256: String, crh: String) -> AuthorizeRequest {
        let mut credentials = std::collections::BTreeMap::new();
        credentials.insert("x-hawcx-haap-token".to_string(), token);
        AuthorizeRequest {
            version: "1".into(),
            request: RequestDescriptor {
                method: "POST".into(),
                scheme: "https".into(),
                authority: AUTH.into(),
                path: path.into(),
                query: String::new(),
                body_sha256,
                body_len: 0,
                canonical_request_hash: crh,
            },
            context: WireContext {
                agent_id: AGT.into(),
                sandbox_id: SBX.into(),
                endpoint_rule: "r".into(),
                received_at_unix_ms: 0,
                ..Default::default()
            },
            credentials,
        }
    }

    /// F1 regression: a descriptor whose `body_sha256` is not hex must be a hard
    /// `DESCRIPTOR_MALFORMED` deny — it must NOT be satisfiable by crafting
    /// `canonical_request_hash` to equal an in-band error sentinel.
    #[tokio::test]
    async fn malformed_body_sha_cannot_bypass_the_crh_gate() {
        let st = VerifierState::new(DEMO_KEY.to_vec());
        let req = wire(
            coarse_token(),
            "/x",
            "not-hex".into(),          // unparseable body hash
            "invalid-body-sha".into(), // the old sentinel value
        );
        let Json(resp) = authorize(State(st), Json(req)).await;
        assert_eq!(resp.decision, Decision::Deny);
        assert_eq!(resp.reason_code, reason::DESCRIPTOR_MALFORMED);
    }

    #[tokio::test]
    async fn unsupported_wire_version_is_denied() {
        let st = VerifierState::new(DEMO_KEY.to_vec());
        let body_sha = sha256_bytes(b"");
        let crh = hex::encode(canonical_request_hash(&CanonicalRequestParts {
            method: "POST",
            scheme: "https",
            authority: AUTH,
            path: "/x",
            query: "",
            body_sha256: body_sha,
        }));
        let mut req = wire(coarse_token(), "/x", hex::encode(body_sha), crh);
        req.version = "2".into();

        let Json(resp) = authorize(State(st), Json(req)).await;
        assert_eq!(resp.decision, Decision::Deny);
        assert_eq!(resp.reason_code, reason::UNSUPPORTED_VERSION);
    }

    #[tokio::test]
    async fn malformed_canonical_hash_is_descriptor_malformed() {
        let st = VerifierState::new(DEMO_KEY.to_vec());
        let req = wire(
            coarse_token(),
            "/x",
            hex::encode(sha256_bytes(b"")),
            "not-hex".into(),
        );

        let Json(resp) = authorize(State(st), Json(req)).await;
        assert_eq!(resp.decision, Decision::Deny);
        assert_eq!(resp.reason_code, reason::DESCRIPTOR_MALFORMED);
    }

    /// A well-formed but non-matching hash is `CRH_MISMATCH`, distinct from malformed.
    #[tokio::test]
    async fn wellformed_nonmatching_crh_is_crh_mismatch() {
        let st = VerifierState::new(DEMO_KEY.to_vec());
        let req = wire(
            coarse_token(),
            "/x",
            hex::encode(sha256_bytes(b"")),
            "ab".repeat(32), // valid 64-hex, but not the real crh
        );
        let Json(resp) = authorize(State(st), Json(req)).await;
        assert_eq!(resp.decision, Decision::Deny);
        assert_eq!(resp.reason_code, reason::CRH_MISMATCH);
    }

    #[tokio::test]
    async fn default_port_scope_matches_normalized_authority() {
        let st = VerifierState::new(DEMO_KEY.to_vec());
        let body_sha = sha256_bytes(b"");
        let crh = hex::encode(canonical_request_hash(&CanonicalRequestParts {
            method: "POST",
            scheme: "https",
            authority: "api.github.com:443",
            path: "/x",
            query: "",
            body_sha256: body_sha,
        }));
        let mut req = wire(coarse_token(), "/x", hex::encode(body_sha), crh);
        req.request.authority = "api.github.com:443".into();

        let Json(resp) = authorize(State(st), Json(req)).await;
        assert_eq!(resp.decision, Decision::Allow);
        assert_eq!(resp.reason_code, reason::OK);
    }

    #[tokio::test]
    async fn path_prefix_is_segment_aware() {
        let st = VerifierState::new(DEMO_KEY.to_vec());
        let token = token_with_scope(
            "j-segment",
            Scope {
                method: "POST".into(),
                authority: AUTH.into(),
                path_prefix: "/repos/acme".into(),
            },
            None,
        );
        let body_sha = sha256_bytes(b"");
        let crh = hex::encode(canonical_request_hash(&CanonicalRequestParts {
            method: "POST",
            scheme: "https",
            authority: AUTH,
            path: "/repos/acmeevil/issues",
            query: "",
            body_sha256: body_sha,
        }));
        let req = wire(token, "/repos/acmeevil/issues", hex::encode(body_sha), crh);

        let Json(resp) = authorize(State(st), Json(req)).await;
        assert_eq!(resp.decision, Decision::Deny);
        assert_eq!(resp.reason_code, reason::INTENT_MISMATCH);
    }

    #[tokio::test]
    async fn path_prefix_allows_exact_segment_and_descendants() {
        let scope = Scope {
            method: "POST".into(),
            authority: AUTH.into(),
            path_prefix: "/repos/acme".into(),
        };

        for (jti, path) in [
            ("j-exact", "/repos/acme"),
            ("j-child", "/repos/acme/issues"),
        ] {
            let st = VerifierState::new(DEMO_KEY.to_vec());
            let token = token_with_scope(jti, scope.clone(), None);
            let body_sha = sha256_bytes(b"");
            let crh = hex::encode(canonical_request_hash(&CanonicalRequestParts {
                method: "POST",
                scheme: "https",
                authority: AUTH,
                path,
                query: "",
                body_sha256: body_sha,
            }));
            let req = wire(token, path, hex::encode(body_sha), crh);

            let Json(resp) = authorize(State(st), Json(req)).await;
            assert_eq!(resp.decision, Decision::Allow);
            assert_eq!(resp.reason_code, reason::OK);
        }
    }

    /// F2: a coarse grant (crh: None) is allowed but audited as `binding: "coarse"`, so
    /// the unbound-body case is visible in the trail.
    #[tokio::test]
    async fn coarse_grant_allows_but_is_audited_as_coarse() {
        let st = VerifierState::new(DEMO_KEY.to_vec());
        let body_sha = sha256_bytes(b"");
        let crh = hex::encode(canonical_request_hash(&CanonicalRequestParts {
            method: "POST",
            scheme: "https",
            authority: AUTH,
            path: "/x",
            query: "",
            body_sha256: body_sha,
        }));
        let req = wire(coarse_token(), "/x", hex::encode(body_sha), crh);
        let Json(resp) = authorize(State(st), Json(req)).await;
        assert_eq!(resp.decision, Decision::Allow);
        assert_eq!(resp.reason_code, reason::OK);
        assert_eq!(resp.evidence.unwrap()["binding"], "coarse");
    }

    /// The principal is the agent: a token for AGT presented by a different acting agent
    /// is refused, regardless of sandbox.
    #[tokio::test]
    async fn wrong_agent_is_agent_mismatch() {
        let st = VerifierState::new(DEMO_KEY.to_vec());
        let body_sha = sha256_bytes(b"");
        let crh = hex::encode(canonical_request_hash(&CanonicalRequestParts {
            method: "POST",
            scheme: "https",
            authority: AUTH,
            path: "/x",
            query: "",
            body_sha256: body_sha,
        }));
        let mut req = wire(coarse_token(), "/x", hex::encode(body_sha), crh);
        req.context.agent_id = "agt-OTHER".into();
        let Json(resp) = authorize(State(st), Json(req)).await;
        assert_eq!(resp.reason_code, reason::AGENT_MISMATCH);
    }

    /// Revocation is keyed on the agent, so it applies even from a different sandbox —
    /// the property that's impossible when the principal is the ephemeral sandbox.
    #[tokio::test]
    async fn revoked_agent_is_denied_across_sandboxes() {
        let st = VerifierState::new(DEMO_KEY.to_vec());
        st.revoke_agent(AGT);
        let body_sha = sha256_bytes(b"");
        let crh = hex::encode(canonical_request_hash(&CanonicalRequestParts {
            method: "POST",
            scheme: "https",
            authority: AUTH,
            path: "/x",
            query: "",
            body_sha256: body_sha,
        }));
        let mut req = wire(coarse_token(), "/x", hex::encode(body_sha), crh);
        req.context.sandbox_id = "sbx-different".into();
        let Json(resp) = authorize(State(st), Json(req)).await;
        assert_eq!(resp.reason_code, reason::AGENT_REVOKED);
    }

    /// An optional workload selector pins the sandbox; an off-selector sandbox is refused.
    #[tokio::test]
    async fn workload_selector_mismatch_is_workload_mismatch() {
        let st = VerifierState::new(DEMO_KEY.to_vec());
        let token = mint(
            &Claims {
                jti: "j-wl".into(),
                agent_id: AGT.into(),
                on_behalf_of: None,
                workload_selector: Some("sbx-prod-".into()),
                scope: Scope {
                    method: "POST".into(),
                    authority: AUTH.into(),
                    path_prefix: "/".into(),
                },
                crh: None,
                exp_unix_ms: i64::MAX,
            },
            DEMO_KEY,
        );
        let body_sha = sha256_bytes(b"");
        let crh = hex::encode(canonical_request_hash(&CanonicalRequestParts {
            method: "POST",
            scheme: "https",
            authority: AUTH,
            path: "/x",
            query: "",
            body_sha256: body_sha,
        }));
        let mut req = wire(token, "/x", hex::encode(body_sha), crh);
        req.context.sandbox_id = "sbx-dev-1".into();
        let Json(resp) = authorize(State(st), Json(req)).await;
        assert_eq!(resp.reason_code, reason::WORKLOAD_MISMATCH);
    }
}
