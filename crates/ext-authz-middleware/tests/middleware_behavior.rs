//! End-to-end behavior: the middleware against a real in-process axum verifier.
//! Covers the allow path, the verifier-deny path, fail-closed vs fail-open on an
//! unreachable verifier, verifier timeout, non-200 and undeserializable-200 responses
//! (both treated as failures, never as a verdict), observe mode, the local
//! TOKEN_MISSING short-circuit, the duplicate-header TOKEN_AMBIGUOUS refusal, the
//! oversize-body deny, forward-header delivery, and the token-header strip (on/off).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::{extract::State, routing::post, Json, Router};
use ext_authz_core::types::{
    reason, AuthorizeRequest, AuthorizeResponse, Decision as WireDecision,
};
use ext_authz_core::{ExtAuthzConfig, FailPolicy, Mode};
use ext_authz_middleware::{Decision, EgressRequest, ExtAuthzMiddleware, RequestContext};

#[derive(Clone, Default)]
struct VerifierState {
    hits: Arc<AtomicUsize>,
    // If set, deny every request with this code; else allow.
    deny_code: Arc<std::sync::Mutex<Option<String>>>,
    // If true, recompute crh and deny CRH_MISMATCH when it doesn't match.
    check_crh: Arc<std::sync::atomic::AtomicBool>,
}

async fn authorize(
    State(st): State<VerifierState>,
    Json(req): Json<AuthorizeRequest>,
) -> Json<AuthorizeResponse> {
    st.hits.fetch_add(1, Ordering::SeqCst);

    if st.check_crh.load(Ordering::SeqCst) {
        let recomputed = recompute_crh(&req);
        if recomputed != req.request.canonical_request_hash {
            return Json(AuthorizeResponse {
                decision: WireDecision::Deny,
                reason_code: reason::CRH_MISMATCH.into(),
                message: Some("server-recomputed crh != client crh".into()),
                receipt_id: None,
                evidence: None,
            });
        }
    }

    if let Some(code) = st.deny_code.lock().unwrap().clone() {
        return Json(AuthorizeResponse {
            decision: WireDecision::Deny,
            reason_code: code,
            message: Some("denied by test verifier".into()),
            receipt_id: Some("rcpt-test".into()),
            evidence: Some(serde_json::json!({"src":"test"})),
        });
    }
    Json(AuthorizeResponse {
        decision: WireDecision::Allow,
        reason_code: reason::OK.into(),
        message: None,
        receipt_id: Some("rcpt-ok".into()),
        evidence: None,
    })
}

fn recompute_crh(req: &AuthorizeRequest) -> String {
    use ext_authz_core::{canonical_request_hash, CanonicalRequestParts};
    let mut body = [0u8; 32];
    hex::decode_to_slice(&req.request.body_sha256, &mut body).unwrap();
    hex::encode(canonical_request_hash(&CanonicalRequestParts {
        method: &req.request.method,
        scheme: &req.request.scheme,
        authority: &req.request.authority,
        path: &req.request.path,
        query: &req.request.query,
        body_sha256: body,
    }))
}

async fn spawn_verifier(st: VerifierState) -> SocketAddr {
    let app = Router::new()
        .route("/v1/authorize", post(authorize))
        .with_state(st);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn cfg(url: String, mode: Mode, fail: FailPolicy) -> ExtAuthzConfig {
    ExtAuthzConfig {
        verifier_url: url,
        mode,
        fail,
        timeout_ms: 1000,
        token_header: "x-hawcx-haap-token".into(),
        forward_headers: vec![],
        strip_token_header: true,
        max_body_bytes: 1024,
    }
}

fn ctx<'a>() -> RequestContext<'a> {
    RequestContext {
        agent_id: "agt-test",
        on_behalf_of: None,
        agent_class: None,
        sandbox_id: "sbx-test",
        sandbox_name: Some("test"),
        endpoint_rule: "github-api",
        policy_revision: Some("v1"),
        request_id: Some("req-1"),
    }
}

fn req<'a>(headers: &'a [(String, String)], body: &'a [u8]) -> EgressRequest<'a> {
    EgressRequest {
        method: "POST",
        scheme: "https",
        authority: "api.github.com",
        path: "/repos/acme/widgets/issues",
        query: "",
        headers,
        body,
    }
}

fn token_header() -> Vec<(String, String)> {
    vec![("X-Hawcx-HAAP-Token".into(), "opaque-token".into())]
}

#[tokio::test]
async fn allow_path_continues_and_strips_token_header() {
    let st = VerifierState::default();
    let addr = spawn_verifier(st.clone()).await;
    let mw = ExtAuthzMiddleware::new(cfg(
        format!("http://{addr}/v1/authorize"),
        Mode::Enforce,
        FailPolicy::Closed,
    ))
    .unwrap();

    let h = token_header();
    let r = req(&h, b"{\"title\":\"bug\"}");
    let (decision, audit) = mw.evaluate(&ctx(), &r).await;

    match decision {
        Decision::Continue { strip_headers } => {
            assert_eq!(strip_headers, vec!["x-hawcx-haap-token".to_string()]);
        }
        Decision::Deny(v) => panic!("expected allow, got deny {v:?}"),
    }
    assert_eq!(audit.decision, "allow");
    assert_eq!(audit.reason_code, reason::OK);
    assert!(audit.canonical_request_hash.is_some());
    assert_eq!(st.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn verifier_deny_blocks_with_reason() {
    let st = VerifierState::default();
    *st.deny_code.lock().unwrap() = Some(reason::TOKEN_REPLAYED.into());
    let addr = spawn_verifier(st.clone()).await;
    let mw = ExtAuthzMiddleware::new(cfg(
        format!("http://{addr}/v1/authorize"),
        Mode::Enforce,
        FailPolicy::Closed,
    ))
    .unwrap();

    let h = token_header();
    let r = req(&h, b"{}");
    let (decision, audit) = mw.evaluate(&ctx(), &r).await;

    match decision {
        Decision::Deny(v) => {
            assert_eq!(v.http_status, 403);
            assert_eq!(v.reason_code, reason::TOKEN_REPLAYED);
            assert_eq!(v.receipt_id.as_deref(), Some("rcpt-test"));
        }
        Decision::Continue { .. } => panic!("expected deny"),
    }
    assert_eq!(audit.decision, "deny");
    assert!(audit.enforced);
}

#[tokio::test]
async fn missing_token_denies_locally_without_calling_verifier() {
    let st = VerifierState::default();
    let addr = spawn_verifier(st.clone()).await;
    let mw = ExtAuthzMiddleware::new(cfg(
        format!("http://{addr}/v1/authorize"),
        Mode::Enforce,
        FailPolicy::Closed,
    ))
    .unwrap();

    let h: Vec<(String, String)> = vec![]; // no token
    let r = req(&h, b"{}");
    let (decision, audit) = mw.evaluate(&ctx(), &r).await;

    assert!(matches!(decision, Decision::Deny(_)));
    assert_eq!(audit.reason_code, reason::TOKEN_MISSING);
    assert_eq!(
        st.hits.load(Ordering::SeqCst),
        0,
        "no verifier round trip for a local deny"
    );
}

#[tokio::test]
async fn oversize_body_denies_locally() {
    let st = VerifierState::default();
    let addr = spawn_verifier(st.clone()).await;
    let mut c = cfg(
        format!("http://{addr}/v1/authorize"),
        Mode::Enforce,
        FailPolicy::Closed,
    );
    c.max_body_bytes = 8;
    let mw = ExtAuthzMiddleware::new(c).unwrap();

    let h = token_header();
    let big = vec![b'x'; 9];
    let r = req(&h, &big);
    let (decision, audit) = mw.evaluate(&ctx(), &r).await;

    assert!(matches!(decision, Decision::Deny(_)));
    assert_eq!(audit.reason_code, reason::REQUEST_TOO_LARGE);
    assert_eq!(st.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn fail_closed_denies_when_verifier_unreachable() {
    // Point at a closed port (nothing listening).
    let mw = ExtAuthzMiddleware::new(cfg(
        "http://127.0.0.1:1/v1/authorize".into(),
        Mode::Enforce,
        FailPolicy::Closed,
    ))
    .unwrap();

    let h = token_header();
    let r = req(&h, b"{}");
    let (decision, audit) = mw.evaluate(&ctx(), &r).await;

    match decision {
        Decision::Deny(v) => {
            assert_eq!(v.http_status, 503, "infra denial, not an authz denial");
            assert_eq!(v.reason_code, reason::VERIFIER_UNAVAILABLE);
        }
        Decision::Continue { .. } => panic!("fail-closed must deny when the verifier is down"),
    }
    assert!(audit.degraded);
}

#[tokio::test]
async fn fail_open_allows_when_verifier_unreachable() {
    let mw = ExtAuthzMiddleware::new(cfg(
        "http://127.0.0.1:1/v1/authorize".into(),
        Mode::Enforce,
        FailPolicy::Open,
    ))
    .unwrap();

    let h = token_header();
    let r = req(&h, b"{}");
    let (decision, audit) = mw.evaluate(&ctx(), &r).await;

    assert!(
        decision.is_allow(),
        "fail-open continues when the verifier is down"
    );
    assert!(audit.degraded);
    assert_eq!(audit.decision, "allow");
}

#[tokio::test]
async fn observe_mode_never_blocks_but_records_would_deny() {
    let st = VerifierState::default();
    *st.deny_code.lock().unwrap() = Some(reason::INTENT_MISMATCH.into());
    let addr = spawn_verifier(st.clone()).await;
    let mw = ExtAuthzMiddleware::new(cfg(
        format!("http://{addr}/v1/authorize"),
        Mode::Observe,
        FailPolicy::Closed,
    ))
    .unwrap();

    let h = token_header();
    let r = req(&h, b"{}");
    let (decision, audit) = mw.evaluate(&ctx(), &r).await;

    assert!(decision.is_allow(), "observe mode does not block");
    assert!(!audit.enforced);
    assert!(audit.would_deny);
    assert_eq!(audit.decision, "allow");
    assert_eq!(audit.reason_code, reason::INTENT_MISMATCH);
}

#[tokio::test]
async fn verifier_recomputes_crh_and_accepts_matching_hash() {
    let st = VerifierState::default();
    st.check_crh.store(true, Ordering::SeqCst);
    let addr = spawn_verifier(st.clone()).await;
    let mw = ExtAuthzMiddleware::new(cfg(
        format!("http://{addr}/v1/authorize"),
        Mode::Enforce,
        FailPolicy::Closed,
    ))
    .unwrap();

    let h = token_header();
    let r = req(&h, b"{\"title\":\"bug\"}");
    let (decision, audit) = mw.evaluate(&ctx(), &r).await;

    assert!(
        decision.is_allow(),
        "the crh the middleware sent must match the verifier's recompute"
    );
    assert_eq!(audit.reason_code, reason::OK);
}

// ---- coverage added in the hardening pass ----

async fn bind_and_serve(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn slow_verifier_times_out_and_fails_closed() {
    // Verifier accepts the connection but answers after the middleware's deadline.
    let app = Router::new().route(
        "/v1/authorize",
        post(|Json(_): Json<AuthorizeRequest>| async {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            Json(AuthorizeResponse {
                decision: WireDecision::Allow,
                reason_code: reason::OK.into(),
                message: None,
                receipt_id: None,
                evidence: None,
            })
        }),
    );
    let addr = bind_and_serve(app).await;
    let mut c = cfg(
        format!("http://{addr}/v1/authorize"),
        Mode::Enforce,
        FailPolicy::Closed,
    );
    c.timeout_ms = 50;
    let mw = ExtAuthzMiddleware::new(c).unwrap();

    let h = token_header();
    let r = req(&h, b"{}");
    let (decision, audit) = mw.evaluate(&ctx(), &r).await;

    match decision {
        Decision::Deny(v) => {
            assert_eq!(v.http_status, 503);
            assert_eq!(v.reason_code, reason::VERIFIER_TIMEOUT);
        }
        Decision::Continue { .. } => panic!("a verifier timeout must fail closed"),
    }
    assert!(audit.degraded);
}

#[tokio::test]
async fn non_200_is_a_verifier_failure_not_a_verdict() {
    let app = Router::new().route(
        "/v1/authorize",
        post(|Json(_): Json<AuthorizeRequest>| async {
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom")
        }),
    );
    let addr = bind_and_serve(app).await;
    let mw = ExtAuthzMiddleware::new(cfg(
        format!("http://{addr}/v1/authorize"),
        Mode::Enforce,
        FailPolicy::Closed,
    ))
    .unwrap();

    let h = token_header();
    let r = req(&h, b"{}");
    let (decision, audit) = mw.evaluate(&ctx(), &r).await;

    match decision {
        Decision::Deny(v) => {
            assert_eq!(v.http_status, 503);
            assert_eq!(v.reason_code, reason::VERIFIER_MALFORMED_RESPONSE);
        }
        Decision::Continue { .. } => panic!("a 500 must not be read as allow"),
    }
    assert!(audit.degraded);
}

#[tokio::test]
async fn undeserializable_200_is_a_verifier_failure() {
    // 200 OK, but the body is not an AuthorizeResponse (decision is not allow/deny).
    let app = Router::new().route(
        "/v1/authorize",
        post(|Json(_): Json<AuthorizeRequest>| async {
            Json(serde_json::json!({ "decision": "maybe" }))
        }),
    );
    let addr = bind_and_serve(app).await;
    let mw = ExtAuthzMiddleware::new(cfg(
        format!("http://{addr}/v1/authorize"),
        Mode::Enforce,
        FailPolicy::Closed,
    ))
    .unwrap();

    let h = token_header();
    let r = req(&h, b"{}");
    let (decision, _audit) = mw.evaluate(&ctx(), &r).await;

    match decision {
        Decision::Deny(v) => assert_eq!(v.reason_code, reason::VERIFIER_MALFORMED_RESPONSE),
        Decision::Continue { .. } => panic!("an undeserializable 200 must not be read as allow"),
    }
}

#[tokio::test]
async fn strip_token_header_false_keeps_the_header_on_continue() {
    let st = VerifierState::default();
    let addr = spawn_verifier(st.clone()).await;
    let mut c = cfg(
        format!("http://{addr}/v1/authorize"),
        Mode::Enforce,
        FailPolicy::Closed,
    );
    c.strip_token_header = false;
    let mw = ExtAuthzMiddleware::new(c).unwrap();

    let h = token_header();
    let r = req(&h, b"{}");
    let (decision, _audit) = mw.evaluate(&ctx(), &r).await;

    match decision {
        Decision::Continue { strip_headers } => assert!(strip_headers.is_empty()),
        Decision::Deny(v) => panic!("expected allow, got {v:?}"),
    }
}

#[tokio::test]
async fn duplicate_token_header_is_refused_locally() {
    let st = VerifierState::default();
    let addr = spawn_verifier(st.clone()).await;
    let mw = ExtAuthzMiddleware::new(cfg(
        format!("http://{addr}/v1/authorize"),
        Mode::Enforce,
        FailPolicy::Closed,
    ))
    .unwrap();

    // Two instances (different case) of the credential header.
    let h = vec![
        ("X-Hawcx-HAAP-Token".to_string(), "a".to_string()),
        ("x-hawcx-haap-token".to_string(), "b".to_string()),
    ];
    let r = req(&h, b"{}");
    let (decision, audit) = mw.evaluate(&ctx(), &r).await;

    assert!(matches!(decision, Decision::Deny(_)));
    assert_eq!(audit.reason_code, reason::TOKEN_AMBIGUOUS);
    assert_eq!(
        st.hits.load(Ordering::SeqCst),
        0,
        "ambiguous credential is rejected before any verifier round trip"
    );
}

#[tokio::test]
async fn forward_headers_reach_the_verifier() {
    // Echo verifier: reflects the x-request-id it saw in `credentials` as the receipt.
    let app = Router::new().route(
        "/v1/authorize",
        post(|Json(req): Json<AuthorizeRequest>| async move {
            let rid = req.credentials.get("x-request-id").cloned();
            Json(AuthorizeResponse {
                decision: WireDecision::Allow,
                reason_code: reason::OK.into(),
                message: None,
                receipt_id: rid,
                evidence: None,
            })
        }),
    );
    let addr = bind_and_serve(app).await;
    let mut c = cfg(
        format!("http://{addr}/v1/authorize"),
        Mode::Enforce,
        FailPolicy::Closed,
    );
    c.forward_headers = vec!["x-request-id".into()];
    let mw = ExtAuthzMiddleware::new(c).unwrap();

    let h = vec![
        ("X-Hawcx-HAAP-Token".to_string(), "tok".to_string()),
        ("X-Request-Id".to_string(), "rid-123".to_string()),
    ];
    let r = req(&h, b"{}");
    let (decision, audit) = mw.evaluate(&ctx(), &r).await;

    assert!(decision.is_allow());
    assert_eq!(
        audit.receipt_id.as_deref(),
        Some("rid-123"),
        "the configured forward header must arrive in the verifier's credentials map"
    );
}

#[tokio::test]
async fn local_deny_carries_no_canonical_request_hash() {
    // A local precondition deny (missing token) short-circuits before hashing.
    let mw = ExtAuthzMiddleware::new(cfg(
        "http://127.0.0.1:1/v1/authorize".into(),
        Mode::Enforce,
        FailPolicy::Closed,
    ))
    .unwrap();

    let h: Vec<(String, String)> = vec![];
    let r = req(&h, b"{}");
    let (_decision, audit) = mw.evaluate(&ctx(), &r).await;

    assert_eq!(audit.reason_code, reason::TOKEN_MISSING);
    assert!(
        audit.canonical_request_hash.is_none(),
        "no crh is computed for a local short-circuit deny"
    );
}
