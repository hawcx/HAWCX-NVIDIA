//! Scenario driver: builds outbound requests + demo tokens and runs them through the
//! middleware, returning the decision + audit per scenario. Doubles as a smoke test —
//! each scenario asserts the expected reason code.
//!
//! The principal is the **durable agent** (`agent_id`), not the ephemeral sandbox. The
//! headline scenario is "agent respawned into a new sandbox" — still authorized, because
//! the grant binds the agent, not the sandbox.

use ext_authz_core::types::reason;
use ext_authz_core::{
    canonical_request_hash, sha256_bytes, CanonicalRequestParts, ExtAuthzConfig, FailPolicy, Mode,
};
use ext_authz_middleware::{
    AuditEvent, Decision, EgressRequest, ExtAuthzMiddleware, RequestContext,
};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::token::{mint, Claims, Scope};

pub struct ScenarioResult {
    pub name: &'static str,
    /// One-line "why" for story mode — what this scenario exercises.
    pub narrative: &'static str,
    /// A short, printable rendering of the request body (empty if none).
    pub body_preview: String,
    pub body_len: usize,
    pub token_present: bool,
    pub expect_allow: bool,
    pub expect_reason: &'static str,
    pub got_allow: bool,
    pub got_reason: String,
    pub http_status: Option<u16>,
    pub message: String,
    pub crh_hex: Option<String>,
    pub bound_crh: Option<String>,
    pub audit: AuditEvent,
}

impl ScenarioResult {
    pub fn passed(&self) -> bool {
        self.got_allow == self.expect_allow && self.got_reason == self.expect_reason
    }
}

/// A short, single-line preview of a request body for story mode.
fn preview(body: &[u8]) -> String {
    if body.is_empty() {
        return String::new();
    }
    let s = String::from_utf8_lossy(body);
    if s.chars().count() > 38 {
        let t: String = s.chars().take(37).collect();
        format!("{t}…")
    } else {
        s.into_owned()
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn crh_hex(
    method: &str,
    scheme: &str,
    authority: &str,
    path: &str,
    query: &str,
    body: &[u8],
) -> String {
    hex::encode(canonical_request_hash(&CanonicalRequestParts {
        method,
        scheme,
        authority,
        path,
        query,
        body_sha256: sha256_bytes(body),
    }))
}

fn hdr(tok: Option<&str>) -> Vec<(String, String)> {
    let mut h = vec![("content-type".to_string(), "application/json".to_string())];
    if let Some(t) = tok {
        h.push(("X-Hawcx-HAAP-Token".to_string(), t.to_string()));
    }
    h
}

fn cfg(url: &str, mode: Mode, fail: FailPolicy) -> ExtAuthzConfig {
    ExtAuthzConfig {
        verifier_url: url.to_string(),
        mode,
        fail,
        timeout_ms: 1000,
        token_header: "x-hawcx-haap-token".into(),
        forward_headers: vec!["x-request-id".into()],
        strip_token_header: true,
        max_body_bytes: 1 << 20,
    }
}

fn ctx<'a>(agent: &'a str, sandbox: &'a str) -> RequestContext<'a> {
    RequestContext {
        agent_id: agent,
        on_behalf_of: None,
        agent_class: Some("demo-agent"),
        sandbox_id: sandbox,
        sandbox_name: Some("demo-sandbox"),
        endpoint_rule: "github-api",
        policy_revision: Some("rev-7"),
        request_id: Some("req-demo"),
    }
}

const AGENT: &str = "agt-7f3a";
const SANDBOX: &str = "sbx-run-1";
const AUTHORITY: &str = "api.github.com";
const PATH: &str = "/repos/acme/widgets/issues";

fn good_scope() -> Scope {
    Scope {
        method: "POST".into(),
        authority: AUTHORITY.into(),
        path_prefix: "/repos/acme/".into(),
    }
}

/// Mint a demo token bound to a durable agent principal.
fn token_for(
    agent: &str,
    jti: &str,
    crh: Option<String>,
    workload_selector: Option<String>,
    exp_unix_ms: i64,
    key: &[u8],
) -> String {
    mint(
        &Claims {
            jti: jti.into(),
            agent_id: agent.into(),
            on_behalf_of: None,
            workload_selector,
            scope: good_scope(),
            crh,
            exp_unix_ms,
        },
        key,
    )
}

/// Revoke an agent at the (demo) verifier — exercises the agent-level revocation path.
async fn revoke_agent(verifier_url: &str, agent_id: &str) {
    let url = verifier_url.replace("/v1/authorize", &format!("/v1/revoke/{agent_id}"));
    let _ = reqwest::Client::new().post(url).send().await;
}

async fn eval_one(
    mw: &ExtAuthzMiddleware,
    agent: &str,
    sandbox: &str,
    method: &str,
    path: &str,
    body: &[u8],
    token: Option<&str>,
) -> (Decision, AuditEvent) {
    let h = hdr(token);
    let req = EgressRequest {
        method,
        scheme: "https",
        authority: AUTHORITY,
        path,
        query: "",
        headers: &h,
        body,
    };
    mw.evaluate(&ctx(agent, sandbox), &req).await
}

/// (allowed, reason_code, http_status, message) extracted from a decision + audit.
fn decision_detail(d: &Decision, a: &AuditEvent) -> (bool, String, Option<u16>, String) {
    match d {
        Decision::Continue { .. } => (
            true,
            a.reason_code.clone(),
            None,
            "forwarded to upstream · token stripped".to_string(),
        ),
        Decision::Deny(v) => (
            false,
            v.reason_code.clone(),
            Some(v.http_status),
            v.message.clone(),
        ),
    }
}

/// Run the full scenario suite against `verifier_url` (whose HMAC key is `key`).
/// `down_url` should point at a closed port to exercise fail-closed.
pub async fn run_scenarios(verifier_url: &str, key: &[u8], down_url: &str) -> Vec<ScenarioResult> {
    let mw = ExtAuthzMiddleware::new(cfg(verifier_url, Mode::Enforce, FailPolicy::Closed)).unwrap();
    let mut out = Vec::new();
    let body = b"{\"title\":\"fix egress\"}";
    let exp = now_ms() + 60_000;

    macro_rules! record {
        ($name:expr, $narrative:expr, $body:expr, $token_present:expr, $allow:expr, $reason:expr, $d:expr, $a:expr) => {{
            let (got_allow, got_reason, http_status, message) = decision_detail(&$d, &$a);
            out.push(ScenarioResult {
                name: $name,
                narrative: $narrative,
                body_preview: preview($body),
                body_len: $body.len(),
                token_present: $token_present,
                expect_allow: $allow,
                expect_reason: $reason,
                got_allow,
                got_reason,
                http_status,
                message,
                crh_hex: $a.canonical_request_hash.clone(),
                bound_crh: None,
                audit: $a,
            });
        }};
    }

    // 1. happy path: valid token bound to the durable agent, in-scope, intent-bound
    {
        let crh = crh_hex("POST", "https", AUTHORITY, PATH, "", body);
        let t = token_for(AGENT, "jti-happy", Some(crh), None, exp, key);
        let (d, a) = eval_one(&mw, AGENT, SANDBOX, "POST", PATH, body, Some(&t)).await;
        record!(
            "allow (valid agent, in-scope, intent-bound)",
            "A single-use token bound to the durable agent, minted for exactly this request.",
            body,
            true,
            true,
            reason::OK,
            d,
            a
        );
    }

    // 2. agent respawn: SAME agent, NEW sandbox id -> still allowed (the headline)
    {
        let crh = crh_hex("POST", "https", AUTHORITY, PATH, "", body);
        let t = token_for(AGENT, "jti-respawn", Some(crh), None, exp, key);
        let (d, a) = eval_one(&mw, AGENT, "sbx-run-2", "POST", PATH, body, Some(&t)).await;
        record!(
            "allow: agent respawned into a new sandbox",
            "Same durable agent, fresh sandbox id after a respawn. Bound to the agent, not the sandbox — so it still authorizes.",
            body,
            true,
            true,
            reason::OK,
            d,
            a
        );
    }

    // 3. wrong agent: token minted for one agent, a different agent is acting
    {
        let crh = crh_hex("POST", "https", AUTHORITY, PATH, "", body);
        let t = token_for(AGENT, "jti-wrongagent", Some(crh), None, exp, key);
        let (d, a) = eval_one(&mw, "agt-intruder", SANDBOX, "POST", PATH, body, Some(&t)).await;
        record!(
            "deny: wrong agent",
            "A token minted for one agent, presented while a different agent is acting.",
            body,
            true,
            false,
            reason::AGENT_MISMATCH,
            d,
            a
        );
    }

    // 4. agent revoked: revocation is keyed on the agent, so it applies across sandboxes
    {
        revoke_agent(verifier_url, "agt-revoked").await;
        let crh = crh_hex("POST", "https", AUTHORITY, PATH, "", body);
        let t = token_for("agt-revoked", "jti-revoked", Some(crh), None, exp, key);
        let (d, a) = eval_one(&mw, "agt-revoked", SANDBOX, "POST", PATH, body, Some(&t)).await;
        record!(
            "deny: agent revoked (applies across sandboxes)",
            "The agent principal was revoked; every sandbox of that agent is denied — impossible to express if the key were the sandbox.",
            body,
            true,
            false,
            reason::AGENT_REVOKED,
            d,
            a
        );
    }

    // 5. workload constraint: the mandate pins a workload selector; off-selector sandbox
    {
        let crh = crh_hex("POST", "https", AUTHORITY, PATH, "", body);
        let t = token_for(
            AGENT,
            "jti-workload",
            Some(crh),
            Some("sbx-prod-".into()),
            exp,
            key,
        );
        let (d, a) = eval_one(&mw, AGENT, "sbx-dev-1", "POST", PATH, body, Some(&t)).await;
        record!(
            "deny: workload constraint (off-selector sandbox)",
            "The token's mandate pins a workload selector (sbx-prod-); the agent is acting from an off-selector sandbox.",
            body,
            true,
            false,
            reason::WORKLOAD_MISMATCH,
            d,
            a
        );
    }

    // 6. replay: reuse the SAME token a second time -> jti already consumed
    {
        let crh = crh_hex("POST", "https", AUTHORITY, PATH, "", body);
        let t = token_for(AGENT, "jti-replay", Some(crh), None, exp, key);
        let _ = eval_one(&mw, AGENT, SANDBOX, "POST", PATH, body, Some(&t)).await; // first: allowed
        let (d, a) = eval_one(&mw, AGENT, SANDBOX, "POST", PATH, body, Some(&t)).await; // replay
        record!(
            "deny: token replay (jti consumed)",
            "The same token, replayed. Each action is its own authorization — single-use.",
            body,
            true,
            false,
            reason::TOKEN_REPLAYED,
            d,
            a
        );
    }

    // 7. out of scope: mandate scoped to /repos/acme/, request hits /repos/evil/
    {
        let evil = "/repos/evil/exfil/contents";
        let crh = crh_hex("POST", "https", AUTHORITY, evil, "", body);
        let t = token_for(AGENT, "jti-scope", Some(crh), None, exp, key);
        let (d, a) = eval_one(&mw, AGENT, SANDBOX, "POST", evil, body, Some(&t)).await;
        record!(
            "deny: out of scope (path prefix)",
            "Mandate scoped to /repos/acme/; the request reaches for /repos/evil/.",
            body,
            true,
            false,
            reason::INTENT_MISMATCH,
            d,
            a
        );
    }

    // 8. intent mismatch: token crh-bound to the ORIGINAL body, request sends a new body
    {
        let crh = crh_hex("POST", "https", AUTHORITY, PATH, "", body);
        let bound = crh.clone();
        let t = token_for(AGENT, "jti-intent", Some(crh), None, exp, key);
        let tampered = b"{\"title\":\"exfiltrate secrets\"}";
        let (d, a) = eval_one(&mw, AGENT, SANDBOX, "POST", PATH, tampered, Some(&t)).await;
        record!(
            "deny: intent mismatch (body changed after mint)",
            "Token minted for this request, then the body was altered before sending.",
            tampered,
            true,
            false,
            reason::INTENT_MISMATCH,
            d,
            a
        );
        if let Some(last) = out.last_mut() {
            last.bound_crh = Some(bound);
        }
    }

    // 9. expired
    {
        let crh = crh_hex("POST", "https", AUTHORITY, PATH, "", body);
        let t = token_for(AGENT, "jti-exp", Some(crh), None, now_ms() - 1000, key);
        let (d, a) = eval_one(&mw, AGENT, SANDBOX, "POST", PATH, body, Some(&t)).await;
        record!(
            "deny: token expired",
            "A well-formed token whose lifetime has already elapsed.",
            body,
            true,
            false,
            reason::TOKEN_EXPIRED,
            d,
            a
        );
    }

    // 10. missing token: local deny, no verifier round trip
    {
        let (d, a) = eval_one(&mw, AGENT, SANDBOX, "POST", PATH, body, None).await;
        record!(
            "deny: token missing (local)",
            "No per-action token at all — denied locally, without troubling the verifier.",
            body,
            false,
            false,
            reason::TOKEN_MISSING,
            d,
            a
        );
    }

    // 11. fail-closed: verifier unreachable
    {
        let mw_down =
            ExtAuthzMiddleware::new(cfg(down_url, Mode::Enforce, FailPolicy::Closed)).unwrap();
        let crh = crh_hex("POST", "https", AUTHORITY, PATH, "", body);
        let t = token_for(AGENT, "jti-down", Some(crh), None, exp, key);
        let (d, a) = eval_one(&mw_down, AGENT, SANDBOX, "POST", PATH, body, Some(&t)).await;
        record!(
            "deny: fail-closed (verifier down)",
            "The verifier is unreachable. The secure default is to deny, not wave it through.",
            body,
            true,
            false,
            reason::VERIFIER_UNAVAILABLE,
            d,
            a
        );
    }

    out
}
