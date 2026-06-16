# OpenShell ext-authz middleware (reference implementation)

A small, runnable **external-authorization egress middleware** for OpenShell sandboxes —
the example Hawcx offered to contribute alongside Privacy Guard for the sandbox
egress-middleware RFC ([NVIDIA/OpenShell#1733](https://github.com/NVIDIA/OpenShell/issues/1733)).

It demonstrates that the *same* egress-middleware layer that powers Privacy Guard also
serves an **external per-action authorizer**: a middleware that, for each outbound
request, asks an out-of-process verifier ("guard service") "is *this* action allowed?"
and enforces the verdict before the request leaves the sandbox.

> **Status:** reference / illustrative. The verifier here uses a deliberately simple
> demo token (HMAC over JSON claims) — *not* the real HAAP wire format — so the example
> is self-contained. The point is the **middleware ↔ verifier contract** and the
> **per-action semantics**, both of which carry over unchanged to a real verifier.
>
> **License:** Apache-2.0 (matches OpenShell) — see [`LICENSE`](LICENSE) — so it can
> drop into the RFC's `examples/` as-is.
>
> **Reviewed:** the implementation passed an in-depth validity/correctness review —
> 47 tests, `clippy -D warnings` clean, fail-closed by default.

## Why it's interesting for #1733

* The expensive capability — request-content access at the egress stage — is **already
  required by Privacy Guard**. A per-action authorizer needs almost nothing more, if a
  couple of fields are pinned in the v1 contract:
  * a **canonical request hash** (`crh_v1`) in the metadata — what the verifier binds
    its decision to, and the same privacy-preserving digest the "audit evidence without
    raw sensitive values" goal points at;
  * the acting **agent identity** — the *durable* principal (it survives sandbox respawn),
    not the ephemeral sandbox, which is recorded as execution context;
  * a **synchronous deny** with a structured reason into the audit sink.
* It exercises the **ordering** rule: the authorizer binds *the bytes that egress*, so
  it runs **after** any content-mutating middleware and **before** credential injection.
  The only work allowed *after* it is credential material that does not change the action
  `crh_v1` bound — e.g. the AWS SigV4 signing path proposed in
  [PR #1638](https://github.com/NVIDIA/OpenShell/pull/1638) /
  [#1694](https://github.com/NVIDIA/OpenShell/issues/1694), and only while signing merely
  adds credential headers and leaves the method, target, and body untouched.
* It shows the enforcement variant the merged action type needs: #1694's
  `MiddlewareAction` is `Forward`/`Passthrough` only — there is no `Deny`.

## Identity: the principal is the durable agent

The authorization subject is the **durable `agent_id`** the gateway attests — it survives
sandbox respawn — qualified by the on-behalf-of human and the agent's mandate. The
**sandbox is runtime context**: recorded for audit and bound only as an *optional* workload
constraint, never the principal. So a grant, a revocation, or an audit trail follows the
*agent*, not a disposable sandbox. The verifier's principal check is agent binding
(`AGENT_MISMATCH` / `AGENT_REVOKED`); `WORKLOAD_MISMATCH` is the optional sandbox constraint.
The egress-hook context therefore carries `agent_id` (subject) alongside `sandbox_id`
(context) — the schema this example proposes the hook adopt. In this reference `agent_id`
is a plain string the gateway is trusted to attest; a canonical HAAP integration backs that
durable principal with attested/enrolled identity material (e.g. `agent_instance_id` plus
Pattern X `idp_binding`), so the principal is sound identity rather than a self-asserted
value — the property the whole agent-binding argument rests on.

## Layout

```
crates/
  ext-authz-core/        wire contract + the canonical request hash (crh_v1) + config; no I/O
  ext-authz-middleware/  the middleware: extract token, hash, call verifier, enforce, audit
  ext-authz-demo/        a reference HAAP-shaped verifier + a scenario driver (also a smoke test)
policy-example.yaml      the #1694-shaped middleware_configs policy block
demo/index.html          a self-contained interactive visual of one decision (blog / keynote)
```

## Quickstart

```bash
# Self-contained end-to-end demo (spins a verifier in-process, runs 11 scenarios).
cargo run --bin ext-authz-demo -- demo

# Same scenarios, walked one at a time with pauses — built to be screen-recorded.
cargo run --bin ext-authz-demo -- demo --story

# Run the reference verifier as a standalone service.
cargo run --bin ext-authz-demo -- verifier --listen 127.0.0.1:18443

# Tests (unit + integration) and lints.
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The demo prints a PASS/DENY line per scenario and one audit event; it exits non-zero if
any scenario deviates from its expected outcome.

## The request lifecycle

```
agent request (+ per-action token header)
  → L7 / network policy            (OpenShell)
  → content-mutating middleware     (e.g. Privacy Guard)        ── runs BEFORE the authorizer
  → ext-authz middleware            (this crate)                ── LAST pre-credential
        · compute crh_v1 over the request as it will egress
        · POST AuthorizeRequest → verifier (strict timeout)
        · enforce verdict: Continue (strip token header) | Deny | fail-policy
        · emit a structured audit event (digest only; no token, no body)
  → credential injection + sigv4    (OpenShell / #1638)         ── action-neutral; never seen by the authorizer
  → upstream API
```

## The wire contract (`ext-authz-core::types`)

One round trip per request: `POST /v1/authorize` with an `AuthorizeRequest`
(request descriptor + crh + proxy context + the forwarded credential header), answered
with an `AuthorizeResponse` (`{ decision, reason_code, message?, receipt_id?, evidence? }`).

The verifier MUST recompute `crh_v1` from the descriptor and reject on mismatch
(`CRH_MISMATCH`) — it never trusts the middleware's hash blindly.

### `crh_v1` — the canonical request hash

```
crh_v1 = SHA-256( "openshell-crh-v1\0"
    || u32_be(len) || method      (uppercased)
    || u32_be(len) || scheme      (lowercased)
    || u32_be(len) || authority   (lowercased; default port stripped)
    || u32_be(len) || path        (bytes as forwarded; "" -> "/")
    || u32_be(len) || query        (bytes after '?', as forwarded)
    || u32_be(32)  || sha256(body) )
```

Length-prefixed (no concatenation ambiguity), normalized only for case/default-port,
**not** semantically (no percent-decoding, no query reordering — that would re-open
request-smuggling gaps). Body is hashed, never embedded, so the descriptor and the
audit trail stay free of raw content.

## Configuration

See `policy-example.yaml`. Two orthogonal knobs govern degraded behavior:

* `mode`: `enforce` (verdicts block) vs `observe` (never block; log the would-be verdict
  — a canary/rollout mode).
* `fail`: `closed` (verifier unreachable ⇒ deny; the #1733 secure default) vs `open`
  (verifier unreachable ⇒ pass, audited as degraded).

## Security model & deployment requirements

The middleware's guarantees are conditional on the host honoring three contracts:

1. **Ordering.** The request the proxy forwards must be byte-identical to what was hashed
   — so the authorizer runs *after* all content-mutating middleware and *before*
   credential injection. The crh deliberately excludes headers (the semantic action is
   method + target + body); header normalization before this stage is the host's job.
2. **Header stripping.** On allow, the host MUST remove *every* instance of the token
   header, matched case-insensitively, before the request egresses. The middleware
   refuses a request carrying more than one token header (`TOKEN_AMBIGUOUS`) rather than
   first-matching.
3. **Verifier transport.** The per-action credential crosses to the verifier and the
   verifier dispenses ALLOW verdicts, so this channel MUST be mutually authenticated and
   confidential — a loopback unix socket with restrictive permissions, or mTLS. The
   middleware warns at construction on a plaintext non-loopback `verifier_url`.

The verifier independently rejects a non-canonical descriptor (`DESCRIPTOR_MALFORMED`)
and a non-matching hash (`CRH_MISMATCH`), and stamps `evidence.binding` (`exact` vs
`coarse`) so scope-only grants are visible in the audit trail. The HMAC token, the
in-memory replay store, and the plaintext loopback transport are reference
simplifications: a production deployment swaps in the real credential, a shared
TTL-bounded replay store, and an authenticated (unix-socket or mTLS) transport.

## Adapting to the real RFC interface

This crate is written against a small `EgressMiddleware::on_request(ctx, req)` seam (see
`ext-authz-middleware/src/lib.rs`). When `rfc/0005-sandbox-egress-middleware` lands its
concrete signature, the adapter is mechanical: map the RFC's request/headers/context
onto `EgressRequest` + `RequestContext`, map `Decision::Continue` to the RFC's
forward/passthrough (removing the configured headers) and `Decision::Deny` to its
block/reject variant, and route `AuditEvent` to the RFC's audit sink. The crh
canonicalization and the verifier contract are unaffected.
