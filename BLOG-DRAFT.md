# Per-action authorization at the sandbox edge

*Draft: co-authored Hawcx × NVIDIA OpenShell. For NVIDIA review of §2–§5 (your
interface, your framing); Hawcx owns §6. Nothing here should imply a shipped or
committed OpenShell interface before the egress-middleware RFC lands.*

*Authors: [NVIDIA OpenShell: Kirit + team] · [Hawcx: Ravi + team]*
*Companion code (Apache-2.0): this repository, runnable, with a recorded demo.*

---

When you give an AI agent a sandbox, you draw a boundary around it: this much filesystem,
this much network, these destinations and no others. OpenShell makes that boundary real
with default-deny egress and an explicit allowlist of hosts the sandbox may reach. It is
the right first control, and it answers a precise question: *may this sandbox talk to
`api.github.com` at all?*

It does not answer a second question. The gap between the two is where this post lives:
*is **this specific** call, this method, this path, this body, one the agent is allowed
to make, on behalf of this person, right now, exactly once?*

"`api.github.com` is allowed" and "open issue #4127 in `acme/widgets` with this body" are
statements at different granularities. The first is a network fact. The second is an
authorization decision about an action. An agent allowed to reach GitHub is not thereby
allowed to delete a repo, force-push to `main`, or post a comment that exfiltrates a
secret it just read, yet every one of those is "traffic to `api.github.com`." Per-action
authorization closes that gap, and the natural place to enforce it is a layer OpenShell is
already building.

## The seam: an egress-middleware hook

OpenShell is specifying a sandbox egress-middleware layer (RFC #1733): a hook that sees an
outbound request *after* network and L7 policy have accepted it and *before* it is
forwarded upstream, with the ability to inspect, transform, block, or annotate it. The
motivating consumer is Privacy Guard, middleware that scrubs sensitive content out of
requests on their way out.

The insight that started this collaboration is small and, in hindsight, obvious: an
**external per-action authorizer** wants to sit in exactly the same place and use exactly
the same capability. Privacy Guard reads the request content at the egress stage to redact
it. An authorizer binds a decision to the request content at the egress stage to allow or
deny it. Same hook, same stage, two consumers. An egress-middleware interface that serves
both beats a one-off, and pressure-testing it with a second, independent consumer is a
good way to learn whether it is actually general.

So we built that second consumer as a reference example to contribute alongside Privacy
Guard. It is a small Rust workspace, `ext-authz`, written against the proposed
egress-middleware hook as an authorizer: for each outbound request it asks an out-of-process
verifier ("is this action allowed?") and enforces the verdict before the request leaves the
sandbox.

## One layer, two consumers, and a primitive they share

Put a content-redactor and a content-authorizer on the same hook and a shared need falls
out: both want a **canonical hash of the request** in the metadata.

Privacy Guard wants it because the RFC calls for *audit evidence without storing raw
sensitive values*, so you can prove what was decided about a request without keeping the
body around. An authorizer wants the same hash because it is precisely what a verifier
binds its decision to: "I authorized the action whose canonical hash is `362355be…`," not
"I authorized some traffic to GitHub."

Pin one field in the v1 contract and you serve both. We call ours `crh_v1`:

```
crh_v1 = SHA-256( "openshell-crh-v1\0"
    || u32_be(len) || method      (uppercased)
    || u32_be(len) || scheme      (lowercased)
    || u32_be(len) || authority   (lowercased; default port stripped)
    || u32_be(len) || path        (bytes as forwarded; "" -> "/")
    || u32_be(len) || query       (bytes after '?', as forwarded)
    || u32_be(32)  || sha256(body) )
```

Two properties matter, and both are deliberate. First, every field is **length-prefixed**,
so there is no concatenation ambiguity: `"a" + "bc"` can never hash the same as
`"ab" + "c"`. Second, it normalizes only what is genuinely the same target (method case,
scheme case, the scheme's default port) and **nothing semantic**: no percent-decoding, no
dot-segment collapsing, no query reordering. Semantic normalization is exactly how request
smuggling sneaks back in. The hash binds the bytes as they will be forwarded, not a
prettied-up interpretation of them. And the body is hashed, not embedded, so the
descriptor and the audit trail built from it never carry raw content.

## Get the ordering right: bind the bytes that egress

Here is the part that is easy to get subtly wrong. A verifier's decision is sound only if
it covers *what actually leaves the sandbox*. That fixes where the authorizer sits in the
middleware chain:

```
agent request (+ per-action token)
  → L7 / network policy
  → content-mutating middleware   (Privacy Guard, rewrites)   ← BEFORE the authorizer
  → ext-authz                     (hash the egressing bytes,
                                   ask the verifier, enforce)  ← LAST pre-credential step
  → credential injection / SigV4  (action-neutral signing)    ← AFTER; never seen by the authorizer
  → upstream API
```

Anything that *mutates* the request (Privacy Guard's redaction, a header rewrite) must
run **before** the authorizer, or the verifier binds a decision to bytes that then change.
Anything that only adds *credential* material without changing the action `crh_v1` bound
(credential injection, the AWS SigV4 signing proposed in the OpenShell #1638 / #1694 work)
runs **after**, and the authorizer deliberately never sees the secret. That ordering is
sound only while signing stays action-neutral: it may add credential headers, but the
method, target, and body the verifier authorized must not change. The authorizer is the
last step that looks at the *action*; signing is the first step that looks at the
*credential*. Keeping those two concerns adjacent but ordered is the whole game.

This surfaces a small gap in the interface as sketched in #1694: `MiddlewareAction` is
`Forward` / `Passthrough` only, with no `Deny`. Privacy Guard's "block" and an
authorizer's "deny" both need a structured denial with a reason code that flows into the
audit sink. The reference includes that variant so the conversation about the final
interface has something concrete to react to.

## The contract, and a thing you can run

The middleware ↔ verifier contract is one round trip per request: a `POST /v1/authorize`
carrying the request descriptor (the canonical fields above, plus `crh_v1`), the
proxy-attested context (which agent is acting, on which sandbox, under which policy), and the forwarded
per-action token. The verifier answers `200` with `{ decision, reason_code, … }` for every
decision, allow or deny. A non-200 or a transport failure is a *verifier error*, never a
verdict, and the middleware's fail policy resolves it, fail-closed by default.

Crucially, the verifier does not trust the hash it is handed. It recomputes `crh_v1` from
the descriptor and rejects a mismatch, and it treats a descriptor it cannot canonicalize at
all as a distinct, hard failure rather than letting a malformed value slip through. Its
checks run as a short cascade, with the single-use nonce consumed *last* so that a forged,
stale, or out-of-scope token can never burn a legitimate request's nonce:

```
signature → wire version → expiry → recompute & bind crh → agent (the durable principal)
          → scope → exact intent → consume single-use jti → ALLOW
```

None of this is hypothetical. The example ships a reference verifier and an eleven-scenario
driver, and `cargo run --bin ext-authz-demo -- demo --story` walks them one at a time. The
verdicts below are real output.

| scenario | verdict | why |
|---|---|---|
| valid, in-scope, intent-bound | `ALLOW` / `OK` | the happy path |
| **agent respawned into a new sandbox** | `ALLOW` / `OK` | same agent, fresh sandbox; bound to the agent, not the sandbox |
| wrong agent | `DENY` / `AGENT_MISMATCH` | token minted for a different agent |
| agent revoked | `DENY` / `AGENT_REVOKED` | revoked once, denied across every sandbox it runs in |
| workload constraint | `DENY` / `WORKLOAD_MISMATCH` | acting from a sandbox outside the mandate's selector |
| token replayed | `DENY` / `TOKEN_REPLAYED` | single-use; the nonce is spent |
| out of scope | `DENY` / `INTENT_MISMATCH` | path outside the token's grant |
| **body changed after mint** | `DENY` / `INTENT_MISMATCH` | the canonical hash no longer matches |
| token expired | `DENY` / `TOKEN_EXPIRED` | lifetime elapsed |
| no token | `DENY` / `TOKEN_MISSING` | denied locally, no verifier round trip |
| verifier unreachable | `DENY` / `VERIFIER_UNAVAILABLE` | fail-closed (HTTP 503) |

The scenario worth pausing on is **body changed after mint**. A token is minted bound to
one request; the agent then alters the body before sending. The middleware hashes the
bytes that will actually egress, and the verifier watches the canonical hash diverge from
the one the token authorized:

```
request crh    934b208d…c2107508      ← over the changed body
token-bound    362355be…315bd21a   ≠  bytes changed after the token was minted
→ DENY · INTENT_MISMATCH · HTTP 403
```

That single comparison is the whole thesis made concrete: the decision is bound to the
action, byte for byte. Change the action, lose the authorization.

The demo makes two more things visible. The verifier runs **inline on the hot path** and
answers in well under a millisecond to about a millisecond in this setup, so per-action
authorization does not mean a slow request. And every decision emits **one structured audit
line carrying digests and codes only**: the canonical hash, the agent and sandbox, the
reason code, the latency. Never the token, never the body. (There is also a self-contained
interactive visual in `demo/index.html` for readers who would rather click through the
scenarios than read a table.)

Wiring it onto a destination reads like ordinary policy: an authorizer that fails closed in
front of GitHub, with credential signing after it for an AWS endpoint.

```yaml
middleware_configs:
  haap_authz:
    middleware: ext-authz
    stage: pre-credential
    verifier_url: http://127.0.0.1:18443/v1/authorize   # loopback/unix/mTLS in prod
    mode: enforce        # enforce | observe (a canary/rollout mode)
    fail: closed         # closed | open
```

## The principal: the durable agent, not the sandbox

There's a subtlety in *whose* action this is. The obvious answer at an egress proxy is the
sandbox; it's the identity the gateway already attests. But a sandbox is a *runtime*:
respawn the agent and it gets a new one. Bind a grant, a revocation, or an audit trail to the
sandbox and it evaporates on the next restart. The durable thing, the thing a policy is
actually *about*, is the **agent**. So the decision binds the agent (acting for a human,
within a mandate); the sandbox is execution context, recorded for audit and at most an
optional constraint. That is why the demo's headline scenario is *"agent respawned into a new
sandbox → still allowed."*

This reframing has a catch worth stating plainly, because it is the whole reason a credential
layer matters: binding to the agent is an improvement **only if the agent identity is attested
at least as well as the sandbox identity it replaces.** A SPIFFE SVID or an OIDC token is
cryptographically attested. A bare `agent_id` string in a request is self-asserted: any
caller can write any value. Swap one for the other naively and you have *weakened* the check.

And here the bearer-token ecosystem hits a wall. OIDC and SPIFFE JWT-SVIDs each prove a
*subject*, by *possession*, for a *TTL*. Neither binds the specific call, and neither
revokes at per-agent granularity inside a token's life:

| | attests identity | per-call proof | binds the action (body/intent) | per-agent revocation |
|---|---|---|---|---|
| OIDC / SPIFFE JWT-SVID (bearer) | yes | no | no | coarse (TTL) |
| DPoP | rides a bearer | yes | partial (method + URL only) | no |
| a per-call, proof-bound agent credential | yes | yes | **yes** | **yes** |

Safe agent-binding needs all four of the bottom row: an attested durable identity, per-call
proof-of-possession, binding to the *action* (the body and the tool arguments, not just the
host), and revocation keyed on the agent. That bottom row is what a real verifier puts behind
the `/v1/authorize` endpoint, which is what the next section is about.

## What sits behind the verifier (Hawcx)

The reference verifier is deliberately a stand-in: it validates a simple HMAC-signed demo
token so the example stays self-contained and dependency-free. The contract and the
per-action semantics (single-use, identity-bound, intent-bound, fail-closed) are the
transferable part, and they do not change when you put a production verifier behind the
same `/v1/authorize` endpoint.

Behind that endpoint, Hawcx's HAAP is the credential layer that delivers the whole bottom
row of that table. The agent enrolls once, so its identity is **attested**, not
self-asserted. Each call carries a **proof-of-possession over the request envelope** (body
and tool arguments included), which is both the per-call proof and the action/intent binding.
And revocation is **keyed on the agent**, so it holds across every sandbox that agent ever
runs in. That combination is the one no bearer token reaches: OIDC and SPIFFE JWT-SVIDs
attest a subject, but neither binds the specific call nor revokes at agent granularity. HAAP
does, and it consumes those bearer identities rather than competing with them. The demo
verifier is a HAAP-*shaped* miniature, not a transcription: a production HAAP verifier
consumes the single-use nonce atomically inside its own canonical verification cascade, and
treats `crh_v1` as one input to its proof-of-possession and intent machinery rather than as
the binding itself.

The hook and the contract are open by design, so bring your own guard service. But *open* is
not *trivial*: safely binding a per-action decision to a durable agent requires an attested,
per-call, revocable agent credential, and supplying that is what HAAP is for. (Its
credential-handling variants also carry the upstream secret sealed, unwrapping it only at the
verifier; see [HAAP patterns, further reading].)

## Where this goes

The egress-middleware RFC is where the interface gets pinned; this example is a second,
independent consumer that exists to keep that interface honest about being general rather
than Privacy-Guard-shaped. If it proves useful, it can live as an `examples/` entry once
the RFC lands. It is Apache-2.0 for exactly that reason.

If you are building agent infrastructure, the invitation is concrete: bring your own guard
service to the same hook. The open questions are the ones worth arguing about in the RFC:
the exact shape of a `Deny` action, where the canonical hash is specified, how the audit
sink consumes it. They are easier to argue with a runnable second consumer on the table.

*Links: OpenShell egress-middleware RFC (#1733) · the RFC PR · the `ext-authz` example.*
