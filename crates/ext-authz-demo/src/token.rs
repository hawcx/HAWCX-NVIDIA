//! A DEMO per-action token — NOT the real HAAP wire format.
//!
//! Just enough structure to exercise the middleware↔verifier contract and the
//! per-action semantics (single-use, identity-bound, intent-bound). Real HAAP tokens
//! are designated-verifier Schnorr-signed wire structures — a 184-byte fixed prefix
//! plus an encrypted body — verified by the §9.1 RS verification cascade; here we use an
//! HMAC-SHA256 over a deterministic JSON encoding of
//! the claims so the demo is self-contained and dependency-light.
//!
//! Layout: `base64url(claims_json) || "." || base64url(HMAC-SHA256(claims_json, key))`.
//!
//! The signed bytes are the exact `claims_json` produced at mint; `verify` checks the
//! MAC over the *transmitted* bytes before deserializing, so mint and verify never need
//! to re-serialize identically. This is NOT a canonical-JSON scheme (it does not sort
//! map keys; it relies on `Claims`' fixed field order) and must not be reused where the
//! signer and verifier are different implementations — a real token uses a fixed wire
//! layout for exactly that reason.

use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The fixed demo HMAC key (NOT for production). Hex: `64656d6f2d6861776378`.
pub const DEMO_KEY: &[u8] = b"demo-hawcx";

/// Coarse scope grant: a token is valid only for this (method, authority) and paths
/// under `path_prefix`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub method: String,
    pub authority: String,
    pub path_prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    /// Single-use nonce (consumed at the verifier).
    pub jti: String,
    /// The durable agent principal this token was minted for — the authorization subject.
    /// Bound to the agent, not the sandbox, so the grant survives respawn.
    pub agent_id: String,
    /// Optional: the human the agent acts for. When set, the request's `on_behalf_of`
    /// must equal it (the mandate's "on behalf of").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    /// Optional workload constraint: the acting `sandbox_id` must start with this selector
    /// (a label/prefix). Unset = the agent may act from any sandbox, and the sandbox is
    /// audit context only — not an authorization input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_selector: Option<String>,
    pub scope: Scope,
    /// Optional exact intent binding: the `crh_v1` hex this token authorizes. When
    /// present (`exact` grant), the request's canonical hash MUST equal it — the body
    /// and full target are bound. When absent (`coarse` grant), only the scope
    /// (method/authority/path-prefix) is checked: the body, the exact path, and the
    /// scheme are **unbound**, so the per-action body-binding guarantee does not apply. A
    /// per-action authorizer should default to minting `exact` grants; the verifier
    /// audits which kind it honored (`evidence.binding`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crh: Option<String>,
    pub exp_unix_ms: i64,
}

/// Mint a demo token: HMAC-SHA256 over the deterministic claims encoding.
pub fn mint(claims: &Claims, key: &[u8]) -> String {
    let body = claims_bytes(claims);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(body.as_bytes());
    let sig = mac.finalize().into_bytes();
    format!("{}.{}", B64.encode(body.as_bytes()), B64.encode(sig))
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    Malformed,
    BadSignature,
}

/// Verify the HMAC and decode the claims (constant-time MAC check). Does NOT check
/// expiry/scope/jti — those are policy checks the caller layers on top.
pub fn verify(token: &str, key: &[u8]) -> Result<Claims, VerifyError> {
    let (b_body, b_sig) = token.split_once('.').ok_or(VerifyError::Malformed)?;
    let body = B64.decode(b_body).map_err(|_| VerifyError::Malformed)?;
    let sig = B64.decode(b_sig).map_err(|_| VerifyError::Malformed)?;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&body);
    mac.verify_slice(&sig)
        .map_err(|_| VerifyError::BadSignature)?;
    serde_json::from_slice(&body).map_err(|_| VerifyError::Malformed)
}

/// Serialize the claims to the bytes that get signed. Deterministic for this struct
/// (serde_json emits fields in `Claims` declaration order), which is all the demo needs
/// since `verify` authenticates the transmitted bytes rather than re-serializing. This
/// is not a general canonical-JSON encoding — see the module docs.
fn claims_bytes(claims: &Claims) -> String {
    serde_json::to_string(claims).expect("serializing a plain struct cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Claims {
        Claims {
            jti: "j1".into(),
            agent_id: "agt-1".into(),
            on_behalf_of: None,
            workload_selector: None,
            scope: Scope {
                method: "POST".into(),
                authority: "api.github.com".into(),
                path_prefix: "/repos/acme/".into(),
            },
            crh: Some("ab".repeat(32)),
            exp_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn mint_then_verify_roundtrips() {
        let key = b"demo-key";
        let t = mint(&sample(), key);
        let c = verify(&t, key).unwrap();
        assert_eq!(c.jti, "j1");
        assert_eq!(c.scope.authority, "api.github.com");
    }

    #[test]
    fn wrong_key_fails_signature() {
        let t = mint(&sample(), b"demo-key");
        assert_eq!(verify(&t, b"other-key"), Err(VerifyError::BadSignature));
    }

    #[test]
    fn tampered_body_fails_signature() {
        let t = mint(&sample(), b"demo-key");
        let (_, sig) = t.split_once('.').unwrap();
        let forged = Claims {
            jti: "j2".into(),
            ..sample()
        };
        let tampered = format!("{}.{}", B64.encode(claims_bytes(&forged).as_bytes()), sig);
        assert_eq!(
            verify(&tampered, b"demo-key"),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn garbage_is_malformed() {
        assert_eq!(verify("not-a-token", b"k"), Err(VerifyError::Malformed));
    }

    #[test]
    fn demo_key_hex_matches_the_cli_default() {
        // The standalone `verifier --key-hex` default (main.rs) MUST decode to DEMO_KEY,
        // or tokens minted by the `demo` path won't verify against the standalone server.
        assert_eq!(hex::decode("64656d6f2d6861776378").unwrap(), DEMO_KEY);
    }

    #[test]
    fn unknown_claim_field_is_rejected() {
        // deny_unknown_fields: a token body with an extra field must not deserialize.
        let json = r#"{"jti":"j","agent_id":"a","scope":{"method":"GET","authority":"a","path_prefix":"/"},"exp_unix_ms":1,"extra":"x"}"#;
        assert!(serde_json::from_str::<Claims>(json).is_err());
    }
}
