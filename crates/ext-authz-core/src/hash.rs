//! `crh_v1` — the canonical request hash.
//!
//! The hash a per-action verifier binds its decision to, and the digest the proxy can
//! emit as privacy-preserving audit evidence. Two independent implementations MUST
//! produce byte-identical hashes for the same logical request, so the layout is fixed:
//!
//! ```text
//! crh_v1 = SHA-256(
//!     "openshell-crh-v1" || 0x00            // domain separator, NUL-terminated
//!     || u32_be(len(method))    || method      // ASCII-uppercased
//!     || u32_be(len(scheme))    || scheme      // ASCII-lowercased
//!     || u32_be(len(authority)) || authority   // lowercased; default port stripped
//!     || u32_be(len(path))      || path        // bytes as forwarded ("" -> "/")
//!     || u32_be(len(query))     || query       // bytes after '?', as forwarded ("" if none)
//!     || u32_be(32)             || sha256(body)
//! )
//! ```
//!
//! Design rules (and why):
//!
//! * **Length-prefix discipline.** Every variable-length field is prefixed with its
//!   big-endian u32 byte length, so no concatenation ambiguity exists (`"a"+"bc"` can
//!   never collide with `"ab"+"c"`). Same discipline as HAAP's org-token
//!   `binding_fields` layout (HAAP canonical spec §4.3.4.1).
//! * **Bind the bytes that egress.** Path and query are hashed exactly as the proxy
//!   will forward them — no percent-decoding, no dot-segment removal, no query
//!   reordering. Semantic normalization would re-open request-smuggling gaps the
//!   proxy already closed. Corollary: the hash MUST be computed at the verifier's
//!   position in the middleware chain — after any content-mutating middleware,
//!   before credential injection.
//! * **Case/port normalization only.** Method is uppercased, scheme and authority are
//!   lowercased, and the scheme's default port (`:443` for https, `:80` for http) is
//!   stripped — these are transport spellings of the same target, not different
//!   actions.
//! * **Headers are excluded** from v1. Hop-by-hop and credential-bearing headers churn
//!   in flight; the semantic action is method + target + body. A later version can add
//!   a sigv4-style signed-headers list without breaking v1 (the domain separator
//!   versions the layout).
//! * **Body is hashed, not embedded.** `sha256(body)` keeps the descriptor — and the
//!   audit trail — free of raw request content. An absent body hashes as the empty
//!   string (`e3b0c442…`), identical to a present-but-empty body.

use sha2::{Digest, Sha256};

/// Domain separator for `crh_v1`. Changing the layout requires a new domain string.
pub const CRH_DOMAIN: &[u8] = b"openshell-crh-v1\x00";

/// The pieces of a request that participate in `crh_v1`.
#[derive(Debug, Clone)]
pub struct CanonicalRequestParts<'a> {
    /// HTTP method as seen by the proxy (any case).
    pub method: &'a str,
    /// URL scheme (any case): `https` / `http`.
    pub scheme: &'a str,
    /// `host[:port]` as forwarded (any case). IPv6 hosts keep their brackets.
    pub authority: &'a str,
    /// Path bytes exactly as they will be forwarded upstream. Empty means `/`.
    pub path: &'a str,
    /// Query bytes after `?`, exactly as forwarded; empty string if none.
    pub query: &'a str,
    /// SHA-256 of the request body (empty-string hash when there is no body).
    pub body_sha256: [u8; 32],
}

/// SHA-256 of arbitrary bytes.
pub fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Lowercase the authority and strip the scheme's default port (`https`→`:443`,
/// `http`→`:80`). Non-default ports and IPv6 brackets are preserved verbatim.
///
/// Default-port stripping is applied only when the remaining host is a well-formed
/// authority host — a bracketed IPv6 literal (`[…]`) or a name/IPv4 with no embedded
/// colon. A bare (unbracketed) IPv6 such as `2001:db8::443` is not a valid HTTP
/// authority; rather than mangle it (`…::443` → `…:`), we leave it untouched.
pub fn normalize_authority(scheme_lower: &str, authority: &str) -> String {
    let a = authority.to_ascii_lowercase();
    let default_suffix = match scheme_lower {
        "https" => ":443",
        "http" => ":80",
        _ => return a,
    };
    if let Some(host) = a.strip_suffix(default_suffix) {
        let well_formed_host = !host.is_empty() && (host.ends_with(']') || !host.contains(':'));
        if well_formed_host {
            return host.to_string();
        }
    }
    a
}

/// Append a length-prefixed field: `u32_be(len) || bytes`.
///
/// Precondition: `bytes.len() <= u32::MAX`. Callers pass URL-derived fields (method,
/// scheme, authority, path, query) and a 32-byte body digest, all far below 4 GiB;
/// the `max_body_bytes` cap in the middleware keeps the body off this path entirely.
/// The `debug_assert` documents the bound — a field at/above 4 GiB would truncate the
/// length and re-open the concatenation ambiguity this prefixing exists to prevent.
fn put(h: &mut Sha256, bytes: &[u8]) {
    debug_assert!(
        bytes.len() <= u32::MAX as usize,
        "crh field exceeds u32 length"
    );
    h.update((bytes.len() as u32).to_be_bytes());
    h.update(bytes);
}

/// Compute `crh_v1` over the canonical parts.
pub fn canonical_request_hash(p: &CanonicalRequestParts<'_>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CRH_DOMAIN);
    put(&mut h, p.method.to_ascii_uppercase().as_bytes());
    let scheme = p.scheme.to_ascii_lowercase();
    put(&mut h, scheme.as_bytes());
    put(&mut h, normalize_authority(&scheme, p.authority).as_bytes());
    let path = if p.path.is_empty() { "/" } else { p.path };
    put(&mut h, path.as_bytes());
    put(&mut h, p.query.as_bytes());
    put(&mut h, &p.body_sha256);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crh(
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        query: &str,
        body: &[u8],
    ) -> [u8; 32] {
        canonical_request_hash(&CanonicalRequestParts {
            method,
            scheme,
            authority,
            path,
            query,
            body_sha256: sha256_bytes(body),
        })
    }

    #[test]
    fn case_and_default_port_are_normalized() {
        let a = crh("get", "HTTPS", "Example.COM:443", "/x", "", b"");
        let b = crh("GET", "https", "example.com", "/x", "", b"");
        assert_eq!(a, b);
    }

    #[test]
    fn empty_path_means_root() {
        assert_eq!(
            crh("GET", "https", "example.com", "", "", b""),
            crh("GET", "https", "example.com", "/", "", b"")
        );
    }

    #[test]
    fn non_default_port_is_significant() {
        assert_ne!(
            crh("GET", "https", "example.com:8443", "/", "", b""),
            crh("GET", "https", "example.com", "/", "", b"")
        );
    }

    #[test]
    fn http_default_port_is_80_not_443() {
        assert_eq!(
            crh("GET", "http", "example.com:80", "/", "", b""),
            crh("GET", "http", "example.com", "/", "", b"")
        );
        assert_ne!(
            crh("GET", "http", "example.com:443", "/", "", b""),
            crh("GET", "http", "example.com", "/", "", b"")
        );
    }

    #[test]
    fn query_bytes_are_not_reordered_or_decoded() {
        assert_ne!(
            crh("GET", "https", "example.com", "/", "a=1&b=2", b""),
            crh("GET", "https", "example.com", "/", "b=2&a=1", b"")
        );
        assert_ne!(
            crh("GET", "https", "example.com", "/p%2Fq", "", b""),
            crh("GET", "https", "example.com", "/p/q", "", b"")
        );
    }

    #[test]
    fn body_change_changes_hash() {
        assert_ne!(
            crh("POST", "https", "example.com", "/", "", b"{\"a\":1}"),
            crh("POST", "https", "example.com", "/", "", b"{\"a\":2}")
        );
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        // Same concatenated bytes, different field split -> different hashes.
        assert_ne!(
            crh("GET", "https", "example.com", "/ab", "c=1", b""),
            crh("GET", "https", "example.com", "/a", "bc=1", b"")
        );
    }

    #[test]
    fn ipv6_authority_preserved_and_port_stripped_exactly() {
        assert_eq!(
            crh("GET", "https", "[::1]:443", "/", "", b""),
            crh("GET", "https", "[::1]", "/", "", b"")
        );
        assert_ne!(
            crh("GET", "https", "[::1]:8443", "/", "", b""),
            crh("GET", "https", "[::1]", "/", "", b"")
        );
    }

    #[test]
    fn bare_ipv6_ending_in_443_is_not_mangled() {
        // A malformed (unbracketed) IPv6 authority that happens to end in ":443" must
        // be left intact, not truncated to "2001:db8:".
        assert_eq!(
            normalize_authority("https", "2001:db8::443"),
            "2001:db8::443"
        );
    }

    #[test]
    fn non_http_scheme_does_not_strip_ports() {
        // No default port is defined for non-http(s) schemes, so nothing is stripped.
        assert_eq!(
            normalize_authority("ws", "example.com:443"),
            "example.com:443"
        );
        assert_ne!(
            crh("GET", "ws", "example.com:443", "/", "", b""),
            crh("GET", "ws", "example.com", "/", "", b"")
        );
    }
}
