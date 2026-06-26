//! ext-authz-core — the deployment-agnostic pieces of an external-authorization
//! egress middleware for OpenShell (NVIDIA/OpenShell#1733):
//!
//! * [`hash`] — `crh_v1`, the canonical request hash: the field that lets a verifier bind its decision to the bytes that egress, and a privacy-preserving audit digest. RFC 0009 requires raw-value-free audit evidence but does not itself specify a request hash; `crh_v1` is the digest this example proposes to serve that.
//! * [`types`] — the `AuthorizeRequest` / `AuthorizeResponse` wire contract between the in-proxy middleware and an out-of-process verifier ("guard service").
//! * [`config`] — operator-facing middleware configuration (maps onto the `middleware_configs` policy block proposed in NVIDIA/OpenShell#1694).
//!
//! This crate is intentionally free of I/O and of any token format: the middleware is
//! token-opaque (it transports credentials to the verifier and enforces the verdict).

pub mod config;
pub mod hash;
pub mod types;

pub use config::{ExtAuthzConfig, FailPolicy, Mode, DEFAULT_TOKEN_HEADER};
pub use hash::{canonical_request_hash, sha256_bytes, CanonicalRequestParts, CRH_DOMAIN};
pub use types::{AuthorizeRequest, AuthorizeResponse, Decision, RequestDescriptor, WireContext};
