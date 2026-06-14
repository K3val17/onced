//! # onced-gateway
//!
//! The network face of Onced: a drop-in HTTP/1.1 reverse proxy that gives any
//! endpoint **exactly-once effect** (via `onced-core`'s idempotency engine) and
//! **abuse defense** (via its rate-limit rules), in any language, with no SDK.
//!
//! The HTTP stack is hand-rolled on `std::net` — zero external dependencies, so
//! the whole thing stays auditable and builds offline. It supports the common
//! case (request line + headers + `Content-Length` body, `Connection: close`).
//! TLS, HTTP/2, chunked transfer-encoding, and keep-alive are out of scope for
//! this MVP: front it with a real load balancer, and revisit the transport in
//! Phase 6 (io_uring / a vetted async stack) behind the same boundary.

#![forbid(unsafe_code)]

pub mod gateway;
pub mod http;
pub mod server;
