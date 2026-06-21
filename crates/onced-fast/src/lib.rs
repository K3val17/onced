//! # onced-fast
//!
//! A high-performance async transport for Onced, built on **tokio + axum** for
//! the front door and a **connection-pooled `reqwest` client** for the backend
//! forward. Compared to the zero-dependency `onced-gateway` server
//! (thread-per-connection HTTP/1.1, a fresh backend socket per request) it adds:
//!
//! - HTTP keep-alive and a pooled, reused backend connection (no per-request
//!   TCP/TLS handshake);
//! - an async backend forward, so an in-flight upstream call costs a task, not a
//!   thread — thousands can be in flight at once;
//! - TLS to the backend (rustls), for `https://` upstreams.
//!
//! The exactly-once engine, abuse rules, sharding, and durability are reused
//! verbatim from `onced-gateway`: this crate is *only* a transport. It drives
//! [`Router::handle_async`], whose two-phase design holds the per-shard lock only
//! briefly (never across the `await` of the backend call), so correctness is
//! identical to the synchronous path.

#![forbid(unsafe_code)]

use onced_core::store::Store;
use onced_gateway::gateway::NoopUpstream;
use onced_gateway::http::{Request, Response};
use onced_gateway::router::Router;
use onced_gateway::server::now_ms;
use std::sync::Arc;

/// Largest request body the proxy will buffer (16 MiB). Bigger requests are
/// rejected rather than read unbounded into memory.
const MAX_BODY: usize = 16 * 1024 * 1024;

/// The async proxy: a sharded [`Router`] plus a pooled backend client.
pub struct Proxy<S: Store> {
    router: Router<S, NoopUpstream>,
    client: reqwest::Client,
    /// Backend base, e.g. `http://127.0.0.1:9000` or `https://api.internal`.
    backend: String,
}

impl<S: Store + Send + Sync + 'static> Proxy<S> {
    /// Build a proxy over `router`, forwarding to `backend` (a base URL such as
    /// `http://host:port`). A bare `host:port` is treated as `http://host:port`.
    pub fn new(router: Router<S, NoopUpstream>, backend: impl Into<String>) -> Self {
        let mut backend = backend.into();
        if !backend.starts_with("http://") && !backend.starts_with("https://") {
            backend = format!("http://{backend}");
        }
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(64)
            .build()
            .expect("build reqwest client");
        Self {
            router,
            client,
            backend,
        }
    }

    /// Expose the router for out-of-band operations (e.g. the periodic prune).
    pub fn router(&self) -> &Router<S, NoopUpstream> {
        &self.router
    }

    /// Convert one incoming request, run it through the engine (forwarding to the
    /// backend asynchronously only when needed), and convert the result back.
    async fn dispatch(&self, req: axum::extract::Request) -> axum::response::Response {
        let (parts, body) = req.into_parts();
        let body = match axum::body::to_bytes(body, MAX_BODY).await {
            Ok(bytes) => bytes.to_vec(),
            Err(_) => return text_response(413, "request body too large"),
        };
        let onced_req = to_onced_request(&parts, body);
        let now = now_ms();

        // Capture what the (possibly never-invoked) backend forward needs.
        let client = self.client.clone();
        let backend = self.backend.clone();
        let to_forward = onced_req.clone();

        let response = self
            .router
            .handle_async(&onced_req, now, move || async move {
                forward(&client, &backend, &to_forward).await
            })
            .await;

        to_axum_response(response)
    }
}

/// Run the async server until the listener stops. `proxy` is shared across all
/// connection tasks.
pub async fn serve_fast<S>(
    listener: tokio::net::TcpListener,
    proxy: Arc<Proxy<S>>,
) -> std::io::Result<()>
where
    S: Store + Send + Sync + 'static,
{
    let app = axum::Router::new()
        .fallback(proxy_handler::<S>)
        .with_state(proxy);
    axum::serve(listener, app).await
}

/// axum fallback: every method and path flows through the proxy.
async fn proxy_handler<S>(
    axum::extract::State(proxy): axum::extract::State<Arc<Proxy<S>>>,
    req: axum::extract::Request,
) -> axum::response::Response
where
    S: Store + Send + Sync + 'static,
{
    proxy.dispatch(req).await
}

/// Forward `req` to `backend` with the pooled async client.
async fn forward(
    client: &reqwest::Client,
    backend: &str,
    req: &Request,
) -> std::io::Result<Response> {
    let url = format!("{backend}{}", req.target);
    let method = reqwest::Method::from_bytes(req.method.as_bytes())
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut rb = client.request(method, &url);
    for (name, value) in &req.headers {
        // Let the client own these: it sets its own Host and framing.
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        rb = rb.header(name, value);
    }
    if !req.body.is_empty() {
        rb = rb.body(req.body.clone());
    }

    let resp = rb
        .send()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let status = resp.status().as_u16();
    let mut headers = Vec::new();
    for (name, value) in resp.headers() {
        if let Ok(v) = value.to_str() {
            headers.push((name.as_str().to_string(), v.to_string()));
        }
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .to_vec();
    Ok(Response {
        status,
        headers,
        body,
    })
}

/// Build an Onced [`Request`] from an axum request's parts and buffered body.
fn to_onced_request(parts: &axum::http::request::Parts, body: Vec<u8>) -> Request {
    let target = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let mut headers = Vec::new();
    for (name, value) in &parts.headers {
        if let Ok(v) = value.to_str() {
            headers.push((name.as_str().to_string(), v.to_string()));
        }
    }
    Request {
        method: parts.method.as_str().to_string(),
        target,
        headers,
        body,
    }
}

/// Convert an Onced [`Response`] into an axum response.
fn to_axum_response(resp: Response) -> axum::response::Response {
    let mut builder = axum::http::Response::builder().status(resp.status);
    for (name, value) in resp.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(axum::body::Body::from(resp.body))
        .unwrap_or_else(|_| text_response(502, "malformed upstream response"))
}

fn text_response(status: u16, message: &str) -> axum::response::Response {
    axum::http::Response::builder()
        .status(status)
        .body(axum::body::Body::from(message.to_string()))
        .expect("static response is always valid")
}
