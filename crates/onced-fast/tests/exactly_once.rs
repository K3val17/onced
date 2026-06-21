//! End-to-end test of the async transport: exactly-once over real sockets with
//! a keep-alive `reqwest` client, against an `axum` backend that counts hits.

use onced_core::abuse::RuleSet;
use onced_core::engine::Engine;
use onced_core::store::MemoryStore;
use onced_fast::{serve_fast, Proxy};
use onced_gateway::gateway::{Gateway, NoopUpstream};
use onced_gateway::router::Router;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// Spawn a backend that returns `201 charged` and counts how many times it is hit.
async fn spawn_backend() -> (String, Arc<AtomicU32>) {
    let hits = Arc::new(AtomicU32::new(0));
    let backend_hits = Arc::clone(&hits);
    let app = axum::Router::new().fallback(move || {
        let hits = Arc::clone(&backend_hits);
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            "charged"
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, hits)
}

/// Spawn the async Onced gateway in front of `backend`, returning its address.
async fn spawn_onced(backend: &str) -> String {
    let shards = vec![Gateway::new(
        Engine::new(MemoryStore::new(), 30_000),
        RuleSet::new(),
        NoopUpstream,
    )];
    let router = Router::new(shards, vec![RuleSet::new()], NoopUpstream);
    let proxy = Arc::new(Proxy::new(router, format!("http://{backend}")));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = serve_fast(listener, proxy).await;
    });
    addr
}

#[tokio::test]
async fn retried_request_hits_backend_once_over_async_transport() {
    let (backend_addr, backend_hits) = spawn_backend().await;
    let onced_addr = spawn_onced(&backend_addr).await;

    // One keep-alive client for both requests (connection is reused).
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("http://{onced_addr}/charge");

    // Wait for the gateway to be live.
    for _ in 0..50 {
        if client
            .get(format!("http://{onced_addr}/healthz"))
            .send()
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // First request: runs the backend, tagged "created".
    let first = client
        .post(&url)
        .header("Idempotency-Key", "k-async")
        .body("amount=100")
        .send()
        .await
        .unwrap();
    assert_eq!(first.headers().get("onced-status").unwrap(), "created");
    assert_eq!(first.text().await.unwrap(), "charged");

    // Retry with the same key on the same keep-alive connection: replayed, no
    // second backend hit.
    let second = client
        .post(&url)
        .header("Idempotency-Key", "k-async")
        .body("amount=100")
        .send()
        .await
        .unwrap();
    assert_eq!(second.headers().get("onced-status").unwrap(), "replayed");

    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        1,
        "backend must be hit exactly once across the retry"
    );

    // Same key, different body -> 422, backend untouched.
    let mismatch = client
        .post(&url)
        .header("Idempotency-Key", "k-async")
        .body("amount=999")
        .send()
        .await
        .unwrap();
    assert_eq!(mismatch.status().as_u16(), 422);
    assert_eq!(backend_hits.load(Ordering::SeqCst), 1);
}
