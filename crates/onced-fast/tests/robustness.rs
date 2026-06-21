//! Robustness of the async transport: oversized bodies are rejected, and a slow
//! backend times out (rather than pinning a task / shard lease forever).

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

/// Backend that counts hits and optionally sleeps `delay` before replying.
async fn spawn_backend(delay: Duration) -> (String, Arc<AtomicU32>) {
    let hits = Arc::new(AtomicU32::new(0));
    let backend_hits = Arc::clone(&hits);
    let app = axum::Router::new().fallback(move || {
        let hits = Arc::clone(&backend_hits);
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(delay).await;
            "ok"
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, hits)
}

/// Spawn the async gateway with a custom client + body cap, return its address.
async fn spawn_onced(backend: &str, client: reqwest::Client, max_body: usize) -> String {
    let shards = vec![Gateway::new(
        Engine::new(MemoryStore::new(), 30_000),
        RuleSet::new(),
        NoopUpstream,
    )];
    let router = Router::new(shards, vec![RuleSet::new()], NoopUpstream);
    let proxy = Arc::new(Proxy::with_client(
        router,
        format!("http://{backend}"),
        client,
        max_body,
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = serve_fast(listener, proxy).await;
    });
    addr
}

async fn wait_live(client: &reqwest::Client, addr: &str) {
    for _ in 0..50 {
        if client
            .get(format!("http://{addr}/healthz"))
            .send()
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn oversized_body_is_rejected_with_413_without_touching_backend() {
    let (backend, backend_hits) = spawn_backend(Duration::ZERO).await;
    // 1 KiB body cap.
    let onced = spawn_onced(&backend, reqwest::Client::new(), 1024).await;

    let client = reqwest::Client::new();
    wait_live(&client, &onced).await;

    let resp = client
        .post(format!("http://{onced}/charge"))
        .header("Idempotency-Key", "big")
        .body(vec![b'x'; 5000]) // > cap
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 413);
    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        0,
        "an oversized request must be rejected before the backend is touched"
    );
}

#[tokio::test]
async fn slow_backend_times_out_to_502_rather_than_hanging() {
    // Backend sleeps 2s; the gateway's client times out at 150ms.
    let (backend, _hits) = spawn_backend(Duration::from_secs(2)).await;
    let short_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(150))
        .build()
        .unwrap();
    let onced = spawn_onced(&backend, short_client, 1 << 20).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    wait_live(&client, &onced).await;

    let resp = client
        .post(format!("http://{onced}/charge"))
        .header("Idempotency-Key", "slow")
        .body("x")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status().as_u16(),
        502,
        "a slow backend must surface as 502, not hang the request"
    );
}
