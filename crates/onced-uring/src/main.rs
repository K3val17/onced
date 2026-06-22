//! io_uring thread-per-core transport for Onced (Linux-only, built on monoio).
//!
//! The "raw speed" data plane: a monoio runtime drives an io_uring
//! submission/completion ring, so accept/read/write go through batched,
//! near-zero-overhead system calls instead of one syscall per op on a blocked
//! thread. Excluded from the workspace and built only on Linux CI (io_uring does
//! not exist on macOS).
//!
//! It reuses the engine wholesale: the same exactly-once [`Router`] and the same
//! hand-rolled HTTP codec from `onced-gateway`. Only the I/O is different —
//! io_uring instead of thread-per-connection. Correctness is identical because
//! it drives [`Router::handle_async`], whose backend forward here runs over an
//! io_uring socket.
//!
//! Config: `ONCED_LISTEN` (default `0.0.0.0:8080`), `ONCED_BACKEND`
//! (default `127.0.0.1:9000`).

use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
use monoio::net::{TcpListener, TcpStream};
use onced_core::abuse::RuleSet;
use onced_core::engine::Engine;
use onced_core::store::MemoryStore;
use onced_gateway::gateway::{Gateway, NoopUpstream};
use onced_gateway::http::{parse_request, parse_response, write_request, write_response, Request, Response};
use onced_gateway::router::Router;
use onced_gateway::server::now_ms;
use std::net::SocketAddr;
use std::rc::Rc;

const LEASE_MS: u64 = 30_000;
/// Cap on bytes buffered while waiting for a full request (guards against a peer
/// that never completes one).
const MAX_REQUEST: usize = 256 * 1024;

type OncedRouter = Router<MemoryStore, NoopUpstream>;

#[monoio::main(timer_enabled = true)]
async fn main() {
    let listen = std::env::var("ONCED_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let backend: SocketAddr = std::env::var("ONCED_BACKEND")
        .unwrap_or_else(|_| "127.0.0.1:9000".to_string())
        .parse()
        .expect("ONCED_BACKEND must be host:port");

    // One shard, empty rule set (room to grow to thread-per-core sharding).
    let shard = Gateway::new(Engine::new(MemoryStore::new(), LEASE_MS), RuleSet::new(), NoopUpstream);
    let router: Rc<OncedRouter> = Rc::new(Router::new(vec![shard], vec![RuleSet::new()], NoopUpstream));

    let listener = TcpListener::bind(&listen).expect("onced-uring: bind failed");
    eprintln!("onced-uring: io_uring server on {listen}, forwarding to {backend}");

    loop {
        let Ok((stream, _peer)) = listener.accept().await else {
            continue;
        };
        let router = Rc::clone(&router);
        monoio::spawn(async move {
            let _ = serve_connection(stream, router, backend).await;
        });
    }
}

/// Read one request off `stream`, run it through the engine (forwarding to the
/// backend over io_uring only when needed), and write the response back.
async fn serve_connection(
    mut stream: TcpStream,
    router: Rc<OncedRouter>,
    backend: SocketAddr,
) -> std::io::Result<()> {
    let Some(request) = read_request(&mut stream).await? else {
        return Ok(()); // clean EOF or unparseable; drop the connection
    };

    let now = now_ms();
    let to_forward = request.clone();
    let response = router
        .handle_async(&request, now, move || async move {
            forward(backend, &to_forward).await
        })
        .await;

    let mut out = Vec::new();
    write_response(&mut out, &response)?;
    let (res, _) = stream.write_all(out).await;
    res?;
    Ok(())
}

/// Accumulate bytes until a full HTTP request parses (the hand-rolled parser
/// needs the complete request + Content-Length body). Returns `None` on a clean
/// EOF or a request that never completes within `MAX_REQUEST`.
async fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<Request>> {
    let mut acc: Vec<u8> = Vec::new();
    loop {
        let chunk = vec![0u8; 8192];
        let (res, chunk) = stream.read(chunk).await;
        let n = res?;
        if n == 0 {
            return Ok(None); // peer closed
        }
        acc.extend_from_slice(&chunk[..n]);

        let mut cursor: &[u8] = &acc;
        match parse_request(&mut cursor) {
            Ok(Some(request)) => return Ok(Some(request)),
            Ok(None) => return Ok(None),
            // Incomplete so far — read more, unless the peer is flooding us.
            Err(_) if acc.len() < MAX_REQUEST => continue,
            Err(_) => return Ok(None),
        }
    }
}

/// Forward `request` to `backend` over an io_uring socket and parse the reply.
async fn forward(backend: SocketAddr, request: &Request) -> std::io::Result<Response> {
    let mut wire = Vec::new();
    write_request(&mut wire, request)?; // owns Content-Length + Connection: close

    let mut stream = TcpStream::connect(backend).await?;
    let (res, _) = stream.write_all(wire).await;
    res?;

    // The backend sends `Connection: close`, so read to EOF then parse.
    let mut acc: Vec<u8> = Vec::new();
    loop {
        let chunk = vec![0u8; 8192];
        let (res, chunk) = stream.read(chunk).await;
        let n = res?;
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&chunk[..n]);
    }
    let mut cursor: &[u8] = &acc;
    parse_response(&mut cursor)
}
