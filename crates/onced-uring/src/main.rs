//! io_uring thread-per-core transport for Onced (Linux-only, built on monoio).
//!
//! The "raw speed" data plane. One monoio runtime is pinned per CPU, each over
//! its own io_uring submission/completion ring, so accept/read/write go through
//! batched, near-zero-overhead system calls instead of one syscall per op on a
//! blocked thread. Every core accepts on its own `SO_REUSEPORT` socket and the
//! kernel load-balances connections across them (the Seastar / shared-nothing
//! pattern). Excluded from the workspace and built only on Linux CI.
//!
//! Correctness is identical to the other transports: all cores share one
//! sharded [`Router`], so a given key always maps to the same shard and
//! exactly-once holds. Only the I/O is io_uring.
//!
//! Config: `ONCED_LISTEN` (default `0.0.0.0:8080`), `ONCED_BACKEND`
//! (default `127.0.0.1:9000`), `ONCED_THREADS` (default: CPU count).

use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
use monoio::net::{TcpListener, TcpStream};
use onced_core::abuse::RuleSet;
use onced_core::engine::Engine;
use onced_core::store::MemoryStore;
use onced_gateway::gateway::{Gateway, NoopUpstream};
use onced_gateway::http::{parse_request, parse_response, write_request, write_response, Request, Response};
use onced_gateway::router::Router;
use onced_gateway::server::now_ms;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;

const LEASE_MS: u64 = 30_000;
const MAX_REQUEST: usize = 256 * 1024;

type OncedRouter = Router<MemoryStore, NoopUpstream>;

fn main() {
    let listen: SocketAddr = std::env::var("ONCED_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .expect("ONCED_LISTEN must be host:port");
    let backend: SocketAddr = std::env::var("ONCED_BACKEND")
        .unwrap_or_else(|_| "127.0.0.1:9000".to_string())
        .parse()
        .expect("ONCED_BACKEND must be host:port");
    let threads = std::env::var("ONCED_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));

    // One shard per core spreads the per-shard lock contention; all cores share
    // this router so a key's shard mapping is global (exactly-once across cores).
    let shards = (0..threads)
        .map(|_| Gateway::new(Engine::new(MemoryStore::new(), LEASE_MS), RuleSet::new(), NoopUpstream))
        .collect();
    let abuse = (0..threads).map(|_| RuleSet::new()).collect();
    let router: Arc<OncedRouter> = Arc::new(Router::new(shards, abuse, NoopUpstream));

    eprintln!("onced-uring: io_uring on {threads} cores, listening {listen}, backend {backend}");

    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let router = Arc::clone(&router);
        handles.push(std::thread::spawn(move || run_core(listen, backend, router)));
    }
    for handle in handles {
        let _ = handle.join();
    }
}

/// One core: its own monoio runtime + io_uring ring, its own `SO_REUSEPORT`
/// listener. The kernel balances incoming connections across the cores.
fn run_core(listen: SocketAddr, backend: SocketAddr, router: Arc<OncedRouter>) {
    let mut rt = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
        .enable_timer()
        .build()
        .expect("onced-uring: build runtime");
    rt.block_on(async move {
        let listener = reuseport_listener(listen);
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
            };
            let router = Arc::clone(&router);
            monoio::spawn(async move {
                let _ = serve_connection(stream, router, backend).await;
            });
        }
    });
}

/// A `SO_REUSEPORT` listener so every core can bind the same address.
fn reuseport_listener(addr: SocketAddr) -> TcpListener {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))
        .expect("socket");
    socket.set_reuse_address(true).expect("reuse_address");
    socket.set_reuse_port(true).expect("reuse_port");
    socket.set_nonblocking(true).expect("nonblocking");
    socket.bind(&addr.into()).expect("bind");
    socket.listen(1024).expect("listen");
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener).expect("monoio from_std")
}

/// Serve one connection, keep-alive: handle requests in a loop until the peer
/// closes or asks to close.
async fn serve_connection(
    mut stream: TcpStream,
    router: Arc<OncedRouter>,
    backend: SocketAddr,
) -> std::io::Result<()> {
    loop {
        let Some(request) = read_request(&mut stream).await? else {
            return Ok(()); // peer closed
        };
        let wants_close = request
            .header("connection")
            .map(|c| c.eq_ignore_ascii_case("close"))
            .unwrap_or(false);

        let now = now_ms();
        let to_forward = request.clone();
        let mut response = router
            .handle_async(&request, now, move || async move {
                forward(backend, &to_forward).await
            })
            .await;

        // Let HTTP/1.1 keep-alive be the default: drop any upstream Connection
        // header so the socket is reused across requests.
        response
            .headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("connection"));

        let mut out = Vec::new();
        write_response(&mut out, &response)?;
        let (res, _) = stream.write_all(out).await;
        res?;

        if wants_close {
            return Ok(());
        }
    }
}

/// Accumulate bytes until a full HTTP request parses. `None` on clean EOF.
async fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<Request>> {
    let mut acc: Vec<u8> = Vec::new();
    loop {
        let chunk = vec![0u8; 8192];
        let (res, chunk) = stream.read(chunk).await;
        let n = res?;
        if n == 0 {
            return Ok(None);
        }
        acc.extend_from_slice(&chunk[..n]);

        let mut cursor: &[u8] = &acc;
        match parse_request(&mut cursor) {
            Ok(Some(request)) => return Ok(Some(request)),
            Ok(None) => return Ok(None),
            Err(_) if acc.len() < MAX_REQUEST => continue,
            Err(_) => return Ok(None),
        }
    }
}

/// Forward `request` to `backend` over an io_uring socket and parse the reply.
async fn forward(backend: SocketAddr, request: &Request) -> std::io::Result<Response> {
    let mut wire = Vec::new();
    write_request(&mut wire, request)?;

    let mut stream = TcpStream::connect(backend).await?;
    let (res, _) = stream.write_all(wire).await;
    res?;

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
