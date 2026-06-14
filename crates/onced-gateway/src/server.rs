//! The blocking TCP server and the backend HTTP client.
//!
//! A thread-per-connection accept loop (the gateway state is shared behind a
//! `Mutex`) and an [`HttpUpstream`] that forwards to the real backend. One
//! request per connection (`Connection: close`); every socket carries a read
//! timeout so a slow or stuck peer can never wedge a worker. This is the simple,
//! correct transport; the high-throughput io_uring / thread-per-core path is
//! Phase 6, behind this same boundary.
//!
//! Production code is written test-first; the end-to-end test below is watched
//! failing before `serve` and `HttpUpstream` exist.

use crate::gateway::{Gateway, Upstream};
use crate::http::{
    parse_request, parse_response, write_request, write_response, Request, Response,
};
use onced_core::store::Store;
use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Read/write timeout on every socket, so a slow or stuck peer cannot wedge a
/// worker thread indefinitely.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(30);

/// Milliseconds since the Unix epoch — the real clock injected into the engine.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// An [`Upstream`] that forwards each request to a backend over a fresh HTTP/1.1
/// connection (`Connection: close`).
pub struct HttpUpstream {
    backend: String,
}

impl HttpUpstream {
    /// Create an upstream forwarding to `backend` (a `host:port` address).
    pub fn new(backend: impl Into<String>) -> Self {
        Self {
            backend: backend.into(),
        }
    }
}

impl Upstream for HttpUpstream {
    fn forward(&self, request: &Request) -> std::io::Result<Response> {
        let stream = TcpStream::connect(&self.backend)?;
        stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
        stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;

        let mut writer = stream.try_clone()?;
        write_request(&mut writer, request)?;
        writer.flush()?;

        let mut reader = BufReader::new(stream);
        parse_response(&mut reader)
    }
}

/// Run the accept loop, handling each connection on its own thread. The gateway
/// state is shared behind a `Mutex`.
pub fn serve<S, U>(listener: TcpListener, gateway: Arc<Mutex<Gateway<S, U>>>) -> std::io::Result<()>
where
    S: Store + Send + 'static,
    U: Upstream + Send + 'static,
{
    for stream in listener.incoming() {
        let stream = stream?;
        let gateway = Arc::clone(&gateway);
        std::thread::spawn(move || {
            let _ = handle_connection(stream, &gateway);
        });
    }
    Ok(())
}

fn handle_connection<S, U>(stream: TcpStream, gateway: &Mutex<Gateway<S, U>>) -> std::io::Result<()>
where
    S: Store,
    U: Upstream,
{
    stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    if let Some(request) = parse_request(&mut reader)? {
        let response = {
            // Recover a poisoned lock rather than propagating another thread's panic.
            let mut gateway = gateway
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            gateway.handle(&request, now_ms())
        };
        write_response(&mut writer, &response)?;
        writer.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{serve, HttpUpstream};
    use crate::gateway::Gateway;
    use onced_core::abuse::RuleSet;
    use onced_core::engine::Engine;
    use onced_core::store::MemoryStore;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// A minimal fake backend: counts the requests it receives and always
    /// returns `201 charged`.
    fn spawn_fake_backend() -> (String, Arc<AtomicU32>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let hits = Arc::new(AtomicU32::new(0));
        let backend_hits = Arc::clone(&hits);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                backend_hits.fetch_add(1, Ordering::SeqCst);
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .ok();
                let mut scratch = [0u8; 1024];
                let _ = stream.read(&mut scratch); // best-effort drain of the request
                let _ = stream.write_all(
                    b"HTTP/1.1 201 Created\r\nContent-Length: 7\r\nConnection: close\r\n\r\ncharged",
                );
                let _ = stream.flush();
            }
        });

        (addr, hits)
    }

    fn send_idempotent_post(addr: &str, key: &str, body: &[u8]) -> String {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let head = format!(
            "POST /charge HTTP/1.1\r\nHost: onced\r\nX-Forwarded-For: 10.0.0.9\r\n\
             Idempotency-Key: {key}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        stream.flush().unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    /// End-to-end over real loopback sockets: two identical idempotent requests
    /// reach the backend exactly once; both clients get the same body back.
    #[test]
    fn end_to_end_retry_hits_backend_once_over_real_sockets() {
        let (backend_addr, backend_hits) = spawn_fake_backend();

        let gateway = Arc::new(Mutex::new(Gateway::new(
            Engine::new(MemoryStore::new(), 30_000),
            RuleSet::new(),
            HttpUpstream::new(backend_addr),
        )));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let onced_addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let _ = serve(listener, gateway);
        });

        let first = send_idempotent_post(&onced_addr, "k-int", b"amount=100");
        let second = send_idempotent_post(&onced_addr, "k-int", b"amount=100");

        assert!(first.contains("charged"), "first response: {first:?}");
        assert!(second.contains("charged"), "second response: {second:?}");
        assert!(
            second.contains("replayed"),
            "second should be replayed: {second:?}"
        );
        assert_eq!(
            backend_hits.load(Ordering::SeqCst),
            1,
            "the backend must be hit exactly once across the retry"
        );
    }
}
