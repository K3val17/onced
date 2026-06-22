//! io_uring thread-per-core transport for Onced (Linux-only, built on monoio).
//!
//! This is the "raw speed" data plane: each core runs its own monoio runtime
//! over an io_uring submission/completion ring, so accept/read/write/fsync go
//! through batched, near-zero-overhead system calls instead of one syscall per
//! op on a blocked thread. It is excluded from the workspace and built only on
//! Linux CI (io_uring does not exist on macOS).
//!
//! Milestone 1 (this file): prove an io_uring server builds and serves HTTP on a
//! clean Linux runner. The Onced router (exactly-once + abuse) is wired in next,
//! once the platform path is green.

use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
use monoio::net::TcpListener;

/// FusionDriver picks io_uring when the kernel offers it (Linux ≥5.6) and falls
/// back to epoll otherwise, so the binary runs everywhere a Linux runner does.
#[monoio::main(timer_enabled = true)]
async fn main() {
    let addr = std::env::var("ONCED_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = TcpListener::bind(&addr).expect("onced-uring: bind failed");
    eprintln!("onced-uring: io_uring server listening on {addr}");

    loop {
        let Ok((mut stream, _peer)) = listener.accept().await else {
            continue;
        };
        // One task per connection, pinned to this core (monoio is thread-per-core).
        monoio::spawn(async move {
            // Drain the request (one shot is enough for the smoke test).
            let buf = vec![0u8; 8192];
            let (read, _buf) = stream.read(buf).await;
            if !matches!(read, Ok(n) if n > 0) {
                return;
            }
            let body = b"ok";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\nok",
                body.len()
            );
            let (_written, _buf) = stream.write_all(response.into_bytes()).await;
        });
    }
}
