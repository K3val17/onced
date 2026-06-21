//! Minimal HTTP/1.1 message types, request parser, and response serializer.
//!
//! Hand-rolled, no external dependencies. Supports the common case: a request
//! line, headers, and a `Content-Length` body. Chunked transfer-encoding,
//! HTTP/2, TLS, and keep-alive are intentionally out of scope (see crate docs).
//!
//! Production code is written test-first; the tests below are watched failing
//! before the parser and serializer exist.

use std::io::{BufRead, Write};

/// A parsed HTTP request.
#[derive(Clone, Debug)]
pub struct Request {
    /// Request method, e.g. `POST`.
    pub method: String,
    /// Request target (path + query), e.g. `/charge`.
    pub target: String,
    /// Headers in wire order; look them up via [`Request::header`].
    pub headers: Vec<(String, String)>,
    /// Request body (already read using `Content-Length`).
    pub body: Vec<u8>,
}

impl Request {
    /// Case-insensitive header lookup (HTTP header names are case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A response to serialize back to the client.
#[derive(Clone, Debug)]
pub struct Response {
    /// Status code, e.g. `201`.
    pub status: u16,
    /// Headers to emit (the serializer owns `Content-Length`).
    pub headers: Vec<(String, String)>,
    /// Response body.
    pub body: Vec<u8>,
}

/// Parse one request from `reader`. Returns `Ok(None)` on a clean EOF (the peer
/// closed without sending anything), or an error on a malformed request.
pub fn parse_request<R: BufRead>(reader: &mut R) -> std::io::Result<Option<Request>> {
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(None); // clean EOF
    }

    let trimmed = request_line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.split(' ');
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || target.is_empty() {
        return Err(invalid("malformed request line"));
    }

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break; // EOF before the blank line; tolerate it
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break; // blank line: end of headers
        }
        match line.split_once(':') {
            Some((name, value)) => {
                headers.push((name.trim().to_string(), value.trim().to_string()))
            }
            None => return Err(invalid("malformed header line")),
        }
    }

    let content_length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(Some(Request {
        method,
        target,
        headers,
        body,
    }))
}

/// Serialize `response` to `writer`. `Content-Length` is always set to the
/// actual body length (any caller-supplied `Content-Length` is ignored).
pub fn write_response<W: Write>(writer: &mut W, response: &Response) -> std::io::Result<()> {
    write!(
        writer,
        "HTTP/1.1 {} {}\r\n",
        response.status,
        reason_phrase(response.status)
    )?;
    write!(writer, "Content-Length: {}\r\n", response.body.len())?;
    for (name, value) in &response.headers {
        if name.eq_ignore_ascii_case("content-length") {
            continue; // owned by the serializer
        }
        write!(writer, "{name}: {value}\r\n")?;
    }
    writer.write_all(b"\r\n")?;
    writer.write_all(&response.body)?;
    Ok(())
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Status",
    }
}

fn invalid(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

/// Serialize `request` to `writer` to forward it to a backend. Sets
/// `Content-Length` to the actual body length and `Connection: close` (one
/// request per connection), overriding any caller-supplied versions.
pub fn write_request<W: Write>(writer: &mut W, request: &Request) -> std::io::Result<()> {
    write!(writer, "{} {} HTTP/1.1\r\n", request.method, request.target)?;
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("connection") {
            continue;
        }
        write!(writer, "{name}: {value}\r\n")?;
    }
    write!(writer, "Content-Length: {}\r\n", request.body.len())?;
    writer.write_all(b"Connection: close\r\n")?;
    writer.write_all(b"\r\n")?;
    writer.write_all(&request.body)?;
    Ok(())
}

/// Parse a response from a backend. The body length comes from `Content-Length`
/// if present, otherwise it is read to EOF (the `Connection: close` convention).
pub fn parse_response<R: BufRead>(reader: &mut R) -> std::io::Result<Response> {
    let mut status_line = String::new();
    if reader.read_line(&mut status_line)? == 0 {
        return Err(invalid("empty response"));
    }
    let trimmed = status_line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.splitn(3, ' ');
    let _version = parts.next();
    let status: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| invalid("bad status line"))?;

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        match line.split_once(':') {
            Some((name, value)) => {
                headers.push((name.trim().to_string(), value.trim().to_string()))
            }
            None => return Err(invalid("malformed response header")),
        }
    }

    let content_length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok());

    let body = match content_length {
        Some(length) => {
            let mut body = vec![0u8; length];
            if length > 0 {
                reader.read_exact(&mut body)?;
            }
            body
        }
        None => {
            let mut body = Vec::new();
            reader.read_to_end(&mut body)?;
            body
        }
    };

    Ok(Response {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use crate::http::{
        parse_request, parse_response, write_request, write_response, Request, Response,
    };
    use std::io::Cursor;

    #[test]
    fn parses_a_get_with_no_body() {
        let raw = b"GET /health HTTP/1.1\r\nHost: example\r\n\r\n";
        let mut reader = Cursor::new(&raw[..]);
        let request = parse_request(&mut reader).unwrap().expect("a request");
        assert_eq!(request.method, "GET");
        assert_eq!(request.target, "/health");
        assert!(request.body.is_empty());
    }

    #[test]
    fn parses_a_post_body_and_looks_up_headers_case_insensitively() {
        let raw =
            b"POST /charge HTTP/1.1\r\nIdempotency-Key: abc123\r\nContent-Length: 5\r\n\r\nhello";
        let mut reader = Cursor::new(&raw[..]);
        let request = parse_request(&mut reader).unwrap().expect("a request");
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/charge");
        assert_eq!(request.body, b"hello");
        assert_eq!(request.header("idempotency-key"), Some("abc123"));
        assert_eq!(request.header("IDEMPOTENCY-KEY"), Some("abc123"));
        assert_eq!(request.header("missing"), None);
    }

    #[test]
    fn a_clean_eof_yields_no_request() {
        let raw = b"";
        let mut reader = Cursor::new(&raw[..]);
        assert!(parse_request(&mut reader).unwrap().is_none());
    }

    #[test]
    fn writes_a_response_with_status_line_and_content_length() {
        let response = Response {
            status: 201,
            headers: vec![("X-Test".to_string(), "1".to_string())],
            body: b"created".to_vec(),
        };
        let mut out = Vec::new();
        write_response(&mut out, &response).unwrap();

        let text = String::from_utf8(out).unwrap();
        assert!(
            text.starts_with("HTTP/1.1 201 Created\r\n"),
            "got: {text:?}"
        );
        assert!(text.contains("Content-Length: 7\r\n"), "got: {text:?}");
        assert!(text.contains("X-Test: 1\r\n"), "got: {text:?}");
        assert!(text.ends_with("\r\n\r\ncreated"), "got: {text:?}");
    }

    #[test]
    fn write_request_then_parse_request_round_trips() {
        let request = Request {
            method: "POST".into(),
            target: "/charge".into(),
            headers: vec![
                ("Idempotency-Key".into(), "k1".into()),
                ("Host".into(), "backend".into()),
            ],
            body: b"amount=100".to_vec(),
        };
        let mut buf = Vec::new();
        write_request(&mut buf, &request).unwrap();

        let mut reader = Cursor::new(buf);
        let parsed = parse_request(&mut reader).unwrap().expect("a request");
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.target, "/charge");
        assert_eq!(parsed.body, b"amount=100");
        assert_eq!(parsed.header("idempotency-key"), Some("k1"));
    }

    #[test]
    fn parse_response_reads_status_headers_and_body() {
        let raw = b"HTTP/1.1 201 Created\r\nContent-Length: 7\r\nX-Test: 1\r\n\r\ncharged";
        let mut reader = Cursor::new(&raw[..]);
        let response = parse_response(&mut reader).unwrap();
        assert_eq!(response.status, 201);
        assert_eq!(response.body, b"charged");
        assert_eq!(
            response
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("x-test"))
                .map(|(_, v)| v.as_str()),
            Some("1")
        );
    }

    #[test]
    fn parse_response_reads_body_to_eof_without_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nstreamed-body";
        let mut reader = Cursor::new(&raw[..]);
        let response = parse_response(&mut reader).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"streamed-body");
    }

    #[test]
    fn write_response_then_parse_response_round_trips() {
        let response = Response {
            status: 200,
            headers: vec![("X-A".into(), "b".into())],
            body: b"hi".to_vec(),
        };
        let mut buf = Vec::new();
        write_response(&mut buf, &response).unwrap();

        let mut reader = Cursor::new(buf);
        let parsed = parse_response(&mut reader).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, b"hi");
    }
}
