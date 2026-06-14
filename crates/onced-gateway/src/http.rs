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

#[cfg(test)]
mod tests {
    use crate::http::{parse_request, write_response, Response};
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
}
