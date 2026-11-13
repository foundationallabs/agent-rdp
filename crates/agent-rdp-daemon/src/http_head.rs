//! Reading an HTTP request head from a socket and replying with plain responses.
//!
//! The stream server peeks the whole head before deciding what a connection is (viewer,
//! WebSocket or error), so the bytes can still be handed to the WebSocket handshake untouched.
//! Replies that do not upgrade the connection first drain what was peeked, so closing the socket
//! does not turn into a reset that hides the reply from the client.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Largest request head (request line and headers) accepted, in bytes.
pub(crate) const MAX_REQUEST_HEAD_BYTES: usize = 8 * 1024;

/// Maximum number of request headers parsed from the peeked bytes.
const MAX_HEADERS: usize = 64;

/// How long a client may take to send a complete request head.
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(5);

/// Delay between peeks while waiting for the rest of a request head.
const REQUEST_HEAD_POLL: Duration = Duration::from_millis(10);

/// A complete request head, parsed once.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedHead {
    /// Length of the head in bytes (request line, headers and the blank line).
    pub len: usize,
    /// The request target (path and query).
    pub target: String,
    /// Whether an `Upgrade` header asks for `websocket` (case-insensitive).
    pub is_websocket_upgrade: bool,
}

/// Result of parsing the start of an HTTP request.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HeadParse {
    /// The request line and headers are complete.
    Complete(ParsedHead),
    /// More bytes are needed.
    Partial,
    /// The bytes are not an HTTP request head.
    Invalid,
}

/// Parse the head (request line and headers) at the start of `bytes`.
pub(crate) fn parse_head(bytes: &[u8]) -> HeadParse {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(bytes) {
        Ok(httparse::Status::Complete(len)) => HeadParse::Complete(ParsedHead {
            len,
            target: request.path.unwrap_or_default().to_string(),
            is_websocket_upgrade: request.headers.iter().any(|header| {
                header.name.eq_ignore_ascii_case("upgrade")
                    && std::str::from_utf8(header.value)
                        .is_ok_and(|value| value.trim().eq_ignore_ascii_case("websocket"))
            }),
        }),
        Ok(httparse::Status::Partial) => HeadParse::Partial,
        Err(_) => HeadParse::Invalid,
    }
}

/// What reading a request head produced.
pub(crate) enum HeadRead {
    /// The complete head; nothing after it was included.
    Complete(ParsedHead),
    /// Not an HTTP head, or too large; this many bytes were peeked.
    Bad { peeked: usize },
    /// The client went away or was too slow.
    Closed,
}

/// Peek the request head without consuming it.
///
/// Waits for the head to be complete, for up to [`REQUEST_HEAD_TIMEOUT`] and
/// [`MAX_REQUEST_HEAD_BYTES`].
pub(crate) async fn read_request_head(stream: &TcpStream) -> std::io::Result<HeadRead> {
    let read = async {
        let mut buf = [0u8; MAX_REQUEST_HEAD_BYTES];
        loop {
            let n = stream.peek(&mut buf).await?;
            if n == 0 {
                return Ok(HeadRead::Closed);
            }
            match parse_head(&buf[..n]) {
                HeadParse::Complete(head) => return Ok(HeadRead::Complete(head)),
                HeadParse::Invalid => return Ok(HeadRead::Bad { peeked: n }),
                HeadParse::Partial if n == buf.len() => return Ok(HeadRead::Bad { peeked: n }),
                HeadParse::Partial => tokio::time::sleep(REQUEST_HEAD_POLL).await,
            }
        }
    };
    match tokio::time::timeout(REQUEST_HEAD_TIMEOUT, read).await {
        Ok(result) => result,
        Err(_) => Ok(HeadRead::Closed),
    }
}

/// Consume the `consume` bytes that were only peeked, plus whatever else has already arrived
/// (an oversized head has more than was peeked).
pub(crate) async fn drain_head(stream: &mut TcpStream, consume: usize) -> std::io::Result<()> {
    let mut scratch = [0u8; 4096];
    let mut remaining = consume;
    while remaining > 0 {
        let want = remaining.min(scratch.len());
        let n = stream.read(&mut scratch[..want]).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        remaining -= n;
    }
    while matches!(stream.try_read(&mut scratch), Ok(n) if n > 0) {}
    Ok(())
}

/// Drain the peeked head, send a response with `status`, `content_type` and `body`, and close.
pub(crate) async fn serve_response(
    mut stream: TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
    consume: usize,
) -> anyhow::Result<()> {
    drain_head(&mut stream, consume).await?;
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Serve a plain-text response and close.
pub(crate) async fn serve_text(
    stream: TcpStream,
    status: &str,
    body: &str,
    consume: usize,
) -> anyhow::Result<()> {
    serve_response(stream, status, "text/plain", body, consume).await
}

/// Serve an error response (such as `401 Unauthorized`) and close; the body repeats the status.
pub(crate) async fn serve_error(
    stream: TcpStream,
    status: &str,
    consume: usize,
) -> anyhow::Result<()> {
    serve_text(stream, status, &format!("{status}.\n"), consume).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(bytes: &[u8]) -> ParsedHead {
        match parse_head(bytes) {
            HeadParse::Complete(head) => head,
            other => panic!("expected a complete head, got {other:?}"),
        }
    }

    #[test]
    fn parse_head_reports_completeness_and_target() {
        let full = b"GET /?token=x HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let head = complete(full);
        assert_eq!(head.len, full.len());
        assert_eq!(head.target, "/?token=x");
        assert_eq!(parse_head(b"GET /?tok"), HeadParse::Partial);
        assert_eq!(parse_head(b"GET /?token=x HTTP/1.1\r\nHost: loc"), HeadParse::Partial);
        assert_eq!(parse_head(b"\x00\x01garbage"), HeadParse::Invalid);
        assert_eq!(parse_head(b""), HeadParse::Partial);
    }

    #[test]
    fn detects_websocket_upgrade_in_any_case_and_spacing() {
        for header in ["Upgrade: websocket", "upgrade:websocket", "UPGRADE: WebSocket", "Upgrade:  websocket "] {
            let head = format!("GET / HTTP/1.1\r\nHost: x\r\n{header}\r\n\r\n");
            assert!(complete(head.as_bytes()).is_websocket_upgrade, "{header}");
        }
    }

    #[test]
    fn plain_requests_are_not_websocket_upgrades() {
        for head in [
            "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            "GET / HTTP/1.1\r\nUpgrade: h2c\r\n\r\n",
            // The text appearing outside an Upgrade header does not count
            "GET /?x=upgrade:%20websocket HTTP/1.1\r\nX-A: upgrade: websocket\r\n\r\n",
        ] {
            assert!(!complete(head.as_bytes()).is_websocket_upgrade, "{head}");
        }
        assert_eq!(parse_head(b"GET / HTTP/1.1\r\nUpgrade: websocket"), HeadParse::Partial);
    }
}
