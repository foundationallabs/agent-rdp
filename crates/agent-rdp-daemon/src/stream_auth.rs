//! Authentication for the stream server.
//!
//! Each stream server generates a random [`StreamToken`] when it starts. Clients must present
//! it as the [`STREAM_TOKEN_PARAM`] (`token`) query parameter (`/?token=...`) on every HTTP and WebSocket request.
//! This keeps other local users and web pages (for example via DNS rebinding) out of the
//! stream; it does not protect against other processes of the same user, which can read the
//! token from the connect response like any other client.

use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use subtle::ConstantTimeEq;

/// Number of random bytes in a stream token (256 bits).
const TOKEN_BYTES: usize = 32;

/// Name of the query parameter that carries the stream token.
pub const STREAM_TOKEN_PARAM: &str = "token";

/// Secret that authorizes access to the stream server.
///
/// `Debug` never prints the value, so the token cannot leak through logging of containing
/// structs; use [`StreamToken::as_str`] to read it deliberately.
#[derive(Clone, PartialEq, Eq)]
pub struct StreamToken(String);

impl StreamToken {
    /// Generate a token from 32 bytes of OS randomness, encoded as unpadded URL-safe base64.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; TOKEN_BYTES];
        getrandom::getrandom(&mut bytes)?;
        Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// The token text, safe to embed in a URL query.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Compare against a candidate in constant time (with respect to the contents).
    fn matches(&self, candidate: &str) -> bool {
        self.0.as_bytes().ct_eq(candidate.as_bytes()).into()
    }
}

impl fmt::Debug for StreamToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StreamToken(<redacted>)")
    }
}

/// URL of a stream server endpoint: `<scheme>://<host>:<port>/?token=<token>`.
///
/// The one place that builds a tokenised URL (the connect output, the viewer page and
/// `agent-rdp view` all use it).
pub fn stream_url(scheme: &str, host: &str, port: u16, token: &str) -> String {
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair(STREAM_TOKEN_PARAM, token)
        .finish();
    format!("{scheme}://{host}:{port}/?{query}")
}

/// Check whether the request `target` (path and query) carries the right token.
///
/// A target without a query, a missing token or a wrong token is refused.
pub(crate) fn authorize(token: &StreamToken, target: &str) -> bool {
    let Some((_, query)) = target.split_once('?') else {
        return false;
    };
    form_urlencoded::parse(query.as_bytes())
        .any(|(key, value)| key == STREAM_TOKEN_PARAM && token.matches(&value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> StreamToken {
        StreamToken("s3cret-_Tok".to_string())
    }

    #[test]
    fn generated_tokens_are_url_safe_and_unique() {
        let a = StreamToken::generate().unwrap();
        let b = StreamToken::generate().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), 43);
        assert!(a
            .as_str()
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn debug_is_redacted() {
        let shown = format!("{:?}", token());
        assert_eq!(shown, "StreamToken(<redacted>)");
        assert!(!shown.contains("s3cret"));
    }

    #[test]
    fn accepts_correct_token() {
        assert!(authorize(&token(), "/?token=s3cret-_Tok"));
        assert!(authorize(&token(), "/viewer?a=1&token=s3cret-_Tok"));
    }

    #[test]
    fn accepts_percent_encoded_token() {
        assert!(authorize(&token(), "/?token=s3cret%2D_Tok"));
    }

    #[test]
    fn rejects_missing_wrong_or_malformed() {
        let t = token();
        for target in [
            "/",
            "/?token=",
            "/?token=wrong",
            "/?token=s3cret-_To",
            "/?token=s3cret-_Tokk",
            "/?tokens=s3cret-_Tok",
            "",
        ] {
            assert!(!authorize(&t, target), "{target:?}");
        }
        assert!(!authorize(&StreamToken("other".into()), "/?token=s3cret-_Tok"));
    }

    #[test]
    fn stream_url_carries_the_encoded_token() {
        assert_eq!(stream_url("ws", "127.0.0.1", 9224, "abc-_"), "ws://127.0.0.1:9224/?token=abc-_");
        assert_eq!(stream_url("http", "localhost", 1, "a b/c"), "http://localhost:1/?token=a+b%2Fc");
        assert!(authorize(&StreamToken("a b/c".into()), "/?token=a+b%2Fc"));
    }
}
