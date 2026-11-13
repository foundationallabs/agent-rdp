//! IPC client for communicating with the daemon.

use std::io;
use std::path::Path;
use std::time::Duration;

use agent_rdp_protocol::{ErrorCode, Request, Response};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;

use crate::error::CliError;

/// Default connect timeout in seconds.
const CONNECT_TIMEOUT_SECS: u64 = 15;

/// IPC client for daemon communication.
pub struct IpcClient {
    #[cfg(unix)]
    stream: tokio::net::UnixStream,
    #[cfg(windows)]
    stream: tokio::net::TcpStream,
}

impl IpcClient {
    /// Connect to the daemon for the given session with a timeout.
    #[cfg(unix)]
    pub async fn connect(socket_path: &Path) -> io::Result<Self> {
        let connect_future = tokio::net::UnixStream::connect(socket_path);
        let stream = timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS), connect_future)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "Connection to daemon timed out after {}s",
                        CONNECT_TIMEOUT_SECS
                    ),
                )
            })??;
        Ok(Self { stream })
    }

    #[cfg(windows)]
    pub async fn connect(socket_path: &Path) -> io::Result<Self> {
        // On Windows, derive port from session name
        let session = socket_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("default");

        let port = agent_rdp_daemon::get_session_port(session);
        let addr = format!("127.0.0.1:{}", port);
        let connect_future = tokio::net::TcpStream::connect(&addr);
        let stream = timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS), connect_future)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "Connection to daemon timed out after {}s",
                        CONNECT_TIMEOUT_SECS
                    ),
                )
            })??;
        Ok(Self { stream })
    }

    /// Send a request and receive a response.
    pub async fn send(&mut self, request: &Request, timeout_ms: u64) -> anyhow::Result<Response> {
        let json = serde_json::to_string(request)? + "\n";

        // Write request and flush to ensure it's sent immediately
        self.stream
            .write_all(json.as_bytes())
            .await
            .map_err(ipc_error)?;
        self.stream.flush().await.map_err(ipc_error)?;

        // Read response with timeout
        let response = timeout(Duration::from_millis(timeout_ms), self.read_response())
            .await
            .map_err(|_| CliError::new(ErrorCode::Timeout, "Request timed out"))??;

        Ok(response)
    }

    /// Read a response from the stream.
    async fn read_response(&mut self) -> anyhow::Result<Response> {
        let mut reader = BufReader::new(&mut self.stream);
        let mut line = String::new();
        if reader.read_line(&mut line).await.map_err(ipc_error)? == 0 {
            return Err(CliError::new(
                ErrorCode::IpcError,
                "Daemon closed the connection without a response",
            )
            .into());
        }

        let response: Response = serde_json::from_str(line.trim()).map_err(|e| {
            CliError::new(
                ErrorCode::IpcError,
                format!("Invalid response from daemon: {e}"),
            )
        })?;
        Ok(response)
    }
}

/// An I/O failure talking to the daemon.
fn ipc_error(e: io::Error) -> CliError {
    CliError::new(
        ErrorCode::IpcError,
        format!("Daemon connection failed: {e}"),
    )
}

/// Try to connect to an existing daemon, with optional retries.
pub async fn try_connect(socket_path: &Path, retries: u32, delay_ms: u64) -> io::Result<IpcClient> {
    let mut last_error = io::Error::new(io::ErrorKind::Other, "No connection attempts made");

    for _ in 0..retries {
        match IpcClient::connect(socket_path).await {
            Ok(client) => return Ok(client),
            Err(e) => {
                last_error = e;
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
    }

    Err(last_error)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::error::error_code;
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixStream;

    /// A client wired to an in-memory peer that stands in for the daemon.
    fn client_and_peer() -> (IpcClient, UnixStream) {
        let (client, peer) = UnixStream::pair().unwrap();
        (IpcClient { stream: client }, peer)
    }

    /// Read the request line the client sent, so the peer can then misbehave.
    async fn read_request(peer: &mut UnixStream) {
        let mut buf = [0u8; 256];
        let _ = peer.read(&mut buf).await.unwrap();
    }

    #[tokio::test]
    async fn silent_daemon_is_a_timeout() {
        let (mut client, _peer) = client_and_peer();
        let err = client.send(&Request::Ping, 20).await.unwrap_err();
        assert_eq!(error_code(&err), ErrorCode::Timeout);
    }

    #[tokio::test]
    async fn daemon_closing_the_connection_is_an_ipc_error() {
        let (mut client, mut peer) = client_and_peer();
        let daemon = tokio::spawn(async move {
            read_request(&mut peer).await;
            drop(peer);
        });
        let err = client.send(&Request::Ping, 5000).await.unwrap_err();
        daemon.await.unwrap();
        assert_eq!(error_code(&err), ErrorCode::IpcError);
    }

    #[tokio::test]
    async fn unparseable_response_is_an_ipc_error() {
        let (mut client, mut peer) = client_and_peer();
        let daemon = tokio::spawn(async move {
            read_request(&mut peer).await;
            peer.write_all(b"not json\n").await.unwrap();
            peer
        });
        let err = client.send(&Request::Ping, 5000).await.unwrap_err();
        drop(daemon.await.unwrap());
        assert_eq!(error_code(&err), ErrorCode::IpcError);
    }

    #[tokio::test]
    async fn closed_daemon_on_write_is_an_ipc_error() {
        let (mut client, peer) = client_and_peer();
        drop(peer);
        let err = client.send(&Request::Ping, 5000).await.unwrap_err();
        assert_eq!(error_code(&err), ErrorCode::IpcError);
    }
}
