//! WebSocket server for streaming RDP desktop and handling input.
//!
//! Provides a WebSocket interface matching the agent-browser protocol for
//! debugging and interactive viewing of the remote desktop.
//!
//! Also serves the embedded viewer HTML on regular HTTP requests.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde::Serialize;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info};

use crate::rdp_session::RdpSession;
use crate::http_head::{read_request_head, serve_error, serve_response, serve_text, HeadRead};
use crate::stream_auth::{authorize, stream_url, StreamToken};
use crate::ws_input::{keyboard_to_fastpath, mouse_to_fastpath, ClipboardContent, WsInputMessage};

/// Stream frame rate used when neither the connect request nor `AGENT_RDP_STREAM_FPS` sets one.
pub const DEFAULT_STREAM_FPS: u32 = 10;

/// Upper bound for the stream frame rate (keeps the frame interval non-zero).
pub const MAX_STREAM_FPS: u32 = 60;

/// JPEG quality range accepted by the encoder.
const MIN_JPEG_QUALITY: u8 = 1;
const MAX_JPEG_QUALITY: u8 = 100;

/// Embedded viewer HTML.
const VIEWER_HTML: &str = include_str!("../../../assets/viewer/viewer.html");

/// Frame message sent to clients.
#[derive(Debug, Serialize)]
struct FrameMessage {
    #[serde(rename = "type")]
    msg_type: &'static str,
    data: String,
    metadata: FrameMetadata,
}

/// Metadata included with frame messages.
#[derive(Debug, Serialize)]
struct FrameMetadata {
    #[serde(rename = "deviceWidth")]
    device_width: u16,
    #[serde(rename = "deviceHeight")]
    device_height: u16,
}

/// Status message sent to clients.
#[derive(Debug, Serialize)]
struct StatusMessage {
    #[serde(rename = "type")]
    msg_type: &'static str,
    connected: bool,
    streaming: bool,
    #[serde(rename = "viewportWidth")]
    viewport_width: u16,
    #[serde(rename = "viewportHeight")]
    viewport_height: u16,
}

/// Clipboard changed notification (server → client).
#[derive(Debug, Serialize)]
struct ClipboardChangedMessage {
    #[serde(rename = "type")]
    msg_type: &'static str,
}

/// Clipboard data message (server → client).
#[derive(Debug, Serialize)]
struct ClipboardDataMessage {
    #[serde(rename = "type")]
    msg_type: &'static str,
    content: ClipboardContent,
}

/// Client ID type.
type ClientId = u64;

/// WebSocket server for desktop streaming.
pub struct WsServer {
    port: u16,
    jpeg_quality: u8,
    serve_viewer: bool,
    /// Active clients (by ID).
    clients: Arc<Mutex<HashSet<ClientId>>>,
    /// Next client ID.
    next_client_id: Arc<Mutex<ClientId>>,
}

/// Configuration for the WebSocket server.
pub struct WsServerConfig {
    pub port: u16,
    pub fps: u32,
    pub jpeg_quality: u8,
    /// Serve the embedded HTML viewer on HTTP requests.
    pub serve_viewer: bool,
}

impl Default for WsServerConfig {
    fn default() -> Self {
        Self {
            port: 9224,
            fps: DEFAULT_STREAM_FPS,
            jpeg_quality: 80,
            serve_viewer: false,
        }
    }
}

impl WsServer {
    /// Create a new WebSocket server.
    pub fn new(config: WsServerConfig) -> Self {
        Self {
            port: config.port,
            jpeg_quality: config.jpeg_quality.clamp(MIN_JPEG_QUALITY, MAX_JPEG_QUALITY),
            serve_viewer: config.serve_viewer,
            clients: Arc::new(Mutex::new(HashSet::new())),
            next_client_id: Arc::new(Mutex::new(0)),
        }
    }

    /// Start the WebSocket server.
    ///
    /// Returns a handle that can be used to broadcast frames to clients.
    pub async fn start(
        &self,
        rdp_session: Arc<tokio::sync::Mutex<Option<RdpSession>>>,
    ) -> anyhow::Result<WsServerHandle> {
        let token = StreamToken::generate()
            .map_err(|e| anyhow::anyhow!("failed to generate stream token: {}", e))?;
        let listener = bind_loopback(self.port).await?;
        let local_addr = listener.local_addr()?;
        info!("WebSocket server listening on ws://{}", local_addr);

        // Create broadcast channel
        let (broadcast_tx, _) = tokio::sync::broadcast::channel::<String>(16);
        let broadcast_tx_clone = broadcast_tx.clone();

        // Spawn accept loop
        let next_client_id = Arc::clone(&self.next_client_id);

        let port = local_addr.port();
        let ctx = Arc::new(ConnectionCtx {
            clients: Arc::clone(&self.clients),
            rdp_session,
            jpeg_quality: self.jpeg_quality,
            port,
            serve_viewer: self.serve_viewer,
            token: token.clone(),
        });
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let accept_task = tokio::spawn(async move {
            // Client tasks live in a JoinSet owned by this loop, so aborting the accept task
            // drops the set and aborts every client connection too.
            let mut client_tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    // Stop on request: close every client before the listener goes away
                    _ = &mut shutdown_rx => {
                        client_tasks.shutdown().await;
                        break;
                    }
                    // Reap finished client tasks
                    Some(_) = client_tasks.join_next() => {}
                    accepted = listener.accept() => match accepted {
                        Ok((stream, addr)) => {
                            debug!("Connection from {}", addr);

                            let client_id = {
                                let mut id = next_client_id.lock();
                                *id += 1;
                                *id
                            };

                            let broadcast_rx = broadcast_tx.subscribe();
                            let ctx = Arc::clone(&ctx);

                            client_tasks.spawn(async move {
                                if let Err(e) = handle_connection(&ctx, stream, client_id, broadcast_rx).await {
                                    debug!("Client {} disconnected: {}", client_id, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                        }
                    },
                }
            }
        });

        Ok(WsServerHandle {
            broadcast_tx: broadcast_tx_clone,
            clients: Arc::clone(&self.clients),
            jpeg_quality: self.jpeg_quality,
            local_addr,
            token,
            accept_task: Some(accept_task),
            shutdown_tx: Some(shutdown_tx),
        })
    }
}

/// Handle for broadcasting frames to WebSocket clients.
///
/// [`WsServerHandle::shutdown`] stops the server and waits until the listening port is released
/// and every client connection is closed. Dropping the handle stops it too, but without
/// waiting, so the port may stay bound for a moment.
pub struct WsServerHandle {
    broadcast_tx: tokio::sync::broadcast::Sender<String>,
    clients: Arc<Mutex<HashSet<ClientId>>>,
    jpeg_quality: u8,
    local_addr: SocketAddr,
    token: StreamToken,
    accept_task: Option<tokio::task::JoinHandle<()>>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for WsServerHandle {
    /// Backstop for a handle dropped without [`WsServerHandle::shutdown`]: abort the accept
    /// task, which drops its client set and listener.
    fn drop(&mut self) {
        if let Some(task) = self.accept_task.take() {
            task.abort();
        }
    }
}

impl WsServerHandle {
    /// Stop the server and wait for it to finish: every client connection is closed and the
    /// port is free when this returns.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            // An error means the accept task already ended
            let _ = tx.send(());
        }
        if let Some(task) = self.accept_task.take() {
            let _ = task.await;
        }
    }

    /// The token clients must present as `?token=` to use this server.
    pub fn token(&self) -> &StreamToken {
        &self.token
    }

    /// The address the server listens on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Check if there are any connected clients.
    pub fn has_clients(&self) -> bool {
        !self.clients.lock().is_empty()
    }

    /// Broadcast a frame to all connected clients.
    ///
    /// Takes the raw RGBA image data and converts it to JPEG.
    pub fn broadcast_frame(&self, width: u16, height: u16, rgba_data: &[u8]) {
        if !self.has_clients() {
            return;
        }

        // Convert RGBA to JPEG
        let jpeg_data = match encode_jpeg(width, height, rgba_data, self.jpeg_quality) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to encode JPEG: {}", e);
                return;
            }
        };

        // Base64 encode
        let base64_data = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &jpeg_data,
        );

        // Create frame message
        let msg = FrameMessage {
            msg_type: "frame",
            data: base64_data,
            metadata: FrameMetadata {
                device_width: width,
                device_height: height,
            },
        };

        if let Ok(json) = serde_json::to_string(&msg) {
            let _ = self.broadcast_tx.send(json);
        }
    }

    /// Notify clients that the remote clipboard has changed.
    pub fn broadcast_clipboard_changed(&self) {
        if !self.has_clients() {
            return;
        }

        let msg = ClipboardChangedMessage {
            msg_type: "clipboard_changed",
        };

        if let Ok(json) = serde_json::to_string(&msg) {
            debug!("Broadcasting clipboard_changed to clients");
            let _ = self.broadcast_tx.send(json);
        }
    }
}

/// What every connection of one stream server shares.
struct ConnectionCtx {
    clients: Arc<Mutex<HashSet<ClientId>>>,
    rdp_session: Arc<tokio::sync::Mutex<Option<RdpSession>>>,
    jpeg_quality: u8,
    port: u16,
    serve_viewer: bool,
    token: StreamToken,
}

/// Handle an incoming connection - either HTTP or WebSocket.
async fn handle_connection(
    ctx: &ConnectionCtx,
    stream: TcpStream,
    client_id: ClientId,
    broadcast_rx: tokio::sync::broadcast::Receiver<String>,
) -> anyhow::Result<()> {
    // Buffer the whole request head (peeking, so the stream is left untouched)
    let head = match read_request_head(&stream).await? {
        HeadRead::Complete(head) => head,
        HeadRead::Bad { peeked } => return serve_error(stream, "400 Bad Request", peeked).await,
        HeadRead::Closed => return Ok(()),
    };

    // Every request needs the stream token, whatever it asks for
    if !authorize(&ctx.token, &head.target) {
        return serve_error(stream, "401 Unauthorized", head.len).await;
    }

    if head.is_websocket_upgrade {
        let ws_stream = tokio_tungstenite::accept_async(stream).await?;
        handle_websocket_client(
            ws_stream,
            client_id,
            Arc::clone(&ctx.clients),
            Arc::clone(&ctx.rdp_session),
            broadcast_rx,
            ctx.jpeg_quality,
        )
        .await
    } else if ctx.serve_viewer {
        // The viewer page gets the tokenised stream URL
        let html = VIEWER_HTML.replace(
            "value=\"ws://localhost:9224\"",
            &format!("value=\"{}\"", stream_url("ws", "localhost", ctx.port, ctx.token.as_str())),
        );
        serve_response(stream, "200 OK", "text/html; charset=utf-8", &html, head.len).await
    } else {
        serve_text(stream, "404 Not Found", "Viewer is not enabled.\n", head.len).await
    }
}

/// Handle a single WebSocket client connection.
async fn handle_websocket_client<S>(
    ws_stream: S,
    client_id: ClientId,
    clients: Arc<Mutex<HashSet<ClientId>>>,
    rdp_session: Arc<tokio::sync::Mutex<Option<RdpSession>>>,
    mut broadcast_rx: tokio::sync::broadcast::Receiver<String>,
    jpeg_quality: u8,
) -> anyhow::Result<()>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    let (mut ws_sink, mut ws_stream) = ws_stream.split();

    // Register client
    {
        clients.lock().insert(client_id);
    }
    info!("Client {} connected (total: {})", client_id, clients.lock().len());

    // Send initial status
    {
        let session = rdp_session.lock().await;
        let (connected, width, height) = if let Some(ref rdp) = *session {
            (true, rdp.width(), rdp.height())
        } else {
            (false, 0, 0)
        };

        let status = StatusMessage {
            msg_type: "status",
            connected,
            streaming: true,
            viewport_width: width,
            viewport_height: height,
        };

        if let Ok(json) = serde_json::to_string(&status) {
            let _ = ws_sink.send(Message::Text(json.into())).await;
        }
    }

    // Send initial frame
    {
        let session = rdp_session.lock().await;
        if let Some(ref rdp) = *session {
            let (width, height, data) = rdp.get_image_data();
            if let Ok(jpeg_data) = encode_jpeg(width, height, &data, jpeg_quality) {
                let base64_data = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &jpeg_data,
                );
                let msg = FrameMessage {
                    msg_type: "frame",
                    data: base64_data,
                    metadata: FrameMetadata {
                        device_width: width,
                        device_height: height,
                    },
                };
                if let Ok(json) = serde_json::to_string(&msg) {
                    let _ = ws_sink.send(Message::Text(json.into())).await;
                }
            }
        }
    }

    loop {
        tokio::select! {
            // Receive broadcast frames
            result = broadcast_rx.recv() => {
                match result {
                    Ok(json) => {
                        if let Err(e) = ws_sink.send(Message::Text(json.into())).await {
                            debug!("Failed to send frame to client {}: {}", client_id, e);
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        debug!("Client {} lagged {} frames", client_id, n);
                    }
                    Err(_) => break,
                }
            }

            // Receive client messages
            result = ws_stream.next() => {
                match result {
                    Some(Ok(msg)) => {
                        if let Message::Text(text) = msg {
                            handle_client_message(&text, &rdp_session, &mut ws_sink).await;
                        } else if let Message::Close(_) = msg {
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        debug!("WebSocket error for client {}: {}", client_id, e);
                        break;
                    }
                    None => break,
                }
            }
        }
    }

    // Unregister client
    {
        clients.lock().remove(&client_id);
    }
    info!("Client {} disconnected (total: {})", client_id, clients.lock().len());

    Ok(())
}

/// Handle an incoming message from a WebSocket client.
async fn handle_client_message<S>(
    text: &str,
    rdp_session: &Arc<tokio::sync::Mutex<Option<RdpSession>>>,
    ws_sink: &mut S,
) where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::fmt::Debug,
{
    // Parse the input message
    let input: WsInputMessage = match serde_json::from_str(text) {
        Ok(msg) => msg,
        Err(e) => {
            debug!("Failed to parse WebSocket message: {} - {}", e, text);
            return;
        }
    };

    match input {
        WsInputMessage::Mouse(payload) => {
            let events = mouse_to_fastpath(&payload);
            if !events.is_empty() {
                let session = rdp_session.lock().await;
                if let Some(ref rdp) = *session {
                    if let Err(e) = rdp.send_input(events).await {
                        error!("Failed to send input to RDP session: {}", e);
                    }
                }
            }
        }
        WsInputMessage::Keyboard(payload) => {
            let events = keyboard_to_fastpath(&payload);
            if !events.is_empty() {
                let session = rdp_session.lock().await;
                if let Some(ref rdp) = *session {
                    if let Err(e) = rdp.send_input(events).await {
                        error!("Failed to send input to RDP session: {}", e);
                    }
                }
            }
        }
        WsInputMessage::ClipboardGet(_payload) => {
            // Client is requesting remote clipboard content
            debug!("Received clipboard_get request from client");
            let session = rdp_session.lock().await;
            if let Some(ref rdp) = *session {
                match rdp.clipboard_get().await {
                    Ok(text) => {
                        let msg = ClipboardDataMessage {
                            msg_type: "clipboard_data",
                            content: ClipboardContent {
                                content_type: "text".to_string(),
                                text,
                            },
                        };
                        if let Ok(json) = serde_json::to_string(&msg) {
                            let _ = ws_sink.send(Message::Text(json.into())).await;
                        }
                    }
                    Err(e) => {
                        debug!("Failed to get clipboard: {}", e);
                    }
                }
            }
        }
        WsInputMessage::ClipboardSet(payload) => {
            // Client is setting clipboard (before paste)
            debug!("Received clipboard_set from client: {} chars", payload.text.len());
            let session = rdp_session.lock().await;
            if let Some(ref rdp) = *session {
                if let Err(e) = rdp.clipboard_set(payload.text).await {
                    debug!("Failed to set clipboard: {}", e);
                }
            }
        }
    }
}

/// Encode RGBA image data to JPEG.
fn encode_jpeg(width: u16, height: u16, rgba_data: &[u8], quality: u8) -> anyhow::Result<Vec<u8>> {
    use image::{ImageBuffer, Rgba};

    // Create image buffer from RGBA data
    let img: ImageBuffer<Rgba<u8>, _> = ImageBuffer::from_raw(
        width as u32,
        height as u32,
        rgba_data.to_vec(),
    )
    .ok_or_else(|| anyhow::anyhow!("Failed to create image buffer"))?;

    // Convert to RGB (JPEG doesn't support alpha)
    let rgb_img = image::DynamicImage::ImageRgba8(img).into_rgb8();

    // Encode to JPEG
    let mut jpeg_data = Vec::new();
    let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg_data, quality);
    rgb_img.write_with_encoder(encoder)?;

    Ok(jpeg_data)
}

/// Get the stream port from environment or default.
pub fn get_stream_port() -> u16 {
    std::env::var("AGENT_RDP_STREAM_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Resolve the stream FPS: connect request, then `AGENT_RDP_STREAM_FPS`, then the default.
///
/// The result is clamped to `1..=MAX_STREAM_FPS`.
pub fn resolve_stream_fps(request: Option<u32>, env: Option<&str>) -> u32 {
    request
        .or_else(|| env.and_then(|s| s.trim().parse().ok()))
        .unwrap_or(DEFAULT_STREAM_FPS)
        .clamp(1, MAX_STREAM_FPS)
}

/// Get the stream FPS for an optional connect-request value (see [`resolve_stream_fps`]).
pub fn get_stream_fps(request: Option<u32>) -> u32 {
    resolve_stream_fps(request, std::env::var("AGENT_RDP_STREAM_FPS").ok().as_deref())
}

/// Interval between broadcast frames at the given FPS.
pub fn frame_interval(fps: u32) -> std::time::Duration {
    std::time::Duration::from_millis(1000 / u64::from(fps.clamp(1, MAX_STREAM_FPS)))
}

/// Get the stream JPEG quality from environment or default.
pub fn get_stream_quality() -> u8 {
    std::env::var("AGENT_RDP_STREAM_QUALITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80)
}

/// Bind the stream port on loopback only: the stream carries full input control and is only
/// meant for consumers on the same host. Access is additionally gated by the stream token
/// (see `stream_auth`), which keeps other local users and web pages out.
async fn bind_loopback(port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_head::MAX_REQUEST_HEAD_BYTES;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn stream_server_listens_on_loopback_only() {
        let server = WsServer::new(WsServerConfig {
            port: 0,
            fps: 10,
            jpeg_quality: 80,
            serve_viewer: false,
        });
        let handle = server
            .start(Arc::new(tokio::sync::Mutex::new(None)))
            .await
            .unwrap();
        assert_eq!(handle.local_addr().ip(), Ipv4Addr::LOCALHOST);
    }

    async fn start_server(serve_viewer: bool) -> WsServerHandle {
        WsServer::new(WsServerConfig {
            port: 0,
            serve_viewer,
            ..Default::default()
        })
        .start(Arc::new(tokio::sync::Mutex::new(None)))
        .await
        .unwrap()
    }

    async fn start_server_on(port: u16) -> WsServerHandle {
        WsServer::new(WsServerConfig {
            port,
            ..Default::default()
        })
        .start(Arc::new(tokio::sync::Mutex::new(None)))
        .await
        .unwrap()
    }

    /// Send a plain HTTP GET and return the response text.
    async fn http_get(port: u16, target: &str) -> String {
        use tokio::io::AsyncReadExt;

        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();
        let request = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    /// A GET with a header block of `padding` bytes, read to the end of the response.
    async fn http_get_with_padding(port: u16, target: &str, padding: usize) -> std::io::Result<String> {
        use tokio::io::AsyncReadExt;

        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: localhost\r\nCookie: {}\r\nConnection: close\r\n\r\n",
            "a".repeat(padding)
        );
        stream.write_all(request.as_bytes()).await?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await?;
        Ok(response)
    }

    #[tokio::test]
    async fn large_heads_under_the_cap_get_the_full_viewer_and_404_responses() {
        for (serve_viewer, status) in [(true, "HTTP/1.1 200"), (false, "HTTP/1.1 404")] {
            let handle = start_server(serve_viewer).await;
            let port = handle.local_addr().port();
            let target = format!("/?token={}", handle.token().as_str());
            // Over the old 4 KiB read, under MAX_REQUEST_HEAD_BYTES
            for _ in 0..20 {
                let response = http_get_with_padding(port, &target, 6000).await.unwrap();
                assert!(response.starts_with(status), "{status}: {}", &response[..response.len().min(80)]);
                assert!(response.contains("Content-Length"));
            }
        }
    }

    fn status_of(err: tokio_tungstenite::tungstenite::Error) -> u16 {
        match err {
            tokio_tungstenite::tungstenite::Error::Http(response) => response.status().as_u16(),
            other => panic!("expected an HTTP error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn websocket_without_or_with_wrong_token_is_401() {
        let handle = start_server(false).await;
        let port = handle.local_addr().port();
        for target in ["", "?token=wrong"] {
            let err = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/{target}"))
                .await
                .unwrap_err();
            assert_eq!(status_of(err), 401);
        }
    }

    #[tokio::test]
    async fn websocket_with_right_token_upgrades() {
        let handle = start_server(false).await;
        let port = handle.local_addr().port();
        let url = format!("ws://127.0.0.1:{port}/?token={}", handle.token().as_str());
        let (_socket, response) = tokio_tungstenite::connect_async(url).await.unwrap();
        assert_eq!(response.status().as_u16(), 101);
    }

    #[tokio::test]
    async fn viewer_requires_token_and_embeds_it() {
        let handle = start_server(true).await;
        let port = handle.local_addr().port();
        let token = handle.token().as_str().to_string();

        assert!(http_get(port, "/").await.starts_with("HTTP/1.1 401"));
        assert!(http_get(port, "/?token=wrong").await.starts_with("HTTP/1.1 401"));

        let ok = http_get(port, &format!("/?token={token}")).await;
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        assert!(ok.contains(&format!("ws://localhost:{port}/?token={token}")));
    }

    #[tokio::test]
    async fn unauthorized_response_does_not_echo_the_request() {
        let handle = start_server(false).await;
        let response = http_get(handle.local_addr().port(), "/?token=leakme").await;
        assert!(response.starts_with("HTTP/1.1 401"));
        assert!(!response.contains("leakme"));
    }

    /// Wait until the client's connection ends.
    async fn expect_closed<S>(socket: &mut S)
    where
        S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
    {
        let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match socket.next().await {
                    None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                    Some(Ok(_)) => {}
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "client connection was not closed");
    }

    #[tokio::test]
    async fn dropping_the_handle_closes_clients_and_frees_the_port() {
        let handle = start_server(false).await;
        let port = handle.local_addr().port();
        let first_token = handle.token().as_str().to_string();
        let url = format!("ws://127.0.0.1:{port}/?token={first_token}");
        let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();

        drop(handle);
        expect_closed(&mut socket).await;

        // The port can be bound again, and a new server gets a new token
        let rebound = start_server_on(port).await;
        assert_ne!(rebound.token().as_str(), first_token);
    }

    #[tokio::test]
    async fn shutdown_closes_clients_and_frees_the_port_immediately() {
        let handle = start_server(false).await;
        let port = handle.local_addr().port();
        let url = format!("ws://127.0.0.1:{port}/?token={}", handle.token().as_str());
        let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();

        handle.shutdown().await;

        // No yield or sleep between shutdown and the rebind
        let _rebound = start_server_on(port).await;
        expect_closed(&mut socket).await;
    }

    #[tokio::test]
    async fn head_arriving_in_pieces_is_authorized_once_complete() {
        let handle = start_server(false).await;
        let port = handle.local_addr().port();
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();
        stream.write_all(b"GET /?tok").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let rest = format!(
            "en={} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            handle.token().as_str()
        );
        stream.write_all(rest.as_bytes()).await.unwrap();

        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 12];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HTTP/1.1 101");
    }

    #[tokio::test]
    async fn oversized_head_gets_400() {
        let handle = start_server(false).await;
        let port = handle.local_addr().port();
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();
        let junk = format!("GET /{} HTTP/1.1\r\n", "a".repeat(MAX_REQUEST_HEAD_BYTES));
        stream.write_all(junk.as_bytes()).await.unwrap();

        use tokio::io::AsyncReadExt;
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response).await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    }

    #[tokio::test]
    async fn tokenless_websocket_clients_get_401_not_a_reset() {
        let handle = start_server(false).await;
        let port = handle.local_addr().port();
        for attempt in 0..50 {
            let err = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/"))
                .await
                .unwrap_err();
            assert_eq!(status_of(err), 401, "attempt {attempt}");
        }
    }

    #[test]
    fn stream_fps_request_beats_env_and_default() {
        assert_eq!(resolve_stream_fps(Some(25), Some("30")), 25);
        assert_eq!(resolve_stream_fps(Some(25), None), 25);
    }

    #[test]
    fn stream_fps_env_beats_default() {
        assert_eq!(resolve_stream_fps(None, Some("30")), 30);
        assert_eq!(resolve_stream_fps(None, Some(" 15 ")), 15);
    }

    #[test]
    fn stream_fps_falls_back_to_default() {
        assert_eq!(resolve_stream_fps(None, None), DEFAULT_STREAM_FPS);
        assert_eq!(resolve_stream_fps(None, Some("not-a-number")), DEFAULT_STREAM_FPS);
    }

    #[test]
    fn stream_fps_is_clamped() {
        assert_eq!(resolve_stream_fps(Some(0), None), 1);
        assert_eq!(resolve_stream_fps(Some(100_000), None), MAX_STREAM_FPS);
        assert_eq!(resolve_stream_fps(None, Some("100000")), MAX_STREAM_FPS);
    }

    #[test]
    fn frame_interval_is_never_zero() {
        assert_eq!(frame_interval(10), std::time::Duration::from_millis(100));
        assert_eq!(frame_interval(0), std::time::Duration::from_millis(1000));
        assert!(!frame_interval(u32::MAX).is_zero());
    }

    fn server_with_quality(jpeg_quality: u8) -> WsServer {
        WsServer::new(WsServerConfig {
            jpeg_quality,
            ..Default::default()
        })
    }

    #[test]
    fn jpeg_quality_is_clamped_to_1_100() {
        assert_eq!(server_with_quality(0).jpeg_quality, 1);
        assert_eq!(server_with_quality(1).jpeg_quality, 1);
        assert_eq!(server_with_quality(80).jpeg_quality, 80);
        assert_eq!(server_with_quality(100).jpeg_quality, 100);
        assert_eq!(server_with_quality(101).jpeg_quality, 100);
        assert_eq!(server_with_quality(255).jpeg_quality, 100);
    }
}
