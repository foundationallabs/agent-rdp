//! Clipboard backend for CLIPRDR integration.
//!
//! This module provides a custom clipboard backend that stores clipboard data
//! and communicates with the frame processor via channels.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use ironrdp_cliprdr::backend::{CliprdrBackend, ClipboardMessage, ClipboardMessageProxy};
use ironrdp_cliprdr::pdu::{
    ClipboardGeneralCapabilityFlags, FileContentsRequest, FileContentsResponse,
    FormatDataRequest, FormatDataResponse, LockDataId, OwnedFormatDataResponse,
};
use ironrdp_cliprdr::{Cliprdr, Client};
use ironrdp_svc::impl_as_any;
use parking_lot::Mutex;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use super::RdpError;

// Re-export types needed by rdp_session
pub use ironrdp_cliprdr::pdu::{ClipboardFormat, ClipboardFormatId};
pub use ironrdp_cliprdr::CliprdrClient;

/// Standard clipboard format ID for Unicode text (CF_UNICODETEXT = 13).
pub fn cf_unicodetext() -> ClipboardFormatId {
    ClipboardFormatId::new(13)
}

/// Messages from backend to frame processor.
#[derive(Debug)]
pub enum BackendMessage {
    /// Backend wants to initiate copy (announce formats).
    InitiateCopy(Vec<ClipboardFormat>),
    /// Backend has format data ready to send.
    FormatData(OwnedFormatDataResponse),
    /// Backend wants to request data from remote.
    InitiatePaste(ClipboardFormatId),
}

/// Proxy that sends messages to the frame processor.
#[derive(Debug, Clone)]
pub struct ChannelProxy {
    tx: mpsc::UnboundedSender<BackendMessage>,
}

impl ChannelProxy {
    pub fn new(tx: mpsc::UnboundedSender<BackendMessage>) -> Self {
        Self { tx }
    }
}

impl ClipboardMessageProxy for ChannelProxy {
    fn send_clipboard_message(&self, message: ClipboardMessage) {
        let backend_msg = match message {
            ClipboardMessage::SendInitiateCopy(formats) => BackendMessage::InitiateCopy(formats),
            ClipboardMessage::SendFormatData(data) => BackendMessage::FormatData(data),
            ClipboardMessage::SendInitiatePaste(format_id) => BackendMessage::InitiatePaste(format_id),
            // File transfer over CLIPRDR is not supported; the backend never produces these.
            ClipboardMessage::SendFileContentsRequest(_)
            | ClipboardMessage::SendFileContentsResponse(_) => {
                debug!("Ignoring unsupported clipboard file contents message");
                return;
            }
            ClipboardMessage::Error(e) => {
                warn!("Clipboard backend error: {}", e);
                return;
            }
        };
        let _ = self.tx.send(backend_msg);
    }
}

/// Shared state for clipboard data.
#[derive(Debug)]
pub struct ClipboardState {
    /// Text we want to send to remote (set by clipboard set command).
    pub local_text: Option<String>,
    /// Text received from remote.
    pub remote_text: Option<String>,
    /// Formats available on remote clipboard.
    pub remote_formats: Vec<ClipboardFormat>,
    /// Pending text get request response channel.
    pub pending_get: Option<tokio::sync::oneshot::Sender<Result<Option<String>, String>>>,
    /// Notify when remote clipboard changes (for WebSocket integration).
    pub clipboard_changed_tx: Option<mpsc::UnboundedSender<()>>,
    /// Whether the remote has finished setting up the channel. Until it has, text we offer is
    /// never asked for.
    pub ready: bool,
    /// Gets the remote's answer to the next format list we send.
    pub format_list_answer_tx: Option<oneshot::Sender<bool>>,
    /// Fires when the remote next asks for our text.
    pub text_requested_tx: Option<oneshot::Sender<()>>,
}

impl Default for ClipboardState {
    fn default() -> Self {
        Self {
            local_text: None,
            remote_text: None,
            remote_formats: Vec::new(),
            pending_get: None,
            clipboard_changed_tx: None,
            ready: false,
            format_list_answer_tx: None,
            text_requested_tx: None,
        }
    }
}

/// Custom clipboard backend that stores data in memory.
#[derive(Debug)]
pub struct AgentClipboardBackend {
    state: Arc<Mutex<ClipboardState>>,
    proxy: ChannelProxy,
}

impl_as_any!(AgentClipboardBackend);

impl AgentClipboardBackend {
    pub fn new(state: Arc<Mutex<ClipboardState>>, proxy: ChannelProxy) -> Self {
        Self { state, proxy }
    }
}

impl CliprdrBackend for AgentClipboardBackend {
    fn temporary_directory(&self) -> &str {
        ".cliprdr"
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
    }

    fn on_ready(&mut self) {
        info!("CLIPRDR clipboard ready");
        self.state.lock().ready = true;
    }

    fn on_format_list_response(&mut self, ok: bool) {
        debug!("Backend: format list response, ok={}", ok);
        if let Some(tx) = self.state.lock().format_list_answer_tx.take() {
            let _ = tx.send(ok);
        }
    }

    fn on_request_format_list(&mut self) {
        debug!("Backend: on_request_format_list");
        // During initialization, send our available formats (if any).
        let state = self.state.lock();
        if state.local_text.is_some() {
            let formats = vec![ClipboardFormat::new(cf_unicodetext())];
            self.proxy.send_clipboard_message(ClipboardMessage::SendInitiateCopy(formats));
        } else {
            // Send empty format list to complete initialization.
            self.proxy.send_clipboard_message(ClipboardMessage::SendInitiateCopy(vec![]));
        }
    }

    fn on_process_negotiated_capabilities(&mut self, _capabilities: ClipboardGeneralCapabilityFlags) {
        debug!("Backend: negotiated capabilities");
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        debug!("Backend: remote copied, formats: {:?}", available_formats);
        let mut state = self.state.lock();
        state.remote_formats = available_formats.to_vec();
        // Clear old remote data since new data is available.
        state.remote_text = None;

        // Notify WebSocket clients that clipboard changed (if channel is set up).
        if let Some(ref tx) = state.clipboard_changed_tx {
            let _ = tx.send(());
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        debug!("Backend: format data request for {:?}", request.format);
        let mut state = self.state.lock();

        let response = if request.format == cf_unicodetext() {
            if let Some(ref text) = state.local_text {
                // Convert to UTF-16LE with null terminator.
                let utf16: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
                let bytes: Vec<u8> = utf16.iter().flat_map(|&c| c.to_le_bytes()).collect();
                if let Some(tx) = state.text_requested_tx.take() {
                    let _ = tx.send(());
                }
                OwnedFormatDataResponse::new_data(bytes)
            } else {
                OwnedFormatDataResponse::new_error()
            }
        } else {
            OwnedFormatDataResponse::new_error()
        };

        self.proxy.send_clipboard_message(ClipboardMessage::SendFormatData(response));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        debug!("Backend: format data response, is_error={}", response.is_error());

        let mut state = self.state.lock();

        if response.is_error() {
            // Server returned error - clipboard is empty or doesn't have text format.
            // This is normal, not an error condition.
            if let Some(tx) = state.pending_get.take() {
                let _ = tx.send(Ok(None));
            }
            return;
        }

        // Decode UTF-16LE to String.
        let data = response.data();
        if data.len() >= 2 {
            let utf16: Vec<u16> = data
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            // Remove null terminator if present.
            let text: String = String::from_utf16_lossy(&utf16)
                .trim_end_matches('\0')
                .to_string();

            debug!("Received clipboard text: {} chars", text.len());
            state.remote_text = Some(text.clone());

            if let Some(tx) = state.pending_get.take() {
                let _ = tx.send(Ok(Some(text)));
            }
        } else if let Some(tx) = state.pending_get.take() {
            let _ = tx.send(Ok(None));
        }
    }

    fn on_file_contents_request(&mut self, _request: FileContentsRequest) {
        debug!("Backend: file contents request (not supported)");
    }

    fn on_file_contents_response(&mut self, _response: FileContentsResponse<'_>) {
        debug!("Backend: file contents response (not supported)");
    }

    fn on_lock(&mut self, _data_id: LockDataId) {
        debug!("Backend: lock");
    }

    fn on_unlock(&mut self, _data_id: LockDataId) {
        debug!("Backend: unlock");
    }
}

/// Why a paste did not go through. Nothing was pasted in any of these cases.
#[derive(Debug, Error)]
pub enum PasteError {
    #[error("the remote has not set up the clipboard channel")]
    NotReady,
    #[error("the remote did not accept the clipboard text")]
    NotAccepted,
    #[error("the remote did not ask for the clipboard text after the paste")]
    NotRequested,
    #[error(transparent)]
    Session(#[from] RdpError),
}

/// Offer the text with `announce`, press paste with `press_paste`, and confirm the remote took
/// the text.
///
/// A broken channel takes the offer without an error and then pastes nothing, for the rest of
/// the session. So this waits up to `step_timeout` for the remote to accept the offer before
/// pressing paste, and as long again for it to ask for the text. A request any time after the
/// offer counts, because a clipboard history or other watcher on the remote can fetch the text
/// before the paste, which then uses that copy. When no request comes, the offer is withdrawn,
/// so a late one gets nothing and the caller can type the text instead without doubling it.
pub async fn paste_and_confirm<A, P>(
    state: &Mutex<ClipboardState>,
    step_timeout: Duration,
    announce: A,
    press_paste: P,
) -> Result<(), PasteError>
where
    A: Future<Output = Result<(), RdpError>>,
    P: Future<Output = Result<(), RdpError>>,
{
    let (answer_tx, answer_rx) = oneshot::channel();
    let (requested_tx, mut requested_rx) = oneshot::channel();
    {
        let mut state = state.lock();
        if !state.ready {
            return Err(PasteError::NotReady);
        }
        state.format_list_answer_tx = Some(answer_tx);
        state.text_requested_tx = Some(requested_tx);
    }

    if let Err(e) = announce.await {
        withdraw_offer(&mut state.lock());
        return Err(e.into());
    }
    let accepted = matches!(tokio::time::timeout(step_timeout, answer_rx).await, Ok(Ok(true)));
    if !accepted {
        withdraw_offer(&mut state.lock());
        return Err(PasteError::NotAccepted);
    }

    if let Err(e) = press_paste.await {
        withdraw_offer(&mut state.lock());
        return Err(e.into());
    }
    if let Ok(Ok(())) = tokio::time::timeout(step_timeout, &mut requested_rx).await {
        return Ok(());
    }

    // The backend answers requests under this lock, so a request either came before it, or
    // finds the offer withdrawn.
    let mut locked = state.lock();
    if requested_rx.try_recv().is_ok() {
        return Ok(());
    }
    withdraw_offer(&mut locked);
    Err(PasteError::NotRequested)
}

fn withdraw_offer(state: &mut ClipboardState) {
    state.local_text = None;
    state.format_list_answer_tx = None;
    state.text_requested_tx = None;
}

/// Create the cliprdr client with our custom backend.
/// Returns the cliprdr client and a receiver for backend messages.
pub fn create_cliprdr(
    state: Arc<Mutex<ClipboardState>>,
) -> (CliprdrClient, mpsc::UnboundedReceiver<BackendMessage>) {
    let (proxy_tx, proxy_rx) = mpsc::unbounded_channel();
    let proxy = ChannelProxy::new(proxy_tx);
    let backend = Box::new(AgentClipboardBackend::new(state, proxy));
    let cliprdr = Cliprdr::<Client>::new(backend);
    (cliprdr, proxy_rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STEP: Duration = Duration::from_millis(50);

    fn done() -> Result<(), RdpError> {
        Ok(())
    }

    fn must_not_run(what: &str) -> Result<(), RdpError> {
        panic!("{what}")
    }

    struct Remote {
        state: Arc<Mutex<ClipboardState>>,
        backend: Mutex<AgentClipboardBackend>,
        sent: Mutex<mpsc::UnboundedReceiver<BackendMessage>>,
    }

    impl Remote {
        fn ready() -> Self {
            let state = Arc::new(Mutex::new(ClipboardState::default()));
            let (tx, rx) = mpsc::unbounded_channel();
            let mut backend = AgentClipboardBackend::new(Arc::clone(&state), ChannelProxy::new(tx));
            backend.on_ready();
            Self { state, backend: Mutex::new(backend), sent: Mutex::new(rx) }
        }

        /// What `clipboard_set` does in the frame processor.
        fn offer(&self, text: &str) {
            self.state.lock().local_text = Some(text.to_string());
        }

        fn answer_format_list(&self, ok: bool) {
            self.backend.lock().on_format_list_response(ok);
        }

        /// The remote asks for our text; returns whether it got any.
        fn request_text(&self) -> bool {
            self.backend.lock().on_format_data_request(FormatDataRequest { format: cf_unicodetext() });
            match self.sent.lock().try_recv() {
                Ok(BackendMessage::FormatData(response)) => !response.is_error(),
                other => panic!("expected a format data response, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn confirms_a_paste_the_remote_asks_for() {
        let remote = Remote::ready();
        let result = paste_and_confirm(
            &remote.state,
            STEP,
            async {
                remote.offer("https://example.com/a/long/path");
                remote.answer_format_list(true);
                done()
            },
            async {
                assert!(remote.request_text());
                done()
            },
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn refuses_before_offering_when_the_channel_never_got_ready() {
        let remote = Remote::ready();
        remote.state.lock().ready = false;
        let result = paste_and_confirm(
            &remote.state,
            STEP,
            async { must_not_run("offered on a channel that is not ready") },
            async { must_not_run("pressed paste on a channel that is not ready") },
        )
        .await;
        assert!(matches!(result, Err(PasteError::NotReady)), "{result:?}");
    }

    #[tokio::test]
    async fn does_not_press_paste_when_the_remote_never_answers_the_offer() {
        let remote = Remote::ready();
        let result = paste_and_confirm(
            &remote.state,
            STEP,
            async {
                remote.offer("https://example.com/a/long/path");
                done()
            },
            async { must_not_run("pressed paste without an accepted offer") },
        )
        .await;
        assert!(matches!(result, Err(PasteError::NotAccepted)), "{result:?}");
        assert!(remote.state.lock().local_text.is_none());
    }

    #[tokio::test]
    async fn does_not_press_paste_when_the_remote_rejects_the_offer() {
        let remote = Remote::ready();
        let result = paste_and_confirm(
            &remote.state,
            STEP,
            async {
                remote.offer("https://example.com/a/long/path");
                remote.answer_format_list(false);
                done()
            },
            async { must_not_run("pressed paste after a rejected offer") },
        )
        .await;
        assert!(matches!(result, Err(PasteError::NotAccepted)), "{result:?}");
    }

    #[tokio::test]
    async fn withdraws_the_text_when_the_remote_never_asks_for_it() {
        let remote = Remote::ready();
        let result = paste_and_confirm(
            &remote.state,
            STEP,
            async {
                remote.offer("https://example.com/a/long/path");
                remote.answer_format_list(true);
                done()
            },
            async { done() },
        )
        .await;
        assert!(matches!(result, Err(PasteError::NotRequested)), "{result:?}");
        assert!(!remote.request_text(), "a late request must not paste the text");
    }

    #[tokio::test]
    async fn counts_a_request_made_before_the_paste_key() {
        let remote = Remote::ready();
        let result = paste_and_confirm(
            &remote.state,
            STEP,
            async {
                remote.offer("https://example.com/a/long/path");
                remote.answer_format_list(true);
                assert!(remote.request_text());
                done()
            },
            async { done() },
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
    }
}
