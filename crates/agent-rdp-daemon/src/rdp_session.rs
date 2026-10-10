//! RDP session wrapper using IronRDP.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use parking_lot::RwLock;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use agent_rdp_protocol::{AuthFailureReason, DriveMapping};
use ironrdp::connector::{
    self, ClientConnector, ClientConnectorState, ConnectionResult, ConnectorError, ConnectorResult,
    Credentials, ServerName,
};
use ironrdp::pdu::gcc::KeyboardType;
use ironrdp::pdu::input::fast_path::FastPathInputEvent;
use ironrdp::pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp::pdu::rdp::client_info::PerformanceFlags;
use ironrdp::pdu::WriteBuf;
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStage, ActiveStageOutput};
use ironrdp_dvc::DrdynvcClient;
use ironrdp_rdpdr::Rdpdr;

use crate::automation::{AutomationDvc, SharedDvcState};
use crate::logon::{self, LogonOutcome, LogonReport, LogonWatch};
use crate::rdpdr::MultiDriveBackend;
use crate::tls::{self, CertPin};
use ironrdp_rdpsnd::client::{NoopRdpsndBackend, Rdpsnd};
use ironrdp_tokio::{FramedWrite, TokioFramed};
use tokio::net::TcpStream;

pub mod clipboard;
#[cfg(test)]
mod mock_server;

#[derive(Error, Debug)]
pub enum RdpError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Authentication failed ({0:?})")]
    AuthenticationFailed(AuthFailureReason),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("{0}")]
    CertificateMismatch(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Not connected")]
    NotConnected,

    #[error("Session closed")]
    SessionClosed,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl From<ConnectorError> for RdpError {
    fn from(error: ConnectorError) -> Self {
        match logon::connector_auth_failure(&error) {
            Some(reason) => Self::AuthenticationFailed(reason),
            None => Self::ConnectionFailed(error.to_string()),
        }
    }
}

/// A pin mismatch is its own error, so the caller does not retry it as a connection failure.
fn tls_upgrade_error(error: std::io::Error) -> RdpError {
    match tls::certificate_mismatch(&error) {
        Some(mismatch) => RdpError::CertificateMismatch(mismatch.to_string()),
        None => RdpError::TlsError(error.to_string()),
    }
}

/// How long an NLA-off `connect()` waits for the server to report the login result before it
/// fails closed. Short of the SDK's 30 s default request timeout, so the connect response still
/// reaches the caller.
const LOGON_OUTCOME_WINDOW: Duration = Duration::from_secs(20);

/// Whether `connect()` must wait for the server to confirm the login. Without CredSSP the server
/// checks the password only after the connection is up. Reads what the server selected: it can
/// pick TLS-only even when the client offered NLA.
fn awaits_logon(connector: &ClientConnector) -> bool {
    !connector.should_perform_credssp()
}

/// `connect_finalize` for a server that selected TLS-only security. The credentials travel in
/// the Client Info PDU, and the server may check them as soon as it arrives, so an end after it
/// was sent fails the login closed (see [`finalize_error`]).
async fn finalize_without_nla(
    mut connector: ClientConnector,
    framed: &mut TokioFramed<tokio_rustls::client::TlsStream<TcpStream>>,
) -> Result<ConnectionResult, RdpError> {
    let mut buf = WriteBuf::new();
    let mut credentials_sent = false;
    loop {
        let sends_client_info = matches!(
            connector.state,
            ClientConnectorState::SecureSettingsExchange { .. }
        );
        if let Err(error) =
            ironrdp_tokio::single_sequence_step(framed, &mut connector, &mut buf).await
        {
            return Err(finalize_error(error, credentials_sent));
        }
        credentials_sent |= sends_client_info;
        if let ClientConnectorState::Connected { result } = connector.state {
            return Ok(result);
        }
    }
}

/// Once the credentials are out, a failure is not a connection failure the caller may retry:
/// the server may have counted a login attempt.
fn finalize_error(error: ConnectorError, credentials_sent: bool) -> RdpError {
    match RdpError::from(error) {
        RdpError::ConnectionFailed(message) if credentials_sent => {
            warn!(%message, "Connection ended after the credentials were sent; ending the login unconfirmed");
            RdpError::AuthenticationFailed(AuthFailureReason::LogonUnconfirmed)
        }
        other => other,
    }
}

/// The NLA-off login result: success only when the server confirmed the login. Silence and a
/// session end both fail closed: on some hosts Windows sends nothing for a wrong password, and
/// the server may have counted the attempt before the session ended.
fn logon_verdict(report: Option<LogonReport>) -> Result<(), RdpError> {
    match report {
        Some(LogonReport::Outcome(LogonOutcome::Succeeded)) => {
            info!("Server confirmed the login");
            Ok(())
        }
        Some(LogonReport::Outcome(LogonOutcome::Failed(reason))) => {
            Err(RdpError::AuthenticationFailed(reason))
        }
        Some(LogonReport::SessionEnded) => {
            warn!("Session ended before the server confirmed the login");
            Err(RdpError::AuthenticationFailed(
                AuthFailureReason::LogonUnconfirmed,
            ))
        }
        None => {
            warn!(
                "No login confirmation from the server within {:?}; ending the session",
                LOGON_OUTCOME_WINDOW
            );
            Err(RdpError::AuthenticationFailed(
                AuthFailureReason::LogonUnconfirmed,
            ))
        }
    }
}

/// Configuration for an RDP connection.
pub struct RdpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub domain: Option<String>,
    /// Alternate shell to start instead of the desktop (e.g. CyberArk PSM).
    pub alternate_shell: Option<String>,
    /// Negotiate NLA/CredSSP. When false, only TLS security is used.
    pub enable_credssp: bool,
    pub width: u16,
    pub height: u16,
    /// Drives to map at connect time.
    pub drives: Vec<DriveMapping>,
    /// Shared DVC state for automation (enables DVC channel if provided).
    pub automation_dvc_state: Option<SharedDvcState>,
    /// Required server key. Without one, any certificate is accepted.
    pub server_cert_pin: Option<CertPin>,
}

use crate::automation::DvcCommandReceiver;

/// Commands sent to the background frame processor.
enum SessionCommand {
    SendInput(Vec<FastPathInputEvent>),
    /// Set clipboard text and announce to remote.
    ClipboardSet {
        text: String,
        response_tx: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    /// Get clipboard text from remote.
    ClipboardGet {
        response_tx: tokio::sync::oneshot::Sender<Result<Option<String>, String>>,
    },
    Shutdown,
}

/// Shared session state accessible from the main thread.
struct SharedState {
    image: DecodedImage,
    host: String,
    width: u16,
    height: u16,
    /// Drives that were mapped at connect time.
    drives: Vec<DriveMapping>,
    /// Clipboard state for CLIPRDR.
    clipboard: Arc<parking_lot::Mutex<clipboard::ClipboardState>>,
}

/// An active RDP session with background frame processing.
pub struct RdpSession {
    /// Shared state (image, connection info)
    shared: Arc<RwLock<SharedState>>,
    /// Channel to send commands to the background task
    command_tx: mpsc::Sender<SessionCommand>,
    /// Handle to the background task
    _task_handle: tokio::task::JoinHandle<()>,
}

/// Callback type for connection drop notification.
pub type DisconnectNotify = mpsc::Sender<()>;

/// Build the IronRDP connector config for an RDP connection.
fn build_connector_config(config: &RdpConfig) -> connector::Config {
    connector::Config {
        credentials: Credentials::UsernamePassword {
            username: config.username.clone(),
            password: config.password.clone(),
        },
        domain: config.domain.clone(),
        enable_tls: true,
        enable_credssp: config.enable_credssp,
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0x409, // US English
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: connector::DesktopSize {
            width: config.width,
            height: config.height,
        },
        bitmap: None,
        client_build: 0,
        client_name: "agent-rdp".to_string(),
        client_dir: String::new(),
        alternate_shell: config.alternate_shell.clone().unwrap_or_default(),
        work_dir: String::new(),
        #[cfg(windows)]
        platform: MajorPlatformType::WINDOWS,
        #[cfg(target_os = "macos")]
        platform: MajorPlatformType::MACINTOSH,
        #[cfg(all(not(windows), not(target_os = "macos")))]
        platform: MajorPlatformType::UNIX,
        pointer_software_rendering: true,
        performance_flags: PerformanceFlags::default(),
        enable_server_pointer: false,
        request_data: None,
        autologon: true,
        enable_audio_playback: false,
        desktop_scale_factor: 0,
        hardware_id: None,
        license_cache: None,
        timezone_info: Default::default(),
        compression_type: None,
        multitransport_flags: None,
    }
}

impl RdpSession {
    /// Establish a new RDP connection.
    ///
    /// If `disconnect_notify` is provided, it will be signaled when the connection drops.
    pub async fn connect(
        config: RdpConfig,
        disconnect_notify: Option<DisconnectNotify>,
    ) -> Result<Self, RdpError> {
        info!("Connecting to {}:{}", config.host, config.port);

        let connector_config = build_connector_config(&config);

        // Establish TCP connection
        let addr = format!("{}:{}", config.host, config.port);
        let tcp_stream = TcpStream::connect(&addr).await?;
        let client_addr: SocketAddr = tcp_stream.local_addr()?;
        debug!("TCP connection established from {:?}", client_addr);

        // Create framed transport for initial connection
        let mut framed: TokioFramed<TcpStream> = TokioFramed::new(tcp_stream);

        // Create connector
        let mut connector = ClientConnector::new(connector_config, client_addr);

        // Create clipboard state (shared between backend and session)
        let clipboard_state = Arc::new(parking_lot::Mutex::new(clipboard::ClipboardState::default()));

        // RDPSND (audio) channel - required for RDPDR on Windows 2012+ and good to have
        let rdpsnd = Rdpsnd::new(Box::new(NoopRdpsndBackend));
        connector.attach_static_channel(rdpsnd);

        // Set up CLIPRDR (clipboard) with our custom backend
        let (cliprdr, clipboard_backend_rx) = clipboard::create_cliprdr(Arc::clone(&clipboard_state));
        connector.attach_static_channel(cliprdr);
        info!("Clipboard redirection enabled");

        // Set up RDPDR (drive redirection) if drives are configured
        if !config.drives.is_empty() {
            // Create multi-drive backend with all drive paths
            let mut backend = MultiDriveBackend::new();

            // Configure drives - device IDs start at 1
            let drive_list: Vec<(u32, String)> = config
                .drives
                .iter()
                .enumerate()
                .map(|(idx, d)| {
                    let device_id = (idx + 1) as u32;
                    // Register path for this device ID
                    backend.add_drive(device_id, std::path::PathBuf::from(&d.path));
                    (device_id, d.name.clone())
                })
                .collect();

            let rdpdr = Rdpdr::new(Box::new(backend), "agent-rdp".to_string());
            let rdpdr = rdpdr.with_drives(Some(drive_list.clone()));
            connector.attach_static_channel(rdpdr);

            for (device_id, name) in &drive_list {
                let path = &config.drives[(*device_id - 1) as usize].path;
                info!(
                    "Drive redirection enabled: {} -> \\\\TSCLIENT\\{} (device_id={})",
                    path, name, device_id
                );
            }
        }

        // Set up DRDYNVC (dynamic virtual channels) for automation if enabled
        let dvc_command_rx: Option<DvcCommandReceiver> = if let Some(dvc_state) = config.automation_dvc_state {
            // Create command channel for sending DVC data
            let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel();

            // Store the sender in the shared state
            {
                let mut state = dvc_state.lock();
                state.command_tx = Some(command_tx);
            }

            let automation_dvc = AutomationDvc::new(dvc_state);
            let drdynvc = DrdynvcClient::new().with_dynamic_channel(automation_dvc);
            connector.attach_static_channel(drdynvc);
            info!("Dynamic Virtual Channel enabled for automation");
            Some(command_rx)
        } else {
            None
        };

        // Begin connection (pre-TLS)
        let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector).await?;

        // Perform TLS upgrade
        let initial_stream: TcpStream = framed.into_inner_no_leftover();
        let (tls_stream, server_cert) =
            tls::upgrade(initial_stream, &config.host, config.server_cert_pin.as_ref())
                .await
                .map_err(tls_upgrade_error)?;
        debug!("TLS connection established");

        // Mark upgrade as done
        let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
        let await_logon = awaits_logon(&connector);

        // Create framed transport for upgraded connection
        let mut upgraded_framed: TokioFramed<tokio_rustls::client::TlsStream<TcpStream>> =
            TokioFramed::new(tls_stream);

        // Extract server public key from certificate
        let server_public_key = Self::extract_public_key(&server_cert)?;

        // Create network client for CredSSP
        let mut network_client = NoopNetworkClient;

        // Convert host to ServerName
        let server_name: ServerName = config.host.clone().into();

        // Finalize connection (post-TLS)
        let connection_result = if await_logon {
            finalize_without_nla(connector, &mut upgraded_framed).await?
        } else {
            ironrdp_tokio::connect_finalize(
                upgraded,
                connector,
                &mut upgraded_framed,
                &mut network_client,
                server_name,
                server_public_key,
                None, // No Kerberos
            )
            .await?
        };

        info!("RDP connection established to {}", config.host);

        // Create decoded image for storing desktop state
        let image = DecodedImage::new(
            ironrdp_graphics::image_processing::PixelFormat::RgbA32,
            connection_result.desktop_size.width,
            connection_result.desktop_size.height,
        );

        let (logon_tx, logon_rx) = if await_logon {
            let (tx, rx) = tokio::sync::oneshot::channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let logon_watch = LogonWatch::new(connection_result.io_channel_id, logon_tx);

        // Create active stage for ongoing communication
        let active_stage = ActiveStage::new(connection_result);

        // Create shared state
        let shared = Arc::new(RwLock::new(SharedState {
            image,
            host: config.host.clone(),
            width: config.width,
            height: config.height,
            drives: config.drives.clone(),
            clipboard: clipboard_state,
        }));

        // Create command channel
        let (command_tx, command_rx) = mpsc::channel(32);

        // Spawn background frame processor
        let shared_clone = Arc::clone(&shared);
        let task_handle = tokio::spawn(async move {
            run_frame_processor(
                upgraded_framed,
                active_stage,
                shared_clone,
                command_rx,
                disconnect_notify,
                clipboard_backend_rx,
                dvc_command_rx,
                logon_watch,
            )
            .await;
        });

        if let Some(logon_rx) = logon_rx {
            let report = logon::await_logon_report(logon_rx, LOGON_OUTCOME_WINDOW).await;
            if let Err(error) = logon_verdict(report) {
                // Leave no session sitting at the Windows logon screen. A graceful shutdown does
                // not report a drop to the daemon, and is a no-op when the session already ended.
                let _ = command_tx.send(SessionCommand::Shutdown).await;
                return Err(error);
            }
        }

        Ok(Self {
            shared,
            command_tx,
            _task_handle: task_handle,
        })
    }

    /// Extract public key from DER-encoded certificate.
    fn extract_public_key(cert_der: &[u8]) -> Result<Vec<u8>, RdpError> {
        use x509_cert::der::Decode;

        let cert = x509_cert::Certificate::from_der(cert_der)
            .map_err(|e| RdpError::TlsError(format!("Failed to parse certificate: {}", e)))?;

        Ok(cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| RdpError::TlsError("No public key in certificate".into()))?
            .to_vec())
    }

    /// Get the connected host.
    pub fn host(&self) -> String {
        self.shared.read().host.clone()
    }

    /// Get the desktop width.
    pub fn width(&self) -> u16 {
        self.shared.read().width
    }

    /// Get the desktop height.
    pub fn height(&self) -> u16 {
        self.shared.read().height
    }

    /// Get the drives that were mapped at connect time.
    pub fn get_drives(&self) -> Vec<DriveMapping> {
        self.shared.read().drives.clone()
    }

    /// Get a copy of the current desktop image data.
    pub fn get_image_data(&self) -> (u16, u16, Vec<u8>) {
        let state = self.shared.read();
        let width = state.image.width();
        let height = state.image.height();
        let data = state.image.data().to_vec();
        (width, height, data)
    }

    /// Send input events to the remote desktop.
    pub async fn send_input(&self, events: Vec<FastPathInputEvent>) -> Result<(), RdpError> {
        debug!("Sending {} input events to frame processor", events.len());
        self.command_tx
            .send(SessionCommand::SendInput(events))
            .await
            .map_err(|_| RdpError::SessionClosed)
    }

    /// Send a key combination (e.g., "super+r", "ctrl+c").
    pub async fn send_key_press(&self, keys: &str) -> Result<(), RdpError> {
        use std::time::Duration;

        let key_infos = parse_key_combination(keys)
            .map_err(|e| RdpError::InvalidInput(e))?;

        // Press all keys down
        for info in &key_infos {
            let event = create_key_event(info.scancode, info.extended, false);
            self.send_input(vec![event]).await?;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Small delay before releasing
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Release all keys in reverse order
        for info in key_infos.iter().rev() {
            let event = create_key_event(info.scancode, info.extended, true);
            self.send_input(vec![event]).await?;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        Ok(())
    }

    /// Send text input as Unicode characters.
    pub async fn send_text(&self, text: &str) -> Result<(), RdpError> {
        use ironrdp::pdu::input::fast_path::KeyboardFlags;
        use std::time::Duration;

        for ch in text.chars() {
            let code = ch as u16;
            let events = vec![
                FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::empty(), code),
                FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::RELEASE, code),
            ];
            self.send_input(events).await?;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        Ok(())
    }

    /// Set clipboard text (will be available when remote pastes).
    pub async fn clipboard_set(&self, text: String) -> Result<(), RdpError> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(SessionCommand::ClipboardSet { text, response_tx })
            .await
            .map_err(|_| RdpError::SessionClosed)?;

        response_rx
            .await
            .map_err(|_| RdpError::SessionClosed)?
            .map_err(|e| RdpError::ProtocolError(e))
    }

    /// Get clipboard text from remote.
    pub async fn clipboard_get(&self) -> Result<Option<String>, RdpError> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(SessionCommand::ClipboardGet { response_tx })
            .await
            .map_err(|_| RdpError::SessionClosed)?;

        response_rx
            .await
            .map_err(|_| RdpError::SessionClosed)?
            .map_err(|e| RdpError::ProtocolError(e))
    }

    /// Disconnect from the RDP server.
    pub async fn disconnect(self) -> Result<(), RdpError> {
        info!("Disconnecting from RDP session");
        let _ = self.command_tx.send(SessionCommand::Shutdown).await;
        Ok(())
    }

    /// Set up clipboard change notification channel (for WebSocket integration).
    /// When the remote clipboard changes, a message will be sent through this channel.
    pub fn set_clipboard_changed_notify(&self, tx: mpsc::UnboundedSender<()>) {
        let state = self.shared.read();
        let mut clipboard = state.clipboard.lock();
        clipboard.clipboard_changed_tx = Some(tx);
    }
}

/// Background task that continuously processes RDP frames.
async fn run_frame_processor(
    mut framed: TokioFramed<tokio_rustls::client::TlsStream<TcpStream>>,
    mut active_stage: ActiveStage,
    shared: Arc<RwLock<SharedState>>,
    mut command_rx: mpsc::Receiver<SessionCommand>,
    disconnect_notify: Option<DisconnectNotify>,
    mut clipboard_backend_rx: mpsc::UnboundedReceiver<clipboard::BackendMessage>,
    mut dvc_command_rx: Option<DvcCommandReceiver>,
    mut logon_watch: LogonWatch,
) {
    info!("Frame processor started");
    let mut graceful_shutdown = false;
    let mut end = LogonReport::SessionEnded;

    loop {
        tokio::select! {
            // Handle incoming commands
            cmd = command_rx.recv() => {
                match cmd {
                    Some(SessionCommand::SendInput(events)) => {
                        debug!("Frame processor received {} input events", events.len());
                        // Process input and collect response frames
                        let frames_to_send: Vec<Vec<u8>> = {
                            let mut state = shared.write();
                            match active_stage.process_fastpath_input(&mut state.image, &events) {
                                Ok(outputs) => {
                                    debug!("Input processing generated {} outputs", outputs.len());
                                    outputs.into_iter()
                                        .filter_map(|o| {
                                            if let ActiveStageOutput::ResponseFrame(frame) = o {
                                                Some(frame)
                                            } else {
                                                None
                                            }
                                        })
                                        .collect()
                                }
                                Err(e) => {
                                    error!("Failed to process input: {}", e);
                                    Vec::new()
                                }
                            }
                        };
                        // Send frames after releasing lock
                        debug!("Sending {} input response frames", frames_to_send.len());
                        for frame in &frames_to_send {
                            debug!("Sending input frame of {} bytes", frame.len());
                            if let Err(e) = framed.write_all(frame).await {
                                error!("Failed to send input frame: {}", e);
                            }
                        }
                    }
                    Some(SessionCommand::ClipboardSet { text, response_tx }) => {
                        debug!("Clipboard set: {} chars", text.len());
                        // Store text in clipboard state
                        {
                            let state = shared.read();
                            let mut clipboard = state.clipboard.lock();
                            clipboard.local_text = Some(text);
                        }
                        // Trigger initiate_copy to announce we have data
                        if let Some(cliprdr) = active_stage.get_svc_processor_mut::<clipboard::CliprdrClient>() {
                            let formats = vec![clipboard::ClipboardFormat::new(clipboard::cf_unicodetext())];
                            match cliprdr.initiate_copy(&formats) {
                                Ok(messages) => {
                                    if let Ok(pdu_bytes) = active_stage.process_svc_processor_messages(messages) {
                                        let _ = framed.write_all(&pdu_bytes).await;
                                    }
                                    let _ = response_tx.send(Ok(()));
                                }
                                Err(e) => {
                                    let _ = response_tx.send(Err(format!("initiate_copy failed: {}", e)));
                                }
                            }
                        } else {
                            let _ = response_tx.send(Err("Clipboard not available".to_string()));
                        }
                    }
                    Some(SessionCommand::ClipboardGet { response_tx }) => {
                        debug!("Clipboard get requested");
                        // Check if we already have remote text cached
                        let cached = {
                            let state = shared.read();
                            let clipboard = state.clipboard.lock();
                            clipboard.remote_text.clone()
                        };
                        if let Some(text) = cached {
                            let _ = response_tx.send(Ok(Some(text)));
                        } else {
                            // Need to request from remote - store the response channel
                            {
                                let state = shared.read();
                                let mut clipboard = state.clipboard.lock();
                                clipboard.pending_get = Some(response_tx);
                            }
                            // Initiate paste to request data
                            if let Some(cliprdr) = active_stage.get_svc_processor_mut::<clipboard::CliprdrClient>() {
                                match cliprdr.initiate_paste(clipboard::cf_unicodetext()) {
                                    Ok(messages) => {
                                        if let Ok(pdu_bytes) = active_stage.process_svc_processor_messages(messages) {
                                            let _ = framed.write_all(&pdu_bytes).await;
                                        }
                                    }
                                    Err(e) => {
                                        error!("initiate_paste failed: {}", e);
                                        // Return pending response with error
                                        let state = shared.read();
                                        let mut clipboard = state.clipboard.lock();
                                        if let Some(tx) = clipboard.pending_get.take() {
                                            let _ = tx.send(Err(format!("initiate_paste failed: {}", e)));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Some(SessionCommand::Shutdown) => {
                        info!("Shutdown command received");
                        graceful_shutdown = true;
                        // Collect shutdown frames
                        let frames_to_send: Vec<Vec<u8>> = {
                            if let Ok(outputs) = active_stage.graceful_shutdown() {
                                outputs.into_iter()
                                    .filter_map(|o| {
                                        if let ActiveStageOutput::ResponseFrame(frame) = o {
                                            Some(frame)
                                        } else {
                                            None
                                        }
                                    })
                                    .collect()
                            } else {
                                Vec::new()
                            }
                        };
                        // Send frames
                        for frame in frames_to_send {
                            let _ = framed.write_all(&frame).await;
                        }
                        break;
                    }
                    None => {
                        // Channel closed, exit
                        break;
                    }
                }
            }

            // Process incoming RDP frames
            result = framed.read_pdu() => {
                match result {
                    Ok((action, payload)) => {
                        // Process frame and collect responses
                        let (frames_to_send, should_terminate) = {
                            let mut state = shared.write();
                            match active_stage.process(&mut state.image, action, &payload) {
                                Ok(outputs) => {
                                    let mut frames = Vec::new();
                                    let mut terminate = false;
                                    for output in outputs {
                                        match output {
                                            ActiveStageOutput::ResponseFrame(frame) => {
                                                frames.push(frame);
                                            }
                                            ActiveStageOutput::Terminate(reason) => {
                                                warn!("Session terminated: {:?}", reason);
                                                terminate = true;
                                            }
                                            _ => {}
                                        }
                                    }
                                    (frames, terminate)
                                }
                                Err(e) => {
                                    error!("Failed to process frame: {}", e);
                                    (Vec::new(), false)
                                }
                            }
                        };
                        // Send frames after releasing lock
                        for frame in frames_to_send {
                            if let Err(e) = framed.write_all(&frame).await {
                                error!("Failed to send response frame: {}", e);
                            }
                        }
                        if let Some(reason) = logon_watch.observe(action, &payload) {
                            // Leave no session sitting at the Windows logon screen.
                            warn!(?reason, "Server rejected the login, ending the session");
                            end = LogonReport::Outcome(LogonOutcome::Failed(reason));
                            break;
                        }
                        if should_terminate {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Failed to read PDU: {}", e);
                        break;
                    }
                }
            }

            // Handle clipboard backend messages
            msg = clipboard_backend_rx.recv() => {
                if let Some(msg) = msg {
                    match msg {
                        clipboard::BackendMessage::InitiateCopy(formats) => {
                            debug!("Backend: InitiateCopy with {} formats", formats.len());
                            if let Some(cliprdr) = active_stage.get_svc_processor_mut::<clipboard::CliprdrClient>() {
                                if let Ok(messages) = cliprdr.initiate_copy(&formats) {
                                    if let Ok(pdu_bytes) = active_stage.process_svc_processor_messages(messages) {
                                        let _ = framed.write_all(&pdu_bytes).await;
                                    }
                                }
                            }
                        }
                        clipboard::BackendMessage::FormatData(response) => {
                            debug!("Backend: FormatData");
                            if let Some(cliprdr) = active_stage.get_svc_processor_mut::<clipboard::CliprdrClient>() {
                                if let Ok(messages) = cliprdr.submit_format_data(response) {
                                    if let Ok(pdu_bytes) = active_stage.process_svc_processor_messages(messages) {
                                        let _ = framed.write_all(&pdu_bytes).await;
                                    }
                                }
                            }
                        }
                        clipboard::BackendMessage::InitiatePaste(format_id) => {
                            debug!("Backend: InitiatePaste for {:?}", format_id);
                            if let Some(cliprdr) = active_stage.get_svc_processor_mut::<clipboard::CliprdrClient>() {
                                if let Ok(messages) = cliprdr.initiate_paste(format_id) {
                                    if let Ok(pdu_bytes) = active_stage.process_svc_processor_messages(messages) {
                                        let _ = framed.write_all(&pdu_bytes).await;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Handle DVC commands (for automation)
            dvc_cmd = async {
                match dvc_command_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(cmd) = dvc_cmd {
                    debug!("Sending {} bytes on DVC channel {}", cmd.data.len(), cmd.channel_id);
                    use ironrdp_dvc::pdu::DataPdu;
                    use ironrdp_svc::SvcMessage;

                    let data_pdu = ironrdp_dvc::pdu::DrdynvcDataPdu::Data(
                        DataPdu::new(cmd.channel_id, cmd.data)
                    );
                    let svc_msg = SvcMessage::from(data_pdu);

                    match active_stage.encode_dvc_messages(vec![svc_msg]) {
                        Ok(frame) => {
                            if let Err(e) = framed.write_all(&frame).await {
                                error!("Failed to send DVC data: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Failed to encode DVC data: {:?}", e);
                        }
                    }
                }
            }
        }
    }

    info!("Frame processor stopped (graceful={})", graceful_shutdown);

    // An unconfirmed login is connect()'s to answer: it reports the end itself or is already
    // failing the login. Otherwise notify the daemon of the connection drop (unless this was a
    // graceful shutdown).
    let connect_reports = logon_watch.finish(end);
    if !graceful_shutdown && !connect_reports {
        if let Some(notify) = disconnect_notify {
            info!("Notifying daemon of connection drop");
            let _ = notify.send(()).await;
        }
    }
}

/// No-op network client for CredSSP.
/// This works for basic NTLM authentication but doesn't support Kerberos.
struct NoopNetworkClient;

impl ironrdp_tokio::NetworkClient for NoopNetworkClient {
    fn send(
        &mut self,
        _network_request: &ironrdp::connector::sspi::generator::NetworkRequest,
    ) -> impl Future<Output = ConnectorResult<Vec<u8>>> {
        async move {
            // Return empty response - NTLM auth doesn't need network calls
            Ok(Vec::new())
        }
    }
}

// ============ Key Input Helpers ============

/// Key information including scancode and extended flag.
struct KeyInfo {
    scancode: u8,
    extended: bool,
}

/// Parse a key combination like "ctrl+c" into key info for sending.
fn parse_key_combination(keys: &str) -> Result<Vec<KeyInfo>, String> {
    let parts: Vec<String> = keys.split('+').map(|s| s.trim().to_lowercase()).collect();

    let mut key_infos = Vec::new();

    for key in &parts {
        let (scancode, extended) = key_to_scancode(key)
            .ok_or_else(|| format!("Unknown key: {}", key))?;
        key_infos.push(KeyInfo { scancode, extended });
    }

    Ok(key_infos)
}

/// Convert a key name to a scancode and extended flag.
fn key_to_scancode(key: &str) -> Option<(u8, bool)> {
    use std::collections::HashMap;

    let key_lower = key.to_lowercase();
    let key_map: HashMap<&str, (u8, bool)> = [
        // Modifier keys
        ("ctrl", (0x1D, false)),
        ("control", (0x1D, false)),
        ("alt", (0x38, false)),
        ("shift", (0x2A, false)),
        ("win", (0x5B, true)),
        ("windows", (0x5B, true)),
        ("super", (0x5B, true)),

        // Function keys
        ("esc", (0x01, false)),
        ("escape", (0x01, false)),
        ("tab", (0x0F, false)),
        ("enter", (0x1C, false)),
        ("return", (0x1C, false)),
        ("backspace", (0x0E, false)),
        ("space", (0x39, false)),

        // Arrow keys
        ("up", (0x48, true)),
        ("down", (0x50, true)),
        ("left", (0x4B, true)),
        ("right", (0x4D, true)),

        // Letter keys
        ("a", (0x1E, false)),
        ("b", (0x30, false)),
        ("c", (0x2E, false)),
        ("d", (0x20, false)),
        ("e", (0x12, false)),
        ("f", (0x21, false)),
        ("g", (0x22, false)),
        ("h", (0x23, false)),
        ("i", (0x17, false)),
        ("j", (0x24, false)),
        ("k", (0x25, false)),
        ("l", (0x26, false)),
        ("m", (0x32, false)),
        ("n", (0x31, false)),
        ("o", (0x18, false)),
        ("p", (0x19, false)),
        ("q", (0x10, false)),
        ("r", (0x13, false)),
        ("s", (0x1F, false)),
        ("t", (0x14, false)),
        ("u", (0x16, false)),
        ("v", (0x2F, false)),
        ("w", (0x11, false)),
        ("x", (0x2D, false)),
        ("y", (0x15, false)),
        ("z", (0x2C, false)),
    ]
    .into_iter()
    .collect();

    key_map.get(key_lower.as_str()).copied()
}

/// Create a keyboard event with proper flags.
fn create_key_event(scancode: u8, extended: bool, release: bool) -> FastPathInputEvent {
    use ironrdp::pdu::input::fast_path::KeyboardFlags;

    let mut flags = KeyboardFlags::empty();
    if release {
        flags |= KeyboardFlags::RELEASE;
    }
    if extended {
        flags |= KeyboardFlags::EXTENDED;
    }
    FastPathInputEvent::KeyboardEvent(flags, scancode)
}

#[cfg(test)]
mod tests {
    use ironrdp::connector::sspi::{self, credssp::NStatusCode};
    use ironrdp::connector::{ConnectorErrorKind, Sequence};
    use ironrdp::pdu::nego::{ConnectionConfirm, ResponseFlags, SecurityProtocol};
    use ironrdp::pdu::x224::X224;
    use ironrdp::pdu::WriteBuf;

    use super::*;

    #[test]
    fn refused_login_connector_error_is_authentication_failed() {
        let refused = ConnectorError::new(
            "CredSSP",
            ConnectorErrorKind::Credssp(sspi::Error::new_with_nstatus(
                sspi::ErrorKind::InvalidToken,
                "CredSSP server returned an error status",
                NStatusCode::WRONG_PASSWORD,
            )),
        );
        assert!(matches!(
            RdpError::from(refused),
            RdpError::AuthenticationFailed(AuthFailureReason::WrongPassword)
        ));
        let other = ConnectorError::new("connect", ConnectorErrorKind::General);
        assert!(matches!(RdpError::from(other), RdpError::ConnectionFailed(_)));
    }

    #[test]
    fn pin_mismatch_is_not_a_tls_error() {
        let mismatch = rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
            rustls::OtherError(Arc::new(tls::CertificateMismatch { presented: None })),
        ));
        let error = std::io::Error::new(std::io::ErrorKind::InvalidData, mismatch);
        assert!(matches!(tls_upgrade_error(error), RdpError::CertificateMismatch(_)));

        let reset = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        assert!(matches!(tls_upgrade_error(reset), RdpError::TlsError(_)));
    }

    pub(super) fn test_config(alternate_shell: Option<&str>) -> RdpConfig {
        RdpConfig {
            host: "host".to_string(),
            port: 3389,
            username: "user".to_string(),
            password: "pass".to_string(),
            domain: None,
            alternate_shell: alternate_shell.map(str::to_string),
            enable_credssp: true,
            width: 1280,
            height: 800,
            drives: Vec::new(),
            automation_dvc_state: None,
            server_cert_pin: None,
        }
    }

    #[test]
    fn connector_config_carries_alternate_shell() {
        let shell = "psm /u user@domain /a target /c PSM-RDP";
        let config = build_connector_config(&test_config(Some(shell)));
        assert_eq!(config.alternate_shell, shell);
        assert!(config.work_dir.is_empty());
    }

    #[test]
    fn connector_config_carries_enable_credssp() {
        let mut config = test_config(None);
        assert!(build_connector_config(&config).enable_credssp);
        assert!(build_connector_config(&config).enable_tls);

        config.enable_credssp = false;
        let connector = build_connector_config(&config);
        assert!(!connector.enable_credssp);
        assert!(connector.enable_tls);
    }

    #[test]
    fn only_a_confirmed_login_succeeds() {
        assert!(logon_verdict(Some(LogonReport::Outcome(LogonOutcome::Succeeded))).is_ok());
        assert!(matches!(
            logon_verdict(Some(LogonReport::Outcome(LogonOutcome::Failed(
                AuthFailureReason::LogonFailedBadPassword
            )))),
            Err(RdpError::AuthenticationFailed(
                AuthFailureReason::LogonFailedBadPassword
            ))
        ));
        assert!(matches!(
            logon_verdict(Some(LogonReport::SessionEnded)),
            Err(RdpError::AuthenticationFailed(
                AuthFailureReason::LogonUnconfirmed
            ))
        ));
    }

    #[test]
    fn a_connection_error_after_the_credentials_is_an_unconfirmed_login() {
        let closed = || ConnectorError::new("read frame", ConnectorErrorKind::General);
        assert!(matches!(
            finalize_error(closed(), false),
            RdpError::ConnectionFailed(_)
        ));
        assert!(matches!(
            finalize_error(closed(), true),
            RdpError::AuthenticationFailed(AuthFailureReason::LogonUnconfirmed)
        ));
        let refused = ConnectorError::new(
            "CredSSP",
            ConnectorErrorKind::Credssp(sspi::Error::new_with_nstatus(
                sspi::ErrorKind::InvalidToken,
                "CredSSP server returned an error status",
                NStatusCode::WRONG_PASSWORD,
            )),
        );
        assert!(matches!(
            finalize_error(refused, true),
            RdpError::AuthenticationFailed(AuthFailureReason::WrongPassword)
        ));
    }

    #[test]
    fn a_silent_server_fails_the_login_closed() {
        assert!(matches!(
            logon_verdict(None),
            Err(RdpError::AuthenticationFailed(
                AuthFailureReason::LogonUnconfirmed
            ))
        ));
    }

    /// Drive a connector through negotiation to the point where `connect()` decides whether to
    /// wait for the login, with the server selecting `selected`.
    fn negotiated_connector(enable_credssp: bool, selected: SecurityProtocol) -> ClientConnector {
        let mut config = test_config(None);
        config.enable_credssp = enable_credssp;
        let mut connector = ClientConnector::new(
            build_connector_config(&config),
            "127.0.0.1:50000".parse().unwrap(),
        );
        let mut output = WriteBuf::new();
        connector.step(&[], &mut output).unwrap();
        let confirm = ironrdp::pdu::encode_vec(&X224(ConnectionConfirm::Response {
            flags: ResponseFlags::empty(),
            protocol: selected,
        }))
        .unwrap();
        connector.step(&confirm, &mut output).unwrap();
        connector.mark_security_upgrade_as_done();
        connector
    }

    #[test]
    fn nla_on_does_not_wait_for_the_login() {
        let connector = negotiated_connector(true, SecurityProtocol::HYBRID);
        assert!(!awaits_logon(&connector));
    }

    #[test]
    fn tls_only_waits_for_the_login() {
        let tls_offered = negotiated_connector(false, SecurityProtocol::SSL);
        assert!(awaits_logon(&tls_offered));
        // The server can pick TLS-only even when the client offered NLA.
        let nla_offered = negotiated_connector(true, SecurityProtocol::SSL);
        assert!(awaits_logon(&nla_offered));
    }

    #[test]
    fn connector_config_alternate_shell_empty_when_none() {
        let config = build_connector_config(&test_config(None));
        assert!(config.alternate_shell.is_empty());
        assert!(config.work_dir.is_empty());
    }
}
