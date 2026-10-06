//! Connection handler.

use std::sync::Arc;

use agent_rdp_protocol::{ConnectRequest, DriveMapping, ErrorCode, Response, ResponseData};
use tokio::sync::{watch, Mutex};
use tracing::{info, warn};

use crate::automation::{AutomationBootstrap, SharedAutomationState, SharedDvcState};
use crate::daemon::{ClipboardChangedRx, SharedWsHandle};
use crate::rdp_session::{DisconnectNotify, RdpConfig, RdpSession};
use crate::ws_server::{get_stream_fps, WsServer, WsServerConfig};

/// Map a connect request onto the RDP session configuration.
///
/// `drives` is passed separately because the handler appends the automation drive to the
/// request's own drive list before connecting.
fn build_rdp_config(
    params: ConnectRequest,
    drives: Vec<DriveMapping>,
    automation_dvc_state: Option<SharedDvcState>,
) -> RdpConfig {
    RdpConfig {
        host: params.host,
        port: params.port,
        username: params.username,
        password: params.password,
        domain: params.domain,
        alternate_shell: params.alternate_shell,
        width: params.width,
        height: params.height,
        drives,
        automation_dvc_state,
    }
}

/// Handle a connect request.
pub async fn handle(
    rdp_session: &Arc<Mutex<Option<RdpSession>>>,
    automation_state: &SharedAutomationState,
    ws_handle: &SharedWsHandle,
    params: ConnectRequest,
    disconnect_notify: DisconnectNotify,
    clipboard_changed_rx: &ClipboardChangedRx,
    stream_fps_tx: &watch::Sender<u32>,
) -> Response {
    let enable_automation = params.enable_win_automation;
    let stream_port = params.stream_port;
    let stream_fps = params.stream_fps;
    let stream_quality = params.stream_quality;
    let serve_viewer = params.serve_viewer;

    // Auto-disconnect if already connected (handles stale/dropped connections)
    {
        let mut session = rdp_session.lock().await;
        if let Some(old_session) = session.take() {
            info!("Disconnecting existing session before new connection");
            if let Err(e) = old_session.disconnect().await {
                // Log but don't fail - the old connection might already be dead
                info!("Previous disconnect returned error (may be expected): {}", e);
            }
        }
    }

    // Clean up any previous automation state
    {
        let mut auto_state = automation_state.lock().await;
        if auto_state.enabled {
            let session_dir = crate::get_session_dir("");
            let bootstrap = AutomationBootstrap::new(session_dir);
            let _ = bootstrap.cleanup(&mut auto_state).await;
        }
    }

    // Build drive list, adding automation drive if enabled
    // IMPORTANT: Create the automation directory BEFORE registering the drive,
    // otherwise Windows will get "invalid address" errors trying to access it
    let mut drives = params.drives.clone();
    if enable_automation {
        let session_dir = crate::get_session_dir("");
        let bootstrap = AutomationBootstrap::new(session_dir);

        // Initialize automation directory structure first
        {
            let mut auto_state = automation_state.lock().await;
            if let Err(e) = bootstrap.initialize(&mut auto_state).await {
                warn!("Failed to initialize automation directory: {}", e);
                // Don't add the drive if we can't create the directory
            } else {
                // Only add drive if directory was created successfully
                drives.push(bootstrap.get_drive_mapping(&auto_state));
            }
        }
    }

    // Log the drives being configured
    for (idx, drive) in drives.iter().enumerate() {
        info!(
            "Drive {}: name={}, path={}",
            idx + 1,
            drive.name,
            drive.path
        );
    }

    // Get DVC state for automation (if enabled)
    let automation_dvc_state = if enable_automation {
        let auto_state = automation_state.lock().await;
        auto_state.dvc_state.clone()
    } else {
        None
    };

    // Build configuration
    let config = build_rdp_config(params, drives, automation_dvc_state);

    // Attempt connection
    let rdp = match RdpSession::connect(config, Some(disconnect_notify)).await {
        Ok(rdp) => rdp,
        Err(e) => {
            let code = match &e {
                crate::rdp_session::RdpError::AuthenticationFailed => ErrorCode::AuthenticationFailed,
                _ => ErrorCode::ConnectionFailed,
            };
            return Response::error(code, e.to_string());
        }
    };

    let host = rdp.host();
    let width = rdp.width();
    let height = rdp.height();

    // Store the session
    {
        let mut session = rdp_session.lock().await;
        *session = Some(rdp);
    }

    info!("Connected to {} ({}x{})", host, width, height);

    // Start WebSocket streaming server if requested
    if stream_port > 0 {
        let mut ws = ws_handle.lock().await;
        if ws.is_none() {
            let fps = get_stream_fps(stream_fps);
            let config = WsServerConfig {
                port: stream_port,
                fps,
                jpeg_quality: stream_quality,
                serve_viewer,
            };
            let ws_server = WsServer::new(config);
            match ws_server.start(Arc::clone(rdp_session)).await {
                Ok(handle) => {
                    info!("WebSocket streaming enabled on port {} at {} fps", stream_port, fps);
                    stream_fps_tx.send_replace(fps);
                    *ws = Some(handle);

                    // Set up clipboard change notification channel
                    let session = rdp_session.lock().await;
                    if let Some(ref rdp) = *session {
                        let (changed_tx, changed_rx) = tokio::sync::mpsc::unbounded_channel();
                        rdp.set_clipboard_changed_notify(changed_tx);
                        *clipboard_changed_rx.lock().await = Some(changed_rx);
                        info!("Clipboard WebSocket integration enabled");
                    }
                }
                Err(e) => {
                    warn!("Failed to start WebSocket server: {}", e);
                }
            }
        } else {
            info!("WebSocket server already running");
        }
    }

    // Bootstrap automation if enabled (directory was already created before connection)
    if enable_automation {
        info!("Bootstrapping Windows UI Automation...");

        let session_dir = crate::get_session_dir("");
        let bootstrap = AutomationBootstrap::new(session_dir);

        // Launch the agent via Win+R
        {
            let session = rdp_session.lock().await;
            if let Some(ref rdp) = *session {
                let auto_state = automation_state.lock().await;
                if let Err(e) = bootstrap.launch_agent(rdp, &auto_state).await {
                    warn!("Failed to launch automation agent: {}", e);
                }
            }
        }

        // Wait for handshake
        {
            let mut auto_state = automation_state.lock().await;
            if let Err(e) = bootstrap.wait_for_agent(&mut auto_state, 10).await {
                warn!("Automation agent handshake failed: {}", e);
                // Don't fail - automation just won't be available
            }
        }
    }

    Response::success(ResponseData::Connected {
        host,
        width,
        height,
    })
}

/// Handle a disconnect request.
pub async fn handle_disconnect(
    rdp_session: &Arc<Mutex<Option<RdpSession>>>,
    automation_state: &SharedAutomationState,
    ws_handle: &SharedWsHandle,
) -> Response {
    // Stop WebSocket server if running
    {
        let mut ws = ws_handle.lock().await;
        if ws.is_some() {
            info!("Stopping WebSocket streaming server");
            *ws = None; // Drop the handle to stop the server
        }
    }

    // Clean up automation state
    {
        let mut auto_state = automation_state.lock().await;
        if auto_state.enabled {
            let session_dir = crate::get_session_dir("");
            let bootstrap = AutomationBootstrap::new(session_dir);
            if let Err(e) = bootstrap.cleanup(&mut auto_state).await {
                warn!("Error cleaning up automation: {}", e);
            }
        }
    }

    let mut session = rdp_session.lock().await;

    match session.take() {
        Some(rdp) => {
            if let Err(e) = rdp.disconnect().await {
                return Response::error(ErrorCode::InternalError, format!("Disconnect error: {}", e));
            }
            Response::ok()
        }
        None => {
            Response::error(ErrorCode::NotConnected, "Not connected to an RDP server")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drive(name: &str) -> DriveMapping {
        DriveMapping {
            path: format!("/tmp/{name}"),
            name: name.to_string(),
        }
    }

    #[test]
    fn rdp_config_carries_connect_request_fields() {
        let shell = "psm /u user@domain /a target /c PSM-RDP";
        let params = ConnectRequest {
            host: "10.0.0.5".to_string(),
            port: 4489,
            username: "admin".to_string(),
            password: "secret".to_string(),
            domain: Some("CORP".to_string()),
            alternate_shell: Some(shell.to_string()),
            width: 1920,
            height: 1080,
            ..Default::default()
        };

        let config = build_rdp_config(params, vec![drive("docs"), drive("auto")], None);

        assert_eq!(config.host, "10.0.0.5");
        assert_eq!(config.port, 4489);
        assert_eq!(config.username, "admin");
        assert_eq!(config.password, "secret");
        assert_eq!(config.domain.as_deref(), Some("CORP"));
        assert_eq!(config.alternate_shell.as_deref(), Some(shell));
        assert_eq!((config.width, config.height), (1920, 1080));
        let names: Vec<_> = config.drives.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["docs", "auto"]);
        assert!(config.automation_dvc_state.is_none());
    }

    #[test]
    fn rdp_config_alternate_shell_none_when_unset() {
        let config = build_rdp_config(ConnectRequest::default(), Vec::new(), None);
        assert_eq!(config.alternate_shell, None);
    }
}
