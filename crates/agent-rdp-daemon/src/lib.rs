//! Daemon process for agent-rdp RDP session management.
//!
//! This crate implements the background daemon that maintains RDP connections
//! and handles commands from CLI instances via IPC.

pub mod automation;
pub mod daemon;
pub mod handlers;
mod http_head;
pub mod ipc_server;
pub mod logon;
pub mod ocr;
pub mod paths;
pub mod rdp_session;
pub mod rdpdr;
pub mod stream_auth;
pub mod tls;
pub mod ws_input;
pub mod ws_server;

pub use daemon::{Daemon, SharedWsHandle};
pub use ipc_server::IpcServer;
pub use paths::{
    check_state_dir, cleanup_session, ensure_session_dirs, get_base_dir, get_pid_path,
    get_session_dir, get_session_port, get_socket_path, resolve_base_dir, validate_session_name,
    verify_base_dir, verify_session_dirs, write_pid_file, PathsError, STATE_DIR_ENV,
};
pub use rdp_session::RdpSession;

/// Run the daemon server for the given session.
/// This is the main entry point called by `agent-rdp session daemon`.
pub async fn run_server(session: &str) -> anyhow::Result<()> {
    // Refuse an over-long socket path before anything is written
    #[cfg(unix)]
    paths::check_socket_path_len(&get_socket_path(session))?;

    // Create the base and session directories (private session dir on Unix)
    ensure_session_dirs(session)?;

    // Write PID file
    write_pid_file(&get_pid_path(session))?;

    // Create and run daemon; a failed start must not leave the session directory behind
    let mut daemon = match Daemon::new(session.to_string()).await {
        Ok(daemon) => daemon,
        Err(e) => {
            cleanup_session(session);
            return Err(e);
        }
    };
    let result = daemon.run().await;

    // Cleanup on exit
    cleanup_session(session);

    result
}
