//! Bootstrap automation agent on remote Windows machine.

use std::path::PathBuf;
use std::time::Duration;

use agent_rdp_protocol::DriveMapping;
use tokio::time::{sleep, Instant};
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::{new_shared_dvc_state, AutomationState, DvcIpc};
use crate::rdp_session::{RdpError, SessionKeyboard};

/// Embedded PowerShell agent script (main entry point).
const AGENT_SCRIPT: &str = include_str!("scripts/agent.ps1");

/// Embedded PowerShell library files.
const LIB_TYPES: &str = include_str!("scripts/lib/types.ps1");
const LIB_SNAPSHOT: &str = include_str!("scripts/lib/snapshot.ps1");
const LIB_SELECTORS: &str = include_str!("scripts/lib/selectors.ps1");
const LIB_ACTIONS: &str = include_str!("scripts/lib/actions.ps1");
const LIB_DVC: &str = include_str!("scripts/lib/dvc.ps1");

/// One launch of the agent: how long to wait before Win+R (still watching for a handshake), how long the Run dialog gets to open
/// before the command is typed, and how long to wait for the agent's handshake afterwards.
struct LaunchAttempt {
    settle: Duration,
    run_dialog: Duration,
    handshake: Duration,
}

/// The connect response waits for all of these, about 30 s in total, so the budget stays where a
/// single launch with its long handshake wait had it. A first agent that is merely slow still
/// gets the whole budget to answer.
const LAUNCH_ATTEMPTS: [LaunchAttempt; 2] = [
    LaunchAttempt {
        settle: Duration::from_secs(2),
        run_dialog: Duration::from_millis(500),
        handshake: Duration::from_secs(10),
    },
    LaunchAttempt {
        settle: Duration::from_millis(500),
        run_dialog: Duration::from_millis(1500),
        handshake: Duration::from_secs(10),
    },
];

/// How often to check for the agent's handshake.
const HANDSHAKE_POLL: Duration = Duration::from_millis(250);

/// Keyboard access to the remote desktop.
pub(crate) trait RemoteKeyboard {
    async fn key_press(&self, keys: &str) -> Result<(), RdpError>;
    async fn type_text(&self, text: &str) -> Result<(), RdpError>;
}

impl RemoteKeyboard for SessionKeyboard {
    async fn key_press(&self, keys: &str) -> Result<(), RdpError> {
        self.send_key_press(keys).await
    }

    async fn type_text(&self, text: &str) -> Result<(), RdpError> {
        self.send_text(text).await
    }
}

/// The Run dialog command that starts the agent from the mapped drive. Every agent started with
/// the same `launch_id` after the first exits at once.
fn launch_command(drive_name: &str, launch_id: &str) -> String {
    format!(
        "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File \"\\\\TSCLIENT\\{drive_name}\\scripts\\agent.ps1\" -BasePath \"\\\\TSCLIENT\\{drive_name}\" -LaunchId {launch_id}"
    )
}

/// Whether the agent's handshake arrives within `window`.
async fn handshake_within(dvc_ipc: &DvcIpc, window: Duration) -> bool {
    let deadline = Instant::now() + window;
    loop {
        if dvc_ipc.is_ready() {
            return true;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        sleep(HANDSHAKE_POLL.min(left)).await;
    }
}

fn mark_ready(state: &mut AutomationState, dvc_ipc: &DvcIpc) {
    let pid = dvc_ipc.agent_pid().unwrap_or(0);
    info!(
        "Automation agent ready via DVC: PID={}, version={}, capabilities={:?}",
        pid,
        dvc_ipc.agent_version().unwrap_or_default(),
        dvc_ipc.capabilities()
    );
    state.agent_ready = true;
    state.agent_pid = Some(pid);
}

/// [`AutomationBootstrap::start_agent`] with the launch timing as a parameter.
async fn start_agent_within(
    keyboard: &impl RemoteKeyboard,
    state: &mut AutomationState,
    attempts: &[LaunchAttempt],
) -> anyhow::Result<()> {
    let dvc_ipc = state
        .dvc_ipc
        .clone()
        .ok_or_else(|| anyhow::anyhow!("DVC IPC not initialized"))?;
    let launch_id = Uuid::new_v4().simple().to_string()[..8].to_string();
    let command = launch_command(&state.drive_name, &launch_id);
    debug!("PowerShell command: {}", command);

    for (index, attempt) in attempts.iter().enumerate() {
        // The settle time doubles as more time for a slow earlier launch to answer.
        if handshake_within(&dvc_ipc, attempt.settle).await {
            mark_ready(state, &dvc_ipc);
            return Ok(());
        }
        if index > 0 {
            warn!(
                "No automation agent handshake after launch {}; retrying",
                index
            );
            // Close a Run dialog or error box left open by the previous try. If that launch
            // went through and its agent is merely slower than the wait, this reaches whatever
            // window has focus instead.
            keyboard.key_press("escape").await?;
        }
        info!("Launching automation agent (try {})", index + 1);
        keyboard.key_press("super+r").await?;
        sleep(attempt.run_dialog).await;
        keyboard.type_text(&command).await?;
        sleep(Duration::from_millis(200)).await;
        keyboard.key_press("return").await?;

        if handshake_within(&dvc_ipc, attempt.handshake).await {
            mark_ready(state, &dvc_ipc);
            return Ok(());
        }
    }

    anyhow::bail!(
        "automation agent did not start after {} launches",
        attempts.len()
    )
}

/// Automation bootstrap handler.
pub struct AutomationBootstrap {
    /// Session directory path (kept for potential future use).
    _session_dir: PathBuf,
}

impl AutomationBootstrap {
    /// Create a new automation bootstrap handler.
    pub fn new(session_dir: PathBuf) -> Self {
        Self { _session_dir: session_dir }
    }

    /// Initialize automation directory and write the agent script.
    ///
    /// This creates the directory structure and scripts needed for RDPDR-based
    /// bootstrap. The actual IPC will be over DVC once the agent starts.
    pub async fn initialize(&self, state: &mut AutomationState) -> anyhow::Result<()> {
        info!("Initializing automation for session");

        // Create automation directory structure
        let automation_dir = &state.automation_dir;
        tokio::fs::create_dir_all(automation_dir).await?;
        tokio::fs::create_dir_all(automation_dir.join("scripts")).await?;
        tokio::fs::create_dir_all(automation_dir.join("scripts/lib")).await?;

        // Write the PowerShell agent script (main entry point)
        let script_path = state.script_path();
        tokio::fs::write(&script_path, AGENT_SCRIPT).await?;
        debug!("Wrote automation agent script to {:?}", script_path);

        // Write the PowerShell library files
        let lib_dir = automation_dir.join("scripts/lib");
        tokio::fs::write(lib_dir.join("types.ps1"), LIB_TYPES).await?;
        tokio::fs::write(lib_dir.join("snapshot.ps1"), LIB_SNAPSHOT).await?;
        tokio::fs::write(lib_dir.join("selectors.ps1"), LIB_SELECTORS).await?;
        tokio::fs::write(lib_dir.join("actions.ps1"), LIB_ACTIONS).await?;
        tokio::fs::write(lib_dir.join("dvc.ps1"), LIB_DVC).await?;
        debug!("Wrote automation library files to {:?}", lib_dir);

        // Initialize DVC state and IPC
        let dvc_state = new_shared_dvc_state();
        let dvc_ipc = DvcIpc::new(dvc_state.clone());
        state.dvc_state = Some(dvc_state);
        state.dvc_ipc = Some(dvc_ipc);

        state.enabled = true;
        info!(
            "Automation initialized with ID {} at {:?}",
            state.automation_id, automation_dir
        );

        Ok(())
    }

    /// Get the drive mapping for the automation directory.
    pub fn get_drive_mapping(&self, state: &AutomationState) -> DriveMapping {
        DriveMapping {
            path: state.automation_dir.to_string_lossy().to_string(),
            name: state.drive_name.clone(),
        }
    }

    /// Start the agent on the remote desktop and wait for its DVC handshake.
    ///
    /// The agent is launched by typing into the Run dialog, which nothing confirms: Win+R can
    /// land before the desktop is ready (first logon), and the typed command can arrive before
    /// the dialog has focus (seen on reconnect). So each try that ends without a handshake
    /// presses Escape to close whatever it left open and launches again with more time for the
    /// dialog. A slow first agent is safe to relaunch over: of two agents with the same launch
    /// ID, the later one exits.
    pub(crate) async fn start_agent(
        &self,
        keyboard: &impl RemoteKeyboard,
        state: &mut AutomationState,
    ) -> anyhow::Result<()> {
        start_agent_within(keyboard, state, &LAUNCH_ATTEMPTS).await
    }

    /// Clean up automation resources.
    pub async fn cleanup(&self, state: &mut AutomationState) -> anyhow::Result<()> {
        if !state.enabled {
            return Ok(());
        }

        info!("Cleaning up automation resources");

        // Remove automation directory
        let automation_dir = &state.automation_dir;
        if automation_dir.exists() {
            if let Err(e) = tokio::fs::remove_dir_all(automation_dir).await {
                warn!("Failed to remove automation directory: {}", e);
            } else {
                debug!("Removed automation directory: {:?}", automation_dir);
            }
        }

        state.enabled = false;
        state.agent_ready = false;
        state.agent_pid = None;
        state.dvc_ipc = None;
        state.dvc_state = None;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::automation::{DvcHandshake, SharedDvcState};
    use tempfile::TempDir;

    /// A remote desktop whose agent hands shake `answer_after` the `answer_on`-th launch command
    /// is entered (never if `None`), and whose keyboard fails once the session is `closed`.
    struct FakeDesktop {
        dvc: SharedDvcState,
        answer_on: Option<usize>,
        answer_after: Duration,
        closed: bool,
        keys: std::sync::Mutex<Vec<String>>,
    }

    impl FakeDesktop {
        fn new(state: &AutomationState, answer_on: Option<usize>) -> Self {
            Self {
                dvc: state.dvc_state.clone().expect("initialized"),
                answer_on,
                answer_after: Duration::ZERO,
                closed: false,
                keys: Default::default(),
            }
        }

        fn keys(&self) -> Vec<String> {
            self.keys.lock().unwrap().clone()
        }

        fn record(&self, key: String) -> Result<(), RdpError> {
            if self.closed {
                return Err(RdpError::SessionClosed);
            }
            let mut keys = self.keys.lock().unwrap();
            keys.push(key);
            let entered = keys.iter().filter(|k| *k == "return").count();
            if keys.last().is_some_and(|k| k == "return") && self.answer_on == Some(entered) {
                let (dvc, delay) = (self.dvc.clone(), self.answer_after);
                tokio::spawn(async move {
                    sleep(delay).await;
                    let mut dvc = dvc.lock();
                    dvc.channel_id = Some(1);
                    dvc.handshake = Some(DvcHandshake {
                        version: "1.1.0".to_string(),
                        agent_pid: 4242,
                        capabilities: vec![],
                    });
                });
            }
            Ok(())
        }

        /// The keys pressed, and the launch command typed with them.
        fn keys_and_command(&self) -> (Vec<String>, String) {
            let keys = self.keys();
            let command = keys
                .iter()
                .find_map(|k| k.strip_prefix("text:"))
                .expect("a command was typed")
                .to_string();
            (keys, command)
        }
    }

    impl RemoteKeyboard for FakeDesktop {
        async fn key_press(&self, keys: &str) -> Result<(), RdpError> {
            self.record(keys.to_string())
        }

        async fn type_text(&self, text: &str) -> Result<(), RdpError> {
            self.record(format!("text:{text}"))
        }
    }

    const QUICK_ATTEMPT: LaunchAttempt = LaunchAttempt {
        settle: Duration::ZERO,
        run_dialog: Duration::ZERO,
        handshake: Duration::from_millis(30),
    };

    async fn initialized() -> (TempDir, AutomationState) {
        let temp_dir = TempDir::new().unwrap();
        let mut state = AutomationState::new(temp_dir.path().to_path_buf());
        AutomationBootstrap::new(temp_dir.path().to_path_buf())
            .initialize(&mut state)
            .await
            .unwrap();
        (temp_dir, state)
    }

    /// The keys of one launch typing `command`.
    fn launch(command: &str) -> Vec<String> {
        vec![
            "super+r".to_string(),
            format!("text:{command}"),
            "return".to_string(),
        ]
    }

    #[tokio::test]
    async fn an_agent_that_answers_is_launched_once() {
        let (_dir, mut state) = initialized().await;
        let desktop = FakeDesktop::new(&state, Some(1));

        start_agent_within(&desktop, &mut state, &[QUICK_ATTEMPT, QUICK_ATTEMPT])
            .await
            .unwrap();

        let (keys, command) = desktop.keys_and_command();
        assert_eq!(keys, launch(&command));
        assert!(state.agent_ready);
        assert_eq!(state.agent_pid, Some(4242));
    }

    #[tokio::test]
    async fn a_silent_launch_is_closed_and_retried_with_the_same_command() {
        let (_dir, mut state) = initialized().await;
        let desktop = FakeDesktop::new(&state, Some(2));

        start_agent_within(&desktop, &mut state, &[QUICK_ATTEMPT, QUICK_ATTEMPT])
            .await
            .unwrap();

        let (keys, command) = desktop.keys_and_command();
        // The same launch ID both times, so a slow first agent and the relaunch can't both run.
        let mut expected = launch(&command);
        expected.push("escape".to_string());
        expected.extend(launch(&command));
        assert_eq!(keys, expected);
        assert!(state.agent_ready);
    }

    #[tokio::test]
    async fn an_agent_answering_before_the_retry_is_not_relaunched() {
        let (_dir, mut state) = initialized().await;
        let mut desktop = FakeDesktop::new(&state, Some(1));
        // Later than the first wait, well within the second launch's settle time.
        desktop.answer_after = Duration::from_millis(100);
        let retry = LaunchAttempt {
            settle: Duration::from_secs(5),
            ..QUICK_ATTEMPT
        };

        start_agent_within(&desktop, &mut state, &[QUICK_ATTEMPT, retry])
            .await
            .unwrap();

        let (keys, command) = desktop.keys_and_command();
        assert_eq!(keys, launch(&command), "no Escape, no second launch");
        assert!(state.agent_ready);
    }

    #[test]
    fn all_launches_fit_the_single_launch_budget() {
        // The single launch this replaced made connect wait up to about 30 s for the agent, and
        // callers' connect timeouts were sized for that. Typing each command adds about 2 s.
        let total: Duration = LAUNCH_ATTEMPTS
            .iter()
            .map(|a| a.settle + a.run_dialog + a.handshake + Duration::from_secs(2))
            .sum();
        assert!(total <= Duration::from_secs(30), "{total:?}");
    }

    #[tokio::test]
    async fn gives_up_after_the_last_launch() {
        let (_dir, mut state) = initialized().await;
        let desktop = FakeDesktop::new(&state, None);

        let err = start_agent_within(&desktop, &mut state, &[QUICK_ATTEMPT, QUICK_ATTEMPT])
            .await
            .unwrap_err();

        assert!(err.to_string().contains("after 2 launches"), "{err}");
        let launches = desktop.keys().iter().filter(|k| *k == "super+r").count();
        assert_eq!(launches, 2);
        assert!(!state.agent_ready);
    }

    #[tokio::test]
    async fn a_closed_session_stops_the_launch() {
        let (_dir, mut state) = initialized().await;
        let mut desktop = FakeDesktop::new(&state, None);
        desktop.closed = true;

        let err = start_agent_within(&desktop, &mut state, &[QUICK_ATTEMPT, QUICK_ATTEMPT])
            .await
            .unwrap_err();

        assert!(matches!(
            err.downcast_ref::<RdpError>(),
            Some(RdpError::SessionClosed)
        ));
    }

    #[test]
    fn launch_command_carries_the_launch_id_and_fits_the_run_dialog() {
        let drive = AutomationState::new(PathBuf::new()).drive_name;
        let command = launch_command(&drive, "0123abcd");
        assert!(command.ends_with(" -LaunchId 0123abcd"), "{command}");
        let script = format!(r#"-File "\\TSCLIENT\{drive}\scripts\agent.ps1""#);
        assert!(command.contains(&script), "{command}");
        // The Run dialog accepts at most 259 characters.
        assert!(command.len() < 260, "{} characters", command.len());
    }

    #[tokio::test]
    async fn test_initialize_creates_structure() {
        let temp_dir = TempDir::new().unwrap();
        let bootstrap = AutomationBootstrap::new(temp_dir.path().to_path_buf());
        let mut state = AutomationState::new(temp_dir.path().to_path_buf());

        bootstrap.initialize(&mut state).await.unwrap();

        assert!(state.enabled);
        assert!(state.automation_dir.exists());
        assert!(state.script_path().exists());

        // Verify library files are created
        let lib_dir = state.automation_dir.join("scripts/lib");
        assert!(lib_dir.join("types.ps1").exists());
        assert!(lib_dir.join("snapshot.ps1").exists());
        assert!(lib_dir.join("selectors.ps1").exists());
        assert!(lib_dir.join("actions.ps1").exists());
        assert!(lib_dir.join("dvc.ps1").exists());

        // Verify DVC IPC is initialized
        assert!(state.dvc_ipc.is_some());
        assert!(state.dvc_state.is_some());
    }

    #[test]
    fn test_get_drive_mapping() {
        let temp_dir = TempDir::new().unwrap();
        let bootstrap = AutomationBootstrap::new(temp_dir.path().to_path_buf());
        let state = AutomationState::new(temp_dir.path().to_path_buf());

        let mapping = bootstrap.get_drive_mapping(&state);

        assert_eq!(mapping.name, "agent-automation");
        assert!(mapping.path.contains("automation-"));
    }
}
