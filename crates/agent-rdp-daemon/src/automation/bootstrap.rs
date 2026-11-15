//! Bootstrap automation agent on remote Windows machine.

use std::path::PathBuf;
use std::time::Duration;

use agent_rdp_protocol::DriveMapping;
use tokio::time::{sleep, Instant};
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::{new_shared_dvc_state, AutomationState, DvcIpc, ScreenBefore, ScreenSample};
use crate::rdp_session::{RdpError, SessionDesktop};

/// Embedded PowerShell agent script (main entry point).
const AGENT_SCRIPT: &str = include_str!("scripts/agent.ps1");

/// Embedded PowerShell library files.
const LIB_TYPES: &str = include_str!("scripts/lib/types.ps1");
const LIB_SNAPSHOT: &str = include_str!("scripts/lib/snapshot.ps1");
const LIB_SELECTORS: &str = include_str!("scripts/lib/selectors.ps1");
const LIB_ACTIONS: &str = include_str!("scripts/lib/actions.ps1");
const LIB_DVC: &str = include_str!("scripts/lib/dvc.ps1");

/// When and how the agent is launched.
struct LaunchPlan {
    /// How long to wait for the server's logon notification before the first launch.
    logon_wait: Duration,
    /// No launch starts later than this after the agent start began (the logon wait included).
    launch_until: Duration,
    /// How often to look at the screen, and the gap between the two looks before Win+R.
    screen_poll: Duration,
    /// How long Win+R gets to show the Run dialog.
    run_dialog_wait: Duration,
    /// Between tries, after Escape, still watching for a handshake.
    retry_pause: Duration,
    /// How long to wait for the agent's handshake after a launch.
    handshake: Duration,
    /// From the Run dialog showing to typing into it, and from typing to pressing Enter.
    key_settle: Duration,
}

/// On a first logon the shell takes 17–44 s after the logon notification to answer Win+R, and
/// the notification comes up to about 12 s after connecting; on a reconnect the shell is
/// already up. The whole start fits in [`agent_rdp_protocol::AGENT_START_TIMEOUT_MS`].
const LAUNCH_PLAN: LaunchPlan = LaunchPlan {
    logon_wait: Duration::from_secs(20),
    launch_until: Duration::from_secs(70),
    screen_poll: Duration::from_millis(100),
    run_dialog_wait: Duration::from_secs(2),
    retry_pause: Duration::from_secs(2),
    handshake: Duration::from_secs(10),
    key_settle: Duration::from_millis(200),
};

/// How often to check for the agent's handshake.
const HANDSHAKE_POLL: Duration = Duration::from_millis(250);

/// What launching the agent needs of the remote desktop.
pub(crate) trait RemoteDesktop {
    async fn key_press(&self, keys: &str) -> Result<(), RdpError>;
    async fn type_text(&self, text: &str) -> Result<(), RdpError>;
    /// Whether the server has sent its logon notification by the end of `window`; an error if
    /// the session ends first.
    async fn logged_on_within(&self, window: Duration) -> Result<bool, RdpError>;
    /// The parts of the screen that show the Run dialog.
    fn screen_sample(&self) -> ScreenSample;
}

impl RemoteDesktop for SessionDesktop {
    async fn key_press(&self, keys: &str) -> Result<(), RdpError> {
        self.send_key_press(keys).await
    }

    async fn type_text(&self, text: &str) -> Result<(), RdpError> {
        self.send_text(text).await
    }

    async fn logged_on_within(&self, window: Duration) -> Result<bool, RdpError> {
        SessionDesktop::logged_on_within(self, window).await
    }

    fn screen_sample(&self) -> ScreenSample {
        SessionDesktop::screen_sample(self)
    }
}

/// The Run dialog command that starts the agent from the mapped drive. Every agent started with
/// the same `launch_id` after the first exits at once.
fn launch_command(drive_name: &str, launch_id: &str) -> String {
    format!(
        "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File \"\\\\TSCLIENT\\{drive_name}\\scripts\\agent.ps1\" -BasePath \"\\\\TSCLIENT\\{drive_name}\" -LaunchId {launch_id}"
    )
}

/// Whether `check` holds within `window`, looking every `poll`.
async fn holds_within(window: Duration, poll: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + window;
    loop {
        if check() {
            return true;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        sleep(poll.min(left)).await;
    }
}

/// Whether the agent's handshake arrives within `window`.
async fn handshake_within(dvc_ipc: &DvcIpc, window: Duration) -> bool {
    holds_within(window, HANDSHAKE_POLL, || dvc_ipc.is_ready()).await
}

/// Look at the screen twice, `poll` apart, before pressing Win+R.
async fn screen_before(desktop: &impl RemoteDesktop, poll: Duration) -> ScreenBefore {
    let first = desktop.screen_sample();
    sleep(poll).await;
    ScreenBefore::new(&first, desktop.screen_sample())
}

/// The screen showing the Run dialog, opened since `before`, on two looks in a row within
/// `plan.run_dialog_wait`; `None` if it doesn't.
async fn run_dialog_within(
    desktop: &impl RemoteDesktop,
    before: &ScreenBefore,
    plan: &LaunchPlan,
) -> Option<ScreenSample> {
    let (mut seen, mut last) = (0, None);
    let shown = holds_within(plan.run_dialog_wait, plan.screen_poll, || {
        let now = desktop.screen_sample();
        seen = if before.run_dialog_opened(&now) {
            seen + 1
        } else {
            0
        };
        last = Some(now);
        seen >= 2
    })
    .await;
    last.filter(|_| shown)
}

fn log_ready(dvc_ipc: &DvcIpc) {
    info!(
        "Automation agent ready via DVC: PID={}, version={}, capabilities={:?}",
        dvc_ipc.agent_pid().unwrap_or(0),
        dvc_ipc.agent_version().unwrap_or_default(),
        dvc_ipc.capabilities()
    );
}

/// [`AutomationBootstrap::start_agent`] with the launch plan as a parameter.
async fn start_agent_within(
    desktop: &impl RemoteDesktop,
    dvc_ipc: &DvcIpc,
    drive_name: &str,
    plan: &LaunchPlan,
) -> anyhow::Result<()> {
    let launch_id = Uuid::new_v4().simple().to_string()[..8].to_string();
    let command = launch_command(drive_name, &launch_id);
    debug!("PowerShell command: {}", command);
    let deadline = Instant::now() + plan.launch_until;

    if !desktop.logged_on_within(plan.logon_wait).await? {
        warn!(
            "No logon notification within {:?}; launching the automation agent anyway",
            plan.logon_wait
        );
    }

    let (mut tries, mut launches) = (0, 0);
    loop {
        if tries > 0 {
            // Close a Run dialog or error box the previous try left open. If that launch went
            // through and its agent is merely slower than the wait, this reaches whatever window
            // has focus instead.
            desktop.key_press("escape").await?;
            if handshake_within(dvc_ipc, plan.retry_pause).await {
                log_ready(dvc_ipc);
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        tries += 1;

        let before = screen_before(desktop, plan.screen_poll).await;
        desktop.key_press("super+r").await?;
        let Some(dialog) = run_dialog_within(desktop, &before, plan).await else {
            debug!("No Run dialog after Win+R (try {tries}); the shell may still be starting");
            continue;
        };
        sleep(plan.key_settle).await;
        desktop.type_text(&command).await?;
        sleep(plan.key_settle).await;
        if !dialog.shows_typing(&desktop.screen_sample()) {
            // What looked like the dialog was not, or it closed: the text went elsewhere, and
            // Enter could open what it selected.
            warn!("The launch command did not show in the Run dialog (try {tries}); retrying");
            continue;
        }
        launches += 1;
        info!("Launching automation agent (launch {launches}, try {tries})");
        desktop.key_press("return").await?;

        if handshake_within(dvc_ipc, plan.handshake).await {
            log_ready(dvc_ipc);
            return Ok(());
        }
        warn!("No automation agent handshake after launch {launches}; retrying");
    }

    anyhow::bail!(
        "automation agent did not start within {:?}: launched on {launches} of {tries} tries",
        plan.launch_until
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

    /// Start the agent on the remote desktop and wait for its DVC handshake on `dvc_ipc`.
    ///
    /// The agent is launched by typing into the Run dialog. On a first logon the shell ignores
    /// Win+R for up to a minute, and text typed meanwhile reaches the desktop, where Enter can
    /// open an icon. So the first try waits for the server's logon notification, the command is
    /// typed only once the screen shows the Run dialog, and Enter is pressed only once the
    /// typed text shows in it. Each try that ends without a handshake presses Escape to close
    /// whatever it left open and tries again, until [`LAUNCH_PLAN`]'s deadline. A slow first
    /// agent is safe to relaunch over: of two agents with the same launch ID, the later one
    /// exits.
    pub(crate) async fn start_agent(
        &self,
        desktop: &impl RemoteDesktop,
        dvc_ipc: &DvcIpc,
        drive_name: &str,
    ) -> anyhow::Result<()> {
        start_agent_within(desktop, dvc_ipc, drive_name, &LAUNCH_PLAN).await
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

    /// A remote desktop whose shell opens the Run dialog from the `shell_ready_on`-th Win+R on,
    /// whose agent hands shake `answer_after` the `answer_on`-th launch command is entered (never
    /// if `None`), and whose keyboard fails once the session is `closed`.
    struct FakeDesktop {
        dvc: SharedDvcState,
        answer_on: Option<usize>,
        answer_after: Duration,
        shell_ready_on: usize,
        /// When the server sends its logon notification; never if `None`.
        logon_after: Option<Duration>,
        /// Every screen sample differs everywhere, as while the desktop paints in.
        busy_screen: bool,
        /// Every screen sample differs top-right, as while a video plays there.
        busy_corner: bool,
        /// Whether text typed into the open dialog shows in it; not if what opened bottom-left
        /// was something else.
        typing_shows: bool,
        closed: bool,
        created: Instant,
        screen: std::sync::Mutex<FakeScreen>,
    }

    #[derive(Default)]
    struct FakeScreen {
        keys: Vec<String>,
        first_key_after: Option<Duration>,
        win_r_presses: usize,
        entered: usize,
        dialog_open: bool,
        typed: bool,
        samples: u8,
    }

    impl FakeDesktop {
        fn new(answer_on: Option<usize>) -> Self {
            Self {
                dvc: new_shared_dvc_state(),
                answer_on,
                answer_after: Duration::ZERO,
                shell_ready_on: 1,
                logon_after: Some(Duration::ZERO),
                busy_screen: false,
                busy_corner: false,
                typing_shows: true,
                closed: false,
                created: Instant::now(),
                screen: Default::default(),
            }
        }

        /// The client end of the channel the agent hands shake on.
        fn ipc(&self) -> DvcIpc {
            DvcIpc::new(self.dvc.clone())
        }

        fn keys(&self) -> Vec<String> {
            self.screen.lock().unwrap().keys.clone()
        }

        fn first_key_after(&self) -> Duration {
            self.screen
                .lock()
                .unwrap()
                .first_key_after
                .expect("a key was pressed")
        }

        fn record(&self, key: String) -> Result<(), RdpError> {
            if self.closed {
                return Err(RdpError::SessionClosed);
            }
            let mut screen = self.screen.lock().unwrap();
            screen.first_key_after.get_or_insert(self.created.elapsed());
            match key.as_str() {
                "super+r" => {
                    screen.win_r_presses += 1;
                    screen.dialog_open |= screen.win_r_presses >= self.shell_ready_on;
                }
                "escape" => (screen.dialog_open, screen.typed) = (false, false),
                "return" if screen.dialog_open => {
                    (screen.dialog_open, screen.typed) = (false, false);
                    screen.entered += 1;
                    if self.answer_on == Some(screen.entered) {
                        self.answer_later();
                    }
                }
                text if text.starts_with("text:") => {
                    screen.typed = screen.dialog_open && self.typing_shows;
                }
                _ => {}
            }
            screen.keys.push(key);
            Ok(())
        }

        fn answer_later(&self) {
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

    impl RemoteDesktop for FakeDesktop {
        async fn key_press(&self, keys: &str) -> Result<(), RdpError> {
            self.record(keys.to_string())
        }

        async fn type_text(&self, text: &str) -> Result<(), RdpError> {
            self.record(format!("text:{text}"))
        }

        async fn logged_on_within(&self, window: Duration) -> Result<bool, RdpError> {
            if self.closed {
                return Err(RdpError::SessionClosed);
            }
            let left = self.logon_after.map_or(Duration::MAX, |logon| {
                logon.saturating_sub(self.created.elapsed())
            });
            sleep(left.min(window)).await;
            Ok(left <= window)
        }

        /// A 100x100 screen: the Run dialog fills its bottom-left while open, with the typed
        /// text in it.
        fn screen_sample(&self) -> ScreenSample {
            const SIDE: usize = 100;
            let mut screen = self.screen.lock().unwrap();
            screen.samples = screen.samples.wrapping_add(1);
            let background = if self.busy_screen { screen.samples } else { 10 };
            let mut frame = vec![background; SIDE * SIDE * 4];
            let mut paint = |rows: std::ops::Range<usize>, cols: std::ops::Range<usize>, colour| {
                for row in rows {
                    frame[(row * SIDE + cols.start) * 4..(row * SIDE + cols.end) * 4].fill(colour);
                }
            };
            if self.busy_corner {
                paint(0..50, 50..100, screen.samples);
            }
            if screen.dialog_open {
                paint(50..90, 0..30, 200);
            }
            if screen.typed {
                paint(60..65, 2..28, 0);
            }
            ScreenSample::of(SIDE, SIDE, &frame)
        }
    }

    const QUICK_PLAN: LaunchPlan = LaunchPlan {
        logon_wait: Duration::from_secs(1),
        launch_until: Duration::from_secs(1),
        screen_poll: Duration::from_millis(5),
        run_dialog_wait: Duration::from_millis(50),
        retry_pause: Duration::from_millis(10),
        handshake: Duration::from_millis(30),
        key_settle: Duration::ZERO,
    };

    const DRIVE: &str = "agent-automation";

    /// The keys of one launch typing `command`.
    fn launch(command: &str) -> Vec<String> {
        vec![
            "super+r".to_string(),
            format!("text:{command}"),
            "return".to_string(),
        ]
    }

    fn escape() -> Vec<String> {
        vec!["escape".to_string()]
    }

    #[tokio::test]
    async fn an_agent_that_answers_is_launched_once() {
        let desktop = FakeDesktop::new(Some(1));
        let ipc = desktop.ipc();

        start_agent_within(&desktop, &ipc, DRIVE, &QUICK_PLAN)
            .await
            .unwrap();

        let (keys, command) = desktop.keys_and_command();
        assert_eq!(keys, launch(&command));
        assert!(ipc.is_ready());
        assert_eq!(ipc.agent_pid(), Some(4242));
    }

    #[tokio::test]
    async fn a_silent_launch_is_closed_and_retried_with_the_same_command() {
        let desktop = FakeDesktop::new(Some(2));
        let ipc = desktop.ipc();

        start_agent_within(&desktop, &ipc, DRIVE, &QUICK_PLAN)
            .await
            .unwrap();

        let (keys, command) = desktop.keys_and_command();
        // The same launch ID both times, so a slow first agent and the relaunch can't both run.
        assert_eq!(
            keys,
            [launch(&command), escape(), launch(&command)].concat()
        );
        assert!(ipc.is_ready());
    }

    #[tokio::test]
    async fn an_agent_answering_during_the_retry_pause_is_not_relaunched() {
        let mut desktop = FakeDesktop::new(Some(1));
        let ipc = desktop.ipc();
        // Ten times the handshake wait, well within the retry pause.
        desktop.answer_after = Duration::from_millis(300);
        let plan = LaunchPlan {
            retry_pause: Duration::from_secs(5),
            ..QUICK_PLAN
        };

        start_agent_within(&desktop, &ipc, DRIVE, &plan)
            .await
            .unwrap();

        let (keys, command) = desktop.keys_and_command();
        assert_eq!(
            keys,
            [launch(&command), escape()].concat(),
            "no second launch"
        );
        assert!(ipc.is_ready());
    }

    #[tokio::test]
    async fn the_first_launch_waits_for_the_logon() {
        let mut desktop = FakeDesktop::new(Some(1));
        let ipc = desktop.ipc();
        desktop.logon_after = Some(Duration::from_millis(150));

        start_agent_within(&desktop, &ipc, DRIVE, &QUICK_PLAN)
            .await
            .unwrap();

        assert!(desktop.first_key_after() >= Duration::from_millis(150));
        let (keys, command) = desktop.keys_and_command();
        assert_eq!(keys, launch(&command));
    }

    #[tokio::test]
    async fn without_a_logon_notification_the_agent_is_launched_after_the_logon_wait() {
        let mut desktop = FakeDesktop::new(Some(1));
        let ipc = desktop.ipc();
        desktop.logon_after = None;
        let plan = LaunchPlan {
            logon_wait: Duration::from_millis(100),
            ..QUICK_PLAN
        };

        start_agent_within(&desktop, &ipc, DRIVE, &plan)
            .await
            .unwrap();

        assert!(desktop.first_key_after() >= Duration::from_millis(100));
        assert!(ipc.is_ready());
    }

    #[tokio::test]
    async fn the_logon_wait_counts_against_the_deadline() {
        let mut desktop = FakeDesktop::new(None);
        let ipc = desktop.ipc();
        desktop.logon_after = Some(Duration::from_millis(300));
        // One try takes well under 350 ms, so a deadline counted from the logon would allow a
        // second launch.
        let plan = LaunchPlan {
            launch_until: Duration::from_millis(350),
            ..QUICK_PLAN
        };

        let err = start_agent_within(&desktop, &ipc, DRIVE, &plan)
            .await
            .unwrap_err();

        let (keys, command) = desktop.keys_and_command();
        assert_eq!(keys, [launch(&command), escape()].concat());
        assert!(
            err.to_string().contains("launched on 1 of 1 tries"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn nothing_is_typed_until_the_run_dialog_opens() {
        let mut desktop = FakeDesktop::new(Some(1));
        let ipc = desktop.ipc();
        // The shell ignores Win+R twice, as while it starts on a first logon.
        desktop.shell_ready_on = 3;

        start_agent_within(&desktop, &ipc, DRIVE, &QUICK_PLAN)
            .await
            .unwrap();

        let (keys, command) = desktop.keys_and_command();
        let ignored = ["super+r".to_string(), "escape".to_string()];
        assert_eq!(keys, [&ignored[..], &ignored, &launch(&command)].concat());
        assert!(ipc.is_ready());
    }

    #[tokio::test]
    async fn nothing_is_typed_while_the_whole_screen_changes() {
        let mut desktop = FakeDesktop::new(Some(1));
        let ipc = desktop.ipc();
        desktop.busy_screen = true;
        let plan = LaunchPlan {
            launch_until: Duration::from_millis(200),
            ..QUICK_PLAN
        };

        let err = start_agent_within(&desktop, &ipc, DRIVE, &plan)
            .await
            .unwrap_err();

        let keys = desktop.keys();
        assert!(
            keys.iter().all(|k| k == "super+r" || k == "escape"),
            "{keys:?}"
        );
        assert!(
            keys.iter().filter(|k| *k == "super+r").count() >= 2,
            "{keys:?}"
        );
        assert!(err.to_string().contains("launched on 0 of"), "{err}");
        assert!(!ipc.is_ready());
    }

    #[tokio::test]
    async fn motion_elsewhere_does_not_stop_the_launch() {
        let mut desktop = FakeDesktop::new(Some(1));
        let ipc = desktop.ipc();
        desktop.busy_corner = true;

        start_agent_within(&desktop, &ipc, DRIVE, &QUICK_PLAN)
            .await
            .unwrap();

        let (keys, command) = desktop.keys_and_command();
        assert_eq!(keys, launch(&command));
    }

    #[tokio::test]
    async fn enter_is_not_pressed_unless_the_typed_command_shows() {
        let mut desktop = FakeDesktop::new(Some(1));
        let ipc = desktop.ipc();
        desktop.typing_shows = false;
        let plan = LaunchPlan {
            launch_until: Duration::from_millis(200),
            ..QUICK_PLAN
        };

        let err = start_agent_within(&desktop, &ipc, DRIVE, &plan)
            .await
            .unwrap_err();

        let (keys, command) = desktop.keys_and_command();
        assert!(!keys.contains(&"return".to_string()), "{keys:?}");
        let typed_then_escaped = [
            "super+r".to_string(),
            format!("text:{command}"),
            "escape".to_string(),
        ];
        assert!(keys.starts_with(&typed_then_escaped), "{keys:?}");
        assert!(err.to_string().contains("launched on 0 of"), "{err}");
    }

    #[tokio::test]
    async fn gives_up_at_the_deadline() {
        let desktop = FakeDesktop::new(None);
        let ipc = desktop.ipc();
        let plan = LaunchPlan {
            launch_until: Duration::from_millis(200),
            ..QUICK_PLAN
        };
        let started = Instant::now();

        let err = start_agent_within(&desktop, &ipc, DRIVE, &plan)
            .await
            .unwrap_err();

        // The last launch starts before the deadline and gets its full handshake wait; nothing
        // starts after it.
        let latest = plan.launch_until
            + plan.screen_poll
            + plan.run_dialog_wait
            + plan.handshake
            + plan.retry_pause;
        assert!(started.elapsed() < latest * 3, "{:?}", started.elapsed());
        let (keys, command) = desktop.keys_and_command();
        let launches = keys.iter().filter(|k| *k == "return").count();
        assert!(launches >= 2, "{keys:?}");
        assert!(keys
            .iter()
            .filter_map(|k| k.strip_prefix("text:"))
            .all(|c| c == command));
        let tried = format!("launched on {launches} of {launches} tries");
        assert!(err.to_string().contains(&tried), "{err}");
        assert!(!ipc.is_ready());
    }

    #[tokio::test]
    async fn a_closed_session_stops_the_launch() {
        let mut desktop = FakeDesktop::new(None);
        let ipc = desktop.ipc();
        desktop.closed = true;

        let err = start_agent_within(&desktop, &ipc, DRIVE, &QUICK_PLAN)
            .await
            .unwrap_err();

        assert!(matches!(
            err.downcast_ref::<RdpError>(),
            Some(RdpError::SessionClosed)
        ));
        assert!(desktop.keys().is_empty());
    }

    #[test]
    fn the_agent_start_fits_the_time_clients_allow_for_it() {
        // The last launch starts just before `launch_until`. Typing the command takes about 2 s.
        // The daemon also cuts the start off at the allowed time; this keeps it from needing to.
        let plan = &LAUNCH_PLAN;
        let longest = plan.launch_until
            + plan.screen_poll
            + plan.run_dialog_wait
            + plan.key_settle * 2
            + Duration::from_secs(2)
            + plan.handshake
            + plan.retry_pause;
        let allowed = Duration::from_millis(agent_rdp_protocol::AGENT_START_TIMEOUT_MS);
        assert!(longest <= allowed, "{longest:?} > {allowed:?}");
        assert!(plan.logon_wait < plan.launch_until);
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
