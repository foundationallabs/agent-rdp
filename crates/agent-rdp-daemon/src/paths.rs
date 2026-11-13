//! On-disk layout of the daemon's state: base directory, per-session directory, socket and
//! pid file, plus the validation and permission rules that protect them.
//!
//! Layout (Unix): `<base>/<session>/{socket,pid}`. The base directory is `AGENT_RDP_STATE_DIR`
//! when set (it must be absolute), otherwise `/tmp/agent-rdp` (`%TEMP%\agent-rdp` on Windows).
//! On Unix the directories are created `0700` and the socket and pid file `0600`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use agent_rdp_protocol::ErrorCode;
use thiserror::Error;

/// Environment variable that overrides the base directory for all sessions.
pub const STATE_DIR_ENV: &str = "AGENT_RDP_STATE_DIR";

/// Longest Unix socket path (in bytes) accepted; `sun_path` is 104 bytes on macOS including
/// the trailing NUL, which is the smallest limit among supported platforms.
pub const MAX_SOCKET_PATH_BYTES: usize = 103;

/// Mode of the socket and pid file: owner read/write only.
#[cfg(unix)]
pub(crate) const PRIVATE_FILE_MODE: u32 = 0o600;

/// Mode of the per-session directory: owner only.
#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;

/// Any group or other permission.
#[cfg(unix)]
const GROUP_OTHER_BITS: u32 = 0o077;

/// Group or other write permission.
#[cfg(unix)]
const GROUP_OTHER_WRITE_BITS: u32 = 0o022;

#[cfg(unix)]
const STICKY_BIT: u32 = 0o1000;

/// Errors from resolving, validating or preparing state paths.
#[derive(Error, Debug)]
pub enum PathsError {
    /// `AGENT_RDP_STATE_DIR` was set to a relative path.
    #[error("{STATE_DIR_ENV} must be an absolute path, got {path:?}")]
    RelativeStateDir {
        /// The rejected value.
        path: PathBuf,
    },

    /// A session name contained characters outside `[A-Za-z0-9._-]`, was empty, or was `.`/`..`.
    #[error("invalid session name {name:?}: {reason}")]
    InvalidSessionName {
        /// The rejected name.
        name: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// The Unix socket path would not fit in `sun_path`.
    #[error("socket path {path:?} is {len} bytes, over the {limit}-byte limit; use a shorter {STATE_DIR_ENV} or session name")]
    SocketPathTooLong {
        /// The offending path.
        path: PathBuf,
        /// Its length in bytes.
        len: usize,
        /// The maximum allowed length in bytes.
        limit: usize,
    },

    /// A state directory exists but is not safe to use.
    #[error("unsafe state directory {path:?}: {reason} (remove it, or make it owned by you and not writable by others)")]
    UnsafeDir {
        /// The directory.
        path: PathBuf,
        /// Why it was refused.
        reason: String,
    },

    /// An I/O error while preparing a path.
    #[error("{path:?}: {source}")]
    Io {
        /// The path being operated on.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
}

impl PathsError {
    /// The protocol error code that reports this error: `internal_error` for I/O failures,
    /// `invalid_request` for everything else (the caller's input or state directory is unusable).
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Io { .. } => ErrorCode::InternalError,
            Self::RelativeStateDir { .. }
            | Self::InvalidSessionName { .. }
            | Self::SocketPathTooLong { .. }
            | Self::UnsafeDir { .. } => ErrorCode::InvalidRequest,
        }
    }

    fn io(path: &Path) -> impl FnOnce(std::io::Error) -> PathsError + '_ {
        move |source| PathsError::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

/// Resolve the base directory from the value of `AGENT_RDP_STATE_DIR`.
///
/// Unset or empty gives the platform default; anything else must be an absolute path.
/// Trailing separators are dropped (a bare root stays), so `/a/b/` and `/a/b` are the same
/// directory to every later check (a trailing slash would make `lstat` follow a symlink).
pub fn resolve_base_dir(env_value: Option<OsString>) -> Result<PathBuf, PathsError> {
    match env_value {
        Some(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                // Re-collecting the components drops trailing separators
                Ok(path.components().collect())
            } else {
                Err(PathsError::RelativeStateDir { path })
            }
        }
        _ => Ok(default_base_dir()),
    }
}

fn default_base_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/tmp/agent-rdp")
    }
    #[cfg(windows)]
    {
        let temp = std::env::var("TEMP")
            .or_else(|_| std::env::var("TMP"))
            .unwrap_or_else(|_| "C:\\Windows\\Temp".to_string());
        PathBuf::from(format!("{}\\agent-rdp", temp))
    }
}

/// Check that `AGENT_RDP_STATE_DIR` is usable. The CLI calls this first so a bad value exits
/// cleanly instead of panicking in [`get_base_dir`].
pub fn check_state_dir() -> Result<(), PathsError> {
    resolve_base_dir(std::env::var_os(STATE_DIR_ENV)).map(|_| ())
}

/// Get the base directory for all agent-rdp sessions (see [`resolve_base_dir`]).
///
/// Panics if `AGENT_RDP_STATE_DIR` is invalid; callers run [`check_state_dir`] first.
pub fn get_base_dir() -> PathBuf {
    match resolve_base_dir(std::env::var_os(STATE_DIR_ENV)) {
        Ok(dir) => dir,
        Err(e) => panic!("{e}"),
    }
}

/// Validate a session name: non-empty, only `[A-Za-z0-9._-]`, and not `.` or `..`.
///
/// Call this where a name enters the program (CLI argument, SDK option); the path helpers do
/// not validate.
pub fn validate_session_name(name: &str) -> Result<(), PathsError> {
    let reason = if name.is_empty() {
        Some("must not be empty")
    } else if name == "." || name == ".." {
        Some("must not be '.' or '..'")
    } else if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        Some("may only contain A-Z a-z 0-9 . _ -")
    } else {
        None
    };
    match reason {
        Some(reason) => Err(PathsError::InvalidSessionName {
            name: name.to_string(),
            reason,
        }),
        None => Ok(()),
    }
}

/// Get the session directory path.
pub fn get_session_dir(session: &str) -> PathBuf {
    get_base_dir().join(session)
}

/// Get the socket path for a session.
pub fn get_socket_path(session: &str) -> PathBuf {
    #[cfg(unix)]
    {
        get_session_dir(session).join("socket")
    }
    #[cfg(windows)]
    {
        // On Windows, we use a named pipe path
        PathBuf::from(format!("\\\\.\\pipe\\agent-rdp-{}", session))
    }
}

/// Get the PID file path for a session.
pub fn get_pid_path(session: &str) -> PathBuf {
    get_session_dir(session).join("pid")
}

/// Get the TCP port for a session (Windows fallback).
/// Uses a deterministic hash of the session name to derive a port in the range 49152-65535.
pub fn get_session_port(session: &str) -> u16 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    session.hash(&mut hasher);
    let hash = hasher.finish();
    // Map to ephemeral port range: 49152-65535 (16384 ports)
    49152 + (hash % 16384) as u16
}

/// Remove a session directory and everything in it.
pub fn cleanup_session(session: &str) {
    let dir = get_session_dir(session);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Fail if a Unix socket at `path` would not fit in `sun_path` ([`MAX_SOCKET_PATH_BYTES`]).
#[cfg(unix)]
pub(crate) fn check_socket_path_len(path: &Path) -> Result<(), PathsError> {
    use std::os::unix::ffi::OsStrExt;

    let len = path.as_os_str().as_bytes().len();
    if len > MAX_SOCKET_PATH_BYTES {
        return Err(PathsError::SocketPathTooLong {
            path: path.to_path_buf(),
            len,
            limit: MAX_SOCKET_PATH_BYTES,
        });
    }
    Ok(())
}

/// `lstat` a state directory and refuse symlinks and non-directories.
#[cfg(unix)]
fn lstat_dir(path: &Path) -> Result<std::fs::Metadata, PathsError> {
    let meta = std::fs::symlink_metadata(path).map_err(PathsError::io(path))?;
    if meta.file_type().is_symlink() {
        return Err(unsafe_dir(path, "is a symlink"));
    }
    if !meta.is_dir() {
        return Err(unsafe_dir(path, "is not a directory"));
    }
    Ok(meta)
}

#[cfg(unix)]
fn unsafe_dir(path: &Path, reason: &str) -> PathsError {
    PathsError::UnsafeDir {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    }
}

#[cfg(unix)]
fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Require a directory owned by the current user, or also by root when `allow_root`.
#[cfg(unix)]
fn check_owner(path: &Path, meta: &std::fs::Metadata, allow_root: bool) -> Result<(), PathsError> {
    use std::os::unix::fs::MetadataExt;

    let euid = current_euid();
    if meta.uid() == euid || (allow_root && meta.uid() == 0) {
        return Ok(());
    }
    let or_root = if allow_root { " or root" } else { "" };
    Err(unsafe_dir(
        path,
        &format!(
            "is owned by uid {}, not the current user (uid {}){}",
            meta.uid(),
            euid,
            or_root
        ),
    ))
}

/// Rules for the base directory, which may be shared: owned by the current user or root, and
/// if group/other-writable then sticky.
#[cfg(unix)]
fn check_base_dir_meta(path: &Path, meta: &std::fs::Metadata) -> Result<(), PathsError> {
    use std::os::unix::fs::MetadataExt;

    check_owner(path, meta, true)?;
    let mode = meta.mode();
    if mode & GROUP_OTHER_WRITE_BITS != 0 && mode & STICKY_BIT == 0 {
        return Err(unsafe_dir(
            path,
            "is writable by other users and has no sticky bit; other users could replace session directories in it",
        ));
    }
    Ok(())
}

/// Create `path` as a `0700` directory (missing parents get the default mode). An existing
/// directory is left for the caller to check.
#[cfg(unix)]
fn create_dir_0700(path: &Path) -> Result<(), PathsError> {
    use std::os::unix::fs::DirBuilderExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(PathsError::io(parent))?;
    }
    match std::fs::DirBuilder::new()
        .mode(PRIVATE_DIR_MODE)
        .create(path)
    {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(PathsError::io(path)(e)),
    }
}

/// Create `path` (a session directory) as a private (`0700`) directory owned by the current user.
///
/// Missing parents are created with the default mode. An existing directory is reused after
/// checking it with `lstat`: a symlink, a non-directory, or a directory owned by another uid
/// is refused ([`PathsError::UnsafeDir`]); loose permissions on a directory we own are
/// tightened to `0700`.
#[cfg(unix)]
pub(crate) fn ensure_private_dir(path: &Path) -> Result<(), PathsError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    create_dir_0700(path)?;
    let meta = lstat_dir(path)?;
    check_owner(path, &meta, false)?;
    if meta.mode() & GROUP_OTHER_BITS != 0 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))
            .map_err(PathsError::io(path))?;
    }
    Ok(())
}

/// Make sure the base directory exists and is safe to put session directories in.
///
/// A missing base is created `0700` (missing parents get the default mode). An existing base
/// is never chmodded, because it may be shared (for example `/tmp` itself or a `1777`
/// directory); it is refused if it is a symlink, not a directory, owned by neither the current
/// user nor root, or group/other-writable without the sticky bit ([`PathsError::UnsafeDir`]).
#[cfg(unix)]
pub(crate) fn ensure_base_dir(path: &Path) -> Result<(), PathsError> {
    create_dir_0700(path)?;
    let meta = lstat_dir(path)?;
    check_base_dir_meta(path, &meta)
}

/// Check, without creating or changing anything, that the state directories of `session` are
/// safe to connect to: the base directory is a real directory owned by the current user or
/// root (sticky if group/other-writable), and the session directory is a real directory owned
/// by the current user with no group/other permissions.
///
/// Clients call this before trusting a pid file or socket, so they never send credentials to a
/// daemon whose directory another user controls. It does not protect against other processes
/// running as the same user, nor against a state directory whose parent directories are
/// controlled by another user. A missing directory is an [`PathsError::Io`] error. No-op on
/// Windows.
pub fn verify_session_dirs(session: &str) -> Result<(), PathsError> {
    #[cfg(unix)]
    verify_dirs_at(&get_base_dir(), &get_session_dir(session))?;
    #[cfg(not(unix))]
    let _ = session;
    Ok(())
}

/// Check, without creating or changing anything, that the base (state) directory is safe to
/// put session directories in: a real directory owned by the current user or root, sticky if
/// group/other-writable.
///
/// Clients call this when a session has no directory yet, so an unsafe base is reported to the
/// user instead of showing up as a daemon that never starts (the daemon refuses it too, but its
/// output is discarded). A missing base is an [`PathsError::Io`] error. No-op on Windows.
pub fn verify_base_dir() -> Result<(), PathsError> {
    #[cfg(unix)]
    verify_base_at(&get_base_dir())?;
    Ok(())
}

#[cfg(unix)]
fn verify_base_at(base: &Path) -> Result<(), PathsError> {
    check_base_dir_meta(base, &lstat_dir(base)?)
}

#[cfg(unix)]
fn verify_dirs_at(base: &Path, session_dir: &Path) -> Result<(), PathsError> {
    use std::os::unix::fs::MetadataExt;

    verify_base_at(base)?;

    let meta = lstat_dir(session_dir)?;
    check_owner(session_dir, &meta, false)?;
    if meta.mode() & GROUP_OTHER_BITS != 0 {
        return Err(unsafe_dir(
            session_dir,
            "is accessible by other users (expected mode 0700)",
        ));
    }
    Ok(())
}

/// Prepare the base and session directories for a daemon (private session dir on Unix).
pub fn ensure_session_dirs(session: &str) -> Result<(), PathsError> {
    let session_dir = get_session_dir(session);
    #[cfg(unix)]
    {
        ensure_base_dir(&get_base_dir())?;
        ensure_private_dir(&session_dir)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(&session_dir).map_err(PathsError::io(&session_dir))?;
    Ok(())
}

/// Write this process's PID to `path`, replacing any existing content (mode `0600` on Unix).
pub fn write_pid_file(path: &Path) -> std::io::Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PRIVATE_FILE_MODE);
    }
    let mut file = options.open(path)?;
    writeln!(file, "{}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_base_dir_unset_and_empty_use_default() {
        assert_eq!(resolve_base_dir(None).unwrap(), default_base_dir());
        assert_eq!(
            resolve_base_dir(Some(OsString::new())).unwrap(),
            default_base_dir()
        );
    }

    #[test]
    fn resolve_base_dir_uses_absolute_value() {
        let abs = std::env::temp_dir().join("rdp-state");
        assert_eq!(
            resolve_base_dir(Some(abs.clone().into_os_string())).unwrap(),
            abs
        );
    }

    #[test]
    fn resolve_base_dir_strips_trailing_separators_but_keeps_root() {
        let resolve = |s: &str| resolve_base_dir(Some(OsString::from(s))).unwrap();
        #[cfg(unix)]
        {
            assert_eq!(resolve("/a/b/"), PathBuf::from("/a/b"));
            assert_eq!(resolve("/a/b//"), PathBuf::from("/a/b"));
            assert_eq!(resolve("/"), PathBuf::from("/"));
        }
        #[cfg(windows)]
        {
            assert_eq!(resolve("C:\\a\\b\\"), PathBuf::from("C:\\a\\b"));
            assert_eq!(resolve("C:\\a\\b\\\\"), PathBuf::from("C:\\a\\b"));
        }
    }

    #[test]
    fn resolve_base_dir_rejects_relative_value() {
        let err = resolve_base_dir(Some(OsString::from("relative/dir"))).unwrap_err();
        assert!(matches!(err, PathsError::RelativeStateDir { .. }));
        assert!(err.to_string().contains("AGENT_RDP_STATE_DIR"));
    }

    #[test]
    fn session_name_accepts_valid_names() {
        assert!(validate_session_name("default").is_ok());
        assert!(validate_session_name("rdp-1.a_b").is_ok());
    }

    #[test]
    fn session_name_rejects_invalid_names() {
        for bad in ["", ".", "..", "a/b", "../x", "a b", "a\\b"] {
            assert!(
                matches!(
                    validate_session_name(bad),
                    Err(PathsError::InvalidSessionName { .. })
                ),
                "{bad:?} should be rejected"
            );
        }
    }

    #[cfg(unix)]
    mod unix {
        use super::*;
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        fn mode(path: &Path) -> u32 {
            std::fs::metadata(path).unwrap().mode() & 0o777
        }

        fn chmod(path: &Path, mode: u32) {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }

        /// A fresh `base` directory (created private) inside `tmp`.
        fn base_in(tmp: &tempfile::TempDir) -> PathBuf {
            let base = tmp.path().join("base");
            ensure_base_dir(&base).unwrap();
            base
        }

        #[test]
        fn ensure_private_dir_creates_0700() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("a").join("state");
            ensure_private_dir(&dir).unwrap();
            assert_eq!(mode(&dir), 0o700);
        }

        #[test]
        fn ensure_private_dir_tightens_existing_dir() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("state");
            std::fs::create_dir(&dir).unwrap();
            chmod(&dir, 0o755);
            ensure_private_dir(&dir).unwrap();
            assert_eq!(mode(&dir), 0o700);
        }

        #[test]
        fn ensure_private_dir_refuses_symlink() {
            let tmp = tempfile::tempdir().unwrap();
            let target = tmp.path().join("target");
            std::fs::create_dir(&target).unwrap();
            let link = tmp.path().join("link");
            symlink(&target, &link).unwrap();
            assert!(matches!(
                ensure_private_dir(&link),
                Err(PathsError::UnsafeDir { .. })
            ));
        }

        #[test]
        fn ensure_base_dir_creates_0700() {
            let tmp = tempfile::tempdir().unwrap();
            let base = base_in(&tmp);
            assert_eq!(mode(&base), 0o700);
        }

        #[test]
        fn ensure_base_dir_leaves_sticky_shared_dir_alone() {
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().join("shared");
            std::fs::create_dir(&base).unwrap();
            chmod(&base, 0o1777);
            ensure_base_dir(&base).unwrap();
            assert_eq!(std::fs::metadata(&base).unwrap().mode() & 0o7777, 0o1777);
            // Session directories can still be made inside it
            ensure_private_dir(&base.join("s")).unwrap();
            assert_eq!(mode(&base.join("s")), 0o700);
        }

        #[test]
        fn ensure_base_dir_refuses_other_writable_without_sticky() {
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().join("open");
            std::fs::create_dir(&base).unwrap();
            chmod(&base, 0o757);
            assert!(matches!(
                ensure_base_dir(&base),
                Err(PathsError::UnsafeDir { .. })
            ));
            assert_eq!(mode(&base), 0o757, "must not be chmodded");
        }

        #[test]
        fn ensure_base_dir_refuses_symlink_with_or_without_trailing_slash() {
            let tmp = tempfile::tempdir().unwrap();
            let target = tmp.path().join("target");
            std::fs::create_dir(&target).unwrap();
            let link = tmp.path().join("link");
            symlink(&target, &link).unwrap();
            for value in [
                link.clone().into_os_string(),
                format!("{}/", link.display()).into(),
            ] {
                let base = resolve_base_dir(Some(value)).unwrap();
                assert!(
                    matches!(ensure_base_dir(&base), Err(PathsError::UnsafeDir { .. })),
                    "{base:?}"
                );
            }
        }

        fn session_under(base: &Path) -> PathBuf {
            let dir = base.join("default");
            ensure_private_dir(&dir).unwrap();
            dir
        }

        #[test]
        fn verify_dirs_accepts_private_session_in_own_base() {
            let tmp = tempfile::tempdir().unwrap();
            let base = base_in(&tmp);
            let dir = session_under(&base);
            verify_dirs_at(&base, &dir).unwrap();
        }

        #[test]
        fn verify_dirs_accepts_sticky_shared_base() {
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().join("shared");
            std::fs::create_dir(&base).unwrap();
            chmod(&base, 0o1777);
            let dir = session_under(&base);
            verify_dirs_at(&base, &dir).unwrap();
        }

        #[test]
        fn verify_dirs_refuses_symlinked_session_dir() {
            let tmp = tempfile::tempdir().unwrap();
            let base = base_in(&tmp);
            let real = tmp.path().join("real");
            ensure_private_dir(&real).unwrap();
            let link = base.join("default");
            symlink(&real, &link).unwrap();
            assert!(matches!(
                verify_dirs_at(&base, &link),
                Err(PathsError::UnsafeDir { .. })
            ));
        }

        #[test]
        fn verify_dirs_refuses_group_writable_session_dir() {
            let tmp = tempfile::tempdir().unwrap();
            let base = base_in(&tmp);
            let dir = session_under(&base);
            chmod(&dir, 0o770);
            assert!(matches!(
                verify_dirs_at(&base, &dir),
                Err(PathsError::UnsafeDir { .. })
            ));
        }

        #[test]
        fn verify_dirs_refuses_group_writable_base_without_sticky() {
            let tmp = tempfile::tempdir().unwrap();
            let base = base_in(&tmp);
            let dir = session_under(&base);
            chmod(&base, 0o770);
            assert!(matches!(
                verify_dirs_at(&base, &dir),
                Err(PathsError::UnsafeDir { .. })
            ));
        }

        #[test]
        fn verify_base_refuses_group_writable_base_without_sticky() {
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().join("base");
            std::fs::create_dir(&base).unwrap();
            chmod(&base, 0o775);
            assert!(matches!(
                verify_base_at(&base),
                Err(PathsError::UnsafeDir { .. })
            ));
            chmod(&base, 0o700);
            verify_base_at(&base).unwrap();
        }

        #[test]
        fn verify_dirs_refuses_missing_session_dir() {
            let tmp = tempfile::tempdir().unwrap();
            assert!(matches!(
                verify_dirs_at(tmp.path(), &tmp.path().join("nope")),
                Err(PathsError::Io { .. })
            ));
        }

        #[test]
        fn pid_file_is_0600_and_holds_pid() {
            let tmp = tempfile::tempdir().unwrap();
            let path = tmp.path().join("pid");
            write_pid_file(&path).unwrap();
            assert_eq!(mode(&path), 0o600);
            let content = std::fs::read_to_string(&path).unwrap();
            assert_eq!(content.trim(), std::process::id().to_string());
        }

        #[test]
        fn long_socket_path_is_rejected() {
            let long = PathBuf::from(format!("/tmp/{}/socket", "x".repeat(MAX_SOCKET_PATH_BYTES)));
            assert!(matches!(
                check_socket_path_len(&long),
                Err(PathsError::SocketPathTooLong { .. })
            ));
            assert!(check_socket_path_len(Path::new("/tmp/agent-rdp/default/socket")).is_ok());
        }
    }
}
