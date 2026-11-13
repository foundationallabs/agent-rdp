//! Confinement of server-supplied paths to a redirected drive's folder.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use ironrdp_rdpdr::pdu::efs::NtStatus;
use tracing::warn;

/// Why a server-supplied path was refused.
///
/// The refusal is logged by kind only; the path itself is attacker-controlled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    ParentSegment,
    StreamOrDrivePrefix,
    Nul,
    NotPlainSegment,
    Symlink,
    Unreadable,
}

/// Resolve a server-supplied RDPDR path inside the drive folder `base`.
///
/// Splits on `\` and `/`, ignores empty and `.` segments, and refuses `..`, drive prefixes,
/// alternate data streams (`:`), NUL, and any symlink below `base`. Every refusal is
/// `STATUS_ACCESS_DENIED`. The empty path resolves to `base`.
pub(crate) fn resolve_in_drive(base: &Path, remote: &str) -> Result<PathBuf, NtStatus> {
    confine(base, remote).map_err(|refusal| {
        warn!(
            ?refusal,
            "Refused a redirected-drive path outside the drive folder"
        );
        NtStatus::ACCESS_DENIED
    })
}

fn confine(base: &Path, remote: &str) -> Result<PathBuf, Refusal> {
    let mut path = base.to_path_buf();
    // Once a prefix is missing or is not a directory, nothing below it exists to be a symlink.
    let mut probe = true;

    for segment in remote.split(['\\', '/']) {
        match segment {
            "" | "." => continue,
            ".." => return Err(Refusal::ParentSegment),
            _ if segment.contains('\0') => return Err(Refusal::Nul),
            _ if segment.contains(':') => return Err(Refusal::StreamOrDrivePrefix),
            _ => {}
        }

        let mut components = Path::new(segment).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(part)), None) => path.push(part),
            _ => return Err(Refusal::NotPlainSegment),
        }

        if probe {
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_symlink() => return Err(Refusal::Symlink),
                Ok(meta) => probe = meta.is_dir(),
                Err(e) if e.kind() == io::ErrorKind::NotFound => probe = false,
                Err(_) => return Err(Refusal::Unreadable),
            }
        }
    }

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drive() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub").join("file.txt"), b"x").unwrap();
        dir
    }

    #[test]
    fn resolves_paths_inside_the_drive() {
        let dir = drive();
        let base = dir.path();
        assert_eq!(resolve_in_drive(base, "").unwrap(), base);
        assert_eq!(resolve_in_drive(base, "\\").unwrap(), base);
        assert_eq!(
            resolve_in_drive(base, "sub\\file.txt").unwrap(),
            base.join("sub/file.txt")
        );
        assert_eq!(
            resolve_in_drive(base, "\\sub\\.\\file.txt").unwrap(),
            base.join("sub/file.txt")
        );
        assert_eq!(
            resolve_in_drive(base, "/sub//new.txt").unwrap(),
            base.join("sub/new.txt")
        );
        assert_eq!(
            resolve_in_drive(base, "missing\\deeper").unwrap(),
            base.join("missing/deeper")
        );
    }

    #[test]
    fn refuses_escapes_and_special_segments() {
        let dir = drive();
        for remote in [
            "..\\..\\etc\\passwd",
            "a\\..\\..\\x",
            "sub\\..",
            "C:\\x",
            "x:stream",
            "sub\\file.txt:secret",
            "nul\0byte",
            // Below a missing prefix nothing is probed, so only the explicit checks can refuse.
            "missing\\nul\0byte",
            "missing\\x:stream",
        ] {
            assert_eq!(
                resolve_in_drive(dir.path(), remote),
                Err(NtStatus::ACCESS_DENIED),
                "{remote:?} must be refused"
            );
        }
    }

    #[test]
    fn leading_separator_stays_inside_the_drive() {
        let dir = drive();
        assert_eq!(
            resolve_in_drive(dir.path(), "/abs").unwrap(),
            dir.path().join("abs")
        );
        assert_eq!(
            resolve_in_drive(dir.path(), "\\etc\\passwd").unwrap(),
            dir.path().join("etc/passwd")
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinks_below_the_base() {
        let dir = drive();
        std::os::unix::fs::symlink("/", dir.path().join("root")).unwrap();
        std::os::unix::fs::symlink("/etc/hosts", dir.path().join("sub").join("hosts")).unwrap();
        for remote in ["root", "root\\etc\\passwd", "sub\\hosts"] {
            assert_eq!(
                resolve_in_drive(dir.path(), remote),
                Err(NtStatus::ACCESS_DENIED),
                "{remote:?} must be refused"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_base_is_allowed() {
        let target = drive();
        let holder = tempfile::tempdir().unwrap();
        let base = holder.path().join("drive");
        std::os::unix::fs::symlink(target.path(), &base).unwrap();
        assert_eq!(
            resolve_in_drive(&base, "sub\\file.txt").unwrap(),
            base.join("sub/file.txt")
        );
    }
}
