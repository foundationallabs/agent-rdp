//! Errors the CLI raises itself, each carrying the protocol [`ErrorCode`] that `--json`
//! output reports for it.

use std::fmt;

use agent_rdp_daemon::PathsError;
use agent_rdp_protocol::ErrorCode;

/// A CLI failure with the error code to report for it.
#[derive(Debug)]
pub struct CliError {
    code: ErrorCode,
    message: String,
}

impl CliError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

/// The error code to report for a failed command: the code of a [`CliError`] or
/// [`PathsError`] anywhere in the chain, else `internal_error`.
pub fn error_code(err: &anyhow::Error) -> ErrorCode {
    err.chain()
        .find_map(|cause| {
            cause
                .downcast_ref::<CliError>()
                .map(|e| e.code)
                .or_else(|| {
                    cause
                        .downcast_ref::<PathsError>()
                        .map(PathsError::error_code)
                })
        })
        .unwrap_or(ErrorCode::InternalError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn cli_error_reports_its_code_even_with_context() {
        let err = Err::<(), _>(CliError::new(ErrorCode::Timeout, "Request timed out"))
            .context("sending request")
            .unwrap_err();
        assert_eq!(error_code(&err), ErrorCode::Timeout);
    }

    #[test]
    fn paths_error_reports_its_code() {
        let invalid = anyhow::Error::new(PathsError::UnsafeDir {
            path: "/tmp/x".into(),
            reason: "is a symlink".into(),
        });
        assert_eq!(error_code(&invalid), ErrorCode::InvalidRequest);

        let io = anyhow::Error::new(PathsError::Io {
            path: "/tmp/x".into(),
            source: std::io::Error::other("boom"),
        });
        assert_eq!(error_code(&io), ErrorCode::InternalError);
    }

    #[test]
    fn other_errors_are_internal() {
        assert_eq!(
            error_code(&anyhow::anyhow!("unexpected")),
            ErrorCode::InternalError
        );
    }
}
