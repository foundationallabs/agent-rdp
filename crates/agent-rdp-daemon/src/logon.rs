//! Classification of login failures.
//!
//! With NLA on, the server refuses a login during CredSSP, so it surfaces as a typed connector
//! error. With NLA off, the login happens inside the session: the server reports a failed
//! auto-logon in a Save Session Info PDU (MS-RDPBCGR 2.2.10.1), which `ironrdp-session` drops.

use agent_rdp_protocol::AuthFailureReason;
use ironrdp::connector::legacy::{decode_io_channel, decode_send_data_indication, IoChannelPdu};
use ironrdp::connector::sspi::credssp::NStatusCode;
use ironrdp::connector::sspi::ErrorKind;
use ironrdp::connector::{ConnectorError, ConnectorErrorKind};
use ironrdp::pdu::rdp::headers::ShareDataPdu;
use ironrdp::pdu::rdp::session_info::{
    InfoData, LogonErrorNotificationData, LogonErrorNotificationDataErrorCode,
    LogonErrorNotificationType, LogonErrorsInfo,
};
use ironrdp::pdu::Action;
use std::time::Duration;
use tokio::sync::oneshot;
use tracing::info;

/// How an NLA-off login ended, as reported by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogonOutcome {
    Succeeded,
    Failed(AuthFailureReason),
}

/// The reason when a connector error is the server refusing the login, `None` otherwise.
pub fn connector_auth_failure(error: &ConnectorError) -> Option<AuthFailureReason> {
    match error.kind() {
        ConnectorErrorKind::AccessDenied => Some(AuthFailureReason::AccessDenied),
        ConnectorErrorKind::Credssp(sspi_error) => {
            sspi_error.nstatus.and_then(nstatus_reason).or_else(|| {
                (sspi_error.error_type == ErrorKind::LogonDenied)
                    .then_some(AuthFailureReason::LogonDenied)
            })
        }
        _ => None,
    }
}

fn nstatus_reason(status: NStatusCode) -> Option<AuthFailureReason> {
    use AuthFailureReason as R;
    Some(match status {
        NStatusCode::LOGON_FAILURE => R::LogonFailure,
        NStatusCode::WRONG_PASSWORD => R::WrongPassword,
        NStatusCode::NO_SUCH_USER => R::NoSuchUser,
        NStatusCode::ACCOUNT_LOCKED_OUT => R::AccountLockedOut,
        NStatusCode::ACCOUNT_DISABLED => R::AccountDisabled,
        NStatusCode::ACCOUNT_RESTRICTION => R::AccountRestriction,
        NStatusCode::PASSWORD_EXPIRED => R::PasswordExpired,
        NStatusCode::PASSWORD_MUST_CHANGE => R::PasswordMustChange,
        NStatusCode::INVALID_LOGON_HOURS => R::InvalidLogonHours,
        NStatusCode::INVALID_WORKSTATION => R::InvalidWorkstation,
        NStatusCode::LOGON_NOT_GRANTED => R::LogonNotGranted,
        NStatusCode::LOGON_TYPE_NOT_GRANTED => R::LogonTypeNotGranted,
        _ => return None,
    })
}

/// Peek a server frame for a logon notification on the I/O channel.
///
/// Returns `None` for every frame that is not a Save Session Info PDU carrying a logon result.
pub fn logon_outcome(io_channel_id: u16, action: Action, frame: &[u8]) -> Option<LogonOutcome> {
    if action != Action::X224 {
        return None;
    }
    let ctx = decode_send_data_indication(frame).ok()?;
    if ctx.channel_id != io_channel_id {
        return None;
    }
    let IoChannelPdu::Data(data) = decode_io_channel(ctx).ok()? else {
        return None;
    };
    let ShareDataPdu::SaveSessionInfo(session_info) = data.pdu else {
        return None;
    };
    let info_type = session_info.info_type;
    match session_info.info_data {
        InfoData::LogonInfoV1(_) | InfoData::LogonInfoV2(_) | InfoData::PlainNotify => {
            info!(?info_type, "Server sent a logon notification");
            Some(LogonOutcome::Succeeded)
        }
        InfoData::LogonExtended(extended) => {
            let Some(errors) = extended.errors_info else {
                info!(
                    fields = ?extended.present_fields_flags,
                    "Server sent extended logon info without errors"
                );
                return None;
            };
            info!(
                error_type = ?errors.error_type,
                error_data = ?errors.error_data,
                "Server sent logon errors info"
            );
            logon_error_reason(&errors).map(LogonOutcome::Failed)
        }
    }
}

/// Map a Logon Errors Info structure to a login failure.
///
/// SESSION_CONTINUE is informational whatever its data: the logon goes on, and a WS2019 broker
/// farm sends it with LOGON_FAILED_OTHER on every good logon. The data field holds a
/// LOGON_FAILED_* code only alongside SESSION_CONTINUE or SESSION_TERMINATE; with the
/// session-choice types it is a session ID that can collide with those codes, so it is not read
/// there.
fn logon_error_reason(errors: &LogonErrorsInfo) -> Option<AuthFailureReason> {
    use LogonErrorNotificationDataErrorCode as Code;
    use LogonErrorNotificationType as Type;
    match errors.error_type {
        Type::NoPermission => Some(AuthFailureReason::NoPermission),
        Type::AccessDenied => Some(AuthFailureReason::AccessDenied),
        Type::SessionTerminate => match errors.error_data {
            LogonErrorNotificationData::ErrorCode(Code::FailedBadPassword) => {
                Some(AuthFailureReason::LogonFailedBadPassword)
            }
            LogonErrorNotificationData::ErrorCode(Code::FailedUpdatePassword) => {
                Some(AuthFailureReason::LogonFailedUpdatePassword)
            }
            LogonErrorNotificationData::ErrorCode(Code::FailedOther) => {
                Some(AuthFailureReason::LogonFailedOther)
            }
            LogonErrorNotificationData::ErrorCode(Code::Warning)
            | LogonErrorNotificationData::SessionId(_) => None,
        },
        Type::SessionContinue
        | Type::SessionBusyOptions
        | Type::DisconnectRefused
        | Type::BumpOptions
        | Type::ReconnectOptions => None,
    }
}

/// What the frame processor tells a `connect()` that is waiting for the NLA-off login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogonReport {
    Outcome(LogonOutcome),
    /// The session ended before the server reported a login result.
    SessionEnded,
}

/// Watches server frames for the login result on behalf of the frame processor.
pub struct LogonWatch {
    io_channel_id: u16,
    report_tx: Option<oneshot::Sender<LogonReport>>,
    awaited: bool,
    confirmed: bool,
}

impl LogonWatch {
    /// `report_tx` is set when `connect()` waits for the login result (NLA off).
    pub fn new(io_channel_id: u16, report_tx: Option<oneshot::Sender<LogonReport>>) -> Self {
        Self {
            io_channel_id,
            awaited: report_tx.is_some(),
            report_tx,
            confirmed: false,
        }
    }

    /// Peek a server frame. Returns the reason when the server rejected the login, in which
    /// case the session must end.
    pub fn observe(&mut self, action: Action, frame: &[u8]) -> Option<AuthFailureReason> {
        match logon_outcome(self.io_channel_id, action, frame)? {
            LogonOutcome::Succeeded => {
                // Confirmed only once connect() took it; it may already have given up.
                self.confirmed |= self.report(LogonReport::Outcome(LogonOutcome::Succeeded));
                None
            }
            LogonOutcome::Failed(reason) => Some(reason),
        }
    }

    /// Hand the session's end to a waiting `connect()`. Returns `true` when the login was never
    /// confirmed: `connect()` then answers the caller itself, or has already given up and is
    /// ending the session, so the daemon must not be told the connection dropped.
    pub fn finish(mut self, end: LogonReport) -> bool {
        self.report(end);
        self.awaited && !self.confirmed
    }

    /// Returns `true` when `connect()` received the report.
    fn report(&mut self, report: LogonReport) -> bool {
        self.report_tx
            .take()
            .is_some_and(|tx| tx.send(report).is_ok())
    }
}

/// Wait up to `window` for the frame processor's report. `None` means the server stayed silent.
pub async fn await_logon_report(
    mut report_rx: oneshot::Receiver<LogonReport>,
    window: Duration,
) -> Option<LogonReport> {
    match tokio::time::timeout(window, &mut report_rx).await {
        Ok(received) => Some(received.unwrap_or(LogonReport::SessionEnded)),
        Err(_) => settle_after_deadline(&mut report_rx),
    }
}

/// Close first so a report racing the deadline is either received here or refused. A refused
/// report is dropped: `connect()` fails the login and ends the session either way.
fn settle_after_deadline(report_rx: &mut oneshot::Receiver<LogonReport>) -> Option<LogonReport> {
    report_rx.close();
    report_rx.try_recv().ok()
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use ironrdp::connector::sspi;
    use ironrdp::pdu::mcs::SendDataIndication;
    use ironrdp::pdu::rdp::client_info::CompressionType;
    use ironrdp::pdu::rdp::headers::{
        CompressionFlags, ShareControlHeader, ShareControlPdu, ShareDataHeader, StreamPriority,
    };
    use ironrdp::pdu::rdp::session_info::{
        InfoType, LogonExFlags, LogonInfoExtended, SaveSessionInfoPdu,
    };
    use ironrdp::pdu::x224::X224;

    use super::*;

    const IO_CHANNEL: u16 = 1003;

    fn credssp_error(error_type: ErrorKind, nstatus: Option<NStatusCode>) -> ConnectorError {
        let sspi_error = match nstatus {
            Some(status) => sspi::Error::new_with_nstatus(error_type, "server error", status),
            None => sspi::Error::new(error_type, "server error"),
        };
        ConnectorError::new("CredSSP", ConnectorErrorKind::Credssp(sspi_error))
    }

    #[test]
    fn every_logon_ntstatus_is_an_auth_failure() {
        use AuthFailureReason as R;
        for (status, reason) in [
            (NStatusCode::LOGON_FAILURE, R::LogonFailure),
            (NStatusCode::WRONG_PASSWORD, R::WrongPassword),
            (NStatusCode::NO_SUCH_USER, R::NoSuchUser),
            (NStatusCode::ACCOUNT_LOCKED_OUT, R::AccountLockedOut),
            (NStatusCode::ACCOUNT_DISABLED, R::AccountDisabled),
            (NStatusCode::ACCOUNT_RESTRICTION, R::AccountRestriction),
            (NStatusCode::PASSWORD_EXPIRED, R::PasswordExpired),
            (NStatusCode::PASSWORD_MUST_CHANGE, R::PasswordMustChange),
            (NStatusCode::INVALID_LOGON_HOURS, R::InvalidLogonHours),
            (NStatusCode::INVALID_WORKSTATION, R::InvalidWorkstation),
            (NStatusCode::LOGON_NOT_GRANTED, R::LogonNotGranted),
            (NStatusCode::LOGON_TYPE_NOT_GRANTED, R::LogonTypeNotGranted),
        ] {
            // CredSSP reports a server errorCode as InvalidToken carrying the NTSTATUS.
            let error = credssp_error(ErrorKind::InvalidToken, Some(status));
            assert_eq!(connector_auth_failure(&error), Some(reason), "{reason:?}");
        }
    }

    #[test]
    fn early_user_auth_access_denied_is_an_auth_failure() {
        let error = ConnectorError::new("CredSSP", ConnectorErrorKind::AccessDenied);
        assert_eq!(
            connector_auth_failure(&error),
            Some(AuthFailureReason::AccessDenied)
        );
    }

    #[test]
    fn logon_denied_kind_is_an_auth_failure() {
        let error = credssp_error(ErrorKind::LogonDenied, None);
        assert_eq!(
            connector_auth_failure(&error),
            Some(AuthFailureReason::LogonDenied)
        );
        // A specific NTSTATUS wins over the generic kind.
        let error = credssp_error(
            ErrorKind::LogonDenied,
            Some(NStatusCode::ACCOUNT_LOCKED_OUT),
        );
        assert_eq!(
            connector_auth_failure(&error),
            Some(AuthFailureReason::AccountLockedOut)
        );
    }

    #[test]
    fn other_connector_errors_are_not_auth_failures() {
        let io_timeout = credssp_error(ErrorKind::InvalidToken, Some(NStatusCode::IO_TIMEOUT));
        assert_eq!(connector_auth_failure(&io_timeout), None);
        let no_status = credssp_error(ErrorKind::InternalError, None);
        assert_eq!(connector_auth_failure(&no_status), None);
        for kind in [
            ConnectorErrorKind::General,
            ConnectorErrorKind::Custom,
            ConnectorErrorKind::Reason("server closed the connection".to_owned()),
        ] {
            assert_eq!(
                connector_auth_failure(&ConnectorError::new("connect", kind)),
                None
            );
        }
    }

    /// Encode a Save Session Info PDU as the server sends it: X.224 / MCS Send Data
    /// Indication on `channel_id` / Share Control / Share Data.
    fn save_session_info_frame(
        channel_id: u16,
        info_type: InfoType,
        info_data: InfoData,
    ) -> Vec<u8> {
        let share = ShareControlHeader {
            share_control_pdu: ShareControlPdu::Data(ShareDataHeader {
                share_data_pdu: ShareDataPdu::SaveSessionInfo(SaveSessionInfoPdu {
                    info_type,
                    info_data,
                }),
                stream_priority: StreamPriority::Medium,
                compression_flags: CompressionFlags::empty(),
                compression_type: CompressionType::K8,
            }),
            pdu_source: 1002,
            share_id: 0x0001_03ea,
        };
        let user_data = ironrdp::pdu::encode_vec(&share).unwrap();
        ironrdp::pdu::encode_vec(&X224(SendDataIndication {
            initiator_id: 1002,
            channel_id,
            user_data: Cow::Owned(user_data),
        }))
        .unwrap()
    }

    fn logon_errors_frame(
        error_type: LogonErrorNotificationType,
        error_data: LogonErrorNotificationData,
    ) -> Vec<u8> {
        save_session_info_frame(
            IO_CHANNEL,
            InfoType::LogonExtended,
            InfoData::LogonExtended(LogonInfoExtended {
                present_fields_flags: LogonExFlags::LOGON_ERRORS,
                auto_reconnect: None,
                errors_info: Some(LogonErrorsInfo {
                    error_type,
                    error_data,
                }),
            }),
        )
    }

    #[test]
    fn bad_password_logon_error_fails_the_login() {
        let frame = logon_errors_frame(
            LogonErrorNotificationType::SessionTerminate,
            LogonErrorNotificationData::ErrorCode(
                LogonErrorNotificationDataErrorCode::FailedBadPassword,
            ),
        );
        assert_eq!(
            logon_outcome(IO_CHANNEL, Action::X224, &frame),
            Some(LogonOutcome::Failed(
                AuthFailureReason::LogonFailedBadPassword
            ))
        );
    }

    #[test]
    fn each_failure_type_fails_the_login() {
        use LogonErrorNotificationData as Data;
        use LogonErrorNotificationDataErrorCode as Code;
        use LogonErrorNotificationType as Type;
        for (error_type, error_data, reason) in [
            (
                Type::SessionTerminate,
                Data::ErrorCode(Code::FailedBadPassword),
                AuthFailureReason::LogonFailedBadPassword,
            ),
            (
                Type::SessionTerminate,
                Data::ErrorCode(Code::FailedUpdatePassword),
                AuthFailureReason::LogonFailedUpdatePassword,
            ),
            (
                Type::SessionTerminate,
                Data::ErrorCode(Code::FailedOther),
                AuthFailureReason::LogonFailedOther,
            ),
            (
                Type::NoPermission,
                Data::SessionId(7),
                AuthFailureReason::NoPermission,
            ),
            (
                Type::AccessDenied,
                Data::SessionId(7),
                AuthFailureReason::AccessDenied,
            ),
        ] {
            let case = format!("{error_type:?}/{error_data:?}");
            let frame = logon_errors_frame(error_type, error_data);
            assert_eq!(
                logon_outcome(IO_CHANNEL, Action::X224, &frame),
                Some(LogonOutcome::Failed(reason)),
                "{case}"
            );
        }
    }

    #[test]
    fn non_failure_logon_errors_are_ignored() {
        use LogonErrorNotificationData as Data;
        use LogonErrorNotificationDataErrorCode as Code;
        use LogonErrorNotificationType as Type;
        for (error_type, error_data) in [
            // SESSION_CONTINUE is informational; a broker farm sends it with FAILED_OTHER.
            (Type::SessionContinue, Data::ErrorCode(Code::FailedOther)),
            (
                Type::SessionContinue,
                Data::ErrorCode(Code::FailedBadPassword),
            ),
            (
                Type::SessionContinue,
                Data::ErrorCode(Code::FailedUpdatePassword),
            ),
            (Type::SessionContinue, Data::ErrorCode(Code::Warning)),
            (Type::SessionContinue, Data::SessionId(7)),
            (Type::SessionTerminate, Data::ErrorCode(Code::Warning)),
            // Session-choice dialogs carry a session ID; ID 0..2 decodes like a failure code.
            (Type::ReconnectOptions, Data::ErrorCode(Code::FailedOther)),
            (Type::BumpOptions, Data::ErrorCode(Code::FailedBadPassword)),
            (
                Type::SessionBusyOptions,
                Data::ErrorCode(Code::FailedUpdatePassword),
            ),
            (Type::DisconnectRefused, Data::SessionId(7)),
        ] {
            let case = format!("{error_type:?}/{error_data:?}");
            let frame = logon_errors_frame(error_type, error_data);
            assert_eq!(
                logon_outcome(IO_CHANNEL, Action::X224, &frame),
                None,
                "{case}"
            );
        }
    }

    #[test]
    fn logon_notification_is_a_success() {
        let frame =
            save_session_info_frame(IO_CHANNEL, InfoType::PlainNotify, InfoData::PlainNotify);
        assert_eq!(
            logon_outcome(IO_CHANNEL, Action::X224, &frame),
            Some(LogonOutcome::Succeeded)
        );
    }

    #[test]
    fn extended_info_without_errors_is_not_an_outcome() {
        let frame = save_session_info_frame(
            IO_CHANNEL,
            InfoType::LogonExtended,
            InfoData::LogonExtended(LogonInfoExtended {
                present_fields_flags: LogonExFlags::empty(),
                auto_reconnect: None,
                errors_info: None,
            }),
        );
        assert_eq!(logon_outcome(IO_CHANNEL, Action::X224, &frame), None);
    }

    #[test]
    fn frames_off_the_io_channel_or_fast_path_are_ignored() {
        let frame = logon_errors_frame(
            LogonErrorNotificationType::SessionTerminate,
            LogonErrorNotificationData::ErrorCode(
                LogonErrorNotificationDataErrorCode::FailedBadPassword,
            ),
        );
        assert_eq!(logon_outcome(IO_CHANNEL + 1, Action::X224, &frame), None);
        assert_eq!(logon_outcome(IO_CHANNEL, Action::FastPath, &frame), None);
        assert_eq!(
            logon_outcome(IO_CHANNEL, Action::X224, &frame[..frame.len() - 4]),
            None
        );
    }

    fn bad_password_frame() -> Vec<u8> {
        logon_errors_frame(
            LogonErrorNotificationType::SessionTerminate,
            LogonErrorNotificationData::ErrorCode(
                LogonErrorNotificationDataErrorCode::FailedBadPassword,
            ),
        )
    }

    #[test]
    fn watch_reports_a_successful_login_and_keeps_the_session() {
        let (tx, mut rx) = oneshot::channel();
        let mut watch = LogonWatch::new(IO_CHANNEL, Some(tx));
        let frame =
            save_session_info_frame(IO_CHANNEL, InfoType::PlainNotify, InfoData::PlainNotify);
        assert_eq!(watch.observe(Action::X224, &frame), None);
        assert_eq!(
            rx.try_recv(),
            Ok(LogonReport::Outcome(LogonOutcome::Succeeded))
        );
        // The result is handed over once; a later drop is the daemon's to hear about, even
        // when the server sends a second logon notification.
        assert_eq!(watch.observe(Action::X224, &frame), None);
        assert!(!watch.finish(LogonReport::SessionEnded));
    }

    #[test]
    fn watch_hands_a_rejected_login_to_the_waiting_connect() {
        let (tx, mut rx) = oneshot::channel();
        let mut watch = LogonWatch::new(IO_CHANNEL, Some(tx));
        let reason = watch.observe(Action::X224, &bad_password_frame());
        assert_eq!(reason, Some(AuthFailureReason::LogonFailedBadPassword));
        assert!(watch.finish(LogonReport::Outcome(LogonOutcome::Failed(
            AuthFailureReason::LogonFailedBadPassword
        ))));
        assert_eq!(
            rx.try_recv(),
            Ok(LogonReport::Outcome(LogonOutcome::Failed(
                AuthFailureReason::LogonFailedBadPassword
            )))
        );
    }

    #[test]
    fn watch_hands_an_early_session_end_to_the_waiting_connect() {
        let (tx, mut rx) = oneshot::channel();
        let watch = LogonWatch::new(IO_CHANNEL, Some(tx));
        assert!(watch.finish(LogonReport::SessionEnded));
        assert_eq!(rx.try_recv(), Ok(LogonReport::SessionEnded));
    }

    #[test]
    fn watch_without_a_waiting_connect_leaves_the_end_to_the_daemon() {
        // NLA on: nobody waits.
        let mut watch = LogonWatch::new(IO_CHANNEL, None);
        assert_eq!(
            watch.observe(Action::X224, &bad_password_frame()),
            Some(AuthFailureReason::LogonFailedBadPassword)
        );
        assert!(!watch.finish(LogonReport::SessionEnded));
    }

    #[test]
    fn an_end_after_connect_gave_up_is_not_a_drop() {
        // connect() stopped waiting and is failing the login, so a session end or rejection that
        // loses the race against its shutdown must not stop the daemon.
        let (tx, rx) = oneshot::channel();
        drop(rx);
        let watch = LogonWatch::new(IO_CHANNEL, Some(tx));
        assert!(watch.finish(LogonReport::SessionEnded));

        let (tx, mut rx) = oneshot::channel();
        assert_eq!(settle_after_deadline(&mut rx), None);
        let mut watch = LogonWatch::new(IO_CHANNEL, Some(tx));
        assert!(watch.observe(Action::X224, &bad_password_frame()).is_some());
        assert!(watch.finish(LogonReport::Outcome(LogonOutcome::Failed(
            AuthFailureReason::LogonFailedBadPassword
        ))));

        // A confirmation that arrives after connect() gave up confirms nothing.
        let (tx, mut rx) = oneshot::channel();
        assert_eq!(settle_after_deadline(&mut rx), None);
        let mut watch = LogonWatch::new(IO_CHANNEL, Some(tx));
        let frame =
            save_session_info_frame(IO_CHANNEL, InfoType::PlainNotify, InfoData::PlainNotify);
        assert_eq!(watch.observe(Action::X224, &frame), None);
        assert!(watch.finish(LogonReport::SessionEnded));
    }

    #[tokio::test]
    async fn connect_receives_the_report() {
        let (tx, rx) = oneshot::channel();
        tx.send(LogonReport::Outcome(LogonOutcome::Failed(
            AuthFailureReason::LogonFailedOther,
        )))
        .unwrap();
        assert_eq!(
            await_logon_report(rx, Duration::from_secs(5)).await,
            Some(LogonReport::Outcome(LogonOutcome::Failed(
                AuthFailureReason::LogonFailedOther
            )))
        );
    }

    #[tokio::test]
    async fn a_vanished_frame_processor_reads_as_a_session_end() {
        let (tx, rx) = oneshot::channel::<LogonReport>();
        drop(tx);
        assert_eq!(
            await_logon_report(rx, Duration::from_secs(5)).await,
            Some(LogonReport::SessionEnded)
        );
    }

    #[tokio::test]
    async fn a_silent_server_sends_no_report() {
        let (tx, rx) = oneshot::channel::<LogonReport>();
        assert_eq!(
            await_logon_report(rx, Duration::from_millis(20)).await,
            None
        );
        // The frame processor learns that connect() moved on.
        assert!(tx.is_closed());
    }

    #[test]
    fn a_report_racing_the_deadline_is_received_or_refused() {
        let (tx, mut rx) = oneshot::channel();
        tx.send(LogonReport::SessionEnded).unwrap();
        assert_eq!(
            settle_after_deadline(&mut rx),
            Some(LogonReport::SessionEnded)
        );

        let (tx, mut rx) = oneshot::channel();
        assert_eq!(settle_after_deadline(&mut rx), None);
        // rx is still alive, yet the late report is refused.
        assert!(tx.send(LogonReport::SessionEnded).is_err());
    }
}
