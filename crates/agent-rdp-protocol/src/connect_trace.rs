//! The phases of a connect, reported with its result so a caller can tell where a connect failed.
//!
//! A phase carries timing and an allowlisted detail only: never a username, password, alternate
//! shell or screen content.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::ErrorCode;

/// One phase of a connect, in the order it ran. A failed connect ends with its failed phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/agent-rdp/src/generated/")]
pub struct ConnectPhase {
    pub phase: ConnectPhaseName,
    /// When the phase started, in milliseconds since the Unix epoch.
    #[ts(type = "number")]
    pub started_at_ms: u64,
    /// How long the phase took, in milliseconds.
    pub ms: u32,
    pub outcome: PhaseOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub detail: Option<ConnectPhaseDetail>,
}

/// The phases of a connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/agent-rdp/src/generated/")]
#[serde(rename_all = "snake_case")]
pub enum ConnectPhaseName {
    /// Resolving the host name.
    Dns,
    /// Opening the TCP connection.
    Tcp,
    /// The X.224 exchange in which the server selects the security protocol.
    RdpNegotiate,
    /// The TLS handshake.
    Tls,
    /// The rest of the connection sequence, including CredSSP when the server selected NLA.
    RdpConnect,
    /// NLA off: waiting for the server to confirm the login.
    Logon,
}

/// How a phase ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/agent-rdp/src/generated/")]
#[serde(rename_all = "snake_case")]
pub enum PhaseOutcome {
    Ok,
    Failed,
    TimedOut,
}

/// The security protocol the server selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/agent-rdp/src/generated/")]
#[serde(rename_all = "snake_case")]
pub enum SelectedProtocol {
    Rdp,
    Tls,
    Hybrid,
    HybridEx,
    Unknown,
}

/// What a phase reports beyond its timing. Every field is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../../packages/agent-rdp/src/generated/")]
pub struct ConnectPhaseDetail {
    /// `dns`: the resolved addresses, in the order `tcp` tries them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub addresses: Option<Vec<String>>,
    /// `tcp`: the address connected to, or the last one tried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub port: Option<u16>,
    /// A failed or timed-out phase: the code of the connect's error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub error_code: Option<ErrorCode>,
    /// A timed-out phase: its limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub timeout_ms: Option<u32>,
    /// `rdp_negotiate`: the security protocol the server selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub selected_protocol: Option<SelectedProtocol>,
    /// `tls`: the key of the server's certificate, in `server_cert_pin` form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub spki_pin: Option<String>,
    /// `tls`, when the connect had a `server_cert_pin`: whether the server's key matched it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub cert_pin_matched: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_wire_shape() {
        let phase = ConnectPhase {
            phase: ConnectPhaseName::RdpNegotiate,
            started_at_ms: 1_760_000_000_000,
            ms: 12,
            outcome: PhaseOutcome::TimedOut,
            detail: Some(ConnectPhaseDetail {
                error_code: Some(ErrorCode::ConnectionFailed),
                timeout_ms: Some(10_000),
                selected_protocol: Some(SelectedProtocol::HybridEx),
                ..Default::default()
            }),
        };
        let json = serde_json::to_value(&phase).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "phase": "rdp_negotiate",
                "started_at_ms": 1_760_000_000_000u64,
                "ms": 12,
                "outcome": "timed_out",
                "detail": {
                    "error_code": "connection_failed",
                    "timeout_ms": 10_000,
                    "selected_protocol": "hybrid_ex",
                },
            })
        );
        assert_eq!(serde_json::from_value::<ConnectPhase>(json).unwrap(), phase);
    }

    #[test]
    fn a_phase_without_detail_omits_it() {
        let json = serde_json::to_value(ConnectPhase {
            phase: ConnectPhaseName::Logon,
            started_at_ms: 0,
            ms: 0,
            outcome: PhaseOutcome::Ok,
            detail: None,
        })
        .unwrap();
        assert!(json.get("detail").is_none());
    }
}
