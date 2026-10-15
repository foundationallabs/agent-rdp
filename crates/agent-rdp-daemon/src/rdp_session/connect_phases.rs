//! The phases of a connect: their timeouts, the steps before RDP itself, and the record of each
//! phase that the connect response carries.

use std::future::Future;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_rdp_protocol::{
    ConnectPhase, ConnectPhaseDetail, ConnectPhaseName, PhaseOutcome, SelectedProtocol,
};
use ironrdp::connector::{ClientConnector, ClientConnectorState};
use ironrdp::pdu::nego::SecurityProtocol;
use tokio::net::TcpStream;
use tokio::time::Instant;

use super::RdpError;

/// How long each phase before the credentials may take. Past it, the connect fails as
/// `connection_failed`, which the session manager retries without counting a login: the server
/// has not seen the credentials yet.
#[derive(Clone, Copy, Debug)]
pub(super) struct PhaseTimeouts {
    pub dns: Duration,
    pub tcp: Duration,
    pub negotiate: Duration,
    pub tls: Duration,
}

pub(super) const PHASE_TIMEOUTS: PhaseTimeouts = PhaseTimeouts {
    dns: Duration::from_secs(5),
    tcp: Duration::from_secs(10),
    negotiate: Duration::from_secs(10),
    tls: Duration::from_secs(10),
};

/// The phases of one connect, in the order they ran.
#[derive(Debug, Default)]
pub struct ConnectTrace {
    phases: Vec<ConnectPhase>,
}

/// When a phase started.
pub(super) struct PhaseStart {
    at: Instant,
    wall: SystemTime,
}

impl PhaseStart {
    pub(super) fn now() -> Self {
        Self {
            at: Instant::now(),
            wall: SystemTime::now(),
        }
    }
}

impl ConnectTrace {
    pub fn into_phases(self) -> Vec<ConnectPhase> {
        self.phases
    }

    /// Runs one phase and records it. Past `timeout`, the phase times out as a connection failure.
    pub(super) async fn run<T>(
        &mut self,
        phase: ConnectPhaseName,
        timeout: Option<Duration>,
        work: impl Future<Output = Result<T, RdpError>>,
    ) -> Result<T, RdpError> {
        let start = PhaseStart::now();
        let (result, timed_out_after) = match timeout {
            None => (work.await, None),
            Some(limit) => match tokio::time::timeout(limit, work).await {
                Ok(result) => (result, None),
                Err(_) => (
                    Err(RdpError::ConnectionFailed(format!(
                        "{} timed out after {limit:?}",
                        label(phase)
                    ))),
                    Some(limit),
                ),
            },
        };
        self.finish(phase, start, &result, timed_out_after);
        result
    }

    /// Records a phase that ended with `result`; `timed_out_after` marks a failure as a timeout.
    pub(super) fn finish<T>(
        &mut self,
        phase: ConnectPhaseName,
        start: PhaseStart,
        result: &Result<T, RdpError>,
        timed_out_after: Option<Duration>,
    ) {
        let (outcome, detail) = match result {
            Ok(_) => (PhaseOutcome::Ok, None),
            Err(error) => (
                if timed_out_after.is_some() {
                    PhaseOutcome::TimedOut
                } else {
                    PhaseOutcome::Failed
                },
                Some(ConnectPhaseDetail {
                    error_code: Some(error.connect_error_code()),
                    timeout_ms: timed_out_after.map(millis),
                    ..Default::default()
                }),
            ),
        };
        let started_at_ms = start.wall.duration_since(UNIX_EPOCH).map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        });
        self.phases.push(ConnectPhase {
            phase,
            started_at_ms,
            ms: millis(start.at.elapsed()),
            outcome,
            detail,
        });
    }

    /// The detail of the last phase recorded, to add what only the caller knows.
    pub(super) fn detail(&mut self) -> &mut ConnectPhaseDetail {
        self.phases
            .last_mut()
            .expect("a phase was recorded")
            .detail
            .get_or_insert_with(Default::default)
    }
}

fn label(phase: ConnectPhaseName) -> &'static str {
    match phase {
        ConnectPhaseName::Dns => "DNS lookup",
        ConnectPhaseName::Tcp => "TCP connect",
        ConnectPhaseName::RdpNegotiate => "RDP negotiation",
        ConnectPhaseName::Tls => "TLS handshake",
        ConnectPhaseName::RdpConnect => "RDP connection sequence",
        ConnectPhaseName::Logon => "Login confirmation",
    }
}

fn millis(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis()).unwrap_or(u32::MAX)
}

/// Resolves `host` to the addresses to try, in order.
pub(super) async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, RdpError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| RdpError::ConnectionFailed(format!("Could not resolve {host}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(RdpError::ConnectionFailed(format!(
            "{host} resolved to no address"
        )));
    }
    Ok(addrs)
}

/// Connects to the first of `addrs` that accepts, trying them in order as `TcpStream::connect`
/// does. Leaves `tried` at the last address it tried.
pub(super) async fn connect_tcp(
    addrs: &[SocketAddr],
    tried: &mut Option<SocketAddr>,
) -> Result<TcpStream, RdpError> {
    let mut last_error = None;
    for addr in addrs {
        *tried = Some(*addr);
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.map_or_else(
        || RdpError::ConnectionFailed("No address to connect to".to_string()),
        RdpError::Io,
    ))
}

/// The security protocol the server selected, once the negotiation finished.
pub(super) fn selected_protocol(connector: &ClientConnector) -> SelectedProtocol {
    let ClientConnectorState::EnhancedSecurityUpgrade { selected_protocol } = connector.state
    else {
        return SelectedProtocol::Unknown;
    };
    if selected_protocol.contains(SecurityProtocol::HYBRID_EX) {
        SelectedProtocol::HybridEx
    } else if selected_protocol.contains(SecurityProtocol::HYBRID) {
        SelectedProtocol::Hybrid
    } else if selected_protocol.contains(SecurityProtocol::SSL) {
        SelectedProtocol::Tls
    } else if selected_protocol.is_empty() {
        SelectedProtocol::Rdp
    } else {
        SelectedProtocol::Unknown
    }
}

#[cfg(test)]
mod tests {
    use agent_rdp_protocol::ErrorCode;

    use super::*;

    #[tokio::test]
    async fn a_phase_past_its_timeout_is_a_timed_out_connection_failure() {
        let mut trace = ConnectTrace::default();
        let result = trace
            .run(
                ConnectPhaseName::Tcp,
                Some(Duration::from_millis(50)),
                std::future::pending::<Result<(), RdpError>>(),
            )
            .await;

        let error = result.unwrap_err();
        assert_eq!(error.connect_error_code(), ErrorCode::ConnectionFailed);
        assert_eq!(
            error.to_string(),
            "Connection failed: TCP connect timed out after 50ms"
        );
        let [phase] = trace.into_phases().try_into().unwrap();
        assert_eq!(phase.phase, ConnectPhaseName::Tcp);
        assert_eq!(phase.outcome, PhaseOutcome::TimedOut);
        assert!(phase.ms >= 50, "took {} ms", phase.ms);
        let detail = phase.detail.unwrap();
        assert_eq!(detail.error_code, Some(ErrorCode::ConnectionFailed));
        assert_eq!(detail.timeout_ms, Some(50));
    }

    #[tokio::test]
    async fn a_failed_phase_carries_the_connect_error_code() {
        let mut trace = ConnectTrace::default();
        let result = trace
            .run(ConnectPhaseName::Tls, Some(PHASE_TIMEOUTS.tls), async {
                Err::<(), _>(RdpError::CertificateMismatch("key".to_string()))
            })
            .await;

        assert!(result.is_err());
        let [phase] = trace.into_phases().try_into().unwrap();
        assert_eq!(phase.outcome, PhaseOutcome::Failed);
        let detail = phase.detail.unwrap();
        assert_eq!(detail.error_code, Some(ErrorCode::CertificateMismatch));
        assert_eq!(detail.timeout_ms, None);
    }

    #[tokio::test]
    async fn a_phase_that_succeeds_has_no_detail_until_the_caller_adds_one() {
        let mut trace = ConnectTrace::default();
        let addrs = trace
            .run(ConnectPhaseName::Dns, None, resolve("127.0.0.1", 3389))
            .await
            .unwrap();
        assert_eq!(trace.phases[0].detail, None);
        trace.detail().addresses = Some(addrs.iter().map(|a| a.ip().to_string()).collect());

        let [phase] = trace.into_phases().try_into().unwrap();
        assert_eq!(phase.outcome, PhaseOutcome::Ok);
        assert_eq!(
            phase.detail.unwrap().addresses,
            Some(vec!["127.0.0.1".to_string()])
        );
    }

    #[tokio::test]
    async fn a_refused_tcp_connect_reports_the_address_it_tried() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let mut tried = None;
        let error = connect_tcp(&[addr], &mut tried).await.unwrap_err();
        assert!(matches!(error, RdpError::Io(_)), "{error}");
        assert_eq!(error.connect_error_code(), ErrorCode::ConnectionFailed);
        assert_eq!(tried, Some(addr));
    }
}
