//! A loopback RDP server that takes a TLS-only (NLA-off) connect to a chosen point and then ends
//! the connection, to test how `RdpSession::connect` classifies each end.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ironrdp::pdu::gcc::{
    ClientGccBlocks, ConferenceCreateResponse, ServerCoreData, ServerCoreOptionalData,
    ServerEarlyCapabilityFlags, ServerGccBlocks, ServerNetworkData, ServerSecurityData,
};
use ironrdp::pdu::input::fast_path::{FastPathInput, FastPathInputEvent, KeyboardFlags};
use ironrdp::pdu::mcs::{
    AttachUserConfirm, ConnectInitial, ConnectResponse, DomainParameters, SendDataIndication,
    SendDataRequest,
};
use ironrdp::pdu::nego::{ConnectionConfirm, ResponseFlags, SecurityProtocol};
use ironrdp::pdu::rdp::capability_sets::{DemandActive, ServerDemandActive};
use ironrdp::pdu::rdp::client_info::CompressionType;
use ironrdp::pdu::rdp::finalization_messages::FontPdu;
use ironrdp::pdu::rdp::headers::{
    CompressionFlags, ShareControlHeader, ShareControlPdu, ShareDataHeader, ShareDataPdu,
    StreamPriority,
};
use ironrdp::pdu::rdp::server_license::{LicensePdu, LicensingErrorMessage};
use ironrdp::pdu::rdp::session_info::{
    InfoData, InfoType, LogonErrorNotificationData, LogonErrorNotificationDataErrorCode,
    LogonErrorNotificationType, LogonErrorsInfo, LogonExFlags, LogonInfo, LogonInfoExtended,
    LogonInfoVersion2, SaveSessionInfoPdu,
};
use ironrdp::pdu::rdp::ClientInfoPdu;
use ironrdp::pdu::x224::{X224Data, X224};
use ironrdp::pdu::{encode_vec, gcc, Encode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;

use super::tests::test_config;
use super::{
    key_to_scancode, ConnectTiming, ConnectTrace, PhaseTimeouts, RdpConfig, RdpError, RdpSession,
    CONNECT_TIMING, LOGON_OUTCOME_WINDOW,
};
use crate::tls::CertPin;
use agent_rdp_protocol::{
    AuthFailureReason, ConnectPhase, ConnectPhaseName, CredentialBoundary, ErrorCode, PhaseOutcome,
    SelectedProtocol,
};

const CERT: &[u8] = include_bytes!("../../testdata/tls/server-a.crt.der");
const KEY: &[u8] = include_bytes!("../../testdata/tls/server-a.key.der");
const SERVER_CHANNEL: u16 = 1002;
const IO_CHANNEL: u16 = 1003;
const USER_CHANNEL: u16 = 1007;
const SHARE_ID: u32 = 0x0001_03ea;

/// Where the server stops following the connection sequence.
#[derive(Clone, Copy, Debug)]
enum Stop {
    /// After the Attach User Request, before the client can send the Client Info PDU.
    BeforeClientInfo,
    /// After the Attach User Request, the server goes silent until the client closes.
    StallBeforeClientInfo,
    /// After the Attach User Confirm: the server reads whatever arrives until the client closes.
    ReadAfterAttach,
    /// Right after the Client Info PDU arrived.
    AfterClientInfo,
    /// Right after the Client Info PDU arrived, the server goes silent until the client closes.
    StallAfterClientInfo,
    /// After the connection sequence finished, inside the logon window.
    AfterConnect,
    /// After the connection sequence finished, the server stays silent until the client closes.
    SilentAfterConnect,
    /// Never: the server confirms the login and keeps the connection open.
    Confirm,
    /// Never: the server holds the login at a pre-logon notice, confirms it once Enter is
    /// pressed, and keeps the connection open.
    ConfirmOnEnter,
}

/// How the server ends the connection at its stop point.
#[derive(Clone, Copy, Debug)]
enum End {
    /// TLS close_notify, then FIN.
    Close,
    /// TCP reset.
    Reset,
}

/// Where the server sends a SESSION_CONTINUE notice for session 2, which IronRDP decodes as
/// LOGON_FAILED_OTHER, as the lab broker farm does on a good logon.
#[derive(Clone, Copy, Debug)]
enum SessionContinue {
    Never,
    /// Inside connection finalization, before the Font Map PDU.
    BeforeFontMap,
    /// After the connection sequence, before the stop point. Where the lab farm sends it.
    AfterFontMap,
}

/// One connect against the mock server.
#[derive(Clone, Debug)]
struct Script {
    stop: Stop,
    end: End,
    /// The client offers NLA; the server still selects TLS-only.
    offer_nla: bool,
    session_continue: SessionContinue,
    /// What a confirming server sends.
    confirmation: InfoData,
    /// How long the server waits before the MCS Connect Response, before any credentials.
    connect_delay: Duration,
    /// How long the server waits after the Client Info PDU before it answers.
    license_delay: Duration,
    alternate_shell: Option<String>,
    /// A shorter NLA-off `rdp_connect` timeout through `connect_within`; `None` runs the production one.
    client_info_timeout: Option<Duration>,
    /// A shorter logon window through `connect_within`; `None` runs the production window.
    logon_window: Option<Duration>,
    /// A shorter notice delay through `connect_within`; `None` runs the production delay.
    notice_delay: Option<Duration>,
    acknowledge_logon_notice: bool,
}

impl Script {
    fn new(stop: Stop, end: End) -> Self {
        Self {
            stop,
            end,
            offer_nla: false,
            session_continue: SessionContinue::Never,
            confirmation: InfoData::PlainNotify,
            connect_delay: Duration::ZERO,
            license_delay: Duration::ZERO,
            alternate_shell: None,
            client_info_timeout: None,
            logon_window: None,
            notice_delay: None,
            acknowledge_logon_notice: false,
        }
    }
}

/// What `connect` returned, how long it took, and whether the server received the credentials.
struct Run {
    result: Result<(), RdpError>,
    elapsed: Duration,
    credentials_received: bool,
    /// From the server receiving the Client Info PDU to `connect` returning.
    since_credentials: Option<Duration>,
    /// The GCC blocks of the client's MCS Connect Initial.
    client_gcc: ClientGccBlocks,
    /// Enter presses the server received after the connection sequence.
    enter_presses: usize,
    /// The phases `connect` recorded.
    phases: Vec<ConnectPhase>,
    credential_boundary: CredentialBoundary,
}

/// What the server saw of one connect.
struct Served {
    client_gcc: ClientGccBlocks,
    /// When the Client Info PDU arrived, if it did.
    credentials_at: Option<Instant>,
    enter_presses: usize,
}

impl Run {
    fn error(&self) -> &RdpError {
        match &self.result {
            Ok(_) => panic!("connect succeeded"),
            Err(error) => error,
        }
    }
}

/// Runs `script`; the server always selects TLS-only.
async fn run(script: Script) -> Run {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn({
        let script = script.clone();
        async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve(stream, script).await
        }
    });

    let mut config = loopback_config(port, script.offer_nla, script.alternate_shell.as_deref());
    config.acknowledge_logon_notice = script.acknowledge_logon_notice;
    let timing = ConnectTiming {
        phases: PhaseTimeouts {
            client_info: script
                .client_info_timeout
                .unwrap_or(CONNECT_TIMING.phases.client_info),
            ..CONNECT_TIMING.phases
        },
        logon_window: script.logon_window.unwrap_or(CONNECT_TIMING.logon_window),
        notice_delay: script.notice_delay.unwrap_or(CONNECT_TIMING.notice_delay),
        ..CONNECT_TIMING
    };
    let started = Instant::now();
    let mut trace = ConnectTrace::default();
    let connect = RdpSession::connect_within(config, None, timing, &mut trace);
    let result = tokio::time::timeout(Duration::from_secs(30), connect)
        .await
        .expect("connect did not finish");
    let ended = Instant::now();
    let (phases, credential_boundary) = trace.into_parts();
    // Dropping the session closes the connection, which a confirming server waits for.
    let result = result.map(drop);
    let Served {
        client_gcc,
        credentials_at,
        enter_presses,
    } = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server did not finish")
        .unwrap();
    Run {
        result,
        elapsed: ended - started,
        credentials_received: credentials_at.is_some(),
        since_credentials: credentials_at.map(|at| ended - at),
        client_gcc,
        enter_presses,
        phases,
        credential_boundary,
    }
}

fn loopback_config(port: u16, offer_nla: bool, alternate_shell: Option<&str>) -> RdpConfig {
    let mut config = test_config(alternate_shell);
    config.host = "127.0.0.1".to_string();
    config.port = port;
    config.enable_credssp = offer_nla;
    config
}

/// Runs the server side of the connection sequence up to `stop`. Returns the client's GCC blocks
/// and when the Client Info PDU arrived, if it did (for `ReadAfterAttach`: when the client closed,
/// if any byte arrived).
async fn serve(mut tcp: TcpStream, script: Script) -> Served {
    let Script { stop, end, .. } = script;
    read_frame(&mut tcp).await; // X.224 Connection Request
    write_frame(
        &mut tcp,
        &X224(ConnectionConfirm::Response {
            flags: ResponseFlags::empty(),
            protocol: SecurityProtocol::SSL,
        }),
    )
    .await;
    let mut tls = tls_acceptor().accept(tcp).await.unwrap();

    let frame = read_frame(&mut tls).await;
    let data = ironrdp::pdu::decode::<X224<X224Data<'_>>>(&frame).unwrap();
    let connect_initial = ironrdp::pdu::decode::<ConnectInitial>(&data.0.data).unwrap();
    let client_gcc = connect_initial.conference_create_request.into_gcc_blocks();
    tokio::time::sleep(script.connect_delay).await;
    write_frame(
        &mut tls,
        &X224(X224Data {
            data: Cow::Owned(encode_vec(&connect_response()).unwrap()),
        }),
    )
    .await;
    read_frame(&mut tls).await; // Erect Domain Request
    read_frame(&mut tls).await; // Attach User Request
    if let Stop::BeforeClientInfo | Stop::StallBeforeClientInfo = stop {
        match stop {
            Stop::BeforeClientInfo => finish(tls, end).await,
            _ => drop(read_until_closed(&mut tls).await),
        }
        return Served {
            client_gcc,
            credentials_at: None,
            enter_presses: 0,
        };
    }

    write_frame(
        &mut tls,
        &X224(AttachUserConfirm {
            result: 0,
            initiator_id: USER_CHANNEL,
        }),
    )
    .await;
    if let Stop::ReadAfterAttach = stop {
        let received = read_until_closed(&mut tls).await;
        return Served {
            client_gcc,
            credentials_at: (!received.is_empty()).then(Instant::now),
            enter_presses: 0,
        };
    }
    let frame = read_frame(&mut tls).await;
    let request = ironrdp::pdu::decode::<X224<SendDataRequest<'_>>>(&frame).unwrap();
    let client_info = ironrdp::pdu::decode::<ClientInfoPdu>(&request.0.user_data).unwrap();
    assert_eq!(client_info.client_info.credentials.username, "user");
    let credentials_at = Some(Instant::now());
    match stop {
        Stop::AfterClientInfo => {
            finish(tls, end).await;
            return Served {
                client_gcc,
                credentials_at,
                enter_presses: 0,
            };
        }
        Stop::StallAfterClientInfo => {
            read_until_closed(&mut tls).await;
            return Served {
                client_gcc,
                credentials_at,
                enter_presses: 0,
            };
        }
        _ => {}
    }

    tokio::time::sleep(script.license_delay).await;
    let license = LicensePdu::from(LicensingErrorMessage::new_valid_client().unwrap());
    write_frame(&mut tls, &indication(encode_vec(&license).unwrap())).await;
    write_frame(
        &mut tls,
        &share_control(ShareControlPdu::ServerDemandActive(ServerDemandActive {
            pdu: DemandActive {
                source_descriptor: "RDP".to_string(),
                capability_sets: Vec::new(),
            },
        })),
    )
    .await;
    // Confirm Active, Synchronize, Control Cooperate, Request Control, Font List.
    for _ in 0..5 {
        read_frame(&mut tls).await;
    }
    if let SessionContinue::BeforeFontMap = script.session_continue {
        write_frame(&mut tls, &session_info(session_continue())).await;
    }
    write_frame(
        &mut tls,
        &share_data(ShareDataPdu::FontMap(FontPdu::default())),
    )
    .await;

    if let SessionContinue::AfterFontMap = script.session_continue {
        write_frame(&mut tls, &session_info(session_continue())).await;
    }
    let enter_presses = match stop {
        Stop::AfterConnect => {
            finish(tls, end).await;
            0
        }
        Stop::SilentAfterConnect => count_enter_until_closed(&mut tls).await,
        Stop::Confirm => {
            write_frame(&mut tls, &session_info(script.confirmation)).await;
            count_enter_until_closed(&mut tls).await
        }
        Stop::ConfirmOnEnter => {
            let mut presses = 0;
            while let Some(pdu) = read_pdu(&mut tls).await {
                presses += enter_presses(&pdu);
                if presses > 0 {
                    write_frame(&mut tls, &session_info(script.confirmation)).await;
                    break;
                }
            }
            presses + count_enter_until_closed(&mut tls).await
        }
        Stop::BeforeClientInfo
        | Stop::StallBeforeClientInfo
        | Stop::ReadAfterAttach
        | Stop::AfterClientInfo
        | Stop::StallAfterClientInfo => unreachable!(),
    };
    Served {
        client_gcc,
        credentials_at,
        enter_presses,
    }
}

fn session_continue() -> InfoData {
    logon_error(
        LogonErrorNotificationType::SessionContinue,
        LogonErrorNotificationDataErrorCode::FailedOther,
    )
}

fn logon_error(
    error_type: LogonErrorNotificationType,
    code: LogonErrorNotificationDataErrorCode,
) -> InfoData {
    InfoData::LogonExtended(LogonInfoExtended {
        present_fields_flags: LogonExFlags::LOGON_ERRORS,
        auto_reconnect: None,
        errors_info: Some(LogonErrorsInfo {
            error_type,
            error_data: LogonErrorNotificationData::ErrorCode(code),
        }),
    })
}

fn session_info(info_data: InfoData) -> X224<SendDataIndication<'static>> {
    let info_type = match info_data {
        InfoData::LogonInfoV1(_) => InfoType::Logon,
        InfoData::LogonInfoV2(_) => InfoType::LogonLong,
        InfoData::PlainNotify => InfoType::PlainNotify,
        InfoData::LogonExtended(_) => InfoType::LogonExtended,
    };
    share_data(ShareDataPdu::SaveSessionInfo(SaveSessionInfoPdu {
        info_type,
        info_data,
    }))
}

/// Reads until the client closes the connection, cleanly or not. Returns what arrived.
async fn read_until_closed(tls: &mut TlsStream<TcpStream>) -> Vec<u8> {
    let mut received = Vec::new();
    let _ = tls.read_to_end(&mut received).await;
    received
}

/// Reads PDUs until the client closes the connection. Returns the Enter presses among them.
async fn count_enter_until_closed(tls: &mut TlsStream<TcpStream>) -> usize {
    let mut presses = 0;
    while let Some(pdu) = read_pdu(tls).await {
        presses += enter_presses(&pdu);
    }
    presses
}

/// Reads one client PDU, TPKT or fast-path. `None` once the client closed, cleanly or not.
async fn read_pdu(stream: &mut (impl AsyncRead + Unpin)) -> Option<Vec<u8>> {
    let mut pdu = vec![0u8; 2];
    stream.read_exact(&mut pdu).await.ok()?;
    let length = if pdu[0] == 3 {
        pdu.resize(4, 0);
        stream.read_exact(&mut pdu[2..]).await.ok()?;
        usize::from(u16::from_be_bytes([pdu[2], pdu[3]]))
    } else if pdu[1] & 0x80 != 0 {
        pdu.push(0);
        stream.read_exact(&mut pdu[2..]).await.ok()?;
        usize::from(u16::from_be_bytes([pdu[1] & 0x7f, pdu[2]]))
    } else {
        usize::from(pdu[1])
    };
    let read = pdu.len();
    pdu.resize(length, 0);
    stream.read_exact(&mut pdu[read..]).await.ok()?;
    Some(pdu)
}

/// Enter key-downs in a fast-path input PDU. Other PDUs have none.
fn enter_presses(pdu: &[u8]) -> usize {
    if pdu[0] == 3 {
        return 0;
    }
    let (enter, _) = key_to_scancode("enter").unwrap();
    let input = ironrdp::pdu::decode::<FastPathInput>(pdu).unwrap();
    input
        .input_events()
        .iter()
        .filter(|event| {
            matches!(event, FastPathInputEvent::KeyboardEvent(flags, code)
                if *code == enter && !flags.contains(KeyboardFlags::RELEASE))
        })
        .count()
}

fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(CERT.to_vec())],
        PrivateKeyDer::Pkcs8(KEY.to_vec().into()),
    )
    .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

fn connect_response() -> ConnectResponse {
    let blocks = ServerGccBlocks {
        core: ServerCoreData {
            version: gcc::RdpVersion::V5_PLUS,
            optional_data: ServerCoreOptionalData {
                client_requested_protocols: Some(SecurityProtocol::SSL),
                early_capability_flags: Some(
                    ServerEarlyCapabilityFlags::SKIP_CHANNELJOIN_SUPPORTED,
                ),
            },
        },
        network: ServerNetworkData {
            channel_ids: Vec::new(),
            io_channel: IO_CHANNEL,
        },
        security: ServerSecurityData::no_security(),
        message_channel: None,
        multi_transport_channel: None,
    };
    ConnectResponse {
        conference_create_response: ConferenceCreateResponse::new(USER_CHANNEL, blocks).unwrap(),
        called_connect_id: 0,
        domain_parameters: DomainParameters::target(),
    }
}

fn indication(user_data: Vec<u8>) -> X224<SendDataIndication<'static>> {
    X224(SendDataIndication {
        initiator_id: SERVER_CHANNEL,
        channel_id: IO_CHANNEL,
        user_data: Cow::Owned(user_data),
    })
}

fn share_control(pdu: ShareControlPdu) -> X224<SendDataIndication<'static>> {
    indication(
        encode_vec(&ShareControlHeader {
            share_control_pdu: pdu,
            pdu_source: SERVER_CHANNEL,
            share_id: SHARE_ID,
        })
        .unwrap(),
    )
}

fn share_data(pdu: ShareDataPdu) -> X224<SendDataIndication<'static>> {
    share_control(ShareControlPdu::Data(ShareDataHeader {
        share_data_pdu: pdu,
        stream_priority: StreamPriority::Medium,
        compression_flags: CompressionFlags::empty(),
        compression_type: CompressionType::K8,
    }))
}

/// Reads one TPKT frame.
async fn read_frame(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut frame = vec![0u8; 4];
    stream.read_exact(&mut frame).await.unwrap();
    assert_eq!(frame[0], 3, "expected a TPKT frame");
    let length = usize::from(u16::from_be_bytes([frame[2], frame[3]]));
    frame.resize(length, 0);
    stream.read_exact(&mut frame[4..]).await.unwrap();
    frame
}

async fn write_frame(stream: &mut (impl AsyncWrite + Unpin), pdu: &impl Encode) {
    stream.write_all(&encode_vec(pdu).unwrap()).await.unwrap();
    stream.flush().await.unwrap();
}

async fn finish(mut tls: TlsStream<TcpStream>, end: End) {
    match end {
        End::Close => {
            let _ = tls.shutdown().await;
        }
        End::Reset => {
            let (tcp, _) = tls.into_inner();
            // `set_linger` is deprecated because it can block a drop; a zero linger cannot.
            #[allow(deprecated)]
            tcp.set_linger(Some(Duration::ZERO)).unwrap();
        }
    }
}

fn assert_unconfirmed(run: &Run) {
    assert!(
        matches!(
            run.error(),
            RdpError::AuthenticationFailed(AuthFailureReason::LogonUnconfirmed)
        ),
        "got {:?}",
        run.error()
    );
}

#[tokio::test]
async fn a_close_before_the_credentials_is_a_connection_failure() {
    for end in [End::Close, End::Reset] {
        let run = run(Script::new(Stop::BeforeClientInfo, end)).await;
        assert!(!run.credentials_received);
        assert_eq!(run.credential_boundary, CredentialBoundary::None);
        assert!(
            matches!(run.error(), RdpError::ConnectionFailed(_)),
            "{end:?}: got {:?}",
            run.error()
        );
    }
}

#[tokio::test]
async fn a_client_info_that_never_left_is_a_connection_failure() {
    // Too long to encode, so the Client Info step fails before writing anything.
    let run = run(Script {
        alternate_shell: Some("x".repeat(40_000)),
        ..Script::new(Stop::ReadAfterAttach, End::Close)
    })
    .await;
    assert!(!run.credentials_received);
    assert!(
        matches!(run.error(), RdpError::ConnectionFailed(_)),
        "got {:?}",
        run.error()
    );
}

#[tokio::test]
async fn a_close_right_after_the_credentials_is_an_unconfirmed_login() {
    for end in [End::Close, End::Reset] {
        let run = run(Script::new(Stop::AfterClientInfo, end)).await;
        assert!(run.credentials_received);
        assert_unconfirmed(&run);
        assert_eq!(run.credential_boundary, CredentialBoundary::Logon);
        let last = run.phases.last().unwrap();
        assert_eq!(
            (last.phase, last.outcome),
            (ConnectPhaseName::Logon, PhaseOutcome::Failed)
        );
    }
}

#[tokio::test]
async fn the_server_selection_decides_not_the_client_offer() {
    // The client offers NLA and the server picks TLS-only, so the credentials go in Client Info.
    let run = run(Script {
        offer_nla: true,
        ..Script::new(Stop::AfterClientInfo, End::Close)
    })
    .await;
    assert!(run.credentials_received);
    assert_unconfirmed(&run);
}

#[tokio::test]
async fn a_stall_after_the_credentials_is_an_unconfirmed_login() {
    let logon_window = Duration::from_secs(1);
    let run = run(Script {
        logon_window: Some(logon_window),
        ..Script::new(Stop::StallAfterClientInfo, End::Close)
    })
    .await;
    assert!(run.credentials_received);
    assert_unconfirmed(&run);
    assert!(run.elapsed >= logon_window, "took {:?}", run.elapsed);
}

#[tokio::test]
async fn the_logon_window_counts_from_the_credentials_not_the_connect() {
    let logon_window = Duration::from_secs(2);
    let connect_delay = Duration::from_millis(600);
    let license_delay = Duration::from_millis(1200);
    let run = run(Script {
        logon_window: Some(logon_window),
        connect_delay,
        license_delay,
        ..Script::new(Stop::SilentAfterConnect, End::Close)
    })
    .await;
    assert_unconfirmed(&run);
    // A window counted from the connect would end 0.6 s early; one restarted at the end of the
    // connection sequence would run 1.2 s late.
    let since_credentials = run.since_credentials.unwrap();
    assert!(
        since_credentials + Duration::from_millis(100) >= logon_window
            && since_credentials < logon_window + license_delay / 2,
        "ended {since_credentials:?} after the credentials"
    );
    // The phases split at the credentials too: `rdp_connect` holds the delay before them, and
    // `logon` the delay after them and the rest of the window.
    let [.., rdp_connect, logon] = run.phases.as_slice() else {
        panic!("phases {:?}", names(&run.phases));
    };
    assert_eq!(
        (rdp_connect.phase, logon.phase),
        (ConnectPhaseName::RdpConnect, ConnectPhaseName::Logon)
    );
    let ms = |duration: Duration| u32::try_from(duration.as_millis()).unwrap();
    assert!(
        rdp_connect.ms >= ms(connect_delay)
            && rdp_connect.ms < ms(connect_delay + license_delay / 2),
        "rdp_connect took {} ms",
        rdp_connect.ms
    );
    assert!(
        logon.ms + 100 >= ms(logon_window),
        "logon took {} ms",
        logon.ms
    );
    assert!(logon.started_at_ms + 1 >= rdp_connect.started_at_ms + u64::from(rdp_connect.ms));
}

#[tokio::test]
async fn a_close_inside_the_logon_window_is_an_unconfirmed_login() {
    for session_continue in [SessionContinue::Never, SessionContinue::AfterFontMap] {
        for end in [End::Close, End::Reset] {
            let run = run(Script {
                session_continue,
                ..Script::new(Stop::AfterConnect, end)
            })
            .await;
            assert!(run.credentials_received);
            assert_unconfirmed(&run);
            // The end decided the result, not the logon window running out.
            assert!(
                run.elapsed < LOGON_OUTCOME_WINDOW / 2,
                "{session_continue:?} {end:?}: took {:?}",
                run.elapsed
            );
        }
    }
}

#[tokio::test]
async fn session_continue_then_silence_is_an_unconfirmed_login_at_20_s() {
    let run = run(Script {
        session_continue: SessionContinue::AfterFontMap,
        ..Script::new(Stop::SilentAfterConnect, End::Close)
    })
    .await;
    assert_unconfirmed(&run);
    assert!(
        run.elapsed >= Duration::from_secs(20) && run.elapsed < Duration::from_secs(25),
        "took {:?}",
        run.elapsed
    );
}

#[tokio::test]
async fn the_mock_server_completes_a_confirmed_login() {
    let logon_info_v2 = InfoData::LogonInfoV2(LogonInfoVersion2 {
        logon_info: LogonInfo {
            session_id: 2,
            user_name: "user".to_owned(),
            domain_name: "LAB".to_owned(),
        },
    });
    for session_continue in [SessionContinue::Never, SessionContinue::AfterFontMap] {
        for confirmation in [logon_info_v2.clone(), InfoData::PlainNotify] {
            let run = run(Script {
                session_continue,
                confirmation: confirmation.clone(),
                ..Script::new(Stop::Confirm, End::Close)
            })
            .await;
            assert!(
                run.result.is_ok(),
                "{session_continue:?} {confirmation:?}: got {:?}",
                run.result.err()
            );
        }
    }
}

#[tokio::test]
async fn the_client_never_advertises_server_redirection() {
    // A client that sends TS_UD_CS_CLUSTER with REDIRECTION_SUPPORTED gets Server Redirection PDUs
    // from an RD Connection Broker farm (lab control, LAB-REPORT-0.8.0.md). agent-rdp does not
    // follow them, so it must never advertise support. ironrdp-connector 0.9 sends no cluster block
    // (connection.rs TODO #139); this fails if an upgrade starts sending one. The mock always selects
    // TLS-only, so the NLA leg covers the client's offer, not a CredSSP-selected connection.
    for offer_nla in [false, true] {
        let run = run(Script {
            offer_nla,
            ..Script::new(Stop::Confirm, End::Close)
        })
        .await;
        assert!(
            run.result.is_ok(),
            "offer_nla {offer_nla}: {:?}",
            run.result.err()
        );
        assert_eq!(run.client_gcc.cluster, None, "offer_nla {offer_nla}");
    }
}

#[tokio::test]
async fn session_continue_before_the_font_map_is_an_unconfirmed_login() {
    // IronRDP's connection finalization rejects any SaveSessionInfo before the Font Map. The lab farm
    // sends SESSION_CONTINUE after it; this pins what happens if a server ever sends it earlier.
    let run = run(Script {
        session_continue: SessionContinue::BeforeFontMap,
        ..Script::new(Stop::SilentAfterConnect, End::Close)
    })
    .await;
    assert!(run.credentials_received);
    assert_unconfirmed(&run);
    assert!(
        run.elapsed < LOGON_OUTCOME_WINDOW / 2,
        "took {:?}",
        run.elapsed
    );
}

#[tokio::test]
async fn nla_on_still_runs_credssp_first() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        read_frame(&mut tcp).await; // X.224 Connection Request
        write_frame(
            &mut tcp,
            &X224(ConnectionConfirm::Response {
                flags: ResponseFlags::empty(),
                protocol: SecurityProtocol::HYBRID,
            }),
        )
        .await;
        let mut tls = tls_acceptor().accept(tcp).await.unwrap();
        let mut first = [0u8; 1];
        tls.read_exact(&mut first).await.unwrap();
        finish(tls, End::Reset).await;
        first[0]
    });

    let mut trace = ConnectTrace::default();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        RdpSession::connect(loopback_config(port, true, None), None, &mut trace),
    )
    .await
    .expect("connect did not finish");
    // A CredSSP TSRequest is a DER SEQUENCE; an MCS Connect Initial would start a TPKT frame (3).
    assert_eq!(server.await.unwrap(), 0x30);
    // CredSSP runs inside the connection sequence; there is no NLA-off login wait.
    let (phases, credential_boundary) = trace.into_parts();
    assert_eq!(credential_boundary, CredentialBoundary::RdpConnect);
    assert_eq!(
        phases[2].detail.as_ref().unwrap().selected_protocol,
        Some(SelectedProtocol::Hybrid)
    );
    assert_eq!(phases.last().unwrap().phase, ConnectPhaseName::RdpConnect);
    assert!(
        !matches!(
            result,
            Err(RdpError::AuthenticationFailed(
                AuthFailureReason::LogonUnconfirmed
            ))
        ),
        "an NLA-on end is never an unconfirmed login"
    );
}

#[tokio::test]
async fn an_nla_on_stall_fails_the_login_closed() {
    // CredSSP may have sent the credentials before the stall, so the end cannot be retryable.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        read_frame(&mut tcp).await; // X.224 Connection Request
        write_frame(
            &mut tcp,
            &X224(ConnectionConfirm::Response {
                flags: ResponseFlags::empty(),
                protocol: SecurityProtocol::HYBRID,
            }),
        )
        .await;
        let mut tls = tls_acceptor().accept(tcp).await.unwrap();
        read_until_closed(&mut tls).await;
    });

    let logon_window = Duration::from_millis(300);
    let timing = ConnectTiming {
        logon_window,
        ..CONNECT_TIMING
    };
    let mut trace = ConnectTrace::default();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        RdpSession::connect_within(loopback_config(port, true, None), None, timing, &mut trace),
    )
    .await
    .expect("connect did not finish");
    assert!(
        matches!(
            result,
            Err(RdpError::AuthenticationFailed(
                AuthFailureReason::LogonUnconfirmed
            ))
        ),
        "got {:?}",
        result.err()
    );
    let (phases, credential_boundary) = trace.into_parts();
    assert_eq!(credential_boundary, CredentialBoundary::RdpConnect);
    let last = phases.last().unwrap();
    assert_eq!(
        (last.phase, last.outcome),
        (ConnectPhaseName::RdpConnect, PhaseOutcome::TimedOut)
    );
    let detail = last.detail.as_ref().unwrap();
    assert_eq!(detail.error_code, Some(ErrorCode::AuthenticationFailed));
    assert_eq!(detail.timeout_ms, Some(300));
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server did not finish")
        .unwrap();
}

#[tokio::test]
async fn a_pre_logon_notice_is_answered_with_one_enter() {
    let notice_delay = Duration::from_millis(300);
    let run = run(Script {
        acknowledge_logon_notice: true,
        notice_delay: Some(notice_delay),
        logon_window: Some(Duration::from_secs(5)),
        ..Script::new(Stop::ConfirmOnEnter, End::Close)
    })
    .await;
    assert!(run.result.is_ok(), "got {:?}", run.result.err());
    assert_eq!(run.enter_presses, 1);
    assert!(run.elapsed >= notice_delay, "took {:?}", run.elapsed);
}

#[tokio::test]
async fn without_the_option_a_pre_logon_notice_fails_closed_untouched() {
    let run = run(Script {
        logon_window: Some(Duration::from_secs(1)),
        ..Script::new(Stop::ConfirmOnEnter, End::Close)
    })
    .await;
    assert_unconfirmed(&run);
    assert_eq!(run.enter_presses, 0);
}

#[tokio::test]
async fn an_unanswered_notice_gets_one_enter_then_fails_closed() {
    // A second Enter on a sign-in screen could submit an empty password.
    let logon_window = Duration::from_millis(1500);
    let run = run(Script {
        acknowledge_logon_notice: true,
        notice_delay: Some(Duration::from_millis(200)),
        logon_window: Some(logon_window),
        ..Script::new(Stop::SilentAfterConnect, End::Close)
    })
    .await;
    assert_unconfirmed(&run);
    assert_eq!(run.enter_presses, 1);
    // The press does not extend the deadline.
    assert!(
        run.elapsed >= logon_window && run.elapsed < logon_window + Duration::from_millis(500),
        "took {:?}",
        run.elapsed
    );
}

#[tokio::test]
async fn a_login_refused_after_the_enter_keeps_its_reason() {
    let run = run(Script {
        acknowledge_logon_notice: true,
        notice_delay: Some(Duration::from_millis(200)),
        logon_window: Some(Duration::from_secs(5)),
        confirmation: logon_error(
            LogonErrorNotificationType::SessionTerminate,
            LogonErrorNotificationDataErrorCode::FailedBadPassword,
        ),
        ..Script::new(Stop::ConfirmOnEnter, End::Close)
    })
    .await;
    assert!(
        matches!(
            run.error(),
            RdpError::AuthenticationFailed(AuthFailureReason::LogonFailedBadPassword)
        ),
        "got {:?}",
        run.error()
    );
    assert_eq!(run.enter_presses, 1);
}

#[tokio::test]
async fn a_prompt_login_gets_no_enter() {
    let run = run(Script {
        acknowledge_logon_notice: true,
        ..Script::new(Stop::Confirm, End::Close)
    })
    .await;
    assert!(run.result.is_ok(), "got {:?}", run.result.err());
    assert_eq!(run.enter_presses, 0);
}

#[tokio::test]
async fn a_notice_delay_past_the_window_presses_nothing() {
    let run = run(Script {
        acknowledge_logon_notice: true,
        notice_delay: Some(Duration::from_secs(2)),
        logon_window: Some(Duration::from_secs(1)),
        ..Script::new(Stop::SilentAfterConnect, End::Close)
    })
    .await;
    assert_unconfirmed(&run);
    assert_eq!(run.enter_presses, 0);
}

fn names(phases: &[ConnectPhase]) -> Vec<ConnectPhaseName> {
    phases.iter().map(|phase| phase.phase).collect()
}

#[tokio::test]
async fn a_confirmed_login_reports_every_phase_in_order() {
    let run = run(Script::new(Stop::Confirm, End::Close)).await;
    assert!(run.result.is_ok(), "got {:?}", run.result.err());
    assert_eq!(
        names(&run.phases),
        [
            ConnectPhaseName::Dns,
            ConnectPhaseName::Tcp,
            ConnectPhaseName::RdpNegotiate,
            ConnectPhaseName::Tls,
            ConnectPhaseName::RdpConnect,
            ConnectPhaseName::Logon,
        ]
    );
    assert!(run
        .phases
        .iter()
        .all(|phase| phase.outcome == PhaseOutcome::Ok));
    let detail = |i: usize| run.phases[i].detail.clone().unwrap_or_default();
    assert_eq!(detail(0).addresses, Some(vec!["127.0.0.1".to_string()]));
    assert_eq!(detail(1).address.as_deref(), Some("127.0.0.1"));
    assert!(detail(1).port.is_some());
    assert_eq!(detail(2).selected_protocol, Some(SelectedProtocol::Tls));
    let server_pin = CertPin::of_certificate(CERT).unwrap().to_string();
    assert_eq!(detail(3).spki_pin, Some(server_pin));
    assert_eq!(detail(3).cert_pin_matched, None, "no pin was set");
    assert_eq!(run.phases[4].detail, None);
    assert_eq!(run.phases[5].detail, None);
    assert_eq!(run.credential_boundary, CredentialBoundary::Logon);
}

#[tokio::test]
async fn an_unconfirmed_login_ends_with_its_logon_phase() {
    let logon_window = Duration::from_secs(1);
    let silent = run(Script {
        logon_window: Some(logon_window),
        ..Script::new(Stop::SilentAfterConnect, End::Close)
    })
    .await;
    let closed = run(Script::new(Stop::AfterConnect, End::Close)).await;

    for (run, outcome, timeout_ms) in [
        (&silent, PhaseOutcome::TimedOut, Some(1000)),
        (&closed, PhaseOutcome::Failed, None),
    ] {
        assert_unconfirmed(run);
        let last = run.phases.last().unwrap();
        assert_eq!(
            (last.phase, last.outcome),
            (ConnectPhaseName::Logon, outcome)
        );
        let detail = last.detail.as_ref().unwrap();
        assert_eq!(detail.error_code, Some(ErrorCode::AuthenticationFailed));
        assert_eq!(detail.timeout_ms, timeout_ms);
    }
}

#[tokio::test]
async fn a_failure_before_the_credentials_ends_with_a_failed_connection_phase() {
    let run = run(Script::new(Stop::BeforeClientInfo, End::Close)).await;
    let last = run.phases.last().unwrap();
    assert_eq!((last.phase, last.outcome), (ConnectPhaseName::RdpConnect, PhaseOutcome::Failed));
    assert_eq!(last.detail.as_ref().unwrap().error_code, Some(ErrorCode::ConnectionFailed));
}

#[tokio::test]
async fn a_stall_before_the_credentials_times_out_as_a_connection_failure() {
    let client_info_timeout = Duration::from_millis(300);
    let run = run(Script {
        client_info_timeout: Some(client_info_timeout),
        ..Script::new(Stop::StallBeforeClientInfo, End::Close)
    })
    .await;
    assert!(!run.credentials_received);
    assert!(
        matches!(run.error(), RdpError::ConnectionFailed(_)),
        "got {:?}",
        run.error()
    );
    assert_eq!(run.credential_boundary, CredentialBoundary::None);
    let last = run.phases.last().unwrap();
    assert_eq!(
        (last.phase, last.outcome),
        (ConnectPhaseName::RdpConnect, PhaseOutcome::TimedOut)
    );
    let detail = last.detail.as_ref().unwrap();
    assert_eq!(detail.error_code, Some(ErrorCode::ConnectionFailed));
    assert_eq!(detail.timeout_ms, Some(300));
    assert!(
        run.elapsed < Duration::from_secs(5),
        "took {:?}",
        run.elapsed
    );
}

/// How far a stalling server follows the connection before it goes silent.
#[derive(Clone, Copy, Debug)]
enum Partway {
    /// Reads the X.224 Connection Request and never answers.
    Request,
    /// Selects TLS-only and never starts the TLS handshake.
    Confirm,
    /// Completes the TLS handshake if the client does, then closes.
    Tls,
}

/// Connects to a server that stops at `partway`, with short timeouts for the phases before the
/// credentials. Returns the result and the phases.
async fn connect_partway(
    partway: Partway,
    pin: Option<CertPin>,
) -> (Result<RdpSession, RdpError>, Vec<ConnectPhase>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        read_frame(&mut tcp).await; // X.224 Connection Request
        if let Partway::Request = partway {
            return read_until_eof(&mut tcp).await;
        }
        write_frame(
            &mut tcp,
            &X224(ConnectionConfirm::Response {
                flags: ResponseFlags::empty(),
                protocol: SecurityProtocol::SSL,
            }),
        )
        .await;
        if let Partway::Confirm = partway {
            return read_until_eof(&mut tcp).await;
        }
        if let Ok(tls) = tls_acceptor().accept(tcp).await {
            finish(tls, End::Close).await;
        }
    });

    let mut config = loopback_config(port, false, None);
    config.server_cert_pin = pin;
    let timing = ConnectTiming {
        phases: PhaseTimeouts {
            dns: Duration::from_secs(1),
            tcp: Duration::from_secs(1),
            negotiate: Duration::from_millis(300),
            tls: Duration::from_millis(300),
            client_info: Duration::from_millis(300),
        },
        logon_window: Duration::from_secs(1),
        ..CONNECT_TIMING
    };
    let mut trace = ConnectTrace::default();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        RdpSession::connect_within(config, None, timing, &mut trace),
    )
    .await
    .expect("connect did not finish");
    let (phases, credential_boundary) = trace.into_parts();
    // Every partway server stops before the credentials.
    assert_eq!(credential_boundary, CredentialBoundary::None);
    if result.is_err() {
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server did not finish")
            .unwrap();
    }
    (result, phases)
}

async fn read_until_eof(tcp: &mut TcpStream) {
    let mut buf = Vec::new();
    let _ = tcp.read_to_end(&mut buf).await;
}

#[tokio::test]
async fn a_silent_negotiation_times_out_as_a_connection_failure() {
    let (result, phases) = connect_partway(Partway::Request, None).await;
    let error = result.err().unwrap();
    assert!(
        matches!(error, RdpError::ConnectionFailed(_)),
        "got {error:?}"
    );
    assert_eq!(
        names(&phases),
        [
            ConnectPhaseName::Dns,
            ConnectPhaseName::Tcp,
            ConnectPhaseName::RdpNegotiate
        ]
    );
    let last = phases.last().unwrap();
    assert_eq!(last.outcome, PhaseOutcome::TimedOut);
    let detail = last.detail.as_ref().unwrap();
    assert_eq!(detail.error_code, Some(ErrorCode::ConnectionFailed));
    assert_eq!(detail.timeout_ms, Some(300));
}

#[tokio::test]
async fn a_stalled_tls_handshake_times_out_as_a_connection_failure() {
    let (result, phases) = connect_partway(Partway::Confirm, None).await;
    let error = result.err().unwrap();
    assert!(
        matches!(error, RdpError::ConnectionFailed(_)),
        "got {error:?}"
    );
    let last = phases.last().unwrap();
    assert_eq!((last.phase, last.outcome), (ConnectPhaseName::Tls, PhaseOutcome::TimedOut));
    assert_eq!(last.detail.as_ref().unwrap().error_code, Some(ErrorCode::ConnectionFailed));
}

#[tokio::test]
async fn a_pin_mismatch_fails_the_tls_phase() {
    let other_pin = CertPin::of_certificate(include_bytes!("../../testdata/tls/server-b.crt.der"));
    let (result, phases) = connect_partway(Partway::Tls, other_pin).await;
    assert!(matches!(result, Err(RdpError::CertificateMismatch(_))));
    let last = phases.last().unwrap();
    assert_eq!(
        (last.phase, last.outcome),
        (ConnectPhaseName::Tls, PhaseOutcome::Failed)
    );
    let detail = last.detail.as_ref().unwrap();
    assert_eq!(detail.error_code, Some(ErrorCode::CertificateMismatch));
    assert_eq!(detail.cert_pin_matched, Some(false));
}

#[tokio::test]
async fn a_matching_pin_is_reported_on_the_tls_phase() {
    let (result, phases) = connect_partway(Partway::Tls, CertPin::of_certificate(CERT)).await;
    // The server closes after TLS, so the connection sequence itself fails.
    assert!(result.is_err());
    let tls = phases
        .iter()
        .find(|p| p.phase == ConnectPhaseName::Tls)
        .unwrap();
    assert_eq!(tls.outcome, PhaseOutcome::Ok);
    assert_eq!(tls.detail.as_ref().unwrap().cert_pin_matched, Some(true));
}
