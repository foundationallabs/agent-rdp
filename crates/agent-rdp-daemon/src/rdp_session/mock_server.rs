//! A loopback RDP server that takes a TLS-only (NLA-off) connect to a chosen point and then ends
//! the connection, to test how `RdpSession::connect` classifies each end.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ironrdp::pdu::gcc::{
    ConferenceCreateResponse, ServerCoreData, ServerCoreOptionalData, ServerEarlyCapabilityFlags,
    ServerGccBlocks, ServerNetworkData, ServerSecurityData,
};
use ironrdp::pdu::mcs::{
    AttachUserConfirm, ConnectResponse, DomainParameters, SendDataIndication, SendDataRequest,
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
    LogonErrorNotificationType, LogonErrorsInfo, LogonExFlags, LogonInfoExtended,
    SaveSessionInfoPdu,
};
use ironrdp::pdu::rdp::ClientInfoPdu;
use ironrdp::pdu::x224::{X224Data, X224};
use ironrdp::pdu::{encode_vec, gcc, Encode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;

use super::tests::test_config;
use super::{RdpError, RdpSession, LOGON_OUTCOME_WINDOW};
use agent_rdp_protocol::AuthFailureReason;

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
}

/// How the server ends the connection at its stop point.
#[derive(Clone, Copy, Debug)]
enum End {
    /// TLS close_notify, then FIN.
    Close,
    /// TCP reset.
    Reset,
}

/// One connect against the mock server.
#[derive(Clone, Debug)]
struct Script {
    stop: Stop,
    end: End,
    /// The client offers NLA; the server still selects TLS-only.
    offer_nla: bool,
    /// After the connection sequence, the server first sends SESSION_CONTINUE with
    /// LOGON_FAILED_OTHER, as a WS2019 broker farm does on every good logon.
    session_continue: bool,
    alternate_shell: Option<String>,
    /// A shorter logon window through `connect_within`; `None` runs the production `connect`.
    logon_window: Option<Duration>,
}

impl Script {
    fn new(stop: Stop, end: End) -> Self {
        Self {
            stop,
            end,
            offer_nla: false,
            session_continue: false,
            alternate_shell: None,
            logon_window: None,
        }
    }
}

/// What `connect` returned, how long it took, and whether the server received the credentials.
struct Run {
    result: Result<(), RdpError>,
    elapsed: Duration,
    credentials_received: bool,
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
    let (stop, end, session_continue) = (script.stop, script.end, script.session_continue);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve(stream, stop, end, session_continue).await
    });

    let mut config = test_config(script.alternate_shell.as_deref());
    config.host = "127.0.0.1".to_string();
    config.port = port;
    config.enable_credssp = script.offer_nla;
    let started = Instant::now();
    let connect = async {
        match script.logon_window {
            Some(window) => RdpSession::connect_within(config, None, window).await,
            None => RdpSession::connect(config, None).await,
        }
    };
    let result = tokio::time::timeout(Duration::from_secs(30), connect)
        .await
        .expect("connect did not finish");
    let elapsed = started.elapsed();
    // Dropping the session closes the connection, which a confirming server waits for.
    let result = result.map(drop);
    let credentials_received = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server did not finish")
        .unwrap();
    Run {
        result,
        elapsed,
        credentials_received,
    }
}

async fn connect(port: u16, enable_credssp: bool) -> Result<RdpSession, RdpError> {
    let mut config = test_config(None);
    config.host = "127.0.0.1".to_string();
    config.port = port;
    config.enable_credssp = enable_credssp;
    tokio::time::timeout(Duration::from_secs(30), RdpSession::connect(config, None))
        .await
        .expect("connect did not finish")
}

/// Runs the server side of the connection sequence up to `stop`. Returns whether the Client Info
/// PDU arrived (for `ReadAfterAttach`: whether any byte arrived).
async fn serve(mut tcp: TcpStream, stop: Stop, end: End, session_continue: bool) -> bool {
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

    read_frame(&mut tls).await; // MCS Connect Initial
    write_frame(
        &mut tls,
        &X224(X224Data {
            data: Cow::Owned(encode_vec(&connect_response()).unwrap()),
        }),
    )
    .await;
    read_frame(&mut tls).await; // Erect Domain Request
    read_frame(&mut tls).await; // Attach User Request
    if let Stop::BeforeClientInfo = stop {
        finish(tls, end).await;
        return false;
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
        return !read_until_closed(&mut tls).await.is_empty();
    }
    let frame = read_frame(&mut tls).await;
    let request = ironrdp::pdu::decode::<X224<SendDataRequest<'_>>>(&frame).unwrap();
    let client_info = ironrdp::pdu::decode::<ClientInfoPdu>(&request.0.user_data).unwrap();
    assert_eq!(client_info.client_info.credentials.username, "user");
    match stop {
        Stop::AfterClientInfo => {
            finish(tls, end).await;
            return true;
        }
        Stop::StallAfterClientInfo => {
            read_until_closed(&mut tls).await;
            return true;
        }
        _ => {}
    }

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
    write_frame(
        &mut tls,
        &share_data(ShareDataPdu::FontMap(FontPdu::default())),
    )
    .await;

    if session_continue {
        write_frame(
            &mut tls,
            &share_data(ShareDataPdu::SaveSessionInfo(SaveSessionInfoPdu {
                info_type: InfoType::LogonExtended,
                info_data: InfoData::LogonExtended(LogonInfoExtended {
                    present_fields_flags: LogonExFlags::LOGON_ERRORS,
                    auto_reconnect: None,
                    errors_info: Some(LogonErrorsInfo {
                        error_type: LogonErrorNotificationType::SessionContinue,
                        error_data: LogonErrorNotificationData::ErrorCode(
                            LogonErrorNotificationDataErrorCode::FailedOther,
                        ),
                    }),
                }),
            })),
        )
        .await;
    }
    match stop {
        Stop::AfterConnect => finish(tls, end).await,
        Stop::SilentAfterConnect => {
            read_until_closed(&mut tls).await;
        }
        Stop::Confirm => {
            write_frame(
                &mut tls,
                &share_data(ShareDataPdu::SaveSessionInfo(SaveSessionInfoPdu {
                    info_type: InfoType::PlainNotify,
                    info_data: InfoData::PlainNotify,
                })),
            )
            .await;
            read_until_closed(&mut tls).await;
        }
        Stop::BeforeClientInfo
        | Stop::ReadAfterAttach
        | Stop::AfterClientInfo
        | Stop::StallAfterClientInfo => unreachable!(),
    }
    true
}

/// Reads until the client closes the connection, cleanly or not. Returns what arrived.
async fn read_until_closed(tls: &mut TlsStream<TcpStream>) -> Vec<u8> {
    let mut received = Vec::new();
    let _ = tls.read_to_end(&mut received).await;
    received
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
async fn a_close_inside_the_logon_window_is_an_unconfirmed_login() {
    for session_continue in [false, true] {
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
                "{end:?}: took {:?}",
                run.elapsed
            );
        }
    }
}

#[tokio::test]
async fn session_continue_then_silence_is_an_unconfirmed_login_at_20_s() {
    let run = run(Script {
        session_continue: true,
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
    for session_continue in [false, true] {
        let run = run(Script {
            session_continue,
            ..Script::new(Stop::Confirm, End::Close)
        })
        .await;
        assert!(
            run.result.is_ok(),
            "session_continue={session_continue}: got {:?}",
            run.result.err()
        );
    }
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

    let result = connect(port, true).await;
    // A CredSSP TSRequest is a DER SEQUENCE; an MCS Connect Initial would start a TPKT frame (3).
    assert_eq!(server.await.unwrap(), 0x30);
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
