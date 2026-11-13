//! TLS upgrade for the RDP connection, with optional server key pinning.
//!
//! Without a pin, any certificate is accepted (RDP servers usually present self-signed
//! certificates). With a pin, the certificate's key must match it and the handshake signatures
//! are verified, so a server that replays the pinned certificate without its key is refused.

use std::sync::Arc;

use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, OtherError, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use x509_cert::der::{Decode, Encode};

const PIN_PREFIX: &str = "sha256/";

/// A pinned server key: SHA-256 of the end-entity certificate's DER SubjectPublicKeyInfo,
/// written `sha256/<base64>`. It survives a certificate renewal that keeps the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPin([u8; 32]);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("Invalid server certificate pin: expected sha256/<base64 of a 32-byte SHA-256 digest>")]
pub struct InvalidCertPin;

impl CertPin {
    pub fn parse(pin: &str) -> Result<Self, InvalidCertPin> {
        let encoded = pin.strip_prefix(PIN_PREFIX).ok_or(InvalidCertPin)?;
        let digest = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| InvalidCertPin)?;
        digest.try_into().map(Self).map_err(|_| InvalidCertPin)
    }

    /// The pin of a DER certificate, or `None` when it does not parse.
    pub fn of_certificate(cert_der: &[u8]) -> Option<Self> {
        let cert = x509_cert::Certificate::from_der(cert_der).ok()?;
        let spki = cert.tbs_certificate.subject_public_key_info.to_der().ok()?;
        let digest = ring::digest::digest(&ring::digest::SHA256, &spki);
        digest.as_ref().try_into().ok().map(Self)
    }

    /// Compare in constant time.
    fn matches(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
    }
}

impl std::fmt::Display for CertPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let encoded = base64::engine::general_purpose::STANDARD.encode(self.0);
        write!(f, "{PIN_PREFIX}{encoded}")
    }
}

/// The server's certificate key is not the pinned one. Carries the key it presented, so an
/// operator can tell a changed key from a misconfigured pin.
#[derive(Debug, thiserror::Error)]
#[error("Server certificate key {} does not match the pinned key", .presented.as_ref().map_or_else(|| "(unparseable certificate)".to_string(), ToString::to_string))]
pub struct CertificateMismatch {
    pub presented: Option<CertPin>,
}

/// The pin mismatch behind a failed TLS upgrade, if that is why it failed.
pub fn certificate_mismatch(error: &std::io::Error) -> Option<&CertificateMismatch> {
    match error.get_ref()?.downcast_ref::<rustls::Error>()? {
        rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(inner))) => {
            inner.downcast_ref::<CertificateMismatch>()
        }
        _ => None,
    }
}

/// Upgrade the connection to TLS and return the server's end-entity certificate (DER).
pub async fn upgrade(
    stream: TcpStream,
    server_name: &str,
    pin: Option<&CertPin>,
) -> Result<(TlsStream<TcpStream>, Vec<u8>), std::io::Error> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config(pin)));

    // Try to parse as IP address first, then as DNS name
    let server_name = if let Ok(ip) = server_name.parse::<std::net::IpAddr>() {
        ServerName::IpAddress(ip.into())
    } else {
        ServerName::try_from(server_name.to_string())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
    };

    let tls_stream = connector.connect(server_name, stream).await?;

    // Get peer certificate
    let (_, server_conn) = tls_stream.get_ref();
    let certs = server_conn
        .peer_certificates()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "No peer certificate"))?;

    let cert_der = certs
        .first()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Empty certificate chain"))?
        .to_vec();

    Ok((tls_stream, cert_der))
}

fn client_config(pin: Option<&CertPin>) -> rustls::ClientConfig {
    // Install ring as the default crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    let verifier: Arc<dyn ServerCertVerifier> = match pin {
        Some(pin) => Arc::new(PinnedVerifier::new(pin.clone())),
        None => Arc::new(NoVerifier),
    };
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

/// Accepts the server only if its certificate key matches the pin, and checks the handshake
/// signatures against that key.
#[derive(Debug)]
struct PinnedVerifier {
    pin: CertPin,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedVerifier {
    fn new(pin: CertPin) -> Self {
        Self {
            pin,
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented = CertPin::of_certificate(end_entity);
        if presented
            .as_ref()
            .is_some_and(|presented| self.pin.matches(presented))
        {
            return Ok(ServerCertVerified::assertion());
        }
        Err(rustls::Error::InvalidCertificate(CertificateError::Other(
            OtherError(Arc::new(CertificateMismatch { presented })),
        )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Custom certificate verifier that accepts all certificates.
/// This is necessary because RDP servers typically use self-signed certificates.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::PrivateKeyDer;
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use tokio::net::TcpListener;

    use super::*;

    const CERT_A: &[u8] = include_bytes!("../testdata/tls/server-a.crt.der");
    const KEY_A: &[u8] = include_bytes!("../testdata/tls/server-a.key.der");
    const CERT_B: &[u8] = include_bytes!("../testdata/tls/server-b.crt.der");
    const KEY_B: &[u8] = include_bytes!("../testdata/tls/server-b.key.der");

    // Computed with openssl, independently of this module:
    // openssl x509 -in a.crt -pubkey -noout | openssl pkey -pubin -outform der
    //   | openssl dgst -sha256 -binary | base64
    const PIN_A: &str = "sha256/v0ED3aaQaqkZx0eWMgIKcV21wFokPfvCkSa1dZpbHNA=";
    const PIN_B: &str = "sha256/mfcbmRRslffBQvUZoLvYhHOWqPIreSnKkAWISpFw1ss=";

    /// Serves `cert` and signs the handshake with `key`, which need not belong to `cert`.
    #[derive(Debug)]
    struct Serve(Arc<CertifiedKey>);

    impl ResolvesServerCert for Serve {
        fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(Arc::clone(&self.0))
        }
    }

    /// Run one TLS handshake against a loopback server and return the client's result.
    async fn handshake(
        cert: &[u8],
        key: &[u8],
        version: &'static rustls::SupportedProtocolVersion,
        pin: Option<&str>,
    ) -> Result<Vec<u8>, std::io::Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let signing_key = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(key.to_vec().into()))
            .unwrap();
        let certified = CertifiedKey::new(vec![CertificateDer::from(cert.to_vec())], signing_key);
        let server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Serve(Arc::new(certified))));
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        });

        let pin = pin.map(|pin| CertPin::parse(pin).unwrap());
        let stream = TcpStream::connect(addr).await.unwrap();
        let result = upgrade(stream, "127.0.0.1", pin.as_ref())
            .await
            .map(|(_, cert)| cert);
        server.abort();
        result
    }

    #[test]
    fn parses_a_pin_and_prints_it_back() {
        let pin = CertPin::parse(PIN_A).unwrap();
        assert_eq!(pin.to_string(), PIN_A);
    }

    #[test]
    fn malformed_pins_are_rejected() {
        let short = format!(
            "sha256/{}",
            base64::engine::general_purpose::STANDARD.encode([0u8; 31])
        );
        for pin in [
            "",
            "v0ED3aaQaqkZx0eWMgIKcV21wFokPfvCkSa1dZpbHNA=",
            "sha1/v0ED3aaQaqkZx0eWMgIKcV21wFokPfvCkSa1dZpbHNA=",
            "sha256/not base64!",
            short.as_str(),
        ] {
            assert_eq!(CertPin::parse(pin), Err(InvalidCertPin), "{pin:?}");
        }
    }

    #[test]
    fn pin_of_a_certificate_is_the_spki_sha256() {
        assert_eq!(CertPin::of_certificate(CERT_A).unwrap().to_string(), PIN_A);
        assert_eq!(CertPin::of_certificate(CERT_B).unwrap().to_string(), PIN_B);
        assert_eq!(CertPin::of_certificate(b"not a certificate"), None);
    }

    #[test]
    fn pins_compare_every_byte() {
        let pin = CertPin::parse(PIN_A).unwrap();
        assert!(pin.matches(&pin.clone()));
        for index in [0, 31] {
            let mut other = pin.clone();
            other.0[index] ^= 1;
            assert!(!pin.matches(&other), "byte {index}");
        }
    }

    #[tokio::test]
    async fn matching_pin_connects_under_tls12_and_tls13() {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let cert = handshake(CERT_A, KEY_A, version, Some(PIN_A))
                .await
                .unwrap();
            assert_eq!(cert, CERT_A, "{version:?}");
        }
    }

    #[tokio::test]
    async fn different_key_is_a_certificate_mismatch() {
        let error = handshake(CERT_B, KEY_B, &rustls::version::TLS13, Some(PIN_A))
            .await
            .unwrap_err();
        let mismatch = certificate_mismatch(&error).expect("classified as a pin mismatch");
        assert_eq!(mismatch.presented.as_ref().unwrap().to_string(), PIN_B);
    }

    #[tokio::test]
    async fn pinned_certificate_without_its_key_is_refused() {
        // The server replays certificate A but signs the handshake with key B.
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let error = handshake(CERT_A, KEY_B, version, Some(PIN_A))
                .await
                .unwrap_err();
            assert!(
                certificate_mismatch(&error).is_none(),
                "{version:?}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn without_a_pin_any_certificate_is_accepted() {
        let cert = handshake(CERT_B, KEY_B, &rustls::version::TLS13, None)
            .await
            .unwrap();
        assert_eq!(cert, CERT_B);
    }

    #[test]
    fn other_tls_failures_are_not_a_mismatch() {
        let error = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(CertificateError::BadSignature),
        );
        assert!(certificate_mismatch(&error).is_none());
        assert!(certificate_mismatch(&std::io::Error::other("reset")).is_none());
    }
}
