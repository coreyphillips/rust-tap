// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Pinned-certificate TLS transport for tapd's gRPC listener.
//!
//! tapd (like lnd) serves gRPC over TLS with an auto-generated
//! self-signed certificate (`tls.cert` in its data dir). Those
//! certificates set `CA:TRUE` on the leaf, which webpki rejects when
//! the same cert is presented as the end entity
//! (`CaUsedAsEndEntity`), so tonic's stock `ClientTlsConfig` +
//! `ca_certificate` path cannot validate a stock tapd. This module
//! does what Go's lndclient effectively does: trust exactly the
//! certificate the caller supplies (byte-for-byte pinning), while
//! still verifying the TLS handshake signatures so the peer must hold
//! the matching private key.

use std::sync::Arc;

use tokio_rustls::rustls;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, ServerName, UnixTime,
};
use tokio_rustls::rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme,
};
use tokio_rustls::TlsConnector;

use tonic::transport::Uri;

/// Accepts exactly the pinned certificate(s) and nothing else. The
/// handshake signature is still verified against the pinned cert's
/// public key, so a peer that merely replays the cert without its
/// private key fails the handshake.
#[derive(Debug)]
struct PinnedServerCertVerifier {
    pinned: Vec<CertificateDer<'static>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self
            .pinned
            .iter()
            .any(|cert| cert.as_ref() == end_entity.as_ref())
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Builds a rustls client config that pins the PEM certificate(s) in
/// `cert_pem` and negotiates HTTP/2 (gRPC).
fn pinned_client_config(cert_pem: &[u8]) -> Result<ClientConfig, String> {
    let pinned: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<Result<_, _>>()
            .map_err(|e| format!("parse pinned certificate PEM: {}", e))?;
    if pinned.is_empty() {
        return Err("no certificates found in pinned PEM".into());
    }

    let provider =
        Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls protocol versions: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            PinnedServerCertVerifier { pinned, provider },
        ))
        .with_no_client_auth();

    // gRPC runs over HTTP/2; tonic's built-in TLS path sets the same
    // ALPN.
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

/// A `tower` connector for [`tonic`]'s `connect_with_connector` that
/// dials TCP and wraps the stream in pinned-certificate TLS.
///
/// `sni_override` replaces the URI host as the TLS server name (the
/// pinning verifier ignores names, but a rustls `ServerName` is still
/// required and is sent as SNI).
pub(crate) fn pinned_tls_connector(
    cert_pem: &[u8],
    sni_override: Option<String>,
) -> Result<
    impl tower::Service<
            Uri,
            Response = hyper_util::rt::TokioIo<
                tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
            >,
            Error = Box<dyn std::error::Error + Send + Sync>,
            Future = impl Send,
        > + Clone
        + Send
        + 'static,
    String,
> {
    let config = Arc::new(pinned_client_config(cert_pem)?);

    Ok(tower::service_fn(move |uri: Uri| {
        let config = config.clone();
        let sni_override = sni_override.clone();
        async move {
            type BoxError = Box<dyn std::error::Error + Send + Sync>;

            let host = uri
                .host()
                .ok_or_else(|| {
                    BoxError::from(format!("uri has no host: {}", uri))
                })?
                .to_string();
            let port = uri.port_u16().unwrap_or(443);

            let server_name =
                ServerName::try_from(sni_override.unwrap_or_else(|| {
                    host.clone()
                }))
                .map_err(|e| {
                    BoxError::from(format!("invalid tls server name: {}", e))
                })?;

            let tcp =
                tokio::net::TcpStream::connect((host.as_str(), port)).await?;
            tcp.set_nodelay(true)?;

            let tls = TlsConnector::from(config)
                .connect(server_name, tcp)
                .await?;
            Ok::<_, BoxError>(hyper_util::rt::TokioIo::new(tls))
        }
    }))
}
