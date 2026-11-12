//! TLS configuration for both listeners.
//!
//! All TLS and certificate cryptography is done by `rustls` / `aws-lc-rs`.
//! This module only chooses protocol versions and cipher suites, and decides
//! which client certificates are acceptable.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CipherSuite, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig,
    SignatureScheme, SupportedCipherSuite,
};

use crate::util::{b64url, sha256};

/// TLS 1.2 cipher suites recommended by BCP 195 (RFC 9325 §4.2), which
/// FAPI 2.0 §5.2.2 makes the only ones permitted. TLS 1.3 suites are all
/// acceptable and are not filtered.
const TLS12_SUITES: &[CipherSuite] = &[
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
];

/// A certificate chain and its private key.
#[derive(Debug)]
pub struct TlsIdentity {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl TlsIdentity {
    pub fn from_pem_files(cert: &Path, key: &Path) -> Result<Self> {
        let certs = CertificateDer::pem_file_iter(cert)
            .with_context(|| format!("reading certificate {}", cert.display()))?
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("parsing certificate {}", cert.display()))?;
        anyhow::ensure!(
            !certs.is_empty(),
            "{} contains no certificates",
            cert.display()
        );
        let key = PrivateKeyDer::from_pem_file(key)
            .with_context(|| format!("reading private key {}", key.display()))?;
        Ok(Self { certs, key })
    }

    /// Generate a self-signed certificate valid for `names` (DNS names or IP
    /// addresses). For development and tests only.
    pub fn self_signed(names: Vec<String>) -> Result<Self> {
        let generated = rcgen::generate_simple_self_signed(names)
            .context("generating self-signed certificate")?;
        let key = PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
        Ok(Self {
            certs: vec![generated.cert.der().clone()],
            key: key.into(),
        })
    }

    /// PEM encoding of the leaf certificate.
    pub fn cert_pem(&self) -> String {
        pem("CERTIFICATE", self.certs[0].as_ref())
    }

    /// PEM encoding of the private key.
    pub fn key_pem(&self) -> String {
        let label = match &self.key {
            PrivateKeyDer::Pkcs1(_) => "RSA PRIVATE KEY",
            PrivateKeyDer::Sec1(_) => "EC PRIVATE KEY",
            _ => "PRIVATE KEY",
        };
        pem(label, self.key.secret_der())
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// Which client certificates a listener asks for and accepts.
#[derive(Debug)]
pub enum ClientCertPolicy {
    /// Do not request a client certificate (the browser-facing listener).
    None,
    /// Request a certificate and accept any the client proves possession of.
    /// Tokens are bound to its thumbprint; identity comes from
    /// `private_key_jwt`. This is RFC 8705's self-signed certificate mode.
    AnyProven,
    /// Request a certificate that must chain to one of these roots.
    TrustedRoots(RootCertStore),
}

impl ClientCertPolicy {
    /// Load trusted roots from a PEM bundle.
    pub fn from_ca_file(path: &Path) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_file_iter(path)
            .with_context(|| format!("reading client CA bundle {}", path.display()))?
        {
            let cert = cert.with_context(|| format!("parsing {}", path.display()))?;
            roots
                .add(cert)
                .with_context(|| format!("adding CA from {}", path.display()))?;
        }
        anyhow::ensure!(
            !roots.is_empty(),
            "{} contains no CA certificates",
            path.display()
        );
        Ok(Self::TrustedRoots(roots))
    }
}

/// The crypto provider with TLS 1.2 limited to BCP 195 cipher suites.
fn provider() -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites.retain(|suite| match suite {
        SupportedCipherSuite::Tls13(_) => true,
        SupportedCipherSuite::Tls12(_) => TLS12_SUITES.contains(&suite.suite()),
    });
    Arc::new(provider)
}

/// Build a server configuration: TLS 1.2 and 1.3 only (FAPI 2.0 §5.2.1),
/// offering HTTP/2 and HTTP/1.1.
pub fn server_config(
    identity: &TlsIdentity,
    policy: ClientCertPolicy,
) -> Result<Arc<ServerConfig>> {
    let provider = provider();
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("selecting TLS versions")?;

    let builder = match policy {
        ClientCertPolicy::None => builder.with_no_client_auth(),
        ClientCertPolicy::AnyProven => {
            builder.with_client_cert_verifier(Arc::new(ProofOfPossessionOnly {
                algorithms: provider.signature_verification_algorithms,
            }))
        }
        ClientCertPolicy::TrustedRoots(roots) => {
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                // The certificate is optional at the TLS layer so that a
                // missing one produces an OAuth error, not a handshake failure.
                .allow_unauthenticated()
                .build()
                .map_err(|e| anyhow!("building client certificate verifier: {e}"))?;
            builder.with_client_cert_verifier(verifier)
        }
    };

    let mut config = builder
        .with_single_cert(identity.certs.clone(), identity.key.clone_key())
        .context("loading server certificate and key")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Accepts any client certificate, while still requiring the TLS handshake
/// proof that the client holds the matching private key.
///
/// Chain validation is deliberately skipped: with `private_key_jwt` client
/// authentication the certificate is not an identity credential, only the
/// key that access tokens are bound to. The signature checks below are
/// delegated to rustls and are what make that binding meaningful.
#[derive(Debug)]
struct ProofOfPossessionOnly {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for ProofOfPossessionOnly {
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
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

/// The certificate a client presented on a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCert {
    /// `x5t#S256`: base64url SHA-256 of the DER certificate (RFC 8705 §3.1).
    pub thumbprint: String,
}

impl ClientCert {
    pub fn from_der(der: &[u8]) -> Self {
        Self {
            thumbprint: b64url(sha256(der)),
        }
    }

    /// From a PEM certificate, as handed over by a TLS-terminating proxy.
    /// If there are several, the first is the client's own.
    pub fn from_pem(pem: &str) -> Option<Self> {
        CertificateDer::from_pem_slice(pem.as_bytes())
            .ok()
            .map(|cert| Self::from_der(cert.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> TlsIdentity {
        TlsIdentity::self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]).unwrap()
    }

    #[test]
    fn only_bcp195_suites_are_offered_for_tls12() {
        let provider = provider();
        let mut tls12 = 0;
        for suite in &provider.cipher_suites {
            if let SupportedCipherSuite::Tls12(_) = suite {
                tls12 += 1;
                assert!(TLS12_SUITES.contains(&suite.suite()), "{:?}", suite.suite());
            }
        }
        assert_eq!(tls12, TLS12_SUITES.len());
        assert!(
            provider
                .cipher_suites
                .iter()
                .any(|s| matches!(s, SupportedCipherSuite::Tls13(_)))
        );
    }

    #[test]
    fn builds_configs_for_each_policy() {
        let identity = identity();
        let public = server_config(&identity, ClientCertPolicy::None).unwrap();
        assert_eq!(
            public.alpn_protocols,
            [b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        server_config(&identity, ClientCertPolicy::AnyProven).unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(identity.certs[0].clone()).unwrap();
        server_config(&identity, ClientCertPolicy::TrustedRoots(roots)).unwrap();
    }

    #[test]
    fn proof_of_possession_verifier_requests_but_does_not_require_a_cert() {
        let verifier = ProofOfPossessionOnly {
            algorithms: provider().signature_verification_algorithms,
        };
        assert!(verifier.offer_client_auth());
        assert!(!verifier.client_auth_mandatory());
        assert_ne!(verifier.supported_verify_schemes(), Vec::new());
    }

    #[test]
    fn thumbprint_is_base64url_sha256_of_the_der() {
        let cert = ClientCert::from_der(b"abc");
        // SHA-256("abc"), base64url.
        assert_eq!(
            cert.thumbprint,
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
    }

    #[test]
    fn pem_round_trips_through_the_file_loaders() {
        let identity = identity();
        let dir =
            std::env::temp_dir().join(format!("oxid-tls-test-{}", crate::util::random_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        std::fs::write(&cert, identity.cert_pem()).unwrap();
        std::fs::write(&key, identity.key_pem()).unwrap();

        let loaded = TlsIdentity::from_pem_files(&cert, &key).unwrap();
        assert_eq!(loaded.certs, identity.certs);
        server_config(&loaded, ClientCertPolicy::None).unwrap();
        assert!(matches!(
            ClientCertPolicy::from_ca_file(&cert).unwrap(),
            ClientCertPolicy::TrustedRoots(_)
        ));
        assert!(
            TlsIdentity::from_pem_files(&key, &key).is_err(),
            "no certificate in key file"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
