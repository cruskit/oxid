//! The provider's own signing key and its published JWK Set.

use std::fmt;
use std::path::Path;

use anyhow::{Context, Result};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use jsonwebtoken::EncodingKey;
use jsonwebtoken::jwk::{Jwk, JwkSet, PublicKeyUse, ThumbprintHash};
use serde::Serialize;

use crate::jose::{self, JoseError, SigningAlg};

/// An RSA key used to sign ID tokens with PS256.
///
/// PS256 is the only algorithm the ConnectID profile permits (§5), so the
/// provider's key is always RSA.
pub struct SigningKey {
    kid: String,
    encoding_key: EncodingKey,
    public_jwk: Jwk,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material.
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    pub const ALG: SigningAlg = SigningAlg::PS256;

    /// Load a PEM-encoded RSA private key (PKCS#1 or PKCS#8).
    pub fn from_pem_file(path: &Path) -> Result<Self> {
        let pem = std::fs::read(path)
            .with_context(|| format!("reading signing key {}", path.display()))?;
        Self::from_pem(&pem).with_context(|| format!("loading signing key {}", path.display()))
    }

    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let key = EncodingKey::from_rsa_pem(pem).context("not a PEM-encoded RSA private key")?;
        Self::from_encoding_key(key)
    }

    /// Generate a fresh 2048-bit key. Used for development and tests; a real
    /// deployment configures a persistent key so tokens survive restarts.
    pub fn generate() -> Result<Self> {
        Self::from_pem(Self::generate_pem()?.as_bytes())
    }

    /// Generate a fresh 2048-bit private key as PKCS#8 PEM, for writing to a
    /// file that [`SigningKey::from_pem_file`] can load.
    pub fn generate_pem() -> Result<String> {
        let pair = KeyPair::generate(KeySize::Rsa2048)
            .map_err(|_| anyhow::anyhow!("RSA key generation failed"))?;
        let der = AsDer::<aws_lc_rs::encoding::Pkcs8V1Der<'_>>::as_der(&pair)
            .map_err(|_| anyhow::anyhow!("RSA key serialisation failed"))?;
        Ok(pkcs8_pem(der.as_ref()))
    }

    fn from_encoding_key(encoding_key: EncodingKey) -> Result<Self> {
        let mut public_jwk = Jwk::from_encoding_key(&encoding_key, jsonwebtoken::Algorithm::PS256)
            .context("deriving public JWK from signing key")?;
        anyhow::ensure!(
            jose::key_supports_alg(&public_jwk, Self::ALG),
            "signing key must be RSA with a modulus of at least 2048 bits"
        );
        // The RFC 7638 thumbprint makes a stable, collision-free key id.
        let kid = public_jwk
            .thumbprint(ThumbprintHash::SHA256)
            .context("computing key thumbprint")?;
        public_jwk.common.key_id = Some(kid.clone());
        public_jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        Ok(Self {
            kid,
            encoding_key,
            public_jwk,
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn public_jwk(&self) -> &Jwk {
        &self.public_jwk
    }

    /// The JWK Set served from `jwks_uri`. Contains public material only.
    pub fn jwks(&self) -> JwkSet {
        JwkSet {
            keys: vec![self.public_jwk.clone()],
        }
    }

    /// Sign `claims` as a compact JWS with this key.
    pub fn sign(&self, typ: Option<&str>, claims: &impl Serialize) -> Result<String, JoseError> {
        jose::sign(Self::ALG, Some(&self.kid), typ, claims, &self.encoding_key)
    }

    /// Sign with an externally assigned key id in the header, for keys that
    /// are registered elsewhere under an id that is not their thumbprint.
    pub fn sign_with_kid(
        &self,
        kid: &str,
        typ: Option<&str>,
        claims: &impl Serialize,
    ) -> Result<String, JoseError> {
        jose::sign(Self::ALG, Some(kid), typ, claims, &self.encoding_key)
    }
}

/// Wrap PKCS#8 DER in a PEM envelope so it goes through the same loader as a
/// key read from disk.
fn pkcs8_pem(der: &[u8]) -> String {
    use base64::Engine;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n")
}

/// Helpers for other modules' unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::OnceLock;

    use super::SigningKey;

    /// RSA generation is slow in debug builds, so tests share one key.
    pub fn shared_key() -> &'static SigningKey {
        static KEY: OnceLock<SigningKey> = OnceLock::new();
        KEY.get_or_init(|| SigningKey::generate().expect("generate test key"))
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::jwk::AlgorithmParameters;

    use super::*;

    #[test]
    fn generated_key_publishes_only_public_rsa_material() {
        let key = test_support::shared_key();
        let jwks = serde_json::to_value(key.jwks()).unwrap();
        let jwk = &jwks["keys"][0];
        assert_eq!(jwk["kty"], "RSA");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["alg"], "PS256");
        assert_eq!(jwk["kid"], key.kid());
        for private in ["d", "p", "q", "dp", "dq", "qi"] {
            assert!(
                jwk.get(private).is_none(),
                "{private} must not be published"
            );
        }
        assert!(matches!(
            key.public_jwk().algorithm,
            AlgorithmParameters::RSA(_)
        ));
    }

    #[test]
    fn debug_output_does_not_leak_key_material() {
        let key = test_support::shared_key();
        let debug = format!("{key:?}");
        assert!(debug.contains(key.kid()));
        assert!(!debug.contains("encoding_key"));
    }

    #[test]
    fn rejects_non_rsa_pem() {
        assert!(SigningKey::from_pem(b"not a key").is_err());
    }

    #[test]
    fn kid_is_stable_for_the_same_key() {
        let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let der = AsDer::<aws_lc_rs::encoding::Pkcs8V1Der<'_>>::as_der(&pair).unwrap();
        let pem = pkcs8_pem(der.as_ref());
        let a = SigningKey::from_pem(pem.as_bytes()).unwrap();
        let b = SigningKey::from_pem(pem.as_bytes()).unwrap();
        assert_eq!(a.kid(), b.kid());
    }
}
