//! Compact JWS handling.
//!
//! This module owns the *framing* of JWTs (splitting, base64url, header
//! inspection, key selection) so the provider has full control over what it
//! accepts. The actual signature operations are delegated to `jsonwebtoken`,
//! which in turn uses `aws-lc-rs`.
//!
//! It follows RFC 8725 (JWT BCP) and FAPI 2.0 §5.4: the algorithm must be on an
//! explicit allow-list, `none` can never be selected, and keys are checked for
//! minimum strength and for being the right type for the algorithm.

use std::fmt;
use std::str::FromStr;

use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, crypto};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::util::{b64url, b64url_decode};

/// Minimum RSA modulus size accepted, in bits (FAPI 2.0 §5.4.1).
const MIN_RSA_BITS: usize = 2048;

/// Signature algorithms permitted by FAPI 2.0 §5.4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SigningAlg {
    PS256,
    ES256,
    EdDSA,
}

impl SigningAlg {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PS256 => "PS256",
            Self::ES256 => "ES256",
            Self::EdDSA => "EdDSA",
        }
    }

    fn algorithm(self) -> Algorithm {
        match self {
            Self::PS256 => Algorithm::PS256,
            Self::ES256 => Algorithm::ES256,
            Self::EdDSA => Algorithm::EdDSA,
        }
    }
}

impl fmt::Display for SigningAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SigningAlg {
    type Err = JoseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PS256" => Ok(Self::PS256),
            "ES256" => Ok(Self::ES256),
            "EdDSA" => Ok(Self::EdDSA),
            other => Err(JoseError::UnsupportedAlg(other.to_owned())),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JoseError {
    #[error("malformed JWS: {0}")]
    Malformed(&'static str),
    #[error("signature algorithm '{0}' is not permitted")]
    UnsupportedAlg(String),
    #[error("no suitable verification key found")]
    NoMatchingKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("signing failed: {0}")]
    Signing(String),
}

/// A parsed, not-yet-verified compact JWS whose payload is a JSON object.
#[derive(Debug, Clone)]
pub struct Jws {
    pub alg: SigningAlg,
    pub kid: Option<String>,
    pub typ: Option<String>,
    pub claims: Map<String, Value>,
    signing_input: String,
    signature: String,
}

impl Jws {
    /// Split and decode a compact JWS, checking its `alg` against `allowed`.
    ///
    /// No signature verification happens here; call [`Jws::verify`] before
    /// trusting any claim.
    pub fn parse(token: &str, allowed: &[SigningAlg]) -> Result<Self, JoseError> {
        let mut parts = token.split('.');
        let (Some(header_b64), Some(payload_b64), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JoseError::Malformed("expected three dot-separated parts"));
        };

        let header: Map<String, Value> = b64url_decode(header_b64)
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or(JoseError::Malformed("header is not base64url-encoded JSON"))?;

        let alg_name = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or(JoseError::Malformed("header has no 'alg'"))?;
        let alg = SigningAlg::from_str(alg_name)?;
        if !allowed.contains(&alg) {
            return Err(JoseError::UnsupportedAlg(alg_name.to_owned()));
        }
        // We implement no critical header extensions, so RFC 7515 §4.1.11
        // requires rejecting any JWS that declares one.
        if header.contains_key("crit") {
            return Err(JoseError::Malformed("unsupported 'crit' header"));
        }

        let claims: Map<String, Value> = b64url_decode(payload_b64)
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or(JoseError::Malformed(
                "payload is not a base64url-encoded JSON object",
            ))?;

        if signature.is_empty() {
            return Err(JoseError::Malformed("signature is empty"));
        }

        let str_header = |name: &str| header.get(name).and_then(Value::as_str).map(str::to_owned);
        Ok(Self {
            alg,
            kid: str_header("kid"),
            typ: str_header("typ"),
            claims,
            signing_input: format!("{header_b64}.{payload_b64}"),
            signature: signature.to_owned(),
        })
    }

    /// Verify the signature against a key from `keys`.
    ///
    /// Key selection follows FAPI 2.0 §5.4.3: match on `kid` when the JWS has
    /// one, then narrow by `alg`, `use` and key type. Every remaining
    /// candidate is tried.
    pub fn verify(&self, keys: &JwkSet) -> Result<(), JoseError> {
        let mut tried_any = false;
        for jwk in keys.keys.iter().filter(|jwk| self.key_is_candidate(jwk)) {
            let Ok(key) = DecodingKey::from_jwk(jwk) else {
                continue;
            };
            tried_any = true;
            if crypto::verify(
                &self.signature,
                self.signing_input.as_bytes(),
                &key,
                self.alg.algorithm(),
            )
            .unwrap_or(false)
            {
                return Ok(());
            }
        }
        if tried_any {
            Err(JoseError::BadSignature)
        } else {
            Err(JoseError::NoMatchingKey)
        }
    }

    fn key_is_candidate(&self, jwk: &Jwk) -> bool {
        if let Some(kid) = &self.kid
            && jwk.common.key_id.as_deref() != Some(kid.as_str())
        {
            return false;
        }
        if matches!(&jwk.common.public_key_use, Some(u) if *u != PublicKeyUse::Signature) {
            return false;
        }
        if let Some(key_alg) = jwk.common.key_algorithm
            && key_alg.to_string() != self.alg.as_str()
        {
            return false;
        }
        key_supports_alg(jwk, self.alg)
    }

    /// A string claim, if present and a string.
    pub fn str_claim(&self, name: &str) -> Option<&str> {
        self.claims.get(name).and_then(Value::as_str)
    }

    /// A numeric date claim (seconds since the epoch), if present and numeric.
    #[allow(clippy::cast_possible_truncation)]
    pub fn time_claim(&self, name: &str) -> Option<i64> {
        let value = self.claims.get(name)?;
        value.as_i64().or_else(|| {
            value
                .as_f64()
                .filter(|f| f.is_finite())
                .map(|f| f.floor() as i64)
        })
    }
}

/// Whether `jwk` is the right kind of key, and strong enough, for `alg`.
pub fn key_supports_alg(jwk: &Jwk, alg: SigningAlg) -> bool {
    match (&jwk.algorithm, alg) {
        (AlgorithmParameters::RSA(rsa), SigningAlg::PS256) => {
            b64url_decode(&rsa.n).is_some_and(|n| {
                let significant = n.iter().skip_while(|b| **b == 0).count();
                significant * 8 >= MIN_RSA_BITS
            })
        }
        (AlgorithmParameters::EllipticCurve(ec), SigningAlg::ES256) => {
            ec.curve == EllipticCurve::P256
        }
        (AlgorithmParameters::OctetKeyPair(okp), SigningAlg::EdDSA) => {
            okp.curve == EllipticCurve::Ed25519
        }
        _ => false,
    }
}

/// Produce a compact JWS over `claims`.
pub fn sign(
    alg: SigningAlg,
    kid: Option<&str>,
    typ: Option<&str>,
    claims: &impl Serialize,
    key: &EncodingKey,
) -> Result<String, JoseError> {
    let mut header = Map::new();
    header.insert("alg".into(), alg.as_str().into());
    if let Some(kid) = kid {
        header.insert("kid".into(), kid.into());
    }
    if let Some(typ) = typ {
        header.insert("typ".into(), typ.into());
    }
    let to_json = |v: &dyn erased::Json| v.to_vec().map_err(|e| JoseError::Signing(e.to_string()));
    let signing_input = format!("{}.{}", b64url(to_json(&header)?), b64url(to_json(claims)?));
    let signature = crypto::sign(signing_input.as_bytes(), key, alg.algorithm())
        .map_err(|e| JoseError::Signing(e.to_string()))?;
    Ok(format!("{signing_input}.{signature}"))
}

mod erased {
    /// Object-safe "serialise to JSON bytes", so one closure can handle both
    /// the header map and the caller's claims type.
    pub trait Json {
        fn to_vec(&self) -> serde_json::Result<Vec<u8>>;
    }

    impl<T: serde::Serialize> Json for T {
        fn to_vec(&self) -> serde_json::Result<Vec<u8>> {
            serde_json::to_vec(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::keys::SigningKey;

    const PS256: &[SigningAlg] = &[SigningAlg::PS256];

    fn key() -> &'static SigningKey {
        crate::keys::test_support::shared_key()
    }

    fn jwks(key: &SigningKey) -> JwkSet {
        JwkSet {
            keys: vec![key.public_jwk().clone()],
        }
    }

    fn token(claims: &Value) -> String {
        key().sign(Some("JWT"), claims).unwrap()
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let jws = Jws::parse(&token(&json!({"sub": "a", "exp": 10})), PS256).unwrap();
        assert_eq!(jws.alg, SigningAlg::PS256);
        assert_eq!(jws.kid.as_deref(), Some(key().kid()));
        assert_eq!(jws.typ.as_deref(), Some("JWT"));
        assert_eq!(jws.str_claim("sub"), Some("a"));
        assert_eq!(jws.time_claim("exp"), Some(10));
        jws.verify(&jwks(key())).unwrap();
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let good = token(&json!({"sub": "a"}));
        let mut parts: Vec<&str> = good.split('.').collect();
        let forged = b64url(br#"{"sub":"b"}"#);
        parts[1] = &forged;
        let jws = Jws::parse(&parts.join("."), PS256).unwrap();
        assert_eq!(jws.verify(&jwks(key())), Err(JoseError::BadSignature));
    }

    #[test]
    fn signature_from_another_key_is_rejected() {
        let other = SigningKey::generate().unwrap();
        let jws = Jws::parse(&other.sign(None, &json!({})).unwrap(), PS256).unwrap();
        // Different kid, so no key is even a candidate.
        assert_eq!(jws.verify(&jwks(key())), Err(JoseError::NoMatchingKey));
    }

    #[test]
    fn alg_none_and_unlisted_algs_are_rejected() {
        for alg in ["none", "RS256", "HS256", "PS512"] {
            let header = b64url(json!({"alg": alg}).to_string());
            let token = format!("{header}.{}.sig", b64url("{}"));
            assert_eq!(
                Jws::parse(&token, PS256).unwrap_err(),
                JoseError::UnsupportedAlg(alg.to_owned()),
                "{alg}"
            );
        }
        // A FAPI algorithm that this deployment has not enabled.
        let header = b64url(json!({"alg": "ES256"}).to_string());
        let token = format!("{header}.{}.sig", b64url("{}"));
        assert!(matches!(
            Jws::parse(&token, PS256),
            Err(JoseError::UnsupportedAlg(_))
        ));
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        let h = b64url(json!({"alg": "PS256"}).to_string());
        let p = b64url("{}");
        for bad in [
            String::new(),
            "a.b".into(),
            "a.b.c.d".into(),
            format!("!!!.{p}.sig"),
            format!("{h}.!!!.sig"),
            format!("{h}.{}.sig", b64url("[1,2]")),
            format!("{h}.{p}."),
            format!("{}.{p}.sig", b64url(json!({"kid": "x"}).to_string())),
            format!(
                "{}.{p}.sig",
                b64url(json!({"alg": "PS256", "crit": ["x"]}).to_string())
            ),
        ] {
            assert!(
                matches!(Jws::parse(&bad, PS256), Err(JoseError::Malformed(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn key_selection_honours_use_alg_and_kid() {
        let jws = Jws::parse(&token(&json!({})), PS256).unwrap();

        let mut enc_only = key().public_jwk().clone();
        enc_only.common.public_key_use = Some(PublicKeyUse::Encryption);
        assert_eq!(
            jws.verify(&JwkSet {
                keys: vec![enc_only]
            }),
            Err(JoseError::NoMatchingKey)
        );

        let mut wrong_alg = key().public_jwk().clone();
        wrong_alg.common.key_algorithm = Some(jsonwebtoken::jwk::KeyAlgorithm::RS256);
        assert_eq!(
            jws.verify(&JwkSet {
                keys: vec![wrong_alg]
            }),
            Err(JoseError::NoMatchingKey)
        );

        let mut wrong_kid = key().public_jwk().clone();
        wrong_kid.common.key_id = Some("other".into());
        assert_eq!(
            jws.verify(&JwkSet {
                keys: vec![wrong_kid]
            }),
            Err(JoseError::NoMatchingKey)
        );
    }

    #[test]
    fn duplicate_kids_are_resolved_by_trying_each_candidate() {
        let other = SigningKey::generate().unwrap();
        let mut impostor = other.public_jwk().clone();
        impostor.common.key_id = Some(key().kid().to_owned());
        let set = JwkSet {
            keys: vec![impostor, key().public_jwk().clone()],
        };
        Jws::parse(&token(&json!({})), PS256)
            .unwrap()
            .verify(&set)
            .unwrap();
    }

    #[test]
    fn weak_rsa_keys_are_not_usable() {
        let mut weak = key().public_jwk().clone();
        if let AlgorithmParameters::RSA(rsa) = &mut weak.algorithm {
            rsa.n = b64url([0xffu8; 128]); // 1024-bit modulus
        }
        assert!(!key_supports_alg(&weak, SigningAlg::PS256));
        assert!(key_supports_alg(key().public_jwk(), SigningAlg::PS256));
        assert!(!key_supports_alg(key().public_jwk(), SigningAlg::ES256));
    }

    #[test]
    fn time_claims_accept_integers_and_floats_only() {
        let jws = Jws::parse(&token(&json!({"a": 5, "b": 5.9, "c": "5"})), PS256).unwrap();
        assert_eq!(jws.time_claim("a"), Some(5));
        assert_eq!(jws.time_claim("b"), Some(5));
        assert_eq!(jws.time_claim("c"), None);
        assert_eq!(jws.time_claim("missing"), None);
    }
}
