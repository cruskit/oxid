//! Client authentication with `private_key_jwt` (OpenID Connect Core §9,
//! RFC 7523), the only method ConnectID permits (§4.2-3.4).

use std::sync::Arc;

use serde_json::Value;

use crate::client::{Client, ClientRegistry};
use crate::error::OAuthError;
use crate::jose::{Jws, SigningAlg};

pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Algorithms accepted for client assertions (ConnectID §5).
pub const ALLOWED_ALGS: &[SigningAlg] = &[SigningAlg::PS256];

/// Longest an assertion may remain valid. Bounds how long its `jti` must be
/// remembered for replay detection.
const MAX_ASSERTION_LIFETIME: i64 = 600;

/// The client authentication parameters of a token or PAR request.
#[derive(Debug, Clone, Copy, Default)]
pub struct Credentials<'a> {
    pub client_id: Option<&'a str>,
    pub client_assertion_type: Option<&'a str>,
    pub client_assertion: Option<&'a str>,
}

/// A verified assertion: who it is from, and what must be recorded to stop it
/// being replayed.
#[derive(Debug, Clone)]
pub struct Authenticated {
    pub client: Arc<Client>,
    pub jti: String,
    pub expires_at: i64,
}

/// Verify a `private_key_jwt` assertion.
///
/// The caller must then record `(client, jti)` until `expires_at` and reject
/// the request if it was already present; see [`crate::store::Store::record_jti`].
pub fn authenticate(
    credentials: Credentials<'_>,
    clients: &dyn ClientRegistry,
    issuer: &str,
    clock_skew: i64,
    now: i64,
) -> Result<Authenticated, OAuthError> {
    let bad = |reason: &str| OAuthError::invalid_client(reason.to_owned());

    let assertion = credentials
        .client_assertion
        .ok_or_else(|| bad("client_assertion is required"))?;
    if credentials.client_assertion_type != Some(ASSERTION_TYPE) {
        return Err(bad("client_assertion_type must be the jwt-bearer type"));
    }

    let jws = Jws::parse(assertion, ALLOWED_ALGS)
        .map_err(|e| OAuthError::invalid_client(e.to_string()))?;

    // `iss` selects the client whose keys verify the signature; nothing else
    // in the assertion is trusted until that has happened.
    let claimed = jws
        .str_claim("iss")
        .ok_or_else(|| bad("assertion has no iss"))?;
    if credentials.client_id.is_some_and(|id| id != claimed) {
        return Err(bad("client_id does not match the assertion issuer"));
    }
    let client = clients.get(claimed).ok_or_else(|| bad("unknown client"))?;
    jws.verify(&client.jwks)
        .map_err(|e| OAuthError::invalid_client(e.to_string()))?;

    if jws.str_claim("sub") != Some(client.id.as_str()) {
        return Err(bad("assertion sub must be the client_id"));
    }
    // FAPI 2.0 §5.3.2.1-8: the audience must be the issuer identifier, as a
    // single string. Endpoint URLs and arrays are not accepted.
    if jws.claims.get("aud") != Some(&Value::String(issuer.to_owned())) {
        return Err(bad(
            "assertion aud must be the issuer identifier as a string",
        ));
    }

    let exp = jws
        .time_claim("exp")
        .ok_or_else(|| bad("assertion has no exp"))?;
    if exp <= now {
        return Err(bad("assertion has expired"));
    }
    if exp > now + MAX_ASSERTION_LIFETIME + clock_skew {
        return Err(bad("assertion exp is too far in the future"));
    }
    for claim in ["iat", "nbf"] {
        if jws.time_claim(claim).is_some_and(|t| t > now + clock_skew) {
            return Err(bad("assertion is not yet valid"));
        }
    }

    let jti = jws
        .str_claim("jti")
        .filter(|jti| !jti.is_empty())
        .ok_or_else(|| bad("assertion has no jti"))?
        .to_owned();

    Ok(Authenticated {
        client,
        jti,
        expires_at: exp,
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    use serde_json::{Value, json};

    /// Claims of a valid assertion from client `rp`.
    pub fn valid_assertion(issuer: &str, now: i64) -> Value {
        json!({
            "iss": "rp",
            "sub": "rp",
            "aud": issuer,
            "jti": "jti-1",
            "iat": now,
            "exp": now + 60,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::test_support::valid_assertion;
    use super::*;
    use crate::client::StaticClientRegistry;
    use crate::client::test_support::client_with_key;
    use crate::error::ErrorCode;
    use crate::keys::SigningKey;
    use crate::keys::test_support::shared_key;
    use crate::util::b64url;

    const ISSUER: &str = "https://op.example.com";
    const NOW: i64 = 1_800_000_000;

    fn registry() -> StaticClientRegistry {
        StaticClientRegistry::new([client_with_key("rp", shared_key())]).unwrap()
    }

    fn attempt(assertion: &str, client_id: Option<&str>) -> Result<Authenticated, OAuthError> {
        authenticate(
            Credentials {
                client_id,
                client_assertion_type: Some(ASSERTION_TYPE),
                client_assertion: Some(assertion),
            },
            &registry(),
            ISSUER,
            10,
            NOW,
        )
    }

    fn check(claims: &Value) -> Result<Authenticated, OAuthError> {
        attempt(&shared_key().sign(Some("JWT"), claims).unwrap(), None)
    }

    fn with(name: &str, value: Value) -> Value {
        let mut claims = valid_assertion(ISSUER, NOW);
        claims[name] = value;
        claims
    }

    fn without(name: &str) -> Value {
        let mut claims = valid_assertion(ISSUER, NOW);
        claims.as_object_mut().unwrap().remove(name);
        claims
    }

    fn rejected(claims: &Value) {
        assert_eq!(
            check(claims).unwrap_err().code,
            ErrorCode::InvalidClient,
            "{claims}"
        );
    }

    #[test]
    fn accepts_a_valid_assertion() {
        let auth = check(&valid_assertion(ISSUER, NOW)).unwrap();
        assert_eq!(auth.client.id, "rp");
        assert_eq!(auth.jti, "jti-1");
        assert_eq!(auth.expires_at, NOW + 60);
    }

    #[test]
    fn client_id_parameter_must_agree_with_the_assertion() {
        let token = shared_key()
            .sign(None, &valid_assertion(ISSUER, NOW))
            .unwrap();
        attempt(&token, Some("rp")).unwrap();
        assert!(attempt(&token, Some("other")).is_err());
    }

    #[test]
    fn requires_assertion_and_correct_type() {
        let token = shared_key()
            .sign(None, &valid_assertion(ISSUER, NOW))
            .unwrap();
        let missing = authenticate(Credentials::default(), &registry(), ISSUER, 10, NOW);
        assert_eq!(missing.unwrap_err().code, ErrorCode::InvalidClient);

        let wrong_type = authenticate(
            Credentials {
                client_id: None,
                client_assertion_type: Some(
                    "urn:ietf:params:oauth:client-assertion-type:saml2-bearer",
                ),
                client_assertion: Some(&token),
            },
            &registry(),
            ISSUER,
            10,
            NOW,
        );
        assert!(wrong_type.is_err());
    }

    #[test]
    fn audience_must_be_the_issuer_as_a_single_string() {
        rejected(&with("aud", json!(format!("{ISSUER}/token"))));
        rejected(&with("aud", json!(format!("{ISSUER}/par"))));
        rejected(&with("aud", json!([ISSUER])));
        rejected(&with("aud", json!([ISSUER, format!("{ISSUER}/token")])));
        rejected(&without("aud"));
    }

    #[test]
    fn iss_and_sub_must_both_be_the_client() {
        rejected(&with("sub", json!("someone-else")));
        rejected(&without("sub"));
        rejected(&with("iss", json!("unknown-client")));
        rejected(&without("iss"));
    }

    #[test]
    fn expiry_is_enforced() {
        rejected(&without("exp"));
        rejected(&with("exp", json!(NOW)));
        rejected(&with("exp", json!(NOW - 300)));
        rejected(&with("exp", json!(NOW + 86_400)));
    }

    #[test]
    fn iat_and_nbf_tolerate_small_skew_only() {
        check(&with("iat", json!(NOW + 10))).unwrap();
        rejected(&with("iat", json!(NOW + 61)));
        check(&with("nbf", json!(NOW + 10))).unwrap();
        rejected(&with("nbf", json!(NOW + 61)));
    }

    #[test]
    fn jti_is_mandatory() {
        rejected(&without("jti"));
        rejected(&with("jti", json!("")));
    }

    #[test]
    fn rejects_assertions_signed_by_another_key() {
        let attacker = SigningKey::generate().unwrap();
        let token = attacker.sign(None, &valid_assertion(ISSUER, NOW)).unwrap();
        assert_eq!(
            attempt(&token, None).unwrap_err().code,
            ErrorCode::InvalidClient
        );
    }

    #[test]
    fn rejects_rs256_and_unsigned_assertions() {
        let payload = b64url(valid_assertion(ISSUER, NOW).to_string());
        for alg in ["RS256", "none", "HS256"] {
            let token = format!("{}.{payload}.c2ln", b64url(json!({"alg": alg}).to_string()));
            assert_eq!(
                attempt(&token, None).unwrap_err().code,
                ErrorCode::InvalidClient,
                "{alg}"
            );
        }
        assert!(attempt("not-a-jwt", None).is_err());
    }
}
