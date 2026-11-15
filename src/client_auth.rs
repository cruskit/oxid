//! Client authentication with `private_key_jwt` (OpenID Connect Core §9,
//! RFC 7523), the only method ConnectID permits (§4.2-3.4).

use std::sync::Arc;

use serde_json::Value;

use crate::epoch::{Seconds, Timestamp};
use crate::client::{Client, ClientRegistry};
use crate::error::OAuthError;
use crate::jose::{SigningAlg, UnverifiedJws};

pub(crate) const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Algorithms accepted for client assertions (ConnectID §5).
pub(crate) const ALLOWED_ALGS: &[SigningAlg] = &[SigningAlg::PS256];

/// Longest an assertion may remain valid. Bounds how long its `jti` must be
/// remembered for replay detection.
const MAX_ASSERTION_LIFETIME: Seconds = Seconds::minutes(10);

/// The client authentication parameters of a token or PAR request.
#[derive(Debug, Clone, Copy, Default)]
#[expect(
    clippy::struct_field_names,
    reason = "named after the RFC 7523 request parameters"
)]
pub(crate) struct Credentials<'a> {
    pub client_id: Option<&'a str>,
    pub client_assertion_type: Option<&'a str>,
    pub client_assertion: Option<&'a str>,
}

/// A verified assertion: who it is from, and what must be recorded to stop it
/// being replayed.
#[derive(Debug, Clone)]
pub(crate) struct Authenticated {
    pub client: Arc<Client>,
    pub jti: String,
    pub expires_at: Timestamp,
}

/// Verify a `private_key_jwt` assertion.
///
/// The caller must then record `(client, jti)` until `expires_at` and reject
/// the request if it was already present; see [`crate::store::Store::record_jti`].
pub(crate) fn authenticate(
    credentials: Credentials<'_>,
    clients: &dyn ClientRegistry,
    issuer: &str,
    clock_skew: Seconds,
    now: Timestamp,
) -> Result<Authenticated, OAuthError> {
    let bad = |reason: &str| OAuthError::invalid_client(reason.to_owned());

    let assertion = credentials
        .client_assertion
        .ok_or_else(|| bad("client_assertion is required"))?;
    if credentials.client_assertion_type != Some(ASSERTION_TYPE) {
        return Err(bad("client_assertion_type must be the jwt-bearer type"));
    }

    let unverified = UnverifiedJws::parse(assertion, ALLOWED_ALGS)
        .map_err(|e| OAuthError::invalid_client(e.to_string()))?;

    // `iss` selects the client whose keys verify the signature; nothing else
    // in the assertion is trusted until that has happened.
    let claimed = unverified
        .unverified_issuer()
        .ok_or_else(|| bad("assertion has no iss"))?;
    if credentials.client_id.is_some_and(|id| id != claimed) {
        return Err(bad("client_id does not match the assertion issuer"));
    }
    let client = clients.get(claimed).ok_or_else(|| bad("unknown client"))?;
    let jws = unverified
        .verify(&client.jwks)
        .map_err(|e| OAuthError::invalid_client(e.to_string()))?;

    if jws.str_claim("sub") != Some(client.id.as_str()) {
        return Err(bad("assertion sub must be the client_id"));
    }
    // FAPI 2.0 §5.3.2.1-8: the audience must be the issuer identifier, as a
    // single string. Endpoint URLs and arrays are not accepted.
    if jws.claims().get("aud") != Some(&Value::String(issuer.to_owned())) {
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
mod tests;
