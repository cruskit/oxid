//! Signed authorization request objects (JAR, RFC 9101).
//!
//! ConnectID §4.2-3.8 to 3.11: request objects are mandatory, signed with
//! PS256, carry `nbf` no more than 10 minutes in the past and `exp` no more
//! than 10 minutes after `nbf`.

use serde_json::{Map, Value};

use crate::client::Client;
use crate::config::SecurityConfig;
use crate::error::OAuthError;
use crate::jose::{Jws, SigningAlg};

/// The only algorithm accepted for request objects (ConnectID §4.2-3.8).
pub const ALLOWED_ALGS: &[SigningAlg] = &[SigningAlg::PS256];

/// Verify a request object and return its claims (the authorization
/// parameters).
pub fn verify(
    request: &str,
    client: &Client,
    issuer: &str,
    security: &SecurityConfig,
    now: i64,
) -> Result<Map<String, Value>, OAuthError> {
    let bad = |reason: String| OAuthError::invalid_request_object(reason);

    let jws = Jws::parse(request, ALLOWED_ALGS).map_err(|e| bad(e.to_string()))?;
    jws.verify(&client.jwks).map_err(|e| bad(e.to_string()))?;

    // RFC 9101 §10.8 defines this type; plain "JWT" is what most clients send.
    if let Some(typ) = &jws.typ
        && !typ.eq_ignore_ascii_case("oauth-authz-req+jwt")
        && !typ.eq_ignore_ascii_case("JWT")
    {
        return Err(bad(format!("unexpected typ '{typ}'")));
    }

    if jws.str_claim("iss") != Some(client.id.as_str()) {
        return Err(bad("iss must be the client_id".to_owned()));
    }
    if !audience_contains(jws.claims.get("aud"), issuer) {
        return Err(bad("aud must contain the issuer identifier".to_owned()));
    }

    let exp = jws
        .time_claim("exp")
        .ok_or_else(|| bad("exp is required".to_owned()))?;
    let nbf = jws
        .time_claim("nbf")
        .ok_or_else(|| bad("nbf is required".to_owned()))?;

    if exp <= now {
        return Err(bad("request object has expired".to_owned()));
    }
    if nbf > now + security.clock_skew {
        return Err(bad("nbf is in the future".to_owned()));
    }
    if nbf < now - security.request_object_max_age {
        return Err(bad(format!(
            "nbf is more than {} seconds in the past",
            security.request_object_max_age
        )));
    }
    if exp - nbf > security.request_object_max_lifetime {
        return Err(bad(format!(
            "exp is more than {} seconds after nbf",
            security.request_object_max_lifetime
        )));
    }
    if jws
        .time_claim("iat")
        .is_some_and(|iat| iat > now + security.clock_skew)
    {
        return Err(bad("iat is in the future".to_owned()));
    }

    Ok(jws.claims)
}

/// `aud` may be a single string or an array of strings (RFC 7519 §4.1.3).
fn audience_contains(aud: Option<&Value>, expected: &str) -> bool {
    match aud {
        Some(Value::String(single)) => single == expected,
        Some(Value::Array(many)) => many.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
