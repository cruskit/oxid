//! Authorization request parameters and their validation.
//!
//! Requests reach the provider only through the pushed authorization request
//! endpoint, as a signed request object. This module validates the
//! *parameters* carried in that object; signature and lifetime checks live in
//! [`crate::request_object`].

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::claims::ClaimsRequest;
use crate::client::Client;
use crate::error::{ErrorCode, OAuthError};
use crate::pkce;

/// `purpose` length limits, in characters (OAuth 2 Purpose §3).
pub const PURPOSE_MIN_CHARS: usize = 3;
pub const PURPOSE_MAX_CHARS: usize = 300;

/// `error_description` for a `purpose` that breaks the rules.
pub const INVALID_PURPOSE: &str = "invalid_purpose";

/// Whether `purpose` is acceptable: human-readable text of 3 to 300
/// characters. Control characters are refused as well, since the text is
/// recorded and shown to the user (OAuth 2 Purpose §9.1).
pub fn is_valid_purpose(purpose: &str) -> bool {
    (PURPOSE_MIN_CHARS..=PURPOSE_MAX_CHARS).contains(&purpose.chars().count())
        && !purpose.chars().any(char::is_control)
        && !purpose.trim().is_empty()
}

/// Upper bounds on opaque client-supplied values, to bound stored state.
/// FAPI 2.0 §5.3.2.2-14 requires supporting nonces of at least 64 characters.
const MAX_NONCE_LEN: usize = 512;
const MAX_STATE_LEN: usize = 2048;

pub const SCOPE_OPENID: &str = "openid";

/// A validated authorization request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    /// S256 PKCE challenge.
    pub code_challenge: String,
    pub claims: ClaimsRequest,
    /// Why the client is asking (OAuth 2 Purpose). Shown to the user at
    /// consent and recorded with the transaction.
    pub purpose: Option<String>,
}

impl AuthorizationRequest {
    pub fn is_openid(&self) -> bool {
        self.scope.iter().any(|s| s == SCOPE_OPENID)
    }

    /// Validate authorization parameters for `client`.
    ///
    /// `params` are the claims of a verified request object; only these are
    /// used, never parameters sent alongside it (ConnectID §4.2-3.9).
    pub fn from_params(client: &Client, params: &Map<String, Value>) -> Result<Self, OAuthError> {
        let string = |name: &str| -> Result<Option<&str>, OAuthError> {
            match params.get(name) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.as_str())),
                Some(_) => Err(OAuthError::invalid_request(format!(
                    "{name} must be a string"
                ))),
            }
        };
        let required = |name: &str| -> Result<&str, OAuthError> {
            string(name)?
                .filter(|v| !v.is_empty())
                .ok_or_else(|| OAuthError::invalid_request(format!("{name} is required")))
        };

        // A request object must not itself point at another request.
        if params.contains_key("request") || params.contains_key("request_uri") {
            return Err(OAuthError::invalid_request_object(
                "request and request_uri must not appear inside a request object",
            ));
        }

        if string("client_id")? != Some(client.id.as_str()) {
            return Err(OAuthError::invalid_request(
                "client_id in the request object must match the authenticated client",
            ));
        }

        // FAPI 2.0 §5.3.2.2-6: redirect_uri is mandatory in pushed requests.
        let redirect_uri = required("redirect_uri")?;
        if !client.has_redirect_uri(redirect_uri) {
            return Err(OAuthError::invalid_request(
                "redirect_uri is not registered for this client",
            ));
        }

        // FAPI 2.0 §5.3.2.2-1: only the authorization code flow.
        match required("response_type")? {
            "code" => {}
            _ => {
                return Err(OAuthError::new(
                    ErrorCode::UnsupportedResponseType,
                    "response_type must be 'code'",
                ));
            }
        }

        // ConnectID §4.2-3.5: query is the only response mode.
        if let Some(mode) = string("response_mode")?
            && mode != "query"
        {
            return Err(OAuthError::invalid_request("response_mode must be 'query'"));
        }

        // FAPI 2.0 §5.3.2.2-5: PKCE with S256 is mandatory.
        let code_challenge = required("code_challenge")?;
        match string("code_challenge_method")? {
            Some(pkce::METHOD_S256) => {}
            Some(_) => {
                return Err(OAuthError::invalid_request(
                    "code_challenge_method must be 'S256'",
                ));
            }
            None => {
                return Err(OAuthError::invalid_request(
                    "code_challenge_method is required",
                ));
            }
        }
        if !pkce::is_valid_challenge(code_challenge) {
            return Err(OAuthError::invalid_request(
                "code_challenge is not a valid S256 challenge",
            ));
        }

        let scope: Vec<String> = required("scope")?
            .split(' ')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if scope.is_empty() {
            return Err(OAuthError::invalid_scope("scope is empty"));
        }
        if let Some(unknown) = scope.iter().find(|s| !client.scopes.contains(*s)) {
            return Err(OAuthError::invalid_scope(format!(
                "scope '{unknown}' is not permitted for this client"
            )));
        }

        let state = string("state")?;
        if state.is_some_and(|s| s.len() > MAX_STATE_LEN) {
            return Err(OAuthError::invalid_request("state is too long"));
        }
        let nonce = string("nonce")?;
        if nonce.is_some_and(|n| n.len() > MAX_NONCE_LEN) {
            return Err(OAuthError::invalid_request("nonce is too long"));
        }

        let claims = match params.get("claims") {
            None | Some(Value::Null) => ClaimsRequest::default(),
            Some(value) => ClaimsRequest::parse(value).map_err(OAuthError::invalid_request)?,
        };

        // OAuth 2 Purpose §3: a violation fails the request with
        // `invalid_request` and this exact description.
        let purpose = string("purpose")?;
        if purpose.is_some_and(|p| !is_valid_purpose(p)) {
            return Err(OAuthError::invalid_request(INVALID_PURPOSE));
        }

        // There is no session to reuse yet, so a silent request cannot succeed.
        if string("prompt")?.is_some_and(|p| p.split(' ').any(|v| v == "none")) {
            return Err(OAuthError::new(
                ErrorCode::LoginRequired,
                "prompt=none is not supported: the user must authenticate",
            ));
        }

        Ok(Self {
            client_id: client.id.clone(),
            redirect_uri: redirect_uri.to_owned(),
            scope,
            state: state.map(str::to_owned),
            nonce: nonce.map(str::to_owned),
            code_challenge: code_challenge.to_owned(),
            claims,
            purpose: purpose.map(str::to_owned),
        })
    }
}

#[cfg(test)]
mod tests;
