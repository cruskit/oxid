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

/// ConnectID `purpose` length limits, in characters.
pub const PURPOSE_MIN_CHARS: usize = 3;
pub const PURPOSE_MAX_CHARS: usize = 300;

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
    /// ConnectID: why the RP is asking, shown to the user at consent.
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

        let purpose = string("purpose")?;
        if let Some(purpose) = purpose {
            let chars = purpose.chars().count();
            if !(PURPOSE_MIN_CHARS..=PURPOSE_MAX_CHARS).contains(&chars) {
                return Err(OAuthError::invalid_request(format!(
                    "purpose must be between {PURPOSE_MIN_CHARS} and {PURPOSE_MAX_CHARS} characters"
                )));
            }
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
pub(crate) mod test_support {
    use serde_json::{Map, Value, json};

    /// S256 challenge for [`VERIFIER`].
    pub const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    pub const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    /// A complete, valid set of parameters for client `rp`.
    pub fn valid_params() -> Map<String, Value> {
        json!({
            "client_id": "rp",
            "redirect_uri": "https://rp.example.com/cb",
            "response_type": "code",
            "scope": "openid",
            "state": "st-1",
            "nonce": "n-1",
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
        })
        .as_object()
        .unwrap()
        .clone()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::test_support::valid_params;
    use super::*;
    use crate::client::test_support::client_with_key;
    use crate::keys::test_support::shared_key;

    fn client() -> Client {
        client_with_key("rp", shared_key())
    }

    fn with(name: &str, value: Value) -> Map<String, Value> {
        let mut params = valid_params();
        params.insert(name.to_owned(), value);
        params
    }

    fn without(name: &str) -> Map<String, Value> {
        let mut params = valid_params();
        params.remove(name);
        params
    }

    fn code(params: &Map<String, Value>) -> ErrorCode {
        AuthorizationRequest::from_params(&client(), params)
            .unwrap_err()
            .code
    }

    #[test]
    fn accepts_a_valid_request() {
        let request = AuthorizationRequest::from_params(&client(), &valid_params()).unwrap();
        assert_eq!(request.client_id, "rp");
        assert_eq!(request.scope, ["openid"]);
        assert_eq!(request.state.as_deref(), Some("st-1"));
        assert_eq!(request.nonce.as_deref(), Some("n-1"));
        assert!(request.is_openid());
        assert!(request.claims.is_empty());
        assert!(request.purpose.is_none());
    }

    #[test]
    fn state_and_nonce_are_optional() {
        let request = AuthorizationRequest::from_params(&client(), &without("state")).unwrap();
        assert!(request.state.is_none());
        let request = AuthorizationRequest::from_params(&client(), &without("nonce")).unwrap();
        assert!(request.nonce.is_none());
    }

    #[test]
    fn supports_64_character_nonce() {
        let nonce = "n".repeat(64);
        let request =
            AuthorizationRequest::from_params(&client(), &with("nonce", json!(nonce))).unwrap();
        assert_eq!(request.nonce.unwrap().len(), 64);
        assert_eq!(
            code(&with("nonce", json!("n".repeat(MAX_NONCE_LEN + 1)))),
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            code(&with("state", json!("s".repeat(MAX_STATE_LEN + 1)))),
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn response_type_must_be_code() {
        for bad in ["code id_token", "token", "id_token"] {
            assert_eq!(
                code(&with("response_type", json!(bad))),
                ErrorCode::UnsupportedResponseType,
                "{bad}"
            );
        }
        assert_eq!(code(&without("response_type")), ErrorCode::InvalidRequest);
    }

    #[test]
    fn redirect_uri_is_required_and_must_be_registered() {
        assert_eq!(code(&without("redirect_uri")), ErrorCode::InvalidRequest);
        assert_eq!(
            code(&with("redirect_uri", json!("https://evil.example.com/cb"))),
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn pkce_s256_is_mandatory() {
        assert_eq!(code(&without("code_challenge")), ErrorCode::InvalidRequest);
        assert_eq!(
            code(&without("code_challenge_method")),
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            code(&with("code_challenge_method", json!("plain"))),
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            code(&with("code_challenge", json!("short"))),
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn scope_must_be_permitted_for_the_client() {
        assert_eq!(code(&without("scope")), ErrorCode::InvalidRequest);
        assert_eq!(code(&with("scope", json!("  "))), ErrorCode::InvalidScope);
        assert_eq!(
            code(&with("scope", json!("openid payments"))),
            ErrorCode::InvalidScope
        );
        let request =
            AuthorizationRequest::from_params(&client(), &with("scope", json!("email openid")))
                .unwrap();
        assert_eq!(request.scope, ["email", "openid"]);
    }

    #[test]
    fn client_id_must_match_the_authenticated_client() {
        assert_eq!(
            code(&with("client_id", json!("other"))),
            ErrorCode::InvalidRequest
        );
        assert_eq!(code(&without("client_id")), ErrorCode::InvalidRequest);
    }

    #[test]
    fn nested_request_references_are_rejected() {
        assert_eq!(
            code(&with("request", json!("a.b.c"))),
            ErrorCode::InvalidRequestObject
        );
        assert_eq!(
            code(&with(
                "request_uri",
                json!("urn:ietf:params:oauth:request_uri:x")
            )),
            ErrorCode::InvalidRequestObject
        );
    }

    #[test]
    fn only_query_response_mode_is_allowed() {
        AuthorizationRequest::from_params(&client(), &with("response_mode", json!("query")))
            .unwrap();
        for bad in ["fragment", "jwt", "form_post"] {
            assert_eq!(
                code(&with("response_mode", json!(bad))),
                ErrorCode::InvalidRequest,
                "{bad}"
            );
        }
    }

    #[test]
    fn purpose_length_is_bounded_in_characters_not_bytes() {
        // Hangul Jamo are three bytes each in UTF-8.
        let ok = "\u{1100}".repeat(PURPOSE_MAX_CHARS);
        let request =
            AuthorizationRequest::from_params(&client(), &with("purpose", json!(ok))).unwrap();
        assert_eq!(request.purpose.unwrap().chars().count(), 300);

        let too_long = "\u{1100}".repeat(PURPOSE_MAX_CHARS + 1);
        assert_eq!(
            code(&with("purpose", json!(too_long))),
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            code(&with("purpose", json!("ab"))),
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn claims_parameter_is_parsed_and_validated() {
        let request = AuthorizationRequest::from_params(
            &client(),
            &with("claims", json!({"id_token": {"given_name": null}})),
        )
        .unwrap();
        assert!(request.claims.id_token.contains_key("given_name"));
        assert_eq!(
            code(&with("claims", json!({"id_token": 1}))),
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn non_string_parameters_are_rejected() {
        assert_eq!(code(&with("state", json!(123))), ErrorCode::InvalidRequest);
        assert_eq!(
            code(&with("scope", json!(["openid"]))),
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn prompt_none_yields_login_required() {
        assert_eq!(
            code(&with("prompt", json!("none"))),
            ErrorCode::LoginRequired
        );
        AuthorizationRequest::from_params(&client(), &with("prompt", json!("login consent")))
            .unwrap();
    }
}
