//! Provider metadata (OpenID Connect Discovery, RFC 8414) and the JWK Set.

use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};

use super::{PATH_AUTHORIZE, PATH_JWKS, PATH_PAR, PATH_TOKEN, PATH_USERINFO};
use crate::claims;
use crate::client::Profile;
use crate::keys::SigningKey;
use crate::pkce;
use crate::state::AppState;

pub(super) async fn metadata(State(state): State<AppState>) -> Json<Value> {
    let alg = [SigningKey::ALG.as_str()];
    // Advertise what the registered clients' profiles offer, no more.
    let profiles = state.clients.profiles();
    let connectid = profiles.contains(&Profile::Connectid);

    let mut metadata = json!({
        "issuer": state.issuer,
        "authorization_endpoint": state.url(PATH_AUTHORIZE),
        "token_endpoint": state.url(PATH_TOKEN),
        "userinfo_endpoint": state.url(PATH_USERINFO),
        "pushed_authorization_request_endpoint": state.url(PATH_PAR),
        "jwks_uri": state.url(PATH_JWKS),

        // ConnectID §4.2-3.7: mTLS aliases for token, PAR and UserInfo.
        "mtls_endpoint_aliases": {
            "token_endpoint": state.mtls_url(PATH_TOKEN),
            "userinfo_endpoint": state.mtls_url(PATH_USERINFO),
            "pushed_authorization_request_endpoint": state.mtls_url(PATH_PAR),
        },

        "scopes_supported": claims::scopes_supported(&profiles),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["pairwise"],
        "code_challenge_methods_supported": [pkce::METHOD_S256],

        "id_token_signing_alg_values_supported": alg,
        "request_object_signing_alg_values_supported": alg,
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": alg,

        "require_pushed_authorization_requests": true,
        "require_signed_request_object": true,
        "request_parameter_supported": true,
        "request_uri_parameter_supported": false,
        "authorization_response_iss_parameter_supported": true,
        "tls_client_certificate_bound_access_tokens": true,

        "claims_parameter_supported": true,
        "claim_types_supported": ["normal"],
        "claims_supported": claims::claims_supported(&profiles),
    });
    // OpenID Connect for Identity Assurance metadata, for ConnectID clients.
    if connectid {
        metadata["verified_claims_supported"] = true.into();
        metadata["trust_frameworks_supported"] = json!([claims::TRUST_FRAMEWORK]);
        metadata["claims_in_verified_claims_supported"] =
            claims::verified_claims_supported().into();
    }
    Json(metadata)
}

pub(super) async fn jwks(State(state): State<AppState>) -> Json<jsonwebtoken::jwk::JwkSet> {
    Json(state.signing_key.jwks())
}

#[cfg(test)]
mod tests;
