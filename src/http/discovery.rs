//! Provider metadata (OpenID Connect Discovery, RFC 8414) and the JWK Set.

use axum::Json;
use axum::extract::State;

use super::{PATH_AUTHORIZE, PATH_JWKS, PATH_PAR, PATH_TOKEN, PATH_USERINFO};
use crate::claims;
use crate::client::{GrantType, Profile};
use crate::keys::SigningKey;
use crate::pkce;
use crate::state::AppState;

/// The provider's metadata (OpenID Connect Discovery §3, RFC 8414 §2).
#[derive(Debug, serde::Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the members are the metadata the specifications define"
)]
pub(super) struct ProviderMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    pushed_authorization_request_endpoint: String,
    jwks_uri: String,
    /// ConnectID §4.2-3.7: mTLS aliases for token, PAR and `UserInfo`.
    mtls_endpoint_aliases: MtlsAliases,

    scopes_supported: Vec<&'static str>,
    response_types_supported: [&'static str; 1],
    response_modes_supported: [&'static str; 1],
    grant_types_supported: &'static [GrantType],
    subject_types_supported: [&'static str; 1],
    code_challenge_methods_supported: [&'static str; 1],

    id_token_signing_alg_values_supported: [&'static str; 1],
    request_object_signing_alg_values_supported: [&'static str; 1],
    token_endpoint_auth_methods_supported: [&'static str; 1],
    token_endpoint_auth_signing_alg_values_supported: [&'static str; 1],

    require_pushed_authorization_requests: bool,
    require_signed_request_object: bool,
    request_parameter_supported: bool,
    request_uri_parameter_supported: bool,
    authorization_response_iss_parameter_supported: bool,
    tls_client_certificate_bound_access_tokens: bool,

    claims_parameter_supported: bool,
    claim_types_supported: [&'static str; 1],
    claims_supported: Vec<&'static str>,

    /// OpenID Connect for Identity Assurance metadata, present when
    /// ConnectID clients are registered.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    identity_assurance: Option<IdentityAssurance>,
}

#[derive(Debug, serde::Serialize)]
#[expect(clippy::struct_field_names, reason = "named by RFC 8705 §5")]
struct MtlsAliases {
    token_endpoint: String,
    userinfo_endpoint: String,
    pushed_authorization_request_endpoint: String,
}

#[derive(Debug, serde::Serialize)]
#[expect(
    clippy::struct_field_names,
    reason = "named by OpenID Connect for Identity Assurance"
)]
struct IdentityAssurance {
    verified_claims_supported: bool,
    trust_frameworks_supported: [&'static str; 1],
    claims_in_verified_claims_supported: Vec<String>,
}

pub(super) async fn metadata(State(state): State<AppState>) -> Json<ProviderMetadata> {
    let alg = [SigningKey::ALG.as_str()];
    // Advertise what the registered clients' profiles offer, no more.
    let profiles = state.clients.profiles();
    let connectid = profiles.contains(&Profile::Connectid);

    Json(ProviderMetadata {
        issuer: state.issuer.to_string(),
        authorization_endpoint: state.url(PATH_AUTHORIZE),
        token_endpoint: state.url(PATH_TOKEN),
        userinfo_endpoint: state.url(PATH_USERINFO),
        pushed_authorization_request_endpoint: state.url(PATH_PAR),
        jwks_uri: state.url(PATH_JWKS),
        mtls_endpoint_aliases: MtlsAliases {
            token_endpoint: state.mtls_url(PATH_TOKEN),
            userinfo_endpoint: state.mtls_url(PATH_USERINFO),
            pushed_authorization_request_endpoint: state.mtls_url(PATH_PAR),
        },

        scopes_supported: claims::scopes_supported(&profiles),
        response_types_supported: ["code"],
        response_modes_supported: ["query"],
        grant_types_supported: GrantType::ALL,
        subject_types_supported: ["pairwise"],
        code_challenge_methods_supported: [pkce::METHOD_S256],

        id_token_signing_alg_values_supported: alg,
        request_object_signing_alg_values_supported: alg,
        token_endpoint_auth_methods_supported: ["private_key_jwt"],
        token_endpoint_auth_signing_alg_values_supported: alg,

        require_pushed_authorization_requests: true,
        require_signed_request_object: true,
        request_parameter_supported: true,
        request_uri_parameter_supported: false,
        authorization_response_iss_parameter_supported: true,
        tls_client_certificate_bound_access_tokens: true,

        claims_parameter_supported: true,
        claim_types_supported: ["normal"],
        claims_supported: claims::claims_supported(&profiles),

        identity_assurance: connectid.then(|| IdentityAssurance {
            verified_claims_supported: true,
            trust_frameworks_supported: [claims::TRUST_FRAMEWORK],
            claims_in_verified_claims_supported: claims::verified_claims_supported(),
        }),
    })
}

pub(super) async fn jwks(State(state): State<AppState>) -> Json<jsonwebtoken::jwk::JwkSet> {
    Json(state.signing_key.jwks())
}

#[cfg(test)]
mod tests;
