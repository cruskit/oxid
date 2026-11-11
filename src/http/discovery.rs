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

pub async fn metadata(State(state): State<AppState>) -> Json<Value> {
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

pub async fn jwks(State(state): State<AppState>) -> Json<jsonwebtoken::jwk::JwkSet> {
    Json(state.signing_key.jwks())
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use serde_json::json;

    use crate::http::test_support::{Harness, json_body};
    use crate::http::{PATH_DISCOVERY, PATH_JWKS, PATH_OAUTH_METADATA};
    use crate::state::test_support::{ISSUER, MTLS};

    #[tokio::test]
    async fn metadata_meets_fapi2_and_connectid_requirements() {
        let harness = Harness::new();
        let response = harness.get(None, PATH_DISCOVERY).await;
        assert_eq!(response.status(), StatusCode::OK);
        let m = json_body(response).await;

        assert_eq!(m["issuer"], ISSUER);
        assert_eq!(m["authorization_endpoint"], format!("{ISSUER}/authorize"));
        assert_eq!(
            m["pushed_authorization_request_endpoint"],
            format!("{ISSUER}/par")
        );
        assert_eq!(m["require_pushed_authorization_requests"], true);
        assert_eq!(m["response_types_supported"], json!(["code"]));
        assert_eq!(m["response_modes_supported"], json!(["query"]));
        assert_eq!(m["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(m["authorization_response_iss_parameter_supported"], true);
        assert_eq!(m["tls_client_certificate_bound_access_tokens"], true);

        // ConnectID specifics.
        assert_eq!(m["subject_types_supported"], json!(["pairwise"]));
        assert_eq!(
            m["token_endpoint_auth_methods_supported"],
            json!(["private_key_jwt"])
        );
        for algs in [
            "id_token_signing_alg_values_supported",
            "request_object_signing_alg_values_supported",
            "token_endpoint_auth_signing_alg_values_supported",
        ] {
            assert_eq!(m[algs], json!(["PS256"]), "{algs}");
        }
        assert_eq!(m["claims_parameter_supported"], true);
        assert_eq!(m["trust_frameworks_supported"], json!(["au_connectid"]));
        // Only a ConnectID client is registered, so only that profile's
        // scope and claims are advertised (identity assurance 5.1).
        assert_eq!(m["scopes_supported"], json!(["openid"]));
        assert_eq!(m["verified_claims_supported"], true);
        let listed =
            |member: &str, claim: &str| m[member].as_array().unwrap().contains(&json!(claim));
        for claim in ["given_name", "middle_name", "family_name", "email"] {
            assert!(listed("claims_supported", claim), "{claim}");
        }
        for claim in ["birthdate", "phone_number", "address", "txn"] {
            assert!(listed("claims_supported", claim), "{claim}");
        }
        for claim in ["name", "nickname", "email_verified", "locale"] {
            assert!(!listed("claims_supported", claim), "{claim}");
        }
        assert!(!listed("claims_supported", "acr"));
        for claim in [
            "over16",
            "over18",
            "over21",
            "over25",
            "over65",
            "beneficiary_account_au",
            "beneficiary_account_au_payid",
            "beneficiary_account_international",
        ] {
            assert!(
                listed("claims_in_verified_claims_supported", claim),
                "{claim}"
            );
        }
        let aliases = &m["mtls_endpoint_aliases"];
        assert_eq!(aliases["token_endpoint"], format!("{MTLS}/token"));
        assert_eq!(aliases["userinfo_endpoint"], format!("{MTLS}/userinfo"));
        assert_eq!(
            aliases["pushed_authorization_request_endpoint"],
            format!("{MTLS}/par")
        );
    }

    #[tokio::test]
    async fn oauth_metadata_alias_serves_the_same_document() {
        let harness = Harness::new();
        let a = json_body(harness.get(None, PATH_DISCOVERY).await).await;
        let b = json_body(harness.get(None, PATH_OAUTH_METADATA).await).await;
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn jwks_publishes_the_signing_key() {
        let harness = Harness::new();
        let jwks = json_body(harness.get(None, PATH_JWKS).await).await;
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kid"], harness.state.signing_key.kid());
        assert!(keys[0].get("d").is_none());
    }
}
