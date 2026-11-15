use axum::http::StatusCode;
use serde_json::json;

use crate::http::{PATH_DISCOVERY, PATH_JWKS, PATH_OAUTH_METADATA};
use crate::testing::http::{Harness, json_body};
use crate::testing::state::{ISSUER, MTLS};

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
    let listed = |member: &str, claim: &str| m[member].as_array().unwrap().contains(&json!(claim));
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
