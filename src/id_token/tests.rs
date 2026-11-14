use super::*;
use crate::claims::ClaimsRequest;
use crate::jose::{SigningAlg, UnverifiedJws};
use crate::testing::state::{ISSUER, NOW, state};
use crate::user::{DEMO_PASSWORD, DEMO_USERNAME};

#[expect(clippy::needless_pass_by_value, reason = "called with json! literals")]
fn grant(claims: Value) -> Grant {
    Grant {
        id: "g1".to_owned(),
        client_id: "rp".to_owned(),
        user_subject: "demo-user-0001".to_owned(),
        scope: vec!["openid".to_owned()],
        claims: ClaimsRequest::parse(&claims).unwrap(),
        shared_claims: crate::testing::everything(),
        auth_time: NOW - 5,
        txn: "txn-123".to_owned(),
        purpose: None,
        id_token_edits: None,
    }
}

#[test]
fn id_token_has_required_claims_and_verifies() {
    let (state, _) = state();
    let client = state.clients.get("rp").unwrap();
    let user = state
        .users
        .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
        .unwrap();
    let token = issue(
        &state,
        &client,
        &user,
        &grant(json!({})),
        Some("n-1"),
        "at-value",
    )
    .unwrap();

    let jws = UnverifiedJws::parse(&token, &[SigningAlg::PS256])
        .unwrap()
        .verify(&state.signing_key.jwks())
        .unwrap();
    assert_eq!(jws.header().kid.as_deref(), Some(state.signing_key.kid()));
    assert_eq!(jws.str_claim("iss"), Some(ISSUER));
    assert_eq!(jws.str_claim("aud"), Some("rp"));
    assert_eq!(jws.str_claim("nonce"), Some("n-1"));
    assert_eq!(jws.str_claim("txn"), Some("txn-123"));
    assert_eq!(jws.time_claim("iat"), Some(NOW));
    assert_eq!(jws.time_claim("exp"), Some(NOW + 300));
    assert_eq!(jws.time_claim("auth_time"), Some(NOW - 5));
    assert_eq!(
        jws.str_claim("sub"),
        Some(subject_for(&state, &client, &user).as_str())
    );
    assert_ne!(
        jws.str_claim("sub"),
        Some("demo-user-0001"),
        "sub is pairwise"
    );
    assert!(
        jws.claims().get("given_name").is_none(),
        "nothing released unless requested"
    );
}

#[test]
fn nonce_is_omitted_when_not_requested() {
    let (state, _) = state();
    let client = state.clients.get("rp").unwrap();
    let user = state
        .users
        .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
        .unwrap();
    let token = issue(&state, &client, &user, &grant(json!({})), None, "at").unwrap();
    let jws = UnverifiedJws::parse(&token, &[SigningAlg::PS256])
        .unwrap()
        .skip_verification_in_tests();
    assert!(!jws.claims().contains_key("nonce"));
}

#[test]
fn requested_claims_are_included_but_cannot_override_protocol_claims() {
    let (state, _) = state();
    let client = state.clients.get("rp").unwrap();
    let user = state
        .users
        .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
        .unwrap();
    let grant = grant(json!({"id_token": {
        "given_name": null,
        "iss": {"value": "https://evil.example.com"},
        "txn": {"essential": true},
    }}));
    let token = issue(&state, &client, &user, &grant, None, "at").unwrap();
    let jws = UnverifiedJws::parse(&token, &[SigningAlg::PS256])
        .unwrap()
        .skip_verification_in_tests();
    assert_eq!(jws.str_claim("given_name"), Some("Alex"));
    assert_eq!(jws.str_claim("iss"), Some(ISSUER));
    assert_eq!(jws.str_claim("txn"), Some("txn-123"));
}

#[test]
fn edits_are_the_difference_between_preview_and_edited_claims() {
    let base = json!({"a": 1, "b": "x", "c": {"k": true}, "d": null});
    let edited = json!({"a": 1, "b": "y", "c": {"k": false}, "e": [1]});
    let edits = ClaimEdits::between(base.as_object().unwrap(), edited.as_object().unwrap());
    assert_eq!(
        Value::Object(edits.set.clone()),
        json!({"b": "y", "c": {"k": false}, "e": [1]})
    );
    assert_eq!(edits.remove.iter().collect::<Vec<_>>(), ["d"]);
    assert!(!edits.is_empty());

    let mut live = json!({"a": 2, "b": "x", "d": 0, "z": 9});
    edits.apply(live.as_object_mut().unwrap());
    assert_eq!(
        live,
        json!({"a": 2, "b": "y", "c": {"k": false}, "e": [1], "z": 9}),
        "untouched claims keep their live values"
    );

    let none = ClaimEdits::between(base.as_object().unwrap(), base.as_object().unwrap());
    assert!(none.is_empty());
}

#[test]
fn preview_matches_the_issued_token_apart_from_at_hash() {
    let (state, _) = state();
    let client = state.clients.get("rp").unwrap();
    let user = state
        .users
        .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
        .unwrap();
    let grant = grant(json!({"id_token": {"given_name": null}}));
    let preview = preview(&state, &client, &user, &grant, Some("n-1"));
    assert_eq!(preview["at_hash"], AT_HASH_PLACEHOLDER);

    let token = issue(&state, &client, &user, &grant, Some("n-1"), "at").unwrap();
    let mut issued = UnverifiedJws::parse(&token, &[SigningAlg::PS256])
        .unwrap()
        .skip_verification_in_tests()
        .into_claims();
    assert_eq!(issued["at_hash"], at_hash("at"));
    issued.insert("at_hash".to_owned(), AT_HASH_PLACEHOLDER.into());
    assert_eq!(issued, preview);
}

#[test]
fn manual_edits_are_applied_to_the_issued_token() {
    let (state, clock) = state();
    let client = state.clients.get("rp").unwrap();
    let user = state
        .users
        .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
        .unwrap();
    let mut grant = grant(json!({"id_token": {"given_name": null, "family_name": null}}));
    let base = preview(&state, &client, &user, &grant, Some("n-1"));
    let mut edited = base.clone();
    edited.insert("given_name".to_owned(), "Edited".into());
    edited.insert("custom".to_owned(), json!({"nested": [1, 2]}));
    edited.insert("sub".to_owned(), "someone-else".into());
    edited.remove("family_name");
    edited.remove("nonce");
    grant.id_token_edits = Some(ClaimEdits::between(&base, &edited));

    // Time passes between the preview and the token request.
    clock.advance(7);
    let token = issue(&state, &client, &user, &grant, Some("n-1"), "at").unwrap();
    let jws = UnverifiedJws::parse(&token, &[SigningAlg::PS256])
        .unwrap()
        .verify(&state.signing_key.jwks())
        .unwrap();
    assert_eq!(jws.str_claim("given_name"), Some("Edited"));
    assert_eq!(jws.str_claim("sub"), Some("someone-else"));
    assert_eq!(jws.claims()["custom"], json!({"nested": [1, 2]}));
    assert!(!jws.claims().contains_key("family_name"));
    assert!(!jws.claims().contains_key("nonce"));
    // Untouched claims are live, not frozen at preview time.
    assert_eq!(jws.time_claim("iat"), Some(NOW + 7));
    assert_eq!(jws.claims()["at_hash"], at_hash("at"));
}

#[test]
fn at_hash_is_left_half_of_sha256() {
    // OIDC Core example-style check: 16 bytes -> 22 base64url characters.
    assert_eq!(at_hash("access-token").len(), 22);
    assert_ne!(at_hash("a"), at_hash("b"));
}

#[test]
fn userinfo_returns_sub_and_requested_claims_only() {
    let (state, _) = state();
    let client = state.clients.get("rp").unwrap();
    let user = state
        .users
        .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
        .unwrap();
    let grant = grant(json!({"userinfo": {"email": null}, "id_token": {"given_name": null}}));
    let body = userinfo(&state, &client, &user, &grant);
    assert_eq!(body["sub"], subject_for(&state, &client, &user));
    assert_eq!(body["email"], "alex.citizen@example.com");
    assert_eq!(body.len(), 2, "{body:?}");
}

#[test]
fn id_token_carries_connectid_verified_claims_and_never_acr() {
    let (state, _) = state();
    let client = state.clients.get("rp").unwrap();
    let user = state
        .users
        .authenticate(DEMO_USERNAME, DEMO_PASSWORD)
        .unwrap();
    let grant = grant(json!({"id_token": {
        "acr": {"essential": true, "value": "urn:mace:incommon:iap:silver"},
        "verified_claims": {
            "verification": {"trust_framework": {"value": "au_connectid"}},
            "claims": {"over18": null, "beneficiary_account_au": null},
        },
    }}));
    let token = issue(&state, &client, &user, &grant, None, "at").unwrap();
    let jws = UnverifiedJws::parse(&token, &[SigningAlg::PS256])
        .unwrap()
        .skip_verification_in_tests();
    assert!(!jws.claims().contains_key("acr"));
    let verified = &jws.claims()["verified_claims"];
    assert_eq!(verified["verification"]["trust_framework"], "au_connectid");
    assert_eq!(verified["claims"]["over18"], true);
    assert_eq!(
        verified["claims"]["beneficiary_account_au"]["account_bsb"],
        "123456"
    );
}
