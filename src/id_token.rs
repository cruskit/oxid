//! ID token and `UserInfo` claim assembly.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::claims;
use crate::client::Client;
use crate::state::AppState;
use crate::store::Grant;
use crate::subject;
use crate::user::User;
use crate::util::{b64url, sha256};

/// The `sub` that `client` sees for `user`.
pub fn subject_for(state: &AppState, client: &Client, user: &User) -> String {
    subject::pairwise(
        &state.pairwise_salt,
        &client.sector_identifier,
        &user.subject,
    )
}

/// `at_hash`: base64url of the left half of the access token's SHA-256
/// (OpenID Connect Core §3.1.3.6), binding the ID token to the access token.
fn at_hash(access_token: &str) -> String {
    b64url(&sha256(access_token)[..16])
}

/// Shown in place of `at_hash` when previewing an ID token: the real value
/// depends on the access token, which does not exist yet.
pub const AT_HASH_PLACEHOLDER: &str = "(set when the access token is issued)";

/// Manual changes to a set of claims: values to set and names to remove.
///
/// Edits are kept as a difference from what the user was shown, not as a
/// replacement, so that claims they left alone (`iat`, `exp`, `at_hash`)
/// still get their real values when the token is issued.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimEdits {
    pub set: Map<String, Value>,
    pub remove: BTreeSet<String>,
}

impl ClaimEdits {
    /// The changes that turn `base` into `edited`.
    pub fn between(base: &Map<String, Value>, edited: &Map<String, Value>) -> Self {
        Self {
            set: edited
                .iter()
                .filter(|(name, value)| base.get(*name) != Some(*value))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            remove: base
                .keys()
                .filter(|name| !edited.contains_key(*name))
                .cloned()
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty() && self.remove.is_empty()
    }

    pub fn apply(&self, claims: &mut Map<String, Value>) {
        for name in &self.remove {
            claims.remove(name);
        }
        for (name, value) in &self.set {
            claims.insert(name.clone(), value.clone());
        }
    }
}

/// Build and sign an ID token, applying any manual edits on the grant.
pub fn issue(
    state: &AppState,
    client: &Client,
    user: &User,
    grant: &Grant,
    nonce: Option<&str>,
    access_token: &str,
) -> Result<String, crate::jose::JoseError> {
    let mut claims = claims(state, client, user, grant, nonce, &at_hash(access_token));
    if let Some(edits) = &grant.id_token_edits {
        edits.apply(&mut claims);
    }
    state.signing_key.sign(Some("JWT"), &claims)
}

/// The ID token claims for a grant as they would be issued now, with
/// [`AT_HASH_PLACEHOLDER`] for `at_hash` and before any manual edits.
pub fn preview(
    state: &AppState,
    client: &Client,
    user: &User,
    grant: &Grant,
    nonce: Option<&str>,
) -> Map<String, Value> {
    claims(state, client, user, grant, nonce, AT_HASH_PLACEHOLDER)
}

/// The claims of an ID token, before signing.
fn claims(
    state: &AppState,
    client: &Client,
    user: &User,
    grant: &Grant,
    nonce: Option<&str>,
    at_hash: &str,
) -> Map<String, Value> {
    let now = state.now();
    // Requested identity claims first, so they can never override the
    // protocol claims set below.
    let mut claims = claims::release(
        user,
        client,
        &grant.claims.id_token,
        &[],
        &grant.shared_claims,
        now,
    );
    let protocol = json!({
        "iss": state.issuer,
        "sub": subject_for(state, client, user),
        "aud": client.id,
        "iat": now,
        "exp": now + state.security.id_token_ttl,
        "auth_time": grant.auth_time,
        // ConnectID: every ID token carries a transaction identifier.
        "txn": grant.txn,
        "at_hash": at_hash,
    });
    if let Value::Object(protocol) = protocol {
        claims.extend(protocol);
    }
    if let Some(nonce) = nonce {
        claims.insert("nonce".to_owned(), nonce.into());
    }
    claims
}

/// The `UserInfo` response body for a grant.
pub fn userinfo(
    state: &AppState,
    client: &Client,
    user: &User,
    grant: &Grant,
) -> Map<String, Value> {
    let mut claims = claims::release(
        user,
        client,
        &grant.claims.userinfo,
        &grant.scope,
        &grant.shared_claims,
        state.now(),
    );
    claims.insert("sub".to_owned(), subject_for(state, client, user).into());
    claims
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::ClaimsRequest;
    use crate::jose::{Jws, SigningAlg};
    use crate::state::test_support::{ISSUER, NOW, state};
    use crate::user::{DEMO_PASSWORD, DEMO_USERNAME};

    #[allow(clippy::needless_pass_by_value)]
    fn grant(claims: Value) -> Grant {
        Grant {
            id: "g1".to_owned(),
            client_id: "rp".to_owned(),
            user_subject: "demo-user-0001".to_owned(),
            scope: vec!["openid".to_owned()],
            claims: ClaimsRequest::parse(&claims).unwrap(),
            shared_claims: claims::test_support::everything(),
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

        let jws = Jws::parse(&token, &[SigningAlg::PS256]).unwrap();
        jws.verify(&state.signing_key.jwks()).unwrap();
        assert_eq!(jws.kid.as_deref(), Some(state.signing_key.kid()));
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
            jws.claims.get("given_name").is_none(),
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
        let jws = Jws::parse(&token, &[SigningAlg::PS256]).unwrap();
        assert!(!jws.claims.contains_key("nonce"));
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
        let jws = Jws::parse(&token, &[SigningAlg::PS256]).unwrap();
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
        let mut issued = Jws::parse(&token, &[SigningAlg::PS256]).unwrap().claims;
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
        let jws = Jws::parse(&token, &[SigningAlg::PS256]).unwrap();
        jws.verify(&state.signing_key.jwks()).unwrap();
        assert_eq!(jws.str_claim("given_name"), Some("Edited"));
        assert_eq!(jws.str_claim("sub"), Some("someone-else"));
        assert_eq!(jws.claims["custom"], json!({"nested": [1, 2]}));
        assert!(!jws.claims.contains_key("family_name"));
        assert!(!jws.claims.contains_key("nonce"));
        // Untouched claims are live, not frozen at preview time.
        assert_eq!(jws.time_claim("iat"), Some(NOW + 7));
        assert_eq!(jws.claims["at_hash"], at_hash("at"));
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
        let jws = Jws::parse(&token, &[SigningAlg::PS256]).unwrap();
        assert!(!jws.claims.contains_key("acr"));
        let verified = &jws.claims["verified_claims"];
        assert_eq!(verified["verification"]["trust_framework"], "au_connectid");
        assert_eq!(verified["claims"]["over18"], true);
        assert_eq!(
            verified["claims"]["beneficiary_account_au"]["account_bsb"],
            "123456"
        );
    }
}
