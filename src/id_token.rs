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
        state.pairwise_salt.expose(),
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
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
mod tests;
