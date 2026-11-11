//! In-memory state: pushed requests, authorization codes, tokens and the
//! client assertion replay cache.
//!
//! Everything here is lost on restart and is not shared between instances,
//! which is acceptable for this version. Secrets (codes and tokens) are keyed
//! by their SHA-256 digest so the bearer values themselves are never held.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use crate::authz::AuthorizationRequest;
use crate::claims::ClaimsRequest;
use crate::util::{b64url, random_token, sha256};

/// Bytes of entropy in generated secrets (256 bits; FAPI 2.0 needs >= 128).
const SECRET_BYTES: usize = 32;

/// RFC 9126 §2.2 recommends this URN prefix for `request_uri` values.
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// Failed password attempts allowed against one pushed request.
pub const MAX_FAILED_LOGINS: u32 = 5;

/// A pushed authorization request awaiting the user.
#[derive(Debug, Clone)]
pub struct PushedRequest {
    pub request: AuthorizationRequest,
    pub expires_at: i64,
    pub failed_logins: u32,
}

/// What the user authorised. Shared by the code and every token derived from
/// it, so they can be revoked together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    pub client_id: String,
    /// The user's internal subject (not the pairwise value sent to clients).
    pub user_subject: String,
    pub scope: Vec<String>,
    pub claims: ClaimsRequest,
    pub auth_time: i64,
    /// Transaction identifier returned as the `txn` claim (ConnectID).
    pub txn: String,
}

#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    pub grant: Grant,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct AccessToken {
    pub grant: Grant,
    /// SHA-256 thumbprint of the client certificate the token is bound to
    /// (RFC 8705 §3).
    pub cert_thumbprint: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub grant: Grant,
    pub expires_at: i64,
}

/// Outcome of presenting an authorization code.
#[derive(Debug)]
pub enum CodeRedemption {
    Valid(Box<AuthorizationCode>),
    /// The code was already used. Tokens issued from it have been revoked.
    Replayed,
    /// Unknown, expired, or issued to a different client.
    Invalid,
}

#[derive(Debug)]
struct CodeEntry {
    code: AuthorizationCode,
    used: bool,
}

#[derive(Debug, Default)]
struct Inner {
    pushed: HashMap<String, PushedRequest>,
    codes: HashMap<String, CodeEntry>,
    access_tokens: HashMap<String, AccessToken>,
    refresh_tokens: HashMap<String, RefreshToken>,
    /// (client id, jti) -> assertion expiry.
    jtis: HashMap<(String, String), i64>,
}

#[derive(Debug, Default)]
pub struct Store {
    inner: Mutex<Inner>,
}

fn digest(secret: &str) -> String {
    b64url(sha256(secret))
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // The maps stay structurally valid even if a holder panicked.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Store a pushed request and return its `request_uri`.
    pub fn push_request(&self, request: AuthorizationRequest, expires_at: i64) -> String {
        let uri = format!("{REQUEST_URI_PREFIX}{}", random_token(SECRET_BYTES));
        self.lock().pushed.insert(
            uri.clone(),
            PushedRequest {
                request,
                expires_at,
                failed_logins: 0,
            },
        );
        uri
    }

    /// Look at a pushed request without consuming it. A `request_uri` stays
    /// usable until the user completes authorization, so that reloading the
    /// login page works (FAPI 2.0 §5.3.2.2 note 3).
    pub fn peek_request(&self, request_uri: &str, now: i64) -> Option<PushedRequest> {
        self.lock()
            .pushed
            .get(request_uri)
            .filter(|p| p.expires_at > now)
            .cloned()
    }

    /// Consume a pushed request. Returns `None` if it is unknown, expired or
    /// already consumed, which is what makes a `request_uri` one-time use.
    pub fn take_request(&self, request_uri: &str, now: i64) -> Option<PushedRequest> {
        self.lock()
            .pushed
            .remove(request_uri)
            .filter(|p| p.expires_at > now)
    }

    /// Count a failed login. Returns `false` once the limit is reached, at
    /// which point the request has been discarded.
    pub fn record_failed_login(&self, request_uri: &str) -> bool {
        let mut inner = self.lock();
        let Some(pushed) = inner.pushed.get_mut(request_uri) else {
            return false;
        };
        pushed.failed_logins += 1;
        if pushed.failed_logins >= MAX_FAILED_LOGINS {
            inner.pushed.remove(request_uri);
            return false;
        }
        true
    }

    pub fn create_code(&self, code: AuthorizationCode) -> String {
        let value = random_token(SECRET_BYTES);
        self.lock()
            .codes
            .insert(digest(&value), CodeEntry { code, used: false });
        value
    }

    /// Redeem an authorization code for `client_id`.
    ///
    /// Codes are single use (FAPI 2.0 §5.3.2.2-9). A second presentation
    /// revokes everything issued from the first (RFC 6749 §4.1.2).
    pub fn redeem_code(&self, code: &str, client_id: &str, now: i64) -> CodeRedemption {
        let mut inner = self.lock();
        let Some(entry) = inner.codes.get_mut(&digest(code)) else {
            return CodeRedemption::Invalid;
        };
        if entry.code.grant.client_id != client_id {
            return CodeRedemption::Invalid;
        }
        if entry.used {
            let grant_id = entry.code.grant.id.clone();
            inner.revoke_grant(&grant_id);
            return CodeRedemption::Replayed;
        }
        if entry.code.expires_at <= now {
            return CodeRedemption::Invalid;
        }
        entry.used = true;
        CodeRedemption::Valid(Box::new(entry.code.clone()))
    }

    pub fn issue_access_token(&self, token: AccessToken) -> String {
        let value = random_token(SECRET_BYTES);
        self.lock().access_tokens.insert(digest(&value), token);
        value
    }

    pub fn access_token(&self, token: &str, now: i64) -> Option<AccessToken> {
        self.lock()
            .access_tokens
            .get(&digest(token))
            .filter(|t| t.expires_at > now)
            .cloned()
    }

    pub fn issue_refresh_token(&self, token: RefreshToken) -> String {
        let value = random_token(SECRET_BYTES);
        self.lock().refresh_tokens.insert(digest(&value), token);
        value
    }

    pub fn refresh_token(&self, token: &str, now: i64) -> Option<RefreshToken> {
        self.lock()
            .refresh_tokens
            .get(&digest(token))
            .filter(|t| t.expires_at > now)
            .cloned()
    }

    /// Record a client assertion's `jti`. Returns `false` if it was already
    /// seen and has not yet expired, i.e. the assertion is a replay.
    pub fn record_jti(&self, client_id: &str, jti: &str, expires_at: i64, now: i64) -> bool {
        let mut inner = self.lock();
        let key = (client_id.to_owned(), jti.to_owned());
        if inner
            .jtis
            .get(&key)
            .is_some_and(|seen_until| *seen_until > now)
        {
            return false;
        }
        inner.jtis.insert(key, expires_at);
        true
    }

    /// Drop everything that has expired. Called periodically.
    pub fn purge(&self, now: i64) {
        let mut inner = self.lock();
        inner.pushed.retain(|_, p| p.expires_at > now);
        // Used codes are kept until they expire so replays can be detected.
        inner.codes.retain(|_, c| c.code.expires_at > now);
        inner.access_tokens.retain(|_, t| t.expires_at > now);
        inner.refresh_tokens.retain(|_, t| t.expires_at > now);
        inner.jtis.retain(|_, expires_at| *expires_at > now);
    }

    /// Number of live entries, for diagnostics and tests.
    pub fn len(&self) -> usize {
        let inner = self.lock();
        inner.pushed.len()
            + inner.codes.len()
            + inner.access_tokens.len()
            + inner.refresh_tokens.len()
            + inner.jtis.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Inner {
    fn revoke_grant(&mut self, grant_id: &str) {
        self.access_tokens.retain(|_, t| t.grant.id != grant_id);
        self.refresh_tokens.retain(|_, t| t.grant.id != grant_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::test_support::{CHALLENGE, valid_params};
    use crate::client::test_support::client_with_key;
    use crate::keys::test_support::shared_key;

    const NOW: i64 = 1_800_000_000;

    fn request() -> AuthorizationRequest {
        AuthorizationRequest::from_params(&client_with_key("rp", shared_key()), &valid_params())
            .unwrap()
    }

    fn grant(id: &str) -> Grant {
        Grant {
            id: id.to_owned(),
            client_id: "rp".to_owned(),
            user_subject: "u1".to_owned(),
            scope: vec!["openid".to_owned()],
            claims: ClaimsRequest::default(),
            auth_time: NOW,
            txn: "txn-1".to_owned(),
        }
    }

    fn code(grant_id: &str) -> AuthorizationCode {
        AuthorizationCode {
            grant: grant(grant_id),
            redirect_uri: "https://rp.example.com/cb".to_owned(),
            code_challenge: CHALLENGE.to_owned(),
            nonce: None,
            expires_at: NOW + 60,
        }
    }

    #[test]
    fn request_uri_is_unguessable_and_well_formed() {
        let store = Store::new();
        let a = store.push_request(request(), NOW + 60);
        let b = store.push_request(request(), NOW + 60);
        assert_ne!(a, b);
        assert!(a.starts_with(REQUEST_URI_PREFIX));
        assert!(a.len() - REQUEST_URI_PREFIX.len() >= 43);
    }

    #[test]
    fn pushed_request_can_be_peeked_repeatedly_but_taken_once() {
        let store = Store::new();
        let uri = store.push_request(request(), NOW + 60);
        assert!(store.peek_request(&uri, NOW).is_some());
        assert!(store.peek_request(&uri, NOW).is_some());
        assert!(store.take_request(&uri, NOW).is_some());
        assert!(store.take_request(&uri, NOW).is_none());
        assert!(store.peek_request(&uri, NOW).is_none());
    }

    #[test]
    fn pushed_request_expires() {
        let store = Store::new();
        let uri = store.push_request(request(), NOW + 60);
        assert!(store.peek_request(&uri, NOW + 59).is_some());
        assert!(store.peek_request(&uri, NOW + 60).is_none());
        assert!(store.take_request(&uri, NOW + 60).is_none());
        assert!(
            store
                .peek_request("urn:ietf:params:oauth:request_uri:unknown", NOW)
                .is_none()
        );
    }

    #[test]
    fn repeated_failed_logins_discard_the_request() {
        let store = Store::new();
        let uri = store.push_request(request(), NOW + 60);
        for _ in 1..MAX_FAILED_LOGINS {
            assert!(store.record_failed_login(&uri));
        }
        assert!(!store.record_failed_login(&uri));
        assert!(store.peek_request(&uri, NOW).is_none());
        assert!(!store.record_failed_login("unknown"));
    }

    #[test]
    fn code_is_single_use_and_replay_revokes_its_tokens() {
        let store = Store::new();
        let value = store.create_code(code("g1"));
        let CodeRedemption::Valid(redeemed) = store.redeem_code(&value, "rp", NOW) else {
            panic!("first redemption should succeed");
        };
        let access = store.issue_access_token(AccessToken {
            grant: redeemed.grant.clone(),
            cert_thumbprint: "tp".to_owned(),
            expires_at: NOW + 300,
        });
        let refresh = store.issue_refresh_token(RefreshToken {
            grant: redeemed.grant.clone(),
            expires_at: NOW + 900,
        });
        let other = store.issue_access_token(AccessToken {
            grant: grant("g2"),
            cert_thumbprint: "tp".to_owned(),
            expires_at: NOW + 300,
        });

        assert!(matches!(
            store.redeem_code(&value, "rp", NOW + 1),
            CodeRedemption::Replayed
        ));
        assert!(
            store.access_token(&access, NOW + 1).is_none(),
            "revoked with the grant"
        );
        assert!(
            store.refresh_token(&refresh, NOW + 1).is_none(),
            "revoked with the grant"
        );
        assert!(
            store.access_token(&other, NOW + 1).is_some(),
            "other grants are untouched"
        );
    }

    #[test]
    fn code_is_bound_to_its_client_and_expires() {
        let store = Store::new();
        let value = store.create_code(code("g1"));
        assert!(matches!(
            store.redeem_code(&value, "other", NOW),
            CodeRedemption::Invalid
        ));
        assert!(matches!(
            store.redeem_code("unknown", "rp", NOW),
            CodeRedemption::Invalid
        ));
        // A wrong client must not burn the code for its rightful owner.
        assert!(matches!(
            store.redeem_code(&value, "rp", NOW),
            CodeRedemption::Valid(_)
        ));

        let late = store.create_code(code("g3"));
        assert!(matches!(
            store.redeem_code(&late, "rp", NOW + 60),
            CodeRedemption::Invalid
        ));
    }

    #[test]
    fn tokens_expire_and_unknown_tokens_are_absent() {
        let store = Store::new();
        let access = store.issue_access_token(AccessToken {
            grant: grant("g1"),
            cert_thumbprint: "tp".to_owned(),
            expires_at: NOW + 300,
        });
        assert_eq!(
            store
                .access_token(&access, NOW + 299)
                .unwrap()
                .cert_thumbprint,
            "tp"
        );
        assert!(store.access_token(&access, NOW + 300).is_none());
        assert!(store.access_token("unknown", NOW).is_none());

        let refresh = store.issue_refresh_token(RefreshToken {
            grant: grant("g1"),
            expires_at: NOW + 10,
        });
        assert!(store.refresh_token(&refresh, NOW).is_some());
        assert!(store.refresh_token(&refresh, NOW + 10).is_none());
        // Presenting an access token as a refresh token finds nothing.
        assert!(store.refresh_token(&access, NOW).is_none());
    }

    #[test]
    fn jti_replay_is_detected_per_client_until_expiry() {
        let store = Store::new();
        assert!(store.record_jti("rp", "j1", NOW + 60, NOW));
        assert!(!store.record_jti("rp", "j1", NOW + 60, NOW + 1));
        assert!(
            store.record_jti("other", "j1", NOW + 60, NOW),
            "scoped to the client"
        );
        assert!(store.record_jti("rp", "j2", NOW + 60, NOW));
        assert!(
            store.record_jti("rp", "j1", NOW + 120, NOW + 60),
            "reusable once expired"
        );
    }

    #[test]
    fn purge_removes_only_expired_entries() {
        let store = Store::new();
        store.push_request(request(), NOW + 10);
        store.push_request(request(), NOW + 100);
        store.create_code(code("g1"));
        store.issue_access_token(AccessToken {
            grant: grant("g1"),
            cert_thumbprint: "tp".to_owned(),
            expires_at: NOW + 300,
        });
        store.record_jti("rp", "j1", NOW + 20, NOW);
        assert_eq!(store.len(), 5);

        store.purge(NOW + 50);
        assert_eq!(store.len(), 3, "short-lived request and jti are gone");
        store.purge(NOW + 1000);
        assert!(store.is_empty());
    }
}
