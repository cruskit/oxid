//! Server-side state: pushed requests, authorization codes, tokens, the
//! client assertion replay cache, consent records and generated secrets.
//!
//! [`Store`] holds the rules (expiry, single use, replay detection,
//! revocation). Where the data lives is decided by a [`Backend`]:
//!
//! * [`MemoryBackend`]: in this process. Lost on restart and not shared
//!   between instances; the default, and right for a single local server.
//! * `DynamoBackend` (cargo feature `aws`): an Amazon DynamoDB table, for
//!   deployments where consecutive requests may reach different instances,
//!   such as AWS Lambda.
//!
//! Secrets (request URIs, codes and tokens) are keyed by their SHA-256
//! digest, so the bearer values themselves are never held.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::authz::AuthorizationRequest;
use crate::claims::ClaimsRequest;
use crate::error::OAuthError;
use crate::util::{b64url, random_token, sha256};

#[cfg(feature = "aws")]
pub mod dynamodb;
mod memory;

pub use memory::MemoryBackend;

/// Bytes of entropy in generated secrets (256 bits; FAPI 2.0 needs >= 128).
const SECRET_BYTES: usize = 32;

/// RFC 9126 §2.2 recommends this URN prefix for `request_uri` values.
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// Failed password attempts allowed against one pushed request.
pub const MAX_FAILED_LOGINS: u32 = 5;

/// How long an expired session is remembered, so that the user can still be
/// told what happened and be sent back to the client with an error.
pub const EXPIRED_SESSION_RETENTION: i64 = 60 * 60;

/// How long a user has to finish once they arrive, when nothing else is
/// configured (`security.session_ttl`).
pub const DEFAULT_SESSION_TTL: i64 = 300;

/// Consent records kept before the oldest are dropped.
pub const MAX_CONSENT_RECORDS: usize = 10_000;

/// A pushed authorization request awaiting the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushedRequest {
    pub request: AuthorizationRequest,
    /// The signed request object exactly as the client sent it.
    pub request_object: String,
    /// When the `request_uri` stops being accepted from a browser that has
    /// not yet arrived (RFC 9126 §2.2 `expires_in`).
    pub expires_at: i64,
    /// Kept by the backend as the record's counter, not in the stored value.
    #[serde(skip)]
    pub failed_logins: u32,
}

/// A user's visit to the authorization endpoint for one pushed request.
///
/// It starts when the browser first presents a `request_uri` that is still
/// valid, and from then on it, not the `request_uri` lifetime, limits how
/// long the user has to sign in and decide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub expires_at: i64,
    /// Set once the user has signed in during this session.
    #[serde(default)]
    pub signed_in: Option<SignedIn>,
}

/// Who signed in during a [`Session`], and from which browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedIn {
    /// The user's internal subject.
    pub user_subject: String,
    /// SHA-256 digest of the secret held in that browser's cookie. Signing
    /// in does not authorise anyone else who knows the `request_uri`.
    pub browser: String,
}

impl SignedIn {
    /// Whether `secret` is the one given to the browser that signed in.
    pub fn is_browser(&self, secret: &str) -> bool {
        crate::util::ct_eq(&self.browser, digest(secret))
    }
}

/// A pushed request as found for a browser at the authorization endpoint.
#[derive(Debug, Clone)]
pub enum Visit {
    /// The user is within their session.
    Active(Box<PushedRequest>, Session),
    /// The user arrived in time but then took too long. The request is kept
    /// only so that they can be returned to the client with an error.
    Expired(Box<PushedRequest>),
}

/// The response a client has asked the `ci` experience to give to one of its
/// pushed requests, in place of the default. It is checked when the client
/// sets it, so what is stored can be applied as it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PlannedResponse {
    /// Issue an authorization code.
    Success {
        /// Internal subject of the user the response is about.
        user_subject: String,
        /// The claims to share: every essential one, and the voluntary ones
        /// the client chose.
        shared_claims: BTreeSet<String>,
        /// The voluntary claims left out, as if the user had declined them.
        declined: Vec<String>,
    },
    /// Return an OAuth error to the client's redirect URI.
    Error { error: String, description: String },
    /// Give no response: the user arrives and leaves without deciding. The
    /// request stays pending. This applies to one visit only.
    Abandon,
}

/// What the user authorised. Shared by the code and every token derived from
/// it, so they can be revoked together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    pub client_id: String,
    /// The user's internal subject (not the pairwise value sent to clients).
    pub user_subject: String,
    pub scope: Vec<String>,
    pub claims: ClaimsRequest,
    /// The claims the user agreed to share. Nothing else is ever released
    /// under this grant.
    pub shared_claims: BTreeSet<String>,
    pub auth_time: i64,
    /// Transaction identifier returned as the `txn` claim (ConnectID).
    pub txn: String,
    /// The purpose the client gave for this transaction, if any.
    pub purpose: Option<String>,
    /// Manual changes to the ID token claims, made in the technical
    /// experience.
    pub id_token_edits: Option<crate::id_token::ClaimEdits>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentOutcome {
    Approved,
    Denied,
}

/// The record of one decided transaction: who asked for what, why, and what
/// the user decided. ConnectID identity assurance §5.1 requires the purpose
/// to be recorded for each transaction and to be available for a consent
/// history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub txn: String,
    pub client_id: String,
    /// The user's internal subject. `None` when the request was cancelled
    /// before anyone signed in.
    pub user_subject: Option<String>,
    pub purpose: Option<String>,
    /// Names of the claims the user agreed to share.
    pub claims: Vec<String>,
    /// Names of the voluntary claims the user declined to share.
    pub declined: Vec<String>,
    pub decided_at: i64,
    pub outcome: ConsentOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub grant: Grant,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub grant: Grant,
    /// SHA-256 thumbprint of the client certificate the token is bound to
    /// (RFC 8705 §3).
    pub cert_thumbprint: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// The backend could not be reached, or held something unreadable.
#[derive(Debug, Clone, thiserror::Error)]
#[error("store: {0}")]
pub struct StoreError(pub String);

impl StoreError {
    pub fn new(detail: impl std::fmt::Display) -> Self {
        Self(detail.to_string())
    }
}

impl From<StoreError> for OAuthError {
    fn from(error: StoreError) -> Self {
        Self::server_error(error)
    }
}

pub type StoreResult<T> = Result<T, StoreError>;

/// A stored value with its bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub value: String,
    /// When the record stops being valid (seconds since the epoch). `None`
    /// for records that are kept indefinitely.
    pub expires_at: Option<i64>,
    /// How many times [`Backend::increment`] has been called on it.
    pub count: u64,
}

impl Record {
    fn live(&self, now: i64) -> bool {
        self.expires_at.is_none_or(|at| at > now)
    }
}

pub type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = StoreResult<T>> + Send + 'a>>;

/// Where the store's data lives: a key-value table with a few atomic
/// operations, and an append-only log.
///
/// Backends may return records that have expired; [`Store`] checks. Each
/// operation must be atomic with respect to the others on the same key,
/// including across processes for a shared backend.
pub trait Backend: std::fmt::Debug + Send + Sync {
    /// Write `value` under `key`, replacing anything there and resetting its
    /// counter.
    fn put<'a>(
        &'a self,
        key: &'a str,
        value: String,
        expires_at: Option<i64>,
    ) -> BackendFuture<'a, ()>;

    /// Write `value` only if `key` is absent or its record expired at or
    /// before `now`. Returns whether it was written.
    fn put_new<'a>(
        &'a self,
        key: &'a str,
        value: String,
        expires_at: Option<i64>,
        now: i64,
    ) -> BackendFuture<'a, bool>;

    fn get<'a>(&'a self, key: &'a str) -> BackendFuture<'a, Option<Record>>;

    /// Remove and return the record. Of concurrent callers, exactly one gets
    /// it.
    fn take<'a>(&'a self, key: &'a str) -> BackendFuture<'a, Option<Record>>;

    /// Add one to the record's counter and return the record with the new
    /// count, or `None` if there is no such record. Concurrent callers see
    /// distinct counts.
    fn increment<'a>(&'a self, key: &'a str) -> BackendFuture<'a, Option<Record>>;

    /// Append an entry to the log. `id` identifies the entry; `partition`
    /// groups entries that are listed together; `at` orders them.
    fn log_append<'a>(
        &'a self,
        partition: &'a str,
        id: &'a str,
        at: i64,
        value: String,
    ) -> BackendFuture<'a, ()>;

    /// The entries of one partition, most recent first.
    fn log_list<'a>(&'a self, partition: &'a str) -> BackendFuture<'a, Vec<String>>;

    fn log_get<'a>(&'a self, id: &'a str) -> BackendFuture<'a, Option<String>>;

    /// Drop everything that expired at or before `now`. Backends that
    /// expire records themselves need do nothing.
    fn purge(&self, now: i64) -> BackendFuture<'_, ()>;
}

/// How long a revoked grant is remembered when nothing better is known:
/// the default refresh token lifetime plus the longest access token one.
const DEFAULT_GRANT_LIFETIME: i64 = 24 * 60 * 60 + crate::config::MAX_ACCESS_TOKEN_TTL;

#[derive(Debug, Clone)]
pub struct Store {
    backend: Arc<dyn Backend>,
    /// The longest any token of a grant can outlive the grant's code. A
    /// revocation is remembered for this long.
    grant_lifetime: i64,
    /// How long a user has at the authorization endpoint once they arrive.
    session_ttl: i64,
}

impl Default for Store {
    fn default() -> Self {
        Self::new(Arc::new(MemoryBackend::new()))
    }
}

fn digest(secret: &str) -> String {
    b64url(sha256(secret))
}

fn encode<T: Serialize>(value: &T) -> StoreResult<String> {
    serde_json::to_string(value).map_err(StoreError::new)
}

fn decode<T: DeserializeOwned>(value: &str) -> StoreResult<T> {
    serde_json::from_str(value).map_err(StoreError::new)
}

fn request_key(request_uri: &str) -> String {
    format!("par#{}", digest(request_uri))
}

fn session_key(request_uri: &str) -> String {
    format!("session#{}", digest(request_uri))
}

fn plan_key(request_uri: &str) -> String {
    format!("plan#{}", digest(request_uri))
}

fn code_key(code: &str) -> String {
    format!("code#{}", digest(code))
}

fn access_key(token: &str) -> String {
    format!("at#{}", digest(token))
}

fn refresh_key(token: &str) -> String {
    format!("rt#{}", digest(token))
}

fn revoked_key(grant_id: &str) -> String {
    format!("revoked#{}", digest(grant_id))
}

fn consent_partition(user_subject: Option<&str>) -> String {
    match user_subject {
        Some(subject) => format!("user:{subject}"),
        None => "nobody".to_owned(),
    }
}

impl Store {
    /// A store over `backend`.
    pub fn new(backend: Arc<dyn Backend>) -> Self {
        Self {
            backend,
            grant_lifetime: DEFAULT_GRANT_LIFETIME,
            session_ttl: DEFAULT_SESSION_TTL,
        }
    }

    /// Set how long a user has at the authorization endpoint once they
    /// arrive with a valid `request_uri`.
    #[must_use]
    pub fn session_ttl(mut self, seconds: i64) -> Self {
        self.session_ttl = seconds;
        self
    }

    /// Set how long a revoked grant is remembered: at least as long as its
    /// longest-lived token.
    #[must_use]
    pub fn grant_lifetime(mut self, seconds: i64) -> Self {
        self.grant_lifetime = seconds;
        self
    }

    /// Store a pushed request and return its `request_uri`.
    pub async fn push_request(
        &self,
        request: AuthorizationRequest,
        request_object: String,
        expires_at: i64,
    ) -> StoreResult<String> {
        let uri = format!("{REQUEST_URI_PREFIX}{}", random_token(SECRET_BYTES));
        let pushed = PushedRequest {
            request,
            request_object,
            expires_at,
            failed_logins: 0,
        };
        // The record outlives the `request_uri`: a session that starts just
        // before it expires still needs the request, and so does telling the
        // user afterwards that their session ran out.
        let kept_until = expires_at + self.session_ttl + EXPIRED_SESSION_RETENTION;
        self.backend
            .put(&request_key(&uri), encode(&pushed)?, Some(kept_until))
            .await?;
        Ok(uri)
    }

    fn pushed(record: Option<Record>, now: i64) -> StoreResult<Option<PushedRequest>> {
        let Some(record) = record.filter(|record| record.live(now)) else {
            return Ok(None);
        };
        let mut pushed: PushedRequest = decode(&record.value)?;
        pushed.failed_logins = u32::try_from(record.count).unwrap_or(u32::MAX);
        Ok(Some(pushed))
    }

    /// Look at a pushed request without consuming it, whether or not its
    /// `request_uri` is still accepted from a new browser.
    pub async fn peek_request(
        &self,
        request_uri: &str,
        now: i64,
    ) -> StoreResult<Option<PushedRequest>> {
        Self::pushed(self.backend.get(&request_key(request_uri)).await?, now)
    }

    async fn session(&self, request_uri: &str) -> StoreResult<Option<Session>> {
        self.backend
            .get(&session_key(request_uri))
            .await?
            .map(|record| decode(&record.value))
            .transpose()
    }

    fn visit(pushed: PushedRequest, session: Session, now: i64) -> Visit {
        if session.expires_at > now {
            Visit::Active(Box::new(pushed), session)
        } else {
            Visit::Expired(Box::new(pushed))
        }
    }

    /// The browser has arrived at the authorization endpoint.
    ///
    /// The first arrival must be before the `request_uri` expires (RFC 9126
    /// §2.2, FAPI 2.0 §5.3.2.2-11), and starts the user's session. After
    /// that the session alone decides how long they have, so someone reading
    /// the consent page is not cut off by the short `request_uri` lifetime.
    /// The request is not consumed: a reload works (§5.3.2.2 note 3) and
    /// continues the same session.
    ///
    /// Returns `None` if the request is unknown, already used, or expired
    /// before any browser arrived.
    pub async fn arrive(&self, request_uri: &str, now: i64) -> StoreResult<Option<Visit>> {
        let Some(pushed) = self.peek_request(request_uri, now).await? else {
            return Ok(None);
        };
        if let Some(session) = self.session(request_uri).await? {
            return Ok(Some(Self::visit(pushed, session, now)));
        }
        if pushed.expires_at <= now {
            return Ok(None);
        }
        let session = Session {
            expires_at: now + self.session_ttl,
            signed_in: None,
        };
        let started = self
            .backend
            .put_new(
                &session_key(request_uri),
                encode(&session)?,
                Some(session.expires_at + EXPIRED_SESSION_RETENTION),
                now,
            )
            .await?;
        if started {
            return Ok(Some(Visit::Active(Box::new(pushed), session)));
        }
        // Another request for the same `request_uri` started it first.
        Ok(self
            .session(request_uri)
            .await?
            .map(|session| Self::visit(pushed, session, now)))
    }

    /// The pushed request and session for a form submission. Unlike
    /// [`Store::arrive`] this never starts a session: a form can only come
    /// from a page that was shown within one.
    pub async fn resume(&self, request_uri: &str, now: i64) -> StoreResult<Option<Visit>> {
        let Some(pushed) = self.peek_request(request_uri, now).await? else {
            return Ok(None);
        };
        Ok(self
            .session(request_uri)
            .await?
            .map(|session| Self::visit(pushed, session, now)))
    }

    /// Record that `user_subject` signed in during `session`, from the
    /// browser holding `browser_secret`. Returns the updated session.
    pub async fn sign_in(
        &self,
        request_uri: &str,
        session: &Session,
        user_subject: &str,
        browser_secret: &str,
    ) -> StoreResult<Session> {
        let session = Session {
            expires_at: session.expires_at,
            signed_in: Some(SignedIn {
                user_subject: user_subject.to_owned(),
                browser: digest(browser_secret),
            }),
        };
        self.backend
            .put(
                &session_key(request_uri),
                encode(&session)?,
                Some(session.expires_at + EXPIRED_SESSION_RETENTION),
            )
            .await?;
        Ok(session)
    }

    /// Set the response the `ci` experience is to give to a pushed request,
    /// replacing any set before. It is kept until `expires_at`.
    pub async fn plan_response(
        &self,
        request_uri: &str,
        plan: &PlannedResponse,
        expires_at: i64,
    ) -> StoreResult<()> {
        self.backend
            .put(&plan_key(request_uri), encode(plan)?, Some(expires_at))
            .await
    }

    /// The response a client has asked for, if it has asked for one.
    pub async fn planned_response(
        &self,
        request_uri: &str,
        now: i64,
    ) -> StoreResult<Option<PlannedResponse>> {
        self.live(&plan_key(request_uri), now).await
    }

    /// Forget the response chosen for a pushed request, so that it gets the
    /// default one again.
    pub async fn clear_planned_response(&self, request_uri: &str) -> StoreResult<()> {
        self.backend.take(&plan_key(request_uri)).await.map(|_| ())
    }

    /// Consume a pushed request. Returns `None` if it is unknown or already
    /// consumed, which is what makes a `request_uri` one-time use. Whether
    /// the user was still in time is for the caller to have checked, with
    /// [`Store::arrive`] or [`Store::resume`].
    pub async fn take_request(
        &self,
        request_uri: &str,
        now: i64,
    ) -> StoreResult<Option<PushedRequest>> {
        Self::pushed(self.backend.take(&request_key(request_uri)).await?, now)
    }

    /// Count a failed login. Returns `false` once the limit is reached, at
    /// which point the request has been discarded.
    pub async fn record_failed_login(&self, request_uri: &str) -> StoreResult<bool> {
        let key = request_key(request_uri);
        let Some(record) = self.backend.increment(&key).await? else {
            return Ok(false);
        };
        if record.count >= u64::from(MAX_FAILED_LOGINS) {
            self.backend.take(&key).await?;
            return Ok(false);
        }
        Ok(true)
    }

    pub async fn create_code(&self, code: AuthorizationCode) -> StoreResult<String> {
        let value = random_token(SECRET_BYTES);
        self.backend
            .put(&code_key(&value), encode(&code)?, Some(code.expires_at))
            .await?;
        Ok(value)
    }

    /// Redeem an authorization code for `client_id`.
    ///
    /// Codes are single use (FAPI 2.0 §5.3.2.2-9). A second presentation
    /// revokes everything issued from the first (RFC 6749 §4.1.2). A used
    /// code is kept until it expires so that the replay can be recognised.
    pub async fn redeem_code(
        &self,
        code: &str,
        client_id: &str,
        now: i64,
    ) -> StoreResult<CodeRedemption> {
        let key = code_key(code);
        let Some(record) = self.backend.get(&key).await? else {
            return Ok(CodeRedemption::Invalid);
        };
        let stored: AuthorizationCode = decode(&record.value)?;
        if stored.grant.client_id != client_id {
            return Ok(CodeRedemption::Invalid);
        }
        if record.count > 0 {
            self.revoke_grant(&stored.grant.id, now).await?;
            return Ok(CodeRedemption::Replayed);
        }
        if stored.expires_at <= now {
            return Ok(CodeRedemption::Invalid);
        }
        // The counter decides between concurrent presentations: only the
        // caller that moves it from zero to one has redeemed the code.
        match self.backend.increment(&key).await? {
            Some(record) if record.count == 1 => Ok(CodeRedemption::Valid(Box::new(stored))),
            Some(_) => {
                self.revoke_grant(&stored.grant.id, now).await?;
                Ok(CodeRedemption::Replayed)
            }
            None => Ok(CodeRedemption::Invalid),
        }
    }

    /// Revoke every token of a grant, by recording that it is revoked;
    /// token lookups check the record.
    async fn revoke_grant(&self, grant_id: &str, now: i64) -> StoreResult<()> {
        self.backend
            .put(
                &revoked_key(grant_id),
                String::new(),
                Some(now + self.grant_lifetime),
            )
            .await
    }

    async fn revoked(&self, grant_id: &str, now: i64) -> StoreResult<bool> {
        Ok(self
            .backend
            .get(&revoked_key(grant_id))
            .await?
            .is_some_and(|record| record.live(now)))
    }

    async fn live<T: DeserializeOwned>(&self, key: &str, now: i64) -> StoreResult<Option<T>> {
        match self.backend.get(key).await? {
            Some(record) if record.live(now) => decode(&record.value).map(Some),
            _ => Ok(None),
        }
    }

    pub async fn issue_access_token(&self, token: AccessToken) -> StoreResult<String> {
        let value = random_token(SECRET_BYTES);
        self.backend
            .put(&access_key(&value), encode(&token)?, Some(token.expires_at))
            .await?;
        Ok(value)
    }

    pub async fn access_token(&self, token: &str, now: i64) -> StoreResult<Option<AccessToken>> {
        let Some(found) = self.live::<AccessToken>(&access_key(token), now).await? else {
            return Ok(None);
        };
        if self.revoked(&found.grant.id, now).await? {
            return Ok(None);
        }
        Ok(Some(found))
    }

    pub async fn issue_refresh_token(&self, token: RefreshToken) -> StoreResult<String> {
        let value = random_token(SECRET_BYTES);
        self.backend
            .put(
                &refresh_key(&value),
                encode(&token)?,
                Some(token.expires_at),
            )
            .await?;
        Ok(value)
    }

    pub async fn refresh_token(&self, token: &str, now: i64) -> StoreResult<Option<RefreshToken>> {
        let Some(found) = self.live::<RefreshToken>(&refresh_key(token), now).await? else {
            return Ok(None);
        };
        if self.revoked(&found.grant.id, now).await? {
            return Ok(None);
        }
        Ok(Some(found))
    }

    /// Record a client assertion's `jti`. Returns `false` if it was already
    /// seen and has not yet expired, i.e. the assertion is a replay.
    pub async fn record_jti(
        &self,
        client_id: &str,
        jti: &str,
        expires_at: i64,
        now: i64,
    ) -> StoreResult<bool> {
        // Hashed: both parts are chosen by the client and may be long.
        let key = format!("jti#{}", digest(&format!("{client_id}\n{jti}")));
        self.backend
            .put_new(&key, String::new(), Some(expires_at), now)
            .await
    }

    /// Record a decided transaction. Records do not expire; the in-memory
    /// backend keeps only the most recent [`MAX_CONSENT_RECORDS`].
    pub async fn record_consent(&self, record: ConsentRecord) -> StoreResult<()> {
        self.backend
            .log_append(
                &consent_partition(record.user_subject.as_deref()),
                &record.txn,
                record.decided_at,
                encode(&record)?,
            )
            .await
    }

    /// A user's decided transactions, most recent first.
    pub async fn consent_history(&self, user_subject: &str) -> StoreResult<Vec<ConsentRecord>> {
        self.backend
            .log_list(&consent_partition(Some(user_subject)))
            .await?
            .iter()
            .map(|value| decode(value))
            .collect()
    }

    /// The record of the transaction identified by `txn`.
    pub async fn consent(&self, txn: &str) -> StoreResult<Option<ConsentRecord>> {
        self.backend
            .log_get(txn)
            .await?
            .map(|value| decode(&value))
            .transpose()
    }

    /// A long-lived secret shared by every instance using this store, such
    /// as the signing key: the stored value, or the result of `generate` if
    /// there is none yet. When several instances start at once, they all
    /// end up with the value that was stored first.
    pub async fn secret(
        &self,
        name: &str,
        generate: impl FnOnce() -> anyhow::Result<String>,
    ) -> StoreResult<String> {
        let key = format!("secret#{name}");
        if let Some(record) = self.backend.get(&key).await? {
            return Ok(record.value);
        }
        let candidate = generate().map_err(|error| StoreError::new(format!("{error:#}")))?;
        // Secrets never expire, so `now` is irrelevant to the condition.
        self.backend.put_new(&key, candidate, None, 0).await?;
        self.backend
            .get(&key)
            .await?
            .map(|record| record.value)
            .ok_or_else(|| StoreError::new(format!("secret '{name}' vanished after being stored")))
    }

    /// Drop everything that has expired. Called periodically.
    pub async fn purge(&self, now: i64) -> StoreResult<()> {
        self.backend.purge(now).await
    }
}

/// Behaviour every backend must provide, written against [`Store`] so the
/// same checks run on each.
#[cfg(test)]
pub(crate) mod contract {
    use super::*;
    use crate::authz::test_support::{CHALLENGE, valid_params};
    use crate::client::test_support::client_with_key;
    use crate::keys::test_support::shared_key;

    pub const NOW: i64 = 1_800_000_000;

    pub fn request() -> AuthorizationRequest {
        AuthorizationRequest::from_params(&client_with_key("rp", shared_key()), &valid_params())
            .unwrap()
    }

    pub fn grant(id: &str) -> Grant {
        Grant {
            id: id.to_owned(),
            client_id: "rp".to_owned(),
            user_subject: "u1".to_owned(),
            scope: vec!["openid".to_owned()],
            claims: ClaimsRequest::default(),
            shared_claims: BTreeSet::from(["given_name".to_owned()]),
            auth_time: NOW,
            txn: "txn-1".to_owned(),
            purpose: Some("testing".to_owned()),
            id_token_edits: None,
        }
    }

    pub fn consent(txn: &str, user: Option<&str>, decided_at: i64) -> ConsentRecord {
        ConsentRecord {
            txn: txn.to_owned(),
            client_id: "rp".to_owned(),
            user_subject: user.map(str::to_owned),
            purpose: Some(format!("purpose of {txn}")),
            claims: vec!["given_name".to_owned()],
            declined: Vec::new(),
            decided_at,
            outcome: if user.is_some() {
                ConsentOutcome::Approved
            } else {
                ConsentOutcome::Denied
            },
        }
    }

    pub fn code(grant_id: &str) -> AuthorizationCode {
        AuthorizationCode {
            grant: grant(grant_id),
            redirect_uri: "https://rp.example.com/cb".to_owned(),
            code_challenge: CHALLENGE.to_owned(),
            nonce: Some("n-1".to_owned()),
            expires_at: NOW + 60,
        }
    }

    /// `tag` keeps runs against a shared table apart.
    pub async fn consent_history(store: &Store, tag: &str) {
        let (u1, u2) = (format!("{tag}-u1"), format!("{tag}-u2"));
        let txn = |n: u8| format!("{tag}-t{n}");
        store
            .record_consent(consent(&txn(1), Some(&u1), NOW))
            .await
            .unwrap();
        store
            .record_consent(consent(&txn(2), Some(&u2), NOW + 1))
            .await
            .unwrap();
        store
            .record_consent(consent(&txn(3), None, NOW + 2))
            .await
            .unwrap();
        store
            .record_consent(consent(&txn(4), Some(&u1), NOW + 3))
            .await
            .unwrap();

        let history = store.consent_history(&u1).await.unwrap();
        let txns: Vec<&str> = history.iter().map(|r| r.txn.as_str()).collect();
        assert_eq!(txns, [txn(4), txn(1)]);
        assert_eq!(
            history[1].purpose.as_deref(),
            Some(format!("purpose of {}", txn(1)).as_str())
        );
        let nobody = store.consent_history(&format!("{tag}-nobody")).await;
        assert_eq!(nobody.unwrap(), Vec::new());
        assert_eq!(
            store.consent(&txn(3)).await.unwrap().unwrap().outcome,
            ConsentOutcome::Denied
        );
        assert!(
            store
                .consent(&format!("{tag}-missing"))
                .await
                .unwrap()
                .is_none()
        );

        // Records are not transient state: purging leaves them alone.
        store.purge(NOW + 1_000_000).await.unwrap();
        assert_eq!(store.consent_history(&u1).await.unwrap().len(), 2);
    }

    pub async fn pushed_requests(store: &Store) {
        let a = store
            .push_request(request(), "object".to_owned(), NOW + 60)
            .await
            .unwrap();
        let b = store
            .push_request(request(), String::new(), NOW + 60)
            .await
            .unwrap();
        assert_ne!(a, b);
        assert!(a.starts_with(REQUEST_URI_PREFIX));
        assert!(a.len() - REQUEST_URI_PREFIX.len() >= 43);

        // Peeked repeatedly, taken once.
        let peeked = store.peek_request(&a, NOW).await.unwrap().unwrap();
        assert_eq!(peeked.request, request());
        assert_eq!(peeked.request_object, "object");
        assert_eq!(peeked.failed_logins, 0);
        assert!(store.peek_request(&a, NOW).await.unwrap().is_some());
        assert!(store.take_request(&a, NOW).await.unwrap().is_some());
        assert!(store.take_request(&a, NOW).await.unwrap().is_none());
        assert!(store.peek_request(&a, NOW).await.unwrap().is_none());

        // A browser must arrive before the request_uri expires.
        assert!(store.arrive(&b, NOW + 60).await.unwrap().is_none());
        assert!(store.resume(&b, NOW).await.unwrap().is_none(), "no session");
        assert!(
            store
                .peek_request("urn:ietf:params:oauth:request_uri:unknown", NOW)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A planned response is kept per `request_uri` until it expires, and
    /// the last one set wins.
    pub async fn planned_responses(store: &Store) {
        let uri = format!("{REQUEST_URI_PREFIX}planned");
        assert_eq!(store.planned_response(&uri, NOW).await.unwrap(), None);

        let error = PlannedResponse::Error {
            error: "access_denied".to_owned(),
            description: "the user denied the request".to_owned(),
        };
        store.plan_response(&uri, &error, NOW + 60).await.unwrap();
        assert_eq!(
            store.planned_response(&uri, NOW).await.unwrap(),
            Some(error)
        );

        let success = PlannedResponse::Success {
            user_subject: "u1".to_owned(),
            shared_claims: BTreeSet::from(["given_name".to_owned()]),
            declined: vec!["email".to_owned()],
        };
        store.plan_response(&uri, &success, NOW + 60).await.unwrap();
        assert_eq!(
            store.planned_response(&uri, NOW + 59).await.unwrap(),
            Some(success)
        );
        assert_eq!(store.planned_response(&uri, NOW + 60).await.unwrap(), None);
        let other = format!("{REQUEST_URI_PREFIX}other");
        assert_eq!(store.planned_response(&other, NOW).await.unwrap(), None);

        let abandon = PlannedResponse::Abandon;
        store.plan_response(&uri, &abandon, NOW + 60).await.unwrap();
        assert_eq!(
            store.planned_response(&uri, NOW).await.unwrap(),
            Some(abandon)
        );
        store.clear_planned_response(&uri).await.unwrap();
        assert_eq!(store.planned_response(&uri, NOW).await.unwrap(), None);
        store.clear_planned_response(&uri).await.unwrap();
    }

    /// Arriving in time starts a session, which then outlives the
    /// `request_uri` and is what the user is held to.
    pub async fn sessions(store: &Store) {
        let ttl = DEFAULT_SESSION_TTL;
        let uri = store
            .push_request(request(), String::new(), NOW + 60)
            .await
            .unwrap();
        let arrived = NOW + 59;
        let Some(Visit::Active(_, session)) = store.arrive(&uri, arrived).await.unwrap() else {
            panic!("arriving in time starts a session");
        };
        assert_eq!(session.expires_at, arrived + ttl);
        assert_eq!(session.signed_in, None);

        // Past the request_uri lifetime, the same session carries on, and
        // arriving again does not extend it.
        let later = arrived + ttl - 1;
        for visit in [
            store.arrive(&uri, later).await.unwrap(),
            store.resume(&uri, later).await.unwrap(),
        ] {
            let Some(Visit::Active(pushed, again)) = visit else {
                panic!("the session is still running");
            };
            assert_eq!(again, session);
            assert_eq!(pushed.request, request());
        }

        let session = store
            .sign_in(&uri, &session, "u1", "browser-secret")
            .await
            .unwrap();
        let Some(Visit::Active(_, read)) = store.resume(&uri, later).await.unwrap() else {
            panic!("signing in keeps the session");
        };
        assert_eq!(read, session);
        let signed_in = read.signed_in.unwrap();
        assert_eq!(signed_in.user_subject, "u1");
        assert!(signed_in.is_browser("browser-secret"));
        assert!(!signed_in.is_browser("another"));
        assert_ne!(signed_in.browser, "browser-secret", "only a digest is kept");

        // Once the session ends the request is kept, to explain and to
        // return an error to the client, but only for a while.
        for at in [arrived + ttl, arrived + ttl + EXPIRED_SESSION_RETENTION - 1] {
            assert!(matches!(
                store.arrive(&uri, at).await.unwrap(),
                Some(Visit::Expired(_))
            ));
            assert!(matches!(
                store.resume(&uri, at).await.unwrap(),
                Some(Visit::Expired(_))
            ));
        }
        let gone = NOW + 60 + ttl + EXPIRED_SESSION_RETENTION;
        assert!(store.arrive(&uri, gone).await.unwrap().is_none());

        // A used request has no session to come back to.
        let uri = store
            .push_request(request(), String::new(), NOW + 60)
            .await
            .unwrap();
        assert!(store.arrive(&uri, NOW).await.unwrap().is_some());
        assert!(store.take_request(&uri, NOW).await.unwrap().is_some());
        assert!(store.arrive(&uri, NOW).await.unwrap().is_none());
        assert!(store.resume(&uri, NOW).await.unwrap().is_none());
    }

    pub async fn failed_logins(store: &Store) {
        let uri = store
            .push_request(request(), String::new(), NOW + 60)
            .await
            .unwrap();
        for attempt in 1..MAX_FAILED_LOGINS {
            assert!(store.record_failed_login(&uri).await.unwrap());
            let pushed = store.peek_request(&uri, NOW).await.unwrap().unwrap();
            assert_eq!(pushed.failed_logins, attempt);
        }
        assert!(!store.record_failed_login(&uri).await.unwrap());
        assert!(store.peek_request(&uri, NOW).await.unwrap().is_none());
        assert!(!store.record_failed_login("unknown").await.unwrap());
    }

    pub async fn code_replay(store: &Store) {
        // A grant id unique to this run, for shared tables.
        let grant_id = format!("g-{}", random_token(8));
        let mut unique = code("g1");
        unique.grant.id.clone_from(&grant_id);
        let value = store.create_code(unique).await.unwrap();
        let CodeRedemption::Valid(redeemed) = store.redeem_code(&value, "rp", NOW).await.unwrap()
        else {
            panic!("first redemption should succeed");
        };
        assert_eq!(redeemed.nonce.as_deref(), Some("n-1"));
        assert_eq!(redeemed.grant.id, grant_id);
        let access = store
            .issue_access_token(AccessToken {
                grant: redeemed.grant.clone(),
                cert_thumbprint: "tp".to_owned(),
                expires_at: NOW + 300,
            })
            .await
            .unwrap();
        let refresh = store
            .issue_refresh_token(RefreshToken {
                grant: redeemed.grant.clone(),
                expires_at: NOW + 900,
            })
            .await
            .unwrap();
        let other = store
            .issue_access_token(AccessToken {
                grant: grant(&format!("{grant_id}-other")),
                cert_thumbprint: "tp".to_owned(),
                expires_at: NOW + 300,
            })
            .await
            .unwrap();
        assert!(store.access_token(&access, NOW).await.unwrap().is_some());

        assert!(matches!(
            store.redeem_code(&value, "rp", NOW + 1).await.unwrap(),
            CodeRedemption::Replayed
        ));
        assert!(
            store
                .access_token(&access, NOW + 1)
                .await
                .unwrap()
                .is_none(),
            "revoked with the grant"
        );
        assert!(
            store
                .refresh_token(&refresh, NOW + 1)
                .await
                .unwrap()
                .is_none(),
            "revoked with the grant"
        );
        assert!(
            store.access_token(&other, NOW + 1).await.unwrap().is_some(),
            "other grants are untouched"
        );
    }

    pub async fn code_binding(store: &Store) {
        let value = store.create_code(code("g1")).await.unwrap();
        assert!(matches!(
            store.redeem_code(&value, "other", NOW).await.unwrap(),
            CodeRedemption::Invalid
        ));
        assert!(matches!(
            store.redeem_code("unknown", "rp", NOW).await.unwrap(),
            CodeRedemption::Invalid
        ));
        // A wrong client must not burn the code for its rightful owner.
        assert!(matches!(
            store.redeem_code(&value, "rp", NOW).await.unwrap(),
            CodeRedemption::Valid(_)
        ));

        let late = store.create_code(code("g3")).await.unwrap();
        assert!(matches!(
            store.redeem_code(&late, "rp", NOW + 60).await.unwrap(),
            CodeRedemption::Invalid
        ));
    }

    pub async fn concurrent_redemption(store: &Store) {
        let value = store.create_code(code("g1")).await.unwrap();
        let attempts = (0..8).map(|_| {
            let store = store.clone();
            let value = value.clone();
            tokio::spawn(async move { store.redeem_code(&value, "rp", NOW).await.unwrap() })
        });
        let mut valid = 0;
        for attempt in attempts.collect::<Vec<_>>() {
            if matches!(attempt.await.unwrap(), CodeRedemption::Valid(_)) {
                valid += 1;
            }
        }
        assert_eq!(valid, 1, "exactly one presentation redeems the code");
    }

    pub async fn tokens(store: &Store) {
        // Not a grant another check revokes.
        let id = format!("g-{}", random_token(8));
        let access = store
            .issue_access_token(AccessToken {
                grant: grant(&id),
                cert_thumbprint: "tp".to_owned(),
                expires_at: NOW + 300,
            })
            .await
            .unwrap();
        let found = store.access_token(&access, NOW + 299).await.unwrap();
        let found = found.unwrap();
        assert_eq!(found.cert_thumbprint, "tp");
        assert_eq!(found.grant, grant(&id));
        assert!(
            store
                .access_token(&access, NOW + 300)
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.access_token("unknown", NOW).await.unwrap().is_none());

        let refresh = store
            .issue_refresh_token(RefreshToken {
                grant: grant(&id),
                expires_at: NOW + 10,
            })
            .await
            .unwrap();
        assert!(store.refresh_token(&refresh, NOW).await.unwrap().is_some());
        assert!(
            store
                .refresh_token(&refresh, NOW + 10)
                .await
                .unwrap()
                .is_none()
        );
        // Presenting an access token as a refresh token finds nothing.
        assert!(store.refresh_token(&access, NOW).await.unwrap().is_none());
    }

    pub async fn jti_replay(store: &Store, tag: &str) {
        let (rp, other) = (format!("{tag}-rp"), format!("{tag}-other"));
        assert!(store.record_jti(&rp, "j1", NOW + 60, NOW).await.unwrap());
        assert!(
            !store
                .record_jti(&rp, "j1", NOW + 60, NOW + 1)
                .await
                .unwrap()
        );
        assert!(
            store.record_jti(&other, "j1", NOW + 60, NOW).await.unwrap(),
            "scoped to the client"
        );
        assert!(store.record_jti(&rp, "j2", NOW + 60, NOW).await.unwrap());
        assert!(
            store
                .record_jti(&rp, "j1", NOW + 120, NOW + 60)
                .await
                .unwrap(),
            "reusable once expired"
        );
    }

    pub async fn secrets(store: &Store, tag: &str) {
        let name = format!("{tag}-secret");
        let first = store.secret(&name, || Ok("one".to_owned())).await.unwrap();
        assert_eq!(first, "one");
        let second = store
            .secret(&name, || panic!("must not generate again"))
            .await
            .unwrap();
        assert_eq!(second, "one");
        assert!(
            store
                .secret(&format!("{tag}-failing"), || anyhow::bail!("no entropy"))
                .await
                .is_err()
        );
        // Secrets are not transient state.
        store.purge(NOW + 1_000_000).await.unwrap();
        assert_eq!(
            store.secret(&name, || Ok("two".to_owned())).await.unwrap(),
            "one"
        );
    }

    /// Every check, in turn.
    pub async fn all(store: &Store, tag: &str) {
        // Purging runs inside these, so they go before anything transient.
        consent_history(store, tag).await;
        secrets(store, tag).await;
        pushed_requests(store).await;
        sessions(store).await;
        planned_responses(store).await;
        failed_logins(store).await;
        code_replay(store).await;
        code_binding(store).await;
        concurrent_redemption(store).await;
        tokens(store).await;
        jti_replay(store, tag).await;
    }
}

#[cfg(test)]
mod tests {
    use super::contract::{NOW, code, consent, grant, request};
    use super::*;

    #[tokio::test]
    async fn memory_backend_meets_the_contract() {
        contract::all(&Store::default(), "mem").await;
    }

    #[tokio::test]
    async fn consent_records_are_bounded_in_memory() {
        let store = Store::default();
        for i in 0..=MAX_CONSENT_RECORDS {
            store
                .record_consent(consent(&format!("t{i}"), Some("u1"), NOW))
                .await
                .unwrap();
        }
        assert_eq!(
            store.consent_history("u1").await.unwrap().len(),
            MAX_CONSENT_RECORDS
        );
        assert!(
            store.consent("t0").await.unwrap().is_none(),
            "the oldest was dropped"
        );
        assert!(store.consent("t1").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn purge_removes_only_expired_entries() {
        let backend = Arc::new(MemoryBackend::new());
        let store = Store::new(Arc::clone(&backend) as Arc<dyn Backend>);
        store
            .push_request(request(), String::new(), NOW + 10)
            .await
            .unwrap();
        store
            .push_request(request(), String::new(), NOW + 100)
            .await
            .unwrap();
        store.create_code(code("g1")).await.unwrap();
        store
            .issue_access_token(AccessToken {
                grant: grant("g1"),
                cert_thumbprint: "tp".to_owned(),
                expires_at: NOW + 300,
            })
            .await
            .unwrap();
        store.record_jti("rp", "j1", NOW + 20, NOW).await.unwrap();
        assert_eq!(backend.len(), 5);

        store.purge(NOW + 50).await.unwrap();
        assert_eq!(backend.len(), 4, "the jti is gone");
        // Requests are kept past their request_uri, for sessions.
        store
            .purge(NOW + 10 + DEFAULT_SESSION_TTL + EXPIRED_SESSION_RETENTION)
            .await
            .unwrap();
        assert_eq!(backend.len(), 1, "only the longer-lived request is left");
        store.purge(NOW + 10_000).await.unwrap();
        assert!(backend.is_empty());
    }

    #[tokio::test]
    async fn revocation_outlives_the_grant_tokens() {
        let backend = Arc::new(MemoryBackend::new());
        let store = Store::new(Arc::clone(&backend) as Arc<dyn Backend>).grant_lifetime(1000);
        let value = store.create_code(code("g1")).await.unwrap();
        store.redeem_code(&value, "rp", NOW).await.unwrap();
        store.redeem_code(&value, "rp", NOW + 1).await.unwrap();
        store.purge(NOW + 1000).await.unwrap();
        assert_eq!(backend.len(), 1, "the revocation is still remembered");
        store.purge(NOW + 1001).await.unwrap();
        assert!(backend.is_empty());
    }
}
