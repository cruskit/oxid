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

use crate::error::{BoxError, OAuthError};
use crate::epoch::{Seconds, Timestamp};
use crate::util::{b64url, random_token, sha256};

#[cfg(feature = "aws")]
pub(crate) mod dynamodb;
mod memory;

pub(crate) use memory::MemoryBackend;

/// Bytes of entropy in generated secrets (256 bits; FAPI 2.0 needs >= 128).
const SECRET_BYTES: usize = 32;

/// RFC 9126 §2.2 recommends this URN prefix for `request_uri` values.
pub(crate) const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// Failed password attempts allowed against one pushed request.
pub(crate) const MAX_FAILED_LOGINS: u32 = 5;

/// How long an expired session is remembered, so that the user can still be
/// told what happened and be sent back to the client with an error.
pub(crate) const EXPIRED_SESSION_RETENTION: Seconds = Seconds::hours(1);

/// How long a user has to finish once they arrive, when nothing else is
/// configured (`security.session_ttl`).
pub(crate) const DEFAULT_SESSION_TTL: Seconds = Seconds::minutes(5);

/// Consent records kept before the oldest are dropped.
pub(crate) const MAX_CONSENT_RECORDS: usize = 10_000;

/// A pushed authorization request awaiting the user.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct PushedRequest {
    pub request: AuthorizationRequest,
    /// The signed request object exactly as the client sent it.
    pub request_object: String,
    /// When the `request_uri` stops being accepted from a browser that has
    /// not yet arrived (RFC 9126 §2.2 `expires_in`).
    pub expires_at: Timestamp,
    /// Kept by the backend as the record's counter, not in the stored value.
    #[serde(skip)]
    pub failed_logins: u32,
}

impl PushedRequest {
    /// Whether the sign-in attempts for this request are used up.
    pub(crate) fn is_exhausted(&self) -> bool {
        self.failed_logins >= MAX_FAILED_LOGINS
    }
}

impl std::fmt::Debug for PushedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The request object carries the client's signed claims (and may
        // carry personal data in a claims request); keep it out of logs.
        f.debug_struct("PushedRequest")
            .field("request", &self.request)
            .field("expires_at", &self.expires_at)
            .field("failed_logins", &self.failed_logins)
            .finish_non_exhaustive()
    }
}

/// A user's visit to the authorization endpoint for one pushed request.
///
/// It starts when the browser first presents a `request_uri` that is still
/// valid, and from then on it, not the `request_uri` lifetime, limits how
/// long the user has to sign in and decide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Session {
    pub expires_at: Timestamp,
    /// Set once the user has signed in during this session.
    #[serde(default)]
    pub signed_in: Option<SignedIn>,
}

/// Who signed in during a [`Session`], and from which browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SignedIn {
    /// The user's internal subject.
    pub user_subject: String,
    /// SHA-256 digest of the secret held in that browser's cookie. Signing
    /// in does not authorise anyone else who knows the `request_uri`.
    pub browser: String,
}

impl SignedIn {
    /// Whether `secret` is the one given to the browser that signed in.
    pub(crate) fn is_browser(&self, secret: &str) -> bool {
        crate::util::ct_eq(&self.browser, digest(secret))
    }
}

/// A pushed request as found for a browser at the authorization endpoint.
#[derive(Debug, Clone)]
pub(crate) enum Visit {
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
pub(crate) enum PlannedResponse {
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
pub(crate) struct Grant {
    pub id: String,
    pub client_id: String,
    /// The user's internal subject (not the pairwise value sent to clients).
    pub user_subject: String,
    pub scope: Vec<String>,
    pub claims: ClaimsRequest,
    /// The claims the user agreed to share. Nothing else is ever released
    /// under this grant.
    pub shared_claims: BTreeSet<String>,
    pub auth_time: Timestamp,
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
pub(crate) enum ConsentOutcome {
    Approved,
    Denied,
}

/// The record of one decided transaction: who asked for what, why, and what
/// the user decided. ConnectID identity assurance §5.1 requires the purpose
/// to be recorded for each transaction and to be available for a consent
/// history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsentRecord {
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
    pub decided_at: Timestamp,
    pub outcome: ConsentOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AuthorizationCode {
    pub grant: Grant,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccessToken {
    pub grant: Grant,
    /// SHA-256 thumbprint of the client certificate the token is bound to
    /// (RFC 8705 §3).
    pub cert_thumbprint: String,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RefreshToken {
    pub grant: Grant,
    pub expires_at: Timestamp,
}

/// Outcome of presenting an authorization code.
#[derive(Debug)]
pub(crate) enum CodeRedemption {
    Valid(Box<AuthorizationCode>),
    /// The code was already used. Tokens issued from it have been revoked.
    Replayed,
    /// Unknown, expired, or issued to a different client.
    Invalid,
}

/// Why the store could not do what was asked. The cause is kept as the
/// error's source, so a log line shows the whole chain.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StoreError {
    /// The backend could not be reached, or refused the operation.
    #[error("the store is unavailable")]
    Unavailable(#[source] BoxError),
    /// Something stored could not be read back.
    #[error("a stored item is corrupt")]
    Corrupt(#[source] BoxError),
    /// A value could not be encoded for storing.
    #[error("a value could not be encoded for the store")]
    Encode(#[source] serde_json::Error),
    /// A secret kept in the store could not be generated.
    #[error("the secret '{name}' could not be generated")]
    Generate {
        name: String,
        #[source]
        source: BoxError,
    },
}

impl From<StoreError> for OAuthError {
    fn from(error: StoreError) -> Self {
        Self::server_error(error)
    }
}

pub(crate) type StoreResult<T> = Result<T, StoreError>;

/// A stored value with its bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Record {
    pub value: String,
    /// When the record stops being valid (seconds since the epoch). `None`
    /// for records that are kept indefinitely.
    pub expires_at: Option<Timestamp>,
    /// How many times [`Backend::increment`] has been called on it.
    pub count: u64,
}

impl Record {
    fn live(&self, now: Timestamp) -> bool {
        self.expires_at.is_none_or(|at| at > now)
    }
}

pub(crate) type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = StoreResult<T>> + Send + 'a>>;

/// Where the store's data lives: a key-value table with a few atomic
/// operations, and an append-only log.
///
/// Backends may return records that have expired; [`Store`] checks. Each
/// operation must be atomic with respect to the others on the same key,
/// including across processes for a shared backend.
pub(crate) trait Backend: std::fmt::Debug + Send + Sync {
    /// Write `value` under `key`, replacing anything there and resetting its
    /// counter.
    fn put<'a>(
        &'a self,
        key: &'a str,
        value: String,
        expires_at: Option<Timestamp>,
    ) -> BackendFuture<'a, ()>;

    /// Write `value` only if `key` is absent or its record expired at or
    /// before `now`. Returns whether it was written.
    fn put_new<'a>(
        &'a self,
        key: &'a str,
        value: String,
        expires_at: Option<Timestamp>,
        now: Timestamp,
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
        at: Timestamp,
        value: String,
    ) -> BackendFuture<'a, ()>;

    /// The entries of one partition, most recent first.
    #[cfg_attr(not(test), expect(dead_code, reason = "the read side of the consent log, for the planned consent history"))]
    fn log_list<'a>(&'a self, partition: &'a str) -> BackendFuture<'a, Vec<String>>;

    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(dead_code, reason = "the read side of the consent log, for the planned consent history")
    )]
    fn log_get<'a>(&'a self, id: &'a str) -> BackendFuture<'a, Option<String>>;

    /// Drop everything that expired at or before `now`. Backends that
    /// expire records themselves need do nothing.
    fn purge(&self, now: Timestamp) -> BackendFuture<'_, ()>;
}

/// How long a revoked grant is remembered when nothing better is known:
/// the default refresh token lifetime plus the longest access token one.
const DEFAULT_GRANT_LIFETIME: Seconds = Seconds::new(
    Seconds::days(1).get() + crate::config::MAX_ACCESS_TOKEN_TTL.get(),
);

#[derive(Debug, Clone)]
pub(crate) struct Store {
    backend: Arc<dyn Backend>,
    /// The longest any token of a grant can outlive the grant's code. A
    /// revocation is remembered for this long.
    grant_lifetime: Seconds,
    /// How long a user has at the authorization endpoint once they arrive.
    session_ttl: Seconds,
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
    serde_json::to_string(value).map_err(StoreError::Encode)
}

fn decode<T: DeserializeOwned>(value: &str) -> StoreResult<T> {
    serde_json::from_str(value).map_err(|error| StoreError::Corrupt(error.into()))
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
    pub(crate) fn new(backend: Arc<dyn Backend>) -> Self {
        Self {
            backend,
            grant_lifetime: DEFAULT_GRANT_LIFETIME,
            session_ttl: DEFAULT_SESSION_TTL,
        }
    }

    /// Set how long a user has at the authorization endpoint once they
    /// arrive with a valid `request_uri`.
    #[must_use]
    pub(crate) fn session_ttl(mut self, seconds: Seconds) -> Self {
        self.session_ttl = seconds;
        self
    }

    /// Set how long a revoked grant is remembered: at least as long as its
    /// longest-lived token.
    #[must_use]
    pub(crate) fn grant_lifetime(mut self, seconds: Seconds) -> Self {
        self.grant_lifetime = seconds;
        self
    }

    /// Store a pushed request and return its `request_uri`.
    pub(crate) async fn push_request(
        &self,
        request: AuthorizationRequest,
        request_object: String,
        expires_at: Timestamp,
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

    fn pushed(record: Option<Record>, now: Timestamp) -> StoreResult<Option<PushedRequest>> {
        let Some(record) = record.filter(|record| record.live(now)) else {
            return Ok(None);
        };
        let mut pushed: PushedRequest = decode(&record.value)?;
        pushed.failed_logins = u32::try_from(record.count).unwrap_or(u32::MAX);
        Ok(Some(pushed))
    }

    /// Look at a pushed request without consuming it, whether or not its
    /// `request_uri` is still accepted from a new browser. A request that
    /// has had [`MAX_FAILED_LOGINS`] failed sign-ins is treated as gone.
    pub(crate) async fn peek_request(
        &self,
        request_uri: &str,
        now: Timestamp,
    ) -> StoreResult<Option<PushedRequest>> {
        Ok(Self::pushed(self.backend.get(&request_key(request_uri)).await?, now)?
            .filter(|pushed| !pushed.is_exhausted()))
    }

    async fn session(&self, request_uri: &str) -> StoreResult<Option<Session>> {
        self.backend
            .get(&session_key(request_uri))
            .await?
            .map(|record| decode(&record.value))
            .transpose()
    }

    fn visit(pushed: PushedRequest, session: Session, now: Timestamp) -> Visit {
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
    pub(crate) async fn arrive(&self, request_uri: &str, now: Timestamp) -> StoreResult<Option<Visit>> {
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
    pub(crate) async fn resume(&self, request_uri: &str, now: Timestamp) -> StoreResult<Option<Visit>> {
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
    pub(crate) async fn sign_in(
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
    pub(crate) async fn plan_response(
        &self,
        request_uri: &str,
        plan: &PlannedResponse,
        expires_at: Timestamp,
    ) -> StoreResult<()> {
        self.backend
            .put(&plan_key(request_uri), encode(plan)?, Some(expires_at))
            .await
    }

    /// The response a client has asked for, if it has asked for one.
    pub(crate) async fn planned_response(
        &self,
        request_uri: &str,
        now: Timestamp,
    ) -> StoreResult<Option<PlannedResponse>> {
        self.live(&plan_key(request_uri), now).await
    }

    /// Forget the response chosen for a pushed request, so that it gets the
    /// default one again.
    pub(crate) async fn clear_planned_response(&self, request_uri: &str) -> StoreResult<()> {
        self.backend.take(&plan_key(request_uri)).await.map(|_| ())
    }

    /// Consume a pushed request. Returns `None` if it is unknown or already
    /// consumed, which is what makes a `request_uri` one-time use. Whether
    /// the user was still in time is for the caller to have checked, with
    /// [`Store::arrive`] or [`Store::resume`].
    pub(crate) async fn take_request(
        &self,
        request_uri: &str,
        now: Timestamp,
    ) -> StoreResult<Option<PushedRequest>> {
        Self::pushed(self.backend.take(&request_key(request_uri)).await?, now)
    }

    /// Count a failed login. Returns `false` once the limit is reached:
    /// from then on [`Store::peek_request`] no longer finds the request, and
    /// the denial that follows consumes it with [`Store::take_request`].
    /// Consuming it there, rather than here, means exactly one caller ends
    /// up holding it, and so exactly one consent record is written.
    pub(crate) async fn record_failed_login(&self, request_uri: &str) -> StoreResult<bool> {
        let key = request_key(request_uri);
        let Some(record) = self.backend.increment(&key).await? else {
            return Ok(false);
        };
        Ok(record.count < u64::from(MAX_FAILED_LOGINS))
    }

    pub(crate) async fn create_code(&self, code: AuthorizationCode) -> StoreResult<String> {
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
    pub(crate) async fn redeem_code(
        &self,
        code: &str,
        client_id: &str,
        now: Timestamp,
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
    async fn revoke_grant(&self, grant_id: &str, now: Timestamp) -> StoreResult<()> {
        self.backend
            .put(
                &revoked_key(grant_id),
                String::new(),
                Some(now + self.grant_lifetime),
            )
            .await
    }

    async fn revoked(&self, grant_id: &str, now: Timestamp) -> StoreResult<bool> {
        Ok(self
            .backend
            .get(&revoked_key(grant_id))
            .await?
            .is_some_and(|record| record.live(now)))
    }

    async fn live<T: DeserializeOwned>(&self, key: &str, now: Timestamp) -> StoreResult<Option<T>> {
        match self.backend.get(key).await? {
            Some(record) if record.live(now) => decode(&record.value).map(Some),
            _ => Ok(None),
        }
    }

    pub(crate) async fn issue_access_token(&self, token: AccessToken) -> StoreResult<String> {
        let value = random_token(SECRET_BYTES);
        self.backend
            .put(&access_key(&value), encode(&token)?, Some(token.expires_at))
            .await?;
        Ok(value)
    }

    pub(crate) async fn access_token(&self, token: &str, now: Timestamp) -> StoreResult<Option<AccessToken>> {
        let Some(found) = self.live::<AccessToken>(&access_key(token), now).await? else {
            return Ok(None);
        };
        if self.revoked(&found.grant.id, now).await? {
            return Ok(None);
        }
        Ok(Some(found))
    }

    pub(crate) async fn issue_refresh_token(&self, token: RefreshToken) -> StoreResult<String> {
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

    pub(crate) async fn refresh_token(&self, token: &str, now: Timestamp) -> StoreResult<Option<RefreshToken>> {
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
    pub(crate) async fn record_jti(
        &self,
        client_id: &str,
        jti: &str,
        expires_at: Timestamp,
        now: Timestamp,
    ) -> StoreResult<bool> {
        // Hashed: both parts are chosen by the client and may be long.
        let key = format!("jti#{}", digest(&format!("{client_id}\n{jti}")));
        self.backend
            .put_new(&key, String::new(), Some(expires_at), now)
            .await
    }

    /// Record a decided transaction. Records do not expire; the in-memory
    /// backend keeps only the most recent [`MAX_CONSENT_RECORDS`].
    pub(crate) async fn record_consent(&self, record: ConsentRecord) -> StoreResult<()> {
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
    ///
    /// Consent history is a planned feature; nothing outside the tests
    /// reads this yet. Do not remove it as dead code.
    #[cfg_attr(not(test), expect(dead_code, reason = "the read side of the consent log, for the planned consent history"))]
    pub(crate) async fn consent_history(&self, user_subject: &str) -> StoreResult<Vec<ConsentRecord>> {
        self.backend
            .log_list(&consent_partition(Some(user_subject)))
            .await?
            .iter()
            .map(|value| decode(value))
            .collect()
    }

    /// Decisions made before anyone signed in, most recent first.
    #[cfg(test)]
    pub(crate) async fn consent_history_of_nobody(&self) -> Vec<ConsentRecord> {
        self.backend
            .log_list(&consent_partition(None))
            .await
            .unwrap()
            .iter()
            .map(|value| decode(value).unwrap())
            .collect()
    }

    /// The record of the transaction identified by `txn`. Like
    /// [`Store::consent_history`], planned for the consent history.
    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(dead_code, reason = "the read side of the consent log, for the planned consent history")
    )]
    pub(crate) async fn consent(&self, txn: &str) -> StoreResult<Option<ConsentRecord>> {
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
    pub(crate) async fn secret(
        &self,
        name: &str,
        generate: impl FnOnce() -> anyhow::Result<String>,
    ) -> StoreResult<String> {
        let key = format!("secret#{name}");
        if let Some(record) = self.backend.get(&key).await? {
            return Ok(record.value);
        }
        let candidate = generate().map_err(|source| StoreError::Generate {
            name: name.to_owned(),
            source: source.into(),
        })?;
        // Secrets never expire, so `now` is irrelevant to the condition.
        self.backend
            .put_new(&key, candidate, None, Timestamp::default())
            .await?;
        self.backend
            .get(&key)
            .await?
            .map(|record| record.value)
            .ok_or_else(|| {
                StoreError::Unavailable(format!("secret '{name}' vanished after being stored").into())
            })
    }

    /// Drop everything that has expired. Called periodically.
    pub(crate) async fn purge(&self, now: Timestamp) -> StoreResult<()> {
        self.backend.purge(now).await
    }
}

#[cfg(test)]
pub(crate) mod contract;

#[cfg(test)]
mod tests;
