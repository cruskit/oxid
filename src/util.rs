//! Small helpers shared across the crate: encoding, hashing, randomness and time.
//!
//! All cryptographic primitives are delegated to `aws-lc-rs`; nothing here
//! implements an algorithm itself.

use std::fmt::Debug;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::{constant_time, digest, rand};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A value that must never be printed: its `Debug` output is redacted, so a
/// `?config` or `dbg!` cannot leak it into logs. Read it with
/// [`Secret::expose`].
#[derive(Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(transparent)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// The secret value. Do not log it.
    pub const fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

/// Encode bytes as unpadded base64url (RFC 4648 §5).
pub fn b64url(data: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode unpadded base64url, returning `None` on malformed input.
pub fn b64url_decode(data: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(data).ok()
}

/// SHA-256 digest of `data`.
pub fn sha256(data: impl AsRef<[u8]>) -> [u8; 32] {
    let digest = digest::digest(&digest::SHA256, data.as_ref());
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// A URL-safe random string carrying `bytes * 8` bits of entropy.
///
/// FAPI 2.0 §5.4.1 requires at least 128 bits for credentials that are not
/// handled by end users; callers in this crate use 32 bytes (256 bits).
#[expect(
    clippy::expect_used,
    reason = "without a working random number generator no credential can be issued safely"
)]
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::fill(&mut buf).expect("system random number generator failed");
    b64url(buf)
}

/// Constant-time byte comparison.
pub fn ct_eq(a: impl AsRef<[u8]>, b: impl AsRef<[u8]>) -> bool {
    constant_time::verify_slices_are_equal(a.as_ref(), b.as_ref()).is_ok()
}

/// Source of the current time, injectable so expiry logic can be unit tested.
pub trait Clock: Send + Sync + Debug {
    /// Seconds since the Unix epoch.
    fn now(&self) -> i64;
}

/// The real wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        i64::try_from(secs).unwrap_or(i64::MAX)
    }
}

/// A clock that only moves when told to. Intended for tests.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicI64);

impl ManualClock {
    pub fn new(now: i64) -> Self {
        Self(AtomicI64::new(now))
    }

    pub fn set(&self, now: i64) {
        self.0.store(now, Ordering::SeqCst);
    }

    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests;
