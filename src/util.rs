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
mod tests {
    use super::*;

    #[test]
    fn b64url_round_trips_without_padding() {
        let encoded = b64url([0xfb, 0xff, 0x01]);
        assert_eq!(encoded, "-_8B");
        assert_eq!(b64url_decode(&encoded).unwrap(), vec![0xfb, 0xff, 0x01]);
        assert!(b64url_decode("not base64!").is_none());
        assert!(b64url_decode("-_8B==").is_none(), "padding is rejected");
    }

    #[test]
    fn sha256_matches_known_vector() {
        // RFC 7636 appendix B: the S256 challenge for this verifier.
        let digest = sha256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        assert_eq!(
            b64url(digest),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn random_tokens_are_unique_and_long_enough() {
        let a = random_token(32);
        let b = random_token(32);
        assert_ne!(a, b);
        assert_eq!(b64url_decode(&a).unwrap().len(), 32);
    }

    #[test]
    fn ct_eq_compares_content() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
    }

    #[test]
    fn manual_clock_moves_only_on_request() {
        let clock = ManualClock::new(100);
        assert_eq!(clock.now(), 100);
        clock.advance(5);
        assert_eq!(clock.now(), 105);
        clock.set(7);
        assert_eq!(clock.now(), 7);
    }

    #[test]
    fn system_clock_is_after_2024() {
        assert!(SystemClock.now() > 1_704_067_200);
    }
}
