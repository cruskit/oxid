//! Proof Key for Code Exchange (RFC 7636), S256 only.
//!
//! FAPI 2.0 §5.3.2.2-5 requires PKCE with `S256`; the `plain` method is
//! never accepted.

use crate::util::{b64url, ct_eq, sha256};

/// The only challenge method this provider accepts.
pub(crate) const METHOD_S256: &str = "S256";

/// A base64url SHA-256 digest is always 43 characters.
const CHALLENGE_LEN: usize = 43;

fn is_unreserved(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// Whether `challenge` is syntactically an S256 code challenge.
pub(crate) fn is_valid_challenge(challenge: &str) -> bool {
    challenge.len() == CHALLENGE_LEN
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Whether `verifier` meets RFC 7636 §4.1 (43-128 unreserved characters).
pub(crate) fn is_valid_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len()) && is_unreserved(verifier)
}

/// Check a code verifier against the stored S256 challenge.
pub(crate) fn verify(verifier: &str, challenge: &str) -> bool {
    is_valid_verifier(verifier) && ct_eq(b64url(sha256(verifier)), challenge)
}

#[cfg(test)]
mod tests;
