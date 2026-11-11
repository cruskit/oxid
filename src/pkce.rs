//! Proof Key for Code Exchange (RFC 7636), S256 only.
//!
//! FAPI 2.0 §5.3.2.2-5 requires PKCE with `S256`; the `plain` method is
//! never accepted.

use crate::util::{b64url, ct_eq, sha256};

/// The only challenge method this provider accepts.
pub const METHOD_S256: &str = "S256";

/// A base64url SHA-256 digest is always 43 characters.
const CHALLENGE_LEN: usize = 43;

fn is_unreserved(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// Whether `challenge` is syntactically an S256 code challenge.
pub fn is_valid_challenge(challenge: &str) -> bool {
    challenge.len() == CHALLENGE_LEN
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Whether `verifier` meets RFC 7636 §4.1 (43-128 unreserved characters).
pub fn is_valid_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len()) && is_unreserved(verifier)
}

/// Check a code verifier against the stored S256 challenge.
pub fn verify(verifier: &str, challenge: &str) -> bool {
    is_valid_verifier(verifier) && ct_eq(b64url(sha256(verifier)), challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7636 appendix B.
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn accepts_the_rfc_example() {
        assert!(is_valid_challenge(CHALLENGE));
        assert!(is_valid_verifier(VERIFIER));
        assert!(verify(VERIFIER, CHALLENGE));
    }

    #[test]
    fn rejects_a_wrong_verifier() {
        let wrong = VERIFIER.replace('d', "e");
        assert!(!verify(&wrong, CHALLENGE));
    }

    #[test]
    fn plain_method_does_not_verify() {
        // With `plain`, challenge == verifier. That must never pass.
        assert!(!verify(VERIFIER, VERIFIER));
    }

    #[test]
    fn rejects_malformed_verifiers() {
        assert!(!is_valid_verifier("too-short"));
        assert!(!is_valid_verifier(&"a".repeat(129)));
        assert!(!is_valid_verifier(&format!("{}!", "a".repeat(50))));
        assert!(is_valid_verifier(&"a".repeat(43)));
        assert!(is_valid_verifier(&"a-._~".repeat(20)));
    }

    #[test]
    fn rejects_malformed_challenges() {
        assert!(!is_valid_challenge(""));
        assert!(!is_valid_challenge(&CHALLENGE[1..]));
        assert!(!is_valid_challenge(&format!("{}=", &CHALLENGE[1..])));
        assert!(!is_valid_challenge(&format!("{CHALLENGE}x")));
    }
}
