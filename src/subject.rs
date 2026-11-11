//! Pairwise subject identifiers (OpenID Connect Core §8.1).
//!
//! ConnectID requires that `subject_types_supported` is only `pairwise`, so a
//! user is known to each client sector by a different, unlinkable `sub`.

use aws_lc_rs::hmac;

use crate::util::b64url;

/// Derive the `sub` a given sector sees for a local user.
///
/// HMAC-SHA256 keyed with the deployment's salt gives a value that is stable,
/// differs per sector, and cannot be reversed or correlated without the salt.
pub fn pairwise(salt: &[u8], sector_identifier: &str, local_subject: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(sector_identifier.as_bytes());
    // A separator that cannot occur in a host name keeps (ab, c) != (a, bc).
    ctx.update(&[0]);
    ctx.update(local_subject.as_bytes());
    b64url(ctx.sign())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"0123456789abcdef";

    #[test]
    fn stable_for_the_same_inputs() {
        assert_eq!(
            pairwise(SALT, "rp.example.com", "u1"),
            pairwise(SALT, "rp.example.com", "u1")
        );
    }

    #[test]
    fn differs_by_sector_user_and_salt() {
        let base = pairwise(SALT, "rp.example.com", "u1");
        assert_ne!(base, pairwise(SALT, "other.example.com", "u1"));
        assert_ne!(base, pairwise(SALT, "rp.example.com", "u2"));
        assert_ne!(
            base,
            pairwise(b"another-salt-value", "rp.example.com", "u1")
        );
    }

    #[test]
    fn inputs_cannot_be_shifted_between_fields() {
        assert_ne!(pairwise(SALT, "ab", "c"), pairwise(SALT, "a", "bc"));
    }

    #[test]
    fn does_not_reveal_the_local_subject() {
        let sub = pairwise(SALT, "rp.example.com", "local-user-id");
        assert!(!sub.contains("local-user-id"));
        assert_eq!(sub.len(), 43);
    }
}
