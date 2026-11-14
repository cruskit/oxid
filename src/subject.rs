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
mod tests;
