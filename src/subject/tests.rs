
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
