use jsonwebtoken::jwk::AlgorithmParameters;

use super::*;

#[test]
fn generated_key_publishes_only_public_rsa_material() {
    let key = crate::testing::shared_key();
    let jwks = serde_json::to_value(key.jwks()).unwrap();
    let jwk = &jwks["keys"][0];
    assert_eq!(jwk["kty"], "RSA");
    assert_eq!(jwk["use"], "sig");
    assert_eq!(jwk["alg"], "PS256");
    assert_eq!(jwk["kid"], key.kid());
    for private in ["d", "p", "q", "dp", "dq", "qi"] {
        assert!(
            jwk.get(private).is_none(),
            "{private} must not be published"
        );
    }
    assert!(matches!(
        key.public_jwk().algorithm,
        AlgorithmParameters::RSA(_)
    ));
}

#[test]
fn debug_output_does_not_leak_key_material() {
    let key = crate::testing::shared_key();
    let debug = format!("{key:?}");
    assert!(debug.contains(key.kid()));
    assert!(!debug.contains("encoding_key"));
}

#[test]
fn rejects_non_rsa_pem() {
    assert!(SigningKey::from_pem(b"not a key").is_err());
}

#[test]
fn kid_is_stable_for_the_same_key() {
    let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let der = AsDer::<aws_lc_rs::encoding::Pkcs8V1Der<'_>>::as_der(&pair).unwrap();
    let pem = pkcs8_pem(der.as_ref());
    let a = SigningKey::from_pem(pem.as_bytes()).unwrap();
    let b = SigningKey::from_pem(pem.as_bytes()).unwrap();
    assert_eq!(a.kid(), b.kid());
}
