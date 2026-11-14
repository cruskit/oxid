use super::*;

fn identity() -> TlsIdentity {
    TlsIdentity::self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]).unwrap()
}

#[test]
fn only_bcp195_suites_are_offered_for_tls12() {
    let provider = provider();
    let mut tls12 = 0;
    for suite in &provider.cipher_suites {
        if let SupportedCipherSuite::Tls12(_) = suite {
            tls12 += 1;
            assert!(TLS12_SUITES.contains(&suite.suite()), "{:?}", suite.suite());
        }
    }
    assert_eq!(tls12, TLS12_SUITES.len());
    assert!(
        provider
            .cipher_suites
            .iter()
            .any(|s| matches!(s, SupportedCipherSuite::Tls13(_)))
    );
}

#[test]
fn builds_configs_for_each_policy() {
    let identity = identity();
    let public = server_config(&identity, ClientCertPolicy::None).unwrap();
    assert_eq!(
        public.alpn_protocols,
        [b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    server_config(&identity, ClientCertPolicy::AnyProven).unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(identity.certs[0].clone()).unwrap();
    server_config(&identity, ClientCertPolicy::TrustedRoots(roots)).unwrap();
}

#[test]
fn proof_of_possession_verifier_requests_but_does_not_require_a_cert() {
    let verifier = ProofOfPossessionOnly {
        algorithms: provider().signature_verification_algorithms,
    };
    assert!(verifier.offer_client_auth());
    assert!(!verifier.client_auth_mandatory());
    assert_ne!(verifier.supported_verify_schemes(), Vec::new());
}

#[test]
fn thumbprint_is_base64url_sha256_of_the_der() {
    let cert = ClientCert::from_der(b"abc");
    // SHA-256("abc"), base64url.
    assert_eq!(
        cert.thumbprint,
        "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
    );
}

#[test]
fn pem_round_trips_through_the_file_loaders() {
    let identity = identity();
    let dir = std::env::temp_dir().join(format!("oxid-tls-test-{}", crate::util::random_token(8)));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert, identity.cert_pem()).unwrap();
    std::fs::write(&key, identity.key_pem()).unwrap();

    let loaded = TlsIdentity::from_pem_files(&cert, &key).unwrap();
    assert_eq!(loaded.certs, identity.certs);
    server_config(&loaded, ClientCertPolicy::None).unwrap();
    assert!(matches!(
        ClientCertPolicy::from_ca_file(&cert).unwrap(),
        ClientCertPolicy::TrustedRoots(_)
    ));
    assert!(
        TlsIdentity::from_pem_files(&key, &key).is_err(),
        "no certificate in key file"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
