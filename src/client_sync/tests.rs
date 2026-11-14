use super::*;
use crate::jose::{Jws, SigningAlg};
use crate::testing::shared_key;

fn config() -> ClientSyncConfig {
    toml::from_str(
        r#"
            enabled = true
            discovery_url = "https://auth.registry.example/.well-known/openid-configuration"
            clients_url = "https://matls-api.registry.example/clients"
            client_id = "oxid-idp"
            transport_cert = "transport.pem"
            transport_key = "transport.key"
            signing_key = "signing.key"
            signing_key_id = "registry-kid-1"
            "#,
    )
    .unwrap()
}

fn entry() -> Value {
    json!({
        "client_id": "26c2183c-5e9c-4a63-bc65-164d8e316719",
        "software_id": "26c2183c-5e9c-4a63-bc65-164d8e316719",
        "client_name": "Great Accounting App",
        "redirect_uris": ["https://my.accountingapp.com/cb"],
        "token_endpoint_auth_method": "private_key_jwt",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "openid",
        "jwks_uri": "https://keystore.registry.example/org/app/application.jwks",
        "sector_identifier_uri": "https://sector.accountingapp.com/redirect_uris.json",
        "subject_type": "pairwise",
        "claims": ["given_name", "family_name", "address"],
        "claims_in_verified_claims": ["over18", "over21"],
        "status": "Active",
        "org_status": "Active",
        "org_name": "Test Org",
    })
}

#[test]
fn config_has_defaults_and_is_validated() {
    type Edit = fn(&mut ClientSyncConfig);
    let defaults = config();
    defaults.validate().unwrap();
    assert_eq!(defaults.scope, "directory:software");
    assert_eq!(defaults.page_size, 50);
    assert_eq!(defaults.profile, Profile::Connectid);
    assert!(defaults.ca.is_none());

    let bad: [(&str, Edit); 7] = [
        ("no way to find the token endpoint", |c| {
            c.discovery_url = None;
        }),
        ("plain http discovery", |c| {
            c.discovery_url = Some("http://registry.example/meta".into());
        }),
        ("plain http clients", |c| {
            c.clients_url = "http://registry.example/clients".into();
        }),
        ("plain http token endpoint", |c| {
            c.token_endpoint = Some("http://registry.example/token".into());
        }),
        ("empty client id", |c| c.client_id = " ".into()),
        ("empty key id", |c| c.signing_key_id = String::new()),
        ("zero page size", |c| c.page_size = 0),
    ];
    for (name, edit) in bad {
        let mut config = config();
        edit(&mut config);
        assert!(config.validate().is_err(), "{name}");
    }

    let mut explicit = config();
    explicit.discovery_url = None;
    explicit.token_endpoint = Some("https://matls-auth.registry.example/token".into());
    explicit.validate().unwrap();

    assert!(
        toml::from_str::<ClientSyncConfig>("enabled = true\nclient_secret = \"x\"").is_err(),
        "unknown fields are refused"
    );
}

#[test]
fn token_endpoint_prefers_the_mtls_alias() {
    let metadata = json!({
        "issuer": "https://auth.registry.example",
        "token_endpoint": "https://auth.registry.example/token",
        "mtls_endpoint_aliases": {"token_endpoint": "https://matls-auth.registry.example/token"},
    });
    assert_eq!(
        discovered_token_endpoint(&metadata).unwrap(),
        "https://matls-auth.registry.example/token"
    );
    let plain = json!({"token_endpoint": "https://auth.registry.example/token"});
    assert_eq!(
        discovered_token_endpoint(&plain).unwrap(),
        "https://auth.registry.example/token"
    );
    assert!(discovered_token_endpoint(&json!({})).is_none());
}

#[test]
fn client_assertion_is_a_private_key_jwt_with_the_registry_kid() {
    let config = config();
    let assertion =
        client_assertion(&config, shared_key(), "https://auth.registry.example", 1000).unwrap();
    let jws = Jws::parse(&assertion, &[SigningAlg::PS256]).unwrap();
    assert_eq!(jws.kid.as_deref(), Some("registry-kid-1"));
    assert_eq!(jws.str_claim("iss"), Some("oxid-idp"));
    assert_eq!(jws.str_claim("sub"), Some("oxid-idp"));
    assert_eq!(jws.str_claim("aud"), Some("https://auth.registry.example"));
    assert_eq!(jws.time_claim("iat"), Some(1000));
    assert_eq!(jws.time_claim("exp"), Some(1060));
    assert!(jws.str_claim("jti").is_some_and(|jti| jti.len() >= 16));

    // The signature is by the configured key, whatever kid is claimed.
    let mut jwks = shared_key().jwks();
    jwks.keys[0].common.key_id = Some("registry-kid-1".to_owned());
    jws.verify(&jwks).unwrap();

    let again =
        client_assertion(&config, shared_key(), "https://auth.registry.example", 1000).unwrap();
    let other = Jws::parse(&again, &[SigningAlg::PS256]).unwrap();
    assert_ne!(
        jws.str_claim("jti"),
        other.str_claim("jti"),
        "jti is unique"
    );
}

/// A response shaped like the registry's `RegisteredClientsResponse`.
fn response(clients: usize, page: u64, size: u64, total: u64) -> Value {
    json!({
        "content": vec![json!({}); clients],
        "totalPages": total.div_ceil(size),
        "totalSize": total,
        "pageable": {"number": page, "size": size, "offset": page * size},
        "size": size,
        "offset": page * size,
        "empty": clients == 0,
        "pageNumber": page,
    })
}

#[test]
fn pages_follow_the_registry_pagination_properties() {
    // 120 clients at 50 a page: pages 0 and 1 are full, page 2 has 20.
    let first = ClientsPage::parse(&response(50, 0, 50, 120), 0).unwrap();
    assert_eq!(first.entries.len(), 50);
    assert_eq!(first.total_pages, 3);
    assert_eq!(first.total_size, Some(120));
    assert!(first.has_next(0));
    let second = ClientsPage::parse(&response(50, 1, 50, 120), 1).unwrap();
    assert!(second.has_next(1));
    let last = ClientsPage::parse(&response(20, 2, 50, 120), 2).unwrap();
    assert_eq!(last.entries.len(), 20);
    assert!(!last.has_next(2));

    // A full last page is still the last page: totalPages decides, not
    // how many results came back.
    let exact = ClientsPage::parse(&response(50, 1, 50, 100), 1).unwrap();
    assert!(!exact.has_next(1));

    // No clients at all.
    let none = ClientsPage::parse(&response(0, 0, 50, 0), 0).unwrap();
    assert_eq!(none.entries.len(), 0);
    assert_eq!(none.total_pages, 0);
    assert!(!none.has_next(0));
}

#[test]
fn optional_pagination_properties_may_be_absent() {
    let minimal = json!({"content": [{}, {}], "totalPages": 2});
    let page = ClientsPage::parse(&minimal, 0).unwrap();
    assert_eq!(page.entries.len(), 2);
    assert_eq!(page.total_size, None);
    assert!(page.has_next(0));
    assert!(!ClientsPage::parse(&minimal, 1).unwrap().has_next(1));
}

#[test]
fn malformed_or_inconsistent_pages_are_errors() {
    for (name, body) in [
        (
            "an error body",
            json!({"errors": ["endDate format is invalid"]}),
        ),
        ("a bare list", json!([{}, {}])),
        (
            "content that is not a list",
            json!({"content": "x", "totalPages": 1}),
        ),
        ("no totalPages", json!({"content": [{}]})),
        ("a text body", json!("clients")),
        (
            "content on a page marked empty",
            json!({"content": [{}], "totalPages": 1, "empty": true}),
        ),
    ] {
        assert!(ClientsPage::parse(&body, 0).is_err(), "{name}");
    }
    // The registry answering with a different page than was asked for.
    let error = ClientsPage::parse(&response(50, 0, 50, 120), 1).unwrap_err();
    assert!(error.to_string().contains("page 1"), "{error}");
}

#[test]
fn registry_entry_becomes_a_client() {
    let parsed = RegistryClient::parse(&entry(), Profile::Connectid)
        .unwrap()
        .unwrap();
    assert_eq!(parsed.client_id, "26c2183c-5e9c-4a63-bc65-164d8e316719");
    assert_eq!(
        parsed.sector_identifier.as_deref(),
        Some("sector.accountingapp.com")
    );
    assert_eq!(
        parsed.claims,
        ["address", "family_name", "given_name", "over18", "over21"]
    );

    let client = parsed
        .into_client(shared_key().jwks(), Profile::Connectid)
        .unwrap();
    assert_eq!(client.name, "Great Accounting App");
    assert!(client.has_redirect_uri("https://my.accountingapp.com/cb"));
    assert_eq!(client.sector_identifier, "sector.accountingapp.com");
    assert!(client.allows_claim("given_name") && client.allows_claim("over18"));
    assert!(!client.allows_claim("email"), "not accredited for email");
    assert!(!client.allows_claim("over65"));
    assert!(!client.allows_refresh_tokens());
    assert_eq!(client.profile, Profile::Connectid);
}

#[test]
fn registry_entries_are_normalised() {
    let mut odd = entry();
    odd["grant_types"] = json!(["refresh_token", "client_credentials", "implicit"]);
    odd["scope"] = json!("profile  payments");
    odd["claims"] = json!(["given_name", "nickname", "made_up", 7]);
    odd["claims_in_verified_claims"] = json!(["over18", "place_of_birth"]);
    odd.as_object_mut().unwrap().remove("sector_identifier_uri");
    odd.as_object_mut().unwrap().remove("client_id");
    let parsed = RegistryClient::parse(&odd, Profile::Connectid)
        .unwrap()
        .unwrap();
    assert_eq!(
        parsed.client_id, "26c2183c-5e9c-4a63-bc65-164d8e316719",
        "software_id"
    );
    assert_eq!(parsed.grant_types, ["authorization_code", "refresh_token"]);
    assert_eq!(parsed.scopes, ["openid", "profile", "payments"]);
    assert_eq!(
        parsed.claims,
        ["given_name", "over18"],
        "unknown names are dropped"
    );
    assert!(parsed.sector_identifier.is_none());
    // Without a sector identifier URI it is derived from the redirect host.
    let client = parsed
        .into_client(shared_key().jwks(), Profile::Connectid)
        .unwrap();
    assert_eq!(client.sector_identifier, "my.accountingapp.com");
    assert!(client.allows_refresh_tokens());

    // No claims at all means nothing is released, not everything.
    let mut none = entry();
    none.as_object_mut().unwrap().remove("claims");
    none.as_object_mut()
        .unwrap()
        .remove("claims_in_verified_claims");
    let client = RegistryClient::parse(&none, Profile::Connectid)
        .unwrap()
        .unwrap()
        .into_client(shared_key().jwks(), Profile::Connectid)
        .unwrap();
    assert!(!client.allows_claim("given_name"));
}

#[test]
fn inactive_clients_are_not_registered() {
    for (member, status) in [
        ("status", "Inactive"),
        ("status", "Suspended"),
        ("org_status", "Withdrawn"),
    ] {
        let mut inactive = entry();
        inactive[member] = json!(status);
        assert!(
            RegistryClient::parse(&inactive, Profile::Connectid)
                .unwrap()
                .is_none(),
            "{member}={status}"
        );
    }
    let mut lower = entry();
    lower["status"] = json!("active");
    assert!(
        RegistryClient::parse(&lower, Profile::Connectid)
            .unwrap()
            .is_some()
    );
    let mut missing = entry();
    missing.as_object_mut().unwrap().remove("status");
    assert!(
        RegistryClient::parse(&missing, Profile::Connectid)
            .unwrap()
            .is_some()
    );
}

#[test]
fn unusable_entries_are_errors() {
    type Edit = fn(&mut Value);
    let cases: [(&str, Edit); 5] = [
        ("no id", |e| {
            e.as_object_mut().unwrap().remove("client_id");
            e.as_object_mut().unwrap().remove("software_id");
        }),
        ("no redirect uris", |e| e["redirect_uris"] = json!([])),
        ("no keys", |e| {
            e.as_object_mut().unwrap().remove("jwks_uri");
        }),
        ("malformed inline keys", |e| {
            e["jwks"] = json!({"keys": "x"});
        }),
        ("blank id", |e| e["client_id"] = json!("  ")),
    ];
    for (name, edit) in cases {
        let mut bad = entry();
        edit(&mut bad);
        if name == "blank id" {
            bad.as_object_mut().unwrap().remove("software_id");
        }
        assert!(
            RegistryClient::parse(&bad, Profile::Connectid).is_err(),
            "{name}"
        );
    }

    // A client that parses but cannot be registered (insecure redirect).
    let mut insecure = entry();
    insecure["redirect_uris"] = json!(["http://my.accountingapp.com/cb"]);
    let parsed = RegistryClient::parse(&insecure, Profile::Connectid)
        .unwrap()
        .unwrap();
    assert!(
        parsed
            .into_client(shared_key().jwks(), Profile::Connectid)
            .is_err()
    );
}

#[test]
fn inline_keys_are_accepted_in_place_of_a_jwks_uri() {
    let mut inline = entry();
    inline.as_object_mut().unwrap().remove("jwks_uri");
    inline["jwks"] = serde_json::to_value(shared_key().jwks()).unwrap();
    let parsed = RegistryClient::parse(&inline, Profile::Connectid)
        .unwrap()
        .unwrap();
    assert!(parsed.jwks.is_some() && parsed.jwks_uri.is_none());
}
