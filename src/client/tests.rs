
use super::*;
use crate::keys::test_support::shared_key;

fn config() -> ClientConfig {
    ClientConfig {
        client_id: "rp".to_owned(),
        client_name: None,
        redirect_uris: vec!["https://rp.example.com/cb".to_owned()],
        jwks_file: None,
        jwks: Some(shared_key().jwks()),
        scopes: vec!["openid".to_owned()],
        grant_types: vec![GRANT_AUTHORIZATION_CODE.to_owned()],
        sector_identifier: None,
        profile: Profile::Connectid,
        claims: None,
    }
}

#[test]
fn claims_default_to_everything_and_can_be_restricted() {
    let open = Client::from_config(&config()).unwrap();
    assert!(open.allows_claim("email") && open.allows_claim("beneficiary_account_au"));

    let mut c = config();
    c.claims = Some(vec!["given_name".to_owned(), "over18".to_owned()]);
    let limited = Client::from_config(&c).unwrap();
    assert!(limited.allows_claim("given_name") && limited.allows_claim("over18"));
    assert!(!limited.allows_claim("email") && !limited.allows_claim("over21"));

    c.claims = Some(vec![]);
    assert!(!Client::from_config(&c).unwrap().allows_claim("given_name"));

    c.claims = Some(vec!["nickname".to_owned()]);
    let err = Client::from_config(&c).unwrap_err().to_string();
    assert!(err.contains("nickname"), "{err}");

    // The same list is fine for a standard OpenID Connect client, which
    // in turn has no ConnectID verified claims.
    c.profile = Profile::Oidc;
    let oidc = Client::from_config(&c).unwrap();
    assert!(oidc.allows_claim("nickname") && !oidc.allows_claim("email"));
    c.claims = None;
    let oidc = Client::from_config(&c).unwrap();
    assert!(oidc.allows_claim("name") && oidc.allows_claim("email_verified"));
    assert!(!oidc.allows_claim("over18"));
    assert!(!open.allows_claim("name"), "not a ConnectID claim");
    c.claims = Some(vec!["over18".to_owned()]);
    assert!(Client::from_config(&c).is_err());
}

#[test]
fn builds_a_client_with_derived_defaults() {
    let client = Client::from_config(&config()).unwrap();
    assert_eq!(client.name, "rp");
    assert_eq!(client.sector_identifier, "rp.example.com");
    assert!(!client.allows_refresh_tokens());
}

#[test]
fn redirect_uri_matching_is_exact() {
    let client = Client::from_config(&config()).unwrap();
    assert!(client.has_redirect_uri("https://rp.example.com/cb"));
    assert!(!client.has_redirect_uri("https://rp.example.com/cb/"));
    assert!(!client.has_redirect_uri("https://rp.example.com/cb?x=1"));
    assert!(!client.has_redirect_uri("https://RP.example.com/cb"));
}

#[test]
fn rejects_insecure_or_malformed_redirect_uris() {
    for bad in [
        "http://rp.example.com/cb",
        "https://rp.example.com/cb#frag",
        "custom-scheme://cb",
        "http://localhost/cb",
        "not a url",
    ] {
        let mut c = config();
        c.redirect_uris = vec![bad.to_owned()];
        assert!(Client::from_config(&c).is_err(), "{bad}");
    }
}

#[test]
fn loopback_http_is_allowed_for_native_clients() {
    let mut c = config();
    c.redirect_uris = vec!["http://127.0.0.1:8123/cb".to_owned()];
    Client::from_config(&c).unwrap();
}

#[test]
fn several_redirect_hosts_need_an_explicit_sector() {
    let mut c = config();
    c.redirect_uris
        .push("https://other.example.com/cb".to_owned());
    assert!(Client::from_config(&c).is_err());
    c.sector_identifier = Some("rp.example.com".to_owned());
    assert_eq!(
        Client::from_config(&c).unwrap().sector_identifier,
        "rp.example.com"
    );
}

#[test]
fn needs_keys_and_supported_grants() {
    let mut no_keys = config();
    no_keys.jwks = None;
    assert!(Client::from_config(&no_keys).is_err());

    let mut empty_keys = config();
    empty_keys.jwks = Some(JwkSet { keys: vec![] });
    assert!(Client::from_config(&empty_keys).is_err());

    let mut password_grant = config();
    password_grant.grant_types.push("password".to_owned());
    assert!(Client::from_config(&password_grant).is_err());

    let mut refresh_only = config();
    refresh_only.grant_types = vec![GRANT_REFRESH_TOKEN.to_owned()];
    assert!(Client::from_config(&refresh_only).is_err());

    let mut no_redirects = config();
    no_redirects.redirect_uris.clear();
    assert!(Client::from_config(&no_redirects).is_err());
}

#[test]
fn registry_looks_up_by_id_and_rejects_duplicates() {
    let registry = StaticClientRegistry::from_config(&[config()]).unwrap();
    assert_eq!(registry.len(), 1);
    assert!(registry.get("rp").is_some());
    assert!(registry.get("unknown").is_none());
    assert!(StaticClientRegistry::from_config(&[config(), config()]).is_err());

    assert_eq!(registry.profiles(), BTreeSet::from([Profile::Connectid]));
    let mut oidc = config();
    oidc.client_id = "rp2".to_owned();
    oidc.profile = Profile::Oidc;
    let mixed = StaticClientRegistry::from_config(&[config(), oidc]).unwrap();
    assert_eq!(
        mixed.profiles(),
        BTreeSet::from([Profile::Connectid, Profile::Oidc])
    );
    assert_eq!(
        StaticClientRegistry::default().profiles(),
        BTreeSet::from([Profile::Connectid])
    );
}
