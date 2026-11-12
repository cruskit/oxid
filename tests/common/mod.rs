//! Shared harness for the integration tests.
//!
//! Each test starts a real oxID instance on ephemeral ports and talks to it
//! over TLS, exactly as a relying party and a browser would: a public
//! listener for the browser leg and a mutual-TLS listener for the back
//! channel.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::Arc;

use oxid::config::{ClientConfig, Config};
use oxid::jose::{Jws, SigningAlg};
use oxid::keys::SigningKey;
use oxid::server::{Server, ServerBuilder};
use oxid::tls::TlsIdentity;
use oxid::user::{DEMO_PASSWORD, DEMO_USERNAME};
use oxid::util::{Clock, ManualClock, SystemClock, b64url, random_token, sha256};
use reqwest::header::{COOKIE, LOCATION, SET_COOKIE};
use reqwest::redirect::Policy;
use reqwest::{Certificate, Client, Identity, Response, StatusCode};
use serde_json::{Map, Value, json};
use url::Url;

pub const CLIENT_ID: &str = "test-rp";
pub const REDIRECT_URI: &str = "https://rp.example.com/callback";
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// A relying party's view of one authorization attempt.
#[derive(Debug, Clone)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    pub fn new() -> Self {
        let verifier = random_token(32);
        let challenge = b64url(sha256(&verifier));
        Self {
            verifier,
            challenge,
        }
    }
}

pub struct TestOp {
    server: Option<Server>,
    pub issuer: String,
    pub mtls: String,
    pub clock: Arc<ManualClock>,
    /// The relying party's private key (registered with the provider).
    pub rp_key: SigningKey,
    /// A browser: no client certificate, never follows redirects.
    pub browser: Client,
    /// The relying party's back channel, presenting its TLS certificate.
    pub rp: Client,
    /// Same relying party, different TLS certificate.
    pub rp_other_cert: Client,
    /// SHA-256 thumbprint of the certificate `rp` presents.
    pub rp_cert_thumbprint: String,
}

impl TestOp {
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    /// Start a provider, letting the test adjust the configuration first.
    pub async fn start_with(adjust: impl FnOnce(&mut Config)) -> Self {
        let public = TcpListener::bind("127.0.0.1:0").unwrap();
        let mtls = TcpListener::bind("127.0.0.1:0").unwrap();
        let issuer = format!("https://localhost:{}", public.local_addr().unwrap().port());
        let mtls_base = format!("https://localhost:{}", mtls.local_addr().unwrap().port());

        let rp_key = SigningKey::generate().unwrap();
        let mut config: Config = toml::from_str(&format!(
            "issuer = \"{issuer}\"\nmtls_base_url = \"{mtls_base}\"\n\
             [keys]\npairwise_salt = \"integration-test-salt\"\n"
        ))
        .unwrap();
        config.clients.push(ClientConfig {
            client_id: CLIENT_ID.to_owned(),
            client_name: Some("Integration Test RP".to_owned()),
            redirect_uris: vec![REDIRECT_URI.to_owned()],
            jwks_file: None,
            jwks: Some(rp_key.jwks()),
            scopes: vec!["openid".to_owned()],
            grant_types: vec!["authorization_code".to_owned(), "refresh_token".to_owned()],
            sector_identifier: None,
            profile: oxid::client::Profile::Connectid,
            claims: None,
        });
        // Most tests drive the sign-in and consent page; tests of another
        // experience select it in `adjust`.
        config.experience = oxid::experience::Kind::Login;
        adjust(&mut config);

        // A manual clock started at the real time: flows behave normally and
        // expiry tests can jump forward instead of sleeping.
        let clock = Arc::new(ManualClock::new(SystemClock.now()));
        let server = ServerBuilder::new(config)
            .clock(Arc::clone(&clock) as Arc<dyn Clock>)
            .listeners(public, mtls)
            .start()
            .await
            .expect("server starts");

        let trust = Certificate::from_der(server.certificate().as_ref()).unwrap();
        let base = || {
            Client::builder()
                .tls_certs_only([trust.clone()])
                .redirect(Policy::none())
                .https_only(true)
        };
        let (rp_identity, rp_cert_thumbprint) = client_identity();
        let (other_identity, _) = client_identity();

        Self {
            server: Some(server),
            issuer,
            mtls: mtls_base,
            clock,
            rp_key,
            browser: base().build().unwrap(),
            rp: base().identity(rp_identity).build().unwrap(),
            rp_other_cert: base().identity(other_identity).build().unwrap(),
            rp_cert_thumbprint,
        }
    }

    pub async fn stop(mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown().await;
        }
    }

    /// The running provider's state, for assertions on what it recorded.
    pub fn state(&self) -> &oxid::state::AppState {
        self.server.as_ref().expect("server is running").state()
    }

    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.issuer)
    }

    pub fn mtls_url(&self, path: &str) -> String {
        format!("{}{path}", self.mtls)
    }

    /// A fresh `private_key_jwt` assertion.
    pub fn assertion(&self) -> String {
        self.assertion_with(&json!({}))
    }

    pub fn assertion_with(&self, overrides: &Value) -> String {
        let now = self.now();
        let mut claims = json!({
            "iss": CLIENT_ID, "sub": CLIENT_ID, "aud": self.issuer,
            "jti": random_token(16), "iat": now, "nbf": now, "exp": now + 60,
        });
        apply(&mut claims, overrides);
        self.rp_key.sign(Some("JWT"), &claims).unwrap()
    }

    /// Claims of a valid request object; `overrides` replaces members and
    /// `null` removes them.
    pub fn request_claims(&self, pkce: &Pkce, overrides: &Value) -> Value {
        let now = self.now();
        let mut claims = json!({
            "iss": CLIENT_ID, "aud": self.issuer,
            "iat": now, "nbf": now, "exp": now + 300,
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "state-123",
            "nonce": "nonce-456",
            "code_challenge": pkce.challenge,
            "code_challenge_method": "S256",
        });
        apply(&mut claims, overrides);
        claims
    }

    pub fn request_object(&self, pkce: &Pkce, overrides: &Value) -> String {
        self.rp_key
            .sign(
                Some("oauth-authz-req+jwt"),
                &self.request_claims(pkce, overrides),
            )
            .unwrap()
    }

    /// POST to the mTLS PAR endpoint.
    pub async fn par(&self, request_object: &str) -> Response {
        self.rp
            .post(self.mtls_url("/par"))
            .form(&[
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &self.assertion()),
                ("request", request_object),
            ])
            .send()
            .await
            .unwrap()
    }

    /// Push a request and return its `request_uri`.
    pub async fn push(&self, pkce: &Pkce, overrides: &Value) -> String {
        let response = self.par(&self.request_object(pkce, overrides)).await;
        let status = response.status();
        let body: Value = response.json().await.unwrap();
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["request_uri"].as_str().unwrap().to_owned()
    }

    pub fn authorize_url(&self, request_uri: &str) -> String {
        let mut url = Url::parse(&self.url("/authorize")).unwrap();
        url.query_pairs_mut()
            .append_pair("client_id", CLIENT_ID)
            .append_pair("request_uri", request_uri);
        url.into()
    }

    /// Load the login page as a browser would, returning the session.
    pub async fn open_login(&self, request_uri: &str) -> LoginPage {
        let response = self
            .browser
            .get(self.authorize_url(request_uri))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        LoginPage::from_response(response).await
    }

    /// Submit the login form as a browser would, with every offered claim
    /// left ticked.
    pub async fn decide(
        &self,
        page: &LoginPage,
        request_uri: &str,
        username: &str,
        password: &str,
        action: &str,
    ) -> Response {
        self.decide_declining(page, request_uri, username, password, action, &[])
            .await
    }

    /// As [`Self::decide`], but unticking the checkboxes of `declined` claims.
    pub async fn decide_declining(
        &self,
        page: &LoginPage,
        request_uri: &str,
        username: &str,
        password: &str,
        action: &str,
        declined: &[&str],
    ) -> Response {
        let mut form = vec![
            ("csrf".to_owned(), page.csrf.clone()),
            ("client_id".to_owned(), CLIENT_ID.to_owned()),
            ("request_uri".to_owned(), request_uri.to_owned()),
            ("username".to_owned(), username.to_owned()),
            ("password".to_owned(), password.to_owned()),
            ("action".to_owned(), action.to_owned()),
        ];
        form.extend(
            page.ticked()
                .into_iter()
                .filter(|field| !declined.iter().any(|d| *field == format!("share_{d}")))
                .map(|field| (field, "1".to_owned())),
        );
        self.browser
            .post(self.url("/authorize/decision"))
            .header(COOKIE, &page.cookie)
            .form(&form)
            .send()
            .await
            .unwrap()
    }

    /// Complete the browser leg as the demo user; returns the redirect's
    /// query parameters.
    pub async fn approve(&self, request_uri: &str) -> HashMap<String, String> {
        let page = self.open_login(request_uri).await;
        let response = self
            .decide(&page, request_uri, DEMO_USERNAME, DEMO_PASSWORD, "approve")
            .await;
        redirect_params(&response)
    }

    pub fn code_form(&self, code: &str, pkce: &Pkce) -> Vec<(&'static str, String)> {
        vec![
            ("grant_type", "authorization_code".to_owned()),
            ("code", code.to_owned()),
            ("code_verifier", pkce.verifier.clone()),
            ("redirect_uri", REDIRECT_URI.to_owned()),
            ("client_assertion_type", ASSERTION_TYPE.to_owned()),
            ("client_assertion", self.assertion()),
        ]
    }

    /// Exchange a code at the mTLS token endpoint.
    pub async fn exchange(&self, code: &str, pkce: &Pkce) -> Response {
        self.rp
            .post(self.mtls_url("/token"))
            .form(&self.code_form(code, pkce))
            .send()
            .await
            .unwrap()
    }

    /// Run the whole flow and return the token response.
    pub async fn tokens(&self, overrides: &Value) -> Value {
        let pkce = Pkce::new();
        let request_uri = self.push(&pkce, overrides).await;
        let params = self.approve(&request_uri).await;
        let response = self.exchange(&params["code"], &pkce).await;
        let status = response.status();
        let body: Value = response.json().await.unwrap();
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// Fetch the provider's JWKS and verify an ID token against it.
    pub async fn verify_id_token(&self, id_token: &str) -> Map<String, Value> {
        let jwks = self
            .browser
            .get(self.url("/jwks"))
            .send()
            .await
            .unwrap()
            .json::<jsonwebtoken::jwk::JwkSet>()
            .await
            .unwrap();
        let jws = Jws::parse(id_token, &[SigningAlg::PS256]).expect("well-formed PS256 ID token");
        jws.verify(&jwks)
            .expect("ID token signature verifies against published JWKS");
        jws.claims
    }
}

/// The login form as a browser sees it.
#[derive(Debug)]
pub struct LoginPage {
    pub csrf: String,
    /// `name=value` for the `Cookie` header.
    pub cookie: String,
    pub html: String,
}

impl LoginPage {
    /// Field names of the ticked consent checkboxes.
    pub fn ticked(&self) -> Vec<String> {
        self.html
            .split("<input type=\"checkbox\"")
            .skip(1)
            .filter_map(|rest| {
                let tag = rest.split('>').next()?;
                let name = tag.split("name=\"").nth(1)?.split('"').next()?;
                tag.contains(" checked").then(|| name.to_owned())
            })
            .collect()
    }

    pub async fn from_response(response: Response) -> Self {
        let cookie = response
            .headers()
            .get(SET_COOKIE)
            .expect("login page sets the CSRF cookie")
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let html = response.text().await.unwrap();
        let csrf = html
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("login page contains the CSRF field")
            .to_owned();
        Self { csrf, cookie, html }
    }
}

/// The query parameters of a 303 redirect back to the relying party.
pub fn redirect_params(response: &Response) -> HashMap<String, String> {
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()[LOCATION].to_str().unwrap();
    assert!(location.starts_with(REDIRECT_URI), "{location}");
    Url::parse(location)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

/// A self-signed client certificate, with its `x5t#S256` thumbprint.
fn client_identity() -> (Identity, String) {
    let identity = TlsIdentity::self_signed(vec!["rp.example.com".to_owned()]).unwrap();
    let thumbprint = b64url(sha256(identity.certs[0].as_ref()));
    let pem = format!("{}{}", identity.cert_pem(), identity.key_pem());
    (Identity::from_pem(pem.as_bytes()).unwrap(), thumbprint)
}

fn apply(claims: &mut Value, overrides: &Value) {
    for (name, value) in overrides.as_object().into_iter().flatten() {
        if value.is_null() {
            claims.as_object_mut().unwrap().remove(name);
        } else {
            claims[name] = value.clone();
        }
    }
}

/// Parse an error response body, returning (status, error code).
pub async fn oauth_error(response: Response) -> (StatusCode, String) {
    let status = response.status();
    let body: Value = response.json().await.expect("JSON error body");
    (
        status,
        body["error"].as_str().expect("error member").to_owned(),
    )
}
