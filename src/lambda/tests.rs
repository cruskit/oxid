use axum::http::StatusCode;
use lambda_http::aws_lambda_events::apigw::ApiGatewayV2httpRequest;
use lambda_http::request::LambdaRequest;
use serde_json::{Value, json};

use super::*;
use crate::testing::http::body_text;
use crate::testing::state::state;
use crate::tls::TlsIdentity;

/// An HTTP API (payload format 2.0) event, as API Gateway sends it.
fn event(method: &str, path: &str, authentication: Option<Value>) -> Request {
    let mut context = json!({
        "accountId": "123456789012",
        "apiId": "abc123",
        "domainName": "op.example.com",
        "http": {
            "method": method,
            "path": path,
            "protocol": "HTTP/1.1",
            "sourceIp": "203.0.113.9",
            "userAgent": "test"
        },
        "requestId": "id",
        "routeKey": "$default",
        "stage": "$default",
        "time": "12/Nov/2026:00:00:00 +0000",
        "timeEpoch": 1_794_441_600_000_i64
    });
    if let Some(authentication) = authentication {
        context["authentication"] = authentication;
    }
    let event: ApiGatewayV2httpRequest = serde_json::from_value(json!({
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": path,
        "rawQueryString": "",
        "headers": {"host": "op.example.com"},
        "requestContext": context,
        "isBase64Encoded": false
    }))
    .unwrap();
    LambdaRequest::ApiGatewayV2(event).into()
}

fn certificate_context(pem: &str) -> Value {
    json!({"clientCert": {
        "clientCertPem": pem,
        "issuerDN": "CN=test",
        "serialNumber": "1",
        "subjectDN": "CN=test",
        "validity": {
            "notAfter": "Nov 12 00:00:00 2027 GMT",
            "notBefore": "Nov 12 00:00:00 2026 GMT"
        }
    }})
}

#[test]
fn certificate_comes_from_the_request_context_only() {
    let identity = TlsIdentity::self_signed(vec!["client.example".to_owned()]).unwrap();
    let expected = ClientCert::from_der(identity.certs[0].as_ref());

    let with = event(
        "POST",
        "/token",
        Some(certificate_context(&identity.cert_pem())),
    );
    assert_eq!(client_cert(&with), Some(expected));

    assert_eq!(client_cert(&event("POST", "/token", None)), None);
    let garbled = event("POST", "/token", Some(certificate_context("not a cert")));
    assert_eq!(client_cert(&garbled), None);

    // A header claiming a certificate is not one.
    let mut spoofed = event("POST", "/token", None);
    spoofed.headers_mut().insert(
        "x-amzn-mtls-clientcert",
        identity.cert_pem().replace('\n', "").parse().unwrap(),
    );
    assert_eq!(client_cert(&spoofed), None);
}

#[tokio::test]
async fn events_are_served_by_the_router() {
    let (state, _) = state();
    let router = http::router(state);

    let response = handle(
        router.clone(),
        event("GET", "/.well-known/openid-configuration", None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let metadata: Value = serde_json::from_str(&body_text(response).await).unwrap();
    assert_eq!(metadata["issuer"], crate::testing::state::ISSUER);

    // The token endpoint without a certificate is refused before
    // anything else is looked at... after client authentication.
    let response = handle(router, event("POST", "/token", None)).await;
    assert!(response.status().is_client_error());
}
