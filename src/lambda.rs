//! Running as an AWS Lambda function behind an API Gateway HTTP API.
//!
//! There are no listeners: API Gateway terminates TLS and invokes the
//! function once per request. The same routes are served as by
//! [`crate::server`]. What differs is where the TLS client certificate
//! comes from. API Gateway performs the mutual TLS handshake on custom
//! domain names that have it enabled, and passes the certificate in the
//! event's request context, which the caller cannot influence. Requests
//! arriving through a domain name without mutual TLS carry no certificate,
//! exactly like the public listener.
//!
//! Use the DynamoDB store: consecutive requests may reach different
//! instances of the function, and instances are discarded at any time.

use std::convert::Infallible;

use anyhow::{Result, anyhow};
use axum::Router;
use axum::body::Body;
use axum::http::Response;
use lambda_http::request::RequestContext;
use lambda_http::{Request, RequestExt};
use tower::ServiceExt;

use crate::config::{Config, StoreBackend};
use crate::http::{self, ConnInfo};
use crate::state::AppState;
use crate::tls::ClientCert;

/// Start up, then serve invocations until the execution environment is
/// shut down.
pub async fn run(config: &Config) -> Result<()> {
    if config.store.backend == StoreBackend::Memory {
        tracing::warn!(
            "store.backend is 'memory': state is not shared between Lambda instances, so \
             sign-ins will fail whenever requests reach different instances"
        );
    }
    let state = AppState::start(config, None).await?;
    tracing::info!(issuer = %state.issuer, "oxID is ready for Lambda invocations");
    let router = http::router(state);
    lambda_http::run(lambda_http::service_fn(move |request: Request| {
        let router = router.clone();
        async move { Ok::<_, Infallible>(handle(router, request).await) }
    }))
    .await
    .map_err(|error| anyhow!("Lambda runtime: {error}"))
}

/// The client certificate API Gateway verified for this request, if any.
fn client_cert(request: &Request) -> Option<ClientCert> {
    let Some(RequestContext::ApiGatewayV2(context)) = request.request_context_ref() else {
        return None;
    };
    let pem = context
        .authentication
        .as_ref()?
        .client_cert
        .as_ref()?
        .client_cert_pem
        .as_deref()?;
    let cert = ClientCert::from_pem(pem);
    if cert.is_none() {
        tracing::warn!("the client certificate from API Gateway could not be parsed");
    }
    cert
}

async fn handle(router: Router, request: Request) -> Response<Body> {
    let conn = ConnInfo {
        client_cert: client_cert(&request),
    };
    let (mut parts, body) = request.into_parts();
    parts.extensions.insert(conn);
    let request = axum::http::Request::from_parts(parts, Body::new(body));
    match router.oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use lambda_http::aws_lambda_events::apigw::ApiGatewayV2httpRequest;
    use lambda_http::request::LambdaRequest;
    use serde_json::{Value, json};

    use super::*;
    use crate::http::test_support::body_text;
    use crate::state::test_support::state;
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
        assert_eq!(metadata["issuer"], crate::state::test_support::ISSUER);

        // The token endpoint without a certificate is refused before
        // anything else is looked at... after client authentication.
        let response = handle(router, event("POST", "/token", None)).await;
        assert!(response.status().is_client_error());
    }
}
