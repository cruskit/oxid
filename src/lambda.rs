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
mod tests;
