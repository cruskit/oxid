//! The theme's logo, served to the pages that show it.
//!
//! The image is read once, at startup ([`Theme`](crate::theme::Theme)). It is
//! the only thing a page loads, and it is loaded from this origin, so the
//! pages' content security policy allows images from `'self'` and nothing
//! else.

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::state::AppState;
use crate::theme::Logo;

/// `GET /theme/logo`
pub async fn logo(State(state): State<AppState>) -> Response {
    serve(state.theme.logo.as_ref())
}

/// `GET /theme/logo-dark`
pub async fn logo_dark(State(state): State<AppState>) -> Response {
    serve(state.theme.logo_dark.as_ref())
}

fn serve(logo: Option<&Logo>) -> Response {
    let Some(logo) = logo else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut response = logo.bytes.clone().into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(logo.content_type),
    );
    // The logo changes only when the configuration does.
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    // An SVG opened directly, rather than shown by a page, is a document:
    // this stops it running script or loading anything.
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; sandbox"),
    );
    response
}

#[cfg(test)]
mod tests;
