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
mod tests {
    use axum::body::Bytes;
    use axum::http::{StatusCode, header};

    use crate::http::test_support::{Harness, body_text};
    use crate::http::{PATH_THEME_LOGO, PATH_THEME_LOGO_DARK};
    use crate::theme::{Logo, Theme};

    const SVG: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\"/>";

    #[tokio::test]
    async fn a_theme_without_a_logo_serves_none() {
        let harness = Harness::new();
        for path in [PATH_THEME_LOGO, PATH_THEME_LOGO_DARK] {
            let response = harness.get(None, path).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[tokio::test]
    async fn the_logo_is_served_as_an_inert_image() {
        let harness = Harness::with_theme(Theme {
            logo: Some(Logo {
                content_type: "image/svg+xml",
                bytes: Bytes::from_static(SVG.as_bytes()),
            }),
            ..Theme::default()
        });
        let response = harness.get(None, PATH_THEME_LOGO).await;
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers[header::CONTENT_TYPE], "image/svg+xml");
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(headers[header::CACHE_CONTROL], "public, max-age=3600");
        assert!(
            headers[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("sandbox")
        );
        assert_eq!(body_text(response).await, SVG);

        // No dark logo of its own: the page does not ask for one.
        let response = harness.get(None, PATH_THEME_LOGO_DARK).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
