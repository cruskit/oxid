use axum::body::Bytes;
use axum::http::{StatusCode, header};

use crate::http::{PATH_THEME_LOGO, PATH_THEME_LOGO_DARK};
use crate::testing::http::{Harness, body_text};
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
