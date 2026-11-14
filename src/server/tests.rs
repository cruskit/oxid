
use axum::body::Body;
use axum::routing::get;
use tower::ServiceExt;

use super::*;

#[tokio::test(start_paused = true)]
async fn slow_requests_are_answered_with_503() {
    let limit = Duration::from_secs(30);
    let router = Router::new()
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(31)).await;
                "late"
            }),
        )
        .route("/fast", get(|| async { "ok" }))
        .layer(middleware::from_fn(move |request, next| {
            request_timeout(limit, request, next)
        }));
    let call = |path: &'static str| {
        router
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
    };
    assert_eq!(call("/fast").await.unwrap().status(), StatusCode::OK);
    assert_eq!(
        call("/slow").await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
