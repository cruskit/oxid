use crate::epoch::Seconds;
use super::contract::{NOW, code, consent, grant, request};
use super::*;

#[tokio::test]
async fn memory_backend_meets_the_contract() {
    contract::all(&Store::default(), "mem").await;
}

#[tokio::test]
async fn consent_records_are_bounded_in_memory() {
    let store = Store::default();
    for i in 0..=MAX_CONSENT_RECORDS {
        store
            .record_consent(consent(&format!("t{i}"), Some("u1"), NOW))
            .await
            .unwrap();
    }
    assert_eq!(
        store.consent_history("u1").await.unwrap().len(),
        MAX_CONSENT_RECORDS
    );
    assert!(
        store.consent("t0").await.unwrap().is_none(),
        "the oldest was dropped"
    );
    assert!(store.consent("t1").await.unwrap().is_some());
}

#[tokio::test]
async fn purge_removes_only_expired_entries() {
    let backend = Arc::new(MemoryBackend::new());
    let store = Store::new(Arc::clone(&backend) as Arc<dyn Backend>);
    store
        .push_request(request(), String::new(), NOW + Seconds::new(10))
        .await
        .unwrap();
    store
        .push_request(request(), String::new(), NOW + Seconds::new(100))
        .await
        .unwrap();
    store.create_code(code("g1")).await.unwrap();
    store
        .issue_access_token(AccessToken {
            grant: grant("g1"),
            cert_thumbprint: "tp".to_owned(),
            expires_at: NOW + Seconds::new(300),
        })
        .await
        .unwrap();
    store.record_jti("rp", "j1", NOW + Seconds::new(20), NOW).await.unwrap();
    assert_eq!(backend.len(), 5);

    store.purge(NOW + Seconds::new(50)).await.unwrap();
    assert_eq!(backend.len(), 4, "the jti is gone");
    // Requests are kept past their request_uri, for sessions.
    store
        .purge(NOW + Seconds::new(10) + DEFAULT_SESSION_TTL + EXPIRED_SESSION_RETENTION)
        .await
        .unwrap();
    assert_eq!(backend.len(), 1, "only the longer-lived request is left");
    store.purge(NOW + Seconds::new(10_000)).await.unwrap();
    assert!(backend.is_empty());
}

#[tokio::test]
async fn revocation_outlives_the_grant_tokens() {
    let backend = Arc::new(MemoryBackend::new());
    let store = Store::new(Arc::clone(&backend) as Arc<dyn Backend>).grant_lifetime(Seconds::new(1000));
    let value = store.create_code(code("g1")).await.unwrap();
    store.redeem_code(&value, "rp", NOW).await.unwrap();
    store.redeem_code(&value, "rp", NOW + Seconds::new(1)).await.unwrap();
    store.purge(NOW + Seconds::new(1000)).await.unwrap();
    assert_eq!(backend.len(), 1, "the revocation is still remembered");
    store.purge(NOW + Seconds::new(1001)).await.unwrap();
    assert!(backend.is_empty());
}
