//! Behaviour every backend must provide, written against [`Store`] so the
//! same checks run on each.

use super::*;
use crate::testing::client_with_key;
use crate::testing::shared_key;
use crate::testing::{CHALLENGE, valid_params};

pub const NOW: i64 = 1_800_000_000;

pub fn request() -> AuthorizationRequest {
    AuthorizationRequest::from_params(&client_with_key("rp", shared_key()), &valid_params())
        .unwrap()
}

pub fn grant(id: &str) -> Grant {
    Grant {
        id: id.to_owned(),
        client_id: "rp".to_owned(),
        user_subject: "u1".to_owned(),
        scope: vec!["openid".to_owned()],
        claims: ClaimsRequest::default(),
        shared_claims: BTreeSet::from(["given_name".to_owned()]),
        auth_time: NOW,
        txn: "txn-1".to_owned(),
        purpose: Some("testing".to_owned()),
        id_token_edits: None,
    }
}

pub fn consent(txn: &str, user: Option<&str>, decided_at: i64) -> ConsentRecord {
    ConsentRecord {
        txn: txn.to_owned(),
        client_id: "rp".to_owned(),
        user_subject: user.map(str::to_owned),
        purpose: Some(format!("purpose of {txn}")),
        claims: vec!["given_name".to_owned()],
        declined: Vec::new(),
        decided_at,
        outcome: if user.is_some() {
            ConsentOutcome::Approved
        } else {
            ConsentOutcome::Denied
        },
    }
}

pub fn code(grant_id: &str) -> AuthorizationCode {
    AuthorizationCode {
        grant: grant(grant_id),
        redirect_uri: "https://rp.example.com/cb".to_owned(),
        code_challenge: CHALLENGE.to_owned(),
        nonce: Some("n-1".to_owned()),
        expires_at: NOW + 60,
    }
}

/// `tag` keeps runs against a shared table apart.
pub async fn consent_history(store: &Store, tag: &str) {
    let (u1, u2) = (format!("{tag}-u1"), format!("{tag}-u2"));
    let txn = |n: u8| format!("{tag}-t{n}");
    store
        .record_consent(consent(&txn(1), Some(&u1), NOW))
        .await
        .unwrap();
    store
        .record_consent(consent(&txn(2), Some(&u2), NOW + 1))
        .await
        .unwrap();
    store
        .record_consent(consent(&txn(3), None, NOW + 2))
        .await
        .unwrap();
    store
        .record_consent(consent(&txn(4), Some(&u1), NOW + 3))
        .await
        .unwrap();

    let history = store.consent_history(&u1).await.unwrap();
    let txns: Vec<&str> = history.iter().map(|r| r.txn.as_str()).collect();
    assert_eq!(txns, [txn(4), txn(1)]);
    assert_eq!(
        history[1].purpose.as_deref(),
        Some(format!("purpose of {}", txn(1)).as_str())
    );
    let nobody = store.consent_history(&format!("{tag}-nobody")).await;
    assert_eq!(nobody.unwrap(), Vec::new());
    assert_eq!(
        store.consent(&txn(3)).await.unwrap().unwrap().outcome,
        ConsentOutcome::Denied
    );
    assert!(
        store
            .consent(&format!("{tag}-missing"))
            .await
            .unwrap()
            .is_none()
    );

    // Records are not transient state: purging leaves them alone.
    store.purge(NOW + 1_000_000).await.unwrap();
    assert_eq!(store.consent_history(&u1).await.unwrap().len(), 2);
}

pub async fn pushed_requests(store: &Store) {
    let a = store
        .push_request(request(), "object".to_owned(), NOW + 60)
        .await
        .unwrap();
    let b = store
        .push_request(request(), String::new(), NOW + 60)
        .await
        .unwrap();
    assert_ne!(a, b);
    assert!(a.starts_with(REQUEST_URI_PREFIX));
    assert!(a.len() - REQUEST_URI_PREFIX.len() >= 43);

    // Peeked repeatedly, taken once.
    let peeked = store.peek_request(&a, NOW).await.unwrap().unwrap();
    assert_eq!(peeked.request, request());
    assert_eq!(peeked.request_object, "object");
    assert_eq!(peeked.failed_logins, 0);
    assert!(store.peek_request(&a, NOW).await.unwrap().is_some());
    assert!(store.take_request(&a, NOW).await.unwrap().is_some());
    assert!(store.take_request(&a, NOW).await.unwrap().is_none());
    assert!(store.peek_request(&a, NOW).await.unwrap().is_none());

    // A browser must arrive before the request_uri expires.
    assert!(store.arrive(&b, NOW + 60).await.unwrap().is_none());
    assert!(store.resume(&b, NOW).await.unwrap().is_none(), "no session");
    assert!(
        store
            .peek_request("urn:ietf:params:oauth:request_uri:unknown", NOW)
            .await
            .unwrap()
            .is_none()
    );
}

/// A planned response is kept per `request_uri` until it expires, and
/// the last one set wins.
pub async fn planned_responses(store: &Store) {
    let uri = format!("{REQUEST_URI_PREFIX}planned");
    assert_eq!(store.planned_response(&uri, NOW).await.unwrap(), None);

    let error = PlannedResponse::Error {
        error: "access_denied".to_owned(),
        description: "the user denied the request".to_owned(),
    };
    store.plan_response(&uri, &error, NOW + 60).await.unwrap();
    assert_eq!(
        store.planned_response(&uri, NOW).await.unwrap(),
        Some(error)
    );

    let success = PlannedResponse::Success {
        user_subject: "u1".to_owned(),
        shared_claims: BTreeSet::from(["given_name".to_owned()]),
        declined: vec!["email".to_owned()],
    };
    store.plan_response(&uri, &success, NOW + 60).await.unwrap();
    assert_eq!(
        store.planned_response(&uri, NOW + 59).await.unwrap(),
        Some(success)
    );
    assert_eq!(store.planned_response(&uri, NOW + 60).await.unwrap(), None);
    let other = format!("{REQUEST_URI_PREFIX}other");
    assert_eq!(store.planned_response(&other, NOW).await.unwrap(), None);

    let abandon = PlannedResponse::Abandon;
    store.plan_response(&uri, &abandon, NOW + 60).await.unwrap();
    assert_eq!(
        store.planned_response(&uri, NOW).await.unwrap(),
        Some(abandon)
    );
    store.clear_planned_response(&uri).await.unwrap();
    assert_eq!(store.planned_response(&uri, NOW).await.unwrap(), None);
    store.clear_planned_response(&uri).await.unwrap();
}

/// Arriving in time starts a session, which then outlives the
/// `request_uri` and is what the user is held to.
pub async fn sessions(store: &Store) {
    let ttl = DEFAULT_SESSION_TTL;
    let uri = store
        .push_request(request(), String::new(), NOW + 60)
        .await
        .unwrap();
    let arrived = NOW + 59;
    let Some(Visit::Active(_, session)) = store.arrive(&uri, arrived).await.unwrap() else {
        panic!("arriving in time starts a session");
    };
    assert_eq!(session.expires_at, arrived + ttl);
    assert_eq!(session.signed_in, None);

    // Past the request_uri lifetime, the same session carries on, and
    // arriving again does not extend it.
    let later = arrived + ttl - 1;
    for visit in [
        store.arrive(&uri, later).await.unwrap(),
        store.resume(&uri, later).await.unwrap(),
    ] {
        let Some(Visit::Active(pushed, again)) = visit else {
            panic!("the session is still running");
        };
        assert_eq!(again, session);
        assert_eq!(pushed.request, request());
    }

    let session = store
        .sign_in(&uri, &session, "u1", "browser-secret")
        .await
        .unwrap();
    let Some(Visit::Active(_, read)) = store.resume(&uri, later).await.unwrap() else {
        panic!("signing in keeps the session");
    };
    assert_eq!(read, session);
    let signed_in = read.signed_in.unwrap();
    assert_eq!(signed_in.user_subject, "u1");
    assert!(signed_in.is_browser("browser-secret"));
    assert!(!signed_in.is_browser("another"));
    assert_ne!(signed_in.browser, "browser-secret", "only a digest is kept");

    // Once the session ends the request is kept, to explain and to
    // return an error to the client, but only for a while.
    for at in [arrived + ttl, arrived + ttl + EXPIRED_SESSION_RETENTION - 1] {
        assert!(matches!(
            store.arrive(&uri, at).await.unwrap(),
            Some(Visit::Expired(_))
        ));
        assert!(matches!(
            store.resume(&uri, at).await.unwrap(),
            Some(Visit::Expired(_))
        ));
    }
    let gone = NOW + 60 + ttl + EXPIRED_SESSION_RETENTION;
    assert!(store.arrive(&uri, gone).await.unwrap().is_none());

    // A used request has no session to come back to.
    let uri = store
        .push_request(request(), String::new(), NOW + 60)
        .await
        .unwrap();
    assert!(store.arrive(&uri, NOW).await.unwrap().is_some());
    assert!(store.take_request(&uri, NOW).await.unwrap().is_some());
    assert!(store.arrive(&uri, NOW).await.unwrap().is_none());
    assert!(store.resume(&uri, NOW).await.unwrap().is_none());
}

pub async fn failed_logins(store: &Store) {
    let uri = store
        .push_request(request(), String::new(), NOW + 60)
        .await
        .unwrap();
    for attempt in 1..MAX_FAILED_LOGINS {
        assert!(store.record_failed_login(&uri).await.unwrap());
        let pushed = store.peek_request(&uri, NOW).await.unwrap().unwrap();
        assert_eq!(pushed.failed_logins, attempt);
    }
    assert!(!store.record_failed_login(&uri).await.unwrap());
    assert!(store.peek_request(&uri, NOW).await.unwrap().is_none());
    assert!(!store.record_failed_login("unknown").await.unwrap());
}

pub async fn code_replay(store: &Store) {
    // A grant id unique to this run, for shared tables.
    let grant_id = format!("g-{}", random_token(8));
    let mut unique = code("g1");
    unique.grant.id.clone_from(&grant_id);
    let value = store.create_code(unique).await.unwrap();
    let CodeRedemption::Valid(redeemed) = store.redeem_code(&value, "rp", NOW).await.unwrap()
    else {
        panic!("first redemption should succeed");
    };
    assert_eq!(redeemed.nonce.as_deref(), Some("n-1"));
    assert_eq!(redeemed.grant.id, grant_id);
    let access = store
        .issue_access_token(AccessToken {
            grant: redeemed.grant.clone(),
            cert_thumbprint: "tp".to_owned(),
            expires_at: NOW + 300,
        })
        .await
        .unwrap();
    let refresh = store
        .issue_refresh_token(RefreshToken {
            grant: redeemed.grant.clone(),
            expires_at: NOW + 900,
        })
        .await
        .unwrap();
    let other = store
        .issue_access_token(AccessToken {
            grant: grant(&format!("{grant_id}-other")),
            cert_thumbprint: "tp".to_owned(),
            expires_at: NOW + 300,
        })
        .await
        .unwrap();
    assert!(store.access_token(&access, NOW).await.unwrap().is_some());

    assert!(matches!(
        store.redeem_code(&value, "rp", NOW + 1).await.unwrap(),
        CodeRedemption::Replayed
    ));
    assert!(
        store
            .access_token(&access, NOW + 1)
            .await
            .unwrap()
            .is_none(),
        "revoked with the grant"
    );
    assert!(
        store
            .refresh_token(&refresh, NOW + 1)
            .await
            .unwrap()
            .is_none(),
        "revoked with the grant"
    );
    assert!(
        store.access_token(&other, NOW + 1).await.unwrap().is_some(),
        "other grants are untouched"
    );
}

pub async fn code_binding(store: &Store) {
    let value = store.create_code(code("g1")).await.unwrap();
    assert!(matches!(
        store.redeem_code(&value, "other", NOW).await.unwrap(),
        CodeRedemption::Invalid
    ));
    assert!(matches!(
        store.redeem_code("unknown", "rp", NOW).await.unwrap(),
        CodeRedemption::Invalid
    ));
    // A wrong client must not burn the code for its rightful owner.
    assert!(matches!(
        store.redeem_code(&value, "rp", NOW).await.unwrap(),
        CodeRedemption::Valid(_)
    ));

    let late = store.create_code(code("g3")).await.unwrap();
    assert!(matches!(
        store.redeem_code(&late, "rp", NOW + 60).await.unwrap(),
        CodeRedemption::Invalid
    ));
}

pub async fn concurrent_redemption(store: &Store) {
    let value = store.create_code(code("g1")).await.unwrap();
    let attempts = (0..8).map(|_| {
        let store = store.clone();
        let value = value.clone();
        tokio::spawn(async move { store.redeem_code(&value, "rp", NOW).await.unwrap() })
    });
    let mut valid = 0;
    for attempt in attempts.collect::<Vec<_>>() {
        if matches!(attempt.await.unwrap(), CodeRedemption::Valid(_)) {
            valid += 1;
        }
    }
    assert_eq!(valid, 1, "exactly one presentation redeems the code");
}

pub async fn tokens(store: &Store) {
    // Not a grant another check revokes.
    let id = format!("g-{}", random_token(8));
    let access = store
        .issue_access_token(AccessToken {
            grant: grant(&id),
            cert_thumbprint: "tp".to_owned(),
            expires_at: NOW + 300,
        })
        .await
        .unwrap();
    let found = store.access_token(&access, NOW + 299).await.unwrap();
    let found = found.unwrap();
    assert_eq!(found.cert_thumbprint, "tp");
    assert_eq!(found.grant, grant(&id));
    assert!(
        store
            .access_token(&access, NOW + 300)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.access_token("unknown", NOW).await.unwrap().is_none());

    let refresh = store
        .issue_refresh_token(RefreshToken {
            grant: grant(&id),
            expires_at: NOW + 10,
        })
        .await
        .unwrap();
    assert!(store.refresh_token(&refresh, NOW).await.unwrap().is_some());
    assert!(
        store
            .refresh_token(&refresh, NOW + 10)
            .await
            .unwrap()
            .is_none()
    );
    // Presenting an access token as a refresh token finds nothing.
    assert!(store.refresh_token(&access, NOW).await.unwrap().is_none());
}

pub async fn jti_replay(store: &Store, tag: &str) {
    let (rp, other) = (format!("{tag}-rp"), format!("{tag}-other"));
    assert!(store.record_jti(&rp, "j1", NOW + 60, NOW).await.unwrap());
    assert!(
        !store
            .record_jti(&rp, "j1", NOW + 60, NOW + 1)
            .await
            .unwrap()
    );
    assert!(
        store.record_jti(&other, "j1", NOW + 60, NOW).await.unwrap(),
        "scoped to the client"
    );
    assert!(store.record_jti(&rp, "j2", NOW + 60, NOW).await.unwrap());
    assert!(
        store
            .record_jti(&rp, "j1", NOW + 120, NOW + 60)
            .await
            .unwrap(),
        "reusable once expired"
    );
}

pub async fn secrets(store: &Store, tag: &str) {
    let name = format!("{tag}-secret");
    let first = store.secret(&name, || Ok("one".to_owned())).await.unwrap();
    assert_eq!(first, "one");
    let second = store
        .secret(&name, || panic!("must not generate again"))
        .await
        .unwrap();
    assert_eq!(second, "one");
    assert!(
        store
            .secret(&format!("{tag}-failing"), || anyhow::bail!("no entropy"))
            .await
            .is_err()
    );
    // Secrets are not transient state.
    store.purge(NOW + 1_000_000).await.unwrap();
    assert_eq!(
        store.secret(&name, || Ok("two".to_owned())).await.unwrap(),
        "one"
    );
}

/// Every check, in turn.
pub async fn all(store: &Store, tag: &str) {
    // Purging runs inside these, so they go before anything transient.
    consent_history(store, tag).await;
    secrets(store, tag).await;
    pushed_requests(store).await;
    sessions(store).await;
    planned_responses(store).await;
    failed_logins(store).await;
    code_replay(store).await;
    code_binding(store).await;
    concurrent_redemption(store).await;
    tokens(store).await;
    jti_replay(store, tag).await;
}
