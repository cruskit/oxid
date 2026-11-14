
use std::sync::Arc;

use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_dynamodb::types::{
    AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType,
};
use serde_json::Value;

use super::*;
use crate::store::{Store, contract};
use crate::util::random_token;

/// Set to the URL of a DynamoDB Local instance to run the tests that
/// need one, e.g. `http://localhost:8000`.
const ENDPOINT_VAR: &str = "OXID_TEST_DYNAMODB_ENDPOINT";

fn requirements() -> Value {
    serde_json::from_str(include_str!("../../../deploy/aws/requirements.json")).unwrap()
}

#[test]
fn published_requirements_match_the_code() {
    let table = &requirements()["dynamodb"]["table"];
    assert_eq!(table["hash_key"]["name"], HASH_KEY);
    assert_eq!(table["hash_key"]["type"], "S");
    assert_eq!(table["range_key"]["name"], RANGE_KEY);
    assert_eq!(table["range_key"]["type"], "S");
    assert_eq!(table["ttl_attribute"], TTL_ATTRIBUTE);
    assert_eq!(table["global_secondary_indexes"], serde_json::json!([]));
}

#[test]
fn sort_keys_order_log_entries_by_time() {
    let earlier = format!("{:020}#b", 999);
    let later = format!("{:020}#a", 1000);
    assert!(earlier < later);
}

#[test]
fn records_are_read_from_items() {
    let mut stored = item("k", SOLE, "v".to_owned(), Some(42));
    assert_eq!(
        record(&stored).unwrap(),
        Record {
            value: "v".to_owned(),
            expires_at: Some(42),
            count: 0
        }
    );
    stored.insert(COUNT.to_owned(), number(3));
    stored.remove(TTL_ATTRIBUTE);
    let read = record(&stored).unwrap();
    assert_eq!((read.count, read.expires_at), (3, None));
    stored.insert(COUNT.to_owned(), string("three"));
    assert!(record(&stored).is_err());
    assert!(record(&key("k", SOLE)).is_err());
}

/// Create a table exactly as the published requirements describe it, so
/// the test fails if the code needs anything they do not mention.
async fn table_from_requirements(endpoint: &str) -> DynamoBackend {
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("local"))
        .endpoint_url(endpoint)
        .credentials_provider(Credentials::new("local", "local", None, None, "test"))
        .build();
    let client = Client::from_conf(config);
    let table = &requirements()["dynamodb"]["table"];
    let name = format!("oxid-test-{}", random_token(6).replace(['-', '_'], "x"));
    let attribute = |which: &str| table[which]["name"].as_str().unwrap().to_owned();
    client
        .create_table()
        .table_name(&name)
        .billing_mode(BillingMode::PayPerRequest)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name(attribute("hash_key"))
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name(attribute("range_key"))
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(attribute("hash_key"))
                .key_type(KeyType::Hash)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(attribute("range_key"))
                .key_type(KeyType::Range)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("creating the test table");
    DynamoBackend::from_client(client, name)
}

#[tokio::test]
async fn dynamodb_backend_meets_the_contract() {
    let Ok(endpoint) = std::env::var(ENDPOINT_VAR) else {
        eprintln!("skipped: set {ENDPOINT_VAR} to run against DynamoDB Local");
        return;
    };
    let backend = table_from_requirements(&endpoint).await;
    let store = Store::new(Arc::new(backend.clone()));
    contract::all(&store, "ddb").await;

    // Incrementing a missing key must not create it.
    assert!(backend.increment("absent").await.unwrap().is_none());
    assert!(backend.get("absent").await.unwrap().is_none());
    // A record without expiry is never overwritten by put_new.
    backend.put("forever", "a".to_owned(), None).await.unwrap();
    assert!(
        !backend
            .put_new("forever", "b".to_owned(), None, i64::MAX)
            .await
            .unwrap()
    );

    backend
        .client
        .delete_table()
        .table_name(&backend.table)
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn a_missing_table_is_an_error() {
    let Ok(endpoint) = std::env::var(ENDPOINT_VAR) else {
        return;
    };
    let backend = table_from_requirements(&endpoint).await;
    let missing = DynamoBackend::from_client(backend.client.clone(), "oxid-no-such".to_owned());
    assert!(missing.get("k").await.is_err());
    backend
        .client
        .delete_table()
        .table_name(&backend.table)
        .send()
        .await
        .unwrap();
}
