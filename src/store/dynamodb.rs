//! The Amazon DynamoDB backend.
//!
//! One table, described in `deploy/aws/requirements.json` (a test keeps the
//! two in step):
//!
//! | Item | `pk` | `sk` |
//! |---|---|---|
//! | record | the store's key, e.g. `code#<digest>` | `#` |
//! | log entry | `log#<partition>` | `<time, zero padded>#<id>` |
//! | log entry by id | `logid#<id>` | `#` |
//!
//! Records carry `data` (the value), `n` (the counter, once incremented) and
//! `expires_at` (the table's TTL attribute, when they expire). DynamoDB
//! deletes expired items in its own time, so an expired record may still be
//! returned; [`super::Store`] checks.

use std::collections::HashMap;

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::error::{DisplayErrorContext, SdkError};
use aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_sdk_dynamodb::operation::update_item::UpdateItemError;
use aws_sdk_dynamodb::types::{AttributeValue, ReturnValue};

use super::{Backend, BackendFuture, Record, StoreError, StoreResult};
use crate::config::StoreConfig;

pub const HASH_KEY: &str = "pk";
pub const RANGE_KEY: &str = "sk";
pub const TTL_ATTRIBUTE: &str = "expires_at";
const VALUE: &str = "data";
const COUNT: &str = "n";

/// Sort key of items that are alone in their partition.
const SOLE: &str = "#";

type Item = HashMap<String, AttributeValue>;

#[derive(Debug, Clone)]
pub struct DynamoBackend {
    client: Client,
    table: String,
}

impl DynamoBackend {
    /// Connect using the environment's AWS credentials and region, and
    /// check that the table can be read.
    pub async fn connect(config: &StoreConfig) -> anyhow::Result<Self> {
        let table = config
            .table
            .clone()
            .ok_or_else(|| anyhow::anyhow!("store.table is required"))?;
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = &config.region {
            loader = loader.region(aws_config::Region::new(region.clone()));
        }
        if let Some(endpoint) = &config.endpoint_url {
            loader = loader.endpoint_url(endpoint);
        }
        let backend = Self::from_client(Client::new(&loader.load().await), table);
        // Fail at startup, not on the first sign-in, if the table is missing
        // or not readable.
        backend
            .get("startup-check")
            .await
            .map_err(|error| anyhow::anyhow!("DynamoDB table '{}': {error}", backend.table))?;
        Ok(backend)
    }

    pub fn from_client(client: Client, table: String) -> Self {
        Self { client, table }
    }
}

#[expect(clippy::needless_pass_by_value, reason = "used as `map_err(failure)`")]
fn failure<E, R>(error: SdkError<E, R>) -> StoreError
where
    E: std::error::Error + 'static,
    R: std::fmt::Debug,
{
    StoreError::new(DisplayErrorContext(&error))
}

fn string(value: impl Into<String>) -> AttributeValue {
    AttributeValue::S(value.into())
}

fn number(value: i64) -> AttributeValue {
    AttributeValue::N(value.to_string())
}

fn key(pk: &str, sk: &str) -> Item {
    HashMap::from([
        (HASH_KEY.to_owned(), string(pk)),
        (RANGE_KEY.to_owned(), string(sk)),
    ])
}

fn item(pk: &str, sk: &str, value: String, expires_at: Option<i64>) -> Item {
    let mut item = key(pk, sk);
    item.insert(VALUE.to_owned(), string(value));
    if let Some(expires_at) = expires_at {
        item.insert(TTL_ATTRIBUTE.to_owned(), number(expires_at));
    }
    item
}

fn value_of(item: &Item) -> StoreResult<String> {
    match item.get(VALUE) {
        Some(AttributeValue::S(value)) => Ok(value.clone()),
        _ => Err(StoreError::new("item has no string 'data' attribute")),
    }
}

fn number_of<T: std::str::FromStr>(item: &Item, name: &str) -> StoreResult<Option<T>> {
    match item.get(name) {
        None => Ok(None),
        Some(AttributeValue::N(text)) => text
            .parse()
            .map(Some)
            .map_err(|_| StoreError::new(format!("item attribute '{name}' is out of range"))),
        Some(_) => Err(StoreError::new(format!(
            "item attribute '{name}' is not a number"
        ))),
    }
}

fn record(item: &Item) -> StoreResult<Record> {
    Ok(Record {
        value: value_of(item)?,
        expires_at: number_of(item, TTL_ATTRIBUTE)?,
        count: number_of(item, COUNT)?.unwrap_or(0),
    })
}

impl Backend for DynamoBackend {
    fn put<'a>(
        &'a self,
        key: &'a str,
        value: String,
        expires_at: Option<i64>,
    ) -> BackendFuture<'a, ()> {
        Box::pin(async move {
            self.client
                .put_item()
                .table_name(&self.table)
                .set_item(Some(item(key, SOLE, value, expires_at)))
                .send()
                .await
                .map_err(failure)?;
            Ok(())
        })
    }

    fn put_new<'a>(
        &'a self,
        key: &'a str,
        value: String,
        expires_at: Option<i64>,
        now: i64,
    ) -> BackendFuture<'a, bool> {
        Box::pin(async move {
            let result = self
                .client
                .put_item()
                .table_name(&self.table)
                .set_item(Some(item(key, SOLE, value, expires_at)))
                .condition_expression(
                    "attribute_not_exists(#pk) OR (attribute_exists(#ttl) AND #ttl <= :now)",
                )
                .expression_attribute_names("#pk", HASH_KEY)
                .expression_attribute_names("#ttl", TTL_ATTRIBUTE)
                .expression_attribute_values(":now", number(now))
                .send()
                .await;
            match result {
                Ok(_) => Ok(true),
                Err(error)
                    if error
                        .as_service_error()
                        .is_some_and(PutItemError::is_conditional_check_failed_exception) =>
                {
                    Ok(false)
                }
                Err(error) => Err(failure(error)),
            }
        })
    }

    fn get<'a>(&'a self, key_: &'a str) -> BackendFuture<'a, Option<Record>> {
        Box::pin(async move {
            let output = self
                .client
                .get_item()
                .table_name(&self.table)
                .set_key(Some(key(key_, SOLE)))
                .consistent_read(true)
                .send()
                .await
                .map_err(failure)?;
            output.item.as_ref().map(record).transpose()
        })
    }

    fn take<'a>(&'a self, key_: &'a str) -> BackendFuture<'a, Option<Record>> {
        Box::pin(async move {
            let output = self
                .client
                .delete_item()
                .table_name(&self.table)
                .set_key(Some(key(key_, SOLE)))
                .return_values(ReturnValue::AllOld)
                .send()
                .await
                .map_err(failure)?;
            output.attributes.as_ref().map(record).transpose()
        })
    }

    fn increment<'a>(&'a self, key_: &'a str) -> BackendFuture<'a, Option<Record>> {
        Box::pin(async move {
            let result = self
                .client
                .update_item()
                .table_name(&self.table)
                .set_key(Some(key(key_, SOLE)))
                .update_expression("ADD #n :one")
                // Without this, updating a missing key would create it.
                .condition_expression("attribute_exists(#pk)")
                .expression_attribute_names("#n", COUNT)
                .expression_attribute_names("#pk", HASH_KEY)
                .expression_attribute_values(":one", number(1))
                .return_values(ReturnValue::AllNew)
                .send()
                .await;
            match result {
                Ok(output) => output.attributes.as_ref().map(record).transpose(),
                Err(error)
                    if error
                        .as_service_error()
                        .is_some_and(UpdateItemError::is_conditional_check_failed_exception) =>
                {
                    Ok(None)
                }
                Err(error) => Err(failure(error)),
            }
        })
    }

    fn log_append<'a>(
        &'a self,
        partition: &'a str,
        id: &'a str,
        at: i64,
        value: String,
    ) -> BackendFuture<'a, ()> {
        Box::pin(async move {
            // The by-id item first: if the second write fails, the entry is
            // findable but unlisted, rather than listed but unfindable.
            self.client
                .put_item()
                .table_name(&self.table)
                .set_item(Some(item(
                    &format!("logid#{id}"),
                    SOLE,
                    value.clone(),
                    None,
                )))
                .send()
                .await
                .map_err(failure)?;
            self.client
                .put_item()
                .table_name(&self.table)
                .set_item(Some(item(
                    &format!("log#{partition}"),
                    // Zero padded so that the sort key orders by time.
                    &format!("{at:020}#{id}"),
                    value,
                    None,
                )))
                .send()
                .await
                .map_err(failure)?;
            Ok(())
        })
    }

    fn log_list<'a>(&'a self, partition: &'a str) -> BackendFuture<'a, Vec<String>> {
        Box::pin(async move {
            let mut values = Vec::new();
            let mut start = None;
            loop {
                let output = self
                    .client
                    .query()
                    .table_name(&self.table)
                    .key_condition_expression("#pk = :pk")
                    .expression_attribute_names("#pk", HASH_KEY)
                    .expression_attribute_values(":pk", string(format!("log#{partition}")))
                    .scan_index_forward(false)
                    .consistent_read(true)
                    .set_exclusive_start_key(start)
                    .send()
                    .await
                    .map_err(failure)?;
                for item in output.items() {
                    values.push(value_of(item)?);
                }
                start = output.last_evaluated_key;
                if start.is_none() {
                    return Ok(values);
                }
            }
        })
    }

    fn log_get<'a>(&'a self, id: &'a str) -> BackendFuture<'a, Option<String>> {
        Box::pin(async move {
            let key_ = format!("logid#{id}");
            Ok(self.get(&key_).await?.map(|record| record.value))
        })
    }

    fn purge(&self, _now: i64) -> BackendFuture<'_, ()> {
        // The table's TTL setting removes expired items.
        Box::pin(std::future::ready(Ok(())))
    }
}

#[cfg(test)]
mod tests;
