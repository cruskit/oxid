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
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_sdk_dynamodb::operation::update_item::UpdateItemError;
use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use aws_sdk_dynamodb::types::{AttributeValue, Put, ReturnValue, TransactWriteItem};

use super::{Backend, LogPage, Record, StoreError, StoreResult};
use crate::config::StoreConfig;
use crate::epoch::Timestamp;

pub(crate) const HASH_KEY: &str = "pk";
pub(crate) const RANGE_KEY: &str = "sk";
pub(crate) const TTL_ATTRIBUTE: &str = "expires_at";
const VALUE: &str = "data";
const COUNT: &str = "n";

/// Sort key of items that are alone in their partition.
const SOLE: &str = "#";

type Item = HashMap<String, AttributeValue>;

#[derive(Debug, Clone)]
pub(crate) struct DynamoBackend {
    client: Client,
    table: String,
}

impl DynamoBackend {
    /// Connect using the environment's AWS credentials and region, and
    /// check that the table can be read.
    pub(crate) async fn connect(config: &StoreConfig) -> anyhow::Result<Self> {
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

    pub(crate) fn from_client(client: Client, table: String) -> Self {
        Self { client, table }
    }
}

fn failure<E, R>(error: SdkError<E, R>) -> StoreError
where
    E: std::error::Error + Send + Sync + 'static,
    R: std::fmt::Debug + Send + Sync + 'static,
{
    StoreError::Unavailable(error.into())
}

fn string(value: impl Into<String>) -> AttributeValue {
    AttributeValue::S(value.into())
}

fn number(value: impl std::fmt::Display) -> AttributeValue {
    AttributeValue::N(value.to_string())
}

fn key(pk: &str, sk: &str) -> Item {
    HashMap::from([
        (HASH_KEY.to_owned(), string(pk)),
        (RANGE_KEY.to_owned(), string(sk)),
    ])
}

fn item(pk: &str, sk: &str, value: String, expires_at: Option<Timestamp>) -> Item {
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
        _ => Err(StoreError::Corrupt(
            "item has no string 'data' attribute".into(),
        )),
    }
}

fn number_of<T: std::str::FromStr>(item: &Item, name: &str) -> StoreResult<Option<T>> {
    match item.get(name) {
        None => Ok(None),
        Some(AttributeValue::N(text)) => text
            .parse()
            .map(Some)
            .map_err(|_| StoreError::Corrupt(format!("item attribute '{name}' is out of range").into())),
        Some(_) => Err(StoreError::Corrupt(
            format!("item attribute '{name}' is not a number").into(),
        )),
    }
}

/// The sort key of a log entry: the time, zero padded so that keys order by
/// it, then the id.
fn log_sort_key(at: Timestamp, id: &str) -> String {
    format!("{:020}#{id}", at.unix())
}

/// Whether a transaction was cancelled because a condition did not hold.
fn is_condition_failure<R>(error: &SdkError<TransactWriteItemsError, R>) -> bool {
    matches!(
        error.as_service_error(),
        Some(TransactWriteItemsError::TransactionCanceledException(cancelled))
            if cancelled
                .cancellation_reasons()
                .iter()
                .any(|reason| reason.code() == Some("ConditionalCheckFailed"))
    )
}

fn record(item: &Item) -> StoreResult<Record> {
    Ok(Record {
        value: value_of(item)?,
        expires_at: number_of(item, TTL_ATTRIBUTE)?.map(Timestamp::from_unix),
        count: number_of(item, COUNT)?.unwrap_or(0),
    })
}

#[async_trait::async_trait]
impl Backend for DynamoBackend {
    async fn put(
        &self,
        key: &str,
        value: String,
        expires_at: Option<Timestamp>,
    ) -> StoreResult<()> {
            self.client
                .put_item()
                .table_name(&self.table)
                .set_item(Some(item(key, SOLE, value, expires_at)))
                .send()
                .await
                .map_err(failure)?;
            Ok(())
        }

    async fn put_new(
        &self,
        key: &str,
        value: String,
        expires_at: Option<Timestamp>,
        now: Timestamp,
    ) -> StoreResult<bool> {
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
        }

    async fn replace(
        &self,
        key: &str,
        expected: &str,
        value: String,
        expires_at: Option<Timestamp>,
    ) -> StoreResult<bool> {
        let result = self
            .client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item(key, SOLE, value, expires_at)))
            .condition_expression("#data = :expected")
            .expression_attribute_names("#data", VALUE)
            .expression_attribute_values(":expected", string(expected))
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
    }

    async fn get(&self, key_: &str) -> StoreResult<Option<Record>> {
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
        }

    async fn take(&self, key_: &str) -> StoreResult<Option<Record>> {
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
        }

    async fn increment(&self, key_: &str) -> StoreResult<Option<Record>> {
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
        }

    async fn log_append(
        &self,
        partition: &str,
        id: &str,
        at: Timestamp,
        value: String,
        expires_at: Timestamp,
    ) -> StoreResult<bool> {
        // Two items, one to find the entry by id and one to list it in its
        // partition, written in one transaction: both or neither, and only
        // if the id is new.
        let put = |pk: String, sk: &str, value: String| -> StoreResult<TransactWriteItem> {
            let put = Put::builder()
                .table_name(&self.table)
                .set_item(Some(item(&pk, sk, value, Some(expires_at))))
                .condition_expression("attribute_not_exists(#pk)")
                .expression_attribute_names("#pk", HASH_KEY)
                .build()
                .map_err(|error| StoreError::Unavailable(error.into()))?;
            Ok(TransactWriteItem::builder().put(put).build())
        };
        let result = self
            .client
            .transact_write_items()
            .transact_items(put(format!("logid#{id}"), SOLE, value.clone())?)
            .transact_items(put(
                format!("log#{partition}"),
                // Zero padded so that the sort key orders by time.
                &log_sort_key(at, id),
                value,
            )?)
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error) if is_condition_failure(&error) => Ok(false),
            Err(error) => Err(failure(error)),
        }
    }

    async fn log_list(
        &self,
        partition: &str,
        limit: usize,
        cursor: Option<&str>,
    ) -> StoreResult<LogPage> {
        let pk = format!("log#{partition}");
        let start = cursor.map(|sk| key(&pk, sk));
        let output = self
            .client
            .query()
            .table_name(&self.table)
            .key_condition_expression("#pk = :pk")
            .expression_attribute_names("#pk", HASH_KEY)
            .expression_attribute_values(":pk", string(&pk))
            .scan_index_forward(false)
            .consistent_read(true)
            .limit(i32::try_from(limit).unwrap_or(i32::MAX))
            .set_exclusive_start_key(start)
            .send()
            .await
            .map_err(failure)?;
        let values = output.items().iter().map(value_of).collect::<StoreResult<_>>()?;
        // The sort key of the last item read is where the next page starts.
        let next = output
            .last_evaluated_key
            .as_ref()
            .and_then(|last| match last.get(RANGE_KEY) {
                Some(AttributeValue::S(sk)) => Some(sk.clone()),
                _ => None,
            });
        Ok(LogPage { values, next })
    }

    async fn log_get(&self, id: &str) -> StoreResult<Option<String>> {
            let key_ = format!("logid#{id}");
            Ok(self.get(&key_).await?.map(|record| record.value))
        }

    async fn purge(&self, _now: Timestamp) -> StoreResult<()> {
        // The table's TTL setting removes expired items.
        Ok(())
    }
}

#[cfg(test)]
mod tests;
