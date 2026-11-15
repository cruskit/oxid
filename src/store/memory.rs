//! The in-process backend.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};

use super::{Backend, MAX_CONSENT_RECORDS, Record, StoreResult};
use crate::epoch::Timestamp;

#[derive(Debug)]
struct LogEntry {
    #[cfg_attr(not(test), expect(dead_code, reason = "the read side of the consent log, for the planned consent history"))]
    partition: String,
    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(dead_code, reason = "the read side of the consent log, for the planned consent history")
    )]
    id: String,
    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(dead_code, reason = "the read side of the consent log, for the planned consent history")
    )]
    value: String,
}

#[derive(Debug, Default)]
struct Inner {
    records: HashMap<String, Record>,
    /// Oldest first.
    log: VecDeque<LogEntry>,
}

/// Keeps everything in this process. Nothing survives a restart, and nothing
/// is shared with other instances.
#[derive(Default)]
pub(crate) struct MemoryBackend {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for MemoryBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Records include the generated signing key and pairwise salt, so
        // only their number is shown.
        let inner = self.lock();
        f.debug_struct("MemoryBackend")
            .field("records", &inner.records.len())
            .field("log", &inner.log.len())
            .finish()
    }
}

impl MemoryBackend {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // The maps stay structurally valid even if a holder panicked.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    /// Number of records held (log entries excluded), for diagnostics and
    /// tests.
    pub(crate) fn len(&self) -> usize {
        self.lock().records.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait::async_trait]
impl Backend for MemoryBackend {
    async fn put(&self, key: &str, value: String, expires_at: Option<Timestamp>) -> StoreResult<()> {
        self.lock().records.insert(
            key.to_owned(),
            Record {
                value,
                expires_at,
                count: 0,
            },
        );
        Ok(())
    }

    async fn put_new(
        &self,
        key: &str,
        value: String,
        expires_at: Option<Timestamp>,
        now: Timestamp,
    ) -> StoreResult<bool> {
        let mut inner = self.lock();
        let occupied = inner.records.get(key).is_some_and(|record| record.live(now));
        if !occupied {
            inner.records.insert(
                key.to_owned(),
                Record {
                    value,
                    expires_at,
                    count: 0,
                },
            );
        }
        Ok(!occupied)
    }

    async fn get(&self, key: &str) -> StoreResult<Option<Record>> {
        Ok(self.lock().records.get(key).cloned())
    }

    async fn take(&self, key: &str) -> StoreResult<Option<Record>> {
        Ok(self.lock().records.remove(key))
    }

    async fn increment(&self, key: &str) -> StoreResult<Option<Record>> {
        Ok(self.lock().records.get_mut(key).map(|record| {
            record.count += 1;
            record.clone()
        }))
    }

    async fn log_append(
        &self,
        partition: &str,
        id: &str,
        _at: Timestamp,
        value: String,
    ) -> StoreResult<()> {
        let mut inner = self.lock();
        if inner.log.len() >= MAX_CONSENT_RECORDS {
            inner.log.pop_front();
        }
        inner.log.push_back(LogEntry {
            partition: partition.to_owned(),
            id: id.to_owned(),
            value,
        });
        Ok(())
    }

    async fn log_list(&self, partition: &str) -> StoreResult<Vec<String>> {
        Ok(self
            .lock()
            .log
            .iter()
            .rev()
            .filter(|entry| entry.partition == partition)
            .map(|entry| entry.value.clone())
            .collect())
    }

    async fn log_get(&self, id: &str) -> StoreResult<Option<String>> {
        Ok(self
            .lock()
            .log
            .iter()
            .rev()
            .find(|entry| entry.id == id)
            .map(|entry| entry.value.clone()))
    }

    async fn purge(&self, now: Timestamp) -> StoreResult<()> {
        self.lock().records.retain(|_, record| record.live(now));
        Ok(())
    }
}
