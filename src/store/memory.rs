//! The in-process backend.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};

use super::{Backend, BackendFuture, MAX_CONSENT_RECORDS, Record};

#[derive(Debug)]
struct LogEntry {
    partition: String,
    id: String,
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
#[derive(Debug, Default)]
pub struct MemoryBackend {
    inner: Mutex<Inner>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // The maps stay structurally valid even if a holder panicked.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Number of records held (log entries excluded), for diagnostics and
    /// tests.
    pub fn len(&self) -> usize {
        self.lock().records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn ready<'a, T: Send + 'a>(value: T) -> BackendFuture<'a, T> {
    Box::pin(std::future::ready(Ok(value)))
}

impl Backend for MemoryBackend {
    fn put<'a>(
        &'a self,
        key: &'a str,
        value: String,
        expires_at: Option<i64>,
    ) -> BackendFuture<'a, ()> {
        self.lock().records.insert(
            key.to_owned(),
            Record {
                value,
                expires_at,
                count: 0,
            },
        );
        ready(())
    }

    fn put_new<'a>(
        &'a self,
        key: &'a str,
        value: String,
        expires_at: Option<i64>,
        now: i64,
    ) -> BackendFuture<'a, bool> {
        let mut inner = self.lock();
        let occupied = inner
            .records
            .get(key)
            .is_some_and(|record| record.expires_at.is_none_or(|at| at > now));
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
        ready(!occupied)
    }

    fn get<'a>(&'a self, key: &'a str) -> BackendFuture<'a, Option<Record>> {
        ready(self.lock().records.get(key).cloned())
    }

    fn take<'a>(&'a self, key: &'a str) -> BackendFuture<'a, Option<Record>> {
        ready(self.lock().records.remove(key))
    }

    fn increment<'a>(&'a self, key: &'a str) -> BackendFuture<'a, Option<Record>> {
        ready(self.lock().records.get_mut(key).map(|record| {
            record.count += 1;
            record.clone()
        }))
    }

    fn log_append<'a>(
        &'a self,
        partition: &'a str,
        id: &'a str,
        _at: i64,
        value: String,
    ) -> BackendFuture<'a, ()> {
        let mut inner = self.lock();
        if inner.log.len() >= MAX_CONSENT_RECORDS {
            inner.log.pop_front();
        }
        inner.log.push_back(LogEntry {
            partition: partition.to_owned(),
            id: id.to_owned(),
            value,
        });
        ready(())
    }

    fn log_list<'a>(&'a self, partition: &'a str) -> BackendFuture<'a, Vec<String>> {
        ready(
            self.lock()
                .log
                .iter()
                .rev()
                .filter(|entry| entry.partition == partition)
                .map(|entry| entry.value.clone())
                .collect(),
        )
    }

    fn log_get<'a>(&'a self, id: &'a str) -> BackendFuture<'a, Option<String>> {
        ready(
            self.lock()
                .log
                .iter()
                .rev()
                .find(|entry| entry.id == id)
                .map(|entry| entry.value.clone()),
        )
    }

    fn purge(&self, now: i64) -> BackendFuture<'_, ()> {
        self.lock()
            .records
            .retain(|_, record| record.expires_at.is_none_or(|at| at > now));
        ready(())
    }
}
