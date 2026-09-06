//! Durable create-idempotency operation journal.

use super::codecs;
use super::{CreateIdempotencyRecord, PersistenceResult, SandboxPersistenceError};
use crate::local_store::LocalKvStore;

pub(super) async fn load(store: &LocalKvStore) -> PersistenceResult<Vec<CreateIdempotencyRecord>> {
    let entries = store.entries().await.map_err(|source| {
        SandboxPersistenceError::store("scan create idempotency records", source)
    })?;
    let mut records = Vec::with_capacity(entries.len());
    for (key, bytes) in entries {
        let stored_key =
            String::from_utf8(key).map_err(|source| SandboxPersistenceError::InvalidRecord {
                reason: "create idempotency record key is not UTF-8".to_string(),
                source: Some(source.into()),
            })?;
        let record = codecs::decode_create_idempotency_record(&bytes)?;
        if record.key != stored_key {
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "create idempotency record key mismatch: database key '{stored_key}' contains '{}'",
                    record.key
                ),
                source: None,
            });
        }
        records.push(record);
    }
    Ok(records)
}

pub(super) async fn put(
    store: &LocalKvStore,
    record: &CreateIdempotencyRecord,
) -> PersistenceResult<()> {
    let bytes = codecs::encode_create_idempotency_record(record)?;
    store
        .put(record.key.as_bytes().to_vec(), bytes)
        .await
        .map_err(|source| {
            SandboxPersistenceError::store("persist create idempotency record", source)
        })
}

pub(super) async fn delete(store: &LocalKvStore, key: &str) -> PersistenceResult<()> {
    store
        .delete(key.as_bytes().to_vec())
        .await
        .map_err(|source| {
            SandboxPersistenceError::store("delete create idempotency record", source)
        })
}
