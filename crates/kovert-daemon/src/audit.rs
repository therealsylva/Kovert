use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub event_id: Option<String>,
    pub kind: String,
    pub rule_id: Option<String>,
    pub payload: serde_json::Value,
    pub previous_hash: String,
    pub hash: String,
}

pub struct AuditStore {
    connection: Mutex<Connection>,
    max_records: usize,
}

impl AuditStore {
    pub fn open(path: &Path, max_records: usize) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create state directory {}", parent.display()))?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("open state database {}", path.display()))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_id TEXT,
                kind TEXT NOT NULL,
                rule_id TEXT,
                payload TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                hash TEXT NOT NULL UNIQUE
            );
            CREATE INDEX IF NOT EXISTS audit_timestamp_idx ON audit(timestamp);
            CREATE INDEX IF NOT EXISTS audit_event_idx ON audit(event_id);
            CREATE TABLE IF NOT EXISTS state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS action_ledger (
                event_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                action_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                outcome TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(event_id, rule_id, action_hash)
            );
            ",
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
            max_records,
        })
    }

    pub fn append(
        &self,
        event_id: Option<&str>,
        kind: &str,
        rule_id: Option<&str>,
        payload: &serde_json::Value,
    ) -> Result<AuditRecord> {
        let mut connection = self.connection.lock();
        let transaction = connection.transaction()?;
        let anchor = transaction
            .query_row(
                "SELECT value FROM state WHERE key = 'audit_anchor'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| GENESIS_HASH.to_owned());
        let previous_hash = transaction
            .query_row(
                "SELECT hash FROM audit ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or(anchor);
        let timestamp = Utc::now();
        let payload_text = serde_json::to_string(payload)?;
        let hash = record_hash(
            &previous_hash,
            &timestamp.to_rfc3339(),
            event_id,
            kind,
            rule_id,
            &payload_text,
        );
        transaction.execute(
            "INSERT INTO audit(timestamp, event_id, kind, rule_id, payload, previous_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                timestamp.to_rfc3339(),
                event_id,
                kind,
                rule_id,
                payload_text,
                previous_hash,
                hash,
            ],
        )?;
        let id = transaction.last_insert_rowid();
        prune(&transaction, self.max_records)?;
        transaction.commit()?;
        Ok(AuditRecord {
            id,
            timestamp,
            event_id: event_id.map(str::to_owned),
            kind: kind.to_owned(),
            rule_id: rule_id.map(str::to_owned),
            payload: payload.clone(),
            previous_hash,
            hash,
        })
    }

    pub fn recent(&self, limit: usize) -> Result<Vec<AuditRecord>> {
        let connection = self.connection.lock();
        let mut statement = connection.prepare(
            "SELECT id, timestamp, event_id, kind, rule_id, payload, previous_hash, hash
             FROM audit ORDER BY id DESC LIMIT ?1",
        )?;
        let records = statement
            .query_map([limit.min(1_000) as i64], |row| {
                let timestamp: String = row.get(1)?;
                let payload: String = row.get(5)?;
                Ok((
                    row.get::<_, i64>(0)?,
                    timestamp,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    payload,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })?
            .map(|row| {
                let (id, timestamp, event_id, kind, rule_id, payload, previous_hash, hash) = row?;
                Ok(AuditRecord {
                    id,
                    timestamp: DateTime::parse_from_rfc3339(&timestamp)?.with_timezone(&Utc),
                    event_id,
                    kind,
                    rule_id,
                    payload: serde_json::from_str(&payload)?,
                    previous_hash,
                    hash,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(records)
    }

    pub fn verify(&self) -> Result<usize> {
        let connection = self.connection.lock();
        let mut previous = connection
            .query_row(
                "SELECT value FROM state WHERE key = 'audit_anchor'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| GENESIS_HASH.to_owned());
        let mut statement = connection.prepare(
            "SELECT id, timestamp, event_id, kind, rule_id, payload, previous_hash, hash
             FROM audit ORDER BY id ASC",
        )?;
        let mut rows = statement.query([])?;
        let mut verified = 0;
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let timestamp: String = row.get(1)?;
            let event_id: Option<String> = row.get(2)?;
            let kind: String = row.get(3)?;
            let rule_id: Option<String> = row.get(4)?;
            let payload: String = row.get(5)?;
            let stored_previous: String = row.get(6)?;
            let stored_hash: String = row.get(7)?;
            if stored_previous != previous {
                bail!("audit chain break before record {id}")
            }
            let calculated = record_hash(
                &previous,
                &timestamp,
                event_id.as_deref(),
                &kind,
                rule_id.as_deref(),
                &payload,
            );
            if calculated != stored_hash {
                bail!("audit record {id} digest mismatch")
            }
            previous = stored_hash;
            verified += 1;
        }
        Ok(verified)
    }

    pub fn get_state(&self, key: &str) -> Result<Option<String>> {
        self.connection
            .lock()
            .query_row("SELECT value FROM state WHERE key = ?1", [key], |row| row.get(0))
            .optional()
            .map_err(Into::into)
    }

    pub fn set_state(&self, key: &str, value: &str) -> Result<()> {
        self.connection.lock().execute(
            "INSERT INTO state(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn action_completed(&self, event_id: &str, rule_id: &str, action_hash: &str) -> Result<bool> {
        let status = self
            .connection
            .lock()
            .query_row(
                "SELECT status FROM action_ledger
                 WHERE event_id = ?1 AND rule_id = ?2 AND action_hash = ?3",
                params![event_id, rule_id, action_hash],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(status.as_deref() == Some("succeeded"))
    }

    pub fn record_action(
        &self,
        event_id: &str,
        rule_id: &str,
        action_hash: &str,
        status: &str,
        outcome: Option<&serde_json::Value>,
    ) -> Result<()> {
        let outcome = outcome.map(serde_json::to_string).transpose()?;
        self.connection.lock().execute(
            "INSERT INTO action_ledger(event_id, rule_id, action_hash, status, outcome, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(event_id, rule_id, action_hash) DO UPDATE SET
               status = excluded.status,
               outcome = excluded.outcome,
               updated_at = excluded.updated_at",
            params![event_id, rule_id, action_hash, status, outcome, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }
}

fn record_hash(
    previous_hash: &str,
    timestamp: &str,
    event_id: Option<&str>,
    kind: &str,
    rule_id: Option<&str>,
    payload: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    for value in [
        previous_hash,
        timestamp,
        event_id.unwrap_or_default(),
        kind,
        rule_id.unwrap_or_default(),
        payload,
    ] {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn prune(transaction: &rusqlite::Transaction<'_>, max_records: usize) -> Result<()> {
    if max_records == 0 {
        return Ok(())
    }
    let count: i64 = transaction.query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))?;
    let excess = count.saturating_sub(max_records as i64);
    if excess == 0 {
        return Ok(())
    }
    let (cutoff, anchor): (i64, String) = transaction
        .query_row(
            "SELECT id, hash FROM audit ORDER BY id ASC LIMIT 1 OFFSET ?1",
            [excess - 1],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| anyhow!("select audit retention anchor: {error}"))?;
    transaction.execute("DELETE FROM audit WHERE id <= ?1", [cutoff])?;
    transaction.execute(
        "INSERT INTO state(key, value) VALUES ('audit_anchor', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [anchor],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_audit_tampering() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("state.db");
        let store = AuditStore::open(&path, 100).unwrap_or_else(|error| panic!("open: {error}"));
        store
            .append(None, "test", None, &serde_json::json!({"value": 1}))
            .unwrap_or_else(|error| panic!("append: {error}"));
        assert_eq!(store.verify().unwrap_or_default(), 1);
        store
            .connection
            .lock()
            .execute("UPDATE audit SET payload = '{}' WHERE id = 1", [])
            .unwrap_or_else(|error| panic!("tamper fixture: {error}"));
        assert!(store.verify().is_err());
    }
}

