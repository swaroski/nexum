//! Structured, hash-chained audit events.
//!
//! `event[n].previous_event_hash == event[n-1].event_hash`, and `event_hash`
//! is SHA-256 over the event's canonical JSON with `event_hash` empty. This
//! makes edits, deletions and reordering detectable by `verify`; it does not
//! stop someone with write access from rewriting the whole tail, which is why
//! production deployments should ship events to an external append-only store.
//!
//! Records carry identifiers and decisions only, never tokens, proofs or
//! request payloads.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use nexum_core::{Outcome, ReasonCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("audit encoding error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("audit chain broken at seq {seq}: {msg}")]
    Tampered { seq: u64, msg: String },
    #[error("audit log lock poisoned")]
    Poisoned,
}

/// What the gateway records. No secrets, no payloads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub request_id: Uuid,
    pub decision_id: Option<Uuid>,
    pub agent: Option<String>,
    pub organization: Option<String>,
    pub actor: Option<String>,
    pub action: Option<String>,
    pub resource: Option<String>,
    pub decision: Option<Outcome>,
    pub reason_codes: Vec<ReasonCode>,
    pub delegation_depth: Option<usize>,
    pub policy: Option<String>,
    pub protocol: Option<String>,
    pub grant_ids: Vec<String>,
    pub approval_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub seq: u64,
    #[serde(flatten)]
    pub record: AuditRecord,
    pub previous_event_hash: String,
    pub event_hash: String,
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

impl AuditEvent {
    fn compute_hash(&self) -> Result<String, AuditError> {
        let mut unhashed = self.clone();
        unhashed.event_hash = String::new();
        let bytes = serde_json::to_vec(&unhashed)?;
        Ok(Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }

    fn chain(record: AuditRecord, prev: Option<&AuditEvent>) -> Result<Self, AuditError> {
        let mut e = AuditEvent {
            seq: prev.map_or(1, |p| p.seq + 1),
            record,
            previous_event_hash: prev.map_or(GENESIS.into(), |p| p.event_hash.clone()),
            event_hash: String::new(),
        };
        e.event_hash = e.compute_hash()?;
        Ok(e)
    }
}

/// Parse a stored event and require it to be byte-identical to its canonical
/// encoding. Otherwise fields added to the stored JSON would be dropped by
/// the parser and the hash chain would still verify.
fn parse_canonical(stored: &str) -> Result<AuditEvent, AuditError> {
    let e: AuditEvent = serde_json::from_str(stored)?;
    if serde_json::to_string(&e)? != stored {
        return Err(AuditError::Tampered {
            seq: e.seq,
            msg: "stored event is not in canonical form (fields added or reformatted)".into(),
        });
    }
    Ok(e)
}

/// Verify a sequence of events in order. Returns the number verified.
pub fn verify_events<I: IntoIterator<Item = AuditEvent>>(events: I) -> Result<u64, AuditError> {
    let mut prev: Option<AuditEvent> = None;
    let mut n = 0;
    for e in events {
        let tampered = |msg: &str| AuditError::Tampered {
            seq: e.seq,
            msg: msg.into(),
        };
        let (want_seq, want_prev) = prev.as_ref().map_or((1, GENESIS.to_owned()), |p| {
            (p.seq + 1, p.event_hash.clone())
        });
        if e.seq != want_seq {
            return Err(tampered("sequence gap or reorder"));
        }
        if e.previous_event_hash != want_prev {
            return Err(tampered("previous_event_hash mismatch"));
        }
        if e.compute_hash()? != e.event_hash {
            return Err(tampered("event_hash mismatch (event modified)"));
        }
        n += 1;
        prev = Some(e);
    }
    Ok(n)
}

/// An append-only audit sink. Implementations for PostgreSQL, Kafka,
/// OpenTelemetry logs or a SIEM implement this trait.
pub trait AuditLog: Send + Sync {
    fn append(&self, record: AuditRecord) -> Result<AuditEvent, AuditError>;
    /// All events, oldest first.
    fn read_all(&self) -> Result<Vec<AuditEvent>, AuditError>;
    fn verify(&self) -> Result<u64, AuditError> {
        verify_events(self.read_all()?)
    }
}

/// One JSON object per line.
// ponytail: appends hold a process-wide lock and fsync nothing; use the SQLite
// sink (or ship to an external store) when durability per event matters.
#[derive(Debug)]
pub struct JsonlAudit {
    path: PathBuf,
    state: Mutex<(File, Option<AuditEvent>)>,
}

impl JsonlAudit {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        let last = if path.exists() {
            read_jsonl(&path)?.pop()
        } else {
            None
        };
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            state: Mutex::new((file, last)),
        })
    }
}

fn read_jsonl(path: &Path) -> Result<Vec<AuditEvent>, AuditError> {
    let mut out = Vec::new();
    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        if !line.trim().is_empty() {
            out.push(parse_canonical(&line)?);
        }
    }
    Ok(out)
}

impl AuditLog for JsonlAudit {
    fn append(&self, record: AuditRecord) -> Result<AuditEvent, AuditError> {
        let mut st = self.state.lock().map_err(|_| AuditError::Poisoned)?;
        let event = AuditEvent::chain(record, st.1.as_ref())?;
        let mut line = serde_json::to_vec(&event)?;
        line.push(b'\n');
        st.0.write_all(&line)?;
        st.1 = Some(event.clone());
        Ok(event)
    }

    fn read_all(&self) -> Result<Vec<AuditEvent>, AuditError> {
        read_jsonl(&self.path)
    }
}

#[derive(Debug)]
pub struct SqliteAudit {
    conn: Mutex<rusqlite::Connection>,
}

impl SqliteAudit {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let conn = rusqlite::Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_events (
                seq INTEGER PRIMARY KEY,
                event_hash TEXT NOT NULL,
                previous_event_hash TEXT NOT NULL,
                event_json TEXT NOT NULL
            );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl AuditLog for SqliteAudit {
    fn append(&self, record: AuditRecord) -> Result<AuditEvent, AuditError> {
        let mut conn = self.conn.lock().map_err(|_| AuditError::Poisoned)?;
        // IMMEDIATE takes the write lock up front so concurrent writers
        // (e.g. a second gateway on the same file) cannot fork the chain.
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let last: Option<String> = tx
            .query_row(
                "SELECT event_json FROM audit_events ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(e),
            })?;
        let prev: Option<AuditEvent> = last.map(|s| serde_json::from_str(&s)).transpose()?;
        let event = AuditEvent::chain(record, prev.as_ref())?;
        tx.execute(
            "INSERT INTO audit_events (seq, event_hash, previous_event_hash, event_json)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                event.seq as i64,
                event.event_hash,
                event.previous_event_hash,
                serde_json::to_string(&event)?
            ],
        )?;
        tx.commit()?;
        Ok(event)
    }

    fn read_all(&self) -> Result<Vec<AuditEvent>, AuditError> {
        let conn = self.conn.lock().map_err(|_| AuditError::Poisoned)?;
        let mut stmt = conn.prepare("SELECT event_json FROM audit_events ORDER BY seq")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(parse_canonical(&row?)?);
        }
        Ok(out)
    }
}

/// Open the configured sink.
pub fn open(provider: &str, path: &Path) -> Result<Box<dyn AuditLog>, AuditError> {
    match provider {
        "jsonl" => Ok(Box::new(JsonlAudit::open(path)?)),
        "sqlite" => Ok(Box::new(SqliteAudit::open(path)?)),
        other => Err(AuditError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown audit provider {other:?} (expected jsonl or sqlite)"),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(action: &str) -> AuditRecord {
        AuditRecord {
            event_type: "authorization.decision".into(),
            timestamp: Utc::now(),
            request_id: Uuid::new_v4(),
            decision_id: Some(Uuid::new_v4()),
            agent: Some("spiffe://xyz.com/agents/procurement".into()),
            organization: Some("xyz.com".into()),
            actor: None,
            action: Some(action.into()),
            resource: None,
            decision: Some(Outcome::Allow),
            reason_codes: vec![ReasonCode::PolicyAllow],
            delegation_depth: Some(0),
            policy: None,
            protocol: Some("http".into()),
            grant_ids: vec![],
            approval_id: None,
        }
    }

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("nexum-audit-{}-{name}", Uuid::new_v4()))
    }

    #[test]
    fn jsonl_chain_survives_reopen_and_detects_tampering() {
        let p = tmp("a.jsonl");
        {
            let log = JsonlAudit::open(&p).unwrap();
            log.append(rec("a")).unwrap();
            log.append(rec("b")).unwrap();
        }
        let log = JsonlAudit::open(&p).unwrap();
        assert_eq!(log.append(rec("c")).unwrap().seq, 3);
        assert_eq!(log.verify().unwrap(), 3);

        let text = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, text.replacen("\"action\":\"b\"", "\"action\":\"x\"", 1)).unwrap();
        assert!(matches!(
            log.verify(),
            Err(AuditError::Tampered { seq: 2, .. })
        ));

        let injected = text.replacen("\"seq\":2,", "\"seq\":2,\"note\":\"benign\",", 1);
        assert_ne!(injected, text);
        std::fs::write(&p, injected).unwrap();
        assert!(matches!(
            log.verify(),
            Err(AuditError::Tampered { seq: 2, .. })
        ));

        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&p, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(matches!(
            log.verify(),
            Err(AuditError::Tampered { seq: 3, .. })
        ));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn sqlite_chain() {
        let p = tmp("a.db");
        let log = SqliteAudit::open(&p).unwrap();
        for a in ["a", "b", "c"] {
            log.append(rec(a)).unwrap();
        }
        assert_eq!(log.verify().unwrap(), 3);
        let conn = rusqlite::Connection::open(&p).unwrap();
        conn.execute("DELETE FROM audit_events WHERE seq = 2", [])
            .unwrap();
        assert!(log.verify().is_err());
        std::fs::remove_file(&p).ok();
    }
}
