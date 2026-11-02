//! Local state: agent registry, revocations and approvals, in one SQLite file
//! shared by the gateway and the CLI (WAL mode, so both can open it).

use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use nexum_core::{
    AgentDescriptor, AgentStatus, ApprovalRequest, ApprovalStatus, RevocationList, RevocationTarget,
};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
pub struct State {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Revocation {
    pub target: RevocationTarget,
    pub reason: Option<String>,
    pub revoked_at: DateTime<Utc>,
}

fn status_str(s: ApprovalStatus) -> &'static str {
    match s {
        ApprovalStatus::Pending => "pending",
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Rejected => "rejected",
        ApprovalStatus::Consumed => "consumed",
    }
}

impl State {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS revocations (
                kind TEXT NOT NULL, value TEXT NOT NULL, reason TEXT, revoked_at TEXT NOT NULL,
                PRIMARY KEY (kind, value));
             CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY, status TEXT NOT NULL, data TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY, status TEXT NOT NULL, fingerprint TEXT NOT NULL,
                expires_at INTEGER NOT NULL, decided_by TEXT, decided_at TEXT,
                data TEXT NOT NULL);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> anyhow::Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow::anyhow!("state lock poisoned"))
    }

    // --- revocations ---

    pub fn revoke(&self, target: &RevocationTarget, reason: Option<&str>) -> anyhow::Result<()> {
        self.conn()?.execute(
            "INSERT OR IGNORE INTO revocations (kind, value, reason, revoked_at) VALUES (?1, ?2, ?3, ?4)",
            params![target.kind(), target.value(), reason, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn revocations(&self) -> anyhow::Result<Vec<Revocation>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT kind, value, reason, revoked_at FROM revocations ORDER BY revoked_at",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (kind, value, reason, at) = row?;
            let target: RevocationTarget =
                serde_json::from_value(serde_json::json!({"kind": kind, "value": value}))?;
            out.push(Revocation {
                target,
                reason,
                revoked_at: at.parse()?,
            });
        }
        Ok(out)
    }

    // --- agents ---

    pub fn register_agent(&self, a: &AgentDescriptor) -> anyhow::Result<()> {
        let n = self.conn()?.execute(
            "INSERT OR IGNORE INTO agents (id, status, data) VALUES (?1, 'active', ?2)",
            params![a.id.as_str(), serde_json::to_string(a)?],
        )?;
        anyhow::ensure!(n == 1, "agent {} is already registered", a.id);
        Ok(())
    }

    pub fn agents(&self) -> anyhow::Result<Vec<AgentDescriptor>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT status, data FROM agents ORDER BY id")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (status, data) = row?;
            let mut a: AgentDescriptor = serde_json::from_str(&data)?;
            a.status = if status == "revoked" {
                AgentStatus::Revoked
            } else {
                AgentStatus::Active
            };
            out.push(a);
        }
        Ok(out)
    }

    pub fn agent(&self, id: &str) -> anyhow::Result<Option<AgentDescriptor>> {
        Ok(self.agents()?.into_iter().find(|a| a.id.as_str() == id))
    }

    /// Mark revoked in the registry and add a revocation record, so every
    /// gateway sharing this state rejects the agent's grants immediately.
    pub fn revoke_agent(&self, id: &str, reason: Option<&str>) -> anyhow::Result<()> {
        self.conn()?.execute(
            "UPDATE agents SET status = 'revoked' WHERE id = ?1",
            params![id],
        )?;
        self.revoke(&RevocationTarget::Agent(id.into()), reason)
    }

    // --- approvals ---

    pub fn create_approval(&self, a: &ApprovalRequest) -> anyhow::Result<()> {
        self.conn()?.execute(
            "INSERT INTO approvals (id, status, fingerprint, expires_at, data) VALUES (?1, 'pending', ?2, ?3, ?4)",
            params![a.id.to_string(), a.fingerprint, a.expires_at.timestamp(), serde_json::to_string(a)?],
        )?;
        Ok(())
    }

    pub fn approvals(&self) -> anyhow::Result<Vec<ApprovalRequest>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT status, decided_by, decided_at, data FROM approvals ORDER BY expires_at",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (status, by, at, data) = row?;
            let mut a: ApprovalRequest = serde_json::from_str(&data)?;
            a.status = serde_json::from_value(serde_json::Value::String(status))?;
            a.decided_by = by;
            a.decided_at = at.map(|s| s.parse()).transpose()?;
            out.push(a);
        }
        Ok(out)
    }

    /// Approve or reject a pending, unexpired approval.
    pub fn decide_approval(&self, id: &str, approve: bool, by: &str) -> anyhow::Result<()> {
        let to = if approve {
            ApprovalStatus::Approved
        } else {
            ApprovalStatus::Rejected
        };
        let n = self.conn()?.execute(
            "UPDATE approvals SET status = ?1, decided_by = ?2, decided_at = ?3
             WHERE id = ?4 AND status = 'pending' AND expires_at > ?5",
            params![
                status_str(to),
                by,
                Utc::now().to_rfc3339(),
                id,
                Utc::now().timestamp()
            ],
        )?;
        anyhow::ensure!(n == 1, "approval {id} not found, not pending, or expired");
        Ok(())
    }

    /// Atomically consume an approved approval bound to `fingerprint`.
    /// Single use: a second call returns false.
    pub fn consume_approval(&self, id: &Uuid, fingerprint: &str, now: i64) -> anyhow::Result<bool> {
        let n = self.conn()?.execute(
            "UPDATE approvals SET status = 'consumed'
             WHERE id = ?1 AND status = 'approved' AND fingerprint = ?2 AND expires_at > ?3",
            params![id.to_string(), fingerprint, now],
        )?;
        Ok(n == 1)
    }
}

impl RevocationList for State {
    fn is_revoked(&self, t: &RevocationTarget) -> Result<bool, BoxErr> {
        let conn = self.conn.lock().map_err(|_| "state lock poisoned")?;
        let hit = conn
            .query_row(
                "SELECT 1 FROM revocations WHERE kind = ?1 AND value = ?2",
                params![t.kind(), t.value()],
                |_| Ok(()),
            )
            .optional()?;
        Ok(hit.is_some())
    }
}
