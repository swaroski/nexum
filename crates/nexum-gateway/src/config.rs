//! Gateway configuration (`nexum.yaml`). Unknown keys are errors: a typo in
//! security configuration must not silently fall back to a default.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use nexum_core::Capability;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub server: ServerConfig,
    pub gateway: GatewaySettings,
    pub policy: PolicyConfig,
    pub audit: AuditConfig,
    pub trust: FileRef,
    pub state: FileRef,
    /// MCP servers reachable through `/mcp/{name}`.
    #[serde(default)]
    pub mcp: BTreeMap<String, McpServer>,
    /// A2A agents reachable through `/a2a/{name}`.
    #[serde(default)]
    pub a2a: BTreeMap<String, Upstream>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewaySettings {
    /// The audience this gateway accepts grants and proofs for. Normally the
    /// receiving organization's trust domain, e.g. `abc.com`.
    pub audience: String,
    /// Tolerated clock skew between issuers, agents and this gateway.
    #[serde(default = "d30")]
    pub clock_skew_seconds: i64,
    /// Maximum age of a proof of possession.
    #[serde(default = "d60")]
    pub proof_max_age_seconds: i64,
    #[serde(default = "d3600")]
    pub approval_ttl_seconds: i64,
    #[serde(default = "d1mib")]
    pub max_body_bytes: usize,
}

fn d30() -> i64 {
    30
}
fn d60() -> i64 {
    60
}
fn d3600() -> i64 {
    3600
}
fn d1mib() -> usize {
    1024 * 1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Only `builtin` today. External PDPs plug in via `PolicyDecisionPoint`.
    pub provider: String,
    pub file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// `sqlite` or `jsonl`.
    pub provider: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRef {
    #[serde(alias = "path")]
    pub file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServer {
    pub url: String,
    #[serde(default)]
    pub tools: BTreeMap<String, ToolMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolMapping {
    /// Capability required to call this tool. Default: `mcp.<server>.tool.<tool>`.
    #[serde(default)]
    pub action: Option<Capability>,
    /// Name of a non-negative integer argument to expose as the request value.
    #[serde(default)]
    pub value_argument: Option<String>,
}

impl Config {
    /// Load and resolve relative paths against the config file's directory.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut cfg: Config = yaml_serde::from_str(&text)
            .with_context(|| format!("parsing config {}", path.display()))?;
        if cfg.api_version != nexum_core::API_VERSION {
            bail!(
                "unsupported apiVersion {:?} (expected {})",
                cfg.api_version,
                nexum_core::API_VERSION
            );
        }
        if cfg.policy.provider != "builtin" {
            bail!(
                "unsupported policy provider {:?} (only `builtin` in this release)",
                cfg.policy.provider
            );
        }
        if cfg.gateway.audience.is_empty() {
            bail!("gateway.audience is required");
        }
        if cfg.gateway.clock_skew_seconds < 0 || cfg.gateway.proof_max_age_seconds <= 0 {
            bail!("clock_skew_seconds must be >= 0 and proof_max_age_seconds > 0");
        }
        let base = path.parent().unwrap_or(Path::new("."));
        for p in [
            &mut cfg.policy.file,
            &mut cfg.audit.path,
            &mut cfg.trust.file,
            &mut cfg.state.file,
        ] {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
        Ok(cfg)
    }
}
