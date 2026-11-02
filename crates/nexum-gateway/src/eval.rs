//! Nexum Eval: authorization security scenarios run through the real
//! enforcement pipeline (real signatures, chains, trust, policy and protocol
//! adapters) against a sandboxed copy of a gateway's configuration.
//!
//! The scenario DSL, attacks and grant minting live in `nexum-sim` (shared
//! with the browser playground); the *decision* here is always the gateway's
//! own `Authorizer`.
//!
//! Each scenario gets a fresh sandbox, so revocations and replay caches never
//! leak between scenarios. Production state and audit are never touched; the
//! caller organization's keys are swapped for an ephemeral key so a suite can
//! mint grants without any real signing key.
//!
//! Every scenario that expects ALLOW is also replayed under each built-in
//! [`Attack`], which must turn it into a DENY with the attack's reason code.
//!
//! The question is never "did the model answer well?" but "could this agent
//! obtain or exercise authority it should not have?".

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use axum::http::HeaderMap;
use nexum_core::{Outcome, ReasonCode, TrustDomain};
use nexum_grant::KeyPair;
use serde::Serialize;

use crate::adapters::{ProtocolAdapter, parse_unambiguous};
use crate::authorizer::{Normalized, Presented};
use crate::config::Config;
use crate::server::{AppState, normalize_authorize};

pub use nexum_sim::{Attack, GrantSpec, KIND, RequestSpec, RpcSpec, Scenario, Suite, expand};

/// One scenario's result. Serialized as-is by `nexum eval run --json`.
#[derive(Debug, Serialize)]
pub struct ScenarioResult {
    pub suite: String,
    pub category: Option<String>,
    pub name: String,
    pub attack: Option<Attack>,
    pub invariant: Option<String>,
    pub expect: Outcome,
    pub expect_code: Option<String>,
    pub actual: Outcome,
    pub actual_code: Option<&'static str>,
    pub passed: bool,
    /// The gateway was more permissive than expected: authority leaked.
    pub critical: bool,
    /// Set when the scenario could not be run (bad suite input).
    pub error: Option<String>,
}

fn permissiveness(o: Outcome) -> u8 {
    match o {
        Outcome::Deny => 0,
        Outcome::RequireApproval => 1,
        Outcome::Allow => 2,
    }
}

pub fn load(path: &Path) -> anyhow::Result<Suite> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading eval suite {}", path.display()))?;
    let suite: Suite = yaml_serde::from_str(&text)
        .with_context(|| format!("parsing eval suite {}", path.display()))?;
    if suite.api_version != nexum_core::API_VERSION || suite.kind != KIND {
        bail!(
            "{}: expected apiVersion {} and kind {KIND}",
            path.display(),
            nexum_core::API_VERSION
        );
    }
    Ok(suite)
}

/// Suite files under `paths` (files as given, directories recursively,
/// `*.yaml`/`*.yml`), sorted for stable output.
pub fn discover(paths: &[PathBuf]) -> anyhow::Result<Vec<PathBuf>> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
        for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let p = entry?.path();
            if p.is_dir() {
                walk(&p, out)?;
            } else if p.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                // Only eval suites; a directory may also hold its gateway config.
                let text = std::fs::read_to_string(&p)?;
                if text.lines().any(|l| l.trim() == format!("kind: {KIND}")) {
                    out.push(p);
                }
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    for p in paths {
        if p.is_dir() {
            walk(p, &mut out)?;
        } else {
            out.push(p.clone());
        }
    }
    out.sort();
    if out.is_empty() {
        bail!("no `kind: {KIND}` files found");
    }
    Ok(out)
}

/// Run every scenario of `suite` (expanded), each in a fresh sandbox.
pub async fn run_suite(cfg: &Config, suite_name: &str, suite: &Suite) -> Vec<ScenarioResult> {
    let mut out = Vec::new();
    for s in expand(suite) {
        let observed = match Sandbox::new(cfg, &suite.org) {
            Ok(sb) => sb.exercise(&s).await,
            Err(e) => Err(e),
        };
        let mut r = ScenarioResult {
            suite: suite_name.to_owned(),
            category: suite.category.clone(),
            name: s.name,
            attack: s.attack,
            invariant: s.invariant,
            expect: s.expect,
            expect_code: s.code,
            actual: Outcome::Deny,
            actual_code: None,
            passed: false,
            critical: false,
            error: None,
        };
        match observed {
            Ok(o) => {
                (r.actual, r.actual_code) = (o.outcome, o.code);
                r.passed = r.actual == r.expect
                    && r.expect_code
                        .as_deref()
                        .is_none_or(|c| Some(c) == r.actual_code);
                r.critical = permissiveness(r.actual) > permissiveness(r.expect);
            }
            Err(e) => r.error = Some(format!("{e:#}")),
        }
        out.push(r);
    }
    out
}

#[derive(Debug)]
struct Observed {
    outcome: Outcome,
    code: Option<&'static str>,
}

/// A throwaway gateway built from `cfg`'s trust, policy and adapters.
#[derive(Debug)]
struct Sandbox {
    dir: PathBuf,
    state: Arc<AppState>,
    org: TrustDomain,
    issuer: String,
    org_key: KeyPair,
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Sandbox {
    fn new(cfg: &Config, org: &TrustDomain) -> anyhow::Result<Self> {
        let mut trust = crate::load_trust(&cfg.trust.file)?;
        let domain = trust
            .trust_domains
            .get_mut(org)
            .with_context(|| format!("suite org {org} is not in the trust store"))?;
        let org_key = KeyPair::generate();
        domain.keys = vec![org_key.public_jwk()];
        let issuer = domain.issuer.clone();

        let dir = std::env::temp_dir().join(format!("nexum-eval-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir)?;
        let mut cfg = cfg.clone();
        cfg.trust.file = dir.join("trust.yaml");
        // In-memory SQLite: sandbox state is discarded anyway, and per-file
        // fsyncs dominated eval time.
        cfg.state.file = ":memory:".into();
        cfg.audit.provider = "sqlite".into();
        cfg.audit.path = ":memory:".into();
        // Upstreams stay configured for normalization but are never called.
        let built = std::fs::write(&cfg.trust.file, yaml_serde::to_string(&trust)?)
            .map_err(anyhow::Error::from)
            .and_then(|()| crate::build(&cfg));
        match built {
            Ok(state) => Ok(Sandbox {
                dir,
                state,
                org: org.clone(),
                issuer,
                org_key,
            }),
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                Err(e)
            }
        }
    }

    async fn exercise(&self, s: &Scenario) -> anyhow::Result<Observed> {
        let now = chrono::Utc::now().timestamp();
        let audience = self.state.authorizer.settings.audience.clone();
        let m = nexum_sim::mint(s, &self.org, &self.issuer, &self.org_key, &audience, now)?;
        if let Some(t) = &m.revoke {
            self.state.authorizer.state.revoke(t, Some("eval"))?;
        }
        let normalized = self.normalize(&s.request, &m.body);
        let mut d = self
            .send(&m.chain, &m.proof, &m.body, normalized.clone())
            .await;
        if m.replay {
            d = self.send(&m.chain, &m.proof, &m.body, normalized).await;
        }
        Ok(d)
    }

    /// The adapter's normalization, exactly as the corresponding route does it.
    fn normalize(&self, r: &RequestSpec, body: &[u8]) -> Result<Normalized, ReasonCode> {
        let headers = HeaderMap::new();
        let rpc = |f: &dyn Fn(&serde_json::Value) -> Result<Normalized, ReasonCode>| {
            parse_unambiguous(body).map_or(Err(ReasonCode::InvalidRequest), |m| f(&m))
        };
        match (&r.mcp, &r.a2a) {
            (Some(t), _) => rpc(&|m| self.state.mcp.normalize(&t.target, &headers, m)),
            (_, Some(t)) => rpc(&|m| self.state.a2a.normalize(&t.target, &headers, m)),
            _ => normalize_authorize(body),
        }
    }

    async fn send(
        &self,
        chain: &[String],
        proof: &str,
        body: &[u8],
        normalized: Result<Normalized, ReasonCode>,
    ) -> Observed {
        let presented = Presented {
            grants: chain.to_vec(),
            proof: Some(proof.to_owned()),
            approval_id: None,
            body,
            trace: opentelemetry::Context::new(),
        };
        let d = self.state.authorizer.authorize(presented, normalized).await;
        Observed {
            outcome: d.outcome,
            code: d.primary_reason().map(ReasonCode::code),
        }
    }
}
