//! `nexum` — command-line interface for the Nexum gateway and local state.

#![forbid(unsafe_code)]

mod console;

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use nexum_core::{
    AgentDescriptor, AgentId, AgentStatus, ApprovalStatus, AuthorizationRequest, Capability,
    DelegationLink, GrantedAuthority, Outcome, ReasonCode, RequestContext, ResourcePattern,
    RevocationTarget, TrustDomain,
};
use nexum_gateway::config::Config;
use nexum_gateway::store::State;
use nexum_grant::{
    Actor, Confirmation, DelegationSpec, GrantClaims, Jwk, KeyPair, TrustDomainConfig, TrustStore,
};
use serde_json::Value;

#[derive(Parser)]
#[command(
    name = "nexum",
    version,
    about = "Zero-trust authorization and delegated identity for AI agents"
)]
struct Cli {
    /// Path to the gateway configuration.
    #[arg(
        short,
        long,
        global = true,
        env = "NEXUM_CONFIG",
        default_value = "nexum.yaml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new organization: config, trust store, starter policy and org signing key.
    Init(InitArgs),
    #[command(subcommand)]
    Gateway(GatewayCmd),
    #[command(subcommand)]
    Agents(AgentsCmd),
    #[command(subcommand)]
    Grants(GrantsCmd),
    #[command(subcommand)]
    Trust(TrustCmd),
    #[command(subcommand)]
    Policies(PoliciesCmd),
    #[command(subcommand)]
    Approvals(ApprovalsCmd),
    #[command(subcommand)]
    Audit(AuditCmd),
    #[command(subcommand)]
    Trace(TraceCmd),
    #[command(subcommand)]
    Risk(RiskCmd),
    #[command(subcommand)]
    Discover(DiscoverCmd),
    /// Call a gateway's decision API as an agent (signs a fresh proof).
    Call(CallArgs),
    #[command(subcommand)]
    Eval(EvalCmd),
    /// Check configuration, keys, trust, policy, state and audit integrity.
    Doctor,
    /// Local web console over this gateway's files (loopback only).
    Console {
        #[arg(long, default_value = "127.0.0.1:7070")]
        listen: std::net::SocketAddr,
        /// Name recorded on approvals and revocations made in the console.
        #[arg(long = "as", env = "USER")]
        operator: String,
    },
}

#[derive(Args)]
struct InitArgs {
    /// This organization's trust domain, e.g. `abc.com`.
    #[arg(long)]
    domain: String,
    /// Issuer URI for root grants. Default: https://identity.<domain>
    #[arg(long)]
    issuer: Option<String>,
    #[arg(long, default_value = ".")]
    dir: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,
}

#[derive(Subcommand)]
enum GatewayCmd {
    /// Run the enforcement gateway.
    Start,
}

#[derive(Subcommand)]
enum AgentsCmd {
    /// Register an agent. Generates a development key unless --public-key is given.
    Register(RegisterArgs),
    List,
    Inspect {
        id: String,
        /// Print as an A2A Agent Card.
        #[arg(long)]
        a2a_card: bool,
    },
    /// Revoke an agent; every grant naming it stops working immediately.
    Revoke {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Args)]
struct RegisterArgs {
    /// SPIFFE ID, e.g. spiffe://xyz.com/agents/procurement
    #[arg(long)]
    id: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    owner: Option<String>,
    #[arg(long)]
    description: Option<String>,
    #[arg(long)]
    environment: Option<String>,
    #[arg(long)]
    framework: Option<String>,
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long = "protocol")]
    protocols: Vec<String>,
    #[arg(long = "capability")]
    capabilities: Vec<String>,
    /// Existing public JWK file (key stays wherever the agent keeps it).
    #[arg(long)]
    public_key: Option<PathBuf>,
}

#[derive(Subcommand)]
enum GrantsCmd {
    /// Issue a root grant signed by this organization's key.
    Issue(IssueArgs),
    /// Delegate an attenuated child grant from a grant you hold.
    Delegate(DelegateArgs),
    /// Decode a grant. Shows claims without verifying unless --verify.
    Inspect {
        /// Grant file or compact token.
        grant: String,
        /// Verify against this gateway's trust store and revocations.
        #[arg(long)]
        verify: bool,
    },
    /// Revoke a grant (and every grant delegated from it) by its id.
    Revoke { jti: String },
}

#[derive(Args)]
struct IssueArgs {
    #[arg(long)]
    sub: String,
    /// Holder key: the agent's key file or public JWK file.
    #[arg(long)]
    holder: PathBuf,
    #[arg(long = "cap", required = true)]
    caps: Vec<String>,
    #[arg(long = "res", required = true)]
    resources: Vec<String>,
    /// Audience (receiving gateway / trust domain).
    #[arg(long = "aud", required = true)]
    audiences: Vec<String>,
    #[arg(long = "delegatable")]
    delegatable: Vec<String>,
    #[arg(long, default_value_t = 0)]
    max_depth: u32,
    /// Lifetime in seconds.
    #[arg(long, default_value_t = 900)]
    ttl: i64,
    /// Human principal this agent acts for.
    #[arg(long)]
    actor: Option<String>,
    #[arg(long)]
    purpose: Option<String>,
    #[arg(long)]
    max_value: Option<u64>,
    /// Org signing key. Default: .nexum/org.key.json next to the config.
    #[arg(long)]
    signing_key: Option<PathBuf>,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
struct DelegateArgs {
    /// Parent chain, root first (repeat).
    #[arg(long = "parent", required = true)]
    parents: Vec<PathBuf>,
    /// The parent holder's private key file.
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    sub: String,
    #[arg(long)]
    holder: PathBuf,
    #[arg(long = "cap", required = true)]
    caps: Vec<String>,
    #[arg(long = "res")]
    resources: Vec<String>,
    #[arg(long = "delegatable")]
    delegatable: Vec<String>,
    #[arg(long, default_value_t = 0)]
    max_depth: u32,
    #[arg(long, default_value_t = 300)]
    ttl: i64,
    #[arg(long)]
    max_value: Option<u64>,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Subcommand)]
enum TrustCmd {
    List,
    /// Trust another organization's root grants.
    Add {
        domain: String,
        #[arg(long)]
        issuer: String,
        /// The organization's public JWK file.
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "allow")]
        allow: Vec<String>,
        #[arg(long = "deny")]
        deny: Vec<String>,
    },
    /// Stop accepting anything from a trust domain (takes effect immediately).
    Revoke {
        domain: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Revoke a signing key: an issuer `kid`, or an agent key's JWK
    /// thumbprint. Every grant signed by or bound to it stops working.
    RevokeKey {
        kid: String,
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand)]
enum PoliciesCmd {
    Validate {
        file: Option<PathBuf>,
    },
    /// Evaluate trust + policy for a hypothetical request.
    Test(PolicyTestArgs),
    /// Re-evaluate recorded decisions under a proposed policy and report
    /// what would change.
    Simulate {
        /// The proposed policy file.
        proposed: PathBuf,
        /// Audit logs to replay (repeat). Default: this gateway's.
        #[arg(long = "audit")]
        audits: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
        /// Exit non-zero if any decision would become more permissive.
        #[arg(long)]
        fail_on_widen: bool,
    },
}

#[derive(Args)]
struct PolicyTestArgs {
    /// Agent SPIFFE ID.
    #[arg(long)]
    agent: String,
    #[arg(long)]
    action: String,
    #[arg(long)]
    resource: String,
    #[arg(long)]
    value: Option<u64>,
    /// Simulated delegation depth (0 = root grant holder).
    #[arg(long, default_value_t = 0)]
    depth: usize,
    #[arg(long)]
    purpose: Option<String>,
}

#[derive(Subcommand)]
enum ApprovalsCmd {
    List {
        /// Include decided and expired approvals.
        #[arg(long)]
        all: bool,
    },
    Approve {
        id: String,
        #[arg(long, env = "USER")]
        by: String,
    },
    Reject {
        id: String,
        #[arg(long, env = "USER")]
        by: String,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    Tail {
        #[arg(short, default_value_t = 20)]
        n: usize,
    },
    Search {
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        decision: Option<String>,
    },
    /// Verify the tamper-evident hash chain.
    Verify,
}

#[derive(Subcommand)]
enum EvalCmd {
    /// Run security eval suites (and generated attacks) against sandboxed
    /// copies of this gateway's trust, policy and adapters. Exits non-zero
    /// if any scenario fails.
    Run {
        /// Suite files or directories (searched recursively).
        #[arg(default_value = "evals")]
        paths: Vec<PathBuf>,
        /// Machine-readable results for CI.
        #[arg(long)]
        json: bool,
        /// A previous `--json` result: report scenarios that passed then and
        /// fail now (e.g. across Nexum versions or policy changes).
        #[arg(long)]
        baseline: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum DiscoverCmd {
    /// Fetch A2A Agent Cards (read-only) and report which agents Nexum
    /// manages. A base URL is tried at /.well-known/agent-card.json.
    A2a {
        #[arg(required = true)]
        urls: Vec<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum RiskCmd {
    /// Explainable findings from trust, policy, registry and recent audit.
    /// Exits non-zero if any HIGH finding exists.
    Scan {
        /// Audit window, in days.
        #[arg(long, default_value_t = 7)]
        days: i64,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum TraceCmd {
    /// Explain a decision: who acted for whom, through which delegation
    /// chain, and which check decided. Accepts a request id, decision id or
    /// trace id; a trace id gathers every hop across the given audit logs.
    Inspect {
        id: String,
        /// Audit logs to search (repeat for several gateways; `.jsonl` or
        /// SQLite). Default: this gateway's audit log.
        #[arg(long = "audit")]
        audits: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args)]
struct CallArgs {
    /// Grant chain files, root first (repeat).
    #[arg(long = "grant", required = true)]
    grants: Vec<PathBuf>,
    /// The leaf holder's private key file.
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    action: String,
    #[arg(long)]
    resource: String,
    #[arg(long)]
    value: Option<u64>,
    #[arg(long)]
    approval: Option<String>,
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    gateway: String,
    /// Gateway audience. Default: the leaf grant's audience if it has one.
    #[arg(long)]
    audience: Option<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Init(a) => init(a),
        Cmd::Gateway(GatewayCmd::Start) => {
            let tracer = init_telemetry()?;
            let served = nexum_gateway::serve(Config::load(&cli.config)?).await;
            if let Some(t) = tracer {
                // Flush buffered spans off the async runtime.
                let _ = tokio::task::spawn_blocking(move || t.shutdown()).await;
            }
            served
        }
        Cmd::Agents(c) => agents(&cli.config, c),
        Cmd::Grants(c) => grants(&cli.config, c),
        Cmd::Trust(c) => trust(&cli.config, c),
        Cmd::Policies(c) => policies(&cli.config, c),
        Cmd::Approvals(c) => approvals(&cli.config, c),
        Cmd::Audit(c) => audit(&cli.config, c),
        Cmd::Risk(RiskCmd::Scan { days, json }) => risk_scan(&cli.config, days, json),
        Cmd::Discover(DiscoverCmd::A2a { urls, json }) => {
            discover_a2a(&cli.config, &urls, json).await
        }
        Cmd::Trace(TraceCmd::Inspect { id, audits, json }) => {
            trace_inspect(&cli.config, &id, audits, json)
        }
        Cmd::Call(a) => call(a).await,
        Cmd::Eval(EvalCmd::Run {
            paths,
            json,
            baseline,
        }) => eval(&cli.config, &paths, json, baseline.as_deref()).await,
        Cmd::Doctor => doctor(&cli.config),
        Cmd::Console { listen, operator } => console::serve(cli.config, listen, operator).await,
    }
}

async fn eval(config: &Path, paths: &[PathBuf], json: bool, baseline: Option<&Path>) -> Result<()> {
    use nexum_gateway::eval;
    let cfg = Config::load(config)?;
    let mut results = Vec::new();
    for path in eval::discover(paths)? {
        let suite = eval::load(&path)?;
        results.extend(eval::run_suite(&cfg, &path.display().to_string(), &suite).await);
    }
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let critical: Vec<_> = results.iter().filter(|r| r.critical).collect();
    let score = 100.0 * passed as f64 / total.max(1) as f64;
    // Scenario names are unique per category; suite paths may differ between runs.
    let key = |cat: &Value, name: &Value| {
        format!(
            "{}/{}",
            cat.as_str().unwrap_or(""),
            name.as_str().unwrap_or("")
        )
    };
    let (base_version, regressions) = match baseline {
        None => (None, vec![]),
        Some(p) => {
            let b: Value = serde_json::from_str(
                &std::fs::read_to_string(p)
                    .with_context(|| format!("reading baseline {}", p.display()))?,
            )
            .with_context(|| format!("parsing baseline {}", p.display()))?;
            let passed_then: std::collections::BTreeSet<String> = b["results"]
                .as_array()
                .context("baseline has no results")?
                .iter()
                .filter(|r| r["passed"] == true)
                .map(|r| key(&r["category"], &r["name"]))
                .collect();
            let regressions: Vec<String> = results
                .iter()
                .filter(|r| !r.passed)
                .map(|r| key(&serde_json::json!(r.category), &serde_json::json!(r.name)))
                .filter(|k| passed_then.contains(k))
                .collect();
            (
                Some(format!(
                    "{} ({:.1}%)",
                    b["nexum_version"].as_str().unwrap_or("?"),
                    b["score"].as_f64().unwrap_or(0.0)
                )),
                regressions,
            )
        }
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "nexum_version": env!("CARGO_PKG_VERSION"),
                "total": total,
                "passed": passed,
                "failed": total - passed,
                "critical": critical.len(),
                "score": score,
                "regressions": regressions,
                "results": results,
            }))?
        );
    } else {
        println!("NEXUM SECURITY EVAL\n\n{total} scenarios\n");
        for r in &results {
            if r.passed {
                println!("  PASS      {}", r.name);
                continue;
            }
            let got = match &r.error {
                Some(e) => format!("error: {e}"),
                None => format!("got {} {}", r.actual, r.actual_code.unwrap_or("-")),
            };
            println!(
                "  {:<9} {}: expected {} {}, {got}  ({})",
                if r.critical { "CRITICAL" } else { "FAIL" },
                r.name,
                r.expect,
                r.expect_code.as_deref().unwrap_or(""),
                r.suite,
            );
        }
        println!(
            "\nPASS {passed}   FAIL {}   CRITICAL {}   score {score:.1}%",
            total - passed,
            critical.len()
        );
        if let Some(v) = &base_version {
            if regressions.is_empty() {
                println!("\nNo regressions against baseline {v}.");
            } else {
                println!("\nREGRESSIONS against baseline {v}:");
                for k in &regressions {
                    println!("  {k}");
                }
            }
        }
        for r in &critical {
            println!(
                "\nCRITICAL  {}\n  Expected {}, actual {}: the gateway granted authority it should not have.",
                r.name, r.expect, r.actual
            );
            if let Some(i) = &r.invariant {
                println!("  Invariant: {i}");
            }
        }
    }
    if passed < total {
        bail!("{} eval scenario(s) failed", total - passed);
    }
    Ok(())
}

/// Logs go to stderr (`NEXUM_LOG_FORMAT=json` for log pipelines). When
/// `OTEL_EXPORTER_OTLP_ENDPOINT` (or `..._TRACES_ENDPOINT`) is set,
/// `nexum.authorize` spans are also exported over OTLP/HTTP; the standard
/// `OTEL_*` variables apply.
fn init_telemetry() -> Result<Option<opentelemetry_sdk::trace::SdkTracerProvider>> {
    use opentelemetry::trace::TracerProvider;
    use tracing_subscriber::prelude::*;

    // Read W3C `traceparent` even without export, so audit events carry the
    // caller's trace id for cross-gateway correlation.
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let fmt = tracing_subscriber::fmt::layer();
    let fmt = if std::env::var("NEXUM_LOG_FORMAT").is_ok_and(|v| v == "json") {
        fmt.json().boxed()
    } else {
        fmt.boxed()
    };
    let endpoint = [
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
    ]
    .into_iter()
    .find_map(|k| std::env::var(k).ok());
    let provider = match endpoint {
        None => None,
        // MINIMAL: plain HTTP to a local/sidecar collector only. TLS here
        // would pull a second rustls crypto provider (aws-lc); add it via
        // reqwest's ring backend if a direct-to-SaaS export is needed.
        Some(e) if e.starts_with("https:") => {
            bail!("OTLP over https is not supported; export to a local OpenTelemetry Collector")
        }
        Some(_) => {
            // The blocking HTTP client must be built off the async runtime.
            let exporter = std::thread::spawn(|| {
                opentelemetry_otlp::SpanExporter::builder()
                    .with_http()
                    .build()
            })
            .join()
            .map_err(|_| anyhow::anyhow!("OTLP exporter setup panicked"))?
            .context("building OTLP exporter")?;
            let mut resource = opentelemetry_sdk::Resource::builder();
            if std::env::var_os("OTEL_SERVICE_NAME").is_none() {
                resource = resource.with_service_name("nexum-gateway");
            }
            Some(
                opentelemetry_sdk::trace::SdkTracerProvider::builder()
                    .with_batch_exporter(exporter)
                    .with_resource(resource.build())
                    .build(),
            )
        }
    };
    let otel = provider
        .as_ref()
        .map(|p| tracing_opentelemetry::layer().with_tracer(p.tracer("nexum")));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt)
        .with(otel)
        .init();
    Ok(provider)
}

// ---------- helpers ----------

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn caps(v: &[String]) -> Result<Vec<Capability>> {
    v.iter()
        .map(|s| Capability::parse(s).map_err(Into::into))
        .collect()
}

fn resources(v: &[String]) -> Result<Vec<ResourcePattern>> {
    v.iter()
        .map(|s| ResourcePattern::parse(s).map_err(Into::into))
        .collect()
}

fn base_dir(config: &Path) -> &Path {
    config
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Record an administrative action in this gateway's audit chain, after the
/// action itself succeeded. An audit failure is reported as an error so the
/// operator knows the action happened but is not on record.
fn record_admin(config: &Path, mut r: nexum_audit::AuditRecord) -> Result<()> {
    let cfg = match Config::load(config) {
        Ok(c) => c,
        Err(_) => {
            eprintln!(
                "note: no gateway config at {}; {} not audited",
                config.display(),
                r.event_type
            );
            return Ok(());
        }
    };
    // MINIMAL: JSONL logs cache their tail in the gateway process, so a second
    // writer would fork the chain. Admin events need the SQLite provider
    // (per-append transaction); a JSONL writer lock would lift this.
    if cfg.audit.provider != "sqlite" {
        eprintln!(
            "note: {} not audited (requires the sqlite audit provider)",
            r.event_type
        );
        return Ok(());
    }
    if r.operator.is_none() {
        r.operator = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .ok();
    }
    let event_type = r.event_type.clone();
    nexum_audit::open(&cfg.audit.provider, &cfg.audit.path)
        .and_then(|log| log.append(r))
        .with_context(|| {
            format!("action applied, but writing the {event_type} audit event failed")
        })?;
    Ok(())
}

fn admin(event_type: &str) -> nexum_audit::AuditRecord {
    nexum_audit::AuditRecord::new(event_type)
}

fn joined(v: &[impl std::fmt::Display]) -> String {
    v.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn state(config: &Path) -> Result<State> {
    State::open(&Config::load(config)?.state.file)
}

/// Write a new file, refusing to overwrite. `secret` restricts it to the owner.
fn write_new(path: &Path, contents: &str, secret: bool) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut f = opts.open(path).with_context(|| {
        format!(
            "creating {} (refusing to overwrite existing files)",
            path.display()
        )
    })?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

/// Replace a file via write-to-temp + rename, so a crash never leaves a
/// half-written trust store.
fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn read_key(path: &Path) -> Result<KeyPair> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    KeyPair::from_json(&text)
        .with_context(|| format!("{} is not a Nexum private key file", path.display()))
}

/// Public JWK from either a private key file or a public JWK file.
fn read_public(path: &Path) -> Result<Jwk> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    if let Ok(k) = KeyPair::from_json(&text) {
        return Ok(k.public_jwk());
    }
    let jwk: Jwk = serde_json::from_str(&text)
        .with_context(|| format!("{} is not an Ed25519 JWK", path.display()))?;
    jwk.to_key()?;
    Ok(jwk)
}

fn read_token(arg: &str) -> Result<String> {
    let p = Path::new(arg);
    if p.exists() {
        Ok(std::fs::read_to_string(p)?.trim().to_owned())
    } else {
        Ok(arg.trim().to_owned())
    }
}

fn emit(out: Option<&Path>, token: &str) -> Result<()> {
    match out {
        Some(p) => {
            std::fs::write(p, format!("{token}\n"))?;
            eprintln!("wrote {}", p.display());
        }
        None => println!("{token}"),
    }
    Ok(())
}

fn short_ttl(secs: i64) -> String {
    if secs <= 0 {
        return "expired".into();
    }
    format!("{}m {}s", secs / 60, secs % 60)
}

// ---------- init ----------

fn init(a: InitArgs) -> Result<()> {
    let domain = TrustDomain::parse(&a.domain)?;
    let issuer = a
        .issuer
        .unwrap_or_else(|| format!("https://identity.{domain}"));
    std::fs::create_dir_all(a.dir.join(".nexum/keys"))?;
    let org = KeyPair::generate();

    let mut store = TrustStore {
        api_version: nexum_core::API_VERSION.into(),
        ..Default::default()
    };
    store.trust_domains.insert(
        domain.clone(),
        TrustDomainConfig {
            issuer: issuer.clone(),
            keys: vec![org.public_jwk()],
            // Your own agents: policy below is still the gate.
            allow: vec![Capability::parse("*")?],
            deny: vec![],
            max_grant_ttl_seconds: nexum_grant::DEFAULT_MAX_GRANT_TTL_SECONDS,
        },
    );

    let config = format!(
        "apiVersion: {api}\n\
         server:\n  listen: {listen}\n\
         gateway:\n  # Grants and proofs must be addressed to this audience.\n  audience: {domain}\n  clock_skew_seconds: 30\n  proof_max_age_seconds: 60\n\
         policy:\n  provider: builtin\n  file: policy.yaml\n\
         audit:\n  provider: sqlite\n  path: .nexum/audit.db\n\
         trust:\n  file: trust.yaml\n\
         state:\n  file: .nexum/state.db\n\
         # mcp:\n#   files:\n#     url: http://127.0.0.1:9000/mcp\n#     tools:\n#       refund: {{ action: refund.create, value_argument: amount }}\n",
        api = nexum_core::API_VERSION,
        listen = a.listen,
    );
    let policy = format!(
        "apiVersion: {api}\n\
         kind: Policy\n\
         id: {domain}-default\n\
         subjects:\n  - organization: \"{domain}\"\n\
         rules:\n\
         \x20 - id: example-read\n    action: example.read\n    effect: allow\n\
         \x20 - id: refund-auto\n    action: refund.create\n    effect: allow\n    conditions: {{ max_value: 500 }}\n\
         \x20 - id: refund-approval\n    action: refund.create\n    effect: approval\n    conditions: {{ value_above: 500 }}\n\
         delegation:\n  max_depth: 2\n",
        api = nexum_core::API_VERSION,
    );

    write_new(&a.dir.join("nexum.yaml"), &config, false)?;
    write_new(
        &a.dir.join("trust.yaml"),
        &yaml_serde::to_string(&store)?,
        false,
    )?;
    write_new(&a.dir.join("policy.yaml"), &policy, false)?;
    write_new(&a.dir.join(".nexum/org.key.json"), &org.to_json(), true)?;
    write_new(
        &a.dir.join("org.jwk.json"),
        &serde_json::to_string_pretty(&org.public_jwk())?,
        false,
    )?;
    State::open(&a.dir.join(".nexum/state.db"))?;

    println!("Initialized {domain} in {}", a.dir.display());
    println!("  issuer:       {issuer}");
    println!(
        "  signing key:  .nexum/org.key.json (kid {}) — keep private",
        org.kid
    );
    println!("  public key:   org.jwk.json — share with partners");
    println!("\nNext: nexum gateway start");
    Ok(())
}

// ---------- agents ----------

fn agents(config: &Path, c: AgentsCmd) -> Result<()> {
    let st = state(config)?;
    match c {
        AgentsCmd::Register(a) => {
            let id = AgentId::parse(&a.id)?;
            if a.name.is_empty()
                || !a
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                bail!("--name must be [A-Za-z0-9_-]+ (it is used as a file name)");
            }
            let jwk = match &a.public_key {
                Some(p) => read_public(p)?,
                None => {
                    let k = KeyPair::generate();
                    let path = base_dir(config)
                        .join(".nexum/keys")
                        .join(format!("{}.key.json", a.name));
                    std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
                    write_new(&path, &k.to_json(), true)?;
                    println!("generated development key {}", path.display());
                    k.public_jwk()
                }
            };
            let desc = AgentDescriptor {
                organization: id.trust_domain(),
                id,
                name: a.name,
                description: a.description,
                owner: a.owner,
                environment: a.environment,
                framework: a.framework,
                capabilities: caps(&a.capabilities)?,
                protocols: a.protocols,
                endpoint: a.endpoint,
                public_key: Some(serde_json::to_value(&jwk)?),
                status: AgentStatus::Active,
                metadata: Default::default(),
                created_at: chrono::Utc::now(),
            };
            st.register_agent(&desc)?;
            println!("registered {}", desc.id);
            record_admin(
                config,
                nexum_audit::AuditRecord {
                    agent: Some(desc.id.to_string()),
                    organization: Some(desc.organization.to_string()),
                    detail: Some(format!(
                        "name={} owner={}",
                        desc.name,
                        desc.owner.as_deref().unwrap_or("-")
                    )),
                    ..admin("agent.registered")
                },
            )?;
        }
        AgentsCmd::List => {
            println!("{:<48} {:<20} {:<8} OWNER", "ID", "NAME", "STATUS");
            for a in st.agents()? {
                println!(
                    "{:<48} {:<20} {:<8} {}",
                    a.id.as_str(),
                    a.name,
                    format!("{:?}", a.status).to_lowercase(),
                    a.owner.unwrap_or_default()
                );
            }
        }
        AgentsCmd::Inspect { id, a2a_card } => {
            let a = st.agent(&id)?.with_context(|| format!("no agent {id}"))?;
            let v = if a2a_card {
                nexum_gateway::adapters::agent_card(&a)
            } else {
                serde_json::to_value(&a)?
            };
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        AgentsCmd::Revoke { id, reason } => {
            st.revoke_agent(&id, reason.as_deref())?;
            println!("revoked agent {id}");
            record_admin(
                config,
                nexum_audit::AuditRecord {
                    agent: Some(id),
                    detail: reason,
                    ..admin("agent.revoked")
                },
            )?;
        }
    }
    Ok(())
}

// ---------- grants ----------

fn grants(config: &Path, c: GrantsCmd) -> Result<()> {
    match c {
        GrantsCmd::Issue(a) => {
            let cfg = Config::load(config)?;
            let store = nexum_gateway::load_trust(&cfg.trust.file)?;
            let domain = TrustDomain::parse(&cfg.gateway.audience)?;
            let own = store
                .domain(&domain)
                .with_context(|| format!("trust store has no entry for own domain {domain}"))?;
            let key_path = a
                .signing_key
                .unwrap_or_else(|| base_dir(config).join(".nexum/org.key.json"));
            let key = read_key(&key_path)?;
            if a.ttl <= 0 || a.ttl > own.max_grant_ttl_seconds {
                bail!(
                    "--ttl must be between 1 and {} seconds (max_grant_ttl_seconds for {domain})",
                    own.max_grant_ttl_seconds
                );
            }
            let sub = AgentId::parse(&a.sub)?;
            if sub.trust_domain() != domain {
                bail!("{sub} is not in this organization's trust domain {domain}");
            }
            let t = now();
            let claims = GrantClaims {
                jti: uuid::Uuid::new_v4().to_string(),
                iss: own.issuer.clone(),
                sub,
                act: a.actor.map(|sub| Actor { sub }),
                org: domain,
                aud: a.audiences,
                cap: caps(&a.caps)?,
                res: resources(&a.resources)?,
                dcap: caps(&a.delegatable)?,
                purpose: a.purpose,
                iat: t,
                nbf: t,
                exp: t + a.ttl,
                mdd: a.max_depth,
                prt: None,
                max_value: a.max_value,
                cnf: Confirmation {
                    jwk: read_public(&a.holder)?,
                },
            };
            if !nexum_core::is_attenuation(&claims.dcap, &claims.cap) {
                bail!("--delegatable must be a subset of --cap");
            }
            eprintln!(
                "grant {} for {} expires in {}",
                claims.jti,
                claims.sub,
                short_ttl(a.ttl)
            );
            emit(a.out.as_deref(), &nexum_grant::sign_grant(&claims, &key)?)?;
            record_admin(
                config,
                nexum_audit::AuditRecord {
                    agent: Some(claims.sub.to_string()),
                    organization: Some(claims.org.to_string()),
                    actor: claims.act.map(|a| a.sub),
                    grant_ids: vec![claims.jti],
                    chain: vec![claims.sub.to_string()],
                    value: claims.max_value,
                    purpose: claims.purpose,
                    detail: Some(format!(
                        "cap={} res={} delegatable={} max_depth={} aud={} ttl={}",
                        joined(&claims.cap),
                        joined(&claims.res),
                        joined(&claims.dcap),
                        claims.mdd,
                        joined(&claims.aud),
                        a.ttl
                    )),
                    ..admin("grant.issued")
                },
            )
        }
        GrantsCmd::Delegate(a) => {
            let chain: Vec<String> = a
                .parents
                .iter()
                .map(|p| read_token(&p.to_string_lossy()))
                .collect::<Result<_>>()?;
            let parent_tok = chain.last().context("no parent grant")?;
            let parent = nexum_grant::decode_unverified(parent_tok)?;
            let key = read_key(&a.key)?;
            if key.public_jwk().x != parent.cnf.jwk.x {
                bail!("--key does not match the parent grant's holder key");
            }
            let spec = DelegationSpec {
                sub: AgentId::parse(&a.sub)?,
                holder: read_public(&a.holder)?,
                cap: caps(&a.caps)?,
                res: if a.resources.is_empty() {
                    None
                } else {
                    Some(resources(&a.resources)?)
                },
                dcap: caps(&a.delegatable)?,
                mdd: a.max_depth,
                ttl_seconds: a.ttl,
                aud: None,
                max_value: a.max_value,
            };
            let child = nexum_grant::child_claims(&parent, parent_tok, spec, now())
                .map_err(|r| anyhow::anyhow!("{} {}", r.code(), r.describe()))?;
            eprintln!(
                "delegated {} -> {} ({})",
                parent.sub,
                child.sub,
                child
                    .cap
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            emit(a.out.as_deref(), &nexum_grant::sign_grant(&child, &key)?)?;
            record_admin(
                config,
                nexum_audit::AuditRecord {
                    agent: Some(child.sub.to_string()),
                    organization: Some(child.org.to_string()),
                    actor: child.act.map(|a| a.sub),
                    grant_ids: vec![parent.jti, child.jti],
                    chain: vec![parent.sub.to_string(), child.sub.to_string()],
                    value: child.max_value,
                    purpose: child.purpose,
                    detail: Some(format!(
                        "cap={} res={} delegatable={} max_depth={}",
                        joined(&child.cap),
                        joined(&child.res),
                        joined(&child.dcap),
                        child.mdd
                    )),
                    ..admin("grant.delegated")
                },
            )
        }
        GrantsCmd::Inspect { grant, verify } => {
            let tok = read_token(&grant)?;
            let claims = nexum_grant::decode_unverified(&tok)?;
            if verify {
                let cfg = Config::load(config)?;
                let store = nexum_gateway::load_trust(&cfg.trust.file)?;
                let st = State::open(&cfg.state.file)?;
                let v = nexum_grant::Verifier {
                    trust: &store,
                    revocations: &st,
                    audience: &cfg.gateway.audience,
                    clock: nexum_grant::Clock {
                        now: now(),
                        leeway: cfg.gateway.clock_skew_seconds,
                    },
                };
                match v.verify_chain(&[&tok]) {
                    Ok(_) => println!(
                        "VERIFIED (as a root grant for audience {})",
                        cfg.gateway.audience
                    ),
                    Err(r) => println!("INVALID {}: {}", r.code(), r.describe()),
                }
            } else {
                println!("UNVERIFIED — signature not checked");
            }
            println!("{}", serde_json::to_string_pretty(&claims)?);
            println!("expires in {}", short_ttl(claims.exp - now()));
            Ok(())
        }
        GrantsCmd::Revoke { jti } => {
            state(config)?.revoke(&RevocationTarget::Grant(jti.clone()), None)?;
            println!("revoked grant {jti}");
            record_admin(
                config,
                nexum_audit::AuditRecord {
                    grant_ids: vec![jti],
                    ..admin("grant.revoked")
                },
            )
        }
    }
}

// ---------- trust ----------

fn trust(config: &Path, c: TrustCmd) -> Result<()> {
    let cfg = Config::load(config)?;
    match c {
        TrustCmd::List => {
            let store = nexum_gateway::load_trust(&cfg.trust.file)?;
            let st = State::open(&cfg.state.file)?;
            let revoked: Vec<String> = st
                .revocations()?
                .into_iter()
                .filter_map(|r| match r.target {
                    RevocationTarget::TrustDomain(d) => Some(d),
                    _ => None,
                })
                .collect();
            for (name, d) in &store.trust_domains {
                let status = if revoked.contains(&name.to_string()) {
                    "REVOKED"
                } else {
                    "trusted"
                };
                println!("{name}  [{status}]");
                println!("  issuer: {}", d.issuer);
                println!(
                    "  keys:   {}",
                    d.keys
                        .iter()
                        .filter_map(|k| k.kid.as_deref())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                println!(
                    "  allow:  {}",
                    d.allow
                        .iter()
                        .map(|c| c.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                println!(
                    "  deny:   {}",
                    d.deny
                        .iter()
                        .map(|c| c.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            Ok(())
        }
        TrustCmd::Add {
            domain,
            issuer,
            key,
            allow,
            deny,
        } => {
            let mut store = nexum_gateway::load_trust(&cfg.trust.file)?;
            let domain = TrustDomain::parse(&domain)?;
            let mut jwk = read_public(&key)?;
            if jwk.kid.is_none() {
                jwk.kid = Some(jwk.thumbprint());
            }
            if store.trust_domains.contains_key(&domain) {
                bail!(
                    "{domain} is already in the trust store; edit {} to change it",
                    cfg.trust.file.display()
                );
            }
            store.trust_domains.insert(
                domain.clone(),
                TrustDomainConfig {
                    issuer,
                    keys: vec![jwk],
                    allow: caps(&allow)?,
                    deny: caps(&deny)?,
                    max_grant_ttl_seconds: nexum_grant::DEFAULT_MAX_GRANT_TTL_SECONDS,
                },
            );
            store.validate().map_err(anyhow::Error::msg)?;
            write_atomic(&cfg.trust.file, &yaml_serde::to_string(&store)?)?;
            println!("now trusting {domain}; restart the gateway to load it");
            record_admin(
                config,
                nexum_audit::AuditRecord {
                    organization: Some(domain.to_string()),
                    detail: Some(format!(
                        "issuer={} allow={} deny={}",
                        store.trust_domains[&domain].issuer,
                        joined(&allow),
                        joined(&deny)
                    )),
                    ..admin("trust.established")
                },
            )
        }
        TrustCmd::Revoke { domain, reason } => {
            State::open(&cfg.state.file)?.revoke(
                &RevocationTarget::TrustDomain(domain.clone()),
                reason.as_deref(),
            )?;
            println!("revoked trust in {domain} (effective immediately)");
            record_admin(
                config,
                nexum_audit::AuditRecord {
                    organization: Some(domain),
                    detail: reason,
                    ..admin("trust.revoked")
                },
            )
        }
        TrustCmd::RevokeKey { kid, reason } => {
            State::open(&cfg.state.file)?
                .revoke(&RevocationTarget::Key(kid.clone()), reason.as_deref())?;
            println!("revoked key {kid} (effective immediately)");
            record_admin(
                config,
                nexum_audit::AuditRecord {
                    detail: Some(format!(
                        "kid={kid} reason={}",
                        reason.as_deref().unwrap_or("-")
                    )),
                    ..admin("key.revoked")
                },
            )
        }
    }
}

// ---------- policies ----------

fn policies(config: &Path, c: PoliciesCmd) -> Result<()> {
    match c {
        PoliciesCmd::Validate { file } => {
            let path = match file {
                Some(f) => f,
                None => Config::load(config)?.policy.builtin_file()?.to_path_buf(),
            };
            let set = nexum_gateway::load_policy(&path)?;
            for p in &set.policies {
                println!("ok  {}  ({} rules)", p.id, p.rules.len());
            }
            Ok(())
        }
        PoliciesCmd::Simulate {
            proposed,
            audits,
            json,
            fail_on_widen,
        } => {
            let current_path = Config::load(config)?.policy.builtin_file()?.to_path_buf();
            let current = nexum_gateway::load_policy(&current_path)?;
            let new = nexum_gateway::load_policy(&proposed)?;
            let events: Vec<_> = verified_audit_events(config, audits)?
                .into_iter()
                .map(|(_, e)| e)
                .collect();
            let rep = nexum_gateway::simulate::simulate(&events, &current, &new);
            let widened = rep.widened();
            if json {
                println!("{}", serde_json::to_string_pretty(&rep)?);
            } else {
                println!(
                    "POLICY IMPACT  {} vs {}\n",
                    proposed.display(),
                    current_path.display()
                );
                println!("  Decisions replayed:        {}", rep.decisions);
                println!(
                    "  Decided before policy:     {}  (identity, proof, authority or trust; unaffected)",
                    rep.decided_before_policy
                );
                println!("  Re-evaluated:              {}", rep.reevaluated);
                println!("    unchanged                {}", rep.unchanged);
                for (t, n) in &rep.transitions {
                    println!("    {t:<24} {n}");
                }
                if rep.insufficient_data > 0 {
                    println!(
                        "  Not re-evaluated:          {}  (recorded before chain/value were audited)",
                        rep.insufficient_data
                    );
                }
                println!(
                    "\n  Affected agents: {}   organizations: {}",
                    rep.affected_agents.len(),
                    rep.affected_organizations.len()
                );
                if widened > 0 {
                    println!(
                        "\nHIGH-RISK CHANGE: {widened} recorded decision(s) would become more permissive"
                    );
                }
                for c in rep.changes.iter().take(20) {
                    println!(
                        "  {} {:<40} {} {}{}  {} → {}  ({} → {})",
                        if c.widens { "▲" } else { "▼" },
                        c.agent,
                        c.action,
                        c.resource,
                        c.value.map(|v| format!(" value {v}")).unwrap_or_default(),
                        c.before,
                        c.after,
                        c.before_rule.as_deref().unwrap_or("default deny"),
                        c.after_rule.as_deref().unwrap_or("default deny"),
                    );
                }
                if rep.changes.len() > 20 {
                    println!("  … {} more (use --json)", rep.changes.len() - 20);
                }
            }
            if fail_on_widen && widened > 0 {
                bail!("{widened} decision(s) would become more permissive");
            }
            Ok(())
        }
        PoliciesCmd::Test(a) => {
            let cfg = Config::load(config)?;
            let set = nexum_gateway::load_policy(cfg.policy.builtin_file()?)?;
            let store = nexum_gateway::load_trust(&cfg.trust.file)?;
            let subject = AgentId::parse(&a.agent)?;
            let org = subject.trust_domain();
            let action = Capability::parse(&a.action)?;
            if !action.is_exact() {
                bail!("--action must be a concrete action, not a pattern");
            }
            let link = DelegationLink {
                grant_id: "simulated".into(),
                issuer: "simulated".into(),
                subject: subject.clone(),
                capabilities: vec![action.clone()],
                expires_at: chrono::Utc::now(),
            };
            let req = AuthorizationRequest {
                request_id: uuid::Uuid::now_v7(),
                timestamp: chrono::Utc::now(),
                subject,
                actor: None,
                organization: org.clone(),
                action: action.clone(),
                resource: ResourcePattern::parse(&a.resource)?,
                purpose: a.purpose,
                delegation_chain: vec![link; a.depth + 1],
                authority: GrantedAuthority {
                    capabilities: vec![action.clone()],
                    resources: vec![],
                    max_value: None,
                    expires_at: chrono::Utc::now(),
                },
                context: RequestContext {
                    value: a.value,
                    protocol: "cli".into(),
                    ..Default::default()
                },
            };
            let trusted = store.domain(&org).is_some();
            let accepts = store.accepts(&org, &action);
            let p = set.evaluate(&req);
            let (outcome, reason) = if !trusted {
                (Outcome::Deny, ReasonCode::UnknownIssuer)
            } else if !accepts {
                (Outcome::Deny, ReasonCode::TrustDomainDenies)
            } else {
                (p.outcome, p.reason)
            };
            println!("{outcome}\n");
            println!("Reason:\n  {} {}", reason.code(), reason.describe());
            println!(
                "Matched:\n  {} / {}",
                p.policy_id.as_deref().unwrap_or("-"),
                p.rule_id.as_deref().unwrap_or("-")
            );
            println!(
                "Trust:\n  {org} -> {}: {}",
                cfg.gateway.audience,
                if !trusted {
                    "not trusted"
                } else if accepts {
                    "accepts this capability"
                } else {
                    "does not accept this capability"
                }
            );
            println!(
                "Delegation:\n  simulated depth {} (grant signatures not evaluated)",
                a.depth
            );
            if outcome == Outcome::Deny {
                std::process::exit(2);
            }
            Ok(())
        }
    }
}

// ---------- approvals ----------

fn approvals(config: &Path, c: ApprovalsCmd) -> Result<()> {
    let st = state(config)?;
    let approve = matches!(c, ApprovalsCmd::Approve { .. });
    match c {
        ApprovalsCmd::List { all } => {
            let t = chrono::Utc::now();
            for a in st.approvals()? {
                if !all && (a.status != ApprovalStatus::Pending || a.expires_at <= t) {
                    continue;
                }
                println!(
                    "{}  {:<9}  {}  {}  {}  value={}  expires in {}",
                    a.id,
                    format!("{:?}", a.status).to_lowercase(),
                    a.requested_by,
                    a.action,
                    a.resource,
                    a.value.map(|v| v.to_string()).unwrap_or("-".into()),
                    short_ttl((a.expires_at - t).num_seconds()),
                );
                if let Some(actor) = &a.actor {
                    println!(
                        "    on behalf of {actor}; policy {}",
                        a.policy.as_deref().unwrap_or("-")
                    );
                }
            }
        }
        ApprovalsCmd::Approve { id, by } | ApprovalsCmd::Reject { id, by } => {
            st.decide_approval(&id, approve, &by)?;
            if approve {
                println!(
                    "approved {id} (single use; the agent must retry with Nexum-Approval: {id})"
                );
            } else {
                println!("rejected {id}");
            }
            let a = st.approvals()?.into_iter().find(|a| a.id.to_string() == id);
            record_admin(
                config,
                nexum_audit::AuditRecord {
                    approval_id: a.as_ref().map(|a| a.id),
                    request_id: a.as_ref().map_or_else(uuid::Uuid::now_v7, |a| a.request_id),
                    agent: a.as_ref().map(|a| a.requested_by.to_string()),
                    actor: a.as_ref().and_then(|a| a.actor.clone()),
                    action: a.as_ref().map(|a| a.action.to_string()),
                    resource: a.as_ref().map(|a| a.resource.to_string()),
                    value: a.as_ref().and_then(|a| a.value),
                    policy: a.and_then(|a| a.policy),
                    operator: Some(by),
                    ..admin(if approve {
                        "approval.approved"
                    } else {
                        "approval.rejected"
                    })
                },
            )?;
        }
    }
    Ok(())
}

// ---------- audit ----------

fn audit(config: &Path, c: AuditCmd) -> Result<()> {
    let cfg = Config::load(config)?;
    let log = nexum_audit::open(&cfg.audit.provider, &cfg.audit.path)?;
    let print = |e: &nexum_audit::AuditEvent| {
        let r = &e.record;
        println!(
            "#{:<5} {}  {:<16}  {:<44}  {:<24}  {}",
            e.seq,
            r.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
            r.decision
                .map_or_else(|| r.event_type.clone(), |d| d.to_string()),
            r.agent
                .as_deref()
                .or(r.organization.as_deref())
                .unwrap_or("-"),
            r.action.as_deref().or(r.detail.as_deref()).unwrap_or("-"),
            r.reason_codes
                .iter()
                .map(|c| c.code())
                .collect::<Vec<_>>()
                .join(","),
        );
    };
    match c {
        AuditCmd::Tail { n } => {
            let all = log.read_all()?;
            all[all.len().saturating_sub(n)..].iter().for_each(print);
        }
        AuditCmd::Search {
            agent,
            action,
            decision,
        } => {
            // ponytail: linear scan of the whole log; index or ship to a SIEM at scale.
            for e in log.read_all()? {
                let r = &e.record;
                let ok = agent.as_ref().is_none_or(|a| r.agent.as_deref() == Some(a))
                    && action
                        .as_ref()
                        .is_none_or(|a| r.action.as_deref() == Some(a))
                    && decision.as_ref().is_none_or(|d| {
                        r.decision
                            .is_some_and(|x| x.to_string().eq_ignore_ascii_case(d))
                    });
                if ok {
                    print(&e);
                }
            }
        }
        AuditCmd::Verify => {
            let n = log.verify()?;
            println!("audit chain intact: {n} events");
        }
    }
    Ok(())
}

// ---------- discover ----------

async fn discover_a2a(config: &Path, urls: &[String], json: bool) -> Result<()> {
    let registry = match Config::load(config) {
        Ok(cfg) => State::open(&cfg.state.file)?.agents()?,
        Err(_) => vec![],
    };
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let mut found = Vec::new();
    for url in urls {
        let card_url = if url.ends_with(".json") {
            url.clone()
        } else {
            format!("{}/.well-known/agent-card.json", url.trim_end_matches('/'))
        };
        let fetched = async {
            let resp = http.get(&card_url).send().await?.error_for_status()?;
            let body = resp.bytes().await?;
            anyhow::ensure!(body.len() <= 1 << 20, "agent card larger than 1 MiB");
            Ok::<Value, anyhow::Error>(serde_json::from_slice(&body)?)
        }
        .await;
        match fetched {
            Ok(card) => found.push(nexum_gateway::discover::summarize(
                &card_url, &card, &registry,
            )),
            Err(e) => eprintln!("{card_url}: {e:#}"),
        }
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&found)?);
        return Ok(());
    }
    let managed = found.iter().filter(|d| d.managed_as.is_some()).count();
    println!(
        "{} agents discovered: {managed} managed, {} unmanaged\n",
        found.len(),
        found.len() - managed
    );
    for d in &found {
        println!(
            "{}  ({})",
            d.name,
            d.organization.as_deref().unwrap_or("unknown provider")
        );
        println!("  card:      {}", d.source);
        println!("  endpoints: {}", d.endpoints.join(", "));
        println!("  skills:    {}", d.skills.join(", "));
        println!(
            "  auth:      {}",
            if d.auth_schemes.is_empty() {
                "-".into()
            } else {
                d.auth_schemes.join(", ")
            }
        );
        println!("  managed:   {}", d.managed_as.as_deref().unwrap_or("no"));
        for f in &d.findings {
            println!("  ! {f}");
        }
        println!();
    }
    Ok(())
}

// ---------- risk ----------

fn risk_scan(config: &Path, days: i64, json: bool) -> Result<()> {
    use nexum_gateway::risk::{Severity, scan};
    let cfg = Config::load(config)?;
    let trust = nexum_gateway::load_trust(&cfg.trust.file)?;
    let policy = match cfg.policy.builtin_file() {
        Ok(f) => Some(nexum_gateway::load_policy(f)?),
        Err(_) => None,
    };
    let agents = State::open(&cfg.state.file)?.agents()?;
    let events: Vec<_> = verified_audit_events(config, vec![])?
        .into_iter()
        .map(|(_, e)| e)
        .collect();
    let own = TrustDomain::parse(&cfg.gateway.audience)?;
    let since = chrono::Utc::now() - chrono::Duration::days(days);
    let findings = scan(&own, &trust, policy.as_ref(), &agents, &events, since);
    let count = |s| findings.iter().filter(|f| f.severity == s).count();
    let high = count(Severity::High);
    if json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    } else {
        println!(
            "NEXUM RISK SCAN  {}  (audit: last {days} days)\n\nHIGH {high}   MEDIUM {}   LOW {}\n",
            cfg.gateway.audience,
            count(Severity::Medium),
            count(Severity::Low)
        );
        if policy.is_none() {
            println!("  (external policy engine: policy findings skipped)\n");
        }
        for f in &findings {
            println!(
                "{:<7} {:<30} {}",
                format!("{:?}", f.severity).to_uppercase(),
                f.id,
                f.subject
            );
            println!("        {}", f.evidence);
            println!("        fix: {}\n", f.fix);
        }
    }
    if high > 0 {
        bail!("{high} high-risk finding(s)");
    }
    Ok(())
}

// ---------- trace ----------

/// Where reason codes are documented.
const ERRORS_URL: &str = "https://swaroski.github.io/nexum/errors";

fn error_url(code: &str) -> String {
    format!("{ERRORS_URL}/{}/", code.to_ascii_lowercase())
}

/// Per-stage result of one decision, derived from its reason code: the
/// pipeline is ordered, so stages before the deciding one passed and stages
/// after a denial never ran.
fn stage_checks(r: &nexum_audit::AuditRecord) -> Vec<(nexum_core::Stage, &'static str)> {
    use nexum_core::Stage;
    let Some(code) = r.reason_codes.first().copied() else {
        return vec![];
    };
    let at = code.stage();
    let outcome = r.decision.unwrap_or(Outcome::Deny);
    Stage::ALL
        .into_iter()
        .map(|s| {
            let status = if s == Stage::Audit {
                "RECORDED"
            } else if s < at {
                "PASS"
            } else if s == at {
                match outcome {
                    Outcome::RequireApproval => "APPROVAL REQUIRED",
                    Outcome::Allow => "PASS",
                    Outcome::Deny => "FAIL",
                }
            } else {
                match (outcome, s) {
                    (Outcome::Allow, Stage::Approval) => "NOT REQUIRED",
                    (Outcome::RequireApproval, Stage::Approval) => "PENDING",
                    _ => "NOT EVALUATED",
                }
            };
            (s, status)
        })
        .collect()
}

/// Open audit logs (`--audit` paths, or this gateway's) and verify each hash
/// chain before anything is read from it.
fn verified_audit_events(
    config: &Path,
    audits: Vec<PathBuf>,
) -> Result<Vec<(String, nexum_audit::AuditEvent)>> {
    let audits = if audits.is_empty() {
        let cfg = Config::load(config)?;
        vec![(cfg.audit.provider, cfg.audit.path)]
    } else {
        audits
            .into_iter()
            .map(|p| {
                let provider = if p.extension().is_some_and(|e| e == "jsonl") {
                    "jsonl"
                } else {
                    "sqlite"
                };
                (provider.to_owned(), p)
            })
            .collect()
    };
    let mut out = Vec::new();
    for (provider, path) in &audits {
        if !path.exists() {
            bail!("audit log {} does not exist", path.display());
        }
        let log = nexum_audit::open(provider, path)?;
        log.verify()
            .with_context(|| format!("audit log {} failed verification", path.display()))?;
        let name = path.display().to_string();
        out.extend(log.read_all()?.into_iter().map(|e| (name.clone(), e)));
    }
    Ok(out)
}

/// One hop of an authority trace (schema: docs "Tracing and observability").
fn hop_json(log: &str, e: &nexum_audit::AuditEvent) -> Value {
    let r = &e.record;
    let code = r.reason_codes.first().copied();
    serde_json::json!({
        "audit_log": log,
        "seq": e.seq,
        "event_hash": e.event_hash,
        "timestamp": r.timestamp,
        "request_id": r.request_id,
        "decision_id": r.decision_id,
        "trace_id": r.trace_id,
        "protocol": r.protocol,
        "actor": r.actor,
        "organization": r.organization,
        "agent": r.agent,
        "delegation_chain": r.chain,
        "grant_ids": r.grant_ids,
        "action": r.action,
        "resource": r.resource,
        "value": r.value,
        "purpose": r.purpose,
        "checks": stage_checks(r)
            .iter()
            .map(|(s, st)| serde_json::json!({"stage": s, "label": s.label(), "status": st}))
            .collect::<Vec<_>>(),
        "decision": r.decision,
        "reason_code": code.map(ReasonCode::code),
        "reason": code.map(ReasonCode::describe),
        "security_event": code.and_then(ReasonCode::security_event),
        "policy": r.policy,
        "approval_id": r.approval_id,
    })
}

fn trace_inspect(config: &Path, id: &str, audits: Vec<PathBuf>, json: bool) -> Result<()> {
    let mut hops: Vec<_> = verified_audit_events(config, audits)?
        .into_iter()
        .filter(|(_, e)| {
            let r = &e.record;
            r.event_type == "authorization.decision"
                && (r.request_id.to_string() == id
                    || r.decision_id.is_some_and(|d| d.to_string() == id)
                    || r.trace_id.as_deref() == Some(id))
        })
        .collect();
    if hops.is_empty() {
        bail!("no decision with request, decision or trace id {id}");
    }
    hops.sort_by_key(|(_, e)| e.record.timestamp);

    if json {
        let hops: Vec<Value> = hops.iter().map(|(log, e)| hop_json(log, e)).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "id": id, "hops": hops }))?
        );
        return Ok(());
    }

    if hops.len() > 1 {
        println!("Authority trace {id}: {} network hops\n", hops.len());
    }
    for (i, (log, e)) in hops.iter().enumerate() {
        let r = &e.record;
        let code = r.reason_codes.first().copied();
        if hops.len() > 1 {
            println!("── hop {} · {log} ──", i + 1);
        }
        println!(
            "{} {}\n",
            r.decision.map(|d| d.to_string()).unwrap_or_default(),
            code.map(ReasonCode::code).unwrap_or("")
        );
        println!("  Request:    {}", r.request_id);
        if let Some(t) = &r.trace_id {
            println!("  Trace:      {t}  (caller-asserted)");
        }
        println!(
            "  When:       {}  via {}",
            r.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
            r.protocol.as_deref().unwrap_or("-")
        );
        if let Some(a) = &r.actor {
            println!("  On behalf:  {a}");
        }
        // Logical delegation, which may differ from the network path above.
        match r.chain.split_first() {
            Some((root, rest)) => {
                println!(
                    "  Authority:  {root}  (root grant from {})",
                    r.organization.as_deref().unwrap_or("-")
                );
                for sub in rest {
                    println!("                ↓ delegated\n              {sub}");
                }
            }
            None => println!("  Agent:      {}", r.agent.as_deref().unwrap_or("-")),
        }
        let value = r.value.map(|v| format!("  value {v}")).unwrap_or_default();
        println!(
            "  Requested:  {}  {}{value}",
            r.action.as_deref().unwrap_or("-"),
            r.resource.as_deref().unwrap_or("-")
        );
        if let Some(p) = &r.purpose {
            println!("  Purpose:    {p}");
        }
        println!();
        for (stage, status) in stage_checks(r) {
            println!("  {:<30}{status}", stage.label());
        }
        println!();
        if let Some(c) = code {
            println!("  Reason:     {}", c.describe());
            if let Some(ev) = c.security_event() {
                println!("  Security:   {ev}");
            }
        }
        if let Some(p) = &r.policy {
            println!("  Policy:     {p}");
        }
        if let Some(a) = r.approval_id {
            println!("  Approval:   {a}");
        }
        println!("  Audit:      event #{} in {log} (chain verified)", e.seq);
        if let Some(c) = code.filter(|_| r.decision != Some(Outcome::Allow)) {
            println!("  Learn more: {}", error_url(c.code()));
        }
        println!();
    }
    Ok(())
}

// ---------- call ----------

async fn call(a: CallArgs) -> Result<()> {
    let chain: Vec<String> = a
        .grants
        .iter()
        .map(|p| read_token(&p.to_string_lossy()))
        .collect::<Result<_>>()?;
    let leaf_tok = chain.last().context("no grants")?;
    let leaf = nexum_grant::decode_unverified(leaf_tok)?;
    let key = read_key(&a.key)?;
    let audience = match a.audience {
        Some(x) => x,
        None if leaf.aud.len() == 1 => leaf.aud[0].clone(),
        None => bail!("leaf grant has several audiences; pass --audience"),
    };
    let mut body = serde_json::json!({"action": a.action, "resource": a.resource});
    if let Some(v) = a.value {
        body["value"] = v.into();
    }
    let body = serde_json::to_vec(&body)?;
    let proof = nexum_grant::create_proof(&key, leaf_tok, &audience, &body, now())?;
    let mut req = reqwest::Client::new()
        .post(format!("{}/v1/authorize", a.gateway.trim_end_matches('/')))
        .header("content-type", "application/json")
        .header("nexum-grant", chain.join(","))
        .header("nexum-proof", proof)
        .body(body);
    if let Some(id) = &a.approval {
        req = req.header("nexum-approval", id);
    }
    let resp: Value = req.send().await.context("calling gateway")?.json().await?;
    let d = &resp["decision"];
    let outcome = d["outcome"].as_str().unwrap_or("DENY");
    let label = match outcome {
        "ALLOW" => "ALLOWED",
        "REQUIRE_APPROVAL" => "APPROVAL REQUIRED",
        _ => "DENIED",
    };
    println!("{label} {}\n", resp["code"].as_str().unwrap_or(""));
    println!("  Agent:      {}", leaf.sub);
    if let Some(act) = &leaf.act {
        println!("  On behalf:  {}", act.sub);
    }
    println!("  Requested:  {}  {}", a.action, a.resource);
    if let Some(v) = a.value {
        println!("  Value:      {v}");
    }
    println!("  Reason:     {}", resp["message"].as_str().unwrap_or(""));
    println!(
        "  Chain:      depth {}, capabilities: {}",
        chain.len() - 1,
        leaf.cap
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if let Some(p) = d["matched_policy"].as_str() {
        println!(
            "  Policy:     {p} / {}",
            d["matched_rule"].as_str().unwrap_or("-")
        );
    }
    if let Some(id) = d["obligations"][0]["approval_id"].as_str() {
        println!(
            "  Approval:   {id}\n\n  Approve with: nexum approvals approve {id}\n  Then retry with: --approval {id}"
        );
    }
    println!("  Decision:   {}", d["decision_id"].as_str().unwrap_or("-"));
    if outcome != "ALLOW" {
        if let Some(code) = resp["code"].as_str() {
            println!("  Learn more: {}", error_url(code));
        }
        std::process::exit(if outcome == "DENY" { 2 } else { 3 });
    }
    Ok(())
}

// ---------- doctor ----------

fn doctor(config: &Path) -> Result<()> {
    let mut failed = false;
    let mut check = |name: &str, r: Result<String>| match r {
        Ok(msg) => println!("ok    {name}: {msg}"),
        Err(e) => {
            failed = true;
            println!("FAIL  {name}: {e:#}");
        }
    };
    let cfg = match Config::load(config) {
        Ok(c) => {
            check("config", Ok(config.display().to_string()));
            c
        }
        Err(e) => {
            check("config", Err(e));
            bail!("cannot continue without a valid config");
        }
    };
    check(
        "trust",
        nexum_gateway::load_trust(&cfg.trust.file)
            .map(|t| format!("{} trust domains", t.trust_domains.len())),
    );
    check(
        "policy",
        match cfg.policy.url.as_deref() {
            Some(url) => Ok(format!(
                "OPA at {url} (not contacted; run `nexum eval run`)"
            )),
            None => cfg
                .policy
                .builtin_file()
                .and_then(nexum_gateway::load_policy)
                .map(|p| format!("{} policies", p.policies.len())),
        },
    );
    check(
        "state",
        State::open(&cfg.state.file)
            .and_then(|s| Ok(format!("{} revocations", s.revocations()?.len()))),
    );
    check(
        "audit",
        nexum_audit::open(&cfg.audit.provider, &cfg.audit.path)
            .and_then(|l| l.verify())
            .map(|n| format!("hash chain intact ({n} events)"))
            .map_err(Into::into),
    );
    let key = base_dir(config).join(".nexum/org.key.json");
    if key.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key)?.permissions().mode();
            check(
                "org key",
                if mode & 0o077 == 0 {
                    Ok("owner-only permissions".into())
                } else {
                    Err(anyhow::anyhow!(
                        "{} is readable by group/others",
                        key.display()
                    ))
                },
            );
        }
    }
    if failed {
        std::process::exit(1);
    }
    Ok(())
}
