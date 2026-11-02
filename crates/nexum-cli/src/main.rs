//! `nexum` — command-line interface for the Nexum gateway and local state.

#![forbid(unsafe_code)]

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
    /// Call a gateway's decision API as an agent (signs a fresh proof).
    Call(CallArgs),
    /// Check configuration, keys, trust, policy, state and audit integrity.
    Doctor,
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
}

#[derive(Subcommand)]
enum PoliciesCmd {
    Validate {
        file: Option<PathBuf>,
    },
    /// Evaluate trust + policy for a hypothetical request.
    Test(PolicyTestArgs),
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
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .init();
            nexum_gateway::serve(Config::load(&cli.config)?).await
        }
        Cmd::Agents(c) => agents(&cli.config, c),
        Cmd::Grants(c) => grants(&cli.config, c),
        Cmd::Trust(c) => trust(&cli.config, c),
        Cmd::Policies(c) => policies(&cli.config, c),
        Cmd::Approvals(c) => approvals(&cli.config, c),
        Cmd::Audit(c) => audit(&cli.config, c),
        Cmd::Call(a) => call(a).await,
        Cmd::Doctor => doctor(&cli.config),
    }
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
            emit(a.out.as_deref(), &nexum_grant::sign_grant(&claims, &key)?)
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
            emit(a.out.as_deref(), &nexum_grant::sign_grant(&child, &key)?)
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
            Ok(())
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
            std::fs::write(&cfg.trust.file, yaml_serde::to_string(&store)?)?;
            println!("now trusting {domain}; restart the gateway to load it");
            Ok(())
        }
        TrustCmd::Revoke { domain, reason } => {
            State::open(&cfg.state.file)?.revoke(
                &RevocationTarget::TrustDomain(domain.clone()),
                reason.as_deref(),
            )?;
            println!("revoked trust in {domain} (effective immediately)");
            Ok(())
        }
    }
}

// ---------- policies ----------

fn policies(config: &Path, c: PoliciesCmd) -> Result<()> {
    match c {
        PoliciesCmd::Validate { file } => {
            let path = match file {
                Some(f) => f,
                None => Config::load(config)?.policy.file,
            };
            let set = nexum_gateway::load_policy(&path)?;
            for p in &set.policies {
                println!("ok  {}  ({} rules)", p.id, p.rules.len());
            }
            Ok(())
        }
        PoliciesCmd::Test(a) => {
            let cfg = Config::load(config)?;
            let set = nexum_gateway::load_policy(&cfg.policy.file)?;
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
        ApprovalsCmd::Approve { id, by } => {
            st.decide_approval(&id, true, &by)?;
            println!("approved {id} (single use; the agent must retry with Nexum-Approval: {id})");
        }
        ApprovalsCmd::Reject { id, by } => {
            st.decide_approval(&id, false, &by)?;
            println!("rejected {id}");
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
            r.decision.map(|d| d.to_string()).unwrap_or_default(),
            r.agent.as_deref().unwrap_or("-"),
            r.action.as_deref().unwrap_or("-"),
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
        nexum_gateway::load_policy(&cfg.policy.file)
            .map(|p| format!("{} policies", p.policies.len())),
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
