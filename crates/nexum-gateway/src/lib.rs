//! The Nexum enforcement gateway.
//!
//! Runs next to the agents and resources it protects. It needs no control
//! plane: trust, policy, revocations and approvals are local files the
//! customer owns.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod authorizer;
pub mod config;
pub mod discover;
pub mod eval;
pub mod opa;
pub mod risk;
pub mod server;
pub mod simulate;
pub mod store;

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use nexum_grant::{MemoryReplayGuard, TrustStore};
use nexum_policy::{BuiltinPdp, PolicySet};

use crate::adapters::{A2aAdapter, McpAdapter};
use crate::authorizer::{Authorizer, Metrics};
use crate::config::Config;
use crate::server::AppState;
use crate::store::State;

pub fn load_trust(path: &Path) -> anyhow::Result<TrustStore> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading trust store {}", path.display()))?;
    let trust: TrustStore = yaml_serde::from_str(&text)
        .with_context(|| format!("parsing trust store {}", path.display()))?;
    trust
        .validate()
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    Ok(trust)
}

pub fn load_policy(path: &Path) -> anyhow::Result<PolicySet> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading policy {}", path.display()))?;
    PolicySet::from_yaml(&text).with_context(|| format!("loading policy {}", path.display()))
}

pub fn build(cfg: &Config) -> anyhow::Result<Arc<AppState>> {
    for name in cfg.mcp.keys().chain(cfg.a2a.keys()) {
        nexum_core::Capability::parse(name)
            .map_err(|_| anyhow::anyhow!("upstream name {name:?} must be [A-Za-z0-9_-]+"))?;
    }
    let authorizer = Authorizer {
        settings: cfg.gateway.clone(),
        trust: load_trust(&cfg.trust.file)?,
        state: Arc::new(State::open(&cfg.state.file)?),
        pdp: match cfg.policy.url.clone() {
            Some(url) => Arc::new(opa::OpaPdp::new(
                url,
                std::time::Duration::from_millis(cfg.policy.timeout_ms.unwrap_or(500)),
            )?),
            None => Arc::new(BuiltinPdp {
                set: load_policy(cfg.policy.builtin_file()?)?,
            }),
        },
        audit: Arc::from(
            nexum_audit::open(&cfg.audit.provider, &cfg.audit.path)
                .with_context(|| format!("opening audit log {}", cfg.audit.path.display()))?,
        ),
        replay: MemoryReplayGuard::default(),
        metrics: Metrics::default(),
    };
    let http = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .read_timeout(std::time::Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    Ok(Arc::new(AppState {
        authorizer,
        mcp: McpAdapter {
            servers: cfg.mcp.clone(),
        },
        a2a: A2aAdapter {
            agents: cfg.a2a.clone(),
        },
        http,
    }))
}

pub async fn serve(cfg: Config) -> anyhow::Result<()> {
    let state = build(&cfg)?;
    let listener = tokio::net::TcpListener::bind(&cfg.server.listen)
        .await
        .with_context(|| format!("binding {}", cfg.server.listen))?;
    let addr = listener.local_addr()?;
    if !addr.ip().is_loopback() {
        tracing::warn!(
            %addr,
            "listening on a non-loopback address without TLS; terminate TLS in front of the gateway"
        );
    }
    tracing::info!(%addr, audience = %cfg.gateway.audience, "nexum gateway listening");
    axum::serve(listener, server::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Ctrl-C, or SIGTERM from `docker stop` / Kubernetes. As a container's
/// PID 1 the gateway would otherwise ignore SIGTERM and be killed mid-request.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "cannot listen for SIGTERM");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
