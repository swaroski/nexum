//! `nexum console`: a local, single-operator UI over this gateway's files.
//!
//! Not a control plane. It reads the audit log (hash chain verified on every
//! read), registry, approvals, trust store and policy, and can approve,
//! reject or revoke through the same state functions and audit events as the
//! CLI. It never holds the organization signing key and cannot issue grants.
//!
//! Exposure: loopback only; every API call needs the per-session bearer token
//! (custom header, so cross-site requests can't send it and no CORS is
//! enabled); the Host header must name the loopback listener, which defeats
//! DNS rebinding.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::extract::{Path as UrlPath, Query, State as AxState};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use nexum_core::{AgentId, AgentStatus, ApprovalStatus, RevocationTarget};
use nexum_gateway::config::Config;
use nexum_gateway::store::State;
use serde::Deserialize;
use serde_json::{Value, json};

const PAGE: &str = include_str!("console.html");

struct Console {
    config: PathBuf,
    token: String,
    addr: SocketAddr,
    operator: String,
}

type Shared = Arc<Console>;

pub async fn serve(config: PathBuf, listen: SocketAddr, operator: String) -> Result<()> {
    if !listen.ip().is_loopback() {
        bail!("the console only listens on loopback addresses (got {listen})");
    }
    Config::load(&config)?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    let addr = listener.local_addr()?;
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    println!("Nexum console for {}", config.display());
    println!("  http://{addr}/#token={token}");
    println!("  acting as {operator} (approvals and revocations are audited under this name)");
    let st = Arc::new(Console {
        config,
        token,
        addr,
        operator,
    });
    let api = Router::new()
        .route("/api/overview", get(overview))
        .route("/api/events", get(events))
        .route("/api/trace/{id}", get(trace))
        .route("/api/agents", get(agents))
        .route("/api/trust", get(trust))
        .route("/api/policy", get(policy))
        .route("/api/approvals", get(approvals))
        .route("/api/approvals/{id}/{verdict}", post(decide))
        .route("/api/revoke", post(revoke))
        .route_layer(axum::middleware::from_fn_with_state(st.clone(), guard))
        .with_state(st.clone());
    let app = Router::new()
        .route("/", get(|| async { Html(PAGE) }))
        .merge(api)
        .layer(axum::middleware::from_fn_with_state(st, host_check));
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

async fn host_check(
    AxState(st): AxState<Shared>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok());
    let port = st.addr.port();
    let ok = host.is_some_and(|h| {
        h == format!("127.0.0.1:{port}")
            || h == format!("localhost:{port}")
            || h == format!("[::1]:{port}")
    });
    if !ok {
        return (StatusCode::FORBIDDEN, "unexpected Host").into_response();
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::X_FRAME_OPTIONS, "DENY".parse().expect("static"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'"
            .parse()
            .expect("static"),
    );
    h.insert(
        header::REFERRER_POLICY,
        "no-referrer".parse().expect("static"),
    );
    resp
}

async fn guard(
    AxState(st): AxState<Shared>,
    headers: HeaderMap,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    // Constant-time comparison: the token is the only credential.
    let ok = presented.is_some_and(|p| {
        p.len() == st.token.len()
            && p.bytes()
                .zip(st.token.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    });
    if !ok {
        return (StatusCode::UNAUTHORIZED, "missing or wrong console token").into_response();
    }
    next.run(req).await
}

fn fail(e: impl std::fmt::Display) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": e.to_string() })),
    )
        .into_response()
}

fn cfg(st: &Console) -> Result<Config> {
    Config::load(&st.config)
}

fn state(st: &Console) -> Result<State> {
    State::open(&cfg(st)?.state.file)
}

fn verified_events(st: &Console) -> Result<Vec<nexum_audit::AuditEvent>> {
    // ponytail: re-reads and re-verifies the whole log per request; fine for a
    // local console, index if logs reach millions of events.
    Ok(super::verified_audit_events(&st.config, vec![])?
        .into_iter()
        .map(|(_, e)| e)
        .collect())
}

async fn overview(AxState(st): AxState<Shared>) -> Response {
    let run = || -> Result<Value> {
        let events = verified_events(&st)?;
        let since = chrono::Utc::now() - chrono::Duration::hours(24);
        let mut counts = std::collections::BTreeMap::<String, u64>::new();
        let mut security = std::collections::BTreeMap::<String, u64>::new();
        for e in events.iter().filter(|e| e.record.timestamp >= since) {
            let r = &e.record;
            let key = match r.decision {
                Some(d) if r.event_type == "authorization.decision" => d.to_string(),
                _ => r.event_type.clone(),
            };
            *counts.entry(key).or_default() += 1;
            if let Some(ev) = r.reason_codes.first().and_then(|c| c.security_event()) {
                *security.entry(ev.to_owned()).or_default() += 1;
            }
        }
        let s = state(&st)?;
        let c = cfg(&st)?;
        let agents = s.agents()?;
        let now = chrono::Utc::now();
        let pending = s
            .approvals()?
            .iter()
            .filter(|a| a.status == ApprovalStatus::Pending && a.expires_at > now)
            .count();
        let trust = nexum_gateway::load_trust(&c.trust.file)?;
        Ok(json!({
            "gateway": c.gateway.audience,
            "audit_events": events.len(),
            "audit_verified": true,
            "last_24h": counts,
            "security_events_24h": security,
            "agents": agents.len(),
            "agents_revoked": agents.iter().filter(|a| a.status == AgentStatus::Revoked).count(),
            "trust_domains": trust.trust_domains.len(),
            "revocations": s.revocations()?.len(),
            "pending_approvals": pending,
            "policy_provider": c.policy.provider,
        }))
    };
    run().map_or_else(fail, |v| Json(v).into_response())
}

#[derive(Deserialize)]
struct EventsQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    decision: Option<String>,
}

async fn events(AxState(st): AxState<Shared>, Query(q): Query<EventsQuery>) -> Response {
    let run = || -> Result<Value> {
        let events = verified_events(&st)?;
        let rows: Vec<Value> = events
            .iter()
            .rev()
            .filter(|e| {
                let r = &e.record;
                q.agent
                    .as_ref()
                    .is_none_or(|a| r.agent.as_deref() == Some(a))
                    && q.decision.as_ref().is_none_or(|d| {
                        r.decision
                            .is_some_and(|x| x.to_string().eq_ignore_ascii_case(d))
                    })
            })
            .take(q.limit.unwrap_or(200).min(2000))
            .map(|e| {
                let r = &e.record;
                json!({
                    "seq": e.seq,
                    "timestamp": r.timestamp,
                    "event_type": r.event_type,
                    "request_id": r.request_id,
                    "decision": r.decision,
                    "reason_code": r.reason_codes.first().map(|c| c.code()),
                    "security_event": r.reason_codes.first().and_then(|c| c.security_event()),
                    "agent": r.agent,
                    "organization": r.organization,
                    "actor": r.actor,
                    "action": r.action,
                    "resource": r.resource,
                    "value": r.value,
                    "detail": r.detail,
                    "operator": r.operator,
                })
            })
            .collect();
        Ok(json!(rows))
    };
    run().map_or_else(fail, |v| Json(v).into_response())
}

async fn trace(AxState(st): AxState<Shared>, UrlPath(id): UrlPath<String>) -> Response {
    let run = || -> Result<Value> {
        let path = cfg(&st)?.audit.path.display().to_string();
        let hops: Vec<Value> = verified_events(&st)?
            .iter()
            .filter(|e| {
                let r = &e.record;
                r.event_type == "authorization.decision"
                    && (r.request_id.to_string() == id || r.trace_id.as_deref() == Some(&id))
            })
            .map(|e| super::hop_json(&path, e))
            .collect();
        Ok(json!({ "id": id, "hops": hops }))
    };
    run().map_or_else(fail, |v| Json(v).into_response())
}

async fn agents(AxState(st): AxState<Shared>) -> Response {
    state(&st)
        .and_then(|s| s.agents())
        .map_or_else(fail, |a| Json(a).into_response())
}

async fn trust(AxState(st): AxState<Shared>) -> Response {
    let run = || -> Result<Value> {
        let c = cfg(&st)?;
        let store = nexum_gateway::load_trust(&c.trust.file)?;
        let revocations = State::open(&c.state.file)?.revocations()?;
        let domains: Vec<Value> = store
            .trust_domains
            .iter()
            .map(|(name, d)| {
                let revoked = revocations.iter().find(
                    |r| matches!(&r.target, RevocationTarget::TrustDomain(t) if t == name.as_str()),
                );
                json!({
                    "domain": name.as_str(),
                    "issuer": d.issuer,
                    "keys": d.keys.iter().filter_map(|k| k.kid.clone()).collect::<Vec<_>>(),
                    "allow": d.allow,
                    "deny": d.deny,
                    "max_grant_ttl_seconds": d.max_grant_ttl_seconds,
                    "revoked": revoked,
                })
            })
            .collect();
        Ok(json!({ "domains": domains, "revocations": revocations }))
    };
    run().map_or_else(fail, |v| Json(v).into_response())
}

async fn policy(AxState(st): AxState<Shared>) -> Response {
    let run = || -> Result<Value> {
        let c = cfg(&st)?;
        Ok(match c.policy.builtin_file() {
            Ok(f) => {
                json!({ "provider": "builtin", "file": f, "text": std::fs::read_to_string(f)? })
            }
            Err(_) => json!({ "provider": c.policy.provider, "url": c.policy.url }),
        })
    };
    run().map_or_else(fail, |v| Json(v).into_response())
}

async fn approvals(AxState(st): AxState<Shared>) -> Response {
    state(&st)
        .and_then(|s| s.approvals())
        .map_or_else(fail, |a| Json(a).into_response())
}

async fn decide(
    AxState(st): AxState<Shared>,
    UrlPath((id, verdict)): UrlPath<(String, String)>,
) -> Response {
    let approve = match verdict.as_str() {
        "approve" => true,
        "reject" => false,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let run = || -> Result<()> {
        let s = state(&st)?;
        s.decide_approval(&id, approve, &st.operator)?;
        let a = s.approvals()?.into_iter().find(|a| a.id.to_string() == id);
        super::record_admin(
            &st.config,
            nexum_audit::AuditRecord {
                approval_id: a.as_ref().map(|a| a.id),
                request_id: a.as_ref().map_or_else(uuid::Uuid::now_v7, |a| a.request_id),
                agent: a.as_ref().map(|a| a.requested_by.to_string()),
                actor: a.as_ref().and_then(|a| a.actor.clone()),
                action: a.as_ref().map(|a| a.action.to_string()),
                resource: a.as_ref().map(|a| a.resource.to_string()),
                value: a.as_ref().and_then(|a| a.value),
                policy: a.and_then(|a| a.policy),
                operator: Some(st.operator.clone()),
                detail: Some("via console".into()),
                ..super::admin(if approve {
                    "approval.approved"
                } else {
                    "approval.rejected"
                })
            },
        )
    };
    run().map_or_else(
        |e| fail(format!("{e:#}")),
        |()| Json(json!({"ok": true})).into_response(),
    )
}

#[derive(Deserialize)]
struct RevokeBody {
    /// `agent`, `grant`, `trust_domain` or `key`.
    kind: String,
    value: String,
    #[serde(default)]
    reason: Option<String>,
}

async fn revoke(AxState(st): AxState<Shared>, Json(b): Json<RevokeBody>) -> Response {
    let run = || -> Result<()> {
        let s = state(&st)?;
        let reason = b.reason.filter(|r| !r.is_empty());
        let (event, mut rec) = match b.kind.as_str() {
            "agent" => {
                AgentId::parse(&b.value)?;
                s.revoke_agent(&b.value, reason.as_deref())?;
                ("agent.revoked", super::admin("agent.revoked"))
            }
            "grant" => {
                s.revoke(&RevocationTarget::Grant(b.value.clone()), reason.as_deref())?;
                ("grant.revoked", super::admin("grant.revoked"))
            }
            "trust_domain" => {
                s.revoke(
                    &RevocationTarget::TrustDomain(b.value.clone()),
                    reason.as_deref(),
                )?;
                ("trust.revoked", super::admin("trust.revoked"))
            }
            "key" => {
                s.revoke(&RevocationTarget::Key(b.value.clone()), reason.as_deref())?;
                ("key.revoked", super::admin("key.revoked"))
            }
            other => bail!("unknown revocation kind {other:?}"),
        };
        match event {
            "agent.revoked" => rec.agent = Some(b.value),
            "grant.revoked" => rec.grant_ids = vec![b.value],
            "trust.revoked" => rec.organization = Some(b.value),
            _ => rec.detail = Some(format!("kid={}", b.value)),
        }
        if event != "key.revoked" {
            rec.detail = reason.map(|r| format!("{r} (via console)"));
        }
        rec.operator = Some(st.operator.clone());
        super::record_admin(&st.config, rec)
    };
    run().map_or_else(
        |e| fail(format!("{e:#}")),
        |()| Json(json!({"ok": true})).into_response(),
    )
}
