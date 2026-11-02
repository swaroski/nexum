//! HTTP surface: the decision API, MCP/A2A enforcement proxies, health and
//! metrics.
//!
//! Credentials travel in headers so the proof can sign the exact body:
//! `Nexum-Grant` (comma-separated compact grants, root first),
//! `Nexum-Proof`, and optionally `Nexum-Approval`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderName, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use nexum_core::{AuthorizationDecision, Capability, Outcome, ReasonCode, ResourcePattern};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::adapters::{A2aAdapter, McpAdapter, ProtocolAdapter};
use crate::authorizer::{Authorizer, Normalized, Presented};

pub const GRANT_HEADER: &str = "nexum-grant";
pub const PROOF_HEADER: &str = "nexum-proof";
pub const APPROVAL_HEADER: &str = "nexum-approval";

#[derive(Debug)]
pub struct AppState {
    pub authorizer: Authorizer,
    pub mcp: McpAdapter,
    pub a2a: A2aAdapter,
    pub http: reqwest::Client,
}

pub fn router(state: Arc<AppState>) -> Router {
    let limit = state.authorizer.settings.max_body_bytes;
    Router::new()
        .route("/v1/authorize", post(authorize))
        .route(
            "/mcp/{server}",
            post(|State(st): State<Arc<AppState>>, Path(t): Path<String>, h: HeaderMap, b: Bytes| async move {
                proxy(&st, &st.mcp, t, h, b).await
            }),
        )
        .route(
            "/a2a/{agent}",
            post(|State(st): State<Arc<AppState>>, Path(t): Path<String>, h: HeaderMap, b: Bytes| async move {
                proxy(&st, &st.a2a, t, h, b).await
            }),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(metrics))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

fn presented<'a>(headers: &HeaderMap, body: &'a [u8]) -> Presented<'a> {
    let h = |n: &str| {
        headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    Presented {
        grants: h(GRANT_HEADER)
            .map(|g| {
                g.split(',')
                    .map(|t| t.trim().to_owned())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        proof: h(PROOF_HEADER),
        approval_id: h(APPROVAL_HEADER),
        body,
        trace: opentelemetry::global::get_text_map_propagator(|p| {
            p.extract(&opentelemetry_http::HeaderExtractor(headers))
        }),
    }
}

/// Body of `POST /v1/authorize`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeBody {
    pub action: String,
    pub resource: String,
    #[serde(default)]
    pub value: Option<u64>,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
}

pub fn normalize_authorize(body: &[u8]) -> Result<Normalized, ReasonCode> {
    let b: AuthorizeBody = serde_json::from_slice(body).map_err(|_| ReasonCode::InvalidRequest)?;
    Ok(Normalized {
        action: Capability::parse(&b.action).map_err(|_| ReasonCode::InvalidRequest)?,
        resource: ResourcePattern::parse(&b.resource).map_err(|_| ReasonCode::InvalidRequest)?,
        value: b.value,
        protocol: "http",
        attributes: b.attributes,
    })
}

/// Decision JSON returned to callers: the structured decision plus a stable
/// error code and a human-readable explanation derived from it.
pub fn decision_body(d: &AuthorizationDecision) -> Value {
    let primary = d.primary_reason();
    json!({
        "decision": d,
        "code": primary.map(ReasonCode::code),
        "message": primary.map(ReasonCode::describe),
    })
}

fn status_for(o: Outcome) -> StatusCode {
    match o {
        Outcome::Allow => StatusCode::OK,
        Outcome::Deny => StatusCode::FORBIDDEN,
        Outcome::RequireApproval => StatusCode::ACCEPTED,
    }
}

async fn authorize(State(st): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    let d = st
        .authorizer
        .authorize(presented(&headers, &body), normalize_authorize(&body))
        .await;
    (status_for(d.outcome), Json(decision_body(&d))).into_response()
}

async fn metrics(State(st): State<Arc<AppState>>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        st.authorizer.metrics.prometheus(),
    )
        .into_response()
}

/// Authorize a JSON-RPC message, then forward it unchanged to the upstream.
/// Nexum credentials and `Authorization` are never forwarded.
async fn proxy<A: ProtocolAdapter>(
    st: &AppState,
    adapter: &A,
    target: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let message = crate::adapters::parse_unambiguous(&body);
    let normalized = match &message {
        Some(m) => adapter.normalize(&target, &headers, m),
        None => Err(ReasonCode::InvalidRequest),
    };
    let d = st
        .authorizer
        .authorize(presented(&headers, &body), normalized)
        .await;
    if d.outcome != Outcome::Allow {
        let id = message
            .as_ref()
            .and_then(|m| m.get("id"))
            .cloned()
            .unwrap_or(Value::Null);
        let code = if d.outcome == Outcome::RequireApproval {
            -32002
        } else {
            -32001
        };
        let primary = d.primary_reason();
        let err = json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": primary.map(ReasonCode::describe).unwrap_or("denied"),
                "data": decision_body(&d),
            }
        });
        return (status_for(d.outcome), Json(err)).into_response();
    }

    let Some(url) = adapter.upstream(&target) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut req = st.http.post(url).body(body);
    for (name, value) in &headers {
        if forwardable(name) {
            req = req.header(name, value);
        }
    }
    match req.send().await {
        Ok(resp) => {
            let mut out = Response::builder().status(resp.status().as_u16());
            for (name, value) in resp.headers() {
                if name == header::CONTENT_TYPE
                    || name.as_str().starts_with("mcp-")
                    || name.as_str().starts_with("a2a-")
                {
                    out = out.header(name.as_str(), value.as_bytes());
                }
            }
            out.body(Body::from_stream(resp.bytes_stream()))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
        }
        Err(e) => {
            tracing::warn!(error = %e, upstream = %url, "upstream request failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

fn forwardable(name: &HeaderName) -> bool {
    let n = name.as_str();
    n == "content-type" || n == "accept" || n.starts_with("mcp-") || n.starts_with("a2a-")
}
