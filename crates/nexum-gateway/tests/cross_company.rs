//! End-to-end: XYZ Corp's procurement agent (and its delegated child) calling
//! Supplier ABC's gateway over HTTP and MCP.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use nexum_core::{AgentId, Capability, ResourcePattern, RevocationTarget, TrustDomain};
use nexum_gateway::config::Config;
use nexum_gateway::server::AppState;
use nexum_grant::*;
use serde_json::{Value, json};
use tower::ServiceExt;

struct Fixture {
    _dir: PathBuf,
    state: Arc<AppState>,
    app: Router,
    procurement: KeyPair,
    child: KeyPair,
    root: String,
    child_grant: String,
}

fn caps(v: &[&str]) -> Vec<Capability> {
    v.iter().map(|s| Capability::parse(s).unwrap()).collect()
}

fn fixture(mcp_upstream: Option<String>) -> Fixture {
    let dir = std::env::temp_dir().join(format!("nexum-it-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let xyz = KeyPair::generate();
    let procurement = KeyPair::generate();
    let child = KeyPair::generate();

    let trust = json!({
        "apiVersion": "nexum.dev/v1alpha1",
        "trust_domains": {"xyz.com": {
            "issuer": "https://identity.xyz.com",
            "keys": [xyz.public_jwk()],
            "allow": ["inventory.read", "pricing.read", "quote.create", "refund.create", "mcp.payments.*"],
            "deny": ["payment.execute", "customer.export"]
        }}
    });
    std::fs::write(
        dir.join("trust.yaml"),
        yaml_serde::to_string(&trust).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("policy.yaml"),
        r#"
apiVersion: nexum.dev/v1alpha1
kind: Policy
id: abc-supplier-v1
subjects: [{ organization: xyz.com }]
rules:
  - { id: read, action: inventory.read, resource: "supplier://abc/*", effect: allow }
  - { action: pricing.read, effect: allow }
  - { id: quote-auto, action: quote.create, effect: allow, conditions: { max_value: 100000 } }
  - { id: quote-approval, action: quote.create, effect: approval, conditions: { value_above: 100000 } }
  - { id: refund-auto, action: refund.create, effect: allow, conditions: { max_value: 500 } }
  - { id: refund-approval, action: refund.create, effect: approval, conditions: { value_above: 500 } }
  - { action: mcp.payments.rpc.tools.list, effect: allow }
  - { action: payment.execute, effect: deny }
delegation: { allowed: [inventory.read, pricing.read], max_depth: 2 }
"#,
    )
    .unwrap();
    let mcp = mcp_upstream
        .map(|u| format!("mcp:\n  payments:\n    url: {u}\n    tools:\n      refund: {{ action: refund.create, value_argument: amount }}\n"))
        .unwrap_or_default();
    std::fs::write(
        dir.join("nexum.yaml"),
        format!(
            "apiVersion: nexum.dev/v1alpha1\nserver: {{ listen: 127.0.0.1:0 }}\ngateway: {{ audience: abc.com }}\n\
             policy: {{ provider: builtin, file: policy.yaml }}\naudit: {{ provider: sqlite, path: audit.db }}\n\
             trust: {{ file: trust.yaml }}\nstate: {{ file: state.db }}\n{mcp}"
        ),
    )
    .unwrap();
    let cfg = Config::load(&dir.join("nexum.yaml")).unwrap();
    let state = nexum_gateway::build(&cfg).unwrap();

    let now = chrono::Utc::now().timestamp();
    let root_claims = GrantClaims {
        jti: uuid::Uuid::new_v4().to_string(),
        iss: "https://identity.xyz.com".into(),
        sub: AgentId::parse("spiffe://xyz.com/agents/procurement").unwrap(),
        act: Some(Actor {
            sub: "jane@xyz.com".into(),
        }),
        org: TrustDomain::parse("xyz.com").unwrap(),
        aud: vec!["abc.com".into()],
        cap: caps(&[
            "inventory.read",
            "pricing.read",
            "quote.create",
            "refund.create",
            "mcp.payments.*",
        ]),
        res: vec![
            ResourcePattern::parse("supplier://abc/*").unwrap(),
            ResourcePattern::parse("mcp://payments*").unwrap(),
        ],
        dcap: caps(&["inventory.read"]),
        purpose: Some("q3-restock".into()),
        iat: now,
        nbf: now,
        exp: now + 900,
        mdd: 1,
        prt: None,
        max_value: None,
        cnf: Confirmation {
            jwk: procurement.public_jwk(),
        },
    };
    let root = sign_grant(&root_claims, &xyz).unwrap();
    let spec = DelegationSpec {
        sub: AgentId::parse("spiffe://xyz.com/agents/inventory-checker").unwrap(),
        holder: child.public_jwk(),
        cap: caps(&["inventory.read"]),
        res: None,
        dcap: vec![],
        mdd: 0,
        ttl_seconds: 300,
        aud: None,
        max_value: None,
    };
    let child_grant = sign_grant(
        &child_claims(&root_claims, &root, spec, now).unwrap(),
        &procurement,
    )
    .unwrap();
    Fixture {
        app: nexum_gateway::server::router(state.clone()),
        state,
        _dir: dir,
        procurement,
        child,
        root,
        child_grant,
    }
}

async fn send(
    app: &Router,
    path: &str,
    chain: &[&str],
    holder: &KeyPair,
    body: &Value,
    extra: &[(&str, &str)],
) -> (StatusCode, Value, String) {
    let body = serde_json::to_vec(body).unwrap();
    let proof = create_proof(
        holder,
        chain[chain.len() - 1],
        "abc.com",
        &body,
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    let mut req = Request::post(path)
        .header("content-type", "application/json")
        .header("nexum-grant", chain.join(","))
        .header("nexum-proof", &proof);
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        proof,
    )
}

fn code(v: &Value) -> &str {
    v["code"]
        .as_str()
        .or(v["error"]["data"]["code"].as_str())
        .unwrap_or("")
}

#[tokio::test]
async fn cross_company_scenario() {
    let f = fixture(None);
    let parent = [f.root.as_str()];
    let delegated = [f.root.as_str(), f.child_grant.as_str()];

    // 1. Parent reads inventory: ALLOW.
    let read = json!({"action": "inventory.read", "resource": "supplier://abc/sku/123"});
    let (s, v, proof) = send(&f.app, "/v1/authorize", &parent, &f.procurement, &read, &[]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["decision"]["outcome"], "ALLOW");
    assert_eq!(v["decision"]["matched_policy"], "abc-supplier-v1");

    // Replaying the exact same request + proof: DENY.
    let body = serde_json::to_vec(&read).unwrap();
    let replay = Request::post("/v1/authorize")
        .header("nexum-grant", f.root.as_str())
        .header("nexum-proof", proof)
        .body(Body::from(body))
        .unwrap();
    let resp = f.app.clone().oneshot(replay).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 2. Delegated child reads inventory: ALLOW.
    let (s, v, _) = send(&f.app, "/v1/authorize", &delegated, &f.child, &read, &[]).await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // 3. Child tries payment.execute: DENY, capability not in chain.
    let pay =
        json!({"action": "payment.execute", "resource": "supplier://abc/invoice/9", "value": 10});
    let (s, v, _) = send(&f.app, "/v1/authorize", &delegated, &f.child, &pay, &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(code(&v), "NX-4032");

    // Child presenting only the parent's grant (grant theft): DENY.
    let (s, v, _) = send(&f.app, "/v1/authorize", &parent, &f.child, &read, &[]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(code(&v), "NX-2002");

    // Child exercising quote.create, which policy forbids via delegation even
    // if it were in the chain: here it's simply not in the chain.
    let quote =
        json!({"action": "quote.create", "resource": "supplier://abc/quote/new", "value": 250000});
    let (_, v, _) = send(&f.app, "/v1/authorize", &delegated, &f.child, &quote, &[]).await;
    assert_eq!(code(&v), "NX-4032");

    // 4. Parent creates a $250k quote: REQUIRE_APPROVAL.
    let (s, v, _) = send(
        &f.app,
        "/v1/authorize",
        &parent,
        &f.procurement,
        &quote,
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["decision"]["outcome"], "REQUIRE_APPROVAL");
    let approval = v["decision"]["obligations"][0]["approval_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Retrying before approval: DENY.
    let (s, _, _) = send(
        &f.app,
        "/v1/authorize",
        &parent,
        &f.procurement,
        &quote,
        &[("nexum-approval", &approval)],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Approval for a different request (different value) cannot be reused.
    f.state
        .authorizer
        .state
        .decide_approval(&approval, true, "cfo@abc.com")
        .unwrap();
    let other =
        json!({"action": "quote.create", "resource": "supplier://abc/quote/new", "value": 900000});
    let (s, v, _) = send(
        &f.app,
        "/v1/authorize",
        &parent,
        &f.procurement,
        &other,
        &[("nexum-approval", &approval)],
    )
    .await;
    assert_eq!((s, code(&v)), (StatusCode::FORBIDDEN, "NX-4004"));

    // After approval: ALLOW once, then the approval is consumed.
    let (s, v, _) = send(
        &f.app,
        "/v1/authorize",
        &parent,
        &f.procurement,
        &quote,
        &[("nexum-approval", &approval)],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(code(&v), "NX-4003");
    let (s, _, _) = send(
        &f.app,
        "/v1/authorize",
        &parent,
        &f.procurement,
        &quote,
        &[("nexum-approval", &approval)],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Revoking the parent agent kills the whole delegated chain.
    f.state
        .authorizer
        .state
        .revoke(
            &RevocationTarget::Agent("spiffe://xyz.com/agents/procurement".into()),
            None,
        )
        .unwrap();
    let (s, v, _) = send(&f.app, "/v1/authorize", &delegated, &f.child, &read, &[]).await;
    assert_eq!((s, code(&v)), (StatusCode::FORBIDDEN, "NX-3001"));

    // Revoking trust in XYZ.
    f.state
        .authorizer
        .state
        .revoke(&RevocationTarget::TrustDomain("xyz.com".into()), None)
        .unwrap();
    let (_, v, _) = send(&f.app, "/v1/authorize", &parent, &f.procurement, &read, &[]).await;
    assert_eq!(code(&v), "NX-3003");

    // Every decision is in a verifiable audit chain.
    let n = f.state.authorizer.audit.verify().unwrap();
    assert_eq!(n, 13);
}

#[tokio::test]
async fn rejects_missing_and_malformed_credentials() {
    let f = fixture(None);
    let read = serde_json::to_vec(
        &json!({"action": "inventory.read", "resource": "supplier://abc/sku/1"}),
    )
    .unwrap();
    for (grant, proof, want) in [
        (None, None, "NX-1001"),
        (Some(f.root.as_str()), None, "NX-2001"),
        (Some("garbage"), Some("x"), "NX-1003"),
    ] {
        let mut req = Request::post("/v1/authorize");
        if let Some(g) = grant {
            req = req.header("nexum-grant", g);
        }
        if let Some(p) = proof {
            req = req.header("nexum-proof", p);
        }
        let resp = f
            .app
            .clone()
            .oneshot(req.body(Body::from(read.clone())).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let v: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), 1 << 20).await.unwrap()).unwrap();
        assert_eq!(code(&v), want);
    }
    // Wildcard actions and unknown body fields are invalid requests.
    for body in [
        json!({"action": "inventory.*", "resource": "supplier://abc/sku/1"}),
        json!({"action": "inventory.read", "resource": "supplier://abc/*"}),
        json!({"action": "inventory.read", "resource": "supplier://abc/1", "admin": true}),
    ] {
        let (s, v, _) = send(
            &f.app,
            "/v1/authorize",
            &[&f.root],
            &f.procurement,
            &body,
            &[],
        )
        .await;
        assert_eq!((s, code(&v)), (StatusCode::FORBIDDEN, "NX-5001"), "{body}");
    }
}

#[tokio::test]
async fn mcp_tool_calls_are_enforced_and_forwarded() {
    // Mock MCP server that echoes what it received.
    let upstream = Router::new().route(
        "/mcp",
        axum::routing::post(|headers: axum::http::HeaderMap, body: String| async move {
            assert!(headers.get("nexum-grant").is_none(), "credentials must not be forwarded");
            assert!(headers.get("nexum-proof").is_none());
            let req: Value = serde_json::from_str(&body).unwrap();
            axum::Json(json!({"jsonrpc": "2.0", "id": req["id"], "result": {"content": [{"type": "text", "text": "refunded"}]}}))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

    let f = fixture(Some(format!("http://{addr}/mcp")));
    let call = |amount: u64| {
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "refund", "arguments": {"amount": amount, "order": "A-1"}}})
    };

    let (s, v, _) = send(
        &f.app,
        "/mcp/payments",
        &[&f.root],
        &f.procurement,
        &call(200),
        &[("mcp-method", "tools/call"), ("mcp-name", "refund")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["result"]["content"][0]["text"], "refunded");

    // $1,700 refund: REQUIRE_APPROVAL, and the upstream is never called.
    let (s, v, _) = send(
        &f.app,
        "/mcp/payments",
        &[&f.root],
        &f.procurement,
        &call(1700),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert_eq!(v["error"]["code"], -32002);
    assert_eq!(v["id"], 7);

    // Header says one tool, body calls another: rejected.
    let (s, v, _) = send(
        &f.app,
        "/mcp/payments",
        &[&f.root],
        &f.procurement,
        &call(1),
        &[("mcp-name", "lookup")],
    )
    .await;
    assert_eq!((s, code(&v)), (StatusCode::FORBIDDEN, "NX-5001"));

    // Parser differential: duplicate "name" keys must not reach the upstream.
    let raw = br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"wipe_ledger","name":"refund","arguments":{"amount":1}}}"#;
    let proof = create_proof(
        &f.procurement,
        &f.root,
        "abc.com",
        raw,
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    let req = Request::post("/mcp/payments")
        .header("nexum-grant", f.root.as_str())
        .header("nexum-proof", proof)
        .body(Body::from(&raw[..]))
        .unwrap();
    let resp = f.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let v: Value =
        serde_json::from_slice(&to_bytes(resp.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(code(&v), "NX-5001");

    // tools/list is allowed by policy; an unmapped tool is not.
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let (s, _, _) = send(
        &f.app,
        "/mcp/payments",
        &[&f.root],
        &f.procurement,
        &list,
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let other = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "wipe_ledger"}});
    let (s, v, _) = send(
        &f.app,
        "/mcp/payments",
        &[&f.root],
        &f.procurement,
        &other,
        &[],
    )
    .await;
    assert_eq!((s, code(&v)), (StatusCode::FORBIDDEN, "NX-4036"));
}

#[tokio::test]
async fn audit_records_the_authority_trace() {
    let f = fixture(None);
    let read = json!({"action": "inventory.read", "resource": "supplier://abc/sku/1"});
    let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );
    let delegated = [f.root.as_str(), f.child_grant.as_str()];
    send(
        &f.app,
        "/v1/authorize",
        &delegated,
        &f.child,
        &read,
        &[("traceparent", tp)],
    )
    .await;
    let pay = json!({"action": "payment.execute", "resource": "supplier://abc/i/1", "value": 7});
    send(&f.app, "/v1/authorize", &delegated, &f.child, &pay, &[]).await;

    let events = f.state.authorizer.audit.read_all().unwrap();
    let (traced, untraced) = (&events[0].record, &events[1].record);
    assert_eq!(
        traced.trace_id.as_deref(),
        Some("4bf92f3577b34da6a3ce929d0e0e4736")
    );
    assert_eq!(
        traced.chain,
        [
            "spiffe://xyz.com/agents/procurement",
            "spiffe://xyz.com/agents/inventory-checker"
        ]
    );
    assert_eq!(traced.purpose.as_deref(), Some("q3-restock"));
    assert_eq!(
        (untraced.trace_id.as_deref(), untraced.value),
        (None, Some(7))
    );
    assert!(
        f.state
            .authorizer
            .metrics
            .prometheus()
            .contains("nexum_security_events_total{event=\"privilege_escalation_attempt\"} 1")
    );
}

#[tokio::test]
async fn policy_simulation_replays_only_policy_decisions() {
    let f = fixture(None);
    let quote =
        json!({"action": "quote.create", "resource": "supplier://abc/q/1", "value": 250000});
    send(
        &f.app,
        "/v1/authorize",
        &[&f.root],
        &f.procurement,
        &quote,
        &[],
    )
    .await;
    let delegated = [f.root.as_str(), f.child_grant.as_str()];
    let pay = json!({"action": "payment.execute", "resource": "supplier://abc/i/1", "value": 7});
    send(&f.app, "/v1/authorize", &delegated, &f.child, &pay, &[]).await;

    let events = f.state.authorizer.audit.read_all().unwrap();
    let current = nexum_gateway::load_policy(&f._dir.join("policy.yaml")).unwrap();
    let text = std::fs::read_to_string(f._dir.join("policy.yaml"))
        .unwrap()
        .replace("max_value: 100000", "max_value: 300000")
        .replace("value_above: 100000", "value_above: 300000");
    let proposed = nexum_policy::PolicySet::from_yaml(&text).unwrap();

    let rep = nexum_gateway::simulate::simulate(&events, &current, &proposed);
    assert_eq!(
        (rep.decisions, rep.decided_before_policy, rep.reevaluated),
        (2, 1, 1)
    );
    assert_eq!(rep.transitions["REQUIRE_APPROVAL → ALLOW"], 1);
    assert_eq!(rep.widened(), 1);
    assert!(
        nexum_gateway::simulate::simulate(&events, &current, &current)
            .changes
            .is_empty()
    );
}

#[tokio::test]
async fn opa_decides_after_chain_and_trust_and_fails_closed() {
    // Mock OPA: approval for quotes, allow for everything else.
    let opa = Router::new().route(
        "/v1/data/nexum/authz",
        axum::routing::post(|axum::Json(body): axum::Json<Value>| async move {
            let input = &body["input"];
            assert_eq!(input["organization"], "xyz.com");
            let result = if input["action"] == "quote.create" {
                json!({"outcome": "REQUIRE_APPROVAL", "policy_id": "rego", "rule_id": "quotes"})
            } else {
                json!(true)
            };
            axum::Json(json!({ "result": result }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, opa).await.unwrap() });

    let f = fixture(None);
    let app = with_policy(
        &f._dir,
        &format!("{{ provider: opa, url: \"http://{addr}/v1/data/nexum/authz\" }}"),
    );

    let read = json!({"action": "inventory.read", "resource": "supplier://abc/sku/1"});
    let (s, v, _) = send(
        &app,
        "/v1/authorize",
        &[&f.root],
        &f.procurement,
        &read,
        &[],
    )
    .await;
    assert_eq!((s, code(&v)), (StatusCode::OK, "NX-4001"), "{v}");
    let quote = json!({"action": "quote.create", "resource": "supplier://abc/q", "value": 5});
    let (s, v, _) = send(
        &app,
        "/v1/authorize",
        &[&f.root],
        &f.procurement,
        &quote,
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert_eq!(v["decision"]["matched_rule"], "quotes");
    // OPA would allow it, but the chain doesn't carry payments: OPA is never asked.
    let pay = json!({"action": "payment.execute", "resource": "supplier://abc/i", "value": 1});
    let (_, v, _) = send(&app, "/v1/authorize", &[&f.root], &f.procurement, &pay, &[]).await;
    assert_eq!(code(&v), "NX-4032");

    // OPA unreachable: fail closed.
    let down = with_policy(
        &f._dir,
        "{ provider: opa, url: \"http://127.0.0.1:9/v1/data/nexum/authz\", timeout_ms: 300 }",
    );
    let (s, v, _) = send(
        &down,
        "/v1/authorize",
        &[&f.root],
        &f.procurement,
        &read,
        &[],
    )
    .await;
    assert_eq!((s, code(&v)), (StatusCode::FORBIDDEN, "NX-5002"));
}

/// Rebuild the fixture gateway with a different `policy:` block.
fn with_policy(dir: &std::path::Path, policy: &str) -> Router {
    let path = dir.join("nexum.yaml");
    let text = std::fs::read_to_string(&path).unwrap();
    let start = text.find("policy: {").unwrap();
    let end = start + text[start..].find('}').unwrap() + 1;
    let text = format!("{}policy: {policy}{}", &text[..start], &text[end..]);
    std::fs::write(&path, text).unwrap();
    nexum_gateway::server::router(nexum_gateway::build(&Config::load(&path).unwrap()).unwrap())
}
