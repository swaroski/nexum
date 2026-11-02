//! In-memory decision pipeline for decision-API requests.
//!
//! Mirrors `nexum_gateway::authorizer::Authorizer::decide`, stage for stage,
//! using the same primitives. Differences, by design: no persistence (an
//! approval outcome stops at REQUIRE_APPROVAL), no audit, and protocol
//! messages (MCP/A2A) are not normalized here. `tests/agreement.rs` holds it
//! to the gateway's results on the official eval suite.

use std::collections::{BTreeMap, HashSet};

use nexum_core::{
    Capability, Outcome, ReasonCode, RequestContext, ResourcePattern, RevocationList,
    RevocationTarget, Stage, resources_cover, set_covers,
};
use nexum_grant::{Clock, MemoryReplayGuard, TrustStore, Verifier};
use nexum_policy::PolicySet;
use serde::{Deserialize, Serialize};

use crate::mint::Minted;

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub stage: Stage,
    pub label: &'static str,
    pub status: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub outcome: Outcome,
    pub code: &'static str,
    pub reason: &'static str,
    pub security_event: Option<&'static str>,
    pub checks: Vec<Check>,
    pub policy: Option<String>,
    pub rule: Option<String>,
    /// The verified delegation path, root first (empty if the chain failed).
    pub chain: Vec<String>,
    pub actor: Option<String>,
}

#[derive(Debug, Default)]
struct Revoked(HashSet<RevocationTarget>);

impl RevocationList for Revoked {
    fn is_revoked(
        &self,
        target: &RevocationTarget,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.0.contains(target))
    }
}

/// Body of `POST /v1/authorize` (same shape and strictness as the gateway).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizeBody {
    action: String,
    resource: String,
    #[serde(default)]
    value: Option<u64>,
    #[serde(default)]
    attributes: BTreeMap<String, serde_json::Value>,
}

/// Parse a decision-API body into one exact action, resource and context.
pub fn normalize_authorize(
    body: &[u8],
) -> Result<(Capability, ResourcePattern, RequestContext), ReasonCode> {
    let b: AuthorizeBody = serde_json::from_slice(body).map_err(|_| ReasonCode::InvalidRequest)?;
    let action = Capability::parse(&b.action).map_err(|_| ReasonCode::InvalidRequest)?;
    let resource = ResourcePattern::parse(&b.resource).map_err(|_| ReasonCode::InvalidRequest)?;
    if !action.is_exact() || !resource.is_exact() {
        return Err(ReasonCode::InvalidRequest);
    }
    Ok((
        action,
        resource,
        RequestContext {
            value: b.value,
            protocol: "http".into(),
            attributes: b.attributes,
        },
    ))
}

fn checks(code: ReasonCode, outcome: Outcome) -> Vec<Check> {
    let at = code.stage();
    Stage::ALL
        .into_iter()
        .map(|s| Check {
            stage: s,
            label: s.label(),
            status: if s == Stage::Audit {
                "NOT RECORDED (simulation)"
            } else if s < at {
                "PASS"
            } else if s == at {
                match outcome {
                    Outcome::Allow => "PASS",
                    Outcome::RequireApproval => "APPROVAL REQUIRED",
                    Outcome::Deny => "FAIL",
                }
            } else {
                match (outcome, s) {
                    (Outcome::Allow, Stage::Approval) => "NOT REQUIRED",
                    (Outcome::RequireApproval, Stage::Approval) => "PENDING",
                    _ => "NOT EVALUATED",
                }
            },
        })
        .collect()
}

/// Decide `m` against `trust` and `policy` for the gateway `audience` at
/// `now` (Unix seconds), with the gateway's default clock skew (30 s) and
/// proof age (60 s).
pub fn decide(
    trust: &TrustStore,
    policy: &PolicySet,
    audience: &str,
    m: &Minted,
    now: i64,
) -> Decision {
    let mut d = Decision {
        outcome: Outcome::Deny,
        code: "",
        reason: "",
        security_event: None,
        checks: vec![],
        policy: None,
        rule: None,
        chain: vec![],
        actor: None,
    };
    let finish = |mut d: Decision, outcome: Outcome, code: ReasonCode| {
        d.outcome = outcome;
        d.code = code.code();
        d.reason = code.describe();
        d.security_event = code.security_event();
        d.checks = checks(code, outcome);
        d
    };

    let revoked = Revoked(m.revoke.iter().cloned().collect());
    let verifier = Verifier {
        trust,
        revocations: &revoked,
        audience,
        clock: Clock { now, leeway: 30 },
    };
    let replay = MemoryReplayGuard::default();
    let tokens: Vec<&str> = m.chain.iter().map(String::as_str).collect();
    let attempts = if m.replay { 2 } else { 1 };
    let mut chain = None;
    for _ in 0..attempts {
        // 1. Chain, 2. proof (a replay is the second identical attempt).
        let c = match verifier.verify_chain(&tokens) {
            Ok(c) => c,
            Err(r) => return finish(d, Outcome::Deny, r),
        };
        if let Err(r) = verifier.verify_proof(&c, &m.proof, &m.body, &replay, 60) {
            d.chain = c.grants.iter().map(|g| g.sub.to_string()).collect();
            return finish(d, Outcome::Deny, r);
        }
        chain = Some(c);
    }
    let Some(chain) = chain else {
        return finish(d, Outcome::Deny, ReasonCode::GrantMissing);
    };
    d.chain = chain.grants.iter().map(|g| g.sub.to_string()).collect();
    d.actor = chain.root().act.as_ref().map(|a| a.sub.clone());

    // 3. Normalize.
    let (action, resource, context) = match normalize_authorize(&m.body) {
        Ok(n) => n,
        Err(r) => return finish(d, Outcome::Deny, r),
    };
    let ts = chrono::DateTime::from_timestamp(now, 0).unwrap_or_default();
    let req = chain.to_request(uuid::Uuid::new_v4(), ts, action, resource, context);

    // 4. Delegated authority, 5. trust.
    let auth = &req.authority;
    let stop = if !set_covers(&auth.capabilities, &req.action) {
        Some(ReasonCode::CapabilityNotInChain)
    } else if !resources_cover(&auth.resources, &req.resource) {
        Some(ReasonCode::ResourceNotInChain)
    } else if auth
        .max_value
        .is_some_and(|m| req.context.value.is_none_or(|v| v > m))
    {
        Some(ReasonCode::ValueExceedsGrant)
    } else if !trust.accepts(&req.organization, &req.action) {
        Some(ReasonCode::TrustDomainDenies)
    } else {
        None
    };
    if let Some(r) = stop {
        return finish(d, Outcome::Deny, r);
    }

    // 6. Policy. Approval would be handled by the gateway's approval store.
    let p = policy.evaluate(&req);
    d.policy = p.policy_id;
    d.rule = p.rule_id;
    finish(d, p.outcome, p.reason)
}
