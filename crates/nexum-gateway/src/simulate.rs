//! Policy simulation: re-evaluate recorded decisions under a proposed policy.
//!
//! Policy runs after chain authority and trust, so only decisions that
//! reached the policy stage can change. Earlier denials (identity, proof,
//! authority, trust) are counted but never re-evaluated: a policy change can't
//! affect them. Events from before the audit log recorded the delegation chain
//! and value lack the data to re-evaluate and are reported separately rather
//! than guessed.

use std::collections::{BTreeMap, BTreeSet};

use nexum_audit::AuditEvent;
use nexum_core::{
    AgentId, AuthorizationRequest, Capability, DelegationLink, GrantedAuthority, Outcome,
    RequestContext, ResourcePattern, Stage, TrustDomain,
};
use nexum_policy::PolicySet;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Change {
    pub request_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub agent: String,
    pub organization: String,
    pub action: String,
    pub resource: String,
    pub value: Option<u64>,
    pub before: Outcome,
    pub after: Outcome,
    pub before_rule: Option<String>,
    pub after_rule: Option<String>,
    /// The proposed policy is more permissive for this request.
    pub widens: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    /// `authorization.decision` events read.
    pub decisions: usize,
    /// Denied before policy ran; no policy change can affect them.
    pub decided_before_policy: usize,
    pub reevaluated: usize,
    pub unchanged: usize,
    /// Reached policy but predate chain/value recording.
    pub insufficient_data: usize,
    /// "DENY → ALLOW" etc.
    pub transitions: BTreeMap<String, usize>,
    pub changes: Vec<Change>,
    pub affected_agents: BTreeSet<String>,
    pub affected_organizations: BTreeSet<String>,
}

impl Report {
    pub fn widened(&self) -> usize {
        self.changes.iter().filter(|c| c.widens).count()
    }
}

fn permissiveness(o: Outcome) -> u8 {
    match o {
        Outcome::Deny => 0,
        Outcome::RequireApproval => 1,
        Outcome::Allow => 2,
    }
}

/// Rebuild the request policy saw. `None` if the event lacks the data.
fn request(e: &AuditEvent) -> Option<AuthorizationRequest> {
    let r = &e.record;
    if r.chain.is_empty() {
        return None;
    }
    let subject = AgentId::parse(r.agent.as_deref()?).ok()?;
    let links = r
        .chain
        .iter()
        .map(|s| {
            Some(DelegationLink {
                grant_id: String::new(),
                issuer: String::new(),
                subject: AgentId::parse(s).ok()?,
                capabilities: vec![],
                expires_at: r.timestamp,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let action = Capability::parse(r.action.as_deref()?).ok()?;
    Some(AuthorizationRequest {
        request_id: r.request_id,
        timestamp: r.timestamp,
        subject,
        actor: r.actor.clone(),
        organization: TrustDomain::parse(r.organization.as_deref()?).ok()?,
        action: action.clone(),
        resource: ResourcePattern::parse(r.resource.as_deref()?).ok()?,
        purpose: r.purpose.clone(),
        delegation_chain: links,
        // Policy never reads the granted authority; chain checks already ran.
        authority: GrantedAuthority {
            capabilities: vec![action],
            resources: vec![],
            max_value: None,
            expires_at: r.timestamp,
        },
        context: RequestContext {
            value: r.value,
            protocol: r.protocol.clone().unwrap_or_default(),
            attributes: Default::default(),
        },
    })
}

pub fn simulate(events: &[AuditEvent], current: &PolicySet, proposed: &PolicySet) -> Report {
    let mut rep = Report::default();
    for e in events {
        let r = &e.record;
        if r.event_type != "authorization.decision" {
            continue;
        }
        rep.decisions += 1;
        let Some(code) = r.reason_codes.first() else {
            rep.insufficient_data += 1;
            continue;
        };
        if code.stage() < Stage::Policy {
            rep.decided_before_policy += 1;
            continue;
        }
        let Some(req) = request(e) else {
            rep.insufficient_data += 1;
            continue;
        };
        rep.reevaluated += 1;
        let (before, after) = (current.evaluate(&req), proposed.evaluate(&req));
        if before.outcome == after.outcome {
            rep.unchanged += 1;
            continue;
        }
        *rep.transitions
            .entry(format!("{} → {}", before.outcome, after.outcome))
            .or_default() += 1;
        rep.affected_agents.insert(req.subject.to_string());
        rep.affected_organizations
            .insert(req.organization.to_string());
        rep.changes.push(Change {
            request_id: r.request_id.to_string(),
            timestamp: r.timestamp,
            agent: req.subject.to_string(),
            organization: req.organization.to_string(),
            action: req.action.to_string(),
            resource: req.resource.to_string(),
            value: req.context.value,
            widens: permissiveness(after.outcome) > permissiveness(before.outcome),
            before: before.outcome,
            after: after.outcome,
            before_rule: before.rule_id,
            after_rule: after.rule_id,
        });
    }
    rep
}
