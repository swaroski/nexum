//! The enforcement pipeline. Protocol adapters hand it what the caller
//! presented plus a normalized action; it returns exactly one decision and
//! writes exactly one audit event. Every error path is a DENY.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use nexum_audit::{AuditLog, AuditRecord};
use nexum_core::{
    ApprovalRequest, ApprovalStatus, AuthorizationDecision, AuthorizationRequest, Capability,
    DelegationLink, GrantedAuthority, Obligation, Outcome, PolicyDecisionPoint, ReasonCode,
    RequestContext, ResourcePattern, resources_cover, set_covers,
};
use nexum_grant::{Clock, MemoryReplayGuard, TrustStore, VerifiedChain, Verifier};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::GatewaySettings;
use crate::store::State;

/// Credentials as presented on the wire. Never logged.
#[derive(Debug, Default)]
pub struct Presented<'a> {
    /// Compact grants, root first.
    pub grants: Vec<String>,
    pub proof: Option<String>,
    pub approval_id: Option<String>,
    /// The exact bytes the proof's `bh` must hash to.
    pub body: &'a [u8],
}

/// What an adapter extracted from the protocol message.
#[derive(Debug, Clone)]
pub struct Normalized {
    pub action: Capability,
    pub resource: ResourcePattern,
    pub value: Option<u64>,
    pub protocol: &'static str,
    pub attributes: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Default)]
pub struct Metrics {
    pub requests: AtomicU64,
    pub allow: AtomicU64,
    pub deny: AtomicU64,
    pub approval: AtomicU64,
    pub audit_errors: AtomicU64,
    pub decision_micros_total: AtomicU64,
}

impl Metrics {
    pub fn prometheus(&self) -> String {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        format!(
            "# TYPE nexum_requests_total counter\nnexum_requests_total {}\n\
             # TYPE nexum_decisions_total counter\n\
             nexum_decisions_total{{outcome=\"allow\"}} {}\n\
             nexum_decisions_total{{outcome=\"deny\"}} {}\n\
             nexum_decisions_total{{outcome=\"require_approval\"}} {}\n\
             # TYPE nexum_audit_errors_total counter\nnexum_audit_errors_total {}\n\
             # TYPE nexum_decision_seconds_sum counter\nnexum_decision_seconds_sum {}\n",
            g(&self.requests),
            g(&self.allow),
            g(&self.deny),
            g(&self.approval),
            g(&self.audit_errors),
            g(&self.decision_micros_total) as f64 / 1e6,
        )
    }
}

pub struct Authorizer {
    pub settings: GatewaySettings,
    pub trust: TrustStore,
    pub state: Arc<State>,
    pub pdp: Arc<dyn PolicyDecisionPoint>,
    pub audit: Arc<dyn AuditLog>,
    pub replay: MemoryReplayGuard,
    pub metrics: Metrics,
}

impl std::fmt::Debug for Authorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorizer")
            .field("audience", &self.settings.audience)
            .finish_non_exhaustive()
    }
}

fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, 0).unwrap_or_default()
}

/// Binds an approval to one exact (subject, actor, org, action, resource, value).
pub fn fingerprint(r: &AuthorizationRequest) -> String {
    let material = serde_json::json!([
        r.subject,
        r.actor,
        r.organization,
        r.action,
        r.resource,
        r.context.value
    ]);
    Sha256::digest(material.to_string().as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl Authorizer {
    pub async fn authorize(
        &self,
        presented: Presented<'_>,
        normalized: Result<Normalized, ReasonCode>,
    ) -> AuthorizationDecision {
        let started = std::time::Instant::now();
        let request_id = Uuid::now_v7();
        let (decision, record) = self.decide(request_id, presented, normalized).await;
        let decision = match self.audit.append(record) {
            Ok(_) => decision,
            Err(e) => {
                tracing::error!(error = %e, "audit write failed; denying");
                self.metrics.audit_errors.fetch_add(1, Ordering::Relaxed);
                AuthorizationDecision::deny(request_id, ReasonCode::AuditUnavailable)
            }
        };
        let m = &self.metrics;
        m.requests.fetch_add(1, Ordering::Relaxed);
        match decision.outcome {
            Outcome::Allow => &m.allow,
            Outcome::Deny => &m.deny,
            Outcome::RequireApproval => &m.approval,
        }
        .fetch_add(1, Ordering::Relaxed);
        m.decision_micros_total
            .fetch_add(started.elapsed().as_micros() as u64, Ordering::Relaxed);
        tracing::info!(
            request_id = %decision.request_id,
            outcome = %decision.outcome,
            reason = ?decision.primary_reason(),
            "authorization decision"
        );
        decision
    }

    async fn decide(
        &self,
        request_id: Uuid,
        presented: Presented<'_>,
        normalized: Result<Normalized, ReasonCode>,
    ) -> (AuthorizationDecision, AuditRecord) {
        let now = Utc::now();
        let mut record = AuditRecord {
            event_type: "authorization.decision".into(),
            timestamp: now,
            request_id,
            decision_id: None,
            agent: None,
            organization: None,
            actor: None,
            action: None,
            resource: None,
            decision: Some(Outcome::Deny),
            reason_codes: vec![],
            delegation_depth: None,
            policy: None,
            protocol: normalized.as_ref().ok().map(|n| n.protocol.to_owned()),
            grant_ids: vec![],
            approval_id: None,
        };
        let deny = |record: &mut AuditRecord, reason| {
            let d = AuthorizationDecision::deny(request_id, reason);
            record.decision_id = Some(d.decision_id);
            record.reason_codes = d.reason_codes.clone();
            d
        };

        // 1. Authenticate: delegation chain + proof of possession.
        let verifier = Verifier {
            trust: &self.trust,
            revocations: self.state.as_ref(),
            audience: &self.settings.audience,
            clock: Clock {
                now: now.timestamp(),
                leeway: self.settings.clock_skew_seconds,
            },
        };
        let tokens: Vec<&str> = presented.grants.iter().map(String::as_str).collect();
        let chain = match verifier.verify_chain(&tokens) {
            Ok(c) => c,
            Err(r) => return (deny(&mut record, r), record),
        };
        record.agent = Some(chain.leaf().sub.to_string());
        record.organization = Some(chain.root().org.to_string());
        record.actor = chain.root().act.as_ref().map(|a| a.sub.clone());
        record.delegation_depth = Some(chain.grants.len() - 1);
        record.grant_ids = chain.grants.iter().map(|g| g.jti.clone()).collect();

        let Some(proof) = presented.proof.as_deref() else {
            return (deny(&mut record, ReasonCode::ProofMissing), record);
        };
        if let Err(r) = verifier.verify_proof(
            &chain,
            proof,
            presented.body,
            &self.replay,
            self.settings.proof_max_age_seconds,
        ) {
            return (deny(&mut record, r), record);
        }

        // 2. Normalize.
        let n = match normalized {
            Ok(n) if n.action.is_exact() && n.resource.is_exact() => n,
            Ok(_) => return (deny(&mut record, ReasonCode::InvalidRequest), record),
            Err(r) => return (deny(&mut record, r), record),
        };
        record.action = Some(n.action.to_string());
        record.resource = Some(n.resource.to_string());
        let req = build_request(request_id, now, &chain, n);

        // 3. Delegated authority: the chain must actually carry this action.
        let auth = &req.authority;
        let chain_check = if !set_covers(&auth.capabilities, &req.action) {
            Some(ReasonCode::CapabilityNotInChain)
        } else if !resources_cover(&auth.resources, &req.resource) {
            Some(ReasonCode::ResourceNotInChain)
        } else if auth
            .max_value
            .is_some_and(|m| req.context.value.is_none_or(|v| v > m))
        {
            Some(ReasonCode::ValueExceedsGrant)
        } else if !self.trust.accepts(&req.organization, &req.action) {
            // 4. Receiving organization's trust relationship.
            Some(ReasonCode::TrustDomainDenies)
        } else {
            None
        };
        if let Some(r) = chain_check {
            return (deny(&mut record, r), record);
        }

        // 5. Policy.
        let policy = match self.pdp.evaluate(&req).await {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "policy evaluation failed; denying");
                return (deny(&mut record, ReasonCode::PolicyUnavailable), record);
            }
        };
        record.policy = policy.policy_id.clone();

        let mut decision = AuthorizationDecision {
            outcome: policy.outcome,
            decision_id: Uuid::now_v7(),
            request_id,
            matched_policy: policy.policy_id.clone(),
            matched_rule: policy.rule_id.clone(),
            reason_codes: vec![policy.reason],
            obligations: vec![],
            expires_at: Some(ts(chain.earliest_expiry())),
        };

        // 6. Human approval.
        if policy.outcome == Outcome::RequireApproval {
            let fp = fingerprint(&req);
            if let Some(id) = presented.approval_id.as_deref() {
                let consumed = Uuid::parse_str(id)
                    .ok()
                    .map(|id| (id, self.state.consume_approval(&id, &fp, now.timestamp())));
                match consumed {
                    Some((id, Ok(true))) => {
                        decision.outcome = Outcome::Allow;
                        decision.reason_codes = vec![ReasonCode::ApprovalGranted];
                        record.approval_id = Some(id);
                    }
                    Some((_, Err(e))) => {
                        tracing::error!(error = %e, "approval store failed; denying");
                        return (deny(&mut record, ReasonCode::StateUnavailable), record);
                    }
                    _ => return (deny(&mut record, ReasonCode::ApprovalInvalid), record),
                }
            } else {
                let approval = ApprovalRequest {
                    id: Uuid::now_v7(),
                    request_id,
                    requested_by: req.subject.clone(),
                    actor: req.actor.clone(),
                    action: req.action.clone(),
                    resource: req.resource.clone(),
                    value: req.context.value,
                    reason: policy.reason,
                    policy: policy.policy_id.clone(),
                    fingerprint: fp,
                    created_at: now,
                    expires_at: now + chrono::Duration::seconds(self.settings.approval_ttl_seconds),
                    status: ApprovalStatus::Pending,
                    decided_by: None,
                    decided_at: None,
                };
                if let Err(e) = self.state.create_approval(&approval) {
                    tracing::error!(error = %e, "approval store failed; denying");
                    return (deny(&mut record, ReasonCode::StateUnavailable), record);
                }
                record.approval_id = Some(approval.id);
                decision.obligations = vec![Obligation::HumanApproval {
                    approval_id: approval.id,
                }];
            }
        }

        record.decision_id = Some(decision.decision_id);
        record.decision = Some(decision.outcome);
        record.reason_codes = decision.reason_codes.clone();
        (decision, record)
    }
}

fn build_request(
    request_id: Uuid,
    now: DateTime<Utc>,
    chain: &VerifiedChain,
    n: Normalized,
) -> AuthorizationRequest {
    let (root, leaf) = (chain.root(), chain.leaf());
    AuthorizationRequest {
        request_id,
        timestamp: now,
        subject: leaf.sub.clone(),
        actor: root.act.as_ref().map(|a| a.sub.clone()),
        organization: root.org.clone(),
        action: n.action,
        resource: n.resource,
        purpose: leaf.purpose.clone(),
        delegation_chain: chain
            .grants
            .iter()
            .map(|g| DelegationLink {
                grant_id: g.jti.clone(),
                issuer: g.iss.clone(),
                subject: g.sub.clone(),
                capabilities: g.cap.clone(),
                expires_at: ts(g.exp),
            })
            .collect(),
        authority: GrantedAuthority {
            capabilities: leaf.cap.clone(),
            resources: leaf.res.clone(),
            max_value: leaf.max_value,
            expires_at: ts(chain.earliest_expiry()),
        },
        context: RequestContext {
            value: n.value,
            protocol: n.protocol.to_owned(),
            attributes: n.attributes,
        },
    }
}
