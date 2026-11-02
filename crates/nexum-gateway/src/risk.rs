//! Explainable risk findings over a gateway's own configuration and history.
//!
//! Every finding names its subject, its evidence and what to do about it.
//! There is deliberately no aggregate score: a number would hide the findings.

use std::collections::BTreeMap;

use nexum_audit::AuditEvent;
use nexum_core::{AgentDescriptor, AgentStatus, TrustDomain};
use nexum_grant::TrustStore;
use nexum_policy::{Effect, PolicySet};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    High,
    Medium,
    Low,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// Stable identifier, e.g. `trust.wildcard`.
    pub id: &'static str,
    pub subject: String,
    pub evidence: String,
    pub fix: &'static str,
}

/// Capabilities whose misuse moves money, data or control.
const HIGH_IMPACT: [&str; 9] = [
    "payment", "refund", "transfer", "export", "delete", "admin", "write", "bank", "execute",
];

fn high_impact(cap: &str) -> bool {
    cap.split(['.', '_', '-']).any(|w| HIGH_IMPACT.contains(&w))
}

fn wildcard(cap: &str) -> bool {
    cap == "*" || cap.ends_with(".*")
}

/// Scan trust, policy, registry and (recent) audit. `own` is this gateway's
/// trust domain; `since` bounds which audit events count as recent.
pub fn scan(
    own: &TrustDomain,
    trust: &TrustStore,
    policy: Option<&PolicySet>,
    agents: &[AgentDescriptor],
    events: &[AuditEvent],
    since: chrono::DateTime<chrono::Utc>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut add = |severity, id, subject: String, evidence: String, fix| {
        out.push(Finding {
            severity,
            id,
            subject,
            evidence,
            fix,
        });
    };

    for (name, d) in &trust.trust_domains {
        let external = name != own;
        let wild: Vec<&str> = d
            .allow
            .iter()
            .map(|c| c.as_str())
            .filter(|c| wildcard(c))
            .collect();
        if !wild.is_empty() {
            add(
                if external {
                    Severity::High
                } else {
                    Severity::Medium
                },
                "trust.wildcard",
                name.to_string(),
                format!(
                    "{} organization may exercise {}",
                    if external { "external" } else { "own" },
                    wild.join(", ")
                ),
                "List the capabilities you accept from this organization explicitly; policy should not be the only limit.",
            );
        }
        let risky: Vec<&str> = d
            .allow
            .iter()
            .map(|c| c.as_str())
            .filter(|c| external && !wildcard(c) && high_impact(c))
            .collect();
        if !risky.is_empty() {
            add(
                Severity::Medium,
                "trust.high_impact",
                name.to_string(),
                format!("external organization trusted for {}", risky.join(", ")),
                "Confirm this is intended; require approval for these actions in policy.",
            );
        }
        if d.max_grant_ttl_seconds > 3600 {
            add(
                Severity::Medium,
                "trust.long_lived_grants",
                name.to_string(),
                format!(
                    "accepts grants valid for up to {}s",
                    d.max_grant_ttl_seconds
                ),
                "Keep agent authority short-lived (≤ 1 hour); agents should request fresh grants.",
            );
        }
    }

    for p in policy.iter().flat_map(|s| &s.policies) {
        for r in &p.rules {
            let rule = r.id.clone().unwrap_or_else(|| r.action.to_string());
            if r.effect != Effect::Allow {
                continue;
            }
            if wildcard(r.action.as_str()) && r.resource.is_none() {
                add(
                    Severity::High,
                    "policy.wildcard_allow",
                    format!("{} / {rule}", p.id),
                    format!("allows {} on any resource", r.action),
                    "Allow specific actions, scoped to resources.",
                );
            }
            let gated = p.rules.iter().any(|o| {
                o.action == r.action
                    && (o.effect == Effect::Approval || o.conditions.value_above.is_some())
            });
            if high_impact(r.action.as_str())
                && !wildcard(r.action.as_str())
                && r.conditions.max_value.is_none()
                && !gated
            {
                add(
                    Severity::Medium,
                    "policy.unbounded_high_impact",
                    format!("{} / {rule}", p.id),
                    format!("allows {} with no value limit or approval", r.action),
                    "Add `conditions: { max_value: … }` and an approval rule above it.",
                );
            }
        }
        if p.delegation.max_depth.is_none() && p.delegation.allowed.is_none() {
            add(
                Severity::Low,
                "policy.unbounded_delegation",
                p.id.clone(),
                "no delegation.allowed or delegation.max_depth".into(),
                "Bound what sub-agents may exercise and how deep chains may go.",
            );
        }
        if p.subjects.iter().any(|s| s.organization == "*") {
            add(
                Severity::Low,
                "policy.any_organization",
                p.id.clone(),
                "applies to every trusted organization".into(),
                "Scope policies to the organizations they are written for.",
            );
        }
    }

    for a in agents.iter().filter(|a| a.status == AgentStatus::Active) {
        if a.owner.as_deref().is_none_or(str::is_empty) {
            add(
                Severity::Low,
                "agent.no_owner",
                a.id.to_string(),
                "registered without an owner".into(),
                "Register an accountable owner (`--owner`).",
            );
        }
    }

    let mut attempts: BTreeMap<String, BTreeMap<&'static str, usize>> = BTreeMap::new();
    for e in events.iter().filter(|e| e.record.timestamp >= since) {
        let r = &e.record;
        let Some(ev) = r.reason_codes.first().and_then(|c| c.security_event()) else {
            continue;
        };
        let who = r
            .agent
            .clone()
            .unwrap_or_else(|| "(unverified caller)".into());
        *attempts.entry(who).or_default().entry(ev).or_default() += 1;
    }
    for (who, evs) in attempts {
        let serious = evs.keys().any(|e| {
            matches!(
                *e,
                "privilege_escalation_attempt"
                    | "delegation_amplification_attempt"
                    | "replay_attempt"
                    | "credential_misuse"
                    | "revoked_credential_use"
            )
        });
        add(
            if serious {
                Severity::High
            } else {
                Severity::Medium
            },
            "activity.security_events",
            who,
            evs.iter()
                .map(|(e, n)| format!("{e} ×{n}"))
                .collect::<Vec<_>>()
                .join(", "),
            "Inspect with `nexum audit search --agent …` and `nexum trace inspect`; revoke if compromised.",
        );
    }

    out.sort_by(|a, b| (a.severity, a.id, &a.subject).cmp(&(b.severity, b.id, &b.subject)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn findings_are_explained() {
        let trust: TrustStore = serde_json::from_value(serde_json::json!({
            "trust_domains": {
                "abc.com": {"issuer": "i", "keys": [], "allow": ["*"]},
                "xyz.com": {"issuer": "i", "keys": [], "allow": ["mcp.erp.*", "payment.execute"],
                            "max_grant_ttl_seconds": 86400}
            }
        }))
        .unwrap();
        let policy = PolicySet::from_yaml(
            "apiVersion: nexum.dev/v1alpha1\nkind: Policy\nid: p\nsubjects: [{organization: \"*\"}]\nrules:\n  - {id: all, action: \"*\", effect: allow}\n  - {id: pay, action: payment.execute, effect: allow}\n",
        )
        .unwrap();
        let own = TrustDomain::parse("abc.com").unwrap();
        let f = scan(&own, &trust, Some(&policy), &[], &[], chrono::Utc::now());
        let ids: Vec<(Severity, &str)> = f.iter().map(|f| (f.severity, f.id)).collect();
        for want in [
            (Severity::High, "trust.wildcard"),
            (Severity::Medium, "trust.wildcard"),
            (Severity::Medium, "trust.high_impact"),
            (Severity::Medium, "trust.long_lived_grants"),
            (Severity::High, "policy.wildcard_allow"),
            (Severity::Medium, "policy.unbounded_high_impact"),
            (Severity::Low, "policy.unbounded_delegation"),
            (Severity::Low, "policy.any_organization"),
        ] {
            assert!(ids.contains(&want), "{want:?} missing from {ids:?}");
        }
        assert!(
            f.iter()
                .all(|f| !f.evidence.is_empty() && !f.fix.is_empty())
        );
    }
}
