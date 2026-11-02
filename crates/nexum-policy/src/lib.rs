//! Built-in declarative policy engine.
//!
//! Deliberately small: subject matching, action/resource patterns, two value
//! conditions, an optional purpose, and delegation rules. Combining is
//! deny-overrides: DENY > REQUIRE_APPROVAL > ALLOW, and no matching rule is
//! DENY. Anything richer belongs in an external PDP (OPA, Cedar, ...) behind
//! the same [`PolicyDecisionPoint`] trait.

#![forbid(unsafe_code)]

use nexum_core::{
    AuthorizationRequest, Capability, Outcome, PolicyDecisionPoint, PolicyResult, ReasonCode,
    ResourcePattern, set_covers,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy parse error: {0}")]
    Parse(String),
    #[error("policy {policy}: {msg}")]
    Invalid { policy: String, msg: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
    Approval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    /// Trust domain, or `*` for any trusted domain.
    pub organization: String,
    /// Agent SPIFFE ID, or a prefix ending in `*`. Default: any agent.
    #[serde(default)]
    pub agent: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conditions {
    /// Matches when `value` is present and `<= max_value`.
    pub max_value: Option<u64>,
    /// Matches when `value` is present and `> value_above`.
    pub value_above: Option<u64>,
    /// Matches when the chain's purpose equals this.
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default)]
    pub id: Option<String>,
    pub action: Capability,
    #[serde(default)]
    pub resource: Option<ResourcePattern>,
    pub effect: Effect,
    #[serde(default)]
    pub conditions: Conditions,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationRules {
    /// If set, only these capabilities may be exercised through delegation.
    #[serde(default)]
    pub allowed: Option<Vec<Capability>>,
    /// Never exercisable through delegation.
    #[serde(default)]
    pub forbidden: Vec<Capability>,
    /// Maximum hops below the root grant.
    #[serde(default)]
    pub max_depth: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub id: String,
    pub subjects: Vec<Subject>,
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub delegation: DelegationRules,
}

fn glob(pattern: &str, value: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => value.starts_with(prefix),
        None => pattern == value,
    }
}

impl Policy {
    fn validate(&self) -> Result<(), PolicyError> {
        let bad = |msg: &str| PolicyError::Invalid {
            policy: self.id.clone(),
            msg: msg.into(),
        };
        if self.api_version != nexum_core::API_VERSION {
            return Err(bad(&format!(
                "unsupported apiVersion {:?}",
                self.api_version
            )));
        }
        if self.kind != "Policy" {
            return Err(bad("kind must be Policy"));
        }
        if self.id.is_empty() {
            return Err(bad("id is required"));
        }
        if self.subjects.is_empty() {
            return Err(bad(
                "at least one subject is required (use organization: \"*\" for all)",
            ));
        }
        for r in &self.rules {
            let c = &r.conditions;
            if let (Some(max), Some(above)) = (c.max_value, c.value_above) {
                if max <= above {
                    return Err(bad(&format!(
                        "rule {:?}: max_value <= value_above can never match",
                        r.id.as_deref().unwrap_or(r.action.as_str())
                    )));
                }
            }
        }
        Ok(())
    }

    fn applies_to(&self, req: &AuthorizationRequest) -> bool {
        self.subjects.iter().any(|s| {
            (s.organization == "*" || s.organization == req.organization.as_str())
                && s.agent
                    .as_deref()
                    .is_none_or(|a| glob(a, req.subject.as_str()))
        })
    }
}

impl Rule {
    fn matches(&self, req: &AuthorizationRequest) -> bool {
        let c = &self.conditions;
        let value = req.context.value;
        self.action.covers(&req.action)
            && self
                .resource
                .as_ref()
                .is_none_or(|r| r.covers(&req.resource))
            && c.max_value.is_none_or(|m| value.is_some_and(|v| v <= m))
            && c.value_above.is_none_or(|m| value.is_some_and(|v| v > m))
            && c.purpose
                .as_ref()
                .is_none_or(|p| req.purpose.as_ref() == Some(p))
    }
}

/// A set of policies evaluated together.
#[derive(Debug, Clone, Default)]
pub struct PolicySet {
    pub policies: Vec<Policy>,
}

impl PolicySet {
    /// Parse one or more YAML documents (`---` separated).
    pub fn from_yaml(s: &str) -> Result<Self, PolicyError> {
        let mut policies = Vec::new();
        for doc in yaml_serde::Deserializer::from_str(s) {
            let p = Policy::deserialize(doc).map_err(|e| PolicyError::Parse(e.to_string()))?;
            p.validate()?;
            policies.push(p);
        }
        if policies.is_empty() {
            return Err(PolicyError::Parse("no policy documents found".into()));
        }
        let mut ids: Vec<&str> = policies.iter().map(|p| p.id.as_str()).collect();
        ids.sort_unstable();
        if let Some(w) = ids.windows(2).find(|w| w[0] == w[1]) {
            return Err(PolicyError::Parse(format!(
                "duplicate policy id {:?}",
                w[0]
            )));
        }
        Ok(Self { policies })
    }

    /// Deterministic, side-effect-free evaluation.
    pub fn evaluate(&self, req: &AuthorizationRequest) -> PolicyResult {
        let mut cands = Vec::new();
        let depth = req.delegation_depth();
        for p in self.policies.iter().filter(|p| p.applies_to(req)) {
            if depth > 0 {
                let d = &p.delegation;
                if set_covers(&d.forbidden, &req.action)
                    || d.allowed
                        .as_ref()
                        .is_some_and(|a| !set_covers(a, &req.action))
                {
                    cands.push((
                        Outcome::Deny,
                        p,
                        None,
                        ReasonCode::DelegationForbiddenByPolicy,
                    ));
                }
                if d.max_depth.is_some_and(|m| depth > m) {
                    cands.push((Outcome::Deny, p, None, ReasonCode::DelegationDepthPolicy));
                }
            }
            for r in p.rules.iter().filter(|r| r.matches(req)) {
                let (o, why) = match r.effect {
                    Effect::Allow => (Outcome::Allow, ReasonCode::PolicyAllow),
                    Effect::Deny => (Outcome::Deny, ReasonCode::PolicyDeny),
                    Effect::Approval => (Outcome::RequireApproval, ReasonCode::ApprovalRequired),
                };
                cands.push((o, p, Some(r), why));
            }
        }
        let rank = |o: &Outcome| match o {
            Outcome::Allow => 0,
            Outcome::RequireApproval => 1,
            Outcome::Deny => 2,
        };
        // First candidate of the highest rank wins (rev + max = first max).
        match cands.into_iter().rev().max_by_key(|c| rank(&c.0)) {
            Some((outcome, p, r, reason)) => PolicyResult {
                outcome,
                policy_id: Some(p.id.clone()),
                rule_id: r.map(|r| r.id.clone().unwrap_or_else(|| r.action.to_string())),
                reason,
            },
            None => PolicyResult {
                outcome: Outcome::Deny,
                policy_id: None,
                rule_id: None,
                reason: ReasonCode::NoMatchingPolicy,
            },
        }
    }
}

/// The built-in PDP: a [`PolicySet`] loaded from YAML.
#[derive(Debug)]
pub struct BuiltinPdp {
    pub set: PolicySet,
}

#[async_trait::async_trait]
impl PolicyDecisionPoint for BuiltinPdp {
    async fn evaluate(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<PolicyResult, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.set.evaluate(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexum_core::*;

    const POLICY: &str = r#"
apiVersion: nexum.dev/v1alpha1
kind: Policy
id: abc-supplier-v1
subjects:
  - organization: xyz.com
rules:
  - { id: read-inventory, action: inventory.read, resource: "supplier://abc/*", effect: allow }
  - { action: pricing.read, effect: allow }
  - { id: quote-auto, action: quote.create, effect: allow, conditions: { max_value: 100000 } }
  - { id: quote-big, action: quote.create, effect: approval, conditions: { value_above: 100000 } }
  - { action: payment.execute, effect: deny }
  - { action: customer.export, effect: deny }
delegation:
  allowed: [inventory.read, pricing.read]
  forbidden: [payment.execute]
  max_depth: 2
"#;

    fn req(action: &str, value: Option<u64>, depth: usize) -> AuthorizationRequest {
        let sub = AgentId::parse("spiffe://xyz.com/agents/procurement").unwrap();
        let link = DelegationLink {
            grant_id: "g".into(),
            issuer: "i".into(),
            subject: sub.clone(),
            capabilities: vec![],
            expires_at: chrono::Utc::now(),
        };
        AuthorizationRequest {
            request_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            subject: sub,
            actor: None,
            organization: TrustDomain::parse("xyz.com").unwrap(),
            action: Capability::parse(action).unwrap(),
            resource: ResourcePattern::parse("supplier://abc/sku/1").unwrap(),
            purpose: None,
            delegation_chain: vec![link; depth + 1],
            authority: GrantedAuthority {
                capabilities: vec![],
                resources: vec![],
                max_value: None,
                expires_at: chrono::Utc::now(),
            },
            context: RequestContext {
                value,
                ..Default::default()
            },
        }
    }

    fn eval(action: &str, value: Option<u64>, depth: usize) -> (Outcome, ReasonCode) {
        let set = PolicySet::from_yaml(POLICY).unwrap();
        let r = set.evaluate(&req(action, value, depth));
        (r.outcome, r.reason)
    }

    #[test]
    fn rules_and_combining() {
        assert_eq!(
            eval("inventory.read", None, 0),
            (Outcome::Allow, ReasonCode::PolicyAllow)
        );
        assert_eq!(eval("quote.create", Some(500), 0).0, Outcome::Allow);
        assert_eq!(
            eval("quote.create", Some(250_000), 0).0,
            Outcome::RequireApproval
        );
        // Missing value never satisfies a value condition: default deny.
        assert_eq!(
            eval("quote.create", None, 0),
            (Outcome::Deny, ReasonCode::NoMatchingPolicy)
        );
        assert_eq!(
            eval("payment.execute", Some(1), 0),
            (Outcome::Deny, ReasonCode::PolicyDeny)
        );
        assert_eq!(
            eval("unknown.thing", None, 0),
            (Outcome::Deny, ReasonCode::NoMatchingPolicy)
        );
    }

    #[test]
    fn delegation_rules() {
        assert_eq!(eval("inventory.read", None, 1).0, Outcome::Allow);
        assert_eq!(
            eval("quote.create", Some(1), 1),
            (Outcome::Deny, ReasonCode::DelegationForbiddenByPolicy)
        );
        assert_eq!(
            eval("inventory.read", None, 3),
            (Outcome::Deny, ReasonCode::DelegationDepthPolicy)
        );
    }

    #[test]
    fn other_orgs_get_nothing() {
        let set = PolicySet::from_yaml(POLICY).unwrap();
        let mut r = req("inventory.read", None, 0);
        r.organization = TrustDomain::parse("evil.com").unwrap();
        assert_eq!(set.evaluate(&r).reason, ReasonCode::NoMatchingPolicy);
    }

    #[test]
    fn adding_a_deny_rule_never_increases_permissions() {
        let base = PolicySet::from_yaml(POLICY).unwrap();
        let mut stricter = base.clone();
        stricter.policies[0].rules.push(Rule {
            id: None,
            action: Capability::parse("inventory.*").unwrap(),
            resource: None,
            effect: Effect::Deny,
            conditions: Conditions::default(),
        });
        for a in [
            "inventory.read",
            "pricing.read",
            "quote.create",
            "payment.execute",
        ] {
            for v in [None, Some(10), Some(500_000)] {
                let (b, s) = (
                    base.evaluate(&req(a, v, 0)),
                    stricter.evaluate(&req(a, v, 0)),
                );
                let rank = |o| match o {
                    Outcome::Allow => 0,
                    Outcome::RequireApproval => 1,
                    Outcome::Deny => 2,
                };
                assert!(rank(s.outcome) >= rank(b.outcome), "{a} {v:?}");
            }
        }
    }

    #[test]
    fn rejects_bad_policies() {
        assert!(
            PolicySet::from_yaml("apiVersion: v0\nkind: Policy\nid: x\nsubjects: []\nrules: []")
                .is_err()
        );
        let typo = POLICY.replace("effect: deny", "efect: deny");
        assert!(
            PolicySet::from_yaml(&typo).is_err(),
            "unknown fields must fail"
        );
        let bad_effect = POLICY.replace("effect: deny", "effect: maybe");
        assert!(PolicySet::from_yaml(&bad_effect).is_err());
        let dup = format!("{POLICY}\n---\n{POLICY}");
        assert!(PolicySet::from_yaml(&dup).is_err());
    }
}
