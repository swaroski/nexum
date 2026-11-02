//! The canonical, protocol-independent authorization model.
//!
//! Every adapter (HTTP, MCP, A2A, ...) normalizes into an
//! [`AuthorizationRequest`]. Nothing in here knows about frameworks, clouds,
//! models or wire protocols; those appear only as opaque context metadata.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AgentId, Capability, ResourcePattern, TrustDomain};

/// One verified hop of a delegation chain (root first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationLink {
    pub grant_id: String,
    pub issuer: String,
    pub subject: AgentId,
    pub capabilities: Vec<Capability>,
    pub expires_at: DateTime<Utc>,
}

/// The authority the presenting agent actually holds after chain verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantedAuthority {
    pub capabilities: Vec<Capability>,
    pub resources: Vec<ResourcePattern>,
    /// Upper bound on `RequestContext::value` carried by the grant, if any.
    pub max_value: Option<u64>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RequestContext {
    /// Monetary or quantity value of the action in integer units (e.g. USD).
    pub value: Option<u64>,
    /// Which adapter produced this request (`http`, `mcp`, `a2a`, ...).
    /// Informational only; policy must not need it to be correct.
    pub protocol: String,
    /// Non-sensitive, adapter-provided attributes.
    pub attributes: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub request_id: Uuid,
    pub timestamp: DateTime<Utc>,
    /// The agent making the request (holder of the leaf grant).
    pub subject: AgentId,
    /// The human/principal on whose behalf the chain was started.
    pub actor: Option<String>,
    /// The trust domain that issued the root grant.
    pub organization: TrustDomain,
    /// A concrete action (never a wildcard).
    pub action: Capability,
    /// A concrete resource (never a pattern).
    pub resource: ResourcePattern,
    pub purpose: Option<String>,
    pub delegation_chain: Vec<DelegationLink>,
    pub authority: GrantedAuthority,
    pub context: RequestContext,
}

impl AuthorizationRequest {
    /// Number of delegation hops below the root grant.
    pub fn delegation_depth(&self) -> usize {
        self.delegation_chain.len().saturating_sub(1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Outcome {
    Allow,
    Deny,
    RequireApproval,
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Outcome::Allow => "ALLOW",
            Outcome::Deny => "DENY",
            Outcome::RequireApproval => "REQUIRE_APPROVAL",
        })
    }
}

/// Machine-readable reasons. Codes are stable once released; never reuse one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    // Grant / chain validation
    GrantMissing,
    ChainTooLong,
    MalformedGrant,
    UnsupportedAlgorithm,
    InvalidSignature,
    UnknownIssuer,
    UnknownKey,
    GrantExpired,
    GrantNotYetValid,
    GrantLifetimeTooLong,
    WrongAudience,
    BrokenChain,
    CapabilityEscalation,
    ResourceEscalation,
    DelegationDepthExceeded,
    LifetimeEscalation,
    SubjectDomainMismatch,
    ContextEscalation,
    LimitEscalation,
    // Invocation proof
    ProofMissing,
    ProofInvalid,
    ProofStale,
    ProofReplayed,
    ProofBindingMismatch,
    // Revocation
    AgentRevoked,
    GrantRevoked,
    TrustRevoked,
    KeyRevoked,
    // Authorization
    PolicyAllow,
    ApprovalRequired,
    ApprovalGranted,
    ApprovalInvalid,
    TrustDomainDenies,
    CapabilityNotInChain,
    ResourceNotInChain,
    ValueExceedsGrant,
    PolicyDeny,
    NoMatchingPolicy,
    DelegationForbiddenByPolicy,
    DelegationDepthPolicy,
    // System
    InvalidRequest,
    PolicyUnavailable,
    AuditUnavailable,
    StateUnavailable,
}

impl ReasonCode {
    pub fn code(self) -> &'static str {
        use ReasonCode::*;
        match self {
            GrantMissing => "NX-1001",
            ChainTooLong => "NX-1002",
            MalformedGrant => "NX-1003",
            UnsupportedAlgorithm => "NX-1004",
            InvalidSignature => "NX-1005",
            UnknownIssuer => "NX-1006",
            UnknownKey => "NX-1007",
            GrantExpired => "NX-1008",
            GrantNotYetValid => "NX-1009",
            GrantLifetimeTooLong => "NX-1010",
            WrongAudience => "NX-1011",
            BrokenChain => "NX-1012",
            CapabilityEscalation => "NX-1013",
            ResourceEscalation => "NX-1014",
            DelegationDepthExceeded => "NX-1015",
            LifetimeEscalation => "NX-1016",
            SubjectDomainMismatch => "NX-1017",
            ContextEscalation => "NX-1018",
            LimitEscalation => "NX-1019",
            ProofMissing => "NX-2001",
            ProofInvalid => "NX-2002",
            ProofStale => "NX-2003",
            ProofReplayed => "NX-2004",
            ProofBindingMismatch => "NX-2005",
            AgentRevoked => "NX-3001",
            GrantRevoked => "NX-3002",
            TrustRevoked => "NX-3003",
            KeyRevoked => "NX-3004",
            PolicyAllow => "NX-4001",
            ApprovalRequired => "NX-4002",
            ApprovalGranted => "NX-4003",
            ApprovalInvalid => "NX-4004",
            TrustDomainDenies => "NX-4031",
            CapabilityNotInChain => "NX-4032",
            ResourceNotInChain => "NX-4033",
            ValueExceedsGrant => "NX-4034",
            PolicyDeny => "NX-4035",
            NoMatchingPolicy => "NX-4036",
            DelegationForbiddenByPolicy => "NX-4037",
            DelegationDepthPolicy => "NX-4038",
            InvalidRequest => "NX-5001",
            PolicyUnavailable => "NX-5002",
            AuditUnavailable => "NX-5003",
            StateUnavailable => "NX-5004",
        }
    }

    pub fn describe(self) -> &'static str {
        use ReasonCode::*;
        match self {
            GrantMissing => "No delegation grant was presented.",
            ChainTooLong => "The delegation chain exceeds the maximum supported length.",
            MalformedGrant => "A grant could not be parsed.",
            UnsupportedAlgorithm => "A grant or proof uses an algorithm other than EdDSA.",
            InvalidSignature => "A signature did not verify.",
            UnknownIssuer => "The root grant was issued by an untrusted or unknown issuer.",
            UnknownKey => "The signing key is not published by the issuing trust domain.",
            GrantExpired => "A grant in the chain has expired.",
            GrantNotYetValid => "A grant in the chain is not yet valid.",
            GrantLifetimeTooLong => "A grant's lifetime exceeds what the trust domain allows.",
            WrongAudience => "A grant is not addressed to this gateway.",
            BrokenChain => "A grant does not link to its parent (issuer or parent hash mismatch).",
            CapabilityEscalation => {
                "A delegated grant claims capabilities its parent may not delegate."
            }
            ResourceEscalation => "A delegated grant claims resources outside its parent's.",
            DelegationDepthExceeded => "The parent grant does not permit further delegation.",
            LifetimeEscalation => "A delegated grant outlives its parent.",
            SubjectDomainMismatch => "An agent identity is outside the issuing trust domain.",
            ContextEscalation => {
                "A delegated grant changes the actor, purpose or audience of its parent."
            }
            LimitEscalation => "A delegated grant raises its parent's value limit.",
            ProofMissing => "No proof of possession was presented.",
            ProofInvalid => "The proof of possession is invalid.",
            ProofStale => "The proof of possession is too old or from the future.",
            ProofReplayed => "The proof of possession has already been used.",
            ProofBindingMismatch => {
                "The proof is not bound to this grant, gateway or request body."
            }
            AgentRevoked => "An agent in the chain has been revoked.",
            GrantRevoked => "A grant in the chain has been revoked.",
            TrustRevoked => "Trust in the issuing organization has been revoked.",
            KeyRevoked => "A signing key in the chain has been revoked.",
            PolicyAllow => "Allowed by policy.",
            ApprovalRequired => "Policy requires human approval for this action.",
            ApprovalGranted => "A matching human approval was presented and consumed.",
            ApprovalInvalid => {
                "The presented approval is unknown, unapproved, expired, used, or for a different request."
            }
            TrustDomainDenies => {
                "The receiving organization does not accept this capability from the issuing organization."
            }
            CapabilityNotInChain => {
                "The requested capability was not present in the delegation chain."
            }
            ResourceNotInChain => "The requested resource is outside the delegated resources.",
            ValueExceedsGrant => "The request value exceeds the limit in the delegation grant.",
            PolicyDeny => "Denied by policy.",
            NoMatchingPolicy => "No policy rule allows this action (default deny).",
            DelegationForbiddenByPolicy => {
                "Policy forbids exercising this capability through delegation."
            }
            DelegationDepthPolicy => "The delegation chain is deeper than policy allows.",
            InvalidRequest => "The request could not be normalized.",
            PolicyUnavailable => "The policy decision point failed; failing closed.",
            AuditUnavailable => "The audit log could not be written; failing closed.",
            StateUnavailable => {
                "Local state (revocations/approvals) is unavailable; failing closed."
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Obligation {
    /// The caller must obtain this approval and retry with it.
    HumanApproval { approval_id: Uuid },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    pub outcome: Outcome,
    pub decision_id: Uuid,
    pub request_id: Uuid,
    pub matched_policy: Option<String>,
    pub matched_rule: Option<String>,
    pub reason_codes: Vec<ReasonCode>,
    pub obligations: Vec<Obligation>,
    /// Earliest expiry in the delegation chain; the decision is not valid past it.
    pub expires_at: Option<DateTime<Utc>>,
}

impl AuthorizationDecision {
    pub fn deny(request_id: Uuid, reason: ReasonCode) -> Self {
        Self {
            outcome: Outcome::Deny,
            decision_id: Uuid::now_v7(),
            request_id,
            matched_policy: None,
            matched_rule: None,
            reason_codes: vec![reason],
            obligations: vec![],
            expires_at: None,
        }
    }

    /// The primary (first) reason.
    pub fn primary_reason(&self) -> Option<ReasonCode> {
        self.reason_codes.first().copied()
    }
}

/// What a policy decision point returns. The gateway composes this with
/// chain, trust and approval checks into the final [`AuthorizationDecision`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyResult {
    pub outcome: Outcome,
    pub policy_id: Option<String>,
    pub rule_id: Option<String>,
    pub reason: ReasonCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Consumed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub request_id: Uuid,
    pub requested_by: AgentId,
    pub actor: Option<String>,
    pub action: Capability,
    pub resource: ResourcePattern,
    pub value: Option<u64>,
    pub reason: ReasonCode,
    pub policy: Option<String>,
    /// Binds the approval to exactly one (subject, actor, action, resource, value).
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: ApprovalStatus,
    pub decided_by: Option<String>,
    pub decided_at: Option<DateTime<Utc>>,
}

/// Something that can be revoked locally.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum RevocationTarget {
    Agent(String),
    Grant(String),
    TrustDomain(String),
    Key(String),
}

impl RevocationTarget {
    pub fn kind(&self) -> &'static str {
        match self {
            RevocationTarget::Agent(_) => "agent",
            RevocationTarget::Grant(_) => "grant",
            RevocationTarget::TrustDomain(_) => "trust_domain",
            RevocationTarget::Key(_) => "key",
        }
    }

    pub fn value(&self) -> &str {
        match self {
            RevocationTarget::Agent(v)
            | RevocationTarget::Grant(v)
            | RevocationTarget::TrustDomain(v)
            | RevocationTarget::Key(v) => v,
        }
    }
}

/// Normalized agent metadata, used by the local registry and translated
/// to/from protocol-specific discovery documents (e.g. A2A Agent Cards).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentDescriptor {
    pub id: AgentId,
    pub name: String,
    pub organization: TrustDomain,
    pub description: Option<String>,
    pub owner: Option<String>,
    pub environment: Option<String>,
    pub framework: Option<String>,
    pub capabilities: Vec<Capability>,
    pub protocols: Vec<String>,
    pub endpoint: Option<String>,
    /// Public verification key as an Ed25519 JWK.
    pub public_key: Option<serde_json::Value>,
    pub status: AgentStatus,
    pub metadata: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Active,
    Revoked,
}
