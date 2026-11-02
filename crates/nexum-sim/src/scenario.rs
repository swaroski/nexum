//! The `EvalSuite` scenario DSL (`nexum.dev/v1alpha1`).

use nexum_core::{AgentId, Capability, Outcome, ReasonCode, ResourcePattern, TrustDomain};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const KIND: &str = "EvalSuite";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suite {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    /// e.g. `delegation`, `identity`, `protocol`. Reported with each result.
    #[serde(default)]
    pub category: Option<String>,
    /// The calling organization. Must be in the gateway's trust store.
    pub org: TrustDomain,
    pub scenarios: Vec<Scenario>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// The security property this scenario protects, in one sentence.
    #[serde(default)]
    pub invariant: Option<String>,
    /// Root first; each later grant is delegated by the previous holder.
    pub grants: Vec<GrantSpec>,
    #[serde(default)]
    pub attack: Option<Attack>,
    pub request: RequestSpec,
    pub expect: Outcome,
    /// Expected reason code, e.g. `NX-4032`.
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantSpec {
    pub sub: AgentId,
    pub cap: Vec<Capability>,
    /// Required on the root; delegations inherit the parent's when absent.
    #[serde(default)]
    pub res: Option<Vec<ResourcePattern>>,
    #[serde(default)]
    pub dcap: Vec<Capability>,
    #[serde(default)]
    pub max_depth: u32,
    /// Delegations inherit the parent's when absent.
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub max_value: Option<u64>,
    /// Lifetime from now. Default 300.
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
}

/// Either a decision-API request (`action` + `resource`), or a protocol
/// message sent through the MCP/A2A adapter configured under that name.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSpec {
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub value: Option<u64>,
    #[serde(default)]
    pub mcp: Option<RpcSpec>,
    #[serde(default)]
    pub a2a: Option<RpcSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcSpec {
    /// MCP server or A2A agent name from `nexum.yaml`.
    pub target: String,
    /// JSON-RPC message, or `raw` for exact bytes (e.g. duplicate keys).
    #[serde(default)]
    pub message: Option<Value>,
    #[serde(default)]
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Attack {
    /// The same request and proof sent twice.
    Replay,
    /// Another key signs the proof for the leaf's grants.
    StolenGrant,
    /// The whole chain expired an hour ago.
    Expired,
    /// The proof was signed ten minutes ago.
    StaleProof,
    /// The chain was issued for a different gateway.
    WrongAudience,
    /// The root is signed by a key the gateway does not trust.
    UntrustedIssuer,
    /// The root claims an organization the gateway has never heard of.
    UnknownOrganization,
    /// The root's lifetime is extended after signing.
    Tampered,
    /// The root grant was revoked.
    RevokedParent,
    /// The requesting agent was revoked.
    RevokedAgent,
    /// The receiving organization revoked trust in the caller's.
    RevokedTrust,
    /// The proof signs a different body than the one sent.
    BodySwap,
}

impl Attack {
    pub const ALL: [Attack; 12] = [
        Attack::Replay,
        Attack::StolenGrant,
        Attack::Expired,
        Attack::StaleProof,
        Attack::WrongAudience,
        Attack::UntrustedIssuer,
        Attack::UnknownOrganization,
        Attack::Tampered,
        Attack::RevokedParent,
        Attack::RevokedAgent,
        Attack::RevokedTrust,
        Attack::BodySwap,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Attack::Replay => "replay",
            Attack::StolenGrant => "stolen-grant",
            Attack::Expired => "expired",
            Attack::StaleProof => "stale-proof",
            Attack::WrongAudience => "wrong-audience",
            Attack::UntrustedIssuer => "untrusted-issuer",
            Attack::UnknownOrganization => "unknown-organization",
            Attack::Tampered => "tampered",
            Attack::RevokedParent => "revoked-parent",
            Attack::RevokedAgent => "revoked-agent",
            Attack::RevokedTrust => "revoked-trust",
            Attack::BodySwap => "body-swap",
        }
    }

    /// The reason the gateway must give.
    pub fn reason(self) -> ReasonCode {
        match self {
            Attack::Replay => ReasonCode::ProofReplayed,
            Attack::StolenGrant => ReasonCode::ProofInvalid,
            Attack::Expired => ReasonCode::GrantExpired,
            Attack::StaleProof => ReasonCode::ProofStale,
            Attack::WrongAudience => ReasonCode::WrongAudience,
            Attack::UntrustedIssuer => ReasonCode::UnknownKey,
            Attack::UnknownOrganization => ReasonCode::UnknownIssuer,
            Attack::Tampered => ReasonCode::InvalidSignature,
            Attack::RevokedParent => ReasonCode::GrantRevoked,
            Attack::RevokedAgent => ReasonCode::AgentRevoked,
            Attack::RevokedTrust => ReasonCode::TrustRevoked,
            Attack::BodySwap => ReasonCode::ProofBindingMismatch,
        }
    }
}

/// Explicit scenarios plus one generated attack variant per ALLOW baseline.
pub fn expand(suite: &Suite) -> Vec<Scenario> {
    let mut out = suite.scenarios.clone();
    for s in &suite.scenarios {
        if s.expect != Outcome::Allow || s.attack.is_some() {
            continue;
        }
        for a in Attack::ALL {
            out.push(Scenario {
                name: format!("{} / {}", s.name, a.name()),
                attack: Some(a),
                expect: Outcome::Deny,
                code: Some(a.reason().code().to_owned()),
                ..s.clone()
            });
        }
    }
    out
}
