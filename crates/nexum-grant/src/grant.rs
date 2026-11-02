//! `DelegationGrant`: a short-lived, audience-bound, holder-of-key JWT.
//!
//! Claim names follow existing registries where one exists: `iss`, `sub`,
//! `aud`, `iat`, `nbf`, `exp`, `jti` (RFC 7519), `act` (RFC 8693 token
//! exchange actor), `cnf` (RFC 7800 proof-of-possession key). Nexum-specific
//! claims are kept few and explicit; unknown claims are rejected so that a
//! restriction we do not understand is never silently ignored.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use nexum_core::{AgentId, Capability, ResourcePattern, TrustDomain, is_attenuation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::keys::{Jwk, KeyPair};
use crate::{GrantError, jws};

pub const GRANT_TYP: &str = "nexum-grant+jwt";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    /// The human or service principal on whose behalf the chain acts.
    pub sub: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmation {
    pub jwk: Jwk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantClaims {
    pub jti: String,
    /// Root: the organization issuer URI. Child: the parent grant's `sub`.
    pub iss: String,
    pub sub: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Actor>,
    pub org: TrustDomain,
    /// Gateways (trust domains) permitted to accept this grant.
    pub aud: Vec<String>,
    pub cap: Vec<Capability>,
    pub res: Vec<ResourcePattern>,
    /// Capabilities the holder may delegate further (must be ⊆ `cap`).
    #[serde(default)]
    pub dcap: Vec<Capability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    /// Remaining delegation depth. 0 = may not delegate.
    #[serde(default)]
    pub mdd: u32,
    /// base64url(SHA-256(parent compact token)). Absent only on root grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_value: Option<u64>,
    pub cnf: Confirmation,
}

pub fn token_hash(token: &str) -> String {
    B64.encode(Sha256::digest(token.as_bytes()))
}

pub fn sign_grant(claims: &GrantClaims, key: &KeyPair) -> Result<String, GrantError> {
    jws::sign(claims, GRANT_TYP, Some(&key.kid), &key.signing)
}

/// What a holder asks for when delegating to a child agent.
#[derive(Debug, Clone)]
pub struct DelegationSpec {
    pub sub: AgentId,
    pub holder: Jwk,
    pub cap: Vec<Capability>,
    /// `None` = inherit the parent's resources.
    pub res: Option<Vec<ResourcePattern>>,
    pub dcap: Vec<Capability>,
    pub mdd: u32,
    pub ttl_seconds: i64,
    /// `None` = inherit the parent's audience.
    pub aud: Option<Vec<String>>,
    pub max_value: Option<u64>,
}

/// Build (unsigned) child claims from a verified parent. Fails early with the
/// same reason the gateway would give, so escalation is caught at issue time.
pub fn child_claims(
    parent: &GrantClaims,
    parent_token: &str,
    spec: DelegationSpec,
    now: i64,
) -> Result<GrantClaims, nexum_core::ReasonCode> {
    let child = GrantClaims {
        jti: uuid::Uuid::new_v4().to_string(),
        iss: parent.sub.to_string(),
        sub: spec.sub,
        act: parent.act.clone(),
        org: parent.org.clone(),
        aud: spec.aud.unwrap_or_else(|| parent.aud.clone()),
        cap: spec.cap,
        res: spec.res.unwrap_or_else(|| parent.res.clone()),
        dcap: spec.dcap,
        purpose: parent.purpose.clone(),
        iat: now,
        nbf: now,
        exp: (now + spec.ttl_seconds).min(parent.exp),
        mdd: spec.mdd,
        prt: Some(token_hash(parent_token)),
        max_value: spec.max_value.or(parent.max_value),
        cnf: Confirmation { jwk: spec.holder },
    };
    check_self(&child)?;
    check_link(parent, parent_token, &child)?;
    Ok(child)
}

/// Invariants of a single grant, independent of its parent.
pub(crate) fn check_self(c: &GrantClaims) -> Result<(), nexum_core::ReasonCode> {
    use nexum_core::ReasonCode::*;
    if c.jti.is_empty() || c.jti.len() > 128 || c.aud.is_empty() || c.exp <= c.nbf {
        return Err(MalformedGrant);
    }
    if !is_attenuation(&c.dcap, &c.cap) {
        return Err(CapabilityEscalation);
    }
    if c.sub.trust_domain() != c.org {
        return Err(SubjectDomainMismatch);
    }
    Ok(())
}

/// Attenuation rules between a parent and a child grant. Signature
/// verification is done separately by the caller.
pub(crate) fn check_link(
    parent: &GrantClaims,
    parent_token: &str,
    child: &GrantClaims,
) -> Result<(), nexum_core::ReasonCode> {
    use nexum_core::ReasonCode::*;
    if child.iss != parent.sub.as_str() || child.prt.as_deref() != Some(&token_hash(parent_token)) {
        return Err(BrokenChain);
    }
    if parent.mdd == 0 || child.mdd >= parent.mdd {
        return Err(DelegationDepthExceeded);
    }
    if !is_attenuation(&child.cap, &parent.dcap) {
        return Err(CapabilityEscalation);
    }
    if !nexum_core::is_resource_attenuation(&child.res, &parent.res) {
        return Err(ResourceEscalation);
    }
    if child.exp > parent.exp || child.nbf < parent.nbf {
        return Err(LifetimeEscalation);
    }
    if child.org != parent.org {
        return Err(SubjectDomainMismatch);
    }
    let purpose_ok = parent.purpose.is_none() || child.purpose == parent.purpose;
    let aud_ok = child.aud.iter().all(|a| parent.aud.contains(a));
    if child.act != parent.act || !purpose_ok || !aud_ok {
        return Err(ContextEscalation);
    }
    if let Some(p) = parent.max_value {
        if child.max_value.is_none_or(|c| c > p) {
            return Err(LimitEscalation);
        }
    }
    Ok(())
}
