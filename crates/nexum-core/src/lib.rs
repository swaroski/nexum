//! Nexum core: the canonical identity, delegation and authorization model.
//!
//! This crate performs no I/O and no cryptography. It defines the types every
//! other component speaks and the extension traits external systems plug into.

#![forbid(unsafe_code)]

mod capability;
mod identity;
mod model;

pub use capability::{
    Capability, ResourcePattern, is_attenuation, is_resource_attenuation, resources_cover,
    set_covers,
};
pub use identity::{AgentId, TrustDomain};
pub use model::*;

/// API version string used in every Nexum configuration document.
pub const API_VERSION: &str = "nexum.dev/v1alpha1";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid SPIFFE agent id: {0:?}")]
    InvalidAgentId(String),
    #[error("invalid trust domain: {0:?}")]
    InvalidTrustDomain(String),
    #[error("invalid capability: {0:?}")]
    InvalidCapability(String),
    #[error("invalid resource: {0:?}")]
    InvalidResource(String),
}

/// A policy decision point. The built-in YAML engine implements this; OPA,
/// Cedar, Cerbos, SpiceDB or an enterprise PDP can be plugged in as adapters.
///
/// Implementations must be deterministic and must return `Err` rather than
/// guess when they cannot decide: the gateway turns errors into DENY.
#[async_trait::async_trait]
pub trait PolicyDecisionPoint: Send + Sync {
    async fn evaluate(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<PolicyResult, Box<dyn std::error::Error + Send + Sync>>;
}

/// Local revocation lookups. Must not require a network round-trip per
/// request; errors are treated as "revoked" (fail closed).
pub trait RevocationList: Send + Sync {
    fn is_revoked(
        &self,
        target: &RevocationTarget,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
}
