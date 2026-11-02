//! Signed delegation grants, proofs of possession, and chain verification.

#![forbid(unsafe_code)]

mod grant;
pub mod jws;
mod keys;
mod trust;
mod verify;

pub use grant::{
    Actor, Confirmation, DelegationSpec, GRANT_TYP, GrantClaims, child_claims, sign_grant,
    token_hash,
};
pub use keys::{Jwk, KeyPair};
pub use trust::{DEFAULT_MAX_GRANT_TTL_SECONDS, TrustDomainConfig, TrustStore};
pub use verify::{
    Clock, MAX_CHAIN_LEN, MemoryReplayGuard, PROOF_TYP, ProofClaims, ReplayGuard, VerifiedChain,
    Verifier, body_hash, create_proof, decode_unverified,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    #[error("malformed token or key")]
    Malformed,
    #[error("unsupported algorithm (only EdDSA/Ed25519 is accepted)")]
    UnsupportedAlgorithm,
    #[error("invalid signature")]
    InvalidSignature,
}
