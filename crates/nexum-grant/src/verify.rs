//! Delegation-chain and proof-of-possession verification.
//!
//! Every failure maps to exactly one [`ReasonCode`]; there is no "warn and
//! continue" path. Callers turn any `Err` into DENY.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::VerifyingKey;
use nexum_core::{ReasonCode, RevocationList, RevocationTarget};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::grant::{GRANT_TYP, GrantClaims, check_link, check_self, token_hash};
use crate::keys::KeyPair;
use crate::trust::TrustStore;
use crate::{GrantError, jws};

pub const PROOF_TYP: &str = "nexum-proof+jwt";
pub const MAX_CHAIN_LEN: usize = 8;

/// A request-level proof of possession of the leaf grant's `cnf` key
/// (DPoP-style, cf. RFC 9449), bound to the gateway, the grant and the exact
/// request body. Prevents use of a stolen grant and replay of a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofClaims {
    pub jti: String,
    pub iat: i64,
    pub aud: String,
    /// `token_hash` of the leaf grant.
    pub gh: String,
    /// base64url(SHA-256(request body)).
    pub bh: String,
}

pub fn body_hash(body: &[u8]) -> String {
    B64.encode(Sha256::digest(body))
}

pub fn create_proof(
    holder: &KeyPair,
    leaf_grant: &str,
    audience: &str,
    body: &[u8],
    now: i64,
) -> Result<String, GrantError> {
    let claims = ProofClaims {
        jti: uuid::Uuid::new_v4().to_string(),
        iat: now,
        aud: audience.into(),
        gh: token_hash(leaf_grant),
        bh: body_hash(body),
    };
    jws::sign(&claims, PROOF_TYP, None, &holder.signing)
}

#[derive(Debug, Clone)]
pub struct VerifiedChain {
    /// Root first.
    pub grants: Vec<GrantClaims>,
    pub leaf_hash: String,
    pub leaf_key: VerifyingKey,
}

impl VerifiedChain {
    pub fn root(&self) -> &GrantClaims {
        &self.grants[0]
    }
    pub fn leaf(&self) -> &GrantClaims {
        &self.grants[self.grants.len() - 1]
    }
    pub fn earliest_expiry(&self) -> i64 {
        self.grants.iter().map(|g| g.exp).min().unwrap_or(0)
    }
}

/// Tracks seen proof ids until they expire.
pub trait ReplayGuard: Send + Sync {
    /// Returns false if `id` was already seen (or the guard cannot accept it).
    fn check_and_insert(&self, id: String, expires_at: i64, now: i64) -> bool;
}

/// In-process replay cache.
// ponytail: single-process only; a gateway fleet behind a load balancer needs
// a shared store (Redis/DB) or sticky routing so a proof can't be replayed on
// a sibling instance.
#[derive(Debug, Default)]
pub struct MemoryReplayGuard {
    seen: Mutex<HashMap<String, i64>>,
}

const REPLAY_CAPACITY: usize = 1_000_000;

impl ReplayGuard for MemoryReplayGuard {
    fn check_and_insert(&self, id: String, expires_at: i64, now: i64) -> bool {
        let Ok(mut seen) = self.seen.lock() else {
            return false;
        };
        if seen.len() >= REPLAY_CAPACITY / 2 {
            seen.retain(|_, exp| *exp >= now);
        }
        if seen.len() >= REPLAY_CAPACITY || seen.contains_key(&id) {
            return false;
        }
        seen.insert(id, expires_at);
        true
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Clock {
    pub now: i64,
    /// Tolerated clock skew between issuer, holder and gateway, in seconds.
    pub leeway: i64,
}

pub struct Verifier<'a> {
    pub trust: &'a TrustStore,
    pub revocations: &'a dyn RevocationList,
    /// This gateway's audience identifier (normally its trust domain).
    pub audience: &'a str,
    pub clock: Clock,
}

impl std::fmt::Debug for Verifier<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

fn map_err(e: GrantError) -> ReasonCode {
    match e {
        GrantError::UnsupportedAlgorithm => ReasonCode::UnsupportedAlgorithm,
        GrantError::InvalidSignature => ReasonCode::InvalidSignature,
        GrantError::Malformed => ReasonCode::MalformedGrant,
    }
}

impl Verifier<'_> {
    fn revoked(&self, target: RevocationTarget, reason: ReasonCode) -> Result<(), ReasonCode> {
        match self.revocations.is_revoked(&target) {
            Ok(false) => Ok(()),
            Ok(true) => Err(reason),
            Err(_) => Err(ReasonCode::StateUnavailable),
        }
    }

    fn check_time_and_audience(&self, c: &GrantClaims) -> Result<(), ReasonCode> {
        let Clock { now, leeway } = self.clock;
        if now >= c.exp + leeway {
            return Err(ReasonCode::GrantExpired);
        }
        if c.nbf > now + leeway || c.iat > now + leeway {
            return Err(ReasonCode::GrantNotYetValid);
        }
        if !c.aud.iter().any(|a| a == self.audience) {
            return Err(ReasonCode::WrongAudience);
        }
        self.revoked(
            RevocationTarget::Grant(c.jti.clone()),
            ReasonCode::GrantRevoked,
        )?;
        self.revoked(
            RevocationTarget::Agent(c.sub.to_string()),
            ReasonCode::AgentRevoked,
        )?;
        Ok(())
    }

    /// Verify a chain of compact grants, root first.
    pub fn verify_chain(&self, tokens: &[&str]) -> Result<VerifiedChain, ReasonCode> {
        if tokens.is_empty() {
            return Err(ReasonCode::GrantMissing);
        }
        if tokens.len() > MAX_CHAIN_LEN {
            return Err(ReasonCode::ChainTooLong);
        }

        // Root: signed by a key the trust store publishes for its domain.
        let root_tok = jws::parse(tokens[0], GRANT_TYP).map_err(map_err)?;
        let peeked: GrantClaims = root_tok.peek().map_err(map_err)?;
        let domain = self
            .trust
            .domain(&peeked.org)
            .ok_or(ReasonCode::UnknownIssuer)?;
        self.revoked(
            RevocationTarget::TrustDomain(peeked.org.to_string()),
            ReasonCode::TrustRevoked,
        )?;
        let kid = root_tok
            .header
            .kid
            .as_deref()
            .ok_or(ReasonCode::UnknownKey)?;
        let jwk = domain
            .keys
            .iter()
            .find(|k| k.kid.as_deref() == Some(kid))
            .ok_or(ReasonCode::UnknownKey)?;
        self.revoked(
            RevocationTarget::Key(kid.to_owned()),
            ReasonCode::KeyRevoked,
        )?;
        let root: GrantClaims = root_tok
            .verify(&jwk.to_key().map_err(map_err)?)
            .map_err(map_err)?;
        if root.iss != domain.issuer {
            return Err(ReasonCode::UnknownIssuer);
        }
        if root.prt.is_some() {
            return Err(ReasonCode::BrokenChain);
        }
        if root.exp - root.iat > domain.max_grant_ttl_seconds {
            return Err(ReasonCode::GrantLifetimeTooLong);
        }
        check_self(&root)?;
        self.check_time_and_audience(&root)?;

        // Children: each signed by its parent's holder key and attenuated.
        let mut grants = vec![root];
        for pair in tokens.windows(2) {
            let parent = &grants[grants.len() - 1];
            let holder = parent.cnf.jwk.to_key().map_err(map_err)?;
            self.revoked(
                RevocationTarget::Key(parent.cnf.jwk.thumbprint()),
                ReasonCode::KeyRevoked,
            )?;
            let child: GrantClaims = jws::parse(pair[1], GRANT_TYP)
                .map_err(map_err)?
                .verify(&holder)
                .map_err(map_err)?;
            check_self(&child)?;
            check_link(parent, pair[0], &child)?;
            self.check_time_and_audience(&child)?;
            grants.push(child);
        }

        let leaf = &grants[grants.len() - 1];
        let leaf_key = leaf.cnf.jwk.to_key().map_err(map_err)?;
        self.revoked(
            RevocationTarget::Key(leaf.cnf.jwk.thumbprint()),
            ReasonCode::KeyRevoked,
        )?;
        Ok(VerifiedChain {
            leaf_hash: token_hash(tokens[tokens.len() - 1]),
            leaf_key,
            grants,
        })
    }

    /// Verify the holder's proof of possession for this exact request body.
    pub fn verify_proof(
        &self,
        chain: &VerifiedChain,
        proof: &str,
        body: &[u8],
        replay: &dyn ReplayGuard,
        max_age: i64,
    ) -> Result<(), ReasonCode> {
        let parsed = jws::parse(proof, PROOF_TYP).map_err(|e| match e {
            GrantError::UnsupportedAlgorithm => ReasonCode::UnsupportedAlgorithm,
            _ => ReasonCode::ProofInvalid,
        })?;
        let claims: ProofClaims = parsed
            .verify(&chain.leaf_key)
            .map_err(|_| ReasonCode::ProofInvalid)?;
        if claims.aud != self.audience
            || claims.gh != chain.leaf_hash
            || claims.bh != body_hash(body)
        {
            return Err(ReasonCode::ProofBindingMismatch);
        }
        let Clock { now, leeway } = self.clock;
        if (now - claims.iat).abs() > max_age + leeway {
            return Err(ReasonCode::ProofStale);
        }
        if claims.jti.is_empty() || claims.jti.len() > 128 {
            return Err(ReasonCode::ProofInvalid);
        }
        let id = format!("{}:{}", claims.gh, claims.jti);
        if !replay.check_and_insert(id, claims.iat + max_age + leeway, now) {
            return Err(ReasonCode::ProofReplayed);
        }
        Ok(())
    }
}

/// Decode a grant without verifying it (for `grants inspect`).
pub fn decode_unverified(token: &str) -> Result<GrantClaims, GrantError> {
    jws::parse(token, GRANT_TYP)?.peek()
}
