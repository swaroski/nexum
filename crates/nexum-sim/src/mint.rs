//! Turn a scenario into what an agent would present, with its attack applied.

use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use nexum_core::{RevocationTarget, TrustDomain};
use nexum_grant::{
    Actor, Confirmation, GrantClaims, KeyPair, create_proof, sign_grant, token_hash,
};
use serde_json::{Value, json};

use crate::scenario::{Attack, GrantSpec, RequestSpec, RpcSpec, Scenario};

/// Exactly what reaches the gateway, plus the environment changes the
/// attack needs (a revocation) and whether to send the request twice.
#[derive(Debug, Clone)]
pub struct Minted {
    /// Compact grants, root first.
    pub chain: Vec<String>,
    pub proof: String,
    pub body: Vec<u8>,
    pub revoke: Option<RevocationTarget>,
    pub replay: bool,
}

/// Mint `s` as organization `org` (`issuer`, `org_key`) calling the gateway
/// whose audience is `audience`, at time `now`.
pub fn mint(
    s: &Scenario,
    org: &TrustDomain,
    issuer: &str,
    org_key: &KeyPair,
    audience: &str,
    now: i64,
) -> anyhow::Result<Minted> {
    let attack = s.attack;
    let iat = if attack == Some(Attack::Expired) {
        now - 7200
    } else {
        now
    };
    let ttl = |g: &GrantSpec| g.ttl_seconds.unwrap_or(300);
    let aud = if attack == Some(Attack::WrongAudience) {
        format!("not-{audience}")
    } else {
        audience.to_owned()
    };
    let root_org = if attack == Some(Attack::UnknownOrganization) {
        TrustDomain::parse("unknown-org.invalid")?
    } else {
        org.clone()
    };

    let Some((root_spec, delegations)) = s.grants.split_first() else {
        bail!("scenario needs at least one grant");
    };
    let mut holder = KeyPair::generate();
    let mut claims = GrantClaims {
        jti: uuid::Uuid::new_v4().to_string(),
        iss: issuer.to_owned(),
        sub: root_spec.sub.clone(),
        act: root_spec.actor.clone().map(|sub| Actor { sub }),
        org: root_org,
        aud: vec![aud],
        cap: root_spec.cap.clone(),
        res: root_spec.res.clone().context("root grant needs `res`")?,
        dcap: root_spec.dcap.clone(),
        purpose: root_spec.purpose.clone(),
        iat,
        nbf: iat,
        exp: iat + ttl(root_spec),
        mdd: root_spec.max_depth,
        prt: None,
        max_value: root_spec.max_value,
        cnf: Confirmation {
            jwk: holder.public_jwk(),
        },
    };
    let signer = if attack == Some(Attack::UntrustedIssuer) {
        KeyPair::generate()
    } else {
        org_key.clone()
    };
    let mut chain = vec![sign_grant(&claims, &signer)?];
    let root_jti = claims.jti.clone();

    for spec in delegations {
        let next = KeyPair::generate();
        let child = GrantClaims {
            jti: uuid::Uuid::new_v4().to_string(),
            iss: claims.sub.to_string(),
            sub: spec.sub.clone(),
            act: spec
                .actor
                .clone()
                .map(|sub| Actor { sub })
                .or_else(|| claims.act.clone()),
            org: claims.org.clone(),
            aud: claims.aud.clone(),
            cap: spec.cap.clone(),
            res: spec.res.clone().unwrap_or_else(|| claims.res.clone()),
            dcap: spec.dcap.clone(),
            purpose: spec.purpose.clone().or_else(|| claims.purpose.clone()),
            iat,
            nbf: iat,
            exp: iat + ttl(spec),
            mdd: spec.max_depth,
            prt: chain.last().map(|t| token_hash(t)),
            max_value: spec.max_value.or(claims.max_value),
            cnf: Confirmation {
                jwk: next.public_jwk(),
            },
        };
        chain.push(sign_grant(&child, &holder)?);
        (claims, holder) = (child, next);
    }

    if attack == Some(Attack::Tampered) {
        chain[0] = tamper(&chain[0])?;
    }
    let revoke = match attack {
        Some(Attack::RevokedParent) => Some(RevocationTarget::Grant(root_jti)),
        Some(Attack::RevokedAgent) => Some(RevocationTarget::Agent(claims.sub.to_string())),
        Some(Attack::RevokedTrust) => Some(RevocationTarget::TrustDomain(org.to_string())),
        _ => None,
    };

    let body = body(&s.request)?;
    let prover = if attack == Some(Attack::StolenGrant) {
        KeyPair::generate()
    } else {
        holder
    };
    let signed_body = if attack == Some(Attack::BodySwap) {
        b"{}".to_vec()
    } else {
        body.clone()
    };
    let proof_iat = if attack == Some(Attack::StaleProof) {
        now - 600
    } else {
        now
    };
    let leaf = chain.last().map(String::as_str).unwrap_or_default();
    let proof = create_proof(&prover, leaf, audience, &signed_body, proof_iat)?;
    Ok(Minted {
        chain,
        proof,
        body,
        revoke,
        replay: attack == Some(Attack::Replay),
    })
}

/// The request body: decision-API JSON, or the protocol message bytes.
fn body(r: &RequestSpec) -> anyhow::Result<Vec<u8>> {
    let rpc = |rpc: &RpcSpec| -> anyhow::Result<Vec<u8>> {
        match (&rpc.message, &rpc.raw) {
            (Some(m), None) => Ok(serde_json::to_vec(m)?),
            (None, Some(raw)) => Ok(raw.as_bytes().to_vec()),
            _ => bail!("protocol request needs exactly one of `message` or `raw`"),
        }
    };
    match (r.action.is_some() || r.resource.is_some(), &r.mcp, &r.a2a) {
        (true, None, None) => Ok(serde_json::to_vec(&json!({
            "action": r.action.as_deref().context("request needs `action`")?,
            "resource": r.resource.as_deref().context("request needs `resource`")?,
            "value": r.value,
        }))?),
        (false, Some(m), None) | (false, None, Some(m)) => rpc(m),
        _ => bail!("request needs exactly one of action/resource, `mcp` or `a2a`"),
    }
}

/// Extend the payload's lifetime by an hour, keeping the original signature.
fn tamper(token: &str) -> anyhow::Result<String> {
    let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
    let [_, payload, _] = parts.as_mut_slice() else {
        bail!("malformed token");
    };
    let mut claims: Value = serde_json::from_slice(&B64.decode(&*payload)?)?;
    claims["exp"] = json!(claims["exp"].as_i64().unwrap_or_default() + 3600);
    *payload = B64.encode(serde_json::to_vec(&claims)?);
    Ok(parts.join("."))
}
