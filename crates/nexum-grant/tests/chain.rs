//! Delegation-chain security tests. Each negative test is a named attack.

#![allow(clippy::unwrap_used)]

use std::collections::HashSet;
use std::sync::Mutex;

use nexum_core::{
    AgentId, Capability, ReasonCode, ResourcePattern, RevocationList, RevocationTarget,
};
use nexum_grant::*;

const NOW: i64 = 1_800_000_000;
const AUD: &str = "abc.com";

#[derive(Default)]
struct Revoked(Mutex<HashSet<RevocationTarget>>);

impl RevocationList for Revoked {
    fn is_revoked(
        &self,
        t: &RevocationTarget,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.0.lock().unwrap().contains(t))
    }
}

fn caps(v: &[&str]) -> Vec<Capability> {
    v.iter().map(|s| Capability::parse(s).unwrap()).collect()
}

fn res(v: &[&str]) -> Vec<ResourcePattern> {
    v.iter()
        .map(|s| ResourcePattern::parse(s).unwrap())
        .collect()
}

struct World {
    org: KeyPair,
    parent: KeyPair,
    child: KeyPair,
    trust: TrustStore,
    revoked: Revoked,
}

fn world() -> World {
    let org = KeyPair::generate();
    let trust: TrustStore = serde_json::from_value(serde_json::json!({
        "trust_domains": {
            "xyz.com": {
                "issuer": "https://identity.xyz.com",
                "keys": [org.public_jwk()],
                "allow": ["inventory.*", "pricing.read", "quote.create"],
                "deny": ["payment.execute"]
            }
        }
    }))
    .unwrap();
    trust.validate().unwrap();
    World {
        org,
        parent: KeyPair::generate(),
        child: KeyPair::generate(),
        trust,
        revoked: Revoked::default(),
    }
}

fn root_claims(w: &World) -> GrantClaims {
    GrantClaims {
        jti: "root-1".into(),
        iss: "https://identity.xyz.com".into(),
        sub: AgentId::parse("spiffe://xyz.com/agents/procurement").unwrap(),
        act: Some(Actor {
            sub: "jane@xyz.com".into(),
        }),
        org: nexum_core::TrustDomain::parse("xyz.com").unwrap(),
        aud: vec![AUD.into()],
        cap: caps(&["inventory.read", "pricing.read", "quote.create"]),
        res: res(&["supplier://abc/*"]),
        dcap: caps(&["inventory.read"]),
        purpose: Some("restock".into()),
        iat: NOW - 10,
        nbf: NOW - 10,
        exp: NOW + 900,
        mdd: 1,
        prt: None,
        max_value: None,
        cnf: Confirmation {
            jwk: w.parent.public_jwk(),
        },
    }
}

fn spec(w: &World, cap: &[&str]) -> DelegationSpec {
    DelegationSpec {
        sub: AgentId::parse("spiffe://xyz.com/agents/inventory-checker").unwrap(),
        holder: w.child.public_jwk(),
        cap: caps(cap),
        res: None,
        dcap: vec![],
        mdd: 0,
        ttl_seconds: 300,
        aud: None,
        max_value: None,
    }
}

fn verifier(w: &World) -> Verifier<'_> {
    Verifier {
        trust: &w.trust,
        revocations: &w.revoked,
        audience: AUD,
        clock: Clock {
            now: NOW,
            leeway: 30,
        },
    }
}

fn chain(w: &World) -> (String, String) {
    let root = sign_grant(&root_claims(w), &w.org).unwrap();
    let child = child_claims(&root_claims(w), &root, spec(w, &["inventory.read"]), NOW).unwrap();
    let child = sign_grant(&child, &w.parent).unwrap();
    (root, child)
}

fn err(w: &World, tokens: &[&str]) -> ReasonCode {
    verifier(w).verify_chain(tokens).unwrap_err()
}

#[test]
fn valid_root_and_child() {
    let w = world();
    let (root, child) = chain(&w);
    let v = verifier(&w).verify_chain(&[&root]).unwrap();
    assert_eq!(v.leaf().sub.as_str(), "spiffe://xyz.com/agents/procurement");
    let v = verifier(&w).verify_chain(&[&root, &child]).unwrap();
    assert_eq!(v.leaf().cap, caps(&["inventory.read"]));
    assert_eq!(v.leaf().act, root_claims(&w).act);
}

#[test]
fn child_escalates_privileges() {
    let w = world();
    let root = sign_grant(&root_claims(&w), &w.org).unwrap();
    // Builder refuses...
    assert_eq!(
        child_claims(&root_claims(&w), &root, spec(&w, &["payment.execute"]), NOW).unwrap_err(),
        ReasonCode::CapabilityEscalation
    );
    // ...and so does the verifier for a hand-crafted escalated child.
    let mut c = child_claims(&root_claims(&w), &root, spec(&w, &["inventory.read"]), NOW).unwrap();
    c.cap = caps(&["inventory.read", "payment.execute"]);
    let tok = sign_grant(&c, &w.parent).unwrap();
    assert_eq!(err(&w, &[&root, &tok]), ReasonCode::CapabilityEscalation);
    // Delegating something held but not delegatable.
    c.cap = caps(&["pricing.read"]);
    let tok = sign_grant(&c, &w.parent).unwrap();
    assert_eq!(err(&w, &[&root, &tok]), ReasonCode::CapabilityEscalation);
    // Wildcard widening.
    c.cap = caps(&["inventory.*"]);
    let tok = sign_grant(&c, &w.parent).unwrap();
    assert_eq!(err(&w, &[&root, &tok]), ReasonCode::CapabilityEscalation);
}

#[test]
fn child_escalates_resources_lifetime_depth_context_limits() {
    let w = world();
    let root = sign_grant(&root_claims(&w), &w.org).unwrap();
    let base = child_claims(&root_claims(&w), &root, spec(&w, &["inventory.read"]), NOW).unwrap();
    type Case = (fn(&mut GrantClaims), ReasonCode);
    let cases: Vec<Case> = vec![
        (
            |c| c.res = res(&["supplier://*"]),
            ReasonCode::ResourceEscalation,
        ),
        (|c| c.exp += 10_000, ReasonCode::LifetimeEscalation),
        (|c| c.mdd = 1, ReasonCode::DelegationDepthExceeded),
        (
            |c| {
                c.act = Some(Actor {
                    sub: "ceo@xyz.com".into(),
                })
            },
            ReasonCode::ContextEscalation,
        ),
        (|c| c.act = None, ReasonCode::ContextEscalation),
        (
            |c| c.purpose = Some("other".into()),
            ReasonCode::ContextEscalation,
        ),
        (
            |c| c.aud.push("evil.com".into()),
            ReasonCode::ContextEscalation,
        ),
        (|c| c.prt = Some("AAAA".into()), ReasonCode::BrokenChain),
        (
            |c| c.iss = "spiffe://xyz.com/agents/someone-else".into(),
            ReasonCode::BrokenChain,
        ),
        (
            |c| c.sub = AgentId::parse("spiffe://evil.com/agents/x").unwrap(),
            ReasonCode::SubjectDomainMismatch,
        ),
        (
            |c| c.dcap = caps(&["inventory.read.*"]),
            ReasonCode::CapabilityEscalation,
        ),
    ];
    for (mutate, want) in cases {
        let mut c = base.clone();
        mutate(&mut c);
        let tok = sign_grant(&c, &w.parent).unwrap();
        assert_eq!(err(&w, &[&root, &tok]), want, "{c:?}");
    }
}

#[test]
fn value_limit_cannot_be_raised_or_dropped() {
    let w = world();
    let mut rc = root_claims(&w);
    rc.max_value = Some(500);
    let root = sign_grant(&rc, &w.org).unwrap();
    let mut s = spec(&w, &["inventory.read"]);
    s.max_value = Some(1000);
    assert_eq!(
        child_claims(&rc, &root, s, NOW).unwrap_err(),
        ReasonCode::LimitEscalation
    );
    let mut c = child_claims(&rc, &root, spec(&w, &["inventory.read"]), NOW).unwrap();
    assert_eq!(c.max_value, Some(500));
    c.max_value = None;
    let tok = sign_grant(&c, &w.parent).unwrap();
    assert_eq!(err(&w, &[&root, &tok]), ReasonCode::LimitEscalation);
}

#[test]
fn grandchild_beyond_depth() {
    let w = world();
    let (_root, child) = chain(&w);
    let child_c = decode_unverified(&child).unwrap();
    // Child has mdd 0, so it may not delegate at all.
    let grandchild = KeyPair::generate();
    let mut s = spec(&w, &["inventory.read"]);
    s.holder = grandchild.public_jwk();
    s.sub = AgentId::parse("spiffe://xyz.com/agents/gc").unwrap();
    assert!(child_claims(&child_c, &child, s, NOW).is_err());
}

#[test]
fn tampered_and_forged_tokens() {
    let w = world();
    let (root, child) = chain(&w);
    // Tampered payload.
    let parts: Vec<&str> = root.split('.').collect();
    let mut c = root_claims(&w);
    c.cap.push(Capability::parse("payment.execute").unwrap());
    let forged_payload = sign_grant(&c, &w.org).unwrap();
    let fp: Vec<&str> = forged_payload.split('.').collect();
    let tampered = format!("{}.{}.{}", parts[0], fp[1], parts[2]);
    assert_eq!(err(&w, &[&tampered]), ReasonCode::InvalidSignature);
    // Root forged by an attacker key with the right kid.
    let attacker = KeyPair {
        kid: w.org.kid.clone(),
        ..KeyPair::generate()
    };
    let forged = sign_grant(&root_claims(&w), &attacker).unwrap();
    assert_eq!(err(&w, &[&forged]), ReasonCode::InvalidSignature);
    // Child signed by the org instead of the parent holder.
    let cc = decode_unverified(&child).unwrap();
    let wrong_signer = sign_grant(&cc, &w.org).unwrap();
    assert_eq!(
        err(&w, &[&root, &wrong_signer]),
        ReasonCode::InvalidSignature
    );
    // Out of order / spliced chains.
    assert!(verifier(&w).verify_chain(&[&child, &root]).is_err());
    assert_eq!(err(&w, &[]), ReasonCode::GrantMissing);
    let long: Vec<&str> = std::iter::repeat_n(root.as_str(), MAX_CHAIN_LEN + 1).collect();
    assert_eq!(err(&w, &long), ReasonCode::ChainTooLong);
}

#[test]
fn unknown_issuer_key_and_domain() {
    let w = world();
    let mut c = root_claims(&w);
    c.iss = "https://evil.example".into();
    assert_eq!(
        err(&w, &[&sign_grant(&c, &w.org).unwrap()]),
        ReasonCode::UnknownIssuer
    );

    let mut c = root_claims(&w);
    c.org = nexum_core::TrustDomain::parse("evil.com").unwrap();
    c.sub = AgentId::parse("spiffe://evil.com/agents/x").unwrap();
    assert_eq!(
        err(&w, &[&sign_grant(&c, &w.org).unwrap()]),
        ReasonCode::UnknownIssuer
    );

    let other = KeyPair::generate();
    assert_eq!(
        err(&w, &[&sign_grant(&root_claims(&w), &other).unwrap()]),
        ReasonCode::UnknownKey
    );

    // Trusted org vouching for an agent in another trust domain.
    let mut c = root_claims(&w);
    c.sub = AgentId::parse("spiffe://abc.com/agents/supplier").unwrap();
    assert_eq!(
        err(&w, &[&sign_grant(&c, &w.org).unwrap()]),
        ReasonCode::SubjectDomainMismatch
    );
}

#[test]
fn time_and_audience() {
    let w = world();
    let mut c = root_claims(&w);
    c.exp = NOW - 31;
    c.iat = NOW - 100;
    c.nbf = NOW - 100;
    assert_eq!(
        err(&w, &[&sign_grant(&c, &w.org).unwrap()]),
        ReasonCode::GrantExpired
    );

    let mut c = root_claims(&w);
    c.nbf = NOW + 120;
    assert_eq!(
        err(&w, &[&sign_grant(&c, &w.org).unwrap()]),
        ReasonCode::GrantNotYetValid
    );

    let mut c = root_claims(&w);
    c.exp = c.iat + DEFAULT_MAX_GRANT_TTL_SECONDS + 1;
    assert_eq!(
        err(&w, &[&sign_grant(&c, &w.org).unwrap()]),
        ReasonCode::GrantLifetimeTooLong
    );

    let mut c = root_claims(&w);
    c.aud = vec!["other.com".into()];
    assert_eq!(
        err(&w, &[&sign_grant(&c, &w.org).unwrap()]),
        ReasonCode::WrongAudience
    );
}

#[test]
fn revocations() {
    let cases = |w: &World| {
        vec![
            (
                RevocationTarget::Grant("root-1".into()),
                ReasonCode::GrantRevoked,
            ),
            (
                RevocationTarget::Agent("spiffe://xyz.com/agents/procurement".into()),
                ReasonCode::AgentRevoked,
            ),
            (
                RevocationTarget::TrustDomain("xyz.com".into()),
                ReasonCode::TrustRevoked,
            ),
            (
                RevocationTarget::Key(w.org.kid.clone()),
                ReasonCode::KeyRevoked,
            ),
            (
                RevocationTarget::Key(w.parent.public_jwk().thumbprint()),
                ReasonCode::KeyRevoked,
            ),
        ]
    };
    let w = world();
    let (root, child) = chain(&w);
    for (target, want) in cases(&w) {
        w.revoked.0.lock().unwrap().insert(target.clone());
        // Revoking a parent invalidates every descendant.
        assert_eq!(err(&w, &[&root, &child]), want, "{target:?}");
        w.revoked.0.lock().unwrap().clear();
    }
    verifier(&w).verify_chain(&[&root, &child]).unwrap();
}

#[test]
fn proof_of_possession() {
    let w = world();
    let (root, child) = chain(&w);
    let v = verifier(&w);
    let verified = v.verify_chain(&[&root, &child]).unwrap();
    let replay = MemoryReplayGuard::default();
    let body = br#"{"action":"inventory.read"}"#;

    let proof = create_proof(&w.child, &child, AUD, body, NOW).unwrap();
    v.verify_proof(&verified, &proof, body, &replay, 60)
        .unwrap();
    // Replayed.
    assert_eq!(
        v.verify_proof(&verified, &proof, body, &replay, 60)
            .unwrap_err(),
        ReasonCode::ProofReplayed
    );
    // Stolen grant, attacker signs with their own key.
    let thief = KeyPair::generate();
    let p = create_proof(&thief, &child, AUD, body, NOW).unwrap();
    assert_eq!(
        v.verify_proof(&verified, &p, body, &replay, 60)
            .unwrap_err(),
        ReasonCode::ProofInvalid
    );
    // Body substituted after signing.
    let p = create_proof(&w.child, &child, AUD, body, NOW).unwrap();
    assert_eq!(
        v.verify_proof(
            &verified,
            &p,
            br#"{"action":"payment.execute"}"#,
            &replay,
            60
        )
        .unwrap_err(),
        ReasonCode::ProofBindingMismatch
    );
    // Proof minted for a different gateway.
    let p = create_proof(&w.child, &child, "other.com", body, NOW).unwrap();
    assert_eq!(
        v.verify_proof(&verified, &p, body, &replay, 60)
            .unwrap_err(),
        ReasonCode::ProofBindingMismatch
    );
    // Proof bound to a different grant (token substitution).
    let p = create_proof(&w.child, &root, AUD, body, NOW).unwrap();
    assert_eq!(
        v.verify_proof(&verified, &p, body, &replay, 60)
            .unwrap_err(),
        ReasonCode::ProofBindingMismatch
    );
    // Stale.
    let p = create_proof(&w.child, &child, AUD, body, NOW - 600).unwrap();
    assert_eq!(
        v.verify_proof(&verified, &p, body, &replay, 60)
            .unwrap_err(),
        ReasonCode::ProofStale
    );
}

#[test]
fn extreme_timestamps_do_not_overflow() {
    let w = world();
    let (root, child) = chain(&w);
    let v = verifier(&w);
    let verified = v.verify_chain(&[&root, &child]).unwrap();
    let replay = MemoryReplayGuard::default();
    for iat in [i64::MIN, i64::MAX] {
        let p = create_proof(&w.child, &child, AUD, b"{}", iat).unwrap();
        assert_eq!(
            v.verify_proof(&verified, &p, b"{}", &replay, 60)
                .unwrap_err(),
            ReasonCode::ProofStale
        );
    }
    // Grants with extreme times are rejected, not wrapped.
    for (iat, exp) in [
        (i64::MIN, NOW + 10),
        (NOW - 10, i64::MAX),
        (i64::MIN, i64::MAX),
    ] {
        let mut c = root_claims(&w);
        c.iat = iat;
        c.nbf = iat;
        c.exp = exp;
        assert!(
            verifier(&w)
                .verify_chain(&[&sign_grant(&c, &w.org).unwrap()])
                .is_err()
        );
    }
}
