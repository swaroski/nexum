//! The in-memory pipeline reaches the same outcome and reason code as the
//! gateway on every decision-API scenario of the official eval suite (the
//! gateway is held to the same expectations by nexum-gateway's eval test).

#![allow(clippy::unwrap_used)]

use std::path::Path;

use nexum_grant::{KeyPair, TrustStore};
use nexum_policy::PolicySet;

#[test]
fn official_suite_agrees_with_gateway_expectations() {
    let evals = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../evals"));
    let read = |p: &str| std::fs::read_to_string(evals.join(p)).unwrap();
    let policy = PolicySet::from_yaml(&read("gateway/policy.yaml")).unwrap();
    let audience = "acme.example";
    let now = 1_800_000_000;
    let (mut ran, mut skipped) = (0, 0);

    for entry in std::fs::read_dir(evals).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "yaml") {
            continue;
        }
        let suite: nexum_sim::Suite =
            yaml_serde::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for s in nexum_sim::expand(&suite) {
            if s.request.mcp.is_some() || s.request.a2a.is_some() {
                skipped += 1;
                continue;
            }
            // Same as the eval sandbox: the caller's keys become an ephemeral key.
            let mut trust: TrustStore = yaml_serde::from_str(&read("gateway/trust.yaml")).unwrap();
            let key = KeyPair::generate();
            let domain = trust.trust_domains.get_mut(&suite.org).unwrap();
            domain.keys = vec![key.public_jwk()];
            let issuer = domain.issuer.clone();

            let m = nexum_sim::mint(&s, &suite.org, &issuer, &key, audience, now).unwrap();
            let d = nexum_sim::decide(&trust, &policy, audience, &m, now);
            assert_eq!(d.outcome, s.expect, "{}: {d:?}", s.name);
            if let Some(code) = &s.code {
                assert_eq!(d.code, code, "{}: {d:?}", s.name);
            }
            ran += 1;
        }
    }
    assert!(ran >= 60 && skipped > 0, "ran {ran}, skipped {skipped}");
}
