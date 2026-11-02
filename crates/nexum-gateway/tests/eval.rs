//! The official security suite (`evals/`) and the cross-company example suite
//! pass, and a wrong expectation is reported as a critical failure.

#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use nexum_core::Outcome;
use nexum_gateway::config::Config;
use nexum_gateway::eval;
use nexum_grant::KeyPair;
use serde_json::json;

#[tokio::test]
async fn cross_company_suite() {
    let example = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/cross-company");
    let dir = std::env::temp_dir().join(format!("nexum-eval-it-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let trust = json!({
        "apiVersion": "nexum.dev/v1alpha1",
        "trust_domains": {"xyz.com": {
            "issuer": "https://identity.xyz.com",
            "keys": [KeyPair::generate().public_jwk()],
            "allow": ["inventory.read", "pricing.read", "quote.create"],
            "deny": ["payment.execute", "customer.export"]
        }}
    });
    std::fs::write(
        dir.join("trust.yaml"),
        yaml_serde::to_string(&trust).unwrap(),
    )
    .unwrap();
    std::fs::copy(
        format!("{example}/abc-policy.yaml"),
        dir.join("policy.yaml"),
    )
    .unwrap();
    std::fs::write(
        dir.join("nexum.yaml"),
        "apiVersion: nexum.dev/v1alpha1\nserver: { listen: 127.0.0.1:0 }\ngateway: { audience: abc.com }\n\
         policy: { provider: builtin, file: policy.yaml }\naudit: { provider: sqlite, path: audit.db }\n\
         trust: { file: trust.yaml }\nstate: { file: state.db }\n",
    )
    .unwrap();
    let cfg = Config::load(&dir.join("nexum.yaml")).unwrap();

    let suite = eval::load(format!("{example}/eval.yaml").as_ref()).unwrap();
    let results = eval::run_suite(&cfg, "cross-company", &suite).await;
    assert_eq!(
        results.len(),
        suite.scenarios.len() + 2 * eval::Attack::ALL.len()
    );
    for r in &results {
        assert!(r.passed, "{r:?}");
    }

    let mut wrong = eval::load(format!("{example}/eval.yaml").as_ref()).unwrap();
    wrong
        .scenarios
        .retain(|s| s.name == "compromised-worker-escalation");
    wrong.scenarios[0].expect = Outcome::Allow;
    wrong.scenarios[0].code = None;
    let r = eval::run_suite(&cfg, "wrong", &wrong).await;
    assert!(!r[0].passed);
    assert!(
        !r[0].critical,
        "stricter than expected is a failure, not a leak"
    );
    wrong.scenarios[0].expect = Outcome::Deny;
    wrong.scenarios[0].request.action = Some("inventory.read".into());
    let r = eval::run_suite(&cfg, "wrong", &wrong).await;
    assert!(!r[0].passed && r[0].critical, "{r:?}");

    // The sandbox never wrote to the real state or audit.
    assert!(!dir.join("audit.db").exists() && !dir.join("state.db").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn official_security_suite() {
    let evals = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../evals"));
    let cfg = Config::load(&evals.join("gateway/nexum.yaml")).unwrap();
    let mut n = 0;
    for path in eval::discover(&[evals]).unwrap() {
        let suite = eval::load(&path).unwrap();
        for r in eval::run_suite(&cfg, &path.display().to_string(), &suite).await {
            assert!(r.passed, "{r:?}");
            n += 1;
        }
    }
    assert!(n >= 90, "only {n} scenarios ran");
}
