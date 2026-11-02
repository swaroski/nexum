# Threat Model

Scope: the Nexum enforcement gateway, its grant/proof formats, its local
state and audit log, and the CLI, as of `v1alpha1`. Status: **experimental;
not yet independently reviewed.**

## Assets

* Authority: the ability to make a protected resource perform an action.
* Signing keys: organization issuer keys and agent holder keys.
* Trust configuration (`trust.yaml`), policy (`policy.yaml`), local state
  (revocations, approvals, registry), audit log.

## Trust boundaries

1. Agent → gateway (network; agent may be compromised or malicious).
2. Foreign organization → gateway (only its public keys are trusted, and only
   for what `trust.yaml` allows).
3. Gateway → upstream tool/agent (upstream may be malicious).
4. Operator → local files (anyone with write access to config/state is an
   administrator).

## Assumptions

* Ed25519 and SHA-256 are secure; `ed25519-dalek` and `sha2` are correct.
* The gateway host is not compromised, and the gateway is the only network
  path to the protected resource (see *gateway bypass*).
* Clocks are synchronized within `clock_skew_seconds` (default 30 s).
* TLS protects agent ↔ gateway and gateway ↔ upstream traffic in production.

## Threats

Each entry: **Threat / Impact / Mitigation / Residual risk.** Tests that
exercise a mitigation are referenced as `file::test`.

### 1. Stolen agent credentials (grant theft)
* **Impact:** attacker acts as the agent.
* **Mitigation:** grants are holder-of-key (`cnf`), not bearer. Every request
  needs a fresh proof signed by the holder's private key. Grants are
  short-lived (trust-domain cap, default 1 h) and audience-bound. Revocable by
  `jti`, agent, or key. (`chain.rs::proof_of_possession`,
  `cross_company.rs::cross_company_scenario` "grant theft")
* **Residual:** theft of the grant *and* the private key gives full use of the
  grant until expiry or revocation. Use HSM/TPM-backed or SPIRE-rotated keys.

### 2. Compromised agent process
* **Impact:** attacker exercises all authority the agent holds.
* **Mitigation:** least privilege and attenuation bound the blast radius to
  the agent's grant (capabilities, resources, value, audience, time).
  Approvals for high-impact actions. Immediate revocation of the agent.
* **Residual:** anything the grant allows is possible until revoked. Keep
  grants task-scoped and short.

### 3. Malicious external agent
* **Impact:** unauthorized access across organizations.
* **Mitigation:** root grants must be signed by a key the *receiving*
  organization lists for that trust domain; issuer pinned; foreign orgs may
  only vouch for agents in their own trust domain; per-domain allow/deny
  list applied before local policy. (`chain.rs::unknown_issuer_key_and_domain`)
* **Residual:** a trusted organization can misbehave within what it was
  granted. Trust is a business decision; keep allow lists narrow.

### 4. Malicious MCP server
* **Impact:** credential theft, data exfiltration via responses, tool-name
  spoofing.
* **Mitigation:** Nexum credentials and `Authorization` headers are never
  forwarded upstream; only `content-type`, `accept`, `mcp-*`, `a2a-*` are.
  Tool calls are authorized per tool by name → capability; unmapped tools get
  a derived capability that default-deny blocks. (`cross_company.rs::mcp_tool_calls_are_enforced_and_forwarded`)
* **Residual:** Nexum does not inspect or sanitize response content; a
  malicious server can still return prompt-injection payloads to the agent
  (see 18).

### 5. Malicious A2A peer
* **Impact:** as 3 and 4.
* **Mitigation:** A2A requests are authorized per operation; unknown methods
  are invalid; outbound credentials are not forwarded.
* **Residual:** response content is not inspected.

### 6. Privilege escalation
* **Impact:** an agent gains capabilities it was never given.
* **Mitigation:** the action must be covered by the leaf grant, the trust
  relationship and policy. All three are default-deny. Wildcards cannot widen
  (`inventory.read` does not cover `inventory.*`).
  (`capability.rs` property tests, `chain.rs::child_escalates_privileges`)
* **Residual:** overly broad grants (`*`) or policies. `nexum policies test`
  helps review.

### 7. Confused deputy
* **Impact:** a privileged agent is tricked into acting for a less privileged
  caller.
* **Mitigation:** authority is carried *with* the request (the chain) instead
  of being ambient; the actor (`act`) is immutable down the chain and recorded
  in audit; a deputy must delegate a narrower grant rather than act with its
  own.
* **Residual:** an agent that uses its *own* grant on another party's behalf
  is still a deputy. Frameworks must pass the caller's chain, not their own.

### 8. Delegation amplification
* **Impact:** a child grant exceeds its parent's authority.
* **Mitigation:** each child must satisfy: `cap ⊆ parent.dcap`,
  `dcap ⊆ cap`, `res ⊆ parent.res`, `aud ⊆ parent.aud`, `exp ≤ parent.exp`,
  `nbf ≥ parent.nbf`, `mdd < parent.mdd`, `max_value ≤ parent.max_value`
  (cannot be dropped), same `org`, `act`, `purpose`. Enforced at issue time
  and at verification. (`chain.rs::child_escalates_resources_lifetime_depth_context_limits`,
  `value_limit_cannot_be_raised_or_dropped`, `grandchild_beyond_depth`)
* **Residual:** none known within the model.

### 9. Replay attacks
* **Impact:** a captured request is executed again.
* **Mitigation:** proofs are single-use (`gh:jti` cache), fresh (max age +
  skew), body-bound and gateway-bound. (`chain.rs::proof_of_possession`,
  `cross_company.rs` replay step)
* **Residual:** the replay cache is per process. Behind a load balancer, a
  proof could be replayed once on each instance within its lifetime. Use
  sticky routing or a shared cache (roadmap). The cache is bounded and fails
  closed when full.

### 10. Forged grants
* **Impact:** arbitrary authority.
* **Mitigation:** EdDSA signatures verified with `verify_strict`; only
  `alg: EdDSA` accepted (no `none`, no HMAC confusion); unknown header
  parameters (`jku`, `x5u`, `jwk`, `crit`) rejected; keys selected only from
  the claimed domain's configured keys. (`jws.rs` tests,
  `chain.rs::tampered_and_forged_tokens`)
* **Residual:** compromise of an issuer key (see 17).

### 11. Grant theft in transit
* **Impact:** as 1.
* **Mitigation:** proof of possession; TLS. Grants are never logged.
* **Residual:** plaintext HTTP exposes grant *contents* (not usable without
  the key). Always terminate TLS in front of the gateway.

### 12. Trust-domain impersonation
* **Impact:** attacker claims to be `xyz.com`.
* **Mitigation:** `org` only selects which configured keys to try; the
  signature must verify with one of them and `iss` must match the configured
  issuer. Subject IDs must be in the issuing domain.
* **Residual:** compromise of the channel used to exchange public keys during
  onboarding. Verify fingerprints (`kid` is the RFC 7638 thumbprint) out of
  band.

### 13. Token substitution
* **Impact:** a proof or child is attached to a different grant.
* **Mitigation:** proofs bind `gh` (leaf grant hash); children bind `prt`
  (parent hash) and `iss` (parent subject).
* **Residual:** none known.

### 14. Audience confusion
* **Impact:** a grant meant for gateway A is used at gateway B.
* **Mitigation:** every grant's `aud` must contain this gateway's audience and
  child audiences must be a subset; proofs carry a single `aud`.
  (`chain.rs::time_and_audience`)
* **Residual:** two gateways configured with the same audience accept each
  other's grants by design (they are one logical recipient).

### 15. Expired credentials
* **Mitigation:** `exp`/`nbf`/`iat` checked with bounded skew on every hop.
* **Residual:** a gateway clock that drifts beyond the skew either rejects
  valid grants or accepts recently expired ones. Run NTP; tune
  `clock_skew_seconds` per site.

### 16. Revoked credentials
* **Mitigation:** revocation by agent, grant, key (issuer `kid` or holder
  thumbprint) and trust domain; checked on every hop on every request; a
  revoked parent invalidates all descendants. Revocation errors fail closed.
  (`chain.rs::revocations`)
* **Residual:** revocation is local. Gateways that do not share state must
  each be told. Short grant lifetimes bound the exposure.

### 17. Compromised signing keys
* **Impact:** forged root grants (issuer key) or delegations (holder key).
* **Mitigation:** revoke the `kid`/thumbprint; remove the key from the trust
  store; rotate. Short grant lifetimes. KMS/HSM custody recommended.
* **Residual:** until revoked, everything within the domain's allow list is
  forgeable. The receiving org's allow list and policy still bound it.

### 18. Prompt injection causing privileged actions
* **Impact:** the model is manipulated into attempting harmful actions.
* **Mitigation:** the model never authorizes. Every action is checked against
  the grant, trust and policy, independent of model output. High-impact
  actions require human approval bound to the exact request.
* **Residual:** injected actions *within* the agent's authority succeed. This
  is the main reason to keep grants task-scoped.

### 19. Malicious human insider
* **Impact:** an operator grants themselves or an agent authority, or approves
  their own request.
* **Mitigation:** every decision and approval consumption is audited with
  approver identity; approvals are bound to one request and single-use.
* **Residual:** v1 has no separation of duties: anyone who can run the CLI
  against the state file can approve and revoke. Restrict file access;
  integrate approvals with an enterprise workflow (roadmap).

### 20. Policy misconfiguration
* **Impact:** unintended allow.
* **Mitigation:** default deny; deny-overrides; unknown fields rejected;
  impossible conditions rejected; value conditions never match a missing
  value; `nexum policies validate|test`. Policy can only narrow what the chain
  and trust already permit.
* **Residual:** a syntactically valid but wrong policy. Review and test
  policies like code.

### 21. Audit tampering
* **Impact:** loss of accountability.
* **Mitigation:** hash chain detects modification, deletion and reordering
  (`nexum audit verify`); audit write failure denies the request.
* **Residual:** an attacker with write access can rewrite the entire chain
  from some point on. Ship events to an external append-only store
  (WORM/SIEM) and anchor periodic chain heads elsewhere.

### 22. Gateway bypass
* **Impact:** all controls skipped.
* **Mitigation:** architectural: the resource must accept traffic only from
  the gateway (network policy, mTLS, or the resource itself verifying
  decisions). The decision API mode relies on the caller honoring the
  decision; the MCP/A2A proxy modes enforce inline.
* **Residual:** Nexum cannot enforce what it is not in the path of.

### 23. Denial of service
* **Impact:** availability.
* **Mitigation:** body size limit (default 1 MiB), token size limit (16 KiB),
  chain length limit (8), bounded replay cache, upstream timeouts, no
  per-request network calls for verification.
* **Residual:** no rate limiting in v1; put a rate limiter in front.
  Signature verification is cheap but not free.

### 24. Compromised control plane
* **Impact:** in a future hosted deployment, malicious policy or trust pushes.
* **Mitigation:** v1 has no control plane. By design the gateway never needs
  one per request, a control plane will never hold customer signing keys or
  payloads, and the customer's local files remain the source of truth.
* **Residual:** to be revisited when a control plane exists (signed
  configuration bundles, customer co-signing).
