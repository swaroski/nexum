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
  a derived capability that default-deny blocks. Bodies with duplicate JSON
  keys are rejected, so the gateway and the server cannot disagree about
  which tool or method a message names (parser differential). (`cross_company.rs::mcp_tool_calls_are_enforced_and_forwarded`)
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
* **Mitigation:** `exp`/`nbf`/`iat` checked with bounded skew on every hop,
  using saturating arithmetic so crafted extreme timestamps cannot wrap
  around a check. (`chain.rs::extreme_timestamps_do_not_overflow`)
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
* **Mitigation:** revoke the `kid`/thumbprint (`nexum trust revoke-key`);
  remove the key from the trust store; rotate. Short grant lifetimes. KMS/HSM custody recommended.
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
  (`nexum audit verify`); stored events must be byte-identical to their
  canonical encoding, so injected fields are detected too; audit write failure denies the request.
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
* **Residual:** to be revisited when a control plane exists. Planned design
  (docs/PLATFORM.md section 9): outbound-only connections, configuration
  bundles signed by the console *and* co-signed by a customer-held key, last
  good bundle enforced while offline, never fail-open on expiry.

## Platform components

Threats introduced by Nexum Eval, authority tracing, the docs site and the
planned console. None of these components is on the request path. Design:
[docs/PLATFORM.md](docs/PLATFORM.md).

### 25. Eval gives false assurance or is subverted
* **Impact:** a policy that leaks authority ships because evals passed.
* **Mitigation:** scenarios run the real verifier, PDP and adapters; every
  ALLOW baseline is re-run under 12 attacks; failures that are more
  permissive than expected are reported as critical and fail the run. The
  sandbox uses an ephemeral issuer key, in-memory state and never calls
  upstreams, so a suite (including one from an untrusted pull request) can't
  read real keys, touch production state or reach the network.
* **Residual:** evals prove only what they encode. A PR can change a policy
  *and* its expectation together; protect `evals/`, `policy.yaml` and
  `trust.yaml` with code owners. Passing evals is not a security review.

### 26. Telemetry leaks sensitive identifiers
* **Impact:** actor ids (often email addresses), agent ids and resource names
  reach third-party observability backends.
* **Mitigation:** spans and audit never contain tokens, proofs, keys, request
  bodies, prompts or model output; agent/org/actor attributes come from the
  verified chain only; metrics never use ids as labels; OTLP export goes over
  plain HTTP only to a local or sidecar collector that the operator controls
  (`https://` endpoints are refused).
* **Residual:** actor and resource values are personal or business data.
  Filter them in the collector if your backend is outside your boundary;
  field-level redaction in the gateway is on the roadmap.

### 27. Spoofed trace correlation
* **Impact:** an attacker sets `traceparent` so its requests appear in someone
  else's trace, misleading an investigation.
* **Mitigation:** the trace id is recorded as caller-asserted, never affects a
  decision, and `nexum trace inspect` labels it as such. Each hop's own
  identity, chain and decision come from the verified audit event.
* **Residual:** until the proof binds the trace id (planned `tid` claim),
  trace membership is a hint, not evidence.

### 28. Tampered audit used for explanations
* **Impact:** a forged event makes `trace inspect` explain a decision that
  never happened.
* **Mitigation:** `trace inspect` verifies each audit log's hash chain before
  reading it and refuses to explain from a log that fails. New audit fields
  are omitted when empty, so pre-existing events keep their canonical form,
  and adding a field to a stored event is detected as tampering.
* **Residual:** as #21: an attacker who can rewrite the whole chain can forge
  history. Ship audit to an append-only store.

### 29. Docs, Action and console supply chain
* **Impact:** users are misled by a compromised docs site or link; a
  compromised Action runs in users' CI; the local console becomes a remote
  control surface.
* **Mitigation:** the docs site is static and has no runtime role; the CLI's
  "Learn more" links point at the project's own GitHub Pages site. The Action
  builds Nexum from the pinned action ref with `--locked`, uses no secrets and
  needs only `contents: read`; pin it to a commit SHA. `nexum console` refuses
  non-loopback binds, requires a per-session bearer token (custom header, no
  CORS, so cross-site requests can't carry it), rejects unexpected `Host`
  headers (DNS rebinding), sets a strict CSP and frame denial, renders all
  audit data as text, never holds the org signing key, and performs approvals
  and revocations through the same audited state functions as the CLI.
* **Residual:** website npm dependencies are not covered by `cargo deny`; a
  custom domain would need its own takeover protection. Anyone who can read
  the console's terminal output (the token) is the operator.

### 30. External policy engine (OPA)
* **Impact:** a compromised or misconfigured OPA allows or denies the wrong
  things; an unreachable OPA blocks traffic.
* **Mitigation:** OPA is asked only after chain verification, proof, chain
  authority and trust, so it can never grant what those deny. Only a boolean
  or a strict `{outcome, policy_id, rule_id}` object is accepted; an undefined
  rule, HTTP error, timeout (default 500 ms), redirect or oversized response is
  `DENY NX-5002`.
* **Residual:** OPA is trusted for everything after trust. Run it as a sidecar
  on loopback, protect its policy bundle like `policy.yaml`, and test it with
  `nexum eval run`.

### 31. Administrative events, simulation and the playground
* **Impact:** a misleading audit timeline; a simulation that understates the
  impact of a change; unsafe code in the browser build.
* **Mitigation:** administrative events are appended to the same hash chain
  as decisions, only after the action succeeded, and the CLI exits non-zero if
  the action happened but couldn't be audited. Simulation replays only
  decisions that reached policy (earlier stages can't change) and reports
  events too old to re-evaluate instead of guessing. The playground pipeline
  is held to the gateway's results by a test on the official eval suite; its
  `unsafe` is confined to a ~40-line wasm shim that never runs server-side.
* **Residual:** `operator` is self-reported (OS user or `--by`/`--as`), not
  authenticated. Administrative events need the SQLite audit provider; with
  JSONL they are skipped with a warning. Simulation covers the built-in
  policy engine only, not trust-store changes or OPA.
