// Hand-written guidance for each reason code page (/errors/nx-xxxx/).
// Meaning, stage and security event are generated from nexum-core; this file
// adds why it happens and how to fix it. scripts/sync.mjs fails if a code is
// missing here, so a new code cannot ship without documentation.
export default {
  "NX-1001": {
    why: "The request carried no `Nexum-Grant` header, or it was empty.",
    fix: "Send the grant chain, root first, comma-separated, in `Nexum-Grant`. With the CLI: `nexum call --grant root.jwt [--grant child.jwt]`.",
  },
  "NX-1002": {
    why: "More than 8 grants were presented.",
    fix: "Flatten the delegation: have an earlier holder delegate directly to the final agent instead of through intermediaries.",
  },
  "NX-1003": {
    why: "A grant isn't a well-formed compact JWS with the `nexum-grant+jwt` type, or it carries claims or header parameters Nexum doesn't understand.",
    fix: "Use grants produced by `nexum grants issue/delegate` or `nexum_grant::sign_grant`. Unknown claims are rejected on purpose, so a restriction the verifier doesn't understand is never silently ignored.",
  },
  "NX-1004": {
    why: "A grant or proof uses an algorithm other than `EdDSA` (Ed25519). `none`, HMAC and RSA are rejected.",
    fix: "Sign with an Ed25519 key. `nexum agents register` and `nexum init` generate suitable keys.",
  },
  "NX-1005": {
    why: "A signature didn't verify: the grant was modified after signing, or signed with a different key than the one it names.",
    fix: "Re-issue the grant. If you didn't modify it, treat this as tampering and investigate where the grant travelled.",
  },
  "NX-1006": {
    why: "The root grant's `org` isn't in this gateway's trust store, or its `iss` doesn't match the issuer configured for that domain.",
    fix: "On the receiving side: `nexum trust add <domain> --issuer <uri> --key <jwk>`. On the issuing side: check `--issuer` in `nexum init` matches what the partner configured.",
  },
  "NX-1007": {
    why: "The root grant's `kid` isn't among the keys this gateway trusts for that organization. Keys are looked up only within the claimed domain.",
    fix: "Share the issuer's current public JWK with the receiving organization, or re-issue with the key they trust. After key rotation, both keys can be listed during the overlap.",
  },
  "NX-1008": {
    why: "A grant in the chain is past its `exp` (beyond the configured clock skew).",
    fix: "Issue a fresh grant. Short lifetimes are intentional; agents should request new authority rather than hold long-lived grants.",
  },
  "NX-1009": {
    why: "A grant's `nbf` or `iat` is in the future beyond the allowed clock skew.",
    fix: "Synchronize clocks (NTP) on the issuer and gateway, or raise `gateway.clock_skew_seconds` slightly.",
  },
  "NX-1010": {
    why: "The root grant lives longer than the trust domain's `max_grant_ttl_seconds` (default 3600).",
    fix: "Issue shorter grants (`--ttl`), or ask the receiving organization to raise the limit for your domain.",
  },
  "NX-1011": {
    why: "No grant `aud` matches this gateway's `gateway.audience`.",
    fix: "Issue the grant with `--aud <receiving gateway's audience>`. A grant for one gateway can't be replayed at another.",
  },
  "NX-1012": {
    why: "A child grant's `iss` isn't its parent's `sub`, or its `prt` isn't the hash of the parent token presented before it.",
    fix: "Present the exact chain, root first, in delegation order. Mint children with `nexum grants delegate` so the link is computed for you.",
  },
  "NX-1013": {
    why: "A child grant claims capabilities outside its parent's delegatable set (`dcap`), or a grant's `dcap` isn't a subset of its `cap`.",
    fix: "Issue the parent with `--delegatable <cap>` for what it may pass on, and delegate only those.",
  },
  "NX-1014": {
    why: "A child grant claims resources broader than its parent's.",
    fix: "Delegate an equal or narrower resource pattern, or omit `--res` to inherit the parent's.",
  },
  "NX-1015": {
    why: "The parent's remaining delegation depth (`mdd`) is 0, or the child didn't decrease it.",
    fix: "Issue the parent with `--max-depth N` (N ≥ 1) if it should be able to delegate.",
  },
  "NX-1016": {
    why: "A child grant expires after its parent, or starts before it.",
    fix: "Delegate with a shorter `--ttl`; `nexum grants delegate` clamps to the parent's expiry automatically.",
  },
  "NX-1017": {
    why: "An agent's SPIFFE ID is outside the trust domain that issued the grant, e.g. `partner.example` vouching for `spiffe://other.example/...`.",
    fix: "Organizations can only vouch for their own agents. Use an agent ID in the issuer's trust domain.",
  },
  "NX-1018": {
    why: "A child grant changes the actor (`act.sub`), purpose, or widens the audience of its parent.",
    fix: "Leave actor and purpose unchanged when delegating, and keep the audience a subset of the parent's.",
  },
  "NX-1019": {
    why: "A child grant raises or removes its parent's `max_value`.",
    fix: "Delegate with an equal or lower `--max-value`, or omit it to inherit the parent's limit.",
  },
  "NX-2001": {
    why: "No `Nexum-Proof` header. Grants are not bearer tokens; every request needs a fresh proof.",
    fix: "Sign a proof per request with the leaf holder's key: `nexum call`, the Python client, or `nexum_grant::create_proof`.",
  },
  "NX-2002": {
    why: "The proof isn't signed by the leaf grant's holder key (`cnf.jwk`). This is what a stolen grant looks like.",
    fix: "Sign the proof with the private key the leaf grant was issued to. If the key is right, the grant may belong to a different agent.",
  },
  "NX-2003": {
    why: "The proof's `iat` is older than `gateway.proof_max_age_seconds` (default 60) or in the future.",
    fix: "Create the proof immediately before sending; never cache proofs. Check clock synchronization.",
  },
  "NX-2004": {
    why: "This exact proof (`jti`) was already used. Proofs are single-use.",
    fix: "Create a new proof for every request, including retries.",
  },
  "NX-2005": {
    why: "The proof's body hash, grant hash or audience doesn't match this request: the body changed after signing, or the proof was made for another grant or gateway.",
    fix: "Sign the exact bytes you send, after any serialization. Don't let proxies re-encode the body. If you didn't change it, something in the path did.",
  },
  "NX-3001": {
    why: "An agent in the chain was revoked with `nexum agents revoke`.",
    fix: "If the revocation is intended, nothing to fix. Otherwise register a new agent identity; revocations are not reversed silently.",
  },
  "NX-3002": {
    why: "A grant in the chain (or an ancestor) was revoked with `nexum grants revoke`.",
    fix: "Issue a new grant if the agent should still have authority.",
  },
  "NX-3003": {
    why: "The receiving organization revoked trust in the issuing organization with `nexum trust revoke`.",
    fix: "Contact the receiving organization. Nothing the caller does can restore trust unilaterally.",
  },
  "NX-3004": {
    why: "An issuer key (`kid`) or agent key (JWK thumbprint) in the chain was revoked with `nexum trust revoke-key`.",
    fix: "Rotate to a new key and re-issue grants signed by or bound to it.",
  },
  "NX-4001": {
    why: "Everything checked out and a policy rule allowed the action.",
    fix: "Nothing to fix.",
  },
  "NX-4002": {
    why: "A policy rule with `effect: approval` matched, typically a value threshold.",
    fix: "An approver runs `nexum approvals approve <id>`; then retry the identical request with `Nexum-Approval: <id>` and a fresh proof.",
  },
  "NX-4003": {
    why: "A matching human approval was presented and consumed. It can't be used again.",
    fix: "Nothing to fix.",
  },
  "NX-4004": {
    why: "The approval id is unknown, not approved yet, rejected, expired, already used, or was issued for a different request (other value, resource, agent or actor).",
    fix: "Retry the exact request that was approved, once, before `gateway.approval_ttl_seconds`. Changed requests need a new approval.",
  },
  "NX-4031": {
    why: "The receiving organization's trust store doesn't allow this capability from the caller's organization, or explicitly denies it, even though the grant carries it.",
    fix: "Ask the receiving organization to add it to `allow` for your domain. The issuer can't grant what the receiver doesn't accept.",
  },
  "NX-4032": {
    why: "The leaf grant doesn't carry the requested capability. For a delegated agent: its parent never delegated it.",
    fix: "Request authority that includes the capability, e.g. `--cap <action>` on issue, or `--delegatable` on the parent and `--cap` on the delegation.",
  },
  "NX-4033": {
    why: "The requested resource is outside the leaf grant's resource patterns.",
    fix: "Issue or delegate a grant whose `--res` covers the resource, e.g. `supplier://abc/*`.",
  },
  "NX-4034": {
    why: "The request's value exceeds the grant's `max_value`, or the grant has a limit and the request has no value.",
    fix: "Send the value with the request, keep it within the grant's limit, or obtain a grant with a higher limit.",
  },
  "NX-4035": {
    why: "A policy rule with `effect: deny` matched. Deny overrides any allow.",
    fix: "If the action should be possible, change the policy (and run `nexum eval run` before deploying). Otherwise the denial is working as intended.",
  },
  "NX-4036": {
    why: "No policy rule allowed the action: no applicable policy, no matching rule, or a value condition on a request without a value. Default deny.",
    fix: "Add a rule for the action, resource and conditions. Test with `nexum policies test` first.",
  },
  "NX-4037": {
    why: "Policy forbids this capability through delegation (`delegation.forbidden`, or not in `delegation.allowed`), even though the chain carries it.",
    fix: "Have the root holder perform the action directly, or ask the receiving organization to permit delegated use.",
  },
  "NX-4038": {
    why: "The chain is deeper than the policy's `delegation.max_depth`.",
    fix: "Use a shorter delegation chain.",
  },
  "NX-5001": {
    why: "The request couldn't be normalized: malformed or ambiguous JSON (including duplicate keys), a wildcard action or resource, unknown fields, an unknown MCP server or A2A method, or routing headers that disagree with the body.",
    fix: "Send exactly one concrete action and resource in valid JSON without duplicate keys. For MCP, `Mcp-Method`/`Mcp-Name` must match the body.",
  },
  "NX-5002": {
    why: "The policy decision point failed. Nexum fails closed.",
    fix: "Check the gateway logs and `nexum policies validate`. Operators: alert on this; it denies all traffic.",
  },
  "NX-5003": {
    why: "The audit event couldn't be written, so the decision was changed to DENY. Nothing happens unaudited.",
    fix: "Check disk space and permissions for the audit path; `nexum doctor` verifies it.",
  },
  "NX-5004": {
    why: "Local state (revocations, approvals) couldn't be read or written. Nexum fails closed.",
    fix: "Check the state database path, permissions and disk; `nexum doctor` verifies it.",
  },
};

// Why each family of checks exists, shown on every code page in the family.
export const rationale = {
  chain:
    "Authority must trace back to an organization this gateway trusts, through grants that each only narrow their parent. Anything that can't be verified is treated as forged.",
  proof:
    "Grants are holder-of-key, not bearer tokens. A fresh, single-use signature over the exact body means a stolen grant, a replayed request, or a modified body is useless.",
  request:
    "The gateway authorizes one exact action on one exact resource. Anything ambiguous could be authorized as one thing and executed as another.",
  authority:
    "The presenting agent can only use authority its own grant carries. This is what stops a compromised sub-agent or a prompt-injected model from exceeding what it was given.",
  trust:
    "The receiving organization decides what it accepts from each partner. An issuer can't grant itself access the receiver never agreed to.",
  policy:
    "Policy runs after chain authority and trust, so it can only narrow. Deny overrides, and no matching rule means deny.",
  approval:
    "Approvals are single-use and bound to the exact request, so one approval can't be stretched to a bigger or different action.",
  audit:
    "Every decision is recorded before it takes effect. If it can't be recorded, it doesn't happen.",
};
