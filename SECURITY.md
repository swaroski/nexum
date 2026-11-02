# Security Policy

Nexum is security infrastructure, and is **experimental**: it has not yet had
an independent security review. Do not rely on it as your only control for
high-impact actions yet.

## Reporting a vulnerability

Please **do not** open a public issue. Report privately through
[GitHub Security Advisories](https://github.com/swaroski/nexum/security/advisories/new).

Include affected version/commit, a description, reproduction steps and
impact. We aim to acknowledge within 3 business days and to agree on a
disclosure timeline with you.

## Scope

In scope: authorization bypass, delegation escalation, signature or proof
verification flaws, replay, revocation bypass, audit tampering that `nexum
audit verify` fails to detect, credential leakage (logs, forwarded headers),
fail-open behavior.

See [THREAT_MODEL.md](THREAT_MODEL.md) for known residual risks; issues listed
there as residual are known limitations rather than vulnerabilities, but
better mitigations are very welcome.

## Supported versions

Only the latest release receives security fixes until 1.0.
