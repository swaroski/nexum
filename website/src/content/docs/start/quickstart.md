---
title: Quickstart
description: Install Nexum, issue a grant, and get your first decision.
---

## Install

Download a prebuilt binary for Linux (x86_64, arm64), macOS (Apple Silicon,
Intel) or Windows from the
[releases page](https://github.com/swaroski/nexum/releases). Each release has
`SHA256SUMS`, a CycloneDX SBOM and build provenance you can verify:

```bash
gh attestation verify nexum-0.1.0-x86_64-unknown-linux-musl.tar.gz --repo swaroski/nexum
```

Or build from source, or run the container:

```bash
cargo install --locked --git https://github.com/swaroski/nexum --tag v0.1.0 nexum
docker run --rm ghcr.io/swaroski/nexum:0.1 --version
```

See [Deploy](/nexum/guides/deploy/) for Docker and Kubernetes.

## One organization, one agent

```bash
nexum init --domain example.com        # config, trust store, starter policy, org key
nexum agents register --id spiffe://example.com/agents/support-bot --name support-bot
nexum grants issue --sub spiffe://example.com/agents/support-bot \
  --holder .nexum/keys/support-bot.key.json \
  --cap refund.create --res 'app://orders/*' --aud example.com --out bot.jwt
nexum gateway start &
```

`init` writes `nexum.yaml`, `trust.yaml`, `policy.yaml` and an organization
signing key under `.nexum/`. The grant is a 15-minute, holder-bound JWT:
useless without the agent's private key.

## Ask for a decision

```bash
nexum call --grant bot.jwt --key .nexum/keys/support-bot.key.json \
  --action refund.create --resource app://orders/42 --value 1700
```

```text
APPROVAL REQUIRED NX-4002

  Agent:      spiffe://example.com/agents/support-bot
  Requested:  refund.create  app://orders/42
  Value:      1700
  Reason:     Policy requires human approval for this action.
  Policy:     example.com-default / refund-approval
  Approval:   01a1999a-6988-77d1-8883-a360a450ad5e
```

Approve it and retry with `--approval <id>`:

```bash
nexum approvals approve 01a1999a-6988-77d1-8883-a360a450ad5e --by you@example.com
```

## Check everything

```bash
nexum doctor          # config, keys, trust, policy, state, audit integrity
nexum audit tail      # every decision so far
nexum audit verify    # the hash chain is intact
```

Next: run the [cross-company demo](/nexum/start/cross-company-demo/).
