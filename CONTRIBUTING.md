# Contributing

Thanks for helping. Nexum is security infrastructure, so the bar is
correctness first, then clarity, then features.

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./examples/cross-company/demo.sh
```

MSRV is Rust 1.87.

## Guidelines

* **Fail closed.** Every new error path must produce DENY with a specific
  `ReasonCode`. Never add a "log and continue" path to the request pipeline.
* **Tests for attacks.** Security changes need a negative test named after the
  attack it prevents. Authorization invariants get property tests.
* **No new standards.** Prefer mapping to existing standards (JOSE, OAuth,
  SPIFFE, MCP, A2A) over inventing formats.
* **Neutral core.** `nexum-core` must not depend on any framework, protocol,
  cloud or vendor; those belong in adapters.
* **No secrets in logs or audit.** Tokens, proofs, keys and payloads are never
  logged.
* **Reason codes are stable.** Never renumber or reuse an `NX-xxxx` code.
* Keep dependencies few and well-maintained; justify new ones in the PR.
* No `unsafe` (`#![forbid(unsafe_code)]`).

## Pull requests

Small, focused PRs with a clear description of the security impact. Sign off
your commits (`git commit -s`) to certify the
[Developer Certificate of Origin](https://developercertificate.org/).

By contributing you agree your contributions are licensed under Apache-2.0.
