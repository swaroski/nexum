//! Authorization scenarios for Nexum Eval and the browser playground.
//!
//! - [`Scenario`]: the `EvalSuite` scenario DSL (grants, request, attack,
//!   expectation).
//! - [`mint`]: turns a scenario into exactly what an agent would present (a
//!   signed grant chain, a proof and a body), applying attacks. Delegations
//!   are signed as written, without issue-time checks, so the *verifier* is
//!   what gets tested.
//! - [`decide`]: an in-memory decision pipeline for decision-API requests,
//!   built from the same primitives as the gateway (`Verifier`, attenuation
//!   and trust checks, the built-in `PolicySet`) in the same order. The
//!   gateway remains the reference: `tests/agreement.rs` runs the official
//!   eval suite through this pipeline and requires the same outcomes and
//!   reason codes the gateway is held to.
//!
//! No I/O, no clocks, no threads: `now` is always passed in, so this compiles
//! to `wasm32-unknown-unknown`.

#![forbid(unsafe_code)]

mod decide;
mod mint;
mod scenario;

pub use decide::{Check, Decision, decide, normalize_authorize};
pub use mint::{Minted, mint};
pub use scenario::{Attack, GrantSpec, KIND, RequestSpec, RpcSpec, Scenario, Suite, expand};
