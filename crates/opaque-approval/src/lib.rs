#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Approval mechanisms for the Opaque daemon.
//!
//! This crate hosts the *mechanisms* backing `opaque_core::approval_gate`'s
//! `ApprovalGate` trait: device pairing, FIDO2, the factor registry, native
//! (LocalAuthentication / polkit) prompting, the LAN approval-server relay,
//! and the dormant APNs push transport.
//!
//! The trait itself — and its `NativeApprovalGate` / `InsecureAutoApproveGate`
//! implementors — stay in `opaqued::enclave` (they hold daemon-private state
//! and Rust forbids inherent `impl` blocks on foreign types). This crate has
//! zero references to `opaqued`'s `DaemonState`/`DaemonConfig`/`Enclave` in
//! either direction; `opaqued` depends on it, never the reverse.

pub use opaque_native_approval as approval;
// Suppressed at the same granularity as before this crate existed: these
// three modules carried `#[allow(dead_code)]` on their `mod` declaration in
// opaqued's main.rs (some items — e.g. `ApprovalServer::state()` — are
// exercised only by tests within the module itself, not by any external
// caller). Preserved verbatim across the move.
#[allow(dead_code)]
pub mod approval_server;
pub mod factors;
#[allow(dead_code)]
pub mod fido2;
#[allow(dead_code)]
pub mod pairing;
pub mod push;
pub mod remote;
pub mod scope_review;
