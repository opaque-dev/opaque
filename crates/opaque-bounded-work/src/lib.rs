#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Opaque's bounded agent work surface: the fixed-manifest task ledger
//! (`task_api`/`task_store`), Vault-signed SSH certificate execution
//! (`ssh`), inference brokering (`inference`), and the delegated metrics
//! resource authority (`resource_authority`).
//!
//! Extracted from the `opaqued` binary crate (which has no `lib.rs`, so none
//! of this was nameable from anywhere else) into its own explicit,
//! independently-buildable, independently-testable crate: this is the
//! newest, least-reviewed surface in the system, which is exactly why it
//! gets a hard boundary rather than staying folded into the 9000-line
//! `main.rs`.
//!
//! `opaqued` remains the composition root and the only place that
//! constructs a real `Enclave`/`DaemonState`. Code in this crate never names
//! either type directly (it cannot — they are private to a binary-only
//! crate); instead it depends on:
//! - [`opaque_core::enclave_facade::EnclaveFacade`] for the handful of
//!   `Enclave` operations already promoted to `opaque-core` (preflight,
//!   execute, policy swap, control-plane approval, principal-context
//!   resolution, and workspace re-verification).
//! - [`task_facade::BoundedWorkFacade`], defined in *this* crate rather than
//!   `opaque-core`, for the three operations that could not be promoted
//!   there: `ssh_profile`/`inference_profile`/`execute_task` all name
//!   `TrustedSshProfile`/`TrustedInferenceProfile`/`TaskStore`, which live
//!   here. `opaqued` implements this trait for its real `Enclave` — the
//!   same "narrow trait, foreign crate implements it" direction already
//!   established by `OperationHandler`.

pub mod inference;
pub mod resource_authority;
pub mod scope_store;
pub mod ssh;
pub mod task_api;
pub mod task_facade;
pub mod task_store;

pub mod mcp;
