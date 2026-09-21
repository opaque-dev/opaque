#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod approval_gate;
pub mod attest;
pub mod audit;
pub mod bundle;
pub mod capability;
pub mod enclave_facade;
pub mod evidence_checkpoint;
pub mod execve_map;
pub mod identity;
pub mod identity_lifecycle;
pub mod inference;
pub mod keyfile;
pub mod operation;
pub mod operation_handler;
pub mod peer;
pub mod policy;
pub mod policy_document;
pub mod policy_regression;
pub mod profile;
pub mod proto;
pub mod release;
pub mod resolver;
pub mod sanitize;
pub mod scope;
pub mod seal;
pub mod secret;
pub mod socket;
pub mod ssh;
pub mod task;
pub mod tenant;
pub mod trust_domain;
pub mod validate;
pub mod workload;
pub mod workstation;

pub const API_VERSION: u32 = 1;

/// Maximum IPC frame size in bytes (128 KB).
///
/// Both daemon and CLI must agree on this limit. Using a shared constant
/// prevents frame-size mismatches that could cause silent truncation or
/// connection resets.
pub const MAX_FRAME_LENGTH: usize = 128 * 1024;

pub mod resource_auth;

pub mod mcp;
