#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Offline MCP admission contracts and the production stdio input protocol.
//! These helpers grant no execution authority.

pub mod gateway_contract;
pub mod protocol;
pub mod validation;
