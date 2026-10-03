//! Shared constants and validation for the isolation layer.

pub mod decision_chain;
pub mod firecracker;
pub mod host_snapshot;
pub mod paths;
pub mod validate;

pub use decision_chain::{
    default_chain_path, ChainError, ChainVerdict, DecisionChain,
};
pub use host_snapshot::{assert_host_clean, assert_host_vmm_hygiene, HostSnapshot};
pub use validate::{LaunchRequest, ValidationError};
