//! Shared constants and validation for the isolation layer.

pub mod firecracker;
pub mod host_snapshot;
pub mod paths;
pub mod validate;

pub use host_snapshot::{assert_host_clean, HostSnapshot};
pub use validate::{LaunchRequest, ValidationError};
