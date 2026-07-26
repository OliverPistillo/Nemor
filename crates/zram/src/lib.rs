#![forbid(unsafe_code)]

pub mod backend;
pub mod benchmark;
pub mod error;
pub mod inventory;
pub mod metrics;
pub mod profile;
pub mod report;
pub mod transaction;

pub use backend::{LinuxZramBackend, ZramBackend};
pub use benchmark::{BenchmarkEvidence, BenchmarkPlan, BenchmarkResult, DatasetKind};
pub use error::ZramError;
pub use inventory::{
    inspect_linux, DeviceInventory, Inventory, Ownership, Provider, WritableCapabilities,
};
pub use metrics::CompressionMetrics;
pub use profile::{
    plan_profile, ProfileContext, ZramProfile, ZramProfilePlan, PROFILE_RULE_VERSION,
};
pub use report::{ZramAuditReport, AUDIT_REASON};
pub use transaction::{
    apply_plan, recover_pending, rollback, MutationSnapshot, TransactionOutcome,
};

#[cfg(test)]
mod tests;
