use crate::{BenchmarkEvidence, Inventory, ZramProfilePlan};
use serde::{Deserialize, Serialize};

pub const AUDIT_REASON: &str = "zram_observe_audit";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZramAuditReport {
    pub timestamp_ns: i64,
    pub inventory: Inventory,
    pub plans: Vec<ZramProfilePlan>,
    pub benchmark_evidence: Vec<BenchmarkEvidence>,
    pub rollback_pending: bool,
    pub recovery_pending: bool,
    pub dry_run: bool,
}
