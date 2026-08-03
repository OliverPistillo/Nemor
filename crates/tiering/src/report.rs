use crate::{
    inspect_linux, inspect_storage, recommend_backend, BackendKind, BackendRecommendation,
    BudgetDecision, StorageTopology, ZswapInventory,
};
use common::TieringConfig;
use policy_engine::PressureState;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TieringAuditReport {
    pub timestamp_ns: i64,
    pub zswap: ZswapInventory,
    pub current_backend: BackendKind,
    pub root_storage: StorageTopology,
    pub budget: BudgetDecision,
    pub recommendation: BackendRecommendation,
    pub rollback_pending: bool,
    pub recovery_pending: bool,
    pub requires_boot_validation: bool,
    pub dry_run: bool,
}

pub fn inspect_host(
    config: &TieringConfig,
    timestamp_ns: i64,
) -> Result<TieringAuditReport, String> {
    let zswap = inspect_linux(Path::new("/"), true).map_err(|error| error.to_string())?;
    let (source, filesystem) =
        root_mount().unwrap_or_else(|| ("unknown".to_owned(), "unknown".to_owned()));
    let root_storage = inspect_storage(Path::new("/"), &source, &filesystem);
    let budget = BudgetDecision {
        allowed: true,
        instantaneous_mib_per_second: 0.0,
        rolling_minute_mib_per_second: 0.0,
        rolling_hour_gib: 0.0,
        daily_gib: 0.0,
        annual_tb: 0.0,
        reasons: vec!["no_write_delta_interval_yet".to_owned()],
    };
    let current_backend = if zswap.parameters.enabled == Some(true) {
        BackendKind::Mixed
    } else {
        BackendKind::Zram
    };
    let recommendation = recommend_backend(&crate::RecommendationInput {
        current: current_backend,
        gaming: false,
        pressure: PressureState::Watch,
        storage: &root_storage,
        zram_benchmark: None,
        zswap_benchmark: None,
        profile_evidence: None,
        budget: &budget,
        safety_events: 0,
        source_state: "unverified",
        environment_identity: "unverified",
    });
    Ok(TieringAuditReport {
        timestamp_ns,
        requires_boot_validation: zswap.parameters.enabled != Some(true) || zswap.provider.conflict,
        zswap,
        current_backend,
        root_storage,
        budget,
        recommendation,
        rollback_pending: false,
        recovery_pending: false,
        dry_run: config.dry_run,
    })
}

fn root_mount() -> Option<(String, String)> {
    let input = fs::read_to_string("/proc/self/mountinfo").ok()?;
    for line in input.lines() {
        let (left, right) = line.split_once(" - ")?;
        let fields: Vec<_> = left.split_whitespace().collect();
        if fields.get(4) != Some(&"/") {
            continue;
        }
        let right: Vec<_> = right.split_whitespace().collect();
        return Some((right.get(1)?.to_string(), right.first()?.to_string()));
    }
    None
}
