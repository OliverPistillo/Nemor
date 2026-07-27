#![forbid(unsafe_code)]

mod backend;
mod inventory;
mod metrics;
mod plan;
mod report;
mod swapfile;
mod topology;
mod zswap_backend;

pub use inventory::{inspect_linux, DebugCounter, ProviderState, ZswapInventory, ZswapParameters};
pub use metrics::{
    estimate_tbw, parse_block_stat, BlockIoDelta, BlockStat, BudgetDecision, TbEstimate,
    WriteBudget, WriteSample,
};
pub use plan::{
    boot_plan, plan_pool, recommend_backend, BackendKind, BackendRecommendation, BenchmarkEvidence,
    BootFilePlan, BootTieringPlan, PoolContext, PoolIntent, PoolPlan, RecommendationInput,
    StorageClass, TIERING_AUDIT_REASON, TIERING_RULE_VERSION,
};
pub use report::{inspect_host, TieringAuditReport};
pub use swapfile::{
    plan_swapfile, validate_candidate_path, FilesystemKind, SwapfileContext, SwapfileOwnership,
    SwapfilePlan,
};
pub use topology::{inspect_storage, BlockDevice, StorageTopology};
pub use zswap_backend::{LinuxZswapBackend, StorageMetricsBackend, ZswapBackend};

#[cfg(test)]
mod tests;
pub use backend::{
    apply_swapfile, rollback_swapfile, BackendError, LinuxSwapfileBackend, MutationSnapshot,
    SwapfileBackend, TransactionOutcome,
};
