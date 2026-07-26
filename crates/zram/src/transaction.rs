use crate::{DeviceInventory, Ownership, ZramBackend, ZramError, ZramProfilePlan};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationPhase {
    Snapshot,
    ReplacementCreated,
    AlgorithmConfigured,
    Initialized,
    Activated,
    OriginalDeactivated,
    Verified,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MutationSnapshot {
    pub session_id: i64,
    pub timestamp_ns: i64,
    pub provider: crate::Provider,
    pub original: DeviceInventory,
    pub replacement_name: Option<String>,
    pub requested_plan: ZramProfilePlan,
    pub phase: MutationPhase,
    pub rollback_pending: bool,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionOutcome {
    pub applied: bool,
    pub verified: bool,
    pub rolled_back: bool,
    pub phase: MutationPhase,
}

pub fn apply_plan<B: ZramBackend>(
    backend: &mut B,
    snapshot: &mut MutationSnapshot,
) -> Result<TransactionOutcome, ZramError> {
    if snapshot.requested_plan.dry_run {
        return Ok(TransactionOutcome {
            applied: false,
            verified: false,
            rolled_back: false,
            phase: MutationPhase::Snapshot,
        });
    }
    if !snapshot.requested_plan.allowed {
        return Err(ZramError::Blocked(
            snapshot.requested_plan.blocked_reasons.join(","),
        ));
    }
    if !matches!(
        snapshot.original.ownership,
        Ownership::NemorOwned | Ownership::Adopted
    ) {
        return Err(ZramError::Blocked(
            "original ownership is ambiguous".to_owned(),
        ));
    }
    let initial_capacity = backend.effective_valid_swap_capacity()?;
    let replacement = backend.create_isolated_managed_device()?;
    snapshot.replacement_name = Some(replacement.name.clone());
    snapshot.phase = MutationPhase::ReplacementCreated;
    let result = apply_after_create(backend, snapshot, initial_capacity);
    if let Err(error) = result {
        snapshot.last_error = Some(error.to_string());
        snapshot.rollback_pending = true;
        let _ = rollback(backend, snapshot);
        return Err(error);
    }
    result
}

fn apply_after_create<B: ZramBackend>(
    backend: &mut B,
    snapshot: &mut MutationSnapshot,
    initial_capacity: u64,
) -> Result<TransactionOutcome, ZramError> {
    let replacement = snapshot
        .replacement_name
        .as_deref()
        .ok_or_else(|| ZramError::Verification("replacement is missing".to_owned()))?;
    let algorithm = snapshot
        .requested_plan
        .selected_algorithm
        .as_deref()
        .ok_or_else(|| ZramError::Blocked("selected algorithm unavailable".to_owned()))?;
    backend.configure_uninitialized(replacement, algorithm)?;
    snapshot.phase = MutationPhase::AlgorithmConfigured;
    let disksize = snapshot
        .requested_plan
        .proposed_disksize
        .filter(|value| *value > 0)
        .ok_or_else(|| ZramError::Blocked("proposed disksize invalid".to_owned()))?;
    backend.initialize(replacement, disksize)?;
    snapshot.phase = MutationPhase::Initialized;
    let initialized = backend.verify(replacement)?;
    if initialized.disksize != Some(disksize) {
        return Err(ZramError::Verification(
            "replacement disksize readback mismatch".to_owned(),
        ));
    }
    backend.activate(
        replacement,
        snapshot.requested_plan.proposed_priority.unwrap_or(100),
    )?;
    snapshot.phase = MutationPhase::Activated;
    ensure_swap(backend)?;
    if snapshot.requested_plan.requires_swap_migration {
        if initial_capacity == 0 {
            return Err(ZramError::Verification(
                "migration cannot start without valid swap".to_owned(),
            ));
        }
        backend.deactivate(&snapshot.original.name)?;
        snapshot.phase = MutationPhase::OriginalDeactivated;
        ensure_swap(backend)?;
    }
    let verified = backend.verify(replacement)?;
    if !verified.active_swap {
        return Err(ZramError::Verification(
            "replacement is not active swap".to_owned(),
        ));
    }
    snapshot.phase = MutationPhase::Verified;
    snapshot.rollback_pending = false;
    Ok(TransactionOutcome {
        applied: true,
        verified: true,
        rolled_back: false,
        phase: MutationPhase::Verified,
    })
}

fn ensure_swap<B: ZramBackend>(backend: &B) -> Result<(), ZramError> {
    if backend.effective_valid_swap_capacity()? == 0 {
        Err(ZramError::Verification(
            "no-swap-loss invariant violated".to_owned(),
        ))
    } else {
        Ok(())
    }
}

pub fn rollback<B: ZramBackend>(
    backend: &mut B,
    snapshot: &mut MutationSnapshot,
) -> Result<TransactionOutcome, ZramError> {
    if snapshot.phase == MutationPhase::RolledBack {
        return Ok(TransactionOutcome {
            applied: false,
            verified: true,
            rolled_back: true,
            phase: MutationPhase::RolledBack,
        });
    }
    if snapshot.original.active_swap {
        let current = backend.verify(&snapshot.original.name)?;
        if !current.active_swap {
            backend.activate(
                &snapshot.original.name,
                snapshot.original.priority.unwrap_or(100),
            )?;
            ensure_swap(backend)?;
        }
    }
    if let Some(replacement) = snapshot.replacement_name.as_deref() {
        if backend.is_owned(replacement) {
            let current = backend.verify(replacement)?;
            if current.active_swap {
                backend.deactivate(replacement)?;
                ensure_swap(backend)?;
            }
            backend.remove_managed_device(replacement)?;
        }
    }
    snapshot.phase = MutationPhase::RolledBack;
    snapshot.rollback_pending = false;
    Ok(TransactionOutcome {
        applied: false,
        verified: true,
        rolled_back: true,
        phase: MutationPhase::RolledBack,
    })
}

pub fn recover_pending<B: ZramBackend>(
    backend: &mut B,
    snapshot: &mut MutationSnapshot,
) -> Result<TransactionOutcome, ZramError> {
    if !snapshot.rollback_pending || snapshot.phase == MutationPhase::RolledBack {
        return Ok(TransactionOutcome {
            applied: false,
            verified: true,
            rolled_back: snapshot.phase == MutationPhase::RolledBack,
            phase: snapshot.phase,
        });
    }
    if !matches!(
        snapshot.original.ownership,
        Ownership::NemorOwned | Ownership::Adopted
    ) {
        return Err(ZramError::Blocked(
            "recovery ownership is ambiguous".to_owned(),
        ));
    }
    rollback(backend, snapshot)
}
