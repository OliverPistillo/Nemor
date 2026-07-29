//! Fixed Checkpoint 3C owned-worker step protocol.
//!
//! The future executor creates one session before allocation, attaches that
//! process to its exact owned systemd scope, verifies `MemoryMax`, and only
//! then may submit a typed level command.

use crate::performance::{INCOMPRESSIBLE_GENERATOR_ID, SYNTHETIC_GENERATOR_VERSION};
use crate::pressure::{PlannedPressureLevel, WorkerLevelAcknowledgement};
use crate::{synthetic_byte, SyntheticPattern};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PRESSURE_WORKER_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerProtocolState {
    StartedUnallocated,
    ScopeAndMemoryMaxVerified,
    LevelAcknowledged,
    Holding,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerLevelCommand {
    pub protocol_version: u32,
    pub experiment_id: String,
    pub run_id: String,
    pub level_index: usize,
    pub seed: u64,
    pub prior_touched_bytes: u64,
    pub requested_delta_bytes: u64,
    pub target_touched_bytes: u64,
    pub generator_id: String,
    pub generator_version: u32,
}

pub struct ProgressiveWorkerSession {
    experiment_id: String,
    run_id: String,
    seed: u64,
    worker_pid: u32,
    worker_start_ticks: u64,
    memory_max_bytes: u64,
    state: WorkerProtocolState,
    payload: Vec<u8>,
}

impl ProgressiveWorkerSession {
    pub fn start_unallocated(
        experiment_id: String,
        run_id: String,
        seed: u64,
        worker_pid: u32,
        worker_start_ticks: u64,
    ) -> Result<Self> {
        if experiment_id.is_empty()
            || run_id.is_empty()
            || worker_pid == 0
            || worker_start_ticks == 0
        {
            bail!("progressive worker identity is incomplete");
        }
        Ok(Self {
            experiment_id,
            run_id,
            seed,
            worker_pid,
            worker_start_ticks,
            memory_max_bytes: 0,
            state: WorkerProtocolState::StartedUnallocated,
            payload: Vec::new(),
        })
    }

    pub fn touched_bytes(&self) -> u64 {
        self.payload.len() as u64
    }

    pub fn state(&self) -> WorkerProtocolState {
        self.state
    }

    pub fn verify_owned_scope_and_memory_max(&mut self, memory_max_bytes: u64) -> Result<()> {
        if self.state != WorkerProtocolState::StartedUnallocated
            || !self.payload.is_empty()
            || memory_max_bytes == 0
        {
            bail!("scope/MemoryMax verification must precede every allocation");
        }
        self.memory_max_bytes = memory_max_bytes;
        self.state = WorkerProtocolState::ScopeAndMemoryMaxVerified;
        Ok(())
    }

    pub fn apply_level(
        &mut self,
        command: &WorkerLevelCommand,
        acknowledged_monotonic_ns: u64,
    ) -> Result<WorkerLevelAcknowledgement> {
        if !matches!(
            self.state,
            WorkerProtocolState::ScopeAndMemoryMaxVerified
                | WorkerProtocolState::LevelAcknowledged
                | WorkerProtocolState::Holding
        ) || command.protocol_version != PRESSURE_WORKER_PROTOCOL_VERSION
            || command.experiment_id != self.experiment_id
            || command.run_id != self.run_id
            || command.seed != self.seed
            || command.generator_id != INCOMPRESSIBLE_GENERATOR_ID
            || command.generator_version != SYNTHETIC_GENERATOR_VERSION
            || command.prior_touched_bytes != self.touched_bytes()
            || command
                .prior_touched_bytes
                .checked_add(command.requested_delta_bytes)
                != Some(command.target_touched_bytes)
            || command.target_touched_bytes > self.memory_max_bytes
        {
            bail!("fixed progressive worker command contract mismatch");
        }
        let prior = usize::try_from(command.prior_touched_bytes)?;
        let target = usize::try_from(command.target_touched_bytes)?;
        self.payload.resize(target, 0);
        for (index, byte) in self.payload[prior..].iter_mut().enumerate() {
            *byte = synthetic_byte(SyntheticPattern::Incompressible, self.seed, prior + index);
        }
        let integrity_identity = hex::encode(Sha256::digest(&self.payload));
        self.state = WorkerProtocolState::LevelAcknowledged;
        Ok(WorkerLevelAcknowledgement {
            experiment_id: self.experiment_id.clone(),
            run_id: self.run_id.clone(),
            level_index: command.level_index,
            seed: self.seed,
            prior_touched_bytes: command.prior_touched_bytes,
            requested_delta_bytes: command.requested_delta_bytes,
            actual_touched_bytes: self.touched_bytes(),
            worker_pid: self.worker_pid,
            worker_start_ticks: self.worker_start_ticks,
            generator_id: INCOMPRESSIBLE_GENERATOR_ID.into(),
            generator_version: SYNTHETIC_GENERATOR_VERSION,
            integrity_identity,
            acknowledged_monotonic_ns,
        })
    }

    pub fn begin_hold(&mut self) -> Result<()> {
        if self.state != WorkerProtocolState::LevelAcknowledged {
            bail!("hold cannot begin before exact level acknowledgement");
        }
        self.state = WorkerProtocolState::Holding;
        Ok(())
    }

    pub fn bounded_integrity_check(&self) -> Result<String> {
        if self.state != WorkerProtocolState::Holding || self.payload.is_empty() {
            bail!("bounded integrity check requires an acknowledged held payload");
        }
        let stride = (self.payload.len() / 1024).max(1);
        let mut digest = Sha256::new();
        for index in (0..self.payload.len()).step_by(stride).take(1024) {
            let expected = synthetic_byte(SyntheticPattern::Incompressible, self.seed, index);
            if self.payload[index] != expected {
                bail!("progressive worker payload integrity mismatch");
            }
            digest.update([self.payload[index]]);
        }
        Ok(hex::encode(digest.finalize()))
    }

    pub fn stop(&mut self) {
        self.state = WorkerProtocolState::Stopped;
    }
}

pub fn command_for_level(
    experiment_id: &str,
    run_id: &str,
    level: &PlannedPressureLevel,
    prior_touched_bytes: u64,
) -> Result<WorkerLevelCommand> {
    let requested_delta_bytes = level
        .target_touched_bytes
        .checked_sub(prior_touched_bytes)
        .ok_or_else(|| anyhow::anyhow!("progressive level cannot shrink"))?;
    Ok(WorkerLevelCommand {
        protocol_version: PRESSURE_WORKER_PROTOCOL_VERSION,
        experiment_id: experiment_id.into(),
        run_id: run_id.into(),
        level_index: level.level_index,
        seed: level.seed,
        prior_touched_bytes,
        requested_delta_bytes,
        target_touched_bytes: level.target_touched_bytes,
        generator_id: INCOMPRESSIBLE_GENERATOR_ID.into(),
        generator_version: SYNTHETIC_GENERATOR_VERSION,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pressure::PlannedLevelState;

    fn level(bytes: u64) -> PlannedPressureLevel {
        PlannedPressureLevel {
            level_index: 0,
            target_logical_bytes: bytes,
            target_touched_bytes: bytes,
            seed: 7,
            state: PlannedLevelState::Planned,
        }
    }

    #[test]
    fn worker_starts_unallocated_and_requires_verified_scope() {
        let mut worker =
            ProgressiveWorkerSession::start_unallocated("exp".into(), "run".into(), 7, 42, 99)
                .unwrap();
        assert_eq!(worker.touched_bytes(), 0);
        let command = command_for_level("exp", "run", &level(4096), 0).unwrap();
        assert!(worker.apply_level(&command, 1).is_err());
        worker.verify_owned_scope_and_memory_max(8192).unwrap();
        let ack = worker.apply_level(&command, 1).unwrap();
        assert_eq!(ack.actual_touched_bytes, 4096);
    }

    #[test]
    fn progressive_bytes_exactly_match_authoritative_splitmix_generator() {
        let mut worker =
            ProgressiveWorkerSession::start_unallocated("exp".into(), "run".into(), 7, 42, 99)
                .unwrap();
        worker.verify_owned_scope_and_memory_max(8192).unwrap();
        let ack = worker
            .apply_level(
                &command_for_level("exp", "run", &level(4096), 0).unwrap(),
                1,
            )
            .unwrap();
        let authoritative = (0..4096)
            .map(|index| synthetic_byte(SyntheticPattern::Incompressible, 7, index))
            .collect::<Vec<_>>();
        assert_eq!(
            ack.integrity_identity,
            hex::encode(Sha256::digest(authoritative))
        );
        worker.begin_hold().unwrap();
        assert!(worker.bounded_integrity_check().is_ok());
    }

    #[test]
    fn acknowledgement_identity_mismatch_fails_closed() {
        let mut worker =
            ProgressiveWorkerSession::start_unallocated("exp".into(), "run".into(), 7, 42, 99)
                .unwrap();
        worker.verify_owned_scope_and_memory_max(8192).unwrap();
        let mut command = command_for_level("exp", "run", &level(4096), 0).unwrap();
        command.run_id = "foreign".into();
        assert!(worker.apply_level(&command, 1).is_err());
        assert_eq!(worker.touched_bytes(), 0);
    }
}
