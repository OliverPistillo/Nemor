//! Fixed Checkpoint 3C owned-worker step protocol.
//!
//! The future executor creates one session before allocation, attaches that
//! process to its exact owned systemd scope, verifies `MemoryMax`, and only
//! then may submit a typed level command.

use crate::performance::{INCOMPRESSIBLE_GENERATOR_ID, SYNTHETIC_GENERATOR_VERSION};
use crate::pressure::{PlannedPressureLevel, WorkerLevelAcknowledgement};
use crate::{synthetic_byte, SyntheticPattern};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

pub const PRESSURE_WORKER_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerIpcMessage {
    Hello {
        version: u32,
        experiment_id: String,
        run_id: String,
        pid: u32,
        start_ticks: u64,
        touched_bytes: u64,
    },
    VerifyBoundary {
        version: u32,
        experiment_id: String,
        run_id: String,
        pid: u32,
        start_ticks: u64,
        memory_max_bytes: u64,
    },
    BoundaryVerified {
        version: u32,
        experiment_id: String,
        run_id: String,
        pid: u32,
        start_ticks: u64,
    },
    LevelRequest {
        version: u32,
        experiment_id: String,
        run_id: String,
        pid: u32,
        start_ticks: u64,
        command: WorkerLevelCommand,
        monotonic_ns: u64,
    },
    LevelAck {
        version: u32,
        experiment_id: String,
        run_id: String,
        pid: u32,
        start_ticks: u64,
        acknowledgement: WorkerLevelAcknowledgement,
    },
    BeginHold {
        version: u32,
        experiment_id: String,
        run_id: String,
        pid: u32,
        start_ticks: u64,
    },
    HeartbeatRequest {
        version: u32,
        experiment_id: String,
        run_id: String,
        pid: u32,
        start_ticks: u64,
    },
    Heartbeat {
        version: u32,
        experiment_id: String,
        run_id: String,
        pid: u32,
        start_ticks: u64,
        touched_bytes: u64,
    },
    IntegrityResult {
        version: u32,
        experiment_id: String,
        run_id: String,
        pid: u32,
        start_ticks: u64,
        identity: String,
    },
    Stop {
        version: u32,
        experiment_id: String,
        run_id: String,
        pid: u32,
        start_ticks: u64,
    },
    Stopped {
        version: u32,
        experiment_id: String,
        run_id: String,
        pid: u32,
        start_ticks: u64,
    },
}

fn write_message(stream: &mut UnixStream, message: &WorkerIpcMessage) -> Result<()> {
    serde_json::to_writer(&mut *stream, message)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn read_message(reader: &mut BufReader<UnixStream>) -> Result<WorkerIpcMessage> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 || line.len() > 64 * 1024 {
        bail!("pressure worker IPC message is absent or oversized");
    }
    Ok(serde_json::from_str(&line)?)
}

fn message_identity_matches(
    message: &WorkerIpcMessage,
    experiment_id: &str,
    run_id: &str,
    pid: u32,
    start_ticks: u64,
) -> bool {
    let identity = match message {
        WorkerIpcMessage::VerifyBoundary {
            version,
            experiment_id,
            run_id,
            pid,
            start_ticks,
            ..
        }
        | WorkerIpcMessage::LevelRequest {
            version,
            experiment_id,
            run_id,
            pid,
            start_ticks,
            ..
        }
        | WorkerIpcMessage::BeginHold {
            version,
            experiment_id,
            run_id,
            pid,
            start_ticks,
        }
        | WorkerIpcMessage::HeartbeatRequest {
            version,
            experiment_id,
            run_id,
            pid,
            start_ticks,
        }
        | WorkerIpcMessage::Stop {
            version,
            experiment_id,
            run_id,
            pid,
            start_ticks,
        } => (*version, experiment_id, run_id, *pid, *start_ticks),
        _ => return false,
    };
    identity.0 == PRESSURE_WORKER_PROTOCOL_VERSION
        && identity.1 == experiment_id
        && identity.2 == run_id
        && identity.3 == pid
        && identity.4 == start_ticks
}

pub fn run_pressure_worker_server(
    socket_path: &Path,
    experiment_id: String,
    run_id: String,
    seed: u64,
    start_ticks: u64,
) -> Result<()> {
    if socket_path.exists() || !socket_path.is_absolute() {
        bail!("pressure worker socket must be a fresh absolute path");
    }
    let pid = std::process::id();
    let mut session = ProgressiveWorkerSession::start_unallocated(
        experiment_id.clone(),
        run_id.clone(),
        seed,
        pid,
        start_ticks,
    )?;
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind pressure worker socket {}", socket_path.display()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("protect pressure worker socket {}", socket_path.display()))?;
    let (mut stream, _) = listener
        .accept()
        .context("accept pressure worker controller connection")?;
    let mut reader = BufReader::new(stream.try_clone()?);
    write_message(
        &mut stream,
        &WorkerIpcMessage::Hello {
            version: PRESSURE_WORKER_PROTOCOL_VERSION,
            experiment_id: experiment_id.clone(),
            run_id: run_id.clone(),
            pid,
            start_ticks,
            touched_bytes: 0,
        },
    )?;
    loop {
        let message = read_message(&mut reader)?;
        if !message_identity_matches(&message, &experiment_id, &run_id, pid, start_ticks) {
            bail!("foreign or out-of-order pressure worker IPC message");
        }
        match message {
            WorkerIpcMessage::VerifyBoundary {
                memory_max_bytes, ..
            } => {
                session.verify_owned_scope_and_memory_max(memory_max_bytes)?;
                write_message(
                    &mut stream,
                    &WorkerIpcMessage::BoundaryVerified {
                        version: PRESSURE_WORKER_PROTOCOL_VERSION,
                        experiment_id: experiment_id.clone(),
                        run_id: run_id.clone(),
                        pid,
                        start_ticks,
                    },
                )?;
            }
            WorkerIpcMessage::LevelRequest {
                command,
                monotonic_ns,
                ..
            } => {
                let acknowledgement = session.apply_level(&command, monotonic_ns)?;
                write_message(
                    &mut stream,
                    &WorkerIpcMessage::LevelAck {
                        version: PRESSURE_WORKER_PROTOCOL_VERSION,
                        experiment_id: experiment_id.clone(),
                        run_id: run_id.clone(),
                        pid,
                        start_ticks,
                        acknowledgement,
                    },
                )?;
            }
            WorkerIpcMessage::BeginHold { .. } => {
                session.begin_hold()?;
                let identity = session.bounded_integrity_check()?;
                write_message(
                    &mut stream,
                    &WorkerIpcMessage::IntegrityResult {
                        version: PRESSURE_WORKER_PROTOCOL_VERSION,
                        experiment_id: experiment_id.clone(),
                        run_id: run_id.clone(),
                        pid,
                        start_ticks,
                        identity,
                    },
                )?;
                write_message(
                    &mut stream,
                    &WorkerIpcMessage::Heartbeat {
                        version: PRESSURE_WORKER_PROTOCOL_VERSION,
                        experiment_id: experiment_id.clone(),
                        run_id: run_id.clone(),
                        pid,
                        start_ticks,
                        touched_bytes: session.touched_bytes(),
                    },
                )?;
            }
            WorkerIpcMessage::HeartbeatRequest { .. } => {
                let identity = session.bounded_integrity_check()?;
                write_message(
                    &mut stream,
                    &WorkerIpcMessage::Heartbeat {
                        version: PRESSURE_WORKER_PROTOCOL_VERSION,
                        experiment_id: experiment_id.clone(),
                        run_id: run_id.clone(),
                        pid,
                        start_ticks,
                        touched_bytes: session.touched_bytes(),
                    },
                )?;
                write_message(
                    &mut stream,
                    &WorkerIpcMessage::IntegrityResult {
                        version: PRESSURE_WORKER_PROTOCOL_VERSION,
                        experiment_id: experiment_id.clone(),
                        run_id: run_id.clone(),
                        pid,
                        start_ticks,
                        identity,
                    },
                )?;
            }
            WorkerIpcMessage::Stop { .. } => {
                session.stop();
                write_message(
                    &mut stream,
                    &WorkerIpcMessage::Stopped {
                        version: PRESSURE_WORKER_PROTOCOL_VERSION,
                        experiment_id,
                        run_id,
                        pid,
                        start_ticks,
                    },
                )?;
                break;
            }
            _ => bail!("pressure worker received an invalid protocol direction"),
        }
    }
    let _ = fs::remove_file(socket_path);
    Ok(())
}

pub struct PressureWorkerClient {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

pub fn current_process_start_ticks() -> Result<u64> {
    let stat = fs::read_to_string("/proc/self/stat")?;
    let close = stat
        .rfind(')')
        .ok_or_else(|| anyhow::anyhow!("malformed /proc/self/stat"))?;
    stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .context("missing process start ticks")?
        .parse()
        .map_err(Into::into)
}

impl PressureWorkerClient {
    pub fn connect(socket_path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(socket_path)?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Self { stream, reader })
    }

    pub fn send(&mut self, message: &WorkerIpcMessage) -> Result<WorkerIpcMessage> {
        write_message(&mut self.stream, message)?;
        read_message(&mut self.reader)
    }

    pub fn receive(&mut self) -> Result<WorkerIpcMessage> {
        read_message(&mut self.reader)
    }

    pub fn set_deadline(&self, timeout: Duration) -> Result<()> {
        if timeout.is_zero() {
            bail!("pressure worker IPC deadline must be nonzero");
        }
        self.stream.set_read_timeout(Some(timeout))?;
        self.stream.set_write_timeout(Some(timeout))?;
        self.reader.get_ref().set_read_timeout(Some(timeout))?;
        Ok(())
    }

    pub fn send_with_timeout(
        &mut self,
        message: &WorkerIpcMessage,
        timeout: Duration,
        operation: &str,
    ) -> Result<WorkerIpcMessage> {
        self.set_deadline(timeout)?;
        self.send(message)
            .with_context(|| format!("pressure worker IPC timeout/failure during {operation}"))
    }

    pub fn receive_with_timeout(
        &mut self,
        timeout: Duration,
        operation: &str,
    ) -> Result<WorkerIpcMessage> {
        self.set_deadline(timeout)?;
        self.receive()
            .with_context(|| format!("pressure worker IPC timeout/failure during {operation}"))
    }
}

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
    next_level_index: usize,
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
            next_level_index: 0,
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
            || command.level_index != self.next_level_index
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
        self.next_level_index = self
            .next_level_index
            .checked_add(1)
            .context("progressive worker level index overflow")?;
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
    use std::time::Instant;

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

    #[test]
    fn duplicate_and_out_of_order_levels_fail_without_allocation() {
        let mut worker =
            ProgressiveWorkerSession::start_unallocated("exp".into(), "run".into(), 7, 42, 99)
                .unwrap();
        worker.verify_owned_scope_and_memory_max(16_384).unwrap();
        let mut out_of_order = command_for_level("exp", "run", &level(4096), 0).unwrap();
        out_of_order.level_index = 1;
        assert!(worker.apply_level(&out_of_order, 1).is_err());
        assert_eq!(worker.touched_bytes(), 0);

        let first = command_for_level("exp", "run", &level(4096), 0).unwrap();
        worker.apply_level(&first, 2).unwrap();
        assert!(worker.apply_level(&first, 3).is_err());
        assert_eq!(worker.touched_bytes(), 4096);
    }

    fn silent_peer_client() -> (PressureWorkerClient, UnixStream) {
        let (stream, peer) = UnixStream::pair().unwrap();
        let reader = BufReader::new(stream.try_clone().unwrap());
        (PressureWorkerClient { stream, reader }, peer)
    }

    #[test]
    fn hello_receive_timeout_is_bounded() {
        let (mut client, _peer) = silent_peer_client();
        let started = Instant::now();
        assert!(client
            .receive_with_timeout(Duration::from_millis(20), "HELLO")
            .is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn level_ack_and_heartbeat_timeouts_are_bounded() {
        for operation in ["LEVEL_REQUEST/LEVEL_ACK", "HEARTBEAT"] {
            let (mut client, _peer) = silent_peer_client();
            let message = WorkerIpcMessage::HeartbeatRequest {
                version: PRESSURE_WORKER_PROTOCOL_VERSION,
                experiment_id: "exp".into(),
                run_id: "run".into(),
                pid: 42,
                start_ticks: 99,
            };
            let started = Instant::now();
            assert!(client
                .send_with_timeout(&message, Duration::from_millis(20), operation)
                .is_err());
            assert!(started.elapsed() < Duration::from_secs(1));
        }
    }

    #[test]
    fn stop_timeout_is_bounded() {
        let (mut client, _peer) = silent_peer_client();
        let message = WorkerIpcMessage::Stop {
            version: PRESSURE_WORKER_PROTOCOL_VERSION,
            experiment_id: "exp".into(),
            run_id: "run".into(),
            pid: 42,
            start_ticks: 99,
        };
        let started = Instant::now();
        assert!(client
            .send_with_timeout(&message, Duration::from_millis(20), "STOP")
            .is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
