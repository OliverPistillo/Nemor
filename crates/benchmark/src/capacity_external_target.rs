//! Exact-owned external HOT/WARM/COLD target contract for benchmark-only validation.
//!
//! This boundary cannot authorize pressure search, capacity evaluation, or production.

use crate::{now_ns, BUILD_GIT_HEAD};
use anyhow::{bail, Context, Result};
use damon::{AddressRange, PageBackingProfile};
use memmap2::{Advice, MmapMut, MmapOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub const CAPACITY_EXTERNAL_TARGET_CONTRACT_VERSION: u32 = 1;
pub const CAPACITY_EXTERNAL_TARGET_PROTOCOL_VERSION: u32 = 1;
pub const CAPACITY_EXTERNAL_TARGET_GENERATOR_VERSION: u32 = 1;
pub const CAPACITY_EXTERNAL_TARGET_ZONE_BYTES: u64 = 8 * 1024 * 1024;
pub const CAPACITY_EXTERNAL_TARGET_COLD_BYTES: u64 = 32 * 1024 * 1024;
pub const CAPACITY_EXTERNAL_TARGET_HEARTBEAT_TIMEOUT_MS: u64 = 1_000;
pub const CAPACITY_EXTERNAL_TARGET_RUNTIME_MS: u64 = 120_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityExternalTargetState {
    Created,
    MappingsFaulted,
    Ready,
    Active,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityExternalTargetRanges {
    pub hot: AddressRange,
    pub warm: AddressRange,
    pub cold: AddressRange,
}

impl CapacityExternalTargetRanges {
    pub fn validate(&self) -> Result<()> {
        let ranges = [self.hot, self.warm, self.cold];
        if ranges.iter().any(|range| range.start >= range.end)
            || ranges.iter().enumerate().any(|(index, left)| {
                ranges
                    .iter()
                    .skip(index + 1)
                    .any(|right| left.overlap(*right) != 0)
            })
            || self.hot.end - self.hot.start != CAPACITY_EXTERNAL_TARGET_ZONE_BYTES
            || self.warm.end - self.warm.start != CAPACITY_EXTERNAL_TARGET_ZONE_BYTES
            || self.cold.end - self.cold.start != CAPACITY_EXTERNAL_TARGET_COLD_BYTES
        {
            bail!("external target ranges are not the exact distinct HOT/WARM/COLD contract");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityExternalTargetIdentity {
    pub validation_transaction_id: String,
    pub target_session_id: String,
    pub nonce: String,
    pub pid: u32,
    pub start_ticks: u64,
    pub executable_path: PathBuf,
    pub executable_sha256: String,
    pub embedded_source_commit: String,
    pub creator_pid: u32,
    pub creator_start_ticks: u64,
    pub preparing_uid: u32,
    pub preparing_gid: u32,
    pub unit_or_cgroup_identity: String,
    pub control_channel_identity: String,
    pub creation_monotonic_ns: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityExternalTargetContract {
    pub contract_version: u32,
    pub protocol_version: u32,
    pub workload_generator_version: u32,
    pub page_backing_profile: PageBackingProfile,
    pub hot_bytes: u64,
    pub warm_bytes: u64,
    pub cold_bytes: u64,
    pub heartbeat_timeout_ms: u64,
    pub maximum_runtime_ms: u64,
    pub one_time_consumption_required: bool,
    pub production_activation_authorized: bool,
    pub pressure_search_authorized: bool,
}

impl CapacityExternalTargetContract {
    #[must_use]
    pub fn v1() -> Self {
        Self {
            contract_version: CAPACITY_EXTERNAL_TARGET_CONTRACT_VERSION,
            protocol_version: CAPACITY_EXTERNAL_TARGET_PROTOCOL_VERSION,
            workload_generator_version: CAPACITY_EXTERNAL_TARGET_GENERATOR_VERSION,
            page_backing_profile: PageBackingProfile::BasePageNoHuge,
            hot_bytes: CAPACITY_EXTERNAL_TARGET_ZONE_BYTES,
            warm_bytes: CAPACITY_EXTERNAL_TARGET_ZONE_BYTES,
            cold_bytes: CAPACITY_EXTERNAL_TARGET_COLD_BYTES,
            heartbeat_timeout_ms: CAPACITY_EXTERNAL_TARGET_HEARTBEAT_TIMEOUT_MS,
            maximum_runtime_ms: CAPACITY_EXTERNAL_TARGET_RUNTIME_MS,
            one_time_consumption_required: true,
            production_activation_authorized: false,
            pressure_search_authorized: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self != &Self::v1() {
            bail!("unsupported or unsafe external target contract");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityExternalTargetDescriptorPayload {
    pub contract: CapacityExternalTargetContract,
    pub identity: CapacityExternalTargetIdentity,
    pub ranges: CapacityExternalTargetRanges,
    pub mapping_content_identities: [String; 3],
    pub descriptor_path: PathBuf,
    pub progress_path: PathBuf,
    pub transaction_root: PathBuf,
    pub state: CapacityExternalTargetState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityExternalTargetDescriptor {
    pub payload: CapacityExternalTargetDescriptorPayload,
    pub payload_sha256: String,
}

impl CapacityExternalTargetDescriptor {
    pub fn seal(payload: CapacityExternalTargetDescriptorPayload) -> Result<Self> {
        let payload_sha256 = hash(&payload)?;
        let descriptor = Self {
            payload,
            payload_sha256,
        };
        descriptor.validate_integrity()?;
        Ok(descriptor)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.payload.contract.validate()?;
        self.payload.ranges.validate()?;
        if self.payload_sha256 != hash(&self.payload)?
            || self.payload.identity.validation_transaction_id.is_empty()
            || self.payload.identity.target_session_id.is_empty()
            || self.payload.identity.nonce.len() < 32
            || self.payload.identity.pid == 0
            || self.payload.identity.start_ticks == 0
            || self.payload.identity.executable_path.as_os_str().is_empty()
            || self.payload.identity.executable_sha256.len() != 64
            || self.payload.identity.embedded_source_commit != BUILD_GIT_HEAD
            || self.payload.identity.creator_pid == 0
            || self.payload.identity.creator_start_ticks == 0
            || self.payload.identity.unit_or_cgroup_identity.is_empty()
            || self.payload.identity.control_channel_identity.is_empty()
            || self
                .payload
                .mapping_content_identities
                .iter()
                .any(|identity| identity.len() != 64)
            || self.payload.state != CapacityExternalTargetState::Ready
        {
            bail!("external target descriptor integrity or identity is invalid");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityExternalTargetProgress {
    pub protocol_version: u32,
    pub target_session_id: String,
    pub nonce: String,
    pub state: CapacityExternalTargetState,
    pub sequence: u64,
    pub heartbeat_monotonic_ns: u128,
    pub hot_cycles: u64,
    pub warm_cycles: u64,
    pub hot_pages_touched: u64,
    pub warm_pages_touched: u64,
    pub cold_cycles: u64,
    pub controlled_refaults: u64,
    pub hot_fingerprint: String,
    pub warm_fingerprint: String,
    pub cold_fingerprint: String,
}

impl CapacityExternalTargetProgress {
    pub fn validate_service(
        &self,
        before: &Self,
        session_id: &str,
        nonce: &str,
        now_monotonic_ns: u128,
    ) -> Result<()> {
        if self.protocol_version != CAPACITY_EXTERNAL_TARGET_PROTOCOL_VERSION
            || self.target_session_id != session_id
            || self.nonce != nonce
            || self.sequence <= before.sequence
            || self.heartbeat_monotonic_ns < before.heartbeat_monotonic_ns
            || now_monotonic_ns.saturating_sub(self.heartbeat_monotonic_ns)
                > u128::from(CAPACITY_EXTERNAL_TARGET_HEARTBEAT_TIMEOUT_MS) * 1_000_000
            || self.hot_cycles <= before.hot_cycles
            || self.warm_cycles <= before.warm_cycles
            || self.hot_pages_touched <= before.hot_pages_touched
            || self.warm_pages_touched <= before.warm_pages_touched
            || self.cold_cycles != before.cold_cycles
        {
            bail!("external target service, heartbeat, or COLD inactivity gate failed");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityExternalTargetCommand {
    Start { nonce: String },
    RefaultCold { nonce: String },
    Stop { nonce: String },
}

pub fn validate_descriptor_file(
    path: &Path,
    expected_transaction: &str,
    expected_session: &str,
    expected_nonce: &str,
    expected_creator_pid: u32,
    expected_creator_start_ticks: u64,
) -> Result<CapacityExternalTargetDescriptor> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        bail!("external target descriptor metadata is unsafe");
    }
    let root = path
        .parent()
        .context("external target descriptor has no transaction root")?;
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.file_type().is_dir()
        || root_metadata.mode() & 0o777 != 0o700
        || root_metadata.uid() != metadata.uid()
        || root_metadata.gid() != metadata.gid()
    {
        bail!("external target transaction directory is unsafe");
    }
    let descriptor: CapacityExternalTargetDescriptor = serde_json::from_slice(&fs::read(path)?)?;
    descriptor.validate_integrity()?;
    let identity = &descriptor.payload.identity;
    if identity.validation_transaction_id != expected_transaction
        || identity.target_session_id != expected_session
        || identity.nonce != expected_nonce
        || identity.creator_pid != expected_creator_pid
        || identity.creator_start_ticks != expected_creator_start_ticks
        || descriptor.payload.descriptor_path != path
        || descriptor.payload.transaction_root != root
        || proc_start_ticks(identity.pid)? != Some(identity.start_ticks)
        || proc_start_ticks(identity.creator_pid)? != Some(identity.creator_start_ticks)
        || canonical_executable(identity.pid)? != identity.executable_path
        || sha256_file(&identity.executable_path)? != identity.executable_sha256
    {
        bail!("external target exact ownership handoff rejected before mutation");
    }
    Ok(descriptor)
}

pub fn consume_descriptor_once(path: &Path, descriptor_hash: &str) -> Result<PathBuf> {
    let consumed = path.with_extension("consumed");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&consumed)
        .context("external target descriptor was already consumed")?;
    file.write_all(descriptor_hash.as_bytes())?;
    file.sync_all()?;
    Ok(consumed)
}

pub fn write_command(root: &Path, command: &CapacityExternalTargetCommand) -> Result<()> {
    let name = match command {
        CapacityExternalTargetCommand::Start { .. } => "command-start.json",
        CapacityExternalTargetCommand::RefaultCold { .. } => "command-refault.json",
        CapacityExternalTargetCommand::Stop { .. } => "command-stop.json",
    };
    write_private_atomic(&root.join(name), &serde_json::to_vec(command)?)
}

pub fn read_progress(path: &Path) -> Result<CapacityExternalTargetProgress> {
    serde_json::from_slice(&fs::read(path)?).context("invalid external target progress")
}

#[allow(clippy::too_many_arguments)]
pub fn run_target_worker(
    transaction_root: &Path,
    transaction_id: &str,
    session_id: &str,
    nonce: &str,
    creator_pid: u32,
    creator_start_ticks: u64,
    preparing_uid: u32,
    preparing_gid: u32,
    unit_or_cgroup_identity: &str,
) -> Result<()> {
    let root_meta = fs::symlink_metadata(transaction_root)?;
    if root_meta.mode() & 0o777 != 0o700 || root_meta.nlink() != 2 {
        bail!("external target transaction root is not a private fresh directory");
    }
    if proc_start_ticks(creator_pid)? != Some(creator_start_ticks) {
        bail!("external target creator identity is stale");
    }
    let hot = owned_zone(CAPACITY_EXTERNAL_TARGET_ZONE_BYTES as usize, 1)?;
    let warm = owned_zone(CAPACITY_EXTERNAL_TARGET_ZONE_BYTES as usize, 2)?;
    let mut cold = owned_zone(CAPACITY_EXTERNAL_TARGET_COLD_BYTES as usize, 3)?;
    let ranges = CapacityExternalTargetRanges {
        hot: range(&hot),
        warm: range(&warm),
        cold: range(&cold),
    };
    ranges.validate()?;
    let initial = [fingerprint(&hot), fingerprint(&warm), fingerprint(&cold)];
    let pid = std::process::id();
    let executable_path = canonical_executable(pid)?;
    let descriptor_path = transaction_root.join("target-descriptor.json");
    let progress_path = transaction_root.join("target-progress.json");
    let descriptor =
        CapacityExternalTargetDescriptor::seal(CapacityExternalTargetDescriptorPayload {
            contract: CapacityExternalTargetContract::v1(),
            identity: CapacityExternalTargetIdentity {
                validation_transaction_id: transaction_id.to_owned(),
                target_session_id: session_id.to_owned(),
                nonce: nonce.to_owned(),
                pid,
                start_ticks: proc_start_ticks(pid)?.context("target start ticks unavailable")?,
                executable_sha256: sha256_file(&executable_path)?,
                executable_path,
                embedded_source_commit: BUILD_GIT_HEAD.to_owned(),
                creator_pid,
                creator_start_ticks,
                preparing_uid,
                preparing_gid,
                unit_or_cgroup_identity: unit_or_cgroup_identity.to_owned(),
                control_channel_identity: hex::encode(Sha256::digest(format!(
                    "{transaction_id}:{session_id}:{nonce}"
                ))),
                creation_monotonic_ns: u128::from(now_ns()),
            },
            ranges,
            mapping_content_identities: initial.clone(),
            descriptor_path: descriptor_path.clone(),
            progress_path: progress_path.clone(),
            transaction_root: transaction_root.to_path_buf(),
            state: CapacityExternalTargetState::Ready,
        })?;
    write_private_atomic(&descriptor_path, &serde_json::to_vec_pretty(&descriptor)?)?;
    let active = Arc::new(AtomicBool::new(false));
    let stopping = Arc::new(AtomicBool::new(false));
    let hot_cycles = Arc::new(AtomicU64::new(0));
    let warm_cycles = Arc::new(AtomicU64::new(0));
    let hot_pages = Arc::new(AtomicU64::new(0));
    let warm_pages = Arc::new(AtomicU64::new(0));
    let hot_worker = service_worker(
        hot,
        Arc::clone(&active),
        Arc::clone(&stopping),
        Arc::clone(&hot_cycles),
        Arc::clone(&hot_pages),
        Duration::ZERO,
    );
    let warm_worker = service_worker(
        warm,
        Arc::clone(&active),
        Arc::clone(&stopping),
        Arc::clone(&warm_cycles),
        Arc::clone(&warm_pages),
        Duration::from_millis(100),
    );
    let started = Instant::now();
    let mut sequence = 0;
    let mut controlled_refaults = 0;
    let mut cold_cycles = 0;
    let mut state = CapacityExternalTargetState::Ready;
    while started.elapsed() < Duration::from_millis(CAPACITY_EXTERNAL_TARGET_RUNTIME_MS) {
        if let Some(command) = read_command(&transaction_root.join("command-start.json"), nonce)? {
            if !matches!(command, CapacityExternalTargetCommand::Start { .. })
                || state != CapacityExternalTargetState::Ready
            {
                bail!("invalid external target START transition");
            }
            active.store(true, Ordering::Release);
            state = CapacityExternalTargetState::Active;
        }
        if let Some(command) = read_command(&transaction_root.join("command-refault.json"), nonce)?
        {
            if !matches!(command, CapacityExternalTargetCommand::RefaultCold { .. })
                || state != CapacityExternalTargetState::Active
                || controlled_refaults != 0
            {
                bail!("invalid or repeated external target COLD refault");
            }
            let _ = touch(&mut cold);
            controlled_refaults = 1;
            cold_cycles = 1;
        }
        if let Some(command) = read_command(&transaction_root.join("command-stop.json"), nonce)? {
            if !matches!(command, CapacityExternalTargetCommand::Stop { .. }) {
                bail!("invalid external target STOP command");
            }
            break;
        }
        sequence += 1;
        write_progress(
            &progress_path,
            session_id,
            nonce,
            state,
            sequence,
            &hot_cycles,
            &warm_cycles,
            &hot_pages,
            &warm_pages,
            cold_cycles,
            controlled_refaults,
            &initial,
        )?;
        thread::sleep(Duration::from_millis(20));
    }
    active.store(false, Ordering::Release);
    stopping.store(true, Ordering::Release);
    let hot = hot_worker
        .join()
        .map_err(|_| anyhow::anyhow!("HOT worker panicked"))?;
    let warm = warm_worker
        .join()
        .map_err(|_| anyhow::anyhow!("WARM worker panicked"))?;
    sequence += 1;
    let final_fingerprints = [fingerprint(&hot), fingerprint(&warm), fingerprint(&cold)];
    if final_fingerprints != initial {
        bail!("external target final content fingerprint mismatch");
    }
    write_progress(
        &progress_path,
        session_id,
        nonce,
        CapacityExternalTargetState::Stopped,
        sequence,
        &hot_cycles,
        &warm_cycles,
        &hot_pages,
        &warm_pages,
        cold_cycles,
        controlled_refaults,
        &final_fingerprints,
    )?;
    Ok(())
}

fn owned_zone(bytes: usize, value: u8) -> Result<MmapMut> {
    let mapping = MmapOptions::new().len(bytes).map_anon()?;
    mapping
        .advise(Advice::NoHugePage)
        .context("MADV_NOHUGEPAGE failed for exact external target")?;
    let mut mapping = mapping;
    mapping.fill(value);
    let _ = touch(&mut mapping);
    Ok(mapping)
}

fn range(mapping: &MmapMut) -> AddressRange {
    AddressRange {
        start: mapping.as_ptr() as u64,
        end: mapping.as_ptr() as u64 + mapping.len() as u64,
    }
}

fn service_worker(
    mut mapping: MmapMut,
    active: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    cycles: Arc<AtomicU64>,
    pages: Arc<AtomicU64>,
    cadence: Duration,
) -> thread::JoinHandle<MmapMut> {
    thread::spawn(move || {
        while !stopping.load(Ordering::Acquire) {
            if !active.load(Ordering::Acquire) {
                thread::yield_now();
                continue;
            }
            pages.fetch_add(touch(&mut mapping), Ordering::Relaxed);
            cycles.fetch_add(1, Ordering::Release);
            if !cadence.is_zero() {
                thread::sleep(cadence);
            }
        }
        mapping
    })
}

fn touch(mapping: &mut [u8]) -> u64 {
    let mut pages = 0;
    for offset in (0..mapping.len()).step_by(4096) {
        mapping[offset] = mapping[offset].wrapping_add(1);
        mapping[offset] = mapping[offset].wrapping_sub(1);
        pages += 1;
    }
    pages
}

fn fingerprint(mapping: &[u8]) -> String {
    let mut digest = Sha256::new();
    for offset in (0..mapping.len()).step_by(4096) {
        digest.update([mapping[offset]]);
    }
    hex::encode(digest.finalize())
}

#[allow(clippy::too_many_arguments)]
fn write_progress(
    path: &Path,
    session_id: &str,
    nonce: &str,
    state: CapacityExternalTargetState,
    sequence: u64,
    hot_cycles: &AtomicU64,
    warm_cycles: &AtomicU64,
    hot_pages: &AtomicU64,
    warm_pages: &AtomicU64,
    cold_cycles: u64,
    controlled_refaults: u64,
    fingerprints: &[String; 3],
) -> Result<()> {
    write_private_atomic(
        path,
        &serde_json::to_vec(&CapacityExternalTargetProgress {
            protocol_version: CAPACITY_EXTERNAL_TARGET_PROTOCOL_VERSION,
            target_session_id: session_id.to_owned(),
            nonce: nonce.to_owned(),
            state,
            sequence,
            heartbeat_monotonic_ns: u128::from(now_ns()),
            hot_cycles: hot_cycles.load(Ordering::Acquire),
            warm_cycles: warm_cycles.load(Ordering::Acquire),
            hot_pages_touched: hot_pages.load(Ordering::Acquire),
            warm_pages_touched: warm_pages.load(Ordering::Acquire),
            cold_cycles,
            controlled_refaults,
            hot_fingerprint: fingerprints[0].clone(),
            warm_fingerprint: fingerprints[1].clone(),
            cold_fingerprint: fingerprints[2].clone(),
        })?,
    )
}

fn read_command(path: &Path, nonce: &str) -> Result<Option<CapacityExternalTargetCommand>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    fs::remove_file(path)?;
    let command: CapacityExternalTargetCommand = serde_json::from_slice(&bytes)?;
    let command_nonce = match &command {
        CapacityExternalTargetCommand::Start { nonce }
        | CapacityExternalTargetCommand::RefaultCold { nonce }
        | CapacityExternalTargetCommand::Stop { nonce } => nonce,
    };
    if command_nonce != nonce {
        bail!("external target command nonce mismatch");
    }
    Ok(Some(command))
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let staged = path.with_extension("next");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(staged, path)?;
    Ok(())
}

pub fn proc_start_ticks(pid: u32) -> Result<Option<u64>> {
    let text = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let close = text.rfind(')').context("invalid proc stat")?;
    Ok(text[close + 1..]
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok()))
}

fn canonical_executable(pid: u32) -> Result<PathBuf> {
    fs::canonicalize(format!("/proc/{pid}/exe")).context("resolve target executable")
}

pub fn sha256_file(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

fn hash<T: Serialize>(value: &T) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn ranges() -> CapacityExternalTargetRanges {
        CapacityExternalTargetRanges {
            hot: AddressRange {
                start: 0x1000_0000,
                end: 0x1080_0000,
            },
            warm: AddressRange {
                start: 0x2000_0000,
                end: 0x2080_0000,
            },
            cold: AddressRange {
                start: 0x3000_0000,
                end: 0x3200_0000,
            },
        }
    }

    fn descriptor(root: &Path) -> CapacityExternalTargetDescriptor {
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let pid = std::process::id();
        CapacityExternalTargetDescriptor::seal(CapacityExternalTargetDescriptorPayload {
            contract: CapacityExternalTargetContract::v1(),
            identity: CapacityExternalTargetIdentity {
                validation_transaction_id: "transaction".into(),
                target_session_id: "session".into(),
                nonce: "0123456789abcdef0123456789abcdef".into(),
                pid,
                start_ticks: proc_start_ticks(pid).unwrap().unwrap(),
                executable_sha256: sha256_file(&executable).unwrap(),
                executable_path: executable,
                embedded_source_commit: BUILD_GIT_HEAD.into(),
                creator_pid: pid,
                creator_start_ticks: proc_start_ticks(pid).unwrap().unwrap(),
                preparing_uid: 1000,
                preparing_gid: 1000,
                unit_or_cgroup_identity: "test.scope".into(),
                control_channel_identity: "channel".into(),
                creation_monotonic_ns: 1,
            },
            ranges: ranges(),
            mapping_content_identities: ["a".repeat(64), "b".repeat(64), "c".repeat(64)],
            descriptor_path: root.join("target-descriptor.json"),
            progress_path: root.join("target-progress.json"),
            transaction_root: root.into(),
            state: CapacityExternalTargetState::Ready,
        })
        .unwrap()
    }

    #[test]
    fn target_contract_and_descriptor_round_trip_with_integrity() {
        let temporary = tempfile::tempdir().unwrap();
        let value = descriptor(temporary.path());
        let bytes = serde_json::to_vec(&value).unwrap();
        let decoded: CapacityExternalTargetDescriptor = serde_json::from_slice(&bytes).unwrap();
        decoded.validate_integrity().unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn exact_three_mapping_contract_rejects_overlap_size_and_zero() {
        ranges().validate().unwrap();
        for mut invalid in [ranges(), ranges(), ranges()] {
            if invalid == ranges() {
                invalid.warm = invalid.hot;
            }
            assert!(invalid.validate().is_err());
        }
        let mut zero = ranges();
        zero.hot.end = zero.hot.start;
        assert!(zero.validate().is_err());
        let mut wrong = ranges();
        wrong.cold.end -= 4096;
        assert!(wrong.validate().is_err());
    }

    #[test]
    fn contract_versions_limits_and_non_authorization_are_frozen() {
        let contract = CapacityExternalTargetContract::v1();
        contract.validate().unwrap();
        assert!(!contract.production_activation_authorized);
        assert!(!contract.pressure_search_authorized);
        assert!(contract.one_time_consumption_required);
        let mut invalid = contract.clone();
        invalid.protocol_version += 1;
        assert!(invalid.validate().is_err());
        let mut invalid = contract;
        invalid.contract_version += 1;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn descriptor_tamper_wrong_source_nonce_identity_and_reuse_fail_closed() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut value = descriptor(temporary.path());
        value.payload.identity.pid = 0;
        assert!(value.validate_integrity().is_err());
        let value = descriptor(temporary.path());
        let path = temporary.path().join("target-descriptor.json");
        write_private_atomic(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        let consumed = consume_descriptor_once(&path, &value.payload_sha256).unwrap();
        assert!(consumed.exists());
        assert!(consume_descriptor_once(&path, &value.payload_sha256).is_err());
    }

    #[test]
    fn descriptor_permissions_and_hard_links_are_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let value = descriptor(temporary.path());
        let path = temporary.path().join("target-descriptor.json");
        write_private_atomic(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_descriptor_file(
            &path,
            "transaction",
            "session",
            "0123456789abcdef0123456789abcdef",
            std::process::id(),
            proc_start_ticks(std::process::id()).unwrap().unwrap()
        )
        .is_err());
    }

    #[test]
    fn service_requires_hot_warm_progress_heartbeat_and_cold_inactivity() {
        let before = CapacityExternalTargetProgress {
            protocol_version: 1,
            target_session_id: "session".into(),
            nonce: "nonce".into(),
            state: CapacityExternalTargetState::Active,
            sequence: 1,
            heartbeat_monotonic_ns: 1_000_000,
            hot_cycles: 1,
            warm_cycles: 1,
            hot_pages_touched: 1,
            warm_pages_touched: 1,
            cold_cycles: 0,
            controlled_refaults: 0,
            hot_fingerprint: "a".repeat(64),
            warm_fingerprint: "b".repeat(64),
            cold_fingerprint: "c".repeat(64),
        };
        let mut after = before.clone();
        after.sequence = 2;
        after.heartbeat_monotonic_ns = 2_000_000;
        after.hot_cycles = 2;
        after.warm_cycles = 2;
        after.hot_pages_touched = 2;
        after.warm_pages_touched = 2;
        after
            .validate_service(&before, "session", "nonce", 2_000_000)
            .unwrap();
        for field in ["hot", "warm", "cold", "heartbeat"] {
            let mut invalid = after.clone();
            match field {
                "hot" => invalid.hot_cycles = 1,
                "warm" => invalid.warm_cycles = 1,
                "cold" => invalid.cold_cycles = 1,
                _ => invalid.heartbeat_monotonic_ns = 0,
            }
            assert!(
                invalid
                    .validate_service(&before, "session", "nonce", 2_000_000_000)
                    .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn only_nonce_bound_lifecycle_commands_are_serialized() {
        for command in [
            CapacityExternalTargetCommand::Start { nonce: "n".into() },
            CapacityExternalTargetCommand::RefaultCold { nonce: "n".into() },
            CapacityExternalTargetCommand::Stop { nonce: "n".into() },
        ] {
            let bytes = serde_json::to_vec(&command).unwrap();
            let decoded: CapacityExternalTargetCommand = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(decoded, command);
        }
    }

    #[test]
    fn validated_damos_action_envelope_remains_unchanged() {
        assert_eq!(damos::VALIDATION_TIME_QUOTA_MS, 5);
        assert_eq!(damos::VALIDATION_BYTE_QUOTA, 8 * 1024 * 1024);
        assert_eq!(damos::VALIDATION_TOTAL_APPLIED_CEILING, 16 * 1024 * 1024);
        assert_eq!(damos::VALIDATION_MAX_NR_SNAPSHOTS, 5);
        assert_eq!(damos::VALIDATION_RESET_INTERVAL_MS, 10_000);
        assert_eq!(damos::VALIDATION_LIVE_DEADLINE_MS, 5_000);
    }
}
