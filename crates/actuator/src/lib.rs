#![forbid(unsafe_code)]

use classifier::{ForegroundState, ProcessCategory, ProcessClassification};
use common::CgroupsConfig;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const FOREGROUND_GROUP: &str = "nemor-foreground.slice";
pub const BACKGROUND_GROUP: &str = "nemor-background.slice";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupCapabilities {
    pub cgroup_v2: bool,
    pub memory_controller: bool,
    pub hierarchy: PathBuf,
    pub writable: bool,
    pub memory_low: bool,
    pub memory_high: bool,
    pub attach: bool,
}

impl CgroupCapabilities {
    #[must_use]
    pub fn mutation_ready(&self) -> bool {
        self.cgroup_v2
            && self.memory_controller
            && self.writable
            && self.memory_low
            && self.memory_high
            && self.attach
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    LinuxCgroupfs,
    Simulated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupState {
    pub name: String,
    pub path: PathBuf,
    pub owned_by_nemor: bool,
    pub memory_low: Option<u64>,
    pub memory_high: Option<u64>,
    pub pids: BTreeSet<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestedProperties {
    pub memory_low: Option<u64>,
    pub memory_high: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupPlan {
    pub process_catalog_id: i64,
    pub identity: String,
    pub pid: u32,
    pub start_time_ticks: u64,
    pub source_group: String,
    pub target_group: String,
    pub properties: RequestedProperties,
    pub reason: String,
    pub allowed: bool,
    pub block_reasons: Vec<String>,
    pub dry_run: bool,
}

#[derive(Debug, Clone)]
pub struct PlanInput<'a> {
    pub process_catalog_id: i64,
    pub identity: &'a str,
    pub current_start_time_ticks: Option<u64>,
    pub source_group: &'a str,
    pub classification: &'a ProcessClassification,
    pub total_ram_bytes: u64,
    pub protected_workload_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationSnapshot {
    pub id: u64,
    pub session_id: i64,
    pub timestamp_ns: i64,
    pub process_catalog_id: i64,
    pub identity: String,
    pub pid: u32,
    pub start_time_ticks: u64,
    pub original_group: String,
    pub target_group: String,
    pub original_properties: RequestedProperties,
    pub requested_properties: RequestedProperties,
    pub reason: String,
    pub applied: bool,
    pub verified: bool,
    pub rolled_back: bool,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupStatus {
    pub cgroup_v2: bool,
    pub memory_controller: bool,
    pub enabled: bool,
    pub dry_run: bool,
    pub backend: BackendKind,
    pub managed_groups: usize,
    pub assignments: usize,
    pub rollback_pending: usize,
    pub stale_recovery_state: usize,
    pub last_safety_error: Option<String>,
}

#[derive(Debug, Error)]
pub enum ActuatorError {
    #[error("cgroup capability unavailable: {0}")]
    Capability(String),
    #[error("mutation is blocked: {0}")]
    Blocked(String),
    #[error("backend operation `{operation}` failed: {source}")]
    Backend {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("snapshot persistence failed: {0}")]
    Persistence(String),
}

pub trait CgroupBackend {
    fn kind(&self) -> BackendKind;
    fn capabilities(&self) -> Result<CgroupCapabilities, ActuatorError>;
    fn inspect_group(&self, name: &str) -> Result<Option<GroupState>, ActuatorError>;
    fn create_managed_group(&mut self, name: &str) -> Result<GroupState, ActuatorError>;
    fn set_properties(
        &mut self,
        name: &str,
        properties: &RequestedProperties,
    ) -> Result<(), ActuatorError>;
    fn attach_pid(&mut self, name: &str, pid: u32) -> Result<(), ActuatorError>;
    fn process_start_time(&self, pid: u32) -> Result<Option<u64>, ActuatorError>;
    fn process_group(&self, pid: u32) -> Result<Option<String>, ActuatorError>;
    fn cleanup_empty_owned_group(&mut self, name: &str) -> Result<(), ActuatorError>;
}

pub trait SnapshotStore {
    fn persist(&mut self, snapshot: MutationSnapshot) -> Result<u64, ActuatorError>;
    fn update(&mut self, snapshot: &MutationSnapshot) -> Result<(), ActuatorError>;
    fn pending(&self) -> Result<Vec<MutationSnapshot>, ActuatorError>;
    fn record_managed_group(
        &mut self,
        name: &str,
        session_id: i64,
        backend: BackendKind,
    ) -> Result<(), ActuatorError>;
    fn remove_managed_group(&mut self, name: &str) -> Result<(), ActuatorError>;
}

#[derive(Debug, Default)]
pub struct MemorySnapshotStore {
    next_id: u64,
    snapshots: BTreeMap<u64, MutationSnapshot>,
    managed_groups: BTreeSet<String>,
}

impl SnapshotStore for MemorySnapshotStore {
    fn persist(&mut self, mut snapshot: MutationSnapshot) -> Result<u64, ActuatorError> {
        self.next_id += 1;
        snapshot.id = self.next_id;
        self.snapshots.insert(snapshot.id, snapshot);
        Ok(self.next_id)
    }

    fn update(&mut self, snapshot: &MutationSnapshot) -> Result<(), ActuatorError> {
        if !self.snapshots.contains_key(&snapshot.id) {
            return Err(ActuatorError::Persistence("unknown snapshot".to_owned()));
        }
        self.snapshots.insert(snapshot.id, snapshot.clone());
        Ok(())
    }

    fn pending(&self) -> Result<Vec<MutationSnapshot>, ActuatorError> {
        Ok(self
            .snapshots
            .values()
            .filter(|snapshot| snapshot.applied && !snapshot.rolled_back)
            .cloned()
            .collect())
    }

    fn record_managed_group(
        &mut self,
        name: &str,
        _session_id: i64,
        _backend: BackendKind,
    ) -> Result<(), ActuatorError> {
        self.managed_groups.insert(name.to_owned());
        Ok(())
    }

    fn remove_managed_group(&mut self, name: &str) -> Result<(), ActuatorError> {
        self.managed_groups.remove(name);
        Ok(())
    }
}

#[must_use]
pub fn memory_low_bytes(total_ram: u64, workload: u64, config: &CgroupsConfig) -> u64 {
    let min = percent(total_ram, config.foreground_min_percent);
    let max = percent(total_ram, config.foreground_max_percent);
    let headroom = percent(total_ram, config.minimum_headroom_percent);
    workload.saturating_add(headroom).clamp(min, max)
}

#[must_use]
pub fn memory_high_bytes(total_ram: u64, protected_low: u64, config: &CgroupsConfig) -> u64 {
    let min = percent(total_ram, config.background_high_min_percent);
    let max = percent(total_ram, config.background_high_max_percent);
    let headroom = percent(total_ram, config.minimum_headroom_percent);
    total_ram
        .saturating_sub(protected_low)
        .saturating_sub(headroom)
        .clamp(min, max)
}

fn percent(total: u64, value: u8) -> u64 {
    total.saturating_mul(u64::from(value)) / 100
}

#[must_use]
pub fn plan(input: &PlanInput<'_>, config: &CgroupsConfig, mode: &str) -> CgroupPlan {
    let process = input.classification;
    let sample = &process.sample;
    let expected_start = sample.start_time_ticks.unwrap_or_default();
    let mut blocks = Vec::new();
    if input.identity.len() != 64 {
        blocks.push("invalid_identity".to_owned());
    }
    let allow_listed = config
        .allowed_identities
        .iter()
        .any(|item| item == input.identity);
    if !allow_listed {
        blocks.push("identity_not_allow_listed".to_owned());
    }
    if input.current_start_time_ticks != Some(expected_start) {
        blocks.push("pid_starttime_mismatch".to_owned());
    }
    if process.category == ProcessCategory::Unknown {
        blocks.push("unknown_process".to_owned());
    }
    let protected_target = process.is_game
        || process.is_critical
        || process.protected
        || process.foreground == ForegroundState::Foreground;
    if !protected_target && process.foreground != ForegroundState::Background {
        blocks.push("not_confirmed_background".to_owned());
    }
    if !config.allow_move {
        blocks.push("pid_migration_disabled".to_owned());
    }
    let observe = mode == "observe";
    let dry_run = observe || config.dry_run || !config.enabled;
    let low = memory_low_bytes(
        input.total_ram_bytes,
        input.protected_workload_bytes,
        config,
    );
    let (target_group, properties, reason) = if protected_target {
        (
            FOREGROUND_GROUP,
            RequestedProperties {
                memory_low: Some(low),
                memory_high: None,
            },
            "dynamic_foreground_protection",
        )
    } else {
        (
            BACKGROUND_GROUP,
            RequestedProperties {
                memory_low: None,
                memory_high: Some(memory_high_bytes(input.total_ram_bytes, low, config)),
            },
            "conservative_background_soft_limit",
        )
    };
    CgroupPlan {
        process_catalog_id: input.process_catalog_id,
        identity: input.identity.to_owned(),
        pid: sample.pid,
        start_time_ticks: expected_start,
        source_group: input.source_group.to_owned(),
        target_group: target_group.to_owned(),
        properties,
        reason: reason.to_owned(),
        allowed: blocks.is_empty(),
        block_reasons: blocks,
        dry_run,
    }
}

pub fn apply_one<B: CgroupBackend, S: SnapshotStore>(
    backend: &mut B,
    store: &mut S,
    session_id: i64,
    timestamp_ns: i64,
    plan: &CgroupPlan,
) -> Result<Option<MutationSnapshot>, ActuatorError> {
    if plan.dry_run {
        return Ok(None);
    }
    if !plan.allowed {
        return Err(ActuatorError::Blocked(plan.block_reasons.join(",")));
    }
    if !is_managed_name(&plan.target_group) {
        return Err(ActuatorError::Blocked(
            "target is not Nemor-owned".to_owned(),
        ));
    }
    let capabilities = backend.capabilities()?;
    if !capabilities.mutation_ready() {
        return Err(ActuatorError::Capability(
            "complete writable cgroup v2 memory interface required".to_owned(),
        ));
    }
    if backend.process_start_time(plan.pid)? != Some(plan.start_time_ticks) {
        return Err(ActuatorError::Blocked("stale process identity".to_owned()));
    }
    let original_group = backend
        .process_group(plan.pid)?
        .ok_or_else(|| ActuatorError::Blocked("process terminated".to_owned()))?;
    let original = backend.inspect_group(&plan.target_group)?.map_or(
        RequestedProperties {
            memory_low: None,
            memory_high: None,
        },
        |state| RequestedProperties {
            memory_low: state.memory_low,
            memory_high: state.memory_high,
        },
    );
    let mut snapshot = MutationSnapshot {
        id: 0,
        session_id,
        timestamp_ns,
        process_catalog_id: plan.process_catalog_id,
        identity: plan.identity.clone(),
        pid: plan.pid,
        start_time_ticks: plan.start_time_ticks,
        original_group,
        target_group: plan.target_group.clone(),
        original_properties: original,
        requested_properties: plan.properties.clone(),
        reason: plan.reason.clone(),
        applied: false,
        verified: false,
        rolled_back: false,
        last_error: None,
    };
    snapshot.id = store.persist(snapshot.clone())?;
    if backend.inspect_group(&plan.target_group)?.is_none() {
        backend.create_managed_group(&plan.target_group)?;
        store.record_managed_group(&plan.target_group, session_id, backend.kind())?;
    }
    if let Err(error) = backend.set_properties(&plan.target_group, &plan.properties) {
        snapshot.last_error = Some(error.to_string());
        store.update(&snapshot)?;
        rollback_one(backend, store, &mut snapshot)?;
        return Err(error);
    }
    if let Err(error) = backend.attach_pid(&plan.target_group, plan.pid) {
        snapshot.last_error = Some(error.to_string());
        store.update(&snapshot)?;
        rollback_one(backend, store, &mut snapshot)?;
        return Err(error);
    }
    snapshot.applied = true;
    store.update(&snapshot)?;
    let state = backend
        .inspect_group(&plan.target_group)?
        .ok_or_else(|| ActuatorError::Verification("target disappeared".to_owned()))?;
    if !state.pids.contains(&plan.pid)
        || state.memory_low != plan.properties.memory_low
        || state.memory_high != plan.properties.memory_high
    {
        let error = ActuatorError::Verification("readback differs from request".to_owned());
        snapshot.last_error = Some(error.to_string());
        store.update(&snapshot)?;
        rollback_one(backend, store, &mut snapshot)?;
        return Err(error);
    }
    snapshot.verified = true;
    store.update(&snapshot)?;
    Ok(Some(snapshot))
}

pub fn rollback_one<B: CgroupBackend, S: SnapshotStore>(
    backend: &mut B,
    store: &mut S,
    snapshot: &mut MutationSnapshot,
) -> Result<(), ActuatorError> {
    if snapshot.rolled_back {
        return Ok(());
    }
    if !is_managed_name(&snapshot.target_group) {
        return Err(ActuatorError::Blocked(
            "refusing rollback of non-Nemor group".to_owned(),
        ));
    }
    if backend.process_start_time(snapshot.pid)? == Some(snapshot.start_time_ticks)
        && backend.process_group(snapshot.pid)?.is_some()
    {
        if backend.inspect_group(&snapshot.original_group)?.is_none() {
            return Err(ActuatorError::Blocked(
                "original group disappeared; placement left untouched".to_owned(),
            ));
        }
        backend.attach_pid(&snapshot.original_group, snapshot.pid)?;
    }
    if backend.inspect_group(&snapshot.target_group)?.is_some() {
        backend.set_properties(&snapshot.target_group, &snapshot.original_properties)?;
        backend.cleanup_empty_owned_group(&snapshot.target_group)?;
        if backend.inspect_group(&snapshot.target_group)?.is_none() {
            store.remove_managed_group(&snapshot.target_group)?;
        }
    }
    snapshot.rolled_back = true;
    store.update(snapshot)
}

pub fn recover<B: CgroupBackend, S: SnapshotStore>(
    backend: &mut B,
    store: &mut S,
) -> Vec<Result<(), ActuatorError>> {
    match store.pending() {
        Ok(pending) => pending
            .into_iter()
            .map(|mut snapshot| rollback_one(backend, store, &mut snapshot))
            .collect(),
        Err(error) => vec![Err(error)],
    }
}

#[must_use]
pub fn is_managed_name(name: &str) -> bool {
    matches!(name, FOREGROUND_GROUP | BACKGROUND_GROUP)
        || (name.starts_with("nemor-test-")
            && name.ends_with(".scope")
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)))
}

pub struct LinuxCgroupBackend {
    root: PathBuf,
}

impl LinuxCgroupBackend {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn group_path(&self, name: &str) -> Result<PathBuf, ActuatorError> {
        if !is_managed_name(name) {
            return Err(ActuatorError::Blocked(
                "group name is outside the Nemor namespace".to_owned(),
            ));
        }
        Ok(self.root.join(name))
    }

    fn inspect_path(&self, name: &str) -> Result<(PathBuf, bool), ActuatorError> {
        if is_managed_name(name) {
            return Ok((self.root.join(name), true));
        }
        let relative = name.strip_prefix('/').ok_or_else(|| {
            ActuatorError::Blocked("external group must be an absolute cgroup path".to_owned())
        })?;
        if relative
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return Err(ActuatorError::Blocked(
                "external group path is not normalized".to_owned(),
            ));
        }
        Ok((self.root.join(relative), false))
    }

    fn write(
        path: &Path,
        value: impl AsRef<[u8]>,
        operation: &'static str,
    ) -> Result<(), ActuatorError> {
        fs::write(path, value).map_err(|source| ActuatorError::Backend { operation, source })
    }
}

impl Default for LinuxCgroupBackend {
    fn default() -> Self {
        Self::new("/sys/fs/cgroup")
    }
}

impl CgroupBackend for LinuxCgroupBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::LinuxCgroupfs
    }

    fn capabilities(&self) -> Result<CgroupCapabilities, ActuatorError> {
        let controllers =
            fs::read_to_string(self.root.join("cgroup.controllers")).map_err(|source| {
                ActuatorError::Backend {
                    operation: "read cgroup.controllers",
                    source,
                }
            })?;
        let probe = self.root.join(FOREGROUND_GROUP);
        Ok(CgroupCapabilities {
            cgroup_v2: self.root.join("cgroup.controllers").is_file(),
            memory_controller: controllers.split_whitespace().any(|item| item == "memory"),
            hierarchy: self.root.clone(),
            writable: fs::OpenOptions::new()
                .write(true)
                .open(self.root.join("cgroup.procs"))
                .is_ok(),
            memory_low: probe.join("memory.low").exists() || self.root.join("memory.low").exists(),
            memory_high: probe.join("memory.high").exists()
                || self.root.join("memory.high").exists(),
            attach: probe.join("cgroup.procs").exists() || self.root.join("cgroup.procs").exists(),
        })
    }

    fn inspect_group(&self, name: &str) -> Result<Option<GroupState>, ActuatorError> {
        let (path, owned_by_nemor) = self.inspect_path(name)?;
        if !path.exists() {
            return Ok(None);
        }
        let read_limit = |file: &str| -> Option<u64> {
            fs::read_to_string(path.join(file))
                .ok()
                .and_then(|value| value.trim().parse().ok())
        };
        let pids = fs::read_to_string(path.join("cgroup.procs"))
            .unwrap_or_default()
            .lines()
            .filter_map(|value| value.parse().ok())
            .collect();
        let memory_low = read_limit("memory.low");
        let memory_high = read_limit("memory.high");
        Ok(Some(GroupState {
            name: name.to_owned(),
            path,
            owned_by_nemor,
            memory_low,
            memory_high,
            pids,
        }))
    }

    fn create_managed_group(&mut self, name: &str) -> Result<GroupState, ActuatorError> {
        let path = self.group_path(name)?;
        fs::create_dir(&path).map_err(|source| ActuatorError::Backend {
            operation: "create managed group",
            source,
        })?;
        self.inspect_group(name)?
            .ok_or_else(|| ActuatorError::Verification("created group is absent".to_owned()))
    }

    fn set_properties(
        &mut self,
        name: &str,
        properties: &RequestedProperties,
    ) -> Result<(), ActuatorError> {
        let path = self.group_path(name)?;
        if let Some(value) = properties.memory_low {
            Self::write(
                &path.join("memory.low"),
                value.to_string(),
                "write memory.low",
            )?;
        }
        if let Some(value) = properties.memory_high {
            Self::write(
                &path.join("memory.high"),
                value.to_string(),
                "write memory.high",
            )?;
        }
        Ok(())
    }

    fn attach_pid(&mut self, name: &str, pid: u32) -> Result<(), ActuatorError> {
        let path = if is_managed_name(name) {
            self.group_path(name)?
        } else {
            let relative = name.strip_prefix('/').ok_or_else(|| {
                ActuatorError::Blocked("original group must be an absolute cgroup path".to_owned())
            })?;
            self.root.join(relative)
        };
        Self::write(&path.join("cgroup.procs"), pid.to_string(), "attach PID")
    }

    fn process_start_time(&self, pid: u32) -> Result<Option<u64>, ActuatorError> {
        let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(ActuatorError::Backend {
                    operation: "read process stat",
                    source,
                })
            }
        };
        let close = stat
            .rfind(')')
            .ok_or_else(|| ActuatorError::Verification("invalid process stat".to_owned()))?;
        Ok(stat[close + 1..]
            .split_whitespace()
            .nth(19)
            .and_then(|value| value.parse().ok()))
    }

    fn process_group(&self, pid: u32) -> Result<Option<String>, ActuatorError> {
        let value = match fs::read_to_string(format!("/proc/{pid}/cgroup")) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(ActuatorError::Backend {
                    operation: "read process cgroup",
                    source,
                })
            }
        };
        Ok(value
            .lines()
            .find_map(|line| line.strip_prefix("0::").map(str::to_owned)))
    }

    fn cleanup_empty_owned_group(&mut self, name: &str) -> Result<(), ActuatorError> {
        let state = self.inspect_group(name)?;
        if let Some(state) = state {
            if !state.owned_by_nemor || !state.pids.is_empty() {
                return Ok(());
            }
            fs::remove_dir(state.path).map_err(|source| ActuatorError::Backend {
                operation: "remove empty managed group",
                source,
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeFailure {
    Create,
    Property,
    Move,
    Verify,
    Rollback,
}

#[cfg(test)]
pub struct FakeCgroupBackend {
    pub capabilities: CgroupCapabilities,
    pub groups: HashMap<String, GroupState>,
    pub starts: HashMap<u32, u64>,
    pub placements: HashMap<u32, String>,
    pub operations: Vec<String>,
    pub failure: Option<FakeFailure>,
}

#[cfg(test)]
impl Default for FakeCgroupBackend {
    fn default() -> Self {
        Self {
            capabilities: CgroupCapabilities {
                cgroup_v2: true,
                memory_controller: true,
                hierarchy: PathBuf::from("/fake"),
                writable: true,
                memory_low: true,
                memory_high: true,
                attach: true,
            },
            groups: HashMap::new(),
            starts: HashMap::new(),
            placements: HashMap::new(),
            operations: Vec::new(),
            failure: None,
        }
    }
}

#[cfg(test)]
impl CgroupBackend for FakeCgroupBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Simulated
    }
    fn capabilities(&self) -> Result<CgroupCapabilities, ActuatorError> {
        Ok(self.capabilities.clone())
    }
    fn inspect_group(&self, name: &str) -> Result<Option<GroupState>, ActuatorError> {
        let mut state = self.groups.get(name).cloned();
        if self.failure == Some(FakeFailure::Verify) {
            if let Some(state) = &mut state {
                state.memory_high = None;
            }
        }
        Ok(state)
    }
    fn create_managed_group(&mut self, name: &str) -> Result<GroupState, ActuatorError> {
        self.operations.push(format!("create:{name}"));
        if self.failure == Some(FakeFailure::Create) {
            return Err(fake_error("create managed group"));
        }
        if !is_managed_name(name) {
            return Err(ActuatorError::Blocked("foreign group".to_owned()));
        }
        let state = GroupState {
            name: name.to_owned(),
            path: PathBuf::from("/fake").join(name),
            owned_by_nemor: true,
            memory_low: None,
            memory_high: None,
            pids: BTreeSet::new(),
        };
        self.groups.insert(name.to_owned(), state.clone());
        Ok(state)
    }
    fn set_properties(
        &mut self,
        name: &str,
        properties: &RequestedProperties,
    ) -> Result<(), ActuatorError> {
        self.operations.push(format!("properties:{name}"));
        if self.failure == Some(FakeFailure::Property) {
            return Err(fake_error("set properties"));
        }
        let state = self
            .groups
            .get_mut(name)
            .ok_or_else(|| fake_error("set properties"))?;
        state.memory_low = properties.memory_low;
        state.memory_high = properties.memory_high;
        Ok(())
    }
    fn attach_pid(&mut self, name: &str, pid: u32) -> Result<(), ActuatorError> {
        self.operations.push(format!("attach:{name}:{pid}"));
        if self.failure == Some(FakeFailure::Move) {
            return Err(fake_error("attach PID"));
        }
        if let Some(old) = self.placements.insert(pid, name.to_owned()) {
            if let Some(group) = self.groups.get_mut(&old) {
                group.pids.remove(&pid);
            }
        }
        if let Some(group) = self.groups.get_mut(name) {
            group.pids.insert(pid);
        }
        Ok(())
    }
    fn process_start_time(&self, pid: u32) -> Result<Option<u64>, ActuatorError> {
        Ok(self.starts.get(&pid).copied())
    }
    fn process_group(&self, pid: u32) -> Result<Option<String>, ActuatorError> {
        Ok(self.placements.get(&pid).cloned())
    }
    fn cleanup_empty_owned_group(&mut self, name: &str) -> Result<(), ActuatorError> {
        self.operations.push(format!("cleanup:{name}"));
        if self.failure == Some(FakeFailure::Rollback) {
            return Err(fake_error("cleanup"));
        }
        if self
            .groups
            .get(name)
            .is_some_and(|state| state.owned_by_nemor && state.pids.is_empty())
        {
            self.groups.remove(name);
        }
        Ok(())
    }
}

#[cfg(test)]
fn fake_error(operation: &'static str) -> ActuatorError {
    ActuatorError::Backend {
        operation,
        source: io::Error::other("injected failure"),
    }
}

#[cfg(test)]
mod tests;
