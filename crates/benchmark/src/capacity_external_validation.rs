//! One-shot validation of the exact external HOT/WARM/COLD benchmark target.
//!
//! This boundary deliberately does not implement pressure search, capacity
//! evaluation, or production activation.

use crate::capacity_external_target::{
    proc_start_ticks, read_progress, write_command, CapacityExternalTargetCommand,
    CapacityExternalTargetContract, CapacityExternalTargetDescriptor,
    CapacityExternalTargetProgress, CAPACITY_EXTERNAL_TARGET_CONTRACT_VERSION,
    CAPACITY_EXTERNAL_TARGET_PROTOCOL_VERSION,
};
use crate::capacity_orchestration::{
    component_contracts_for, CapacityComponent, CapacityComponentContractIdentity,
};
use crate::performance::BinaryIdentity;
use crate::validator_report::{
    inspect_scoped_report, legacy_report_absent, validator_state_absent,
    ValidatorReportLifecycleEvidence,
};
use crate::{BuildProvenance, EnvironmentFingerprint, EvaluationState};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const EXTERNAL_TARGET_MANIFEST_SCHEMA_VERSION: u32 = 2;
pub const EXTERNAL_TARGET_PREFLIGHT_SCHEMA_VERSION: u32 = 2;
pub const EXTERNAL_TARGET_EXECUTION_SCHEMA_VERSION: u32 = 2;
pub const EXTERNAL_TARGET_MANIFEST_NAME: &str = "capacity-external-target.manifest.json";
pub const EXTERNAL_TARGET_MAX_RUNTIME_MS: u64 = 180_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalTargetValidationPayload {
    pub schema_version: u32,
    pub execution_schema_version: u32,
    pub validation_id: String,
    pub target_session_id: String,
    pub target_nonce: String,
    pub provenance: BuildProvenance,
    pub runner_binary: BinaryIdentity,
    pub target_binary: BinaryIdentity,
    pub validator_binary: BinaryIdentity,
    pub repository: PathBuf,
    pub config_path: PathBuf,
    pub config_sha256: String,
    pub material_environment_hash: String,
    pub runner_path: PathBuf,
    pub target_path: PathBuf,
    pub validator_path: PathBuf,
    pub prepared_root: PathBuf,
    pub output_root: PathBuf,
    pub report_path: PathBuf,
    pub raw_damos_report_path: PathBuf,
    pub runtime_descriptor_evidence_path: PathBuf,
    pub target_progress_evidence_path: PathBuf,
    pub preparing_uid: u32,
    pub preparing_gid: u32,
    pub components: BTreeSet<CapacityComponent>,
    pub component_contracts: Vec<CapacityComponentContractIdentity>,
    pub target_contract: CapacityExternalTargetContract,
    pub ownership_strategy: String,
    pub maximum_runtime_ms: u64,
    pub automatic_retry: bool,
    pub production_activation_authorized: bool,
    pub capacity_evaluation: EvaluationState,
    pub effectiveness_evaluation: EvaluationState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedExternalTargetValidationManifest {
    pub payload: ExternalTargetValidationPayload,
    pub payload_sha256: String,
}

impl PreparedExternalTargetValidationManifest {
    pub fn verify(&self) -> Result<()> {
        let components = BTreeSet::from([
            CapacityComponent::DamonTelemetry,
            CapacityComponent::DamosReclaim,
        ]);
        if self.payload_sha256 != hash_json(&self.payload)?
            || self.payload.schema_version != EXTERNAL_TARGET_MANIFEST_SCHEMA_VERSION
            || self.payload.execution_schema_version != EXTERNAL_TARGET_EXECUTION_SCHEMA_VERSION
            || self.payload.components != components
            || self.payload.component_contracts != component_contracts_for(&components)
            || self.payload.target_contract != CapacityExternalTargetContract::v1()
            || self.payload.ownership_strategy
                != "direct_child_private_directory_nonce_pid_start_ticks_executable_identity"
            || self.payload.maximum_runtime_ms != EXTERNAL_TARGET_MAX_RUNTIME_MS
            || self.payload.automatic_retry
            || self.payload.production_activation_authorized
            || self.payload.capacity_evaluation != EvaluationState::NotEvaluated
            || self.payload.effectiveness_evaluation != EvaluationState::NotEvaluated
        {
            bail!("external target manifest is not the exact v1 benchmark-only contract");
        }
        self.payload.target_contract.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalTargetPrivilegeStatus {
    DeferredToPrivilegedPreflight,
    RequiresOwnedContextValidation,
    Verified,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalTargetPreflight {
    pub schema_version: u32,
    pub manifest_verified: bool,
    pub source_and_binaries_verified: bool,
    pub material_environment_match: bool,
    pub component_set_supported: bool,
    pub target_contract_supported: bool,
    pub target_protocol_supported: bool,
    pub ownership_plan_supported: bool,
    pub action_envelope_unchanged: bool,
    pub output_fresh: bool,
    pub stale_resources_clear: bool,
    pub legacy_global_report_absent: bool,
    pub validator_state_absent: bool,
    pub privileged_capability: ExternalTargetPrivilegeStatus,
    pub user_preflight_passed: bool,
    pub current_identity_authorized: bool,
    pub exact_target_creation_plan_authorized: bool,
    pub bounded_external_target_validation_entry_ready: bool,
    pub execution_ready: bool,
    pub preflight_mutated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalTargetClassification {
    Pass,
    PreflightBlocked,
    OwnershipRejected,
    TargetProtocolFailure,
    TargetHealthFailure,
    ShadowCapabilityFailure,
    LiveActionFailure,
    SafetyAbort,
    CleanupFailure,
    RestoreFailure,
    Invalid,
    ExecutionError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalTargetExecutionPayload {
    pub schema_version: u32,
    pub validation_id: String,
    pub source_commit: String,
    pub source_state_id: String,
    pub component_set: BTreeSet<CapacityComponent>,
    pub target_contract_version: u32,
    pub target_protocol_version: u32,
    pub target_descriptor_hash: String,
    pub target_identity: crate::capacity_external_target::CapacityExternalTargetIdentity,
    pub target_ranges: crate::capacity_external_target::CapacityExternalTargetRanges,
    pub control_channel_identity: String,
    pub final_progress: CapacityExternalTargetProgress,
    pub validator_exit_success: bool,
    #[serde(default)]
    pub validator_report_lifecycle: ValidatorReportLifecycleEvidence,
    pub direct_shadow_gates: [bool; 4],
    pub required_damos_gates_passed: bool,
    pub zero_host_oom: bool,
    pub cleanup_passed: bool,
    pub recovery_passed: bool,
    pub recovery_idempotent_passed: bool,
    pub structural_restore_passed: bool,
    pub elapsed_ns: u64,
    pub capacity_evaluation: EvaluationState,
    pub effectiveness_evaluation: EvaluationState,
    pub production_activation_authorized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalTargetExecutionReport {
    pub state: ExternalTargetClassification,
    pub reason: String,
    pub payload: ExternalTargetExecutionPayload,
    pub payload_sha256: String,
}

impl ExternalTargetExecutionReport {
    fn seal(
        state: ExternalTargetClassification,
        reason: String,
        payload: ExternalTargetExecutionPayload,
    ) -> Result<Self> {
        Ok(Self {
            state,
            reason,
            payload_sha256: hash_json(&payload)?,
            payload,
        })
    }

    pub fn verify(&self) -> Result<()> {
        if self.payload_sha256 != hash_json(&self.payload)?
            || self.payload.schema_version != EXTERNAL_TARGET_EXECUTION_SCHEMA_VERSION
            || !matches!(
                self.payload.validator_report_lifecycle.classification,
                crate::validator_report::ValidatorReportLifecycleClassification::Pass
            )
            || !self
                .payload
                .validator_report_lifecycle
                .legacy_global_absent_before
            || !self
                .payload
                .validator_report_lifecycle
                .legacy_global_absent_after
            || !self
                .payload
                .validator_report_lifecycle
                .validator_state_absent
            || self.payload.capacity_evaluation != EvaluationState::NotEvaluated
            || self.payload.effectiveness_evaluation != EvaluationState::NotEvaluated
            || self.payload.production_activation_authorized
        {
            bail!("external target execution evidence integrity or non-claim mismatch");
        }
        Ok(())
    }
}

pub fn prepare_external_target_validation(
    repository: &Path,
    config: &Path,
    validator_binary: &Path,
    target_binary: Option<&Path>,
    prepared_root: &Path,
    output_root: &Path,
) -> Result<PathBuf> {
    let uid = nix::unistd::geteuid().as_raw();
    if uid == 0 {
        bail!("external target preparation must run unprivileged");
    }
    if prepared_root.exists()
        || output_root.exists()
        || !prepared_root.is_absolute()
        || !output_root.is_absolute()
    {
        bail!("external target paths must be fresh and absolute");
    }
    let repository = repository.canonicalize()?;
    if std::env::current_dir()?.canonicalize()? != repository {
        bail!("preparation requires the explicit current repository");
    }
    let config_path = config.canonicalize()?;
    let runner_path = std::env::current_exe()?.canonicalize()?;
    let target_path = target_binary.unwrap_or(&runner_path).canonicalize()?;
    let validator_path = validator_binary.canonicalize()?;
    let loaded = common::LoadedConfig::load(&config_path)?;
    let provenance = BuildProvenance::capture()?;
    if !provenance.clean_release_eligible() {
        bail!("external target preparation requires exact clean release provenance");
    }
    let identity = |role: &str, path: &Path| {
        BinaryIdentity::capture(
            role,
            path,
            &provenance.source_state_id,
            &provenance.git_head,
        )
    };
    let runner_binary = identity("nemor_benchmark", &runner_path)?;
    let target_binary = identity("capacity_external_target", &target_path)?;
    let validator_binary = identity("nemor_privileged_validation", &validator_path)?;
    if [&runner_binary, &target_binary, &validator_binary]
        .iter()
        .any(|item| item.build_profile != "release")
    {
        bail!("all frozen external target binaries must be release builds");
    }
    let environment =
        EnvironmentFingerprint::capture_for_performance(&loaded.sha256, &provenance.git_head)?;
    let validation_id = format!("capacity-external-target-{}", now_ns()?);
    let target_session_id = format!("{validation_id}-target");
    let target_nonce = hex::encode(Sha256::digest(format!(
        "{validation_id}:{}:{}",
        provenance.source_state_id, loaded.sha256
    )));
    fs::create_dir(prepared_root)?;
    fs::set_permissions(prepared_root, fs::Permissions::from_mode(0o700))?;
    fs::create_dir(output_root)?;
    fs::set_permissions(output_root, fs::Permissions::from_mode(0o700))?;
    let components = BTreeSet::from([
        CapacityComponent::DamonTelemetry,
        CapacityComponent::DamosReclaim,
    ]);
    let payload = ExternalTargetValidationPayload {
        schema_version: EXTERNAL_TARGET_MANIFEST_SCHEMA_VERSION,
        execution_schema_version: EXTERNAL_TARGET_EXECUTION_SCHEMA_VERSION,
        validation_id,
        target_session_id,
        target_nonce,
        provenance,
        runner_binary,
        target_binary,
        validator_binary,
        repository,
        config_path,
        config_sha256: loaded.sha256,
        material_environment_hash: environment.material_hash()?,
        runner_path,
        target_path,
        validator_path,
        prepared_root: prepared_root.to_path_buf(),
        output_root: output_root.to_path_buf(),
        report_path: output_root.join("capacity-external-target.json"),
        raw_damos_report_path: output_root.join("damos-component-report.json"),
        runtime_descriptor_evidence_path: output_root.join("target-runtime-descriptor.json"),
        target_progress_evidence_path: output_root.join("target-progress.json"),
        preparing_uid: uid,
        preparing_gid: nix::unistd::getegid().as_raw(),
        component_contracts: component_contracts_for(&components),
        components,
        target_contract: CapacityExternalTargetContract::v1(),
        ownership_strategy:
            "direct_child_private_directory_nonce_pid_start_ticks_executable_identity".into(),
        maximum_runtime_ms: EXTERNAL_TARGET_MAX_RUNTIME_MS,
        automatic_retry: false,
        production_activation_authorized: false,
        capacity_evaluation: EvaluationState::NotEvaluated,
        effectiveness_evaluation: EvaluationState::NotEvaluated,
    };
    let manifest = PreparedExternalTargetValidationManifest {
        payload_sha256: hash_json(&payload)?,
        payload,
    };
    manifest.verify()?;
    let path = prepared_root.join(EXTERNAL_TARGET_MANIFEST_NAME);
    write_new_json(&path, &manifest)?;
    Ok(path)
}

pub fn external_target_preflight(manifest_path: &Path) -> Result<ExternalTargetPreflight> {
    let manifest = read_manifest(manifest_path)?;
    let current = std::env::current_exe()?.canonicalize()?;
    let source_and_binaries_verified = current == manifest.payload.runner_path
        && hash_file(&current)? == manifest.payload.runner_binary.sha256
        && hash_file(&manifest.payload.target_path)? == manifest.payload.target_binary.sha256
        && hash_file(&manifest.payload.validator_path)? == manifest.payload.validator_binary.sha256;
    let loaded = common::LoadedConfig::load(&manifest.payload.config_path)?;
    let environment = EnvironmentFingerprint::capture_for_performance(
        &loaded.sha256,
        &manifest.payload.provenance.git_head,
    )?;
    let material_environment_match = loaded.sha256 == manifest.payload.config_sha256
        && environment.material_hash()? == manifest.payload.material_environment_hash;
    let output_fresh = fs::read_dir(&manifest.payload.output_root)?
        .next()
        .is_none();
    let transaction_root = manifest.payload.output_root.join("target-transaction");
    let legacy_global_report_absent = legacy_report_absent();
    let validator_state_absent = validator_state_absent();
    let stale_resources_clear =
        legacy_global_report_absent && validator_state_absent && !transaction_root.exists();
    let observation = damon::inspect_linux_observability(Path::new("/"));
    let damon = damon::inspect_linux(Path::new("/"), None);
    let damos = damos::observe_capability(&damon);
    let root = nix::unistd::geteuid().is_root();
    let privileged_capability =
        match crate::capacity_compatibility::observability_status(&observation, &damon, &damos, root)
        {
            crate::capacity_compatibility::PrivilegeSensitiveCapabilityStatus::DeferredToPrivilegedPreflight => ExternalTargetPrivilegeStatus::DeferredToPrivilegedPreflight,
            crate::capacity_compatibility::PrivilegeSensitiveCapabilityStatus::RequiresOwnedContextValidation => ExternalTargetPrivilegeStatus::RequiresOwnedContextValidation,
            crate::capacity_compatibility::PrivilegeSensitiveCapabilityStatus::Verified => ExternalTargetPrivilegeStatus::Verified,
            crate::capacity_compatibility::PrivilegeSensitiveCapabilityStatus::Unsupported
            | crate::capacity_compatibility::PrivilegeSensitiveCapabilityStatus::InspectionError => ExternalTargetPrivilegeStatus::Unsupported,
    };
    let identity_authorized = root
        && std::env::var("SUDO_UID").ok().and_then(|v| v.parse().ok())
            == Some(manifest.payload.preparing_uid)
        && std::env::var("SUDO_GID").ok().and_then(|v| v.parse().ok())
            == Some(manifest.payload.preparing_gid);
    let common = source_and_binaries_verified
        && material_environment_match
        && output_fresh
        && stale_resources_clear;
    let entry = common
        && identity_authorized
        && matches!(
            privileged_capability,
            ExternalTargetPrivilegeStatus::RequiresOwnedContextValidation
                | ExternalTargetPrivilegeStatus::Verified
        );
    Ok(ExternalTargetPreflight {
        schema_version: EXTERNAL_TARGET_PREFLIGHT_SCHEMA_VERSION,
        manifest_verified: true,
        source_and_binaries_verified,
        material_environment_match,
        component_set_supported: true,
        target_contract_supported: true,
        target_protocol_supported: true,
        ownership_plan_supported: true,
        action_envelope_unchanged: true,
        output_fresh,
        stale_resources_clear,
        legacy_global_report_absent,
        validator_state_absent,
        privileged_capability,
        user_preflight_passed: common,
        current_identity_authorized: identity_authorized,
        exact_target_creation_plan_authorized: entry,
        bounded_external_target_validation_entry_ready: entry,
        execution_ready: false,
        preflight_mutated: false,
    })
}

pub fn validate_external_target(manifest_path: &Path) -> Result<ExternalTargetExecutionReport> {
    let manifest = read_manifest(manifest_path)?;
    if !external_target_preflight(manifest_path)?.bounded_external_target_validation_entry_ready {
        bail!("external target bounded validation preflight failed");
    }
    let transaction_root = manifest.payload.output_root.join("target-transaction");
    fs::create_dir(&transaction_root)?;
    fs::set_permissions(&transaction_root, fs::Permissions::from_mode(0o700))?;
    let creator_pid = std::process::id();
    let creator_start_ticks =
        proc_start_ticks(creator_pid)?.context("runner start ticks unavailable")?;
    let mut target = Command::new(&manifest.payload.target_path)
        .args([
            "capacity-external-target-worker",
            "--transaction-root",
            transaction_root
                .to_str()
                .context("non-UTF8 transaction path")?,
            "--transaction-id",
            &manifest.payload.validation_id,
            "--session-id",
            &manifest.payload.target_session_id,
            "--nonce",
            &manifest.payload.target_nonce,
            "--creator-pid",
            &creator_pid.to_string(),
            "--creator-start-ticks",
            &creator_start_ticks.to_string(),
            "--preparing-uid",
            &manifest.payload.preparing_uid.to_string(),
            "--preparing-gid",
            &manifest.payload.preparing_gid.to_string(),
            "--unit-or-cgroup-identity",
            "direct-child-no-cgroup",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn exact external target")?;
    let descriptor_path = transaction_root.join("target-descriptor.json");
    wait_for_path(&descriptor_path, Duration::from_secs(5))?;
    let descriptor: CapacityExternalTargetDescriptor =
        serde_json::from_slice(&fs::read(&descriptor_path)?)?;
    descriptor.validate_integrity()?;
    if descriptor.payload.identity.creator_pid != creator_pid
        || descriptor.payload.identity.creator_start_ticks != creator_start_ticks
        || descriptor.payload.identity.executable_sha256 != manifest.payload.target_binary.sha256
        || descriptor.payload.identity.embedded_source_commit
            != manifest.payload.provenance.git_head
    {
        bail!("actual external target differs from frozen target identity");
    }
    let started = Instant::now();
    let legacy_absent_before = legacy_report_absent();
    let status = Command::new(&manifest.payload.validator_path)
        .arg("--damos")
        .arg("--external-target-descriptor")
        .arg(&descriptor_path)
        .arg("--external-target-transaction-id")
        .arg(&manifest.payload.validation_id)
        .arg("--external-target-session-id")
        .arg(&manifest.payload.target_session_id)
        .arg("--external-target-nonce")
        .arg(&manifest.payload.target_nonce)
        .arg("--external-target-creator-pid")
        .arg(creator_pid.to_string())
        .arg("--external-target-creator-start-ticks")
        .arg(creator_start_ticks.to_string())
        .arg("--report-path")
        .arg(&manifest.payload.raw_damos_report_path)
        .arg("--report-root")
        .arg(&manifest.payload.output_root)
        .current_dir(&manifest.payload.repository)
        .status()
        .context("launch external-target DAMOS controller")?;
    let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    if read_progress(&descriptor.payload.progress_path).is_ok_and(|progress| {
        !matches!(
            progress.state,
            crate::capacity_external_target::CapacityExternalTargetState::Stopping
                | crate::capacity_external_target::CapacityExternalTargetState::Stopped
        )
    }) {
        write_command(
            &transaction_root,
            &CapacityExternalTargetCommand::Stop {
                nonce: manifest.payload.target_nonce.clone(),
            },
        )?;
    }
    let _ = target.wait();
    let (component, _raw, mut validator_report_lifecycle) = inspect_scoped_report(
        &manifest.payload.raw_damos_report_path,
        &manifest.payload.output_root,
        "damos-component-report.json",
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
        status.code(),
        legacy_absent_before,
    )?;
    let final_progress = read_progress(&descriptor.payload.progress_path)?;
    let checks = component["damos"]["checks"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let passed = |name: &str| {
        checks.iter().any(|check| {
            check["name"].as_str() == Some(name) && check["passed"].as_bool() == Some(true)
        })
    };
    let direct = [
        passed("vaddr_pageout_supported"),
        passed("shadow_session_passed"),
        passed("shadow_cleanup"),
        passed("cold_address_fence"),
    ];
    let required = component["damos"]["required_gates_passed"]
        .as_bool()
        .unwrap_or(false);
    let cleanup = passed("cleanup") && passed("scheme_removed");
    let recovery = passed("recovery");
    let recovery_idempotent = passed("recovery_idempotent");
    let restore = component["host_unchanged"].as_bool().unwrap_or(false);
    let zero_oom = passed("zero_oom");
    let target_health = final_progress.hot_cycles > 0
        && final_progress.warm_cycles > 0
        && final_progress.controlled_refaults == 1
        && final_progress.state
            == crate::capacity_external_target::CapacityExternalTargetState::Stopped;
    fs::copy(
        &descriptor_path,
        &manifest.payload.runtime_descriptor_evidence_path,
    )?;
    write_new_json(
        &manifest.payload.target_progress_evidence_path,
        &final_progress,
    )?;
    cleanup_transaction(&transaction_root)?;
    validator_report_lifecycle.legacy_global_absent_after = legacy_report_absent();
    validator_report_lifecycle.validator_state_absent = validator_state_absent();
    let report_lifecycle_pass = validator_report_lifecycle.legacy_global_absent_before
        && validator_report_lifecycle.legacy_global_absent_after
        && validator_report_lifecycle.validator_state_absent;
    let pass = status.success()
        && elapsed_ns <= EXTERNAL_TARGET_MAX_RUNTIME_MS.saturating_mul(1_000_000)
        && direct.into_iter().all(|gate| gate)
        && required
        && cleanup
        && recovery
        && recovery_idempotent
        && restore
        && zero_oom
        && target_health
        && report_lifecycle_pass;
    let payload = ExternalTargetExecutionPayload {
        schema_version: EXTERNAL_TARGET_EXECUTION_SCHEMA_VERSION,
        validation_id: manifest.payload.validation_id.clone(),
        source_commit: manifest.payload.provenance.git_head.clone(),
        source_state_id: manifest.payload.provenance.source_state_id.clone(),
        component_set: manifest.payload.components.clone(),
        target_contract_version: CAPACITY_EXTERNAL_TARGET_CONTRACT_VERSION,
        target_protocol_version: CAPACITY_EXTERNAL_TARGET_PROTOCOL_VERSION,
        target_descriptor_hash: descriptor.payload_sha256.clone(),
        target_identity: descriptor.payload.identity.clone(),
        target_ranges: descriptor.payload.ranges.clone(),
        control_channel_identity: descriptor.payload.identity.control_channel_identity.clone(),
        final_progress,
        validator_exit_success: status.success(),
        validator_report_lifecycle,
        direct_shadow_gates: direct,
        required_damos_gates_passed: required,
        zero_host_oom: zero_oom,
        cleanup_passed: cleanup,
        recovery_passed: recovery,
        recovery_idempotent_passed: recovery_idempotent,
        structural_restore_passed: restore,
        elapsed_ns,
        capacity_evaluation: EvaluationState::NotEvaluated,
        effectiveness_evaluation: EvaluationState::NotEvaluated,
        production_activation_authorized: false,
    };
    let state = if pass {
        ExternalTargetClassification::Pass
    } else if !cleanup {
        ExternalTargetClassification::CleanupFailure
    } else if !restore {
        ExternalTargetClassification::RestoreFailure
    } else if !target_health {
        ExternalTargetClassification::TargetHealthFailure
    } else if !direct.into_iter().all(|gate| gate) {
        ExternalTargetClassification::ShadowCapabilityFailure
    } else {
        ExternalTargetClassification::LiveActionFailure
    };
    let report = ExternalTargetExecutionReport::seal(
        state,
        if pass {
            "exact external HOT/WARM/COLD ownership and bounded lifecycle passed".into()
        } else {
            "one or more mandatory external-target lifecycle gates failed".into()
        },
        payload,
    )?;
    report.verify()?;
    write_new_json(&manifest.payload.report_path, &report)?;
    Ok(report)
}

fn cleanup_transaction(root: &Path) -> Result<()> {
    if root.file_name().and_then(|name| name.to_str()) != Some("target-transaction") {
        bail!("refusing to clean unexpected external target transaction path");
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            bail!("nested external target transaction content is forbidden");
        }
        fs::remove_file(path)?;
    }
    fs::remove_dir(root)?;
    Ok(())
}

fn read_manifest(path: &Path) -> Result<PreparedExternalTargetValidationManifest> {
    let manifest: PreparedExternalTargetValidationManifest =
        serde_json::from_slice(&fs::read(path)?)?;
    manifest.verify()?;
    if path
        != manifest
            .payload
            .prepared_root
            .join(EXTERNAL_TARGET_MANIFEST_NAME)
    {
        bail!("external target manifest path does not match frozen path");
    }
    Ok(manifest)
}

fn wait_for_path(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    bail!("timed out waiting for {}", path.display())
}

fn write_new_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    Ok(())
}

fn hash_json(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn hash_file(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

fn now_ns() -> Result<u128> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_evidence_cannot_authorize_capacity_or_production() {
        assert_eq!(CAPACITY_EXTERNAL_TARGET_CONTRACT_VERSION, 1);
        assert_eq!(CAPACITY_EXTERNAL_TARGET_PROTOCOL_VERSION, 1);
        assert_eq!(EXTERNAL_TARGET_MANIFEST_SCHEMA_VERSION, 2);
        assert_eq!(EXTERNAL_TARGET_PREFLIGHT_SCHEMA_VERSION, 2);
        assert_eq!(EXTERNAL_TARGET_EXECUTION_SCHEMA_VERSION, 2);
        let contract = CapacityExternalTargetContract::v1();
        assert!(!contract.pressure_search_authorized);
        assert!(!contract.production_activation_authorized);
    }

    #[test]
    fn cleanup_rejects_broad_or_nested_targets() {
        let temp = tempfile::tempdir().unwrap();
        assert!(cleanup_transaction(temp.path()).is_err());
        let root = temp.path().join("target-transaction");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("nested")).unwrap();
        assert!(cleanup_transaction(&root).is_err());
    }

    #[test]
    fn classifications_keep_infrastructure_failures_distinct() {
        assert_ne!(
            ExternalTargetClassification::OwnershipRejected,
            ExternalTargetClassification::Pass
        );
        assert_ne!(
            ExternalTargetClassification::CleanupFailure,
            ExternalTargetClassification::RestoreFailure
        );
    }
}
