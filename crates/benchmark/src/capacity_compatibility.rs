//! Frozen, bounded compatibility validation for an exact `nemor_capacity` component set.
//!
//! This is a validation-only boundary. It cannot activate `nemor_capacity`,
//! calculate capacity/effectiveness, or start the production daemon.

use crate::capacity_orchestration::{
    component_contracts_for, CapacityCombinedCompatibilityEvidence,
    CapacityCombinedCompatibilityPayload, CapacityCompatibilityClassification, CapacityComponent,
    CapacityEvidencePrerequisite, CapacityOwnershipBoundary,
    CAPACITY_COMBINED_COMPATIBILITY_EVIDENCE_VERSION,
};
use crate::performance::BinaryIdentity;
use crate::{BuildProvenance, EnvironmentFingerprint, EvaluationState};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const PREPARED_CAPACITY_COMPATIBILITY_SCHEMA_VERSION: u32 = 1;
pub const CAPACITY_COMPATIBILITY_EXECUTION_SCHEMA_VERSION: u32 = 1;
pub const CAPACITY_COMPATIBILITY_PREFLIGHT_SCHEMA_VERSION: u32 = 2;
pub const CAPACITY_COMPATIBILITY_MAX_RUNTIME_MS: u64 = 180_000;
pub const CAPACITY_COMPATIBILITY_MANIFEST_NAME: &str = "capacity-compatibility.manifest.json";
const HARNESS_REPORT: &str = "/tmp/nemor-privileged-validation-report.json";
const HARNESS_STATE: &str = "/tmp/nemor-privileged-validation";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityCompatibilityPayload {
    pub schema_version: u32,
    pub execution_schema_version: u32,
    pub validation_id: String,
    pub purpose: String,
    pub provenance: BuildProvenance,
    pub runner_binary: BinaryIdentity,
    pub validator_binary: BinaryIdentity,
    pub config_sha256: String,
    pub material_environment_hash: String,
    pub repository: PathBuf,
    pub config_path: PathBuf,
    pub runner_path: PathBuf,
    pub validator_path: PathBuf,
    pub prepared_root: PathBuf,
    pub output_root: PathBuf,
    pub report_path: PathBuf,
    pub raw_component_report_path: PathBuf,
    pub preparing_uid: u32,
    pub preparing_gid: u32,
    pub components: BTreeSet<CapacityComponent>,
    pub component_contracts: Vec<crate::capacity_orchestration::CapacityComponentContractIdentity>,
    pub ownership: BTreeMap<CapacityComponent, CapacityOwnershipBoundary>,
    pub capabilities: BTreeSet<crate::capacity_orchestration::CapacityCapability>,
    pub individual_evidence: BTreeSet<CapacityEvidencePrerequisite>,
    pub apply_order: Vec<CapacityComponent>,
    pub rollback_order: Vec<CapacityComponent>,
    pub excluded_components: BTreeMap<CapacityComponent, String>,
    pub maximum_runtime_ms: u64,
    pub automatic_retry: bool,
    pub host_oom_prohibited: bool,
    pub restore_failure_invalidates_result: bool,
    pub production_activation_authorized: bool,
    pub capacity_evaluation: EvaluationState,
    pub effectiveness_evaluation: EvaluationState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedCapacityCompatibilityManifest {
    pub payload: CapacityCompatibilityPayload,
    pub payload_sha256: String,
}

impl PreparedCapacityCompatibilityManifest {
    pub fn verify(&self) -> Result<()> {
        if self.payload_sha256 != hash_json(&self.payload)? {
            bail!("capacity compatibility manifest integrity mismatch");
        }
        let expected_components = BTreeSet::from([
            CapacityComponent::DamonTelemetry,
            CapacityComponent::DamosReclaim,
        ]);
        let expected_apply = vec![
            CapacityComponent::DamonTelemetry,
            CapacityComponent::DamosReclaim,
        ];
        let expected_capabilities = BTreeSet::from([
            crate::capacity_orchestration::CapacityCapability::DamonVaddr,
            crate::capacity_orchestration::CapacityCapability::DamonOwnedSession,
            crate::capacity_orchestration::CapacityCapability::DamosPageout,
            crate::capacity_orchestration::CapacityCapability::DamosAddressFence,
        ]);
        let expected_evidence = BTreeSet::from([
            CapacityEvidencePrerequisite::DamonMonitor,
            CapacityEvidencePrerequisite::DamosReclaim,
        ]);
        if self.payload.schema_version != PREPARED_CAPACITY_COMPATIBILITY_SCHEMA_VERSION
            || self.payload.execution_schema_version
                != CAPACITY_COMPATIBILITY_EXECUTION_SCHEMA_VERSION
            || self.payload.purpose != "combined_profile_compatibility_validation"
            || self.payload.components != expected_components
            || self.payload.component_contracts != component_contracts_for(&expected_components)
            || self
                .payload
                .ownership
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != expected_components
            || self.payload.capabilities != expected_capabilities
            || self.payload.individual_evidence != expected_evidence
            || self.payload.apply_order != expected_apply
            || self.payload.rollback_order
                != expected_apply.iter().rev().copied().collect::<Vec<_>>()
            || self.payload.automatic_retry
            || !self.payload.host_oom_prohibited
            || !self.payload.restore_failure_invalidates_result
            || self.payload.production_activation_authorized
            || self.payload.capacity_evaluation != EvaluationState::NotEvaluated
            || self.payload.effectiveness_evaluation != EvaluationState::NotEvaluated
            || self.payload.maximum_runtime_ms != CAPACITY_COMPATIBILITY_MAX_RUNTIME_MS
            || self.payload.ownership.values().any(|boundary| {
                !matches!(
                    boundary,
                    CapacityOwnershipBoundary::ExactOwned { resource_id }
                        if !resource_id.is_empty()
                )
            })
            || self
                .payload
                .excluded_components
                .get(&CapacityComponent::StorageTiering)
                .is_none_or(|reason| !reason.contains("ZswapNvmeBoot"))
        {
            bail!("capacity compatibility manifest is not the exact v1 validation contract");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeSensitiveCapabilityStatus {
    DeferredToPrivilegedPreflight,
    Verified,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityCompatibilityPreflight {
    pub schema_version: u32,
    pub manifest_verified: bool,
    pub current_runner_identity_verified: bool,
    pub validator_identity_verified: bool,
    pub material_environment_match: bool,
    pub contract_component_set_supported: bool,
    pub privileged_runtime_capability: PrivilegeSensitiveCapabilityStatus,
    pub exact_ownership_planned: bool,
    pub stale_resources_clear: bool,
    pub output_fresh: bool,
    pub user_preflight_passed: bool,
    pub current_identity_authorized: bool,
    pub requires_privileged_execution: bool,
    pub preflight_mutated: bool,
    pub execution_ready_except_authorization: bool,
    pub execution_ready: bool,
}

fn privileged_runtime_capability(
    damon: &damon::DamonCapability,
    damos: &damos::DamosCapability,
    privileged: bool,
) -> PrivilegeSensitiveCapabilityStatus {
    if !damon.supported
        || !damon.sysfs_admin_available
        || !damon.tracefs_available
        || !damon.aggregated_tracepoint_available
    {
        return PrivilegeSensitiveCapabilityStatus::Unsupported;
    }
    if !privileged && (!damon.readable || !damon.writable) {
        return PrivilegeSensitiveCapabilityStatus::DeferredToPrivilegedPreflight;
    }
    if damon.readable
        && damon.writable
        && damon.vaddr_supported
        && !damon.active_external_session
        && !damon.special_module_conflict
        && damos.supported
        && !damos.external_session_conflict
        && !damos.special_module_conflict
    {
        PrivilegeSensitiveCapabilityStatus::Verified
    } else {
        PrivilegeSensitiveCapabilityStatus::Unsupported
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityCompatibilityExecutionReport {
    pub schema_version: u32,
    pub validation_id: String,
    pub state: CapacityCompatibilityClassification,
    pub reason: String,
    pub evidence: CapacityCombinedCompatibilityEvidence,
    pub validator_exit_success: bool,
    pub structural_restore_passed: bool,
    pub cleanup_passed: bool,
    pub capacity_evaluation: EvaluationState,
    pub effectiveness_evaluation: EvaluationState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ComponentReportAssessment {
    source_commit_matches: bool,
    scope_matches: bool,
    errors_empty: bool,
    required_gates_passed: bool,
    cleanup_passed: bool,
    structural_restore_passed: bool,
    host_oom_observed: bool,
    damon_safety_passed: bool,
    exact_resource_identities_present: bool,
}

fn assess_damos_report(report: &Value, expected_commit: &str) -> ComponentReportAssessment {
    let checks = report
        .get("damos")
        .and_then(|damos| damos.get("checks"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let check_passed = |name: &str| {
        checks.iter().any(|check| {
            check.get("name").and_then(Value::as_str) == Some(name)
                && check.get("passed").and_then(Value::as_bool) == Some(true)
        })
    };
    ComponentReportAssessment {
        source_commit_matches: report.get("commit").and_then(Value::as_str)
            == Some(expected_commit),
        scope_matches: report.get("scope").and_then(Value::as_str) == Some("damos"),
        errors_empty: report
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty),
        required_gates_passed: report
            .get("damos")
            .and_then(|damos| damos.get("required_gates_passed"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        cleanup_passed: check_passed("cleanup") && check_passed("scheme_removed"),
        structural_restore_passed: report
            .get("host_unchanged")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        host_oom_observed: !check_passed("zero_oom"),
        damon_safety_passed: check_passed("kdamond_started") && check_passed("kdamond_stopped"),
        exact_resource_identities_present: report.get("damos").is_some_and(|damos| {
            damos
                .get("shadow_session_id")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
                && damos
                    .get("live_session_id")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
                && damos.get("target_pid").and_then(Value::as_u64).is_some()
                && damos
                    .get("target_start_ticks")
                    .and_then(Value::as_u64)
                    .is_some()
        }),
    }
}

pub fn prepare_capacity_compatibility(
    repository: &Path,
    config: &Path,
    validator_binary: &Path,
    prepared_root: &Path,
    output_root: &Path,
) -> Result<PathBuf> {
    let euid = nix::unistd::geteuid().as_raw();
    if euid == 0 {
        bail!("capacity compatibility preparation must run unprivileged");
    }
    if prepared_root.exists()
        || output_root.exists()
        || !prepared_root.is_absolute()
        || !output_root.is_absolute()
    {
        bail!("capacity compatibility paths must be fresh and absolute");
    }
    let repository = repository.canonicalize()?;
    if std::env::current_dir()?.canonicalize()? != repository {
        bail!("capacity compatibility preparation requires the explicit current repository");
    }
    let config_path = config.canonicalize()?;
    let validator_path = validator_binary.canonicalize()?;
    let runner_path = std::env::current_exe()?.canonicalize()?;
    let loaded = common::LoadedConfig::load(&config_path)?;
    let provenance = BuildProvenance::capture()?;
    if !provenance.clean_release_eligible() {
        bail!("capacity compatibility preparation requires clean release provenance");
    }
    let runner_binary = BinaryIdentity::capture(
        "nemor_benchmark",
        &runner_path,
        &provenance.source_state_id,
        &provenance.git_head,
    )?;
    let validator_identity = BinaryIdentity::capture(
        "nemor_privileged_validation",
        &validator_path,
        &provenance.source_state_id,
        &provenance.git_head,
    )?;
    if runner_binary.build_profile != "release"
        || validator_identity.build_profile != "release"
        || runner_binary.sha256 != provenance.binary_sha256
    {
        bail!("capacity compatibility binaries are not exact release identities");
    }
    let environment =
        EnvironmentFingerprint::capture_for_performance(&loaded.sha256, &provenance.git_head)?;
    let material_environment_hash = environment.material_hash()?;
    let validation_id = format!("capacity-compatibility-{}", now_ns()?);
    let components = BTreeSet::from([
        CapacityComponent::DamonTelemetry,
        CapacityComponent::DamosReclaim,
    ]);
    let ownership = BTreeMap::from([
        (
            CapacityComponent::DamonTelemetry,
            CapacityOwnershipBoundary::ExactOwned {
                resource_id: format!("{validation_id}-damon-session"),
            },
        ),
        (
            CapacityComponent::DamosReclaim,
            CapacityOwnershipBoundary::ExactOwned {
                resource_id: format!("{validation_id}-damos-target"),
            },
        ),
    ]);
    let capabilities = BTreeSet::from([
        crate::capacity_orchestration::CapacityCapability::DamonVaddr,
        crate::capacity_orchestration::CapacityCapability::DamonOwnedSession,
        crate::capacity_orchestration::CapacityCapability::DamosPageout,
        crate::capacity_orchestration::CapacityCapability::DamosAddressFence,
    ]);
    let individual_evidence = BTreeSet::from([
        CapacityEvidencePrerequisite::DamonMonitor,
        CapacityEvidencePrerequisite::DamosReclaim,
    ]);
    let apply_order = vec![
        CapacityComponent::DamonTelemetry,
        CapacityComponent::DamosReclaim,
    ];
    fs::create_dir(prepared_root)?;
    fs::set_permissions(prepared_root, fs::Permissions::from_mode(0o700))?;
    fs::create_dir(output_root)?;
    fs::set_permissions(output_root, fs::Permissions::from_mode(0o700))?;
    let report_path = output_root.join("capacity-compatibility.json");
    let raw_component_report_path = output_root.join("damos-component-report.json");
    let payload = CapacityCompatibilityPayload {
        schema_version: PREPARED_CAPACITY_COMPATIBILITY_SCHEMA_VERSION,
        execution_schema_version: CAPACITY_COMPATIBILITY_EXECUTION_SCHEMA_VERSION,
        validation_id,
        purpose: "combined_profile_compatibility_validation".into(),
        provenance,
        runner_binary,
        validator_binary: validator_identity,
        config_sha256: loaded.sha256,
        material_environment_hash,
        repository,
        config_path,
        runner_path,
        validator_path,
        prepared_root: prepared_root.to_path_buf(),
        output_root: output_root.to_path_buf(),
        report_path,
        raw_component_report_path,
        preparing_uid: euid,
        preparing_gid: nix::unistd::getegid().as_raw(),
        components: components.clone(),
        component_contracts: component_contracts_for(&components),
        ownership,
        capabilities,
        individual_evidence,
        apply_order: apply_order.clone(),
        rollback_order: apply_order.iter().rev().copied().collect(),
        excluded_components: BTreeMap::from([
            (
                CapacityComponent::CgroupProtection,
                "deferred: no combined DAMOS+cgroup owned-lifecycle evidence".into(),
            ),
            (
                CapacityComponent::CompressionZram,
                "deferred: no combined DAMOS+zram owned-lifecycle evidence".into(),
            ),
            (
                CapacityComponent::StorageTiering,
                "unavailable: ZswapNvmeBoot evidence prerequisite remains pending".into(),
            ),
            (
                CapacityComponent::KsmEligibility,
                "deferred: DAMOS/KSM distinct-target combined lifecycle not yet proven".into(),
            ),
        ]),
        maximum_runtime_ms: CAPACITY_COMPATIBILITY_MAX_RUNTIME_MS,
        automatic_retry: false,
        host_oom_prohibited: true,
        restore_failure_invalidates_result: true,
        production_activation_authorized: false,
        capacity_evaluation: EvaluationState::NotEvaluated,
        effectiveness_evaluation: EvaluationState::NotEvaluated,
    };
    let manifest = PreparedCapacityCompatibilityManifest {
        payload_sha256: hash_json(&payload)?,
        payload,
    };
    manifest.verify()?;
    let path = prepared_root.join(CAPACITY_COMPATIBILITY_MANIFEST_NAME);
    write_new_json(&path, &manifest, 0o600)?;
    Ok(path)
}

pub fn capacity_compatibility_preflight(
    manifest_path: &Path,
) -> Result<CapacityCompatibilityPreflight> {
    let manifest = read_manifest(manifest_path)?;
    let current_exe = std::env::current_exe()?.canonicalize()?;
    let current_runner_identity_verified = current_exe == manifest.payload.runner_path
        && hash_file(&current_exe)? == manifest.payload.runner_binary.sha256;
    let validator_identity_verified =
        hash_file(&manifest.payload.validator_path)? == manifest.payload.validator_binary.sha256;
    let loaded = common::LoadedConfig::load(&manifest.payload.config_path)?;
    let current_environment = EnvironmentFingerprint::capture_for_performance(
        &loaded.sha256,
        &manifest.payload.provenance.git_head,
    )?;
    let material_environment_match = loaded.sha256 == manifest.payload.config_sha256
        && current_environment.material_hash()? == manifest.payload.material_environment_hash;
    let damon = damon::inspect_linux(Path::new("/"), None);
    let damos = damos::observe_capability(&damon);
    let stale_resources_clear =
        !Path::new(HARNESS_REPORT).exists() && !Path::new(HARNESS_STATE).exists();
    let output_fresh = fs::read_dir(&manifest.payload.output_root)?
        .next()
        .is_none();
    let root = nix::unistd::geteuid().is_root();
    let sudo_identity = std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .zip(
            std::env::var("SUDO_GID")
                .ok()
                .and_then(|value| value.parse::<u32>().ok()),
        );
    let current_identity_authorized = root
        && sudo_identity
            == Some((
                manifest.payload.preparing_uid,
                manifest.payload.preparing_gid,
            ));
    let contract_component_set_supported = manifest.payload.components
        == BTreeSet::from([
            CapacityComponent::DamonTelemetry,
            CapacityComponent::DamosReclaim,
        ]);
    let privileged_runtime_capability = privileged_runtime_capability(&damon, &damos, root);
    let user_observable_gates_passed = current_runner_identity_verified
        && validator_identity_verified
        && material_environment_match
        && contract_component_set_supported
        && stale_resources_clear
        && output_fresh;
    let user_preflight_passed = user_observable_gates_passed
        && privileged_runtime_capability != PrivilegeSensitiveCapabilityStatus::Unsupported;
    let execution_ready_except_authorization = user_observable_gates_passed
        && privileged_runtime_capability == PrivilegeSensitiveCapabilityStatus::Verified;
    Ok(CapacityCompatibilityPreflight {
        schema_version: CAPACITY_COMPATIBILITY_PREFLIGHT_SCHEMA_VERSION,
        manifest_verified: true,
        current_runner_identity_verified,
        validator_identity_verified,
        material_environment_match,
        contract_component_set_supported,
        privileged_runtime_capability,
        exact_ownership_planned: true,
        stale_resources_clear,
        output_fresh,
        user_preflight_passed,
        current_identity_authorized,
        requires_privileged_execution: true,
        preflight_mutated: false,
        execution_ready_except_authorization,
        execution_ready: execution_ready_except_authorization && current_identity_authorized,
    })
}

pub fn validate_capacity_compatibility(
    manifest_path: &Path,
) -> Result<CapacityCompatibilityExecutionReport> {
    let manifest = read_manifest(manifest_path)?;
    let preflight = capacity_compatibility_preflight(manifest_path)?;
    if !preflight.execution_ready {
        bail!("capacity compatibility privileged execution preflight failed");
    }
    let started = Instant::now();
    let status = Command::new(&manifest.payload.validator_path)
        .arg("--damos")
        .current_dir(&manifest.payload.repository)
        .status()
        .context("launch exact capacity compatibility validator")?;
    let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let raw = fs::read(HARNESS_REPORT).context("read bounded DAMOS validation report")?;
    let report: Value = serde_json::from_slice(&raw)?;
    let damos = report.get("damos").context("DAMOS evidence missing")?;
    let assessment = assess_damos_report(&report, &manifest.payload.provenance.git_head);
    let bounded_execution_passed = status.success()
        && elapsed <= CAPACITY_COMPATIBILITY_MAX_RUNTIME_MS.saturating_mul(1_000_000);
    let pass = bounded_execution_passed
        && assessment.source_commit_matches
        && assessment.scope_matches
        && assessment.errors_empty
        && assessment.required_gates_passed
        && assessment.cleanup_passed
        && assessment.structural_restore_passed
        && assessment.exact_resource_identities_present
        && !assessment.host_oom_observed;
    let classification = if pass {
        CapacityCompatibilityClassification::Pass
    } else {
        CapacityCompatibilityClassification::Fail
    };
    let mut raw_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&manifest.payload.raw_component_report_path)?;
    raw_file.write_all(&raw)?;
    raw_file.sync_all()?;
    fs::set_permissions(
        &manifest.payload.raw_component_report_path,
        fs::Permissions::from_mode(0o600),
    )?;
    let evidence =
        CapacityCombinedCompatibilityEvidence::seal(CapacityCombinedCompatibilityPayload {
            evidence_version: CAPACITY_COMBINED_COMPATIBILITY_EVIDENCE_VERSION,
            validation_id: manifest.payload.validation_id.clone(),
            source_commit: manifest.payload.provenance.git_head.clone(),
            source_state_id: manifest.payload.provenance.source_state_id.clone(),
            benchmark_binary_sha256: manifest.payload.runner_binary.sha256.clone(),
            config_sha256: manifest.payload.config_sha256.clone(),
            material_environment_hash: manifest.payload.material_environment_hash.clone(),
            components: manifest.payload.components.clone(),
            component_contracts: manifest.payload.component_contracts.clone(),
            ownership: manifest.payload.ownership.clone(),
            validated_resource_identities: BTreeMap::from([
                (
                    "damon_shadow_session".into(),
                    damos
                        .get("shadow_session_id")
                        .and_then(Value::as_str)
                        .unwrap_or("missing")
                        .into(),
                ),
                (
                    "damon_live_session".into(),
                    damos
                        .get("live_session_id")
                        .and_then(Value::as_str)
                        .unwrap_or("missing")
                        .into(),
                ),
                (
                    "damos_target".into(),
                    format!(
                        "pid:{}:start_ticks:{}",
                        damos.get("target_pid").and_then(Value::as_u64).unwrap_or(0),
                        damos
                            .get("target_start_ticks")
                            .and_then(Value::as_u64)
                            .unwrap_or(0)
                    ),
                ),
            ]),
            capabilities: manifest.payload.capabilities.clone(),
            individual_evidence: manifest.payload.individual_evidence.clone(),
            apply_order: manifest.payload.apply_order.clone(),
            rollback_order: manifest.payload.rollback_order.clone(),
            incompatibility_assumptions: vec![
                "StorageTiering excluded until ZswapNvmeBoot validation".into(),
                "KSM excluded until distinct-target combined validation".into(),
            ],
            started_monotonic_ns: 0,
            ended_monotonic_ns: elapsed,
            bounded_execution_passed,
            cleanup_passed: assessment.cleanup_passed,
            restore_passed: assessment.structural_restore_passed,
            host_oom_observed: assessment.host_oom_observed,
            component_safety_passed: BTreeMap::from([
                (
                    CapacityComponent::DamonTelemetry,
                    assessment.damon_safety_passed,
                ),
                (
                    CapacityComponent::DamosReclaim,
                    assessment.required_gates_passed,
                ),
            ]),
            classification,
        })?;
    let result = CapacityCompatibilityExecutionReport {
        schema_version: CAPACITY_COMPATIBILITY_EXECUTION_SCHEMA_VERSION,
        validation_id: manifest.payload.validation_id.clone(),
        state: classification,
        reason: if pass {
            "exact DAMON telemetry + DAMOS reclaim compatibility validation passed".into()
        } else {
            "bounded exact-owned compatibility validation failed; inspect component evidence".into()
        },
        evidence,
        validator_exit_success: status.success(),
        structural_restore_passed: assessment.structural_restore_passed,
        cleanup_passed: assessment.cleanup_passed,
        capacity_evaluation: EvaluationState::NotEvaluated,
        effectiveness_evaluation: EvaluationState::NotEvaluated,
    };
    write_new_json(&manifest.payload.report_path, &result, 0o600)?;
    if !pass {
        bail!("capacity compatibility validation failed; evidence preserved");
    }
    Ok(result)
}

fn read_manifest(path: &Path) -> Result<PreparedCapacityCompatibilityManifest> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        bail!("capacity compatibility manifest must be one regular link");
    }
    let manifest: PreparedCapacityCompatibilityManifest = serde_json::from_slice(&fs::read(path)?)?;
    manifest.verify()?;
    Ok(manifest)
}

fn hash_json<T: Serialize>(value: &T) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn hash_file(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

fn write_new_json<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn now_ns() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn damon_capability() -> damon::DamonCapability {
        damon::DamonCapability {
            supported: true,
            sysfs_admin_available: true,
            tracefs_available: true,
            aggregated_tracepoint_available: true,
            available_operations: vec!["vaddr".into()],
            vaddr_supported: true,
            fvaddr_supported: false,
            paddr_supported: false,
            existing_kdamond_count: Some(0),
            existing_kdamond_pids: Vec::new(),
            active_external_session: false,
            special_module_conflict: false,
            optional_features: BTreeMap::new(),
            readable: true,
            writable: true,
            kernel: None,
            notes: Vec::new(),
            dry_run: true,
        }
    }

    fn damos_capability() -> damos::DamosCapability {
        damos::DamosCapability {
            supported: true,
            vaddr: Some(true),
            ..damos::DamosCapability::default()
        }
    }

    fn report(check_overrides: &[(&str, bool)]) -> Value {
        let mut checks = BTreeMap::from([
            ("cleanup", true),
            ("scheme_removed", true),
            ("zero_oom", true),
            ("kdamond_started", true),
            ("kdamond_stopped", true),
        ]);
        for (name, passed) in check_overrides {
            checks.insert(*name, *passed);
        }
        json!({
            "commit": "commit",
            "scope": "damos",
            "host_unchanged": true,
            "errors": [],
            "damos": {
                "required_gates_passed": true,
                "shadow_session_id": "nemor-validation-damos-shadow-fixture",
                "live_session_id": "nemor-validation-damos-live-fixture",
                "target_pid": 123,
                "target_start_ticks": 456,
                "checks": checks.into_iter().map(|(name, passed)| {
                    json!({"name": name, "passed": passed, "detail": "bounded fixture"})
                }).collect::<Vec<_>>()
            }
        })
    }

    #[test]
    fn component_report_requires_exact_source_scope_and_all_safety_gates() {
        let assessment = assess_damos_report(&report(&[]), "commit");
        assert_eq!(
            assessment,
            ComponentReportAssessment {
                source_commit_matches: true,
                scope_matches: true,
                errors_empty: true,
                required_gates_passed: true,
                cleanup_passed: true,
                structural_restore_passed: true,
                host_oom_observed: false,
                damon_safety_passed: true,
                exact_resource_identities_present: true,
            }
        );
    }

    #[test]
    fn host_oom_is_distinct_and_fail_closed() {
        let assessment = assess_damos_report(&report(&[("zero_oom", false)]), "commit");
        assert!(assessment.host_oom_observed);
        assert!(assessment.cleanup_passed);
    }

    #[test]
    fn partial_apply_cleanup_failure_is_preserved() {
        let assessment = assess_damos_report(&report(&[("scheme_removed", false)]), "commit");
        assert!(!assessment.cleanup_passed);
        assert!(!assessment.host_oom_observed);
    }

    #[test]
    fn damon_dependency_start_stop_is_individually_required() {
        for gate in ["kdamond_started", "kdamond_stopped"] {
            let assessment = assess_damos_report(&report(&[(gate, false)]), "commit");
            assert!(!assessment.damon_safety_passed);
        }
    }

    #[test]
    fn foreign_source_report_is_rejected_without_reinterpretation() {
        let assessment = assess_damos_report(&report(&[]), "other");
        assert!(!assessment.source_commit_matches);
        assert!(assessment.required_gates_passed);
    }

    #[test]
    fn compatibility_harness_never_changes_evaluation_states() {
        assert_eq!(EvaluationState::NotEvaluated, EvaluationState::NotEvaluated);
        assert_eq!(CAPACITY_COMPATIBILITY_MAX_RUNTIME_MS, 180_000);
    }

    #[test]
    fn unprivileged_unreadable_admin_is_deferred_not_unsupported() {
        let mut damon = damon_capability();
        damon.readable = false;
        damon.writable = false;
        assert_eq!(
            privileged_runtime_capability(&damon, &damos_capability(), false),
            PrivilegeSensitiveCapabilityStatus::DeferredToPrivilegedPreflight
        );
    }

    #[test]
    fn observably_absent_admin_is_unsupported_not_deferred() {
        let mut damon = damon_capability();
        damon.supported = false;
        damon.sysfs_admin_available = false;
        damon.readable = false;
        damon.writable = false;
        assert_eq!(
            privileged_runtime_capability(&damon, &damos_capability(), false),
            PrivilegeSensitiveCapabilityStatus::Unsupported
        );
    }

    #[test]
    fn privileged_complete_capability_is_verified() {
        assert_eq!(
            privileged_runtime_capability(&damon_capability(), &damos_capability(), true),
            PrivilegeSensitiveCapabilityStatus::Verified
        );
    }

    #[test]
    fn privileged_missing_vaddr_or_tracepoint_is_unsupported() {
        let mut damon = damon_capability();
        damon.vaddr_supported = false;
        assert_eq!(
            privileged_runtime_capability(&damon, &damos_capability(), true),
            PrivilegeSensitiveCapabilityStatus::Unsupported
        );
        damon.vaddr_supported = true;
        damon.aggregated_tracepoint_available = false;
        assert_eq!(
            privileged_runtime_capability(&damon, &damos_capability(), true),
            PrivilegeSensitiveCapabilityStatus::Unsupported
        );
    }

    #[test]
    fn privileged_external_session_or_module_conflict_is_unsupported() {
        let mut damon = damon_capability();
        damon.active_external_session = true;
        assert_eq!(
            privileged_runtime_capability(&damon, &damos_capability(), true),
            PrivilegeSensitiveCapabilityStatus::Unsupported
        );
        damon.active_external_session = false;
        damon.special_module_conflict = true;
        assert_eq!(
            privileged_runtime_capability(&damon, &damos_capability(), true),
            PrivilegeSensitiveCapabilityStatus::Unsupported
        );
    }

    #[test]
    fn deferred_status_cannot_authorize_execution() {
        let status = PrivilegeSensitiveCapabilityStatus::DeferredToPrivilegedPreflight;
        assert_ne!(status, PrivilegeSensitiveCapabilityStatus::Verified);
        assert!(!matches!(
            status,
            PrivilegeSensitiveCapabilityStatus::Verified
        ));
    }

    #[test]
    fn preflight_v2_round_trips_and_old_boolean_shape_is_not_reinterpreted() {
        let report = CapacityCompatibilityPreflight {
            schema_version: CAPACITY_COMPATIBILITY_PREFLIGHT_SCHEMA_VERSION,
            manifest_verified: true,
            current_runner_identity_verified: true,
            validator_identity_verified: true,
            material_environment_match: true,
            contract_component_set_supported: true,
            privileged_runtime_capability:
                PrivilegeSensitiveCapabilityStatus::DeferredToPrivilegedPreflight,
            exact_ownership_planned: true,
            stale_resources_clear: true,
            output_fresh: true,
            user_preflight_passed: true,
            current_identity_authorized: false,
            requires_privileged_execution: true,
            preflight_mutated: false,
            execution_ready_except_authorization: false,
            execution_ready: false,
        };
        let encoded = serde_json::to_vec(&report).unwrap();
        assert_eq!(
            serde_json::from_slice::<CapacityCompatibilityPreflight>(&encoded).unwrap(),
            report
        );
        assert!(
            serde_json::from_value::<CapacityCompatibilityPreflight>(json!({
                "manifest_verified": true,
                "component_set_supported": false,
                "execution_ready": false
            }))
            .is_err()
        );
    }
}
