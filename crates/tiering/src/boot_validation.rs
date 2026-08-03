use crate::{StorageProfile, TIERING_RULE_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

pub const BOOT_VALIDATION_CONTRACT_VERSION: &str = "tiering-boot-validation-v1";
const ENTRY_ROOT: &str = "/boot/loader/entries";
const UKI_ROOT: &str = "/boot/EFI/Linux";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootValidationStage {
    Prepared,
    UserPreflight,
    RootPreflight,
    Applied,
    Verified,
    OneShotSelected,
    ExperimentalBootValidated,
    BaselineRollbackSelected,
    BaselineRestored,
    Recovered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootValidationCommand {
    Prepare,
    UserPreflight,
    RootPreflight,
    Apply,
    VerifyApplied,
    SelectOneShot,
    PostBootValidate,
    SelectBaselineRollback,
    VerifyFinalRestore,
    Recover,
    VerifyIdempotence,
}

impl BootValidationCommand {
    #[must_use]
    pub fn mutating(self) -> bool {
        matches!(
            self,
            Self::Apply
                | Self::SelectOneShot
                | Self::SelectBaselineRollback
                | Self::VerifyFinalRestore
                | Self::Recover
        )
    }

    #[must_use]
    pub fn requires_authenticated_root(self) -> bool {
        matches!(
            self,
            Self::RootPreflight
                | Self::VerifyApplied
                | Self::PostBootValidate
                | Self::VerifyIdempotence
        ) || self.mutating()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootArtifact {
    pub path: PathBuf,
    pub content: String,
    pub sha256: String,
    pub mode: u32,
    pub owner_uid: u32,
    pub owner_gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TieringBootValidationManifest {
    pub contract_version: String,
    pub rule_version: String,
    pub validation_id: String,
    pub source_commit: String,
    pub source_state: String,
    pub binary_identities: BTreeMap<String, String>,
    pub config_sha256: String,
    pub environment_identity: String,
    pub storage_profile: StorageProfile,
    pub physical_device_identity: String,
    pub filesystem_identity: String,
    pub swapfile_path: PathBuf,
    pub swapfile_size: u64,
    pub swap_priority: i32,
    pub protected_zram_active: bool,
    pub protected_zram_priority: Option<i32>,
    pub baseline_zswap_enabled: bool,
    pub experimental_zswap_parameters: BTreeMap<String, String>,
    pub bootloader: String,
    pub current_entry: String,
    pub default_entry: String,
    pub boot_order: Vec<String>,
    pub esp_identity: String,
    pub kernel_identity: String,
    pub initrd_or_uki_identities: BTreeMap<String, String>,
    pub current_command_line: String,
    pub experimental_command_line: String,
    pub experimental_entry: String,
    pub owned_artifacts: Vec<BootArtifact>,
    pub one_shot_method: String,
    pub rollback_entry: String,
    pub maximum_write_bytes: u64,
    pub timeout_seconds: u64,
    pub recovery_plan: Vec<String>,
    pub production_activation: bool,
}

impl TieringBootValidationManifest {
    pub fn validate(&self) -> Result<(), BootValidationError> {
        if self.contract_version != BOOT_VALIDATION_CONTRACT_VERSION
            || self.rule_version != TIERING_RULE_VERSION
        {
            return Err(BootValidationError::ContractMismatch);
        }
        if !self.storage_profile.boot_supported() {
            return Err(BootValidationError::UnsupportedProfile);
        }
        if self.bootloader != "systemd-boot/kernel-install-uki"
            || self.current_entry.is_empty()
            || self.default_entry.is_empty()
            || self.rollback_entry != self.current_entry
            || self.experimental_entry == self.current_entry
            || self.experimental_entry == self.default_entry
            || self.one_shot_method != "bootctl-set-oneshot"
        {
            return Err(BootValidationError::UnsafeBootIdentity);
        }
        if self.production_activation || !self.protected_zram_active {
            return Err(BootValidationError::ProductionOrFallbackUnsafe);
        }
        if !self.experimental_command_line.contains("zswap.enabled=1")
            || self.experimental_command_line == self.current_command_line
        {
            return Err(BootValidationError::InvalidExperimentalCommandLine);
        }
        if self.owned_artifacts.is_empty() {
            return Err(BootValidationError::NoOwnedArtifacts);
        }
        for artifact in &self.owned_artifacts {
            validate_owned_path(&artifact.path, &self.validation_id)?;
            if artifact.sha256 != sha256_bytes(artifact.content.as_bytes())
                || artifact.owner_uid != 0
                || artifact.owner_gid != 0
                || !matches!(artifact.mode, 0o600 | 0o644)
            {
                return Err(BootValidationError::InvalidArtifactIdentity);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TieringBootValidationPreflight {
    pub stage: BootValidationStage,
    pub manifest_sha256: String,
    pub non_mutating: bool,
    pub manifest_valid: bool,
    pub source_matches: bool,
    pub storage_matches: bool,
    pub bootloader_matches: bool,
    pub baseline_entries_preserved: bool,
    pub boot_order_unchanged: bool,
    pub artifact_paths_absent: bool,
    pub symlinks_absent: bool,
    pub package_update_absent: bool,
    pub secure_boot_compatible: bool,
    pub ready: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TieringBootApplyEvidence {
    pub stage: BootValidationStage,
    pub manifest_sha256: String,
    pub created: Vec<BootArtifact>,
    pub readback_verified: bool,
    pub directories_synced: bool,
    pub permanent_default_unchanged: bool,
    pub boot_order_unchanged: bool,
    pub one_shot_selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TieringPostBootEvidence {
    pub stage: BootValidationStage,
    pub profile: StorageProfile,
    pub booted_entry: String,
    pub kernel_matches: bool,
    pub command_line_matches: bool,
    pub zswap_readback_matches: bool,
    pub swapfile_identity_matches: bool,
    pub swap_priority_matches: bool,
    pub zram_policy_matches: bool,
    pub storage_identity_matches: bool,
    pub counters_available: bool,
    pub backing_write_bytes: Option<u64>,
    pub latency_ns: Option<u64>,
    pub throughput_bytes_per_second: Option<u64>,
    pub compression_ratio_milli: Option<u64>,
    pub refault_passed: bool,
    pub write_budget_passed: bool,
    pub host_oom: bool,
    pub oom_kill: bool,
    pub daemon_observe_only: bool,
    pub production_activation: bool,
    pub valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TieringRollbackEvidence {
    pub stage: BootValidationStage,
    pub rollback_entry: String,
    pub permanent_default_unchanged: bool,
    pub boot_order_unchanged: bool,
    pub experimental_artifacts_preserved_until_baseline: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TieringFinalRestoreEvidence {
    pub stage: BootValidationStage,
    pub baseline_entry_booted: bool,
    pub baseline_zswap_restored: bool,
    pub baseline_zram_restored: bool,
    pub temporary_swapfile_absent: bool,
    pub exact_owned_artifacts_absent: bool,
    pub permanent_default_unchanged: bool,
    pub boot_order_unchanged: bool,
    pub idempotent: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootValidationError {
    #[error("boot validation contract version mismatch")]
    ContractMismatch,
    #[error("storage profile is not authorized")]
    UnsupportedProfile,
    #[error("unsafe or ambiguous boot identity")]
    UnsafeBootIdentity,
    #[error("production activation or zram fallback contract is unsafe")]
    ProductionOrFallbackUnsafe,
    #[error("experimental command line is invalid")]
    InvalidExperimentalCommandLine,
    #[error("manifest has no owned artifacts")]
    NoOwnedArtifacts,
    #[error("artifact path is outside the exact validation namespace")]
    PathOutsideNamespace,
    #[error("artifact identity is invalid")]
    InvalidArtifactIdentity,
    #[error("preflight did not authorize this exact stage")]
    PreflightRejected,
    #[error("backend state changed or failed readback")]
    ReadbackMismatch,
    #[error("post-boot evidence is incomplete or unsafe")]
    PostBootRejected,
}

pub trait BootValidationBackend {
    fn source_matches(&self, manifest: &TieringBootValidationManifest) -> bool;
    fn storage_matches(&self, manifest: &TieringBootValidationManifest) -> bool;
    fn bootloader_matches(&self, manifest: &TieringBootValidationManifest) -> bool;
    fn entries_preserved(&self, manifest: &TieringBootValidationManifest) -> bool;
    fn boot_order_matches(&self, manifest: &TieringBootValidationManifest) -> bool;
    fn artifact_absent_and_safe(&self, artifact: &BootArtifact) -> bool;
    fn package_update_absent(&self) -> bool;
    fn secure_boot_compatible(&self) -> bool;
    fn create_new_artifact(&mut self, artifact: &BootArtifact) -> bool;
    fn artifact_matches(&self, artifact: &BootArtifact) -> bool;
    fn sync_artifact_parents(&mut self) -> bool;
    fn set_one_shot(&mut self, entry: &str) -> bool;
    fn booted_entry(&self) -> Option<String>;
    fn remove_exact_artifact(&mut self, artifact: &BootArtifact) -> bool;
    fn temporary_swapfile_absent(&self, manifest: &TieringBootValidationManifest) -> bool;
    fn baseline_zswap_restored(&self, manifest: &TieringBootValidationManifest) -> bool;
    fn baseline_zram_restored(&self, manifest: &TieringBootValidationManifest) -> bool;
}

pub fn user_preflight<B: BootValidationBackend>(
    manifest: &TieringBootValidationManifest,
    backend: &B,
) -> TieringBootValidationPreflight {
    preflight(manifest, backend, BootValidationStage::UserPreflight)
}

pub fn root_preflight<B: BootValidationBackend>(
    manifest: &TieringBootValidationManifest,
    backend: &B,
) -> TieringBootValidationPreflight {
    preflight(manifest, backend, BootValidationStage::RootPreflight)
}

fn preflight<B: BootValidationBackend>(
    manifest: &TieringBootValidationManifest,
    backend: &B,
    stage: BootValidationStage,
) -> TieringBootValidationPreflight {
    let manifest_valid = manifest.validate().is_ok();
    let source_matches = backend.source_matches(manifest);
    let storage_matches = backend.storage_matches(manifest);
    let bootloader_matches = backend.bootloader_matches(manifest);
    let baseline_entries_preserved = backend.entries_preserved(manifest);
    let boot_order_unchanged = backend.boot_order_matches(manifest);
    let artifact_paths_absent = manifest
        .owned_artifacts
        .iter()
        .all(|artifact| backend.artifact_absent_and_safe(artifact));
    let package_update_absent = backend.package_update_absent();
    let secure_boot_compatible = backend.secure_boot_compatible();
    let mut blockers = Vec::new();
    for (passed, reason) in [
        (manifest_valid, "manifest_invalid"),
        (source_matches, "source_mismatch"),
        (storage_matches, "storage_mismatch"),
        (bootloader_matches, "bootloader_mismatch"),
        (baseline_entries_preserved, "baseline_entry_missing"),
        (boot_order_unchanged, "boot_order_changed"),
        (artifact_paths_absent, "artifact_path_not_create_new_safe"),
        (package_update_absent, "package_update_active"),
        (secure_boot_compatible, "secure_boot_incompatible"),
    ] {
        if !passed {
            blockers.push(reason.to_owned());
        }
    }
    TieringBootValidationPreflight {
        stage,
        manifest_sha256: manifest_hash(manifest),
        non_mutating: true,
        manifest_valid,
        source_matches,
        storage_matches,
        bootloader_matches,
        baseline_entries_preserved,
        boot_order_unchanged,
        artifact_paths_absent,
        symlinks_absent: artifact_paths_absent,
        package_update_absent,
        secure_boot_compatible,
        ready: blockers.is_empty(),
        blockers,
    }
}

pub fn apply_boot_validation<B: BootValidationBackend>(
    manifest: &TieringBootValidationManifest,
    preflight: &TieringBootValidationPreflight,
    backend: &mut B,
) -> Result<TieringBootApplyEvidence, BootValidationError> {
    require_preflight(manifest, preflight, BootValidationStage::RootPreflight)?;
    let mut created = Vec::new();
    for artifact in &manifest.owned_artifacts {
        if !backend.create_new_artifact(artifact) {
            return Err(BootValidationError::ReadbackMismatch);
        }
        created.push(artifact.clone());
    }
    let synced = backend.sync_artifact_parents();
    let readback = created.iter().all(|item| backend.artifact_matches(item));
    let preserved = backend.entries_preserved(manifest);
    let order = backend.boot_order_matches(manifest);
    if !(synced && readback && preserved && order) {
        return Err(BootValidationError::ReadbackMismatch);
    }
    Ok(TieringBootApplyEvidence {
        stage: BootValidationStage::Applied,
        manifest_sha256: manifest_hash(manifest),
        created,
        readback_verified: true,
        directories_synced: true,
        permanent_default_unchanged: true,
        boot_order_unchanged: true,
        one_shot_selected: false,
    })
}

pub fn verify_applied<B: BootValidationBackend>(
    manifest: &TieringBootValidationManifest,
    evidence: &TieringBootApplyEvidence,
    backend: &B,
) -> Result<(), BootValidationError> {
    if evidence.manifest_sha256 != manifest_hash(manifest)
        || evidence.stage != BootValidationStage::Applied
        || !evidence
            .created
            .iter()
            .all(|item| backend.artifact_matches(item))
        || !backend.entries_preserved(manifest)
        || !backend.boot_order_matches(manifest)
    {
        return Err(BootValidationError::ReadbackMismatch);
    }
    Ok(())
}

pub fn select_one_shot<B: BootValidationBackend>(
    manifest: &TieringBootValidationManifest,
    evidence: &mut TieringBootApplyEvidence,
    backend: &mut B,
) -> Result<(), BootValidationError> {
    verify_applied(manifest, evidence, backend)?;
    if !backend.set_one_shot(&manifest.experimental_entry)
        || !backend.entries_preserved(manifest)
        || !backend.boot_order_matches(manifest)
    {
        return Err(BootValidationError::ReadbackMismatch);
    }
    evidence.stage = BootValidationStage::OneShotSelected;
    evidence.one_shot_selected = true;
    Ok(())
}

pub fn post_boot_validate(
    manifest: &TieringBootValidationManifest,
    mut evidence: TieringPostBootEvidence,
) -> Result<TieringPostBootEvidence, BootValidationError> {
    let valid = evidence.profile == manifest.storage_profile
        && evidence.booted_entry == manifest.experimental_entry
        && evidence.kernel_matches
        && evidence.command_line_matches
        && evidence.zswap_readback_matches
        && evidence.swapfile_identity_matches
        && evidence.swap_priority_matches
        && evidence.zram_policy_matches
        && evidence.storage_identity_matches
        && evidence.counters_available
        && evidence.backing_write_bytes.is_some()
        && evidence.latency_ns.is_some()
        && evidence.throughput_bytes_per_second.is_some()
        && evidence.compression_ratio_milli.is_some()
        && evidence.refault_passed
        && evidence.write_budget_passed
        && !evidence.host_oom
        && !evidence.oom_kill
        && evidence.daemon_observe_only
        && !evidence.production_activation;
    if !valid {
        return Err(BootValidationError::PostBootRejected);
    }
    evidence.stage = BootValidationStage::ExperimentalBootValidated;
    evidence.valid = true;
    Ok(evidence)
}

pub fn prepare_baseline_rollback<B: BootValidationBackend>(
    manifest: &TieringBootValidationManifest,
    backend: &mut B,
) -> Result<TieringRollbackEvidence, BootValidationError> {
    if !backend.entries_preserved(manifest)
        || !backend.boot_order_matches(manifest)
        || !backend.set_one_shot(&manifest.rollback_entry)
    {
        return Err(BootValidationError::ReadbackMismatch);
    }
    Ok(TieringRollbackEvidence {
        stage: BootValidationStage::BaselineRollbackSelected,
        rollback_entry: manifest.rollback_entry.clone(),
        permanent_default_unchanged: true,
        boot_order_unchanged: true,
        experimental_artifacts_preserved_until_baseline: true,
    })
}

pub fn verify_final_restore<B: BootValidationBackend>(
    manifest: &TieringBootValidationManifest,
    backend: &mut B,
) -> Result<TieringFinalRestoreEvidence, BootValidationError> {
    let baseline_entry_booted = backend.booted_entry().as_deref() == Some(&manifest.rollback_entry);
    if !baseline_entry_booted {
        return Err(BootValidationError::ReadbackMismatch);
    }
    for artifact in &manifest.owned_artifacts {
        if backend.artifact_matches(artifact) && !backend.remove_exact_artifact(artifact) {
            return Err(BootValidationError::ReadbackMismatch);
        }
    }
    let result = TieringFinalRestoreEvidence {
        stage: BootValidationStage::BaselineRestored,
        baseline_entry_booted,
        baseline_zswap_restored: backend.baseline_zswap_restored(manifest),
        baseline_zram_restored: backend.baseline_zram_restored(manifest),
        temporary_swapfile_absent: backend.temporary_swapfile_absent(manifest),
        exact_owned_artifacts_absent: manifest
            .owned_artifacts
            .iter()
            .all(|item| !backend.artifact_matches(item)),
        permanent_default_unchanged: backend.entries_preserved(manifest),
        boot_order_unchanged: backend.boot_order_matches(manifest),
        idempotent: false,
    };
    if !(result.baseline_zswap_restored
        && result.baseline_zram_restored
        && result.temporary_swapfile_absent
        && result.exact_owned_artifacts_absent
        && result.permanent_default_unchanged
        && result.boot_order_unchanged)
    {
        return Err(BootValidationError::ReadbackMismatch);
    }
    Ok(result)
}

pub fn recover_boot_validation<B: BootValidationBackend>(
    manifest: &TieringBootValidationManifest,
    backend: &mut B,
) -> Result<TieringFinalRestoreEvidence, BootValidationError> {
    let mut result = verify_final_restore(manifest, backend)?;
    result.stage = BootValidationStage::Recovered;
    result.idempotent = true;
    Ok(result)
}

fn require_preflight(
    manifest: &TieringBootValidationManifest,
    preflight: &TieringBootValidationPreflight,
    stage: BootValidationStage,
) -> Result<(), BootValidationError> {
    if preflight.stage != stage
        || !preflight.ready
        || !preflight.non_mutating
        || preflight.manifest_sha256 != manifest_hash(manifest)
    {
        return Err(BootValidationError::PreflightRejected);
    }
    Ok(())
}

fn validate_owned_path(path: &Path, validation_id: &str) -> Result<(), BootValidationError> {
    if validation_id.is_empty()
        || !validation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        || path.starts_with("/usr/lib")
    {
        return Err(BootValidationError::PathOutsideNamespace);
    }
    let allowed = path
        == Path::new(ENTRY_ROOT).join(format!("nemor-validation-{validation_id}.conf"))
        || path == Path::new(UKI_ROOT).join(format!("nemor-validation-{validation_id}.efi"));
    if !allowed {
        return Err(BootValidationError::PathOutsideNamespace);
    }
    Ok(())
}

fn manifest_hash(manifest: &TieringBootValidationManifest) -> String {
    let bytes = serde_json::to_vec(manifest).expect("serializable manifest");
    hex::encode(Sha256::digest(bytes))
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
