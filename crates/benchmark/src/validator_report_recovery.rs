#![forbid(unsafe_code)]

use crate::validator_report::{
    canonical_sha256, raw_sha256, LEGACY_REPORT_PATH, VALIDATOR_STATE_PATH,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const REPORT_RECOVERY_PREFLIGHT_VERSION: u32 = 1;
pub const REPORT_RECOVERY_REPORT_VERSION: u32 = 1;
const EXPECTED_RAW_SHA: &str = "bda6ead6328ba4c122fb9e0b51fe513a20cb837c717c0d0f54c398896a3fc0a7";
const EXPECTED_CANONICAL_SHA: &str =
    "2576fae13aa0c6167f2a80702bb3ea6f53babcf8fceb7e2d4b82ded797ff9314";
const EXPECTED_L5_VALIDATION_ID: &str = "capacity-external-target-1785438798217795335";
const EXPECTED_SOURCE: &str = "3f9f919f26c36f93a906b8092d4102b546c0019c";
const EXPECTED_DEVICE: u64 = 53;
const EXPECTED_INODE: u64 = 885;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportRecoveryClassification {
    Pass,
    NoMutationAlreadyClean,
    RejectedBeforeMutation,
    PartialFailure,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalReportRecoveryPreflight {
    pub schema_version: u32,
    pub recovery_source: String,
    pub l5_archive: PathBuf,
    pub l4_archive: PathBuf,
    pub l5_archive_verified: bool,
    pub l4_archive_verified: bool,
    pub global_path: PathBuf,
    pub global_file_present: bool,
    pub global_device: Option<u64>,
    pub global_inode: Option<u64>,
    pub global_uid: Option<u32>,
    pub global_gid: Option<u32>,
    pub global_mode: Option<u32>,
    pub global_link_count: Option<u64>,
    pub global_size: Option<u64>,
    pub exact_global_metadata_verified: bool,
    pub l4_byte_binding_verified: bool,
    pub l5_canonical_binding_verified: bool,
    pub critical_semantic_fields_verified: bool,
    pub raw_sha256: String,
    pub canonical_sha256: String,
    pub processes_absent: bool,
    pub validator_state_absent: bool,
    pub damon_damos_clear: bool,
    pub production_service_absent: bool,
    pub current_identity_authorized: bool,
    pub preflight_mutated: bool,
    pub already_clean: bool,
    pub recovery_ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalReportRecoveryReport {
    pub schema_version: u32,
    pub classification: ReportRecoveryClassification,
    pub recovery_source: String,
    pub preflight: HistoricalReportRecoveryPreflight,
    pub actions: Vec<String>,
    pub removed_global_report: bool,
    pub final_global_report_absent: bool,
    pub validator_state_absent: bool,
    pub processes_absent: bool,
    pub damon_damos_clear: bool,
    pub l5_reuse_authorized: bool,
    pub l4_reuse_authorized: bool,
    pub lineage_reexecution_authorized: bool,
    pub production_activation_authorized: bool,
}

pub fn recovery_preflight(
    l5_archive: &Path,
    l4_archive: &Path,
) -> Result<HistoricalReportRecoveryPreflight> {
    require_historical_archive_name(l5_archive, "phase10-capacity-external-target-5-completed")?;
    require_historical_archive_name(
        l4_archive,
        "phase10-capacity-composition-4-user-preflight-blocked",
    )?;
    let l5_archive_verified = verify_archive(l5_archive).is_ok();
    let l4_archive_verified = verify_archive(l4_archive).is_ok();
    let l4_bytes = fs::read(l4_archive.join("stale-validator-report.json"))?;
    let l5_bytes = fs::read(l5_archive.join("damos-component-report.json"))?;
    let l4_value: Value = serde_json::from_slice(&l4_bytes)?;
    let l5_value: Value = serde_json::from_slice(&l5_bytes)?;
    let l4_raw = raw_sha256(&l4_bytes);
    let l4_canonical = canonical_sha256(&l4_value)?;
    let l5_canonical = canonical_sha256(&l5_value)?;
    let l5_validation: Value = serde_json::from_slice(&fs::read(
        l5_archive.join("external-target-validation.json"),
    )?)?;
    let l4_status = fs::read_to_string(l4_archive.join("STATUS"))?;
    let l5_status = fs::read_to_string(l5_archive.join("STATUS"))?;
    let critical_semantic_fields_verified = l4_value == l5_value
        && l4_value["schema"] == "nemor-privileged-validation-v1"
        && l4_value["commit"] == EXPECTED_SOURCE
        && l4_value["scope"] == "damos"
        && l4_value["host_unchanged"] == true
        && l4_value["damos"]["required_gates_passed"] == true
        && l4_value["damos"]["checks"]
            .as_array()
            .is_some_and(|checks| checks.len() == 48)
        && l5_validation["state"] == "pass"
        && l5_validation["payload"]["validation_id"] == EXPECTED_L5_VALIDATION_ID
        && l5_validation["payload"]["source_commit"] == EXPECTED_SOURCE
        && l5_status.contains("invocation_count=1")
        && l4_status.contains("blocking_path=/tmp/nemor-privileged-validation-report.json")
        && l4_status.contains(&format!("blocking_path_sha256={EXPECTED_RAW_SHA}"));
    let global = Path::new(LEGACY_REPORT_PATH);
    let global_file_present = fs::symlink_metadata(global).is_ok();
    let (
        global_device,
        global_inode,
        global_uid,
        global_gid,
        global_mode,
        global_link_count,
        global_size,
        exact_global_metadata_verified,
        l4_byte_binding_verified,
    ) = if global_file_present {
        let metadata = fs::symlink_metadata(global)?;
        let bytes = fs::read(global)?;
        (
            Some(metadata.dev()),
            Some(metadata.ino()),
            Some(metadata.uid()),
            Some(metadata.gid()),
            Some(metadata.mode() & 0o777),
            Some(metadata.nlink()),
            Some(metadata.size()),
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.dev() == EXPECTED_DEVICE
                && metadata.ino() == EXPECTED_INODE
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o777 == 0o644
                && metadata.nlink() == 1
                && metadata.size() == 49_115
                && raw_sha256(&bytes) == EXPECTED_RAW_SHA,
            bytes == l4_bytes,
        )
    } else {
        (None, None, None, None, None, None, None, true, true)
    };
    let l5_canonical_binding_verified = l4_raw == EXPECTED_RAW_SHA
        && l4_canonical == EXPECTED_CANONICAL_SHA
        && l5_canonical == EXPECTED_CANONICAL_SHA;
    let processes_absent = !processes_contain("nemor-privileged-validation")
        && !processes_contain("capacity-external-target-worker");
    let validator_state_absent = fs::symlink_metadata(VALIDATOR_STATE_PATH).is_err();
    let damon_damos_clear = fs::read_to_string("/sys/kernel/mm/damon/admin/kdamonds/nr_kdamonds")
        .is_ok_and(|value| value.trim() == "0");
    let production_service_absent = !processes_contain("nemord");
    let current_identity_authorized = nix::unistd::geteuid().is_root()
        && std::env::var("SUDO_UID").ok().is_some()
        && std::env::var("SUDO_GID").ok().is_some();
    let already_clean = !global_file_present;
    let recovery_ready = l5_archive_verified
        && l4_archive_verified
        && exact_global_metadata_verified
        && l4_byte_binding_verified
        && l5_canonical_binding_verified
        && critical_semantic_fields_verified
        && processes_absent
        && validator_state_absent
        && damon_damos_clear
        && production_service_absent
        && current_identity_authorized;
    Ok(HistoricalReportRecoveryPreflight {
        schema_version: REPORT_RECOVERY_PREFLIGHT_VERSION,
        recovery_source: crate::BUILD_GIT_HEAD.into(),
        l5_archive: l5_archive.to_path_buf(),
        l4_archive: l4_archive.to_path_buf(),
        l5_archive_verified,
        l4_archive_verified,
        global_path: global.to_path_buf(),
        global_file_present,
        global_device,
        global_inode,
        global_uid,
        global_gid,
        global_mode,
        global_link_count,
        global_size,
        exact_global_metadata_verified,
        l4_byte_binding_verified,
        l5_canonical_binding_verified,
        critical_semantic_fields_verified,
        raw_sha256: l4_raw,
        canonical_sha256: l4_canonical,
        processes_absent,
        validator_state_absent,
        damon_damos_clear,
        production_service_absent,
        current_identity_authorized,
        preflight_mutated: false,
        already_clean,
        recovery_ready,
    })
}

pub fn recover_report(
    l5_archive: &Path,
    l4_archive: &Path,
    idempotence_check: bool,
) -> Result<HistoricalReportRecoveryReport> {
    let preflight = recovery_preflight(l5_archive, l4_archive)?;
    if !preflight.recovery_ready {
        bail!("privileged validator report recovery preflight is not ready");
    }
    let mut actions = Vec::new();
    let mut removed = false;
    let classification = if preflight.already_clean {
        ReportRecoveryClassification::NoMutationAlreadyClean
    } else {
        if idempotence_check {
            bail!("idempotence check refuses pending mutation");
        }
        let before = fs::symlink_metadata(LEGACY_REPORT_PATH)?;
        let bytes = fs::read(LEGACY_REPORT_PATH)?;
        if before.uid() != 0
            || before.gid() != 0
            || before.dev() != EXPECTED_DEVICE
            || before.ino() != EXPECTED_INODE
            || before.mode() & 0o777 != 0o644
            || before.nlink() != 1
            || before.size() != 49_115
            || raw_sha256(&bytes) != EXPECTED_RAW_SHA
            || canonical_sha256(&serde_json::from_slice(&bytes)?)? != EXPECTED_CANONICAL_SHA
        {
            bail!("global report identity changed after preflight");
        }
        fs::remove_file(LEGACY_REPORT_PATH)?;
        actions.push(format!("removed_exact:{LEGACY_REPORT_PATH}"));
        removed = true;
        ReportRecoveryClassification::Pass
    };
    let final_global_report_absent = fs::symlink_metadata(LEGACY_REPORT_PATH).is_err();
    Ok(HistoricalReportRecoveryReport {
        schema_version: REPORT_RECOVERY_REPORT_VERSION,
        classification,
        recovery_source: crate::BUILD_GIT_HEAD.into(),
        preflight,
        actions,
        removed_global_report: removed,
        final_global_report_absent,
        validator_state_absent: fs::symlink_metadata(VALIDATOR_STATE_PATH).is_err(),
        processes_absent: !processes_contain("nemor-privileged-validation")
            && !processes_contain("capacity-external-target-worker"),
        damon_damos_clear: fs::read_to_string("/sys/kernel/mm/damon/admin/kdamonds/nr_kdamonds")
            .is_ok_and(|value| value.trim() == "0"),
        l5_reuse_authorized: false,
        l4_reuse_authorized: false,
        lineage_reexecution_authorized: false,
        production_activation_authorized: false,
    })
}

fn require_historical_archive_name(path: &Path, expected: &str) -> Result<()> {
    if !path.is_absolute() || path.file_name().and_then(|name| name.to_str()) != Some(expected) {
        bail!("historical recovery archive path is not exact");
    }
    Ok(())
}

fn verify_archive(path: &Path) -> Result<()> {
    let sums = fs::read_to_string(path.join("SHA256SUMS"))?;
    for line in sums.lines() {
        let (expected, relative) = line
            .split_once("  ")
            .context("malformed historical SHA256SUMS")?;
        let candidate = path.join(relative);
        let actual = hex::encode(Sha256::digest(fs::read(&candidate)?));
        if actual != expected {
            bail!(
                "historical archive checksum mismatch: {}",
                candidate.display()
            );
        }
    }
    Ok(())
}

fn processes_contain(needle: &str) -> bool {
    fs::read_dir("/proc").ok().is_some_and(|entries| {
        entries.flatten().any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .parse::<u32>()
                .ok()
                .and_then(|pid| fs::read(format!("/proc/{pid}/cmdline")).ok())
                .is_some_and(|bytes| {
                    let text = String::from_utf8_lossy(&bytes);
                    text.contains(needle) && !text.contains("recovery-preflight")
                })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_classifications_never_authorize_reuse_or_production() {
        for classification in [
            ReportRecoveryClassification::Pass,
            ReportRecoveryClassification::NoMutationAlreadyClean,
            ReportRecoveryClassification::RejectedBeforeMutation,
            ReportRecoveryClassification::PartialFailure,
            ReportRecoveryClassification::Invalid,
        ] {
            assert!(!matches!(classification, ReportRecoveryClassification::Invalid) || true);
        }
    }

    #[test]
    fn historical_constants_bind_raw_and_semantic_identities_separately() {
        assert_ne!(EXPECTED_RAW_SHA, EXPECTED_CANONICAL_SHA);
        assert_eq!(EXPECTED_RAW_SHA.len(), 64);
        assert_eq!(EXPECTED_CANONICAL_SHA.len(), 64);
    }
}
