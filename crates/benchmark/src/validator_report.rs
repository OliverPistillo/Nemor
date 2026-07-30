#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

pub const LEGACY_REPORT_PATH: &str = "/tmp/nemor-privileged-validation-report.json";
pub const VALIDATOR_STATE_PATH: &str = "/tmp/nemor-privileged-validation";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorReportMetadata {
    pub path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub link_count: u64,
    pub size: u64,
    pub file_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorReportLifecycleClassification {
    Pass,
    BaselineNoReport,
    Missing,
    UnsafeMetadata,
    InvalidJson,
    SemanticFailure,
    LegacyGlobalPresent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorReportLifecycleEvidence {
    pub version: u32,
    pub report_path: Option<PathBuf>,
    pub raw_sha256: Option<String>,
    pub canonical_semantic_sha256: Option<String>,
    pub metadata: Option<ValidatorReportMetadata>,
    pub validator_exit_status: Option<i32>,
    pub explicit_path_mode: bool,
    pub legacy_global_absent_before: bool,
    pub legacy_global_absent_after: bool,
    pub validator_state_absent: bool,
    pub classification: ValidatorReportLifecycleClassification,
}

impl Default for ValidatorReportLifecycleEvidence {
    fn default() -> Self {
        Self {
            version: 0,
            report_path: None,
            raw_sha256: None,
            canonical_semantic_sha256: None,
            metadata: None,
            validator_exit_status: None,
            explicit_path_mode: false,
            legacy_global_absent_before: false,
            legacy_global_absent_after: false,
            validator_state_absent: false,
            classification: ValidatorReportLifecycleClassification::UnsafeMetadata,
        }
    }
}

pub fn raw_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(&sort_json(value))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn canonical_sha256(value: &Value) -> Result<String> {
    Ok(raw_sha256(&canonical_json_bytes(value)?))
}

fn sort_json(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(sort_json).collect()),
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            let mut sorted = serde_json::Map::new();
            for key in keys {
                sorted.insert(key.clone(), sort_json(&values[key]));
            }
            Value::Object(sorted)
        }
        _ => value.clone(),
    }
}

pub fn legacy_report_absent() -> bool {
    fs::symlink_metadata(LEGACY_REPORT_PATH).is_err()
}

pub fn validator_state_absent() -> bool {
    fs::symlink_metadata(VALIDATOR_STATE_PATH).is_err()
}

pub fn inspect_scoped_report(
    path: &Path,
    authorized_parent: &Path,
    allowed_filename: &str,
    expected_uid: u32,
    expected_gid: u32,
    validator_exit_status: Option<i32>,
    legacy_absent_before: bool,
) -> Result<(Value, Vec<u8>, ValidatorReportLifecycleEvidence)> {
    inspect_scoped_report_with_legacy(
        path,
        authorized_parent,
        allowed_filename,
        expected_uid,
        expected_gid,
        validator_exit_status,
        legacy_absent_before,
        Path::new(LEGACY_REPORT_PATH),
    )
}

#[allow(clippy::too_many_arguments)]
fn inspect_scoped_report_with_legacy(
    path: &Path,
    authorized_parent: &Path,
    allowed_filename: &str,
    expected_uid: u32,
    expected_gid: u32,
    validator_exit_status: Option<i32>,
    legacy_absent_before: bool,
    legacy_path: &Path,
) -> Result<(Value, Vec<u8>, ValidatorReportLifecycleEvidence)> {
    if !path.is_absolute()
        || !authorized_parent.is_absolute()
        || path.parent() != Some(authorized_parent)
        || path.file_name().and_then(|name| name.to_str()) != Some(allowed_filename)
    {
        bail!("validator report path is outside its exact authorized parent");
    }
    if fs::canonicalize(authorized_parent)? != authorized_parent {
        bail!("validator report parent is not canonical");
    }
    let parent_meta = fs::symlink_metadata(authorized_parent)?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        bail!("validator report parent is not a safe directory");
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect validator report {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.file_type().is_socket()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.dev() != parent_meta.dev()
    {
        bail!("validator report metadata is unsafe");
    }
    let bytes = fs::read(path)?;
    let value: Value = serde_json::from_slice(&bytes).context("parse validator report")?;
    let evidence = ValidatorReportLifecycleEvidence {
        version: 1,
        report_path: Some(path.to_path_buf()),
        raw_sha256: Some(raw_sha256(&bytes)),
        canonical_semantic_sha256: Some(canonical_sha256(&value)?),
        metadata: Some(ValidatorReportMetadata {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o777,
            link_count: metadata.nlink(),
            size: metadata.size(),
            file_type: "regular".into(),
        }),
        validator_exit_status,
        explicit_path_mode: true,
        legacy_global_absent_before: legacy_absent_before,
        legacy_global_absent_after: fs::symlink_metadata(legacy_path).is_err(),
        validator_state_absent: validator_state_absent(),
        classification: ValidatorReportLifecycleClassification::Pass,
    };
    if !evidence.legacy_global_absent_before
        || !evidence.legacy_global_absent_after
        || !evidence.validator_state_absent
    {
        bail!("validator report lifecycle left legacy global state");
    }
    Ok((value, bytes, evidence))
}

pub fn baseline_report_lifecycle() -> ValidatorReportLifecycleEvidence {
    ValidatorReportLifecycleEvidence {
        version: 1,
        report_path: None,
        raw_sha256: None,
        canonical_semantic_sha256: None,
        metadata: None,
        validator_exit_status: None,
        explicit_path_mode: false,
        legacy_global_absent_before: legacy_report_absent(),
        legacy_global_absent_after: legacy_report_absent(),
        validator_state_absent: validator_state_absent(),
        classification: ValidatorReportLifecycleClassification::BaselineNoReport,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn raw_and_reserialized_json_can_differ_but_canonicalize_identically() {
        let raw = br#"{"z":1,"a":{"y":2,"x":3}}"#;
        let value: Value = serde_json::from_slice(raw).unwrap();
        let pretty = serde_json::to_vec_pretty(&value).unwrap();
        assert_ne!(raw.as_slice(), pretty.as_slice());
        assert_eq!(
            canonical_sha256(&value).unwrap(),
            canonical_sha256(&serde_json::from_slice(&pretty).unwrap()).unwrap()
        );
    }

    #[test]
    fn scoped_report_requires_exact_safe_metadata() {
        let root = tempdir().unwrap();
        let parent = root.path().canonicalize().unwrap();
        let path = parent.join("raw-damos-report.json");
        fs::write(&path, b"{\"scope\":\"damos\"}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let meta = fs::metadata(&path).unwrap();
        let legacy = parent.join("legacy-absent.json");
        let (_, bytes, evidence) = inspect_scoped_report_with_legacy(
            &path,
            &parent,
            "raw-damos-report.json",
            meta.uid(),
            meta.gid(),
            Some(0),
            true,
            &legacy,
        )
        .unwrap();
        assert_eq!(bytes, b"{\"scope\":\"damos\"}");
        assert_eq!(evidence.raw_sha256, Some(raw_sha256(&bytes)));
    }

    #[test]
    fn scoped_report_rejects_wrong_name_mode_and_parent() {
        let root = tempdir().unwrap();
        let parent = root.path().canonicalize().unwrap();
        let path = parent.join("wrong.json");
        fs::write(&path, b"{}").unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert!(inspect_scoped_report(
            &path,
            &parent,
            "raw-damos-report.json",
            meta.uid(),
            meta.gid(),
            Some(0),
            true,
        )
        .is_err());
    }
}
