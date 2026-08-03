//! Phase 6 validation-only boot contract v5.
//!
//! V1 and V2 remain in `boot_validation` for historical deserialization.  Nothing in
//! this module accepts a v1 or v2 manifest as authority for mutation.

use crate::{StorageProfile, TIERING_RULE_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

pub const BOOT_VALIDATION_CONTRACT_VERSION_V5: &str = "tiering-boot-validation-v5";
pub const PREPARED_MANIFEST_SCHEMA_V5: &str = "tiering-boot-prepared-manifest-v5";
pub const DURABLE_TRANSACTION_SCHEMA_V5: &str = "tiering-boot-transaction-v5";
pub const PREFLIGHT_SCHEMA_V5: &str = "tiering-boot-preflight-v5";
pub const APPLY_EVIDENCE_SCHEMA_V5: &str = "tiering-boot-apply-evidence-v5";
pub const POST_BOOT_EVIDENCE_SCHEMA_V5: &str = "tiering-post-boot-evidence-v5";
pub const FINAL_RESTORE_SCHEMA_V5: &str = "tiering-final-restore-evidence-v5";
pub const PROFILE_BENCHMARK_EVIDENCE_V5: &str = "tiering-profile-benchmark-v5";
pub const ZRAM_BASELINE_EVIDENCE_V5: &str = "tiering-zram-baseline-v2";
pub const ACTIVATION_EVIDENCE_SCHEMA_V5: &str = "tiering-activation-evidence-v5";
pub const RECOVERY_EVIDENCE_SCHEMA_V5: &str = "tiering-recovery-evidence-v5";
pub const WORKLOAD_PROTOCOL_V5: &str = "tiering-bounded-workload-v1";
pub const TRANSACTION_ROOT_V5: &str = "/var/lib/nemor/validation/phase6";
const ENTRY_ROOT: &str = "/boot/loader/entries";
const UNIT_ROOT: &str = "/etc/systemd/system";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootValidationCommandV5 {
    Prepare,
    UserPreflight,
    RootPreflight,
    MeasureBaseline,
    Apply,
    VerifyApplied,
    SelectOneShot,
    PostBootValidate,
    SelectBaselineRollback,
    VerifyFinalRestore,
    Recover,
    VerifyIdempotence,
}

impl BootValidationCommandV5 {
    #[must_use]
    pub fn mutating(self) -> bool {
        matches!(
            self,
            Self::Apply
                | Self::MeasureBaseline
                | Self::SelectOneShot
                | Self::SelectBaselineRollback
                | Self::VerifyFinalRestore
                | Self::Recover
        )
    }
    #[must_use]
    pub fn requires_authenticated_root(self) -> bool {
        !matches!(self, Self::Prepare | Self::UserPreflight)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BootValidationV5Error {
    #[error("v5 schema or contract mismatch")]
    Version,
    #[error("malformed or mismatched integrity identity: {0}")]
    Identity(&'static str),
    #[error("unsupported or ambiguous storage topology")]
    Topology,
    #[error("unsafe validation-owned path")]
    Path,
    #[error("unsafe Type #1 loader entry")]
    Entry,
    #[error("invalid validation-only swap contract")]
    Swap,
    #[error("invalid zswap parameter contract")]
    Zswap,
    #[error("payload integrity mismatch")]
    Payload,
    #[error("authenticated sudo identity mismatch")]
    SudoIdentity,
    #[error("preflight blocked: {0}")]
    Preflight(String),
    #[error("illegal transaction transition")]
    Transition,
    #[error("host readback mismatch: {0}")]
    Readback(&'static str),
    #[error("post-boot measurement rejected: {0}")]
    Measurement(&'static str),
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_id(value: &str) -> bool {
    (8..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn canonical_json_sha256_v5<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("serializable contract");
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryIdentityV5 {
    pub path: PathBuf,
    pub sha256: String,
    pub embedded_commit: String,
}

/// A source executable is evidence, never an execution target for root.  Apply
/// copies it into the exact root-owned transaction directory and all services
/// execute only the staged destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedBinaryPlanV5 {
    pub source: BinaryIdentityV5,
    pub destination: PathBuf,
    pub destination_mode: u32,
    pub destination_uid: u32,
    pub destination_gid: u32,
    pub require_single_link: bool,
    pub source_uid: u32,
    pub source_gid: u32,
    pub source_mode: u32,
    pub source_link_count: u64,
    pub source_device: u64,
    pub source_inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockLayerIdentityV5 {
    pub path: PathBuf,
    pub kind: String,
    pub major: u32,
    pub minor: u32,
    pub parent: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalDeviceIdentityV5 {
    pub path: PathBuf,
    pub major: u32,
    pub minor: u32,
    pub transport: String,
    pub rotational: bool,
    pub model: String,
    pub serial: Option<String>,
    pub wwn: Option<String>,
    pub capacity_bytes: u64,
    pub logical_block_size: u64,
    pub physical_block_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemIdentityV5 {
    pub filesystem: String,
    pub uuid_or_fsid: String,
    pub mount_source: PathBuf,
    pub mount_point: PathBuf,
    pub mount_id: u64,
    pub device_major: u32,
    pub device_minor: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageTopologyIdentityV5 {
    pub storage_profile_version: String,
    pub profile: StorageProfile,
    pub chain: Vec<BlockLayerIdentityV5>,
    pub physical: PhysicalDeviceIdentityV5,
    pub filesystem: FilesystemIdentityV5,
    pub composite: bool,
    pub ambiguous: bool,
    pub confidence: String,
}

impl StorageTopologyIdentityV5 {
    pub fn validate(&self) -> Result<(), BootValidationV5Error> {
        if self.storage_profile_version != crate::STORAGE_PROFILE_VERSION
            || !self.profile.boot_supported()
            || self.chain.is_empty()
            || self.composite
            || self.ambiguous
            || self.physical.rotational
            || self.physical.capacity_bytes == 0
            || self.physical.logical_block_size == 0
            || self.physical.physical_block_size == 0
            || self.filesystem.uuid_or_fsid.trim().is_empty()
            || self.filesystem.mount_point != Path::new("/")
        {
            return Err(BootValidationV5Error::Topology);
        }
        let stable = self
            .physical
            .serial
            .as_deref()
            .is_some_and(|v| !v.is_empty())
            || self.physical.wwn.as_deref().is_some_and(|v| !v.is_empty());
        if !stable || self.confidence != "high" {
            return Err(BootValidationV5Error::Topology);
        }
        let transport_ok = matches!(
            (self.profile, self.physical.transport.as_str()),
            (StorageProfile::NvmeSsd, "nvme")
                | (StorageProfile::SataSsd, "ata")
                | (StorageProfile::SataSsd, "sata")
        );
        if !transport_ok || self.chain.last().map(|v| &v.path) != Some(&self.physical.path) {
            return Err(BootValidationV5Error::Topology);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapIdentityV5 {
    pub path: PathBuf,
    pub kind: String,
    pub size_bytes: u64,
    pub priority: i32,
    pub uuid: Option<String>,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZramIdentityV5 {
    pub device: PathBuf,
    pub provider: String,
    pub active: bool,
    pub priority: i32,
    pub disksize_bytes: u64,
    pub compressor: String,
    pub memory_limit_bytes: u64,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZswapIdentityV5 {
    pub parameters: BTreeMap<String, String>,
}

impl ZswapIdentityV5 {
    fn validate(&self) -> Result<(), BootValidationV5Error> {
        let required = [
            "enabled",
            "compressor",
            "zpool",
            "max_pool_percent",
            "accept_threshold_percent",
            "shrinker_enabled",
        ];
        if required.iter().any(|k| !self.parameters.contains_key(*k)) {
            return Err(BootValidationV5Error::Zswap);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootEntryIdentityV5 {
    pub id: String,
    pub path: PathBuf,
    pub sha256: String,
    pub title: String,
    pub linux_or_efi: PathBuf,
    pub initrds: Vec<PathBuf>,
    pub options: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferencedBootFileV5 {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnedArtifactKindV5 {
    Type1Entry,
    ValidationUnit,
    HelperBinary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedArtifactV5 {
    pub kind: OwnedArtifactKindV5,
    pub path: PathBuf,
    pub sha256: String,
    pub mode: u32,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootIdentityV5 {
    pub bootloader: String,
    pub bootloader_version: String,
    pub current_entry: BootEntryIdentityV5,
    pub default_entry: BootEntryIdentityV5,
    pub boot_order: Vec<String>,
    pub prior_one_shot: Option<String>,
    pub esp_mount: PathBuf,
    pub esp_device: String,
    pub esp_filesystem: String,
    pub esp_uuid: String,
    pub esp_mount_id: u64,
    pub esp_device_major: u32,
    pub esp_device_minor: u32,
    pub secure_boot: String,
    pub kernel_release: String,
    pub referenced_files: Vec<ReferencedBootFileV5>,
    pub current_command_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadContractV5 {
    pub protocol: String,
    pub seed: u64,
    pub bytes: u64,
    pub iterations: u32,
    pub timeout_seconds: u64,
    pub maximum_write_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedManifestPayloadV5 {
    pub contract_version: String,
    pub rule_version: String,
    pub validation_id: String,
    pub prepared_uid: u32,
    pub prepared_gid: u32,
    pub source_commit: String,
    pub source_state_sha256: String,
    pub binaries: BTreeMap<String, BinaryIdentityV5>,
    pub config_path: PathBuf,
    pub config_sha256: String,
    pub material_environment_sha256: String,
    pub topology: StorageTopologyIdentityV5,
    pub baseline_swaps: Vec<SwapIdentityV5>,
    pub protected_zram: ZramIdentityV5,
    pub baseline_zswap: ZswapIdentityV5,
    pub experimental_zswap: BTreeMap<String, String>,
    pub boot: BootIdentityV5,
    pub experimental_entry: BootEntryIdentityV5,
    pub validation_marker: String,
    pub swapfile: SwapIdentityV5,
    pub owned_artifacts: Vec<OwnedArtifactV5>,
    pub transaction_root: PathBuf,
    pub workload: WorkloadContractV5,
    pub staged_helper: StagedBinaryPlanV5,
    pub recovery_entry: String,
    pub production_activation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TieringBootValidationPreparedManifestV5 {
    pub schema: String,
    pub payload: PreparedManifestPayloadV5,
    pub payload_sha256: String,
}

impl TieringBootValidationPreparedManifestV5 {
    pub fn seal(payload: PreparedManifestPayloadV5) -> Self {
        let payload_sha256 = canonical_json_sha256_v5(&payload);
        Self {
            schema: PREPARED_MANIFEST_SCHEMA_V5.to_owned(),
            payload,
            payload_sha256,
        }
    }

    pub fn validate(&self) -> Result<(), BootValidationV5Error> {
        let p = &self.payload;
        if self.schema != PREPARED_MANIFEST_SCHEMA_V5
            || p.contract_version != BOOT_VALIDATION_CONTRACT_VERSION_V5
            || p.rule_version != TIERING_RULE_VERSION
        {
            return Err(BootValidationV5Error::Version);
        }
        if canonical_json_sha256_v5(p) != self.payload_sha256 {
            return Err(BootValidationV5Error::Payload);
        }
        if !valid_id(&p.validation_id) || !is_commit(&p.source_commit) {
            return Err(BootValidationV5Error::Identity("source"));
        }
        if p.validation_marker != format!("nemor.phase6_validation={}", p.validation_id)
            || !p.config_path.is_absolute()
        {
            return Err(BootValidationV5Error::Identity("bounded inputs"));
        }
        for hash in [
            &p.source_state_sha256,
            &p.config_sha256,
            &p.material_environment_sha256,
        ] {
            if !is_sha256(hash) {
                return Err(BootValidationV5Error::Identity("hash"));
            }
        }
        if p.binaries.is_empty()
            || p.binaries.values().any(|b| {
                !b.path.is_absolute()
                    || !is_sha256(&b.sha256)
                    || b.embedded_commit != p.source_commit
            })
        {
            return Err(BootValidationV5Error::Identity("binary"));
        }
        let validator = p
            .binaries
            .get("nemor-tiering-boot-validation")
            .ok_or(BootValidationV5Error::Identity("validator binary"))?;
        if p.staged_helper.source != *validator
            || p.staged_helper.destination
                != p.transaction_root.join("bin/nemor-tiering-boot-validation")
            || p.staged_helper.destination_mode != 0o755
            || p.staged_helper.destination_uid != 0
            || p.staged_helper.destination_gid != 0
            || !p.staged_helper.require_single_link
            || p.staged_helper.source_link_count != 1
            || p.staged_helper.source_mode & 0o022 != 0
            || p.staged_helper.source_device == 0
            || p.staged_helper.source_inode == 0
        {
            return Err(BootValidationV5Error::Identity("staged helper"));
        }
        p.topology.validate()?;
        p.baseline_zswap.validate()?;
        let mut baseline_paths = BTreeSet::new();
        if p.baseline_swaps.is_empty()
            || p.baseline_swaps.iter().any(|swap| {
                !swap.active
                    || swap.path == p.swapfile.path
                    || !baseline_paths.insert(swap.path.clone())
            })
            || !p.baseline_swaps.iter().any(|swap| {
                swap.path == p.protected_zram.device
                    && swap.priority == p.protected_zram.priority
                    && swap.size_bytes == p.protected_zram.disksize_bytes
            })
        {
            return Err(BootValidationV5Error::Identity("baseline swaps"));
        }
        validate_experimental_zswap(&p.experimental_zswap)?;
        if [
            "compressor",
            "zpool",
            "max_pool_percent",
            "accept_threshold_percent",
            "shrinker_enabled",
        ]
        .iter()
        .any(|name| p.experimental_zswap.get(*name) != p.baseline_zswap.parameters.get(*name))
        {
            return Err(BootValidationV5Error::Zswap);
        }
        validate_boot(p)?;
        validate_swap(p)?;
        if p.production_activation
            || p.recovery_entry != p.boot.current_entry.id
            || p.transaction_root != Path::new(TRANSACTION_ROOT_V5).join(&p.validation_id)
        {
            return Err(BootValidationV5Error::Identity("recovery"));
        }
        let mut paths = BTreeSet::new();
        for artifact in &p.owned_artifacts {
            validate_owned_path(p, artifact)?;
            if !paths.insert(artifact.path.clone())
                || artifact.owner_uid != 0
                || artifact.owner_gid != 0
                || !matches!(artifact.mode, 0o600 | 0o700 | 0o644 | 0o755)
                || (artifact.kind != OwnedArtifactKindV5::HelperBinary
                    && canonical_bytes_sha256(&artifact.content) != artifact.sha256)
            {
                return Err(BootValidationV5Error::Identity("artifact"));
            }
        }
        if p.workload.protocol != WORKLOAD_PROTOCOL_V5
            || p.workload.bytes == 0
            || p.workload.bytes > 256 * 1024 * 1024
            || p.workload.iterations == 0
            || p.workload.timeout_seconds == 0
            || p.workload.timeout_seconds > 600
            || p.workload.maximum_write_bytes == 0
        {
            return Err(BootValidationV5Error::Identity("workload"));
        }
        Ok(())
    }
}

fn canonical_bytes_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_experimental_zswap(
    values: &BTreeMap<String, String>,
) -> Result<(), BootValidationV5Error> {
    const ALLOWED: &[&str] = &[
        "enabled",
        "compressor",
        "zpool",
        "max_pool_percent",
        "accept_threshold_percent",
        "shrinker_enabled",
    ];
    if values.keys().any(|k| !ALLOWED.contains(&k.as_str()))
        || values.get("enabled").map(String::as_str) != Some("Y")
        || values.len() != ALLOWED.len()
    {
        return Err(BootValidationV5Error::Zswap);
    }
    Ok(())
}

fn validate_boot(p: &PreparedManifestPayloadV5) -> Result<(), BootValidationV5Error> {
    let b = &p.boot;
    if b.bootloader != "systemd-boot-type1"
        || b.secure_boot != "disabled"
        || b.current_entry.id.is_empty()
        || b.default_entry.id.is_empty()
        || b.prior_one_shot.is_some()
        || !is_sha256(&b.current_entry.sha256)
        || !is_sha256(&b.default_entry.sha256)
        || p.experimental_entry.id == b.current_entry.id
        || p.experimental_entry.id == b.default_entry.id
        || p.experimental_entry.path
            != Path::new(ENTRY_ROOT).join(format!("nemor-phase6-{}.conf", p.validation_id))
    {
        return Err(BootValidationV5Error::Entry);
    }
    if p.experimental_entry.linux_or_efi != b.current_entry.linux_or_efi
        || p.experimental_entry.initrds != b.current_entry.initrds
        || !p.experimental_entry.options.contains(&p.validation_marker)
        || !p.experimental_entry.options.contains("zswap.enabled=1")
        || !p.experimental_entry.options.contains(&format!(
            "systemd.wants=nemor-phase6-{}.service",
            p.validation_id
        ))
    {
        return Err(BootValidationV5Error::Entry);
    }
    let refs: BTreeSet<_> = b.referenced_files.iter().map(|r| &r.path).collect();
    if !refs.contains(&p.experimental_entry.linux_or_efi)
        || p.experimental_entry
            .initrds
            .iter()
            .any(|v| !refs.contains(v))
        || b.referenced_files.iter().any(|r| !is_sha256(&r.sha256))
    {
        return Err(BootValidationV5Error::Entry);
    }
    let entry_artifact = p
        .owned_artifacts
        .iter()
        .find(|a| a.kind == OwnedArtifactKindV5::Type1Entry)
        .ok_or(BootValidationV5Error::Entry)?;
    if entry_artifact.content != render_type1_entry_v5(&p.experimental_entry).into_bytes() {
        return Err(BootValidationV5Error::Entry);
    }
    if entry_artifact.sha256 != p.experimental_entry.sha256 {
        return Err(BootValidationV5Error::Entry);
    }
    let unit_artifact = p
        .owned_artifacts
        .iter()
        .find(|a| a.kind == OwnedArtifactKindV5::ValidationUnit)
        .ok_or(BootValidationV5Error::Entry)?;
    let helper = p
        .owned_artifacts
        .iter()
        .find(|a| a.kind == OwnedArtifactKindV5::HelperBinary)
        .ok_or(BootValidationV5Error::Identity("staged helper artifact"))?;
    if helper.path != p.staged_helper.destination
        || helper.sha256 != p.staged_helper.source.sha256
        || helper.mode != 0o755
        || !helper.content.is_empty()
    {
        return Err(BootValidationV5Error::Identity("staged helper artifact"));
    }
    if unit_artifact.content
        != render_validation_unit_v5(p, &p.staged_helper.destination).into_bytes()
    {
        return Err(BootValidationV5Error::Entry);
    }
    Ok(())
}

#[must_use]
pub fn render_type1_entry_v5(entry: &BootEntryIdentityV5) -> String {
    let mut text = format!("title {}\n", entry.title);
    text.push_str(&format!("linux {}\n", entry.linux_or_efi.display()));
    for initrd in &entry.initrds {
        text.push_str(&format!("initrd {}\n", initrd.display()));
    }
    text.push_str(&format!("options {}\n", entry.options));
    text
}

#[must_use]
pub fn render_validation_unit_v5(p: &PreparedManifestPayloadV5, validator: &Path) -> String {
    format!(
        "[Unit]\nDescription=Nemor Phase 6 validation-only activation\nConditionKernelCommandLine={}\nAfter=systemd-udev-settle.service dev-zram0.swap\n\n[Service]\nType=oneshot\nExecStart={} experimental-activate --validation-id {}\nRemainAfterExit=yes\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nReadWritePaths={} /sys/module/zswap/parameters\n\n[Install]\nWantedBy=multi-user.target\n",
        p.validation_marker,
        validator.display(),
        p.validation_id,
        p.transaction_root.display()
    )
}

fn validate_swap(p: &PreparedManifestPayloadV5) -> Result<(), BootValidationV5Error> {
    let expected = p.transaction_root.join("backing.swap");
    if p.swapfile.path != expected
        || p.swapfile.active
        || p.swapfile.uuid.is_some()
        || p.swapfile.kind != "file"
        || p.swapfile.size_bytes < 64 * 1024 * 1024
        || p.swapfile.size_bytes > 2 * 1024 * 1024 * 1024
        || p.swapfile.priority <= p.protected_zram.priority
        || p.swapfile.priority > 32_767
        || p.protected_zram.device != Path::new("/dev/zram0")
        || !p.protected_zram.active
    {
        return Err(BootValidationV5Error::Swap);
    }
    Ok(())
}

fn validate_owned_path(
    p: &PreparedManifestPayloadV5,
    a: &OwnedArtifactV5,
) -> Result<(), BootValidationV5Error> {
    if !a.path.is_absolute()
        || a.path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || a.path.starts_with("/usr/lib")
    {
        return Err(BootValidationV5Error::Path);
    }
    let allowed = match a.kind {
        OwnedArtifactKindV5::Type1Entry => a.path == p.experimental_entry.path,
        OwnedArtifactKindV5::ValidationUnit => {
            a.path == Path::new(UNIT_ROOT).join(format!("nemor-phase6-{}.service", p.validation_id))
        }
        OwnedArtifactKindV5::HelperBinary => {
            a.path == p.transaction_root.join("bin/nemor-tiering-boot-validation")
        }
    };
    if !allowed {
        return Err(BootValidationV5Error::Path);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStageV5 {
    Prepared,
    RootPreflighted,
    BaselineMeasuring,
    BaselineMeasured,
    Applying,
    Applied,
    OneShotSelecting,
    OneShotSelected,
    ExperimentalBootDetected,
    ActivationPreparing,
    ZswapDisabling,
    ZswapParametersApplying,
    ZswapEnabling,
    SwapActivating,
    ActivationVerified,
    ActivationFailed,
    PostBootMeasuring,
    PostBootValidated,
    BaselineSelecting,
    BaselineSelected,
    BaselineBoot,
    BaselineVerified,
    Cleaning,
    Restored,
    Recovered,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationRecordV5 {
    pub operation: String,
    pub target: PathBuf,
    pub completed: bool,
    pub evidence_sha256: Option<String>,
    pub boot_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableTransactionPayloadV5 {
    pub validation_id: String,
    pub manifest_sha256: String,
    pub stage: TransactionStageV5,
    pub baseline_boot_id: String,
    pub current_boot_id: String,
    pub artifact_registry: Vec<PathBuf>,
    pub swapfile_registry: Vec<PathBuf>,
    pub unit_registry: Vec<PathBuf>,
    pub transient_unit_registry: Vec<String>,
    pub applied_swap_identity: Option<SwapIdentityV5>,
    pub evidence_hashes: BTreeMap<String, String>,
    pub mutation_records: Vec<MutationRecordV5>,
    pub primary_error: Option<String>,
    pub failed_from_stage: Option<TransactionStageV5>,
    pub secondary_errors: Vec<String>,
    pub recovery_state: String,
    pub idempotence_verified: bool,
    pub activation_parameter_index: usize,
    pub original_primary_error: Option<String>,
    pub terminal_archive_sha256: Option<String>,
    pub post_boot_summary: Option<PostBootSummaryV5>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostBootSummaryV5 {
    pub backing_write_bytes: u64,
    pub latency_ns: u64,
    pub write_budget_passed: bool,
    pub oom: bool,
    pub safety_failure: bool,
    pub backing_write_confidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableTransactionV5 {
    pub schema: String,
    pub payload: DurableTransactionPayloadV5,
    pub payload_sha256: String,
}

impl DurableTransactionV5 {
    pub fn new(
        manifest: &TieringBootValidationPreparedManifestV5,
        boot_id: String,
    ) -> Result<Self, BootValidationV5Error> {
        manifest.validate()?;
        let p = &manifest.payload;
        let payload = DurableTransactionPayloadV5 {
            validation_id: p.validation_id.clone(),
            manifest_sha256: canonical_json_sha256_v5(manifest),
            stage: TransactionStageV5::Prepared,
            baseline_boot_id: boot_id.clone(),
            current_boot_id: boot_id,
            artifact_registry: p.owned_artifacts.iter().map(|a| a.path.clone()).collect(),
            swapfile_registry: vec![p.swapfile.path.clone()],
            unit_registry: p
                .owned_artifacts
                .iter()
                .filter(|a| a.kind == OwnedArtifactKindV5::ValidationUnit)
                .map(|a| a.path.clone())
                .collect(),
            transient_unit_registry: vec![format!(
                "nemor-phase6-workload-{}.scope",
                p.validation_id
            )],
            applied_swap_identity: None,
            evidence_hashes: BTreeMap::new(),
            mutation_records: Vec::new(),
            primary_error: None,
            failed_from_stage: None,
            secondary_errors: Vec::new(),
            recovery_state: "not_required".to_owned(),
            idempotence_verified: false,
            activation_parameter_index: 0,
            original_primary_error: None,
            terminal_archive_sha256: None,
            post_boot_summary: None,
        };
        Ok(Self::seal(payload))
    }
    pub fn seal(payload: DurableTransactionPayloadV5) -> Self {
        let payload_sha256 = canonical_json_sha256_v5(&payload);
        Self {
            schema: DURABLE_TRANSACTION_SCHEMA_V5.to_owned(),
            payload,
            payload_sha256,
        }
    }
    pub fn validate(&self) -> Result<(), BootValidationV5Error> {
        if self.schema != DURABLE_TRANSACTION_SCHEMA_V5
            || canonical_json_sha256_v5(&self.payload) != self.payload_sha256
        {
            Err(BootValidationV5Error::Payload)
        } else {
            Ok(())
        }
    }
    pub fn transition(&mut self, next: TransactionStageV5) -> Result<(), BootValidationV5Error> {
        self.validate()?;
        if !legal_transition_v5(self.payload.stage, next) {
            return Err(BootValidationV5Error::Transition);
        }
        self.payload.stage = next;
        self.payload_sha256 = canonical_json_sha256_v5(&self.payload);
        Ok(())
    }
    pub fn record_intent(&mut self, operation: &str, target: PathBuf) {
        self.payload.mutation_records.push(MutationRecordV5 {
            operation: operation.to_owned(),
            target,
            completed: false,
            evidence_sha256: None,
            boot_id: self.payload.current_boot_id.clone(),
        });
        self.payload_sha256 = canonical_json_sha256_v5(&self.payload);
    }
    pub fn complete_last(&mut self, evidence_sha256: String) -> Result<(), BootValidationV5Error> {
        let last = self
            .payload
            .mutation_records
            .last_mut()
            .ok_or(BootValidationV5Error::Transition)?;
        last.completed = true;
        last.evidence_sha256 = Some(evidence_sha256);
        self.payload_sha256 = canonical_json_sha256_v5(&self.payload);
        Ok(())
    }
}

pub fn legal_transition_v5(from: TransactionStageV5, to: TransactionStageV5) -> bool {
    use TransactionStageV5::*;
    matches!(
        (from, to),
        (Prepared, RootPreflighted)
            | (RootPreflighted, BaselineMeasuring)
            | (BaselineMeasuring, BaselineMeasured)
            | (BaselineMeasured, Applying)
            | (Applying, Applied)
            | (Applied, OneShotSelecting)
            | (OneShotSelecting, OneShotSelected)
            | (OneShotSelected, ExperimentalBootDetected)
            | (ExperimentalBootDetected, ActivationPreparing)
            | (ActivationPreparing, ZswapDisabling)
            | (ZswapDisabling, ZswapParametersApplying)
            | (ZswapParametersApplying, ZswapParametersApplying)
            | (ZswapParametersApplying, ZswapEnabling)
            | (ZswapEnabling, SwapActivating)
            | (SwapActivating, ActivationVerified)
            | (ActivationVerified, PostBootMeasuring)
            | (ActivationPreparing, ActivationFailed)
            | (ZswapDisabling, ActivationFailed)
            | (ZswapParametersApplying, ActivationFailed)
            | (ZswapEnabling, ActivationFailed)
            | (SwapActivating, ActivationFailed)
            | (ActivationFailed, BaselineSelecting)
            | (ActivationPreparing, BaselineSelecting)
            | (ZswapDisabling, BaselineSelecting)
            | (ZswapParametersApplying, BaselineSelecting)
            | (ZswapEnabling, BaselineSelecting)
            | (SwapActivating, BaselineSelecting)
            | (PostBootMeasuring, PostBootValidated)
            | (ActivationVerified, BaselineSelecting)
            | (PostBootMeasuring, BaselineSelecting)
            | (PostBootValidated, BaselineSelecting)
            | (BaselineSelecting, BaselineSelected)
            | (BaselineSelected, BaselineBoot)
            | (BaselineBoot, BaselineVerified)
            | (BaselineVerified, Cleaning)
            | (Cleaning, Restored)
            | (_, Failed)
            | (Prepared, Recovered)
            | (RootPreflighted, Recovered)
            | (BaselineMeasuring, Recovered)
            | (BaselineMeasured, Recovered)
            | (Applying, Recovered)
            | (Applied, Recovered)
            | (OneShotSelecting, Recovered)
            | (OneShotSelected, Recovered)
            | (BaselineVerified, Recovered)
            | (Cleaning, Recovered)
            | (ActivationPreparing, Recovered)
            | (ZswapDisabling, Recovered)
            | (ZswapParametersApplying, Recovered)
            | (ZswapEnabling, Recovered)
            | (SwapActivating, Recovered)
            | (ActivationFailed, Recovered)
            | (Failed, BaselineSelecting)
            | (Failed, Recovered)
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightObservationV5 {
    pub schema: String,
    pub uid: u32,
    pub gid: u32,
    pub sudo_uid: Option<u32>,
    pub sudo_gid: Option<u32>,
    pub host_identity_sha256: String,
    pub source_matches: bool,
    pub binaries_match: bool,
    pub config_matches: bool,
    pub topology_matches: bool,
    pub boot_matches: bool,
    pub bootloader_type_matches: bool,
    pub bootloader_version_matches: bool,
    pub current_entry_semantics_match: bool,
    pub current_entry_hash_matches: bool,
    pub current_entry_path_matches: bool,
    pub default_entry_semantics_match: bool,
    pub default_entry_hash_matches: bool,
    pub default_entry_path_matches: bool,
    pub referenced_boot_files_match: bool,
    pub kernel_release_matches: bool,
    pub command_line_matches: bool,
    pub esp_device_matches: bool,
    pub esp_filesystem_matches: bool,
    pub esp_uuid_matches: bool,
    pub esp_mount_matches: bool,
    pub boot_order_matches: bool,
    pub one_shot_matches: bool,
    pub zram_matches: bool,
    pub zswap_matches: bool,
    pub parents_safe: bool,
    pub transaction_hierarchy_safe: bool,
    pub staged_source_binary_matches: bool,
    pub validation_destinations_absent: bool,
    pub esp_free_bytes: u64,
    pub swap_free_bytes: u64,
    pub package_update_absent: bool,
    pub secure_boot_compatible: bool,
    pub ac_power: Option<bool>,
    pub stale_state_absent: bool,
    pub validation_process_absent: bool,
    pub unrelated_mutation_absent: bool,
    pub mutation_count: u64,
    pub ready: bool,
}

#[must_use]
pub fn derived_preflight_ready_v5(
    manifest: &TieringBootValidationPreparedManifestV5,
    o: &PreflightObservationV5,
) -> bool {
    [
        o.source_matches,
        o.binaries_match,
        o.config_matches,
        o.topology_matches,
        o.boot_matches,
        o.bootloader_type_matches,
        o.bootloader_version_matches,
        o.current_entry_semantics_match,
        o.current_entry_hash_matches,
        o.current_entry_path_matches,
        o.default_entry_semantics_match,
        o.default_entry_hash_matches,
        o.default_entry_path_matches,
        o.referenced_boot_files_match,
        o.kernel_release_matches,
        o.command_line_matches,
        o.esp_device_matches,
        o.esp_filesystem_matches,
        o.esp_uuid_matches,
        o.esp_mount_matches,
        o.boot_order_matches,
        o.one_shot_matches,
        o.zram_matches,
        o.zswap_matches,
        o.parents_safe,
        o.transaction_hierarchy_safe,
        o.staged_source_binary_matches,
        o.validation_destinations_absent,
        o.package_update_absent,
        o.secure_boot_compatible,
        o.stale_state_absent,
        o.validation_process_absent,
        o.unrelated_mutation_absent,
    ]
    .into_iter()
    .all(|gate| gate)
        && o.ac_power != Some(false)
        && o.esp_free_bytes >= 1024 * 1024
        && o.swap_free_bytes
            >= manifest
                .payload
                .swapfile
                .size_bytes
                .saturating_add(64 * 1024 * 1024)
}

pub fn validate_preflight_v5(
    manifest: &TieringBootValidationPreparedManifestV5,
    o: &PreflightObservationV5,
    root: bool,
) -> Result<(), BootValidationV5Error> {
    manifest.validate()?;
    if o.schema != PREFLIGHT_SCHEMA_V5 || o.mutation_count != 0 {
        return Err(BootValidationV5Error::Preflight(
            "not_non_mutating".to_owned(),
        ));
    }
    if o.host_identity_sha256 != manifest.payload.material_environment_sha256 {
        return Err(BootValidationV5Error::Identity("material environment"));
    }
    if root
        && (o.uid != 0
            || o.sudo_uid != Some(manifest.payload.prepared_uid)
            || o.sudo_gid != Some(manifest.payload.prepared_gid))
    {
        return Err(BootValidationV5Error::SudoIdentity);
    }
    if !root && (o.uid != manifest.payload.prepared_uid || o.gid != manifest.payload.prepared_gid) {
        return Err(BootValidationV5Error::Identity("preparing user"));
    }
    let derived_ready = derived_preflight_ready_v5(manifest, o);
    if o.ready != derived_ready {
        return Err(BootValidationV5Error::Preflight(
            "serialized_readiness_contradiction".to_owned(),
        ));
    }
    if !derived_ready {
        return Err(BootValidationV5Error::Preflight(
            "authoritative_gate_failed".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActualPostBootObservationV5 {
    pub schema: String,
    pub boot_id: String,
    pub booted_entry: String,
    pub command_line: String,
    pub kernel_release: String,
    pub zswap: ZswapIdentityV5,
    pub swaps: Vec<SwapIdentityV5>,
    pub protected_zram: ZramIdentityV5,
    pub topology: StorageTopologyIdentityV5,
    pub unit_active: bool,
    pub workload_scope_absent: bool,
    pub daemon_observe_only: bool,
    pub production_activation: bool,
    pub zswap_counters: BTreeMap<String, Option<u64>>,
    pub zswap_counters_before: BTreeMap<String, Option<u64>>,
    pub zswap_counter_deltas: BTreeMap<String, Option<u64>>,
    pub cgroup_path: String,
    pub workload_pid: u32,
    pub workload_start_ticks: u64,
    pub workload_ready: bool,
    pub workload_started: bool,
    pub workload_stopped: bool,
    pub progress_steps: u64,
    pub cgroup_oom_delta: Option<u64>,
    pub cgroup_oom_kill_delta: Option<u64>,
    pub host_oom_kill_delta: Option<u64>,
    pub memory_current_bytes: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    pub swap_current_bytes: Option<u64>,
    pub scoped_psi_some_micros: Option<u64>,
    pub block_write_bytes: Option<u64>,
    pub block_write_attribution: String,
    pub latency_ns: Option<u64>,
    pub bytes_touched: u64,
    pub throughput_bytes_per_second: Option<u64>,
    pub compression_ratio_milli: Option<u64>,
    pub refault_observed: bool,
    pub refault_content_verified: bool,
    pub oom: bool,
    pub oom_kill: bool,
    pub workload_completed: bool,
    pub workload_timeout: bool,
    pub runtime_observation: RuntimeObserveOnlyEvidenceV5,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeObserveOnlyEvidenceV5 {
    pub config_sha256: String,
    pub configured_observe_only: bool,
    pub nemord_active: bool,
    pub nemord_binary: Option<RuntimeBinaryIdentityV5>,
    pub effective_mode: Option<String>,
    pub production_tiering_unit_absent: bool,
    pub unexpected_nemor_units: Vec<String>,
    pub unexpected_nemor_cgroups: Vec<String>,
    pub production_activation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeBinaryIdentityV5 {
    pub path: PathBuf,
    pub sha256: String,
    pub pid: u32,
    pub start_ticks: u64,
}

pub fn validate_actual_post_boot_v5(
    manifest: &TieringBootValidationPreparedManifestV5,
    tx: &DurableTransactionV5,
    o: &ActualPostBootObservationV5,
) -> Result<(), BootValidationV5Error> {
    manifest.validate()?;
    tx.validate()?;
    if o.schema != POST_BOOT_EVIDENCE_SCHEMA_V5
        || tx.payload.stage != TransactionStageV5::PostBootMeasuring
        || o.boot_id == tx.payload.baseline_boot_id
    {
        return Err(BootValidationV5Error::Measurement("boot identity"));
    }
    let p = &manifest.payload;
    if o.booted_entry != p.experimental_entry.id
        || o.kernel_release != p.boot.kernel_release
        || o.command_line != p.experimental_entry.options
        || !o.command_line.contains(&p.validation_marker)
    {
        return Err(BootValidationV5Error::Measurement("boot readback"));
    }
    if o.zswap
        != (ZswapIdentityV5 {
            parameters: p.experimental_zswap.clone(),
        })
        || o.protected_zram != p.protected_zram
        || o.topology != p.topology
        || !o.unit_active
        || !o.workload_scope_absent
    {
        return Err(BootValidationV5Error::Measurement("runtime identity"));
    }
    let swap = o
        .swaps
        .iter()
        .find(|s| s.path == p.swapfile.path)
        .ok_or(BootValidationV5Error::Measurement("swap absent"))?;
    if !swap.active
        || swap.priority != p.swapfile.priority
        || !o.workload_completed
        || o.workload_timeout
        || !o.workload_ready
        || !o.workload_started
        || !o.workload_stopped
        || o.workload_pid == 0
        || o.workload_start_ticks == 0
        || o.cgroup_path.is_empty()
        || o.progress_steps == 0
        || o.bytes_touched == 0
        || !o.refault_content_verified
        || o.cgroup_oom_delta.is_none()
        || o.cgroup_oom_kill_delta.is_none()
        || o.cgroup_oom_delta != Some(0)
        || o.cgroup_oom_kill_delta != Some(0)
        || !matches!(
            o.block_write_attribution.as_str(),
            "physical-device-host-wide-noisy" | "bounded-physical-device-attributed"
        )
        || o.block_write_bytes.is_none()
        || o.latency_ns.is_none()
        || o.throughput_bytes_per_second.is_none()
        || o.compression_ratio_milli.is_none()
        || !o.refault_observed
        || o.block_write_bytes
            .is_some_and(|v| v > p.workload.maximum_write_bytes)
        || o.oom
        || o.oom_kill
        || !o.daemon_observe_only
        || !o.runtime_observation.configured_observe_only
        || o.runtime_observation.production_activation
        || !o.runtime_observation.production_tiering_unit_absent
        || o.runtime_observation.nemord_active != o.runtime_observation.nemord_binary.is_some()
        || o.runtime_observation.effective_mode.is_none()
        || o.runtime_observation
            .nemord_binary
            .as_ref()
            .is_some_and(|binary| {
                !binary.path.is_absolute()
                    || !is_sha256(&binary.sha256)
                    || binary.pid == 0
                    || binary.start_ticks == 0
            })
        || !o.runtime_observation.unexpected_nemor_units.is_empty()
        || !o.runtime_observation.unexpected_nemor_cgroups.is_empty()
        || o.production_activation
    {
        return Err(BootValidationV5Error::Measurement(
            "safety or measurement gate",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineRestoreObservationV5 {
    pub schema: String,
    pub boot_id: String,
    pub booted_entry: String,
    pub command_line: String,
    pub zswap: ZswapIdentityV5,
    pub protected_zram: ZramIdentityV5,
    pub swaps: Vec<SwapIdentityV5>,
    pub default_entry: String,
    pub boot_order: Vec<String>,
    pub one_shot: Option<String>,
    pub production_activation: bool,
}

pub fn verify_baseline_before_cleanup_v5(
    manifest: &TieringBootValidationPreparedManifestV5,
    tx: &DurableTransactionV5,
    o: &BaselineRestoreObservationV5,
) -> Result<(), BootValidationV5Error> {
    let p = &manifest.payload;
    if o.schema != FINAL_RESTORE_SCHEMA_V5
        || tx.payload.stage != TransactionStageV5::BaselineBoot
        || o.boot_id == tx.payload.baseline_boot_id
        || o.booted_entry != p.boot.current_entry.id
        || o.command_line != p.boot.current_command_line
        || o.command_line.contains(&p.validation_marker)
        || o.zswap != p.baseline_zswap
        || o.protected_zram != p.protected_zram
        || o.swaps != p.baseline_swaps
        || o.default_entry != p.boot.default_entry.id
        || o.boot_order != p.boot.boot_order
        || o.one_shot != p.boot.prior_one_shot
        || o.production_activation
    {
        return Err(BootValidationV5Error::Readback(
            "baseline must be proven before deletion",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SameHostZramBaselineEvidenceV5 {
    pub schema: String,
    pub validation_id: String,
    pub source_commit: String,
    pub source_state_sha256: String,
    pub environment_sha256: String,
    pub topology_sha256: String,
    pub workload_sha256: String,
    pub real: bool,
    pub oom: bool,
    pub safety_failure: bool,
    pub cleanup_passed: bool,
    pub final_restore_passed: bool,
    pub archive_sha256: String,
    pub raw_evidence_sha256: String,
    pub workload_protocol: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineMeasurementObservationV5 {
    pub schema: String,
    pub validation_id: String,
    pub boot_id: String,
    pub zram: ZramIdentityV5,
    pub zswap: ZswapIdentityV5,
    pub swaps: Vec<SwapIdentityV5>,
    pub workload_protocol: String,
    pub workload_sha256: String,
    pub bytes_touched: u64,
    pub latency_ns: Option<u64>,
    pub cgroup_oom_delta: Option<u64>,
    pub cgroup_oom_kill_delta: Option<u64>,
    pub content_verified: bool,
    pub cleanup_passed: bool,
    pub scope_absent: bool,
    pub production_activation: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SameHostProfileEvidenceV5 {
    pub schema: String,
    pub validation_id: String,
    pub profile: StorageProfile,
    pub source_commit: String,
    pub source_state_sha256: String,
    pub environment_sha256: String,
    pub topology_sha256: String,
    pub workload_sha256: String,
    pub real: bool,
    pub oom: bool,
    pub safety_failure: bool,
    pub cleanup_passed: bool,
    pub final_restore_passed: bool,
    pub write_budget_passed: bool,
    pub backing_write_bytes: Option<u64>,
    pub latency_ns: Option<u64>,
    pub archive_sha256: String,
    pub raw_evidence_sha256: String,
    pub workload_protocol: String,
    pub backing_write_confidence: String,
}

pub fn matching_same_host_evidence_v5(
    b: &SameHostZramBaselineEvidenceV5,
    p: &SameHostProfileEvidenceV5,
    profile: StorageProfile,
) -> bool {
    b.schema == ZRAM_BASELINE_EVIDENCE_V5
        && p.schema == PROFILE_BENCHMARK_EVIDENCE_V5
        && p.profile == profile
        && b.validation_id == p.validation_id
        && b.source_commit == p.source_commit
        && b.source_state_sha256 == p.source_state_sha256
        && b.environment_sha256 == p.environment_sha256
        && b.topology_sha256 == p.topology_sha256
        && b.workload_sha256 == p.workload_sha256
        && b.real
        && p.real
        && !b.oom
        && !p.oom
        && !b.safety_failure
        && !p.safety_failure
        && b.cleanup_passed
        && p.cleanup_passed
        && b.final_restore_passed
        && p.final_restore_passed
        && p.write_budget_passed
        && p.backing_write_bytes.is_some()
        && p.latency_ns.is_some()
        && is_sha256(&b.archive_sha256)
        && is_sha256(&p.archive_sha256)
        && is_sha256(&b.raw_evidence_sha256)
        && is_sha256(&p.raw_evidence_sha256)
        && b.workload_protocol == WORKLOAD_PROTOCOL_V5
        && p.workload_protocol == WORKLOAD_PROTOCOL_V5
        && p.backing_write_confidence == "bounded-physical-device-attributed"
}

pub fn recovery_action_v5(stage: TransactionStageV5, currently_experimental: bool) -> &'static str {
    use TransactionStageV5::*;
    match stage {
        Prepared | RootPreflighted | BaselineMeasuring | BaselineMeasured | Applying | Applied => {
            "remove_exact_owned_before_reboot"
        }
        OneShotSelecting | OneShotSelected if !currently_experimental => {
            "clear_exact_owned_oneshot_then_remove"
        }
        OneShotSelecting
        | OneShotSelected
        | ExperimentalBootDetected
        | ActivationPreparing
        | ZswapDisabling
        | ZswapParametersApplying
        | ZswapEnabling
        | SwapActivating
        | ActivationVerified
        | ActivationFailed
        | PostBootMeasuring
        | PostBootValidated
        | BaselineSelecting => "select_exact_baseline_oneshot_preserve_artifacts",
        BaselineSelected | BaselineBoot => "verify_baseline_preserve_artifacts",
        BaselineVerified | Cleaning => "resume_exact_cleanup",
        Restored | Recovered => "no_op",
        Failed => "inspect_primary_error_and_resume_stage_aware",
    }
}

/// The privileged implementation is deliberately expressed as narrow typed
/// operations.  Implementations may not execute caller-provided commands or
/// select caller-provided paths: every target comes from the sealed manifest.
pub trait BootLifecycleBackendV5 {
    fn persist_transaction(&mut self, transaction: &DurableTransactionV5) -> Result<(), String>;
    fn create_transaction_root(
        &mut self,
        manifest: &TieringBootValidationPreparedManifestV5,
    ) -> Result<(), String>;
    fn copy_prepared_manifest(
        &mut self,
        manifest: &TieringBootValidationPreparedManifestV5,
    ) -> Result<(), String>;
    fn persist_evidence(&mut self, name: &str, bytes: &[u8]) -> Result<(), String>;
    fn create_swapfile(
        &mut self,
        manifest: &TieringBootValidationPreparedManifestV5,
    ) -> Result<SwapIdentityV5, String>;
    fn create_artifact(&mut self, artifact: &OwnedArtifactV5) -> Result<(), String>;
    fn stage_helper(&mut self, plan: &StagedBinaryPlanV5) -> Result<(), String>;
    fn staged_helper_matches(&self, plan: &StagedBinaryPlanV5) -> bool;
    fn artifact_matches(&self, artifact: &OwnedArtifactV5) -> bool;
    fn artifact_absent(&self, artifact: &OwnedArtifactV5) -> bool;
    fn sync_parents(
        &mut self,
        manifest: &TieringBootValidationPreparedManifestV5,
    ) -> Result<(), String>;
    fn remove_artifact(&mut self, artifact: &OwnedArtifactV5) -> Result<(), String>;
    fn remove_swapfile(
        &mut self,
        manifest: &TieringBootValidationPreparedManifestV5,
    ) -> Result<(), String>;
    fn swapfile_absent(&self, manifest: &TieringBootValidationPreparedManifestV5) -> bool;
    fn finalize_runtime_cleanup(
        &mut self,
        manifest: &TieringBootValidationPreparedManifestV5,
    ) -> Result<(), String>;
    fn set_one_shot(&mut self, entry: &str) -> Result<(), String>;
    fn read_one_shot(&self) -> Result<Option<String>, String>;
    fn permanent_default(&self) -> Result<String, String>;
    fn boot_order(&self) -> Result<Vec<String>, String>;
    fn current_boot_is_experimental(
        &self,
        manifest: &TieringBootValidationPreparedManifestV5,
    ) -> bool;
    fn collect_zram_baseline(
        &mut self,
        manifest: &TieringBootValidationPreparedManifestV5,
    ) -> Result<BaselineMeasurementObservationV5, String>;
    fn collect_post_boot(
        &mut self,
        manifest: &TieringBootValidationPreparedManifestV5,
    ) -> Result<ActualPostBootObservationV5, String>;
    fn collect_baseline(
        &self,
        manifest: &TieringBootValidationPreparedManifestV5,
    ) -> Result<BaselineRestoreObservationV5, String>;
    fn seal_archive(&mut self, transaction: &DurableTransactionV5) -> Result<(), String>;
}

fn persist_or_fail<B: BootLifecycleBackendV5>(
    backend: &mut B,
    tx: &DurableTransactionV5,
) -> Result<(), BootValidationV5Error> {
    backend
        .persist_transaction(tx)
        .map_err(|_| BootValidationV5Error::Readback("durable transaction persistence"))
}

fn fail_transaction<B: BootLifecycleBackendV5>(
    backend: &mut B,
    tx: &mut DurableTransactionV5,
    primary: String,
    secondary: Vec<String>,
) -> BootValidationV5Error {
    tx.payload.failed_from_stage = Some(tx.payload.stage);
    tx.payload.primary_error = Some(primary.clone());
    tx.payload.secondary_errors.extend(secondary);
    tx.payload.stage = TransactionStageV5::Failed;
    tx.payload_sha256 = canonical_json_sha256_v5(&tx.payload);
    let _ = backend.persist_transaction(tx);
    BootValidationV5Error::Readback("bounded mutation failed; transaction retained")
}

fn rollback_partial_apply<B: BootLifecycleBackendV5>(
    manifest: &TieringBootValidationPreparedManifestV5,
    created: &[&OwnedArtifactV5],
    backend: &mut B,
) -> Vec<String> {
    let mut secondary = Vec::new();
    for artifact in created.iter().rev() {
        if let Err(error) = backend.remove_artifact(artifact) {
            secondary.push(error);
        }
    }
    if let Err(error) = backend.remove_swapfile(manifest) {
        secondary.push(error);
    }
    secondary
}

/// Creates the durable transaction and measures the same-host zram baseline
/// before any boot, swapfile, loader-entry, unit, or zswap mutation.
pub fn initialize_and_measure_baseline_v5<B: BootLifecycleBackendV5>(
    manifest: &TieringBootValidationPreparedManifestV5,
    root_preflight: &PreflightObservationV5,
    boot_id: String,
    backend: &mut B,
) -> Result<DurableTransactionV5, BootValidationV5Error> {
    validate_preflight_v5(manifest, root_preflight, true)?;
    let mut tx = DurableTransactionV5::new(manifest, boot_id)?;
    backend
        .create_transaction_root(manifest)
        .map_err(|_| BootValidationV5Error::Readback("create transaction root"))?;
    persist_or_fail(backend, &tx)?;
    backend
        .copy_prepared_manifest(manifest)
        .map_err(|_| BootValidationV5Error::Readback("copy prepared manifest"))?;
    let preflight_bytes =
        serde_json::to_vec(root_preflight).map_err(|_| BootValidationV5Error::Payload)?;
    backend
        .persist_evidence("root-preflight-v5.json", &preflight_bytes)
        .map_err(|_| BootValidationV5Error::Readback("persist root preflight"))?;
    tx.payload.evidence_hashes.insert(
        "root-preflight-v5.json".to_owned(),
        canonical_bytes_sha256(&preflight_bytes),
    );
    tx.payload_sha256 = canonical_json_sha256_v5(&tx.payload);
    tx.transition(TransactionStageV5::RootPreflighted)?;
    persist_or_fail(backend, &tx)?;
    tx.record_intent(
        "stage_trusted_baseline_helper",
        manifest.payload.staged_helper.destination.clone(),
    );
    persist_or_fail(backend, &tx)?;
    backend
        .stage_helper(&manifest.payload.staged_helper)
        .map_err(|primary| fail_transaction(backend, &mut tx, primary, Vec::new()))?;
    if !backend.staged_helper_matches(&manifest.payload.staged_helper) {
        return Err(fail_transaction(
            backend,
            &mut tx,
            "staged baseline helper readback mismatch".into(),
            Vec::new(),
        ));
    }
    tx.complete_last(manifest.payload.staged_helper.source.sha256.clone())?;
    persist_or_fail(backend, &tx)?;
    tx.transition(TransactionStageV5::BaselineMeasuring)?;
    persist_or_fail(backend, &tx)?;
    let observation = backend
        .collect_zram_baseline(manifest)
        .map_err(|primary| fail_transaction(backend, &mut tx, primary, Vec::new()))?;
    if observation.schema != ZRAM_BASELINE_EVIDENCE_V5
        || observation.validation_id != manifest.payload.validation_id
        || observation.boot_id != tx.payload.baseline_boot_id
        || observation.zram != manifest.payload.protected_zram
        || observation.zswap != manifest.payload.baseline_zswap
        || observation.swaps != manifest.payload.baseline_swaps
        || observation.workload_protocol != WORKLOAD_PROTOCOL_V5
        || !is_sha256(&observation.workload_sha256)
        || observation.bytes_touched == 0
        || observation.latency_ns.is_none()
        || observation.cgroup_oom_delta != Some(0)
        || observation.cgroup_oom_kill_delta != Some(0)
        || !observation.content_verified
        || !observation.cleanup_passed
        || !observation.scope_absent
        || observation.production_activation
    {
        return Err(fail_transaction(
            backend,
            &mut tx,
            "same-host zram baseline rejected".into(),
            Vec::new(),
        ));
    }
    let bytes = serde_json::to_vec(&observation).map_err(|_| BootValidationV5Error::Payload)?;
    backend
        .persist_evidence("zram-baseline-evidence-v2.json", &bytes)
        .map_err(|_| BootValidationV5Error::Readback("persist zram baseline"))?;
    tx.payload.evidence_hashes.insert(
        "zram-baseline-evidence-v2.json".into(),
        canonical_bytes_sha256(&bytes),
    );
    tx.payload_sha256 = canonical_json_sha256_v5(&tx.payload);
    tx.transition(TransactionStageV5::BaselineMeasured)?;
    persist_or_fail(backend, &tx)?;
    Ok(tx)
}

/// Applies only after the sealed same-host baseline exists in the durable
/// transaction. Each bounded mutation has a durable intent and readback.
pub fn apply_exact_transaction_v5<B: BootLifecycleBackendV5>(
    manifest: &TieringBootValidationPreparedManifestV5,
    tx: &mut DurableTransactionV5,
    backend: &mut B,
) -> Result<(), BootValidationV5Error> {
    manifest.validate()?;
    tx.validate()?;
    if tx.payload.stage != TransactionStageV5::BaselineMeasured
        || tx.payload.manifest_sha256 != canonical_json_sha256_v5(manifest)
        || !tx
            .payload
            .evidence_hashes
            .contains_key("zram-baseline-evidence-v2.json")
    {
        return Err(BootValidationV5Error::Transition);
    }
    tx.transition(TransactionStageV5::Applying)?;
    persist_or_fail(backend, tx)?;
    let mut completed_artifacts: Vec<&OwnedArtifactV5> = manifest
        .payload
        .owned_artifacts
        .iter()
        .filter(|artifact| artifact.kind == OwnedArtifactKindV5::HelperBinary)
        .collect();
    tx.record_intent(
        "create_btrfs_swapfile",
        manifest.payload.swapfile.path.clone(),
    );
    persist_or_fail(backend, tx)?;
    let applied_swap = match backend.create_swapfile(manifest) {
        Ok(identity) => identity,
        Err(primary) => return Err(fail_transaction(backend, tx, primary, Vec::new())),
    };
    tx.payload.applied_swap_identity = Some(applied_swap.clone());
    tx.payload_sha256 = canonical_json_sha256_v5(&tx.payload);
    persist_or_fail(backend, tx)?;
    if applied_swap.path != manifest.payload.swapfile.path
        || applied_swap.size_bytes != manifest.payload.swapfile.size_bytes
        || applied_swap.active
        || applied_swap.uuid.is_none()
    {
        let secondary = backend
            .remove_swapfile(manifest)
            .err()
            .into_iter()
            .collect();
        return Err(fail_transaction(
            backend,
            tx,
            "created swap identity mismatch".into(),
            secondary,
        ));
    }
    tx.complete_last(canonical_json_sha256_v5(&applied_swap))?;
    persist_or_fail(backend, tx)?;
    for artifact in &manifest.payload.owned_artifacts {
        if artifact.kind == OwnedArtifactKindV5::HelperBinary {
            if !backend.staged_helper_matches(&manifest.payload.staged_helper) {
                return Err(fail_transaction(
                    backend,
                    tx,
                    "pre-staged helper changed before apply".into(),
                    Vec::new(),
                ));
            }
            continue;
        }
        tx.record_intent("create_new_artifact", artifact.path.clone());
        persist_or_fail(backend, tx)?;
        let created = if artifact.kind == OwnedArtifactKindV5::HelperBinary {
            backend.stage_helper(&manifest.payload.staged_helper)
        } else {
            backend.create_artifact(artifact)
        };
        if let Err(primary) = created {
            let secondary = rollback_partial_apply(manifest, &completed_artifacts, backend);
            return Err(fail_transaction(backend, tx, primary, secondary));
        }
        let matches = if artifact.kind == OwnedArtifactKindV5::HelperBinary {
            backend.staged_helper_matches(&manifest.payload.staged_helper)
        } else {
            backend.artifact_matches(artifact)
        };
        if !matches {
            let primary = format!("artifact readback failed: {}", artifact.path.display());
            let mut secondary = Vec::new();
            if let Err(error) = backend.remove_artifact(artifact) {
                secondary.push(error);
            }
            secondary.extend(rollback_partial_apply(
                manifest,
                &completed_artifacts,
                backend,
            ));
            return Err(fail_transaction(backend, tx, primary, secondary));
        }
        completed_artifacts.push(artifact);
        tx.complete_last(artifact.sha256.clone())?;
        persist_or_fail(backend, tx)?;
    }
    if let Err(primary) = backend.sync_parents(manifest) {
        let secondary = rollback_partial_apply(manifest, &completed_artifacts, backend);
        return Err(fail_transaction(backend, tx, primary, secondary));
    }
    if backend.permanent_default().ok().as_deref() != Some(&manifest.payload.boot.default_entry.id)
        || backend.boot_order().ok().as_ref() != Some(&manifest.payload.boot.boot_order)
    {
        let secondary = rollback_partial_apply(manifest, &completed_artifacts, backend);
        return Err(fail_transaction(
            backend,
            tx,
            "default or BootOrder changed".to_owned(),
            secondary,
        ));
    }
    let apply_evidence = serde_json::to_vec(&serde_json::json!({
        "schema": APPLY_EVIDENCE_SCHEMA_V5,
        "validation_id": &tx.payload.validation_id,
        "swap": &tx.payload.applied_swap_identity,
        "artifact_registry": &tx.payload.artifact_registry,
        "mutation_records": &tx.payload.mutation_records,
        "production_activation": false
    }))
    .map_err(|_| BootValidationV5Error::Payload)?;
    backend
        .persist_evidence("apply-evidence-v5.json", &apply_evidence)
        .map_err(|_| BootValidationV5Error::Readback("persist apply evidence"))?;
    tx.payload.evidence_hashes.insert(
        "apply-evidence-v5.json".into(),
        canonical_bytes_sha256(&apply_evidence),
    );
    tx.payload_sha256 = canonical_json_sha256_v5(&tx.payload);
    tx.transition(TransactionStageV5::Applied)?;
    persist_or_fail(backend, tx)?;
    Ok(())
}

pub fn select_exact_one_shot_v5<B: BootLifecycleBackendV5>(
    manifest: &TieringBootValidationPreparedManifestV5,
    tx: &mut DurableTransactionV5,
    backend: &mut B,
) -> Result<(), BootValidationV5Error> {
    manifest.validate()?;
    tx.validate()?;
    if !backend.staged_helper_matches(&manifest.payload.staged_helper) {
        return Err(BootValidationV5Error::Readback("staged helper"));
    }
    tx.transition(TransactionStageV5::OneShotSelecting)?;
    persist_or_fail(backend, tx)?;
    tx.record_intent(
        "set_oneshot",
        manifest.payload.experimental_entry.path.clone(),
    );
    persist_or_fail(backend, tx)?;
    if let Err(primary) = backend.set_one_shot(&manifest.payload.experimental_entry.id) {
        return Err(fail_transaction(backend, tx, primary, Vec::new()));
    }
    if backend.read_one_shot().ok().flatten().as_deref()
        != Some(&manifest.payload.experimental_entry.id)
        || backend.permanent_default().ok().as_deref()
            != Some(&manifest.payload.boot.default_entry.id)
        || backend.boot_order().ok().as_ref() != Some(&manifest.payload.boot.boot_order)
    {
        return Err(fail_transaction(
            backend,
            tx,
            "one-shot readback mismatch".into(),
            Vec::new(),
        ));
    }
    let one_shot_bytes = serde_json::to_vec(&serde_json::json!({
        "schema":"tiering-one-shot-evidence-v5",
        "requested":manifest.payload.experimental_entry.id,
        "effective":backend.read_one_shot().ok().flatten(),
        "default":backend.permanent_default().ok(),
        "boot_order":backend.boot_order().ok(),
    }))
    .map_err(|_| BootValidationV5Error::Payload)?;
    backend
        .persist_evidence("one-shot-evidence-v5.json", &one_shot_bytes)
        .map_err(|_| BootValidationV5Error::Readback("persist one-shot evidence"))?;
    tx.payload.evidence_hashes.insert(
        "one-shot-evidence-v5.json".into(),
        canonical_bytes_sha256(&one_shot_bytes),
    );
    tx.payload_sha256 = canonical_json_sha256_v5(&tx.payload);
    tx.complete_last(canonical_json_sha256_v5(
        &manifest.payload.experimental_entry,
    ))?;
    tx.transition(TransactionStageV5::OneShotSelected)?;
    persist_or_fail(backend, tx)
}

/// Collects measurements from the backend.  There is intentionally no
/// evidence argument, so a caller cannot submit success booleans or metrics.
pub fn collect_and_validate_post_boot_v5<B: BootLifecycleBackendV5>(
    manifest: &TieringBootValidationPreparedManifestV5,
    tx: &mut DurableTransactionV5,
    backend: &mut B,
) -> Result<ActualPostBootObservationV5, BootValidationV5Error> {
    if tx.payload.stage != TransactionStageV5::ActivationVerified {
        return Err(BootValidationV5Error::Transition);
    }
    if !backend.staged_helper_matches(&manifest.payload.staged_helper) {
        return Err(BootValidationV5Error::Readback(
            "staged helper after reboot",
        ));
    }
    tx.transition(TransactionStageV5::PostBootMeasuring)?;
    persist_or_fail(backend, tx)?;
    let observation = backend
        .collect_post_boot(manifest)
        .map_err(|primary| fail_transaction(backend, tx, primary, Vec::new()))?;
    validate_actual_post_boot_v5(manifest, tx, &observation)?;
    let bytes = serde_json::to_vec(&observation).map_err(|_| BootValidationV5Error::Payload)?;
    backend
        .persist_evidence("post-boot-evidence-v5.json", &bytes)
        .map_err(|_| BootValidationV5Error::Readback("persist post-boot evidence"))?;
    tx.payload.evidence_hashes.insert(
        "post-boot-evidence-v5.json".into(),
        canonical_bytes_sha256(&bytes),
    );
    tx.payload.post_boot_summary = Some(PostBootSummaryV5 {
        backing_write_bytes: observation.block_write_bytes.unwrap_or_default(),
        latency_ns: observation.latency_ns.unwrap_or_default(),
        write_budget_passed: observation
            .block_write_bytes
            .is_some_and(|bytes| bytes <= manifest.payload.workload.maximum_write_bytes),
        oom: observation.oom || observation.oom_kill,
        safety_failure: observation.production_activation
            || !observation.daemon_observe_only
            || !observation.workload_completed,
        backing_write_confidence: observation.block_write_attribution.clone(),
    });
    tx.payload_sha256 = canonical_json_sha256_v5(&tx.payload);
    tx.transition(TransactionStageV5::PostBootValidated)?;
    persist_or_fail(backend, tx)?;
    Ok(observation)
}

pub fn select_baseline_rollback_v5<B: BootLifecycleBackendV5>(
    manifest: &TieringBootValidationPreparedManifestV5,
    tx: &mut DurableTransactionV5,
    backend: &mut B,
) -> Result<(), BootValidationV5Error> {
    tx.transition(TransactionStageV5::BaselineSelecting)?;
    persist_or_fail(backend, tx)?;
    tx.record_intent(
        "set_baseline_oneshot",
        manifest.payload.boot.current_entry.path.clone(),
    );
    persist_or_fail(backend, tx)?;
    backend
        .set_one_shot(&manifest.payload.recovery_entry)
        .map_err(|primary| fail_transaction(backend, tx, primary, Vec::new()))?;
    if backend.read_one_shot().ok().flatten().as_deref() != Some(&manifest.payload.recovery_entry)
        || backend.permanent_default().ok().as_deref()
            != Some(&manifest.payload.boot.default_entry.id)
        || backend.boot_order().ok().as_ref() != Some(&manifest.payload.boot.boot_order)
    {
        return Err(fail_transaction(
            backend,
            tx,
            "baseline one-shot readback mismatch".into(),
            Vec::new(),
        ));
    }
    tx.complete_last(canonical_json_sha256_v5(&manifest.payload.recovery_entry))?;
    tx.transition(TransactionStageV5::BaselineSelected)?;
    persist_or_fail(backend, tx)
}

/// Proves the complete baseline before deleting anything. If verification
/// fails all boot/swap artifacts are intentionally preserved for diagnosis.
pub fn verify_then_cleanup_v5<B: BootLifecycleBackendV5>(
    manifest: &TieringBootValidationPreparedManifestV5,
    tx: &mut DurableTransactionV5,
    backend: &mut B,
) -> Result<(), BootValidationV5Error> {
    if tx.payload.stage == TransactionStageV5::BaselineSelected {
        tx.transition(TransactionStageV5::BaselineBoot)?;
        persist_or_fail(backend, tx)?;
    }
    let baseline = backend
        .collect_baseline(manifest)
        .map_err(|_| BootValidationV5Error::Readback("collect baseline"))?;
    verify_baseline_before_cleanup_v5(manifest, tx, &baseline)?;
    let bytes = serde_json::to_vec(&baseline).map_err(|_| BootValidationV5Error::Payload)?;
    backend
        .persist_evidence("baseline-restore-evidence-v5.json", &bytes)
        .map_err(|_| BootValidationV5Error::Readback("persist baseline evidence"))?;
    tx.payload.evidence_hashes.insert(
        "baseline-restore-evidence-v5.json".into(),
        canonical_bytes_sha256(&bytes),
    );
    tx.payload_sha256 = canonical_json_sha256_v5(&tx.payload);
    tx.transition(TransactionStageV5::BaselineVerified)?;
    persist_or_fail(backend, tx)?;
    tx.transition(TransactionStageV5::Cleaning)?;
    persist_or_fail(backend, tx)?;
    for artifact in manifest.payload.owned_artifacts.iter().rev() {
        tx.record_intent("remove_exact_artifact", artifact.path.clone());
        persist_or_fail(backend, tx)?;
        backend
            .remove_artifact(artifact)
            .map_err(|primary| fail_transaction(backend, tx, primary, Vec::new()))?;
        tx.complete_last("absent".into())?;
        persist_or_fail(backend, tx)?;
    }
    tx.record_intent(
        "remove_exact_swapfile",
        manifest.payload.swapfile.path.clone(),
    );
    persist_or_fail(backend, tx)?;
    backend
        .remove_swapfile(manifest)
        .map_err(|primary| fail_transaction(backend, tx, primary, Vec::new()))?;
    tx.complete_last("absent".into())?;
    if manifest
        .payload
        .owned_artifacts
        .iter()
        .any(|artifact| !backend.artifact_absent(artifact))
        || !backend.swapfile_absent(manifest)
    {
        return Err(fail_transaction(
            backend,
            tx,
            "final exact-owned absence verification failed".into(),
            Vec::new(),
        ));
    }
    backend
        .finalize_runtime_cleanup(manifest)
        .map_err(|primary| fail_transaction(backend, tx, primary, Vec::new()))?;
    let baseline_raw = tx
        .payload
        .evidence_hashes
        .get("zram-baseline-evidence-v2.json")
        .cloned()
        .ok_or(BootValidationV5Error::Readback("baseline raw evidence"))?;
    let profile_raw = tx
        .payload
        .evidence_hashes
        .get("post-boot-evidence-v5.json")
        .cloned()
        .ok_or(BootValidationV5Error::Readback("profile raw evidence"))?;
    let summary = tx
        .payload
        .post_boot_summary
        .clone()
        .ok_or(BootValidationV5Error::Readback("profile summary"))?;
    let common_archive = tx.payload.manifest_sha256.clone();
    let baseline_authority = SameHostZramBaselineEvidenceV5 {
        schema: ZRAM_BASELINE_EVIDENCE_V5.into(),
        validation_id: manifest.payload.validation_id.clone(),
        source_commit: manifest.payload.source_commit.clone(),
        source_state_sha256: manifest.payload.source_state_sha256.clone(),
        environment_sha256: manifest.payload.material_environment_sha256.clone(),
        topology_sha256: canonical_json_sha256_v5(&manifest.payload.topology),
        workload_sha256: canonical_json_sha256_v5(&manifest.payload.workload),
        real: true,
        oom: false,
        safety_failure: false,
        cleanup_passed: true,
        final_restore_passed: true,
        archive_sha256: common_archive.clone(),
        raw_evidence_sha256: baseline_raw,
        workload_protocol: WORKLOAD_PROTOCOL_V5.into(),
    };
    let profile_authority = SameHostProfileEvidenceV5 {
        schema: PROFILE_BENCHMARK_EVIDENCE_V5.into(),
        validation_id: manifest.payload.validation_id.clone(),
        profile: manifest.payload.topology.profile,
        source_commit: manifest.payload.source_commit.clone(),
        source_state_sha256: manifest.payload.source_state_sha256.clone(),
        environment_sha256: manifest.payload.material_environment_sha256.clone(),
        topology_sha256: canonical_json_sha256_v5(&manifest.payload.topology),
        workload_sha256: canonical_json_sha256_v5(&manifest.payload.workload),
        real: true,
        oom: summary.oom,
        safety_failure: summary.safety_failure,
        cleanup_passed: true,
        final_restore_passed: true,
        write_budget_passed: summary.write_budget_passed,
        backing_write_bytes: Some(summary.backing_write_bytes),
        latency_ns: Some(summary.latency_ns),
        archive_sha256: common_archive,
        raw_evidence_sha256: profile_raw,
        workload_protocol: WORKLOAD_PROTOCOL_V5.into(),
        backing_write_confidence: summary.backing_write_confidence,
    };
    for (name, value) in [
        (
            "same-host-zram-baseline-v2.json",
            serde_json::to_vec(&baseline_authority),
        ),
        (
            "same-host-profile-v5.json",
            serde_json::to_vec(&profile_authority),
        ),
    ] {
        let bytes = value.map_err(|_| BootValidationV5Error::Payload)?;
        backend
            .persist_evidence(name, &bytes)
            .map_err(|_| BootValidationV5Error::Readback("persist same-host authority"))?;
        tx.payload
            .evidence_hashes
            .insert(name.into(), canonical_bytes_sha256(&bytes));
    }
    tx.payload_sha256 = canonical_json_sha256_v5(&tx.payload);
    tx.transition(TransactionStageV5::Restored)?;
    persist_or_fail(backend, tx)?;
    backend
        .seal_archive(tx)
        .map_err(|_| BootValidationV5Error::Readback("seal evidence archive"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }
    fn manifest() -> TieringBootValidationPreparedManifestV5 {
        let id = "phase6-sata-static-1".to_owned();
        let tx = Path::new(TRANSACTION_ROOT_V5).join(&id);
        let entry_path = Path::new(ENTRY_ROOT).join(format!("nemor-phase6-{id}.conf"));
        let current = BootEntryIdentityV5 {
            id: "linux.conf".into(),
            path: PathBuf::from("/boot/loader/entries/linux.conf"),
            sha256: h('a'),
            title: "Linux".into(),
            linux_or_efi: PathBuf::from("/vmlinuz-linux"),
            initrds: vec![PathBuf::from("/initramfs-linux.img")],
            options: "root=UUID=x quiet".into(),
        };
        let marker = format!("nemor.phase6_validation={id}");
        let experimental = BootEntryIdentityV5 {
            id: format!("nemor-phase6-{id}.conf"),
            path: entry_path.clone(),
            sha256: h('b'),
            title: "Nemor validation".into(),
            linux_or_efi: current.linux_or_efi.clone(),
            initrds: current.initrds.clone(),
            options: format!(
                "root=UUID=x quiet {marker} zswap.enabled=1 systemd.wants=nemor-phase6-{id}.service"
            ),
        };
        let topology = StorageTopologyIdentityV5 {
            storage_profile_version: crate::STORAGE_PROFILE_VERSION.into(),
            profile: StorageProfile::SataSsd,
            chain: vec![
                BlockLayerIdentityV5 {
                    path: PathBuf::from("/dev/sda2"),
                    kind: "part".into(),
                    major: 8,
                    minor: 2,
                    parent: Some(PathBuf::from("/dev/sda")),
                },
                BlockLayerIdentityV5 {
                    path: PathBuf::from("/dev/sda"),
                    kind: "disk".into(),
                    major: 8,
                    minor: 0,
                    parent: None,
                },
            ],
            physical: PhysicalDeviceIdentityV5 {
                path: PathBuf::from("/dev/sda"),
                major: 8,
                minor: 0,
                transport: "ata".into(),
                rotational: false,
                model: "Samsung".into(),
                serial: Some("serial".into()),
                wwn: None,
                capacity_bytes: 1_000_000_000,
                logical_block_size: 512,
                physical_block_size: 4096,
            },
            filesystem: FilesystemIdentityV5 {
                filesystem: "btrfs".into(),
                uuid_or_fsid: "fsid".into(),
                mount_source: PathBuf::from("/dev/sda2"),
                mount_point: PathBuf::from("/"),
                mount_id: 42,
                device_major: 8,
                device_minor: 2,
            },
            composite: false,
            ambiguous: false,
            confidence: "high".into(),
        };
        let zram = ZramIdentityV5 {
            device: PathBuf::from("/dev/zram0"),
            provider: "systemd-zram-generator".into(),
            active: true,
            priority: 100,
            disksize_bytes: 8 << 30,
            compressor: "zstd".into(),
            memory_limit_bytes: 0,
            unit: "dev-zram0.swap".into(),
        };
        let zswap = BTreeMap::from([
            ("enabled".into(), "Y".into()),
            ("compressor".into(), "zstd".into()),
            ("zpool".into(), "zsmalloc".into()),
            ("max_pool_percent".into(), "20".into()),
            ("accept_threshold_percent".into(), "90".into()),
            ("shrinker_enabled".into(), "N".into()),
        ]);
        let validator_path = PathBuf::from("/opt/nemor-validator");
        let mut payload = PreparedManifestPayloadV5 {
            contract_version: BOOT_VALIDATION_CONTRACT_VERSION_V5.into(),
            rule_version: TIERING_RULE_VERSION.into(),
            validation_id: id,
            prepared_uid: 1000,
            prepared_gid: 1000,
            source_commit: "a".repeat(40),
            source_state_sha256: h('1'),
            binaries: BTreeMap::from([(
                "nemor-tiering-boot-validation".into(),
                BinaryIdentityV5 {
                    path: validator_path.clone(),
                    sha256: h('2'),
                    embedded_commit: "a".repeat(40),
                },
            )]),
            config_path: PathBuf::from("/etc/nemor.toml"),
            config_sha256: h('3'),
            material_environment_sha256: h('4'),
            topology,
            baseline_swaps: vec![SwapIdentityV5 {
                path: PathBuf::from("/dev/zram0"),
                kind: "partition".into(),
                size_bytes: 8 << 30,
                priority: 100,
                uuid: None,
                active: true,
            }],
            protected_zram: zram,
            baseline_zswap: ZswapIdentityV5 {
                parameters: BTreeMap::from([
                    ("enabled".into(), "N".into()),
                    ("compressor".into(), "zstd".into()),
                    ("zpool".into(), "zsmalloc".into()),
                    ("max_pool_percent".into(), "20".into()),
                    ("accept_threshold_percent".into(), "90".into()),
                    ("shrinker_enabled".into(), "N".into()),
                ]),
            },
            experimental_zswap: zswap,
            boot: BootIdentityV5 {
                bootloader: "systemd-boot-type1".into(),
                bootloader_version: "systemd 261".into(),
                current_entry: current.clone(),
                default_entry: current.clone(),
                boot_order: vec!["0001".into()],
                prior_one_shot: None,
                esp_mount: PathBuf::from("/boot"),
                esp_device: "/dev/sda1".into(),
                esp_filesystem: "vfat".into(),
                esp_uuid: "ESP".into(),
                esp_mount_id: 7,
                esp_device_major: 8,
                esp_device_minor: 1,
                secure_boot: "disabled".into(),
                kernel_release: "linux".into(),
                referenced_files: vec![
                    ReferencedBootFileV5 {
                        path: current.linux_or_efi.clone(),
                        sha256: h('5'),
                    },
                    ReferencedBootFileV5 {
                        path: current.initrds[0].clone(),
                        sha256: h('6'),
                    },
                ],
                current_command_line: current.options.clone(),
            },
            experimental_entry: experimental,
            validation_marker: marker,
            swapfile: SwapIdentityV5 {
                path: tx.join("backing.swap"),
                kind: "file".into(),
                size_bytes: 64 << 20,
                priority: 110,
                uuid: None,
                active: false,
            },
            owned_artifacts: Vec::new(),
            transaction_root: tx.clone(),
            workload: WorkloadContractV5 {
                protocol: WORKLOAD_PROTOCOL_V5.into(),
                seed: 42,
                bytes: 16 << 20,
                iterations: 2,
                timeout_seconds: 60,
                maximum_write_bytes: 64 << 20,
            },
            staged_helper: StagedBinaryPlanV5 {
                source: BinaryIdentityV5 {
                    path: validator_path.clone(),
                    sha256: h('2'),
                    embedded_commit: "a".repeat(40),
                },
                destination: tx.join("bin/nemor-tiering-boot-validation"),
                destination_mode: 0o755,
                destination_uid: 0,
                destination_gid: 0,
                require_single_link: true,
                source_uid: 1000,
                source_gid: 1000,
                source_mode: 0o755,
                source_link_count: 1,
                source_device: 8,
                source_inode: 42,
            },
            recovery_entry: "linux.conf".into(),
            production_activation: false,
        };
        let entry_content = render_type1_entry_v5(&payload.experimental_entry).into_bytes();
        payload.experimental_entry.sha256 = canonical_bytes_sha256(&entry_content);
        let unit_path =
            Path::new(UNIT_ROOT).join(format!("nemor-phase6-{}.service", payload.validation_id));
        let unit_content =
            render_validation_unit_v5(&payload, &payload.staged_helper.destination).into_bytes();
        payload.owned_artifacts = vec![
            OwnedArtifactV5 {
                kind: OwnedArtifactKindV5::Type1Entry,
                path: entry_path,
                sha256: canonical_bytes_sha256(&entry_content),
                mode: 0o600,
                owner_uid: 0,
                owner_gid: 0,
                content: entry_content,
            },
            OwnedArtifactV5 {
                kind: OwnedArtifactKindV5::ValidationUnit,
                path: unit_path,
                sha256: canonical_bytes_sha256(&unit_content),
                mode: 0o644,
                owner_uid: 0,
                owner_gid: 0,
                content: unit_content,
            },
            OwnedArtifactV5 {
                kind: OwnedArtifactKindV5::HelperBinary,
                path: payload.staged_helper.destination.clone(),
                sha256: payload.staged_helper.source.sha256.clone(),
                mode: 0o755,
                owner_uid: 0,
                owner_gid: 0,
                content: Vec::new(),
            },
        ];
        TieringBootValidationPreparedManifestV5::seal(payload)
    }
    #[test]
    fn valid_manifest_is_integrity_bound() {
        manifest().validate().unwrap();
    }
    #[test]
    fn payload_tamper_is_rejected() {
        let mut m = manifest();
        m.payload.swapfile.size_bytes += 1;
        assert_eq!(m.validate(), Err(BootValidationV5Error::Payload));
    }
    #[test]
    fn unknown_zswap_parameter_is_rejected() {
        let mut m = manifest();
        m.payload
            .experimental_zswap
            .insert("evil".into(), "1".into());
        m = TieringBootValidationPreparedManifestV5::seal(m.payload);
        assert_eq!(m.validate(), Err(BootValidationV5Error::Zswap));
    }
    #[test]
    fn weak_topology_is_rejected() {
        let mut m = manifest();
        m.payload.topology.physical.serial = None;
        m = TieringBootValidationPreparedManifestV5::seal(m.payload);
        assert_eq!(m.validate(), Err(BootValidationV5Error::Topology));
    }
    #[test]
    fn arbitrary_artifact_path_is_rejected() {
        let mut m = manifest();
        m.payload.owned_artifacts[0].path = PathBuf::from("/usr/lib/evil");
        m = TieringBootValidationPreparedManifestV5::seal(m.payload);
        assert_eq!(m.validate(), Err(BootValidationV5Error::Path));
    }
    #[test]
    fn type1_references_must_be_frozen() {
        let mut m = manifest();
        m.payload.boot.referenced_files.pop();
        m = TieringBootValidationPreparedManifestV5::seal(m.payload);
        assert_eq!(m.validate(), Err(BootValidationV5Error::Entry));
    }
    #[test]
    fn swap_must_outrank_protected_zram() {
        let mut m = manifest();
        m.payload.swapfile.priority = 9;
        m = TieringBootValidationPreparedManifestV5::seal(m.payload);
        assert_eq!(m.validate(), Err(BootValidationV5Error::Swap));
    }
    fn observation(root: bool) -> PreflightObservationV5 {
        PreflightObservationV5 {
            schema: PREFLIGHT_SCHEMA_V5.into(),
            uid: if root { 0 } else { 1000 },
            gid: if root { 0 } else { 1000 },
            sudo_uid: root.then_some(1000),
            sudo_gid: root.then_some(1000),
            host_identity_sha256: h('4'),
            source_matches: true,
            binaries_match: true,
            config_matches: true,
            topology_matches: true,
            boot_matches: true,
            bootloader_type_matches: true,
            bootloader_version_matches: true,
            current_entry_semantics_match: true,
            current_entry_hash_matches: true,
            current_entry_path_matches: true,
            default_entry_semantics_match: true,
            default_entry_hash_matches: true,
            default_entry_path_matches: true,
            referenced_boot_files_match: true,
            kernel_release_matches: true,
            command_line_matches: true,
            esp_device_matches: true,
            esp_filesystem_matches: true,
            esp_uuid_matches: true,
            esp_mount_matches: true,
            boot_order_matches: true,
            one_shot_matches: true,
            zram_matches: true,
            zswap_matches: true,
            parents_safe: true,
            transaction_hierarchy_safe: true,
            staged_source_binary_matches: true,
            validation_destinations_absent: true,
            esp_free_bytes: 2 << 20,
            swap_free_bytes: 256 << 20,
            package_update_absent: true,
            secure_boot_compatible: true,
            ac_power: None,
            stale_state_absent: true,
            validation_process_absent: true,
            unrelated_mutation_absent: true,
            mutation_count: 0,
            ready: true,
        }
    }
    #[test]
    fn preflights_are_non_mutating_and_sudo_bound() {
        let m = manifest();
        validate_preflight_v5(&m, &observation(false), false).unwrap();
        validate_preflight_v5(&m, &observation(true), true).unwrap();
        let mut o = observation(true);
        o.sudo_uid = Some(1);
        assert_eq!(
            validate_preflight_v5(&m, &o, true),
            Err(BootValidationV5Error::SudoIdentity)
        );
    }
    #[test]
    fn all_legal_transitions_and_illegal_transition() {
        let m = manifest();
        let mut t = DurableTransactionV5::new(&m, "boot-a".into()).unwrap();
        for s in [
            TransactionStageV5::RootPreflighted,
            TransactionStageV5::BaselineMeasuring,
            TransactionStageV5::BaselineMeasured,
            TransactionStageV5::Applying,
            TransactionStageV5::Applied,
            TransactionStageV5::OneShotSelecting,
            TransactionStageV5::OneShotSelected,
            TransactionStageV5::ExperimentalBootDetected,
            TransactionStageV5::ActivationPreparing,
            TransactionStageV5::ZswapDisabling,
            TransactionStageV5::ZswapParametersApplying,
            TransactionStageV5::ZswapEnabling,
            TransactionStageV5::SwapActivating,
            TransactionStageV5::ActivationVerified,
            TransactionStageV5::PostBootMeasuring,
            TransactionStageV5::PostBootValidated,
            TransactionStageV5::BaselineSelecting,
            TransactionStageV5::BaselineSelected,
            TransactionStageV5::BaselineBoot,
            TransactionStageV5::BaselineVerified,
            TransactionStageV5::Cleaning,
            TransactionStageV5::Restored,
        ] {
            t.transition(s).unwrap();
        }
        assert_eq!(
            t.transition(TransactionStageV5::Applying),
            Err(BootValidationV5Error::Transition)
        );
    }
    #[test]
    fn mutation_intent_precedes_completion() {
        let m = manifest();
        let mut t = DurableTransactionV5::new(&m, "boot-a".into()).unwrap();
        t.record_intent("create", m.payload.experimental_entry.path.clone());
        assert!(!t.payload.mutation_records[0].completed);
        t.complete_last(h('f')).unwrap();
        assert!(t.payload.mutation_records[0].completed);
        t.validate().unwrap();
    }
    #[test]
    fn recovery_is_stage_aware_and_clean_is_noop() {
        assert_eq!(
            recovery_action_v5(TransactionStageV5::Applied, false),
            "remove_exact_owned_before_reboot"
        );
        assert_eq!(
            recovery_action_v5(TransactionStageV5::ActivationVerified, true),
            "select_exact_baseline_oneshot_preserve_artifacts"
        );
        assert_eq!(
            recovery_action_v5(TransactionStageV5::Restored, false),
            "no_op"
        );
    }
    fn post(
        m: &TieringBootValidationPreparedManifestV5,
    ) -> (DurableTransactionV5, ActualPostBootObservationV5) {
        let mut t = DurableTransactionV5::new(m, "a".into()).unwrap();
        for s in [
            TransactionStageV5::RootPreflighted,
            TransactionStageV5::BaselineMeasuring,
            TransactionStageV5::BaselineMeasured,
            TransactionStageV5::Applying,
            TransactionStageV5::Applied,
            TransactionStageV5::OneShotSelecting,
            TransactionStageV5::OneShotSelected,
            TransactionStageV5::ExperimentalBootDetected,
            TransactionStageV5::ActivationPreparing,
            TransactionStageV5::ZswapDisabling,
            TransactionStageV5::ZswapParametersApplying,
            TransactionStageV5::ZswapEnabling,
            TransactionStageV5::SwapActivating,
            TransactionStageV5::ActivationVerified,
            TransactionStageV5::PostBootMeasuring,
        ] {
            t.transition(s).unwrap();
        }
        let p = &m.payload;
        (
            t,
            ActualPostBootObservationV5 {
                schema: POST_BOOT_EVIDENCE_SCHEMA_V5.into(),
                boot_id: "b".into(),
                booted_entry: p.experimental_entry.id.clone(),
                command_line: p.experimental_entry.options.clone(),
                kernel_release: p.boot.kernel_release.clone(),
                zswap: ZswapIdentityV5 {
                    parameters: p.experimental_zswap.clone(),
                },
                swaps: vec![SwapIdentityV5 {
                    active: true,
                    uuid: Some("swap".into()),
                    ..p.swapfile.clone()
                }],
                protected_zram: p.protected_zram.clone(),
                topology: p.topology.clone(),
                unit_active: true,
                workload_scope_absent: true,
                daemon_observe_only: true,
                production_activation: false,
                zswap_counters: BTreeMap::from([("stored_pages".into(), Some(1))]),
                zswap_counters_before: BTreeMap::from([("stored_pages".into(), Some(0))]),
                zswap_counter_deltas: BTreeMap::from([("stored_pages".into(), Some(1))]),
                cgroup_path: "/nemor.slice/workload.scope".into(),
                workload_pid: 123,
                workload_start_ticks: 456,
                workload_ready: true,
                workload_started: true,
                workload_stopped: true,
                progress_steps: 4,
                cgroup_oom_delta: Some(0),
                cgroup_oom_kill_delta: Some(0),
                host_oom_kill_delta: Some(0),
                memory_current_bytes: Some(1),
                memory_peak_bytes: Some(1),
                swap_current_bytes: Some(1),
                scoped_psi_some_micros: Some(1),
                block_write_bytes: Some(4096),
                block_write_attribution: "physical-device-host-wide-noisy".into(),
                latency_ns: Some(1),
                bytes_touched: p.workload.bytes,
                throughput_bytes_per_second: Some(1),
                compression_ratio_milli: Some(2000),
                refault_observed: true,
                refault_content_verified: true,
                oom: false,
                oom_kill: false,
                workload_completed: true,
                workload_timeout: false,
                runtime_observation: RuntimeObserveOnlyEvidenceV5 {
                    config_sha256: p.config_sha256.clone(),
                    configured_observe_only: true,
                    nemord_active: false,
                    nemord_binary: None,
                    effective_mode: Some("absent".into()),
                    production_tiering_unit_absent: true,
                    unexpected_nemor_units: Vec::new(),
                    unexpected_nemor_cgroups: Vec::new(),
                    production_activation: false,
                },
            },
        )
    }
    #[test]
    fn post_boot_accepts_only_actual_complete_measurement() {
        let m = manifest();
        let (t, o) = post(&m);
        validate_actual_post_boot_v5(&m, &t, &o).unwrap();
        let mut bad = o;
        bad.oom_kill = true;
        assert!(validate_actual_post_boot_v5(&m, &t, &bad).is_err());
    }
    #[test]
    fn post_boot_requires_boot_transition_and_marker() {
        let m = manifest();
        let (t, mut o) = post(&m);
        o.boot_id = "a".into();
        assert!(validate_actual_post_boot_v5(&m, &t, &o).is_err());
        o.boot_id = "b".into();
        o.command_line = "quiet".into();
        assert!(validate_actual_post_boot_v5(&m, &t, &o).is_err());
    }
    #[test]
    fn baseline_is_proven_before_cleanup() {
        let m = manifest();
        let mut t = DurableTransactionV5::new(&m, "a".into()).unwrap();
        for s in [
            TransactionStageV5::RootPreflighted,
            TransactionStageV5::BaselineMeasuring,
            TransactionStageV5::BaselineMeasured,
            TransactionStageV5::Applying,
            TransactionStageV5::Applied,
            TransactionStageV5::OneShotSelecting,
            TransactionStageV5::OneShotSelected,
            TransactionStageV5::ExperimentalBootDetected,
            TransactionStageV5::ActivationPreparing,
            TransactionStageV5::ZswapDisabling,
            TransactionStageV5::ZswapParametersApplying,
            TransactionStageV5::ZswapEnabling,
            TransactionStageV5::SwapActivating,
            TransactionStageV5::ActivationVerified,
            TransactionStageV5::BaselineSelecting,
            TransactionStageV5::BaselineSelected,
            TransactionStageV5::BaselineBoot,
        ] {
            t.transition(s).unwrap();
        }
        let p = &m.payload;
        let o = BaselineRestoreObservationV5 {
            schema: FINAL_RESTORE_SCHEMA_V5.into(),
            boot_id: "c".into(),
            booted_entry: p.boot.current_entry.id.clone(),
            command_line: p.boot.current_command_line.clone(),
            zswap: p.baseline_zswap.clone(),
            protected_zram: p.protected_zram.clone(),
            swaps: p.baseline_swaps.clone(),
            default_entry: p.boot.default_entry.id.clone(),
            boot_order: p.boot.boot_order.clone(),
            one_shot: p.boot.prior_one_shot.clone(),
            production_activation: false,
        };
        verify_baseline_before_cleanup_v5(&m, &t, &o).unwrap();
        let mut bad = o;
        bad.command_line.push_str(" marker");
        assert!(verify_baseline_before_cleanup_v5(&m, &t, &bad).is_err());
    }
    #[test]
    fn same_host_evidence_rejects_cross_host() {
        let b = SameHostZramBaselineEvidenceV5 {
            schema: ZRAM_BASELINE_EVIDENCE_V5.into(),
            validation_id: "v".into(),
            source_commit: "a".repeat(40),
            source_state_sha256: h('1'),
            environment_sha256: h('2'),
            topology_sha256: h('3'),
            workload_sha256: h('4'),
            real: true,
            oom: false,
            safety_failure: false,
            cleanup_passed: true,
            final_restore_passed: true,
            archive_sha256: h('5'),
            raw_evidence_sha256: h('7'),
            workload_protocol: WORKLOAD_PROTOCOL_V5.into(),
        };
        let mut p = SameHostProfileEvidenceV5 {
            schema: PROFILE_BENCHMARK_EVIDENCE_V5.into(),
            validation_id: "v".into(),
            profile: StorageProfile::SataSsd,
            source_commit: b.source_commit.clone(),
            source_state_sha256: b.source_state_sha256.clone(),
            environment_sha256: b.environment_sha256.clone(),
            topology_sha256: b.topology_sha256.clone(),
            workload_sha256: b.workload_sha256.clone(),
            real: true,
            oom: false,
            safety_failure: false,
            cleanup_passed: true,
            final_restore_passed: true,
            write_budget_passed: true,
            backing_write_bytes: Some(1),
            latency_ns: Some(1),
            archive_sha256: h('6'),
            raw_evidence_sha256: h('8'),
            workload_protocol: WORKLOAD_PROTOCOL_V5.into(),
            backing_write_confidence: "bounded-physical-device-attributed".into(),
        };
        assert!(matching_same_host_evidence_v5(
            &b,
            &p,
            StorageProfile::SataSsd
        ));
        p.environment_sha256 = h('7');
        assert!(!matching_same_host_evidence_v5(
            &b,
            &p,
            StorageProfile::SataSsd
        ));
        assert!(!matching_same_host_evidence_v5(
            &b,
            &p,
            StorageProfile::NvmeSsd
        ));
    }

    #[test]
    fn v5_unit_executes_only_the_root_owned_staged_helper() {
        let m = manifest();
        let unit = m
            .payload
            .owned_artifacts
            .iter()
            .find(|artifact| artifact.kind == OwnedArtifactKindV5::ValidationUnit)
            .unwrap();
        let text = String::from_utf8(unit.content.clone()).unwrap();
        assert!(text.contains(m.payload.staged_helper.destination.to_str().unwrap()));
        assert!(!text.contains(m.payload.staged_helper.source.path.to_str().unwrap()));
        assert_eq!(m.payload.staged_helper.destination_mode, 0o755);
        assert!(m.payload.staged_helper.require_single_link);
    }

    #[test]
    fn staged_helper_identity_is_not_self_declared_content() {
        let mut m = manifest();
        let helper = m
            .payload
            .owned_artifacts
            .iter_mut()
            .find(|artifact| artifact.kind == OwnedArtifactKindV5::HelperBinary)
            .unwrap();
        helper.content = vec![1, 2, 3];
        m = TieringBootValidationPreparedManifestV5::seal(m.payload);
        assert_eq!(
            m.validate(),
            Err(BootValidationV5Error::Identity("staged helper artifact"))
        );
    }

    #[test]
    fn full_preflight_readiness_is_auditable_conjunction() {
        let m = manifest();
        let mut o = observation(true);
        o.current_entry_hash_matches = false;
        o.ready = true;
        assert_eq!(
            validate_preflight_v5(&m, &o, true),
            Err(BootValidationV5Error::Preflight(
                "serialized_readiness_contradiction".into()
            ))
        );
        o.ready = derived_preflight_ready_v5(&m, &o);
        assert!(!o.ready);
        assert!(validate_preflight_v5(&m, &o, true).is_err());
    }

    #[test]
    fn every_activation_substage_is_monotonic_and_duplicate_activation_is_illegal() {
        let stages = [
            TransactionStageV5::OneShotSelected,
            TransactionStageV5::ExperimentalBootDetected,
            TransactionStageV5::ActivationPreparing,
            TransactionStageV5::ZswapDisabling,
            TransactionStageV5::ZswapParametersApplying,
            TransactionStageV5::ZswapEnabling,
            TransactionStageV5::SwapActivating,
            TransactionStageV5::ActivationVerified,
        ];
        for pair in stages.windows(2) {
            assert!(legal_transition_v5(pair[0], pair[1]));
        }
        assert!(!legal_transition_v5(
            TransactionStageV5::ActivationVerified,
            TransactionStageV5::ActivationPreparing
        ));
    }

    #[test]
    fn post_boot_measuring_and_each_activation_failure_can_select_baseline() {
        for stage in [
            TransactionStageV5::ActivationPreparing,
            TransactionStageV5::ZswapDisabling,
            TransactionStageV5::ZswapParametersApplying,
            TransactionStageV5::ZswapEnabling,
            TransactionStageV5::SwapActivating,
            TransactionStageV5::ActivationFailed,
            TransactionStageV5::PostBootMeasuring,
        ] {
            assert!(legal_transition_v5(
                stage,
                TransactionStageV5::BaselineSelecting
            ));
            assert_eq!(
                recovery_action_v5(stage, true),
                "select_exact_baseline_oneshot_preserve_artifacts"
            );
        }
    }

    #[test]
    fn mutation_intent_is_bound_to_the_current_boot_id() {
        let m = manifest();
        let mut tx = DurableTransactionV5::new(&m, "boot-a".into()).unwrap();
        tx.payload.current_boot_id = "boot-b".into();
        tx.payload_sha256 = canonical_json_sha256_v5(&tx.payload);
        tx.record_intent("write_zswap_parameter", PathBuf::from("/sys/example"));
        assert_eq!(
            tx.payload.mutation_records.last().unwrap().boot_id,
            "boot-b"
        );
    }

    #[test]
    fn apply_cannot_bypass_the_sealed_same_host_baseline() {
        let m = manifest();
        let mut tx = DurableTransactionV5::new(&m, "boot-a".into()).unwrap();
        let mut backend = FakeLifecycle::default();
        assert_eq!(
            apply_exact_transaction_v5(&m, &mut tx, &mut backend),
            Err(BootValidationV5Error::Transition)
        );
        assert_eq!(backend.mutations, 0);
    }

    #[test]
    fn noisy_physical_write_evidence_never_authorizes_recommendation() {
        let (b, mut p) = {
            let m = manifest();
            let baseline = SameHostZramBaselineEvidenceV5 {
                schema: ZRAM_BASELINE_EVIDENCE_V5.into(),
                validation_id: m.payload.validation_id.clone(),
                source_commit: m.payload.source_commit.clone(),
                source_state_sha256: m.payload.source_state_sha256.clone(),
                environment_sha256: m.payload.material_environment_sha256.clone(),
                topology_sha256: h('1'),
                workload_sha256: h('2'),
                real: true,
                oom: false,
                safety_failure: false,
                cleanup_passed: true,
                final_restore_passed: true,
                archive_sha256: h('3'),
                raw_evidence_sha256: h('4'),
                workload_protocol: WORKLOAD_PROTOCOL_V5.into(),
            };
            let profile = SameHostProfileEvidenceV5 {
                schema: PROFILE_BENCHMARK_EVIDENCE_V5.into(),
                validation_id: baseline.validation_id.clone(),
                profile: StorageProfile::SataSsd,
                source_commit: baseline.source_commit.clone(),
                source_state_sha256: baseline.source_state_sha256.clone(),
                environment_sha256: baseline.environment_sha256.clone(),
                topology_sha256: baseline.topology_sha256.clone(),
                workload_sha256: baseline.workload_sha256.clone(),
                real: true,
                oom: false,
                safety_failure: false,
                cleanup_passed: true,
                final_restore_passed: true,
                write_budget_passed: true,
                backing_write_bytes: Some(1),
                latency_ns: Some(1),
                archive_sha256: h('5'),
                raw_evidence_sha256: h('6'),
                workload_protocol: WORKLOAD_PROTOCOL_V5.into(),
                backing_write_confidence: "physical-device-host-wide-noisy".into(),
            };
            (baseline, profile)
        };
        assert!(!matching_same_host_evidence_v5(
            &b,
            &p,
            StorageProfile::SataSsd
        ));
        p.backing_write_confidence = "bounded-physical-device-attributed".into();
        assert!(matching_same_host_evidence_v5(
            &b,
            &p,
            StorageProfile::SataSsd
        ));
    }

    #[test]
    fn config_only_observe_claim_cannot_authorize_post_boot() {
        let m = manifest();
        let (tx, mut actual) = post(&m);
        actual.runtime_observation.nemord_active = true;
        actual.runtime_observation.nemord_binary = None;
        assert!(validate_actual_post_boot_v5(&m, &tx, &actual).is_err());
    }

    #[test]
    fn unavailable_cgroup_oom_is_not_reinterpreted_as_zero() {
        let m = manifest();
        let (tx, mut actual) = post(&m);
        actual.cgroup_oom_delta = None;
        assert!(validate_actual_post_boot_v5(&m, &tx, &actual).is_err());
    }

    #[test]
    fn v1_and_v2_contracts_are_historical_not_v5_authority() {
        let m = manifest();
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(
            json.get("schema").and_then(serde_json::Value::as_str),
            Some(PREPARED_MANIFEST_SCHEMA_V5)
        );
        assert_ne!(
            PREPARED_MANIFEST_SCHEMA_V5,
            crate::boot_validation_v2::PREPARED_MANIFEST_SCHEMA_V2
        );
        assert_ne!(
            BOOT_VALIDATION_CONTRACT_VERSION_V5,
            crate::boot_validation_v2::BOOT_VALIDATION_CONTRACT_VERSION_V2
        );
    }

    #[derive(Default)]
    struct FakeLifecycle {
        persisted: Vec<TransactionStageV5>,
        artifacts: BTreeSet<PathBuf>,
        swap: bool,
        one_shot: Option<String>,
        wrong_one_shot_readback: bool,
        fail_artifact_at: Option<usize>,
        artifact_calls: usize,
        post: Option<ActualPostBootObservationV5>,
        baseline: Option<BaselineRestoreObservationV5>,
        mutations: usize,
    }

    impl BootLifecycleBackendV5 for FakeLifecycle {
        fn persist_transaction(&mut self, t: &DurableTransactionV5) -> Result<(), String> {
            t.validate().map_err(|e| e.to_string())?;
            self.persisted.push(t.payload.stage);
            Ok(())
        }
        fn create_transaction_root(
            &mut self,
            _: &TieringBootValidationPreparedManifestV5,
        ) -> Result<(), String> {
            self.mutations += 1;
            Ok(())
        }
        fn copy_prepared_manifest(
            &mut self,
            _: &TieringBootValidationPreparedManifestV5,
        ) -> Result<(), String> {
            self.mutations += 1;
            Ok(())
        }
        fn persist_evidence(&mut self, _: &str, _: &[u8]) -> Result<(), String> {
            Ok(())
        }
        fn create_swapfile(
            &mut self,
            manifest: &TieringBootValidationPreparedManifestV5,
        ) -> Result<SwapIdentityV5, String> {
            self.mutations += 1;
            self.swap = true;
            Ok(SwapIdentityV5 {
                uuid: Some("owned-swap-uuid".into()),
                ..manifest.payload.swapfile.clone()
            })
        }
        fn create_artifact(&mut self, a: &OwnedArtifactV5) -> Result<(), String> {
            self.artifact_calls += 1;
            self.mutations += 1;
            if self.fail_artifact_at == Some(self.artifact_calls) {
                return Err("primary create failure".into());
            }
            self.artifacts.insert(a.path.clone());
            Ok(())
        }
        fn stage_helper(&mut self, plan: &StagedBinaryPlanV5) -> Result<(), String> {
            self.artifacts.insert(plan.destination.clone());
            Ok(())
        }
        fn staged_helper_matches(&self, plan: &StagedBinaryPlanV5) -> bool {
            self.artifacts.contains(&plan.destination)
        }
        fn artifact_matches(&self, a: &OwnedArtifactV5) -> bool {
            self.artifacts.contains(&a.path)
        }
        fn artifact_absent(&self, a: &OwnedArtifactV5) -> bool {
            !self.artifacts.contains(&a.path)
        }
        fn sync_parents(
            &mut self,
            _: &TieringBootValidationPreparedManifestV5,
        ) -> Result<(), String> {
            self.mutations += 1;
            Ok(())
        }
        fn remove_artifact(&mut self, a: &OwnedArtifactV5) -> Result<(), String> {
            self.mutations += 1;
            self.artifacts.remove(&a.path);
            Ok(())
        }
        fn remove_swapfile(
            &mut self,
            _: &TieringBootValidationPreparedManifestV5,
        ) -> Result<(), String> {
            self.mutations += 1;
            self.swap = false;
            Ok(())
        }
        fn swapfile_absent(&self, _: &TieringBootValidationPreparedManifestV5) -> bool {
            !self.swap
        }
        fn finalize_runtime_cleanup(
            &mut self,
            _: &TieringBootValidationPreparedManifestV5,
        ) -> Result<(), String> {
            Ok(())
        }
        fn set_one_shot(&mut self, e: &str) -> Result<(), String> {
            self.mutations += 1;
            self.one_shot = Some(e.into());
            Ok(())
        }
        fn read_one_shot(&self) -> Result<Option<String>, String> {
            if self.wrong_one_shot_readback {
                Ok(Some("foreign.conf".into()))
            } else {
                Ok(self.one_shot.clone())
            }
        }
        fn permanent_default(&self) -> Result<String, String> {
            Ok("linux.conf".into())
        }
        fn boot_order(&self) -> Result<Vec<String>, String> {
            Ok(vec!["0001".into()])
        }
        fn current_boot_is_experimental(
            &self,
            _: &TieringBootValidationPreparedManifestV5,
        ) -> bool {
            false
        }
        fn collect_zram_baseline(
            &mut self,
            m: &TieringBootValidationPreparedManifestV5,
        ) -> Result<BaselineMeasurementObservationV5, String> {
            Ok(BaselineMeasurementObservationV5 {
                schema: ZRAM_BASELINE_EVIDENCE_V5.into(),
                validation_id: m.payload.validation_id.clone(),
                boot_id: "boot-a".into(),
                zram: m.payload.protected_zram.clone(),
                zswap: m.payload.baseline_zswap.clone(),
                swaps: m.payload.baseline_swaps.clone(),
                workload_protocol: WORKLOAD_PROTOCOL_V5.into(),
                workload_sha256: canonical_json_sha256_v5(&m.payload.workload),
                bytes_touched: m.payload.workload.bytes,
                latency_ns: Some(1),
                cgroup_oom_delta: Some(0),
                cgroup_oom_kill_delta: Some(0),
                content_verified: true,
                cleanup_passed: true,
                scope_absent: true,
                production_activation: false,
            })
        }
        fn collect_post_boot(
            &mut self,
            _: &TieringBootValidationPreparedManifestV5,
        ) -> Result<ActualPostBootObservationV5, String> {
            self.post
                .clone()
                .ok_or_else(|| "missing actual measurement".into())
        }
        fn collect_baseline(
            &self,
            _: &TieringBootValidationPreparedManifestV5,
        ) -> Result<BaselineRestoreObservationV5, String> {
            self.baseline
                .clone()
                .ok_or_else(|| "missing baseline".into())
        }
        fn seal_archive(&mut self, _: &DurableTransactionV5) -> Result<(), String> {
            Ok(())
        }
    }

    fn initialized_tx(
        m: &TieringBootValidationPreparedManifestV5,
        b: &mut FakeLifecycle,
    ) -> DurableTransactionV5 {
        initialize_and_measure_baseline_v5(m, &observation(true), "boot-a".into(), b).unwrap()
    }

    #[test]
    fn apply_persists_before_each_bounded_mutation() {
        let m = manifest();
        let mut b = FakeLifecycle::default();
        let mut tx = initialized_tx(&m, &mut b);
        apply_exact_transaction_v5(&m, &mut tx, &mut b).unwrap();
        assert_eq!(tx.payload.stage, TransactionStageV5::Applied);
        assert!(b.swap);
        assert_eq!(b.artifacts.len(), 3);
        for required in [
            TransactionStageV5::Prepared,
            TransactionStageV5::RootPreflighted,
            TransactionStageV5::BaselineMeasuring,
            TransactionStageV5::BaselineMeasured,
            TransactionStageV5::Applying,
            TransactionStageV5::Applied,
        ] {
            assert!(b.persisted.contains(&required));
        }
        assert!(tx.payload.mutation_records.iter().all(|r| r.completed));
    }

    #[test]
    fn partial_apply_preserves_primary_error_and_rolls_back_exact_owned() {
        let m = manifest();
        let mut b = FakeLifecycle {
            fail_artifact_at: Some(2),
            ..Default::default()
        };
        let mut tx = initialized_tx(&m, &mut b);
        assert!(apply_exact_transaction_v5(&m, &mut tx, &mut b).is_err());
        assert!(!b.swap);
        assert!(b.artifacts.is_empty());
        assert_eq!(b.persisted.last(), Some(&TransactionStageV5::Failed));
    }

    #[test]
    fn oneshot_exit_without_exact_readback_is_rejected() {
        let m = manifest();
        let mut b = FakeLifecycle::default();
        let mut tx = initialized_tx(&m, &mut b);
        apply_exact_transaction_v5(&m, &mut tx, &mut b).unwrap();
        b.wrong_one_shot_readback = true;
        assert!(select_exact_one_shot_v5(&m, &mut tx, &mut b).is_err());
        assert_eq!(
            tx.payload.primary_error.as_deref(),
            Some("one-shot readback mismatch")
        );
    }

    #[test]
    fn post_boot_api_collects_from_backend_not_caller() {
        let m = manifest();
        let (mut tx, actual) = post(&m);
        tx.payload.stage = TransactionStageV5::ActivationVerified;
        tx.payload_sha256 = canonical_json_sha256_v5(&tx.payload);
        let mut b = FakeLifecycle {
            post: Some(actual),
            ..Default::default()
        };
        b.artifacts
            .insert(m.payload.staged_helper.destination.clone());
        let observed = collect_and_validate_post_boot_v5(&m, &mut tx, &mut b).unwrap();
        assert!(observed.workload_completed);
        assert_eq!(tx.payload.stage, TransactionStageV5::PostBootValidated);
    }

    #[test]
    fn failed_baseline_verification_deletes_nothing() {
        let m = manifest();
        let mut b = FakeLifecycle::default();
        for a in &m.payload.owned_artifacts {
            b.artifacts.insert(a.path.clone());
        }
        b.swap = true;
        let mut tx = DurableTransactionV5::new(&m, "a".into()).unwrap();
        for s in [
            TransactionStageV5::RootPreflighted,
            TransactionStageV5::BaselineMeasuring,
            TransactionStageV5::BaselineMeasured,
            TransactionStageV5::Applying,
            TransactionStageV5::Applied,
            TransactionStageV5::OneShotSelecting,
            TransactionStageV5::OneShotSelected,
            TransactionStageV5::ExperimentalBootDetected,
            TransactionStageV5::ActivationPreparing,
            TransactionStageV5::ZswapDisabling,
            TransactionStageV5::ZswapParametersApplying,
            TransactionStageV5::ZswapEnabling,
            TransactionStageV5::SwapActivating,
            TransactionStageV5::ActivationVerified,
            TransactionStageV5::BaselineSelecting,
            TransactionStageV5::BaselineSelected,
        ] {
            tx.transition(s).unwrap();
        }
        assert!(verify_then_cleanup_v5(&m, &mut tx, &mut b).is_err());
        assert_eq!(b.artifacts.len(), 3);
        assert!(b.swap);
    }
}
