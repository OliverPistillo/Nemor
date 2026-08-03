//! Phase 6 boot-authority v4 boundary.
//!
//! Version four is deliberately additive: v1-v3 remain deserializable for
//! historical audit, but only these explicitly sealed records can authorize a
//! future mutation.
use crate::boot_validation_v3::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const BOOT_VALIDATION_CONTRACT_VERSION_V4: &str = "tiering-boot-validation-v4";
pub const PREPARED_MANIFEST_SCHEMA_V4: &str = "tiering-boot-prepared-manifest-v4";
pub const DURABLE_TRANSACTION_SCHEMA_V4: &str = "tiering-boot-transaction-v4";
pub const PREFLIGHT_SCHEMA_V4: &str = "tiering-boot-preflight-v4";
pub const WORKLOAD_PROTOCOL_V2: &str = "tiering-bounded-workload-v2";
pub const WORKLOAD_EVIDENCE_SCHEMA_V4: &str = "tiering-workload-evidence-v4";
pub const ACTIVATION_EVIDENCE_SCHEMA_V4: &str = "tiering-activation-evidence-v4";
pub const POST_BOOT_EVIDENCE_SCHEMA_V4: &str = "tiering-post-boot-evidence-v4";
pub const FINAL_RESTORE_SCHEMA_V4: &str = "tiering-final-restore-evidence-v4";
pub const RECOVERY_EVIDENCE_SCHEMA_V4: &str = "tiering-recovery-evidence-v4";
pub const ZRAM_BASELINE_EVIDENCE_V3: &str = "tiering-zram-baseline-v3";
pub const PROFILE_EVIDENCE_SCHEMA_V4: &str = "tiering-profile-evidence-v4";
pub const TIERING_RULE_VERSION_V3: &str = "tiering-rules-v3-storage-profile-comparison";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationFallbackPreconditionV4 {
    pub zram: ZramIdentityV3,
    pub baseline_zram: ZramIdentityV3,
    pub baseline_swaps: Vec<SwapIdentityV3>,
    pub current_swaps: Vec<SwapIdentityV3>,
    pub validation_swap: SwapIdentityV3,
    pub zswap: ZswapIdentityV3,
    pub baseline_zswap: ZswapIdentityV3,
}

impl ActivationFallbackPreconditionV4 {
    pub fn validate(&self) -> Result<(), BootValidationV3Error> {
        if self.zram != self.baseline_zram
            || !self.zram.active
            || self.zram.priority <= 0
            || self.baseline_swaps.is_empty()
            || self.validation_swap.active
            || self.current_swaps.iter().any(|s| {
                self.baseline_swaps.iter().find(|b| b.path == s.path) != Some(s)
                    && s.path != self.validation_swap.path
            })
            || self
                .zswap
                .parameters
                .keys()
                .any(|k| !self.baseline_zswap.parameters.contains_key(k))
        {
            return Err(BootValidationV3Error::Preflight(
                "protected zram or baseline swap changed".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HierarchyGateV4 {
    pub path: String,
    pub expected_mode: u32,
    pub root_owned: bool,
    pub regular_directory: bool,
    pub same_mount: bool,
    pub create_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicReconciliationEvidenceV4 {
    pub schema: String,
    pub old_present: bool,
    pub candidate_present: bool,
    pub promoted_candidate: bool,
    pub validation_id: String,
    pub manifest_sha256: String,
    pub candidate_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefaultEvidenceV4 {
    pub protocol: String,
    pub primary_start: u64,
    pub primary_length: u64,
    pub residency_before: Option<u64>,
    pub residency_after_pressure: Option<u64>,
    pub major_fault_delta: Option<u64>,
    pub refault_major_delta: Option<u64>,
    pub content_sha256_before: String,
    pub content_sha256_after: String,
    pub target_attributable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadMetricsV4 {
    pub schema: String,
    pub protocol: String,
    pub bytes_initialized: u64,
    pub bytes_written: u64,
    pub bytes_read_for_integrity: u64,
    pub bytes_read_for_refault: u64,
    pub logical_bytes_processed: u64,
    pub measured_service_window_ns: u64,
    pub refault: Option<RefaultEvidenceV4>,
}

impl WorkloadMetricsV4 {
    pub fn validate(&self) -> Result<(), BootValidationV3Error> {
        if self.schema != WORKLOAD_EVIDENCE_SCHEMA_V4
            || self.protocol != WORKLOAD_PROTOCOL_V2
            || self.measured_service_window_ns == 0
            || self.logical_bytes_processed
                != self
                    .bytes_initialized
                    .saturating_add(self.bytes_written)
                    .saturating_add(self.bytes_read_for_integrity)
                    .saturating_add(self.bytes_read_for_refault)
            || !self.refault.as_ref().is_some_and(|r| {
                r.protocol == WORKLOAD_PROTOCOL_V2
                    && r.target_attributable
                    && r.primary_length > 0
                    && r.content_sha256_before == r.content_sha256_after
            })
        {
            return Err(BootValidationV3Error::Measurement("v4 workload metrics"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeObserveOnlyEvidenceV4 {
    pub expected_config_sha256: String,
    pub active: bool,
    pub binary: Option<RuntimeBinaryIdentityV4>,
    pub effective_command_line: Option<String>,
    pub effective_mode: Option<String>,
    pub expected_unit: Option<String>,
    pub production_units_absent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeBinaryIdentityV4 {
    pub path: String,
    pub sha256: String,
    pub embedded_commit: Option<String>,
    pub pid: u32,
    pub start_ticks: u64,
}

impl RuntimeObserveOnlyEvidenceV4 {
    pub fn authorize(&self, frozen_config_sha256: &str) -> bool {
        self.expected_config_sha256 == frozen_config_sha256
            && self.production_units_absent
            && (!self.active
                || self.binary.as_ref().is_some_and(|b| {
                    b.path.starts_with('/')
                        && b.pid > 0
                        && b.start_ticks > 0
                        && b.sha256.len() == 64
                        && self.effective_mode.as_deref() == Some("observe-only")
                        && self.effective_command_line.is_some()
                }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRootV4 {
    pub schema: String,
    pub required_files: Vec<String>,
    pub raw_hashes: BTreeMap<String, String>,
    pub evidence_root_sha256: String,
    pub ledger_sha256: Option<String>,
    pub final_restore_verified: bool,
}

impl EvidenceRootV4 {
    pub fn seal(
        required_files: Vec<String>,
        raw_hashes: BTreeMap<String, String>,
        final_restore_verified: bool,
    ) -> Self {
        let payload = serde_json::to_vec(&(
            required_files.clone(),
            raw_hashes.clone(),
            final_restore_verified,
        ))
        .expect("serializable");
        Self {
            schema: "tiering-evidence-root-v4".into(),
            required_files,
            raw_hashes,
            evidence_root_sha256: hex::encode(Sha256::digest(payload)),
            ledger_sha256: None,
            final_restore_verified,
        }
    }
    pub fn validate(&self) -> bool {
        self.schema == "tiering-evidence-root-v4"
            && self.final_restore_verified
            && !self.required_files.is_empty()
            && self.required_files.iter().all(|p| {
                !p.is_empty()
                    && !p.starts_with('/')
                    && !p.contains("..")
                    && self
                        .raw_hashes
                        .get(p)
                        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
            })
            && self.required_files.windows(2).all(|w| w[0] < w[1])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecommendationComparisonV4 {
    pub schema: String,
    pub baseline_latency_ns: u64,
    pub profile_latency_ns: u64,
    pub baseline_bytes: u64,
    pub profile_bytes: u64,
    pub configured_max_latency_regression_percent: u8,
    pub configured_min_useful_benefit_percent: u8,
    pub safety_passed: bool,
    pub restore_passed: bool,
}

impl RecommendationComparisonV4 {
    pub fn authorizes(&self) -> bool {
        if self.schema != "tiering-recommendation-comparison-v4"
            || !self.safety_passed
            || !self.restore_passed
            || self.baseline_latency_ns == 0
        {
            return false;
        }
        let max = self
            .baseline_latency_ns
            .saturating_mul(100 + u64::from(self.configured_max_latency_regression_percent))
            / 100;
        let useful = self
            .profile_bytes
            .saturating_mul(100 + u64::from(self.configured_min_useful_benefit_percent))
            <= self.baseline_bytes.saturating_mul(100);
        self.profile_latency_ns <= max && useful
    }
}

pub fn v4_archive_identity(root: &EvidenceRootV4) -> Option<String> {
    root.validate().then(|| root.evidence_root_sha256.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(ch: u8) -> String {
        format!("{}", ch as char).repeat(64)
    }

    #[test]
    fn evidence_root_is_not_manifest_hash_and_requires_complete_membership() {
        let mut raw = BTreeMap::new();
        raw.insert("post.json".into(), hash(b'a'));
        let root = EvidenceRootV4::seal(vec!["post.json".into()], raw, true);
        assert!(root.validate());
        assert_eq!(
            v4_archive_identity(&root),
            Some(root.evidence_root_sha256.clone())
        );
        assert_ne!(root.evidence_root_sha256, hash(b'a'));
    }

    #[test]
    fn runtime_observe_only_requires_frozen_config_and_effective_mode() {
        let mut runtime = RuntimeObserveOnlyEvidenceV4 {
            expected_config_sha256: hash(b'a'),
            active: true,
            binary: Some(RuntimeBinaryIdentityV4 {
                path: "/usr/bin/nemord".into(),
                sha256: hash(b'b'),
                embedded_commit: Some(hash(b'c')[..40].into()),
                pid: 1,
                start_ticks: 2,
            }),
            effective_command_line: Some("--observe-only".into()),
            effective_mode: Some("observe-only".into()),
            expected_unit: Some("nemord.service".into()),
            production_units_absent: true,
        };
        assert!(runtime.authorize(&hash(b'a')));
        runtime.expected_config_sha256 = hash(b'd');
        assert!(!runtime.authorize(&hash(b'a')));
    }

    #[test]
    fn workload_metrics_require_target_attributable_refault_and_exact_bytes() {
        let metrics = WorkloadMetricsV4 {
            schema: WORKLOAD_EVIDENCE_SCHEMA_V4.into(),
            protocol: WORKLOAD_PROTOCOL_V2.into(),
            bytes_initialized: 10,
            bytes_written: 20,
            bytes_read_for_integrity: 30,
            bytes_read_for_refault: 40,
            logical_bytes_processed: 100,
            measured_service_window_ns: 1,
            refault: Some(RefaultEvidenceV4 {
                protocol: WORKLOAD_PROTOCOL_V2.into(),
                primary_start: 0,
                primary_length: 10,
                residency_before: Some(10),
                residency_after_pressure: Some(0),
                major_fault_delta: Some(1),
                refault_major_delta: Some(1),
                content_sha256_before: hash(b'a'),
                content_sha256_after: hash(b'a'),
                target_attributable: true,
            }),
        };
        assert!(metrics.validate().is_ok());
    }

    #[test]
    fn recommendation_requires_configured_useful_benefit_and_non_regression() {
        let comparison = RecommendationComparisonV4 {
            schema: "tiering-recommendation-comparison-v4".into(),
            baseline_latency_ns: 100,
            profile_latency_ns: 105,
            baseline_bytes: 100,
            profile_bytes: 80,
            configured_max_latency_regression_percent: 10,
            configured_min_useful_benefit_percent: 5,
            safety_passed: true,
            restore_passed: true,
        };
        assert!(comparison.authorizes());
        assert!(!RecommendationComparisonV4 {
            profile_bytes: 100,
            ..comparison
        }
        .authorizes());
    }
}
