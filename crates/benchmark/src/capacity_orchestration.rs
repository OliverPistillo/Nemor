//! Plan-only contract for a future `nemor_capacity` benchmark variant.
//!
//! This module deliberately has no Linux or executor dependency. It represents
//! an evidence-backed, exact-owned plan but never authorizes live activation.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const CAPACITY_ORCHESTRATION_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityComponent {
    DamonTelemetry,
    CgroupProtection,
    CompressionZram,
    StorageTiering,
    DamosReclaim,
    KsmEligibility,
}

impl CapacityComponent {
    const ORDER: [Self; 6] = [
        Self::DamonTelemetry,
        Self::CgroupProtection,
        Self::CompressionZram,
        Self::StorageTiering,
        Self::DamosReclaim,
        Self::KsmEligibility,
    ];

    const fn mutates(self) -> bool {
        true
    }

    const fn dependencies(self) -> &'static [Self] {
        match self {
            Self::DamosReclaim => &[Self::DamonTelemetry],
            _ => &[],
        }
    }

    fn required_capabilities(self) -> BTreeSet<CapacityCapability> {
        use CapacityCapability::*;
        match self {
            Self::DamonTelemetry => [DamonOwnedSession, DamonVaddr].into_iter().collect(),
            Self::CgroupProtection => [CgroupV2, MemoryController, SystemdTransientUnits]
                .into_iter()
                .collect(),
            Self::CompressionZram => [Swap, ZramControl].into_iter().collect(),
            Self::StorageTiering => [OwnedSwapfile, ValidatedBootTiering, Zswap]
                .into_iter()
                .collect(),
            Self::DamosReclaim => [DamosAddressFence, DamosPageout, DamonVaddr]
                .into_iter()
                .collect(),
            Self::KsmEligibility => [Ksm, KsmProcessOptIn].into_iter().collect(),
        }
    }

    const fn required_evidence(self) -> CapacityEvidencePrerequisite {
        match self {
            Self::DamonTelemetry => CapacityEvidencePrerequisite::DamonMonitor,
            Self::CgroupProtection => CapacityEvidencePrerequisite::OwnedCgroupHarness,
            Self::CompressionZram => CapacityEvidencePrerequisite::ZramLifecycle,
            Self::StorageTiering => CapacityEvidencePrerequisite::ZswapNvmeBoot,
            Self::DamosReclaim => CapacityEvidencePrerequisite::DamosReclaim,
            Self::KsmEligibility => CapacityEvidencePrerequisite::KsmSelective,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityCapability {
    CgroupV2,
    MemoryController,
    SystemdTransientUnits,
    Swap,
    ZramControl,
    Zswap,
    OwnedSwapfile,
    ValidatedBootTiering,
    DamonVaddr,
    DamonOwnedSession,
    DamosPageout,
    DamosAddressFence,
    Ksm,
    KsmProcessOptIn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityEvidencePrerequisite {
    OwnedCgroupHarness,
    ZramLifecycle,
    ZswapNvmeBoot,
    DamonMonitor,
    DamosReclaim,
    KsmSelective,
    CombinedProfileCompatibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityOwnershipBoundary {
    ExactOwned { resource_id: String },
    ReadOnlyHost,
    Ambiguous { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityComponentRequest {
    pub desired: bool,
    pub required: bool,
    pub ownership: CapacityOwnershipBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityComponentState {
    Eligible,
    Unavailable,
    Disallowed,
    Deferred,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityComponentPlan {
    pub component: CapacityComponent,
    pub state: CapacityComponentState,
    pub ownership: CapacityOwnershipBoundary,
    pub required_capabilities: BTreeSet<CapacityCapability>,
    pub missing_capabilities: BTreeSet<CapacityCapability>,
    pub required_evidence: CapacityEvidencePrerequisite,
    pub dependencies: Vec<CapacityComponent>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityEvaluationState {
    NotEvaluated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityOrchestrationInput {
    pub contract_version: u32,
    pub production_mode: String,
    pub allow_automatic_actions: bool,
    pub capabilities: BTreeSet<CapacityCapability>,
    pub evidence: BTreeSet<CapacityEvidencePrerequisite>,
    pub components: BTreeMap<CapacityComponent, CapacityComponentRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityOrchestrationPlan {
    pub contract_version: u32,
    pub variant: String,
    pub production_mode: String,
    pub allow_automatic_actions: bool,
    pub activation_authorized: bool,
    pub available_capabilities: BTreeSet<CapacityCapability>,
    pub evidence_prerequisites: BTreeSet<CapacityEvidencePrerequisite>,
    pub components: Vec<CapacityComponentPlan>,
    pub apply_order: Vec<CapacityComponent>,
    pub rollback_order: Vec<CapacityComponent>,
    pub host_oom_prohibited: bool,
    pub restore_failure_invalidates_result: bool,
    pub capacity_evaluation: CapacityEvaluationState,
    pub effectiveness_evaluation: CapacityEvaluationState,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CapacityContractError {
    #[error("unsupported capacity orchestration contract version {0}")]
    UnsupportedVersion(u32),
    #[error("capacity planning requires production mode `observe`")]
    ProductionModeChanged,
    #[error("capacity planning cannot enable automatic production actions")]
    AutomaticActionsEnabled,
    #[error("component {component:?} has ambiguous ownership: {reason}")]
    AmbiguousOwnership {
        component: CapacityComponent,
        reason: String,
    },
    #[error("required component {component:?} is missing capabilities: {missing:?}")]
    RequiredCapabilityMissing {
        component: CapacityComponent,
        missing: BTreeSet<CapacityCapability>,
    },
    #[error("required component {component:?} is missing evidence {evidence:?}")]
    RequiredEvidenceMissing {
        component: CapacityComponent,
        evidence: CapacityEvidencePrerequisite,
    },
    #[error("component {component:?} requires eligible dependency {dependency:?}")]
    DependencyMissing {
        component: CapacityComponent,
        dependency: CapacityComponent,
    },
    #[error("DAMOS and KSM cannot share the same exact-owned memory target")]
    IncompatibleOwnedTarget,
    #[error("multiple eligible mutating components require combined-profile evidence")]
    CombinedEvidenceMissing,
    #[error("capacity apply ordering is invalid")]
    InvalidApplyOrder,
    #[error("capacity rollback ordering is not the reverse apply order")]
    InvalidRollbackOrder,
    #[error("plan component state is inconsistent for {0:?}")]
    InconsistentComponentState(CapacityComponent),
    #[error("capacity plan must never authorize activation")]
    ActivationAuthorized,
    #[error("capacity plan attempted to claim an evaluation result")]
    EvaluationClaimed,
    #[error("capacity plan safety invariant is absent or inconsistent")]
    SafetyInvariantViolated,
    #[error("capacity plan component set is incomplete or duplicated")]
    InvalidComponentSet,
}

pub fn plan_capacity_orchestration(
    input: &CapacityOrchestrationInput,
) -> Result<CapacityOrchestrationPlan, CapacityContractError> {
    validate_input(input)?;
    let mut components = Vec::with_capacity(CapacityComponent::ORDER.len());

    for component in CapacityComponent::ORDER {
        let request =
            input
                .components
                .get(&component)
                .cloned()
                .unwrap_or(CapacityComponentRequest {
                    desired: false,
                    required: false,
                    ownership: CapacityOwnershipBoundary::ReadOnlyHost,
                });
        if let CapacityOwnershipBoundary::Ambiguous { reason } = &request.ownership {
            if request.desired {
                return Err(CapacityContractError::AmbiguousOwnership {
                    component,
                    reason: reason.clone(),
                });
            }
        }
        if component.mutates()
            && request.desired
            && !matches!(
                &request.ownership,
                CapacityOwnershipBoundary::ExactOwned { resource_id }
                    if !resource_id.is_empty()
            )
        {
            return Err(CapacityContractError::AmbiguousOwnership {
                component,
                reason: "mutating component is not bound to an exact-owned resource".into(),
            });
        }

        let required_capabilities = component.required_capabilities();
        let missing_capabilities = required_capabilities
            .difference(&input.capabilities)
            .copied()
            .collect::<BTreeSet<_>>();
        let required_evidence = component.required_evidence();
        let (state, reason) = if !request.desired {
            (
                CapacityComponentState::Deferred,
                Some("component was not selected".into()),
            )
        } else if !missing_capabilities.is_empty() {
            if request.required {
                return Err(CapacityContractError::RequiredCapabilityMissing {
                    component,
                    missing: missing_capabilities,
                });
            }
            (
                CapacityComponentState::Unavailable,
                Some("required capability is unavailable".into()),
            )
        } else if !input.evidence.contains(&required_evidence) {
            if request.required {
                return Err(CapacityContractError::RequiredEvidenceMissing {
                    component,
                    evidence: required_evidence,
                });
            }
            (
                CapacityComponentState::Deferred,
                Some("component evidence prerequisite is missing".into()),
            )
        } else {
            (CapacityComponentState::Eligible, None)
        };
        components.push(CapacityComponentPlan {
            component,
            state,
            ownership: request.ownership,
            required_capabilities,
            missing_capabilities,
            required_evidence,
            dependencies: component.dependencies().to_vec(),
            reason,
        });
    }

    enforce_dependencies(&components)?;
    enforce_incompatibilities(&components)?;
    let apply_order = components
        .iter()
        .filter(|item| item.state == CapacityComponentState::Eligible)
        .map(|item| item.component)
        .collect::<Vec<_>>();
    let mutating_count = apply_order
        .iter()
        .filter(|component| component.mutates())
        .count();
    if mutating_count > 1
        && !input
            .evidence
            .contains(&CapacityEvidencePrerequisite::CombinedProfileCompatibility)
    {
        return Err(CapacityContractError::CombinedEvidenceMissing);
    }
    let rollback_order = apply_order.iter().rev().copied().collect();
    let plan = CapacityOrchestrationPlan {
        contract_version: CAPACITY_ORCHESTRATION_CONTRACT_VERSION,
        variant: "nemor_capacity".into(),
        production_mode: input.production_mode.clone(),
        allow_automatic_actions: input.allow_automatic_actions,
        activation_authorized: false,
        available_capabilities: input.capabilities.clone(),
        evidence_prerequisites: input.evidence.clone(),
        components,
        apply_order,
        rollback_order,
        host_oom_prohibited: true,
        restore_failure_invalidates_result: true,
        capacity_evaluation: CapacityEvaluationState::NotEvaluated,
        effectiveness_evaluation: CapacityEvaluationState::NotEvaluated,
    };
    validate_capacity_orchestration_plan(&plan)?;
    Ok(plan)
}

pub fn validate_capacity_orchestration_plan(
    plan: &CapacityOrchestrationPlan,
) -> Result<(), CapacityContractError> {
    if plan.contract_version != CAPACITY_ORCHESTRATION_CONTRACT_VERSION {
        return Err(CapacityContractError::UnsupportedVersion(
            plan.contract_version,
        ));
    }
    if plan.production_mode != "observe" {
        return Err(CapacityContractError::ProductionModeChanged);
    }
    if plan.allow_automatic_actions {
        return Err(CapacityContractError::AutomaticActionsEnabled);
    }
    if plan.activation_authorized {
        return Err(CapacityContractError::ActivationAuthorized);
    }
    if plan.variant != "nemor_capacity"
        || !plan.host_oom_prohibited
        || !plan.restore_failure_invalidates_result
    {
        return Err(CapacityContractError::SafetyInvariantViolated);
    }
    if plan.capacity_evaluation != CapacityEvaluationState::NotEvaluated
        || plan.effectiveness_evaluation != CapacityEvaluationState::NotEvaluated
    {
        return Err(CapacityContractError::EvaluationClaimed);
    }
    let component_set = plan
        .components
        .iter()
        .map(|item| item.component)
        .collect::<BTreeSet<_>>();
    if plan.components.len() != CapacityComponent::ORDER.len()
        || component_set != CapacityComponent::ORDER.into_iter().collect()
    {
        return Err(CapacityContractError::InvalidComponentSet);
    }
    let eligible = plan
        .components
        .iter()
        .filter(|item| item.state == CapacityComponentState::Eligible)
        .map(|item| item.component)
        .collect::<BTreeSet<_>>();
    let expected_apply = CapacityComponent::ORDER
        .into_iter()
        .filter(|component| eligible.contains(component))
        .collect::<Vec<_>>();
    if plan.apply_order != expected_apply {
        return Err(CapacityContractError::InvalidApplyOrder);
    }
    if plan.rollback_order != plan.apply_order.iter().rev().copied().collect::<Vec<_>>() {
        return Err(CapacityContractError::InvalidRollbackOrder);
    }
    for item in &plan.components {
        if item.required_capabilities != item.component.required_capabilities()
            || item.required_evidence != item.component.required_evidence()
            || item.dependencies != item.component.dependencies()
        {
            return Err(CapacityContractError::InconsistentComponentState(
                item.component,
            ));
        }
        if item.state == CapacityComponentState::Eligible
            && (!item.missing_capabilities.is_empty()
                || !item
                    .required_capabilities
                    .is_subset(&plan.available_capabilities)
                || !plan
                    .evidence_prerequisites
                    .contains(&item.required_evidence)
                || item.reason.is_some()
                || !matches!(
                    &item.ownership,
                    CapacityOwnershipBoundary::ExactOwned { resource_id }
                        if !resource_id.is_empty()
                ))
        {
            return Err(CapacityContractError::InconsistentComponentState(
                item.component,
            ));
        }
        for dependency in &item.dependencies {
            if item.state == CapacityComponentState::Eligible && !eligible.contains(dependency) {
                return Err(CapacityContractError::DependencyMissing {
                    component: item.component,
                    dependency: *dependency,
                });
            }
        }
    }
    if eligible
        .iter()
        .filter(|component| component.mutates())
        .count()
        > 1
        && !plan
            .evidence_prerequisites
            .contains(&CapacityEvidencePrerequisite::CombinedProfileCompatibility)
    {
        return Err(CapacityContractError::CombinedEvidenceMissing);
    }
    Ok(())
}

fn validate_input(input: &CapacityOrchestrationInput) -> Result<(), CapacityContractError> {
    if input.contract_version != CAPACITY_ORCHESTRATION_CONTRACT_VERSION {
        return Err(CapacityContractError::UnsupportedVersion(
            input.contract_version,
        ));
    }
    if input.production_mode != "observe" {
        return Err(CapacityContractError::ProductionModeChanged);
    }
    if input.allow_automatic_actions {
        return Err(CapacityContractError::AutomaticActionsEnabled);
    }
    Ok(())
}

fn enforce_dependencies(components: &[CapacityComponentPlan]) -> Result<(), CapacityContractError> {
    let eligible = components
        .iter()
        .filter(|item| item.state == CapacityComponentState::Eligible)
        .map(|item| item.component)
        .collect::<BTreeSet<_>>();
    for item in components {
        for dependency in &item.dependencies {
            if item.state == CapacityComponentState::Eligible && !eligible.contains(dependency) {
                return Err(CapacityContractError::DependencyMissing {
                    component: item.component,
                    dependency: *dependency,
                });
            }
        }
    }
    Ok(())
}

fn enforce_incompatibilities(
    components: &[CapacityComponentPlan],
) -> Result<(), CapacityContractError> {
    let exact_id = |component| {
        components
            .iter()
            .find(|item| {
                item.component == component && item.state == CapacityComponentState::Eligible
            })
            .and_then(|item| match &item.ownership {
                CapacityOwnershipBoundary::ExactOwned { resource_id } => Some(resource_id.as_str()),
                _ => None,
            })
    };
    if exact_id(CapacityComponent::DamosReclaim).is_some()
        && exact_id(CapacityComponent::DamosReclaim) == exact_id(CapacityComponent::KsmEligibility)
    {
        return Err(CapacityContractError::IncompatibleOwnedTarget);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_capabilities() -> BTreeSet<CapacityCapability> {
        [
            CapacityCapability::CgroupV2,
            CapacityCapability::MemoryController,
            CapacityCapability::SystemdTransientUnits,
            CapacityCapability::Swap,
            CapacityCapability::ZramControl,
            CapacityCapability::Zswap,
            CapacityCapability::OwnedSwapfile,
            CapacityCapability::ValidatedBootTiering,
            CapacityCapability::DamonVaddr,
            CapacityCapability::DamonOwnedSession,
            CapacityCapability::DamosPageout,
            CapacityCapability::DamosAddressFence,
            CapacityCapability::Ksm,
            CapacityCapability::KsmProcessOptIn,
        ]
        .into_iter()
        .collect()
    }

    fn all_evidence() -> BTreeSet<CapacityEvidencePrerequisite> {
        [
            CapacityEvidencePrerequisite::OwnedCgroupHarness,
            CapacityEvidencePrerequisite::ZramLifecycle,
            CapacityEvidencePrerequisite::ZswapNvmeBoot,
            CapacityEvidencePrerequisite::DamonMonitor,
            CapacityEvidencePrerequisite::DamosReclaim,
            CapacityEvidencePrerequisite::KsmSelective,
            CapacityEvidencePrerequisite::CombinedProfileCompatibility,
        ]
        .into_iter()
        .collect()
    }

    fn request(resource_id: &str) -> CapacityComponentRequest {
        CapacityComponentRequest {
            desired: true,
            required: true,
            ownership: CapacityOwnershipBoundary::ExactOwned {
                resource_id: resource_id.into(),
            },
        }
    }

    fn full_input() -> CapacityOrchestrationInput {
        CapacityOrchestrationInput {
            contract_version: CAPACITY_ORCHESTRATION_CONTRACT_VERSION,
            production_mode: "observe".into(),
            allow_automatic_actions: false,
            capabilities: all_capabilities(),
            evidence: all_evidence(),
            components: BTreeMap::from([
                (
                    CapacityComponent::DamonTelemetry,
                    request("capacity-damon-session"),
                ),
                (
                    CapacityComponent::CgroupProtection,
                    request("capacity-cgroup"),
                ),
                (CapacityComponent::CompressionZram, request("capacity-zram")),
                (CapacityComponent::StorageTiering, request("capacity-tier")),
                (CapacityComponent::DamosReclaim, request("capacity-damos")),
                (CapacityComponent::KsmEligibility, request("capacity-ksm")),
            ]),
        }
    }

    #[test]
    fn deterministic_full_capability_plan() {
        let input = full_input();
        assert_eq!(
            plan_capacity_orchestration(&input).unwrap(),
            plan_capacity_orchestration(&input).unwrap()
        );
    }

    #[test]
    fn serialization_round_trip() {
        let plan = plan_capacity_orchestration(&full_input()).unwrap();
        let encoded = serde_json::to_vec(&plan).unwrap();
        assert_eq!(
            plan,
            serde_json::from_slice::<CapacityOrchestrationPlan>(&encoded).unwrap()
        );
    }

    #[test]
    fn valid_full_capability_plan_is_plan_only() {
        let plan = plan_capacity_orchestration(&full_input()).unwrap();
        assert_eq!(plan.components.len(), 6);
        assert!(plan
            .components
            .iter()
            .all(|item| item.state == CapacityComponentState::Eligible));
        assert!(!plan.activation_authorized);
        assert!(plan.host_oom_prohibited);
        assert!(plan.restore_failure_invalidates_result);
    }

    #[test]
    fn required_capability_missing_fails_closed() {
        let mut input = full_input();
        input.capabilities.remove(&CapacityCapability::ZramControl);
        assert!(matches!(
            plan_capacity_orchestration(&input),
            Err(CapacityContractError::RequiredCapabilityMissing {
                component: CapacityComponent::CompressionZram,
                ..
            })
        ));
    }

    #[test]
    fn dependency_missing_fails_closed() {
        let mut input = full_input();
        input
            .components
            .get_mut(&CapacityComponent::DamonTelemetry)
            .unwrap()
            .desired = false;
        assert_eq!(
            plan_capacity_orchestration(&input),
            Err(CapacityContractError::DependencyMissing {
                component: CapacityComponent::DamosReclaim,
                dependency: CapacityComponent::DamonTelemetry,
            })
        );
    }

    #[test]
    fn invalid_ordering_is_rejected() {
        let mut plan = plan_capacity_orchestration(&full_input()).unwrap();
        plan.apply_order.swap(0, 1);
        assert_eq!(
            validate_capacity_orchestration_plan(&plan),
            Err(CapacityContractError::InvalidApplyOrder)
        );
    }

    #[test]
    fn ambiguous_ownership_is_rejected() {
        let mut input = full_input();
        input
            .components
            .get_mut(&CapacityComponent::CompressionZram)
            .unwrap()
            .ownership = CapacityOwnershipBoundary::Ambiguous {
            reason: "foreign zram device".into(),
        };
        assert!(matches!(
            plan_capacity_orchestration(&input),
            Err(CapacityContractError::AmbiguousOwnership {
                component: CapacityComponent::CompressionZram,
                ..
            })
        ));
    }

    #[test]
    fn empty_exact_ownership_is_rejected() {
        let mut input = full_input();
        input
            .components
            .get_mut(&CapacityComponent::CompressionZram)
            .unwrap()
            .ownership = CapacityOwnershipBoundary::ExactOwned {
            resource_id: String::new(),
        };
        assert!(matches!(
            plan_capacity_orchestration(&input),
            Err(CapacityContractError::AmbiguousOwnership {
                component: CapacityComponent::CompressionZram,
                ..
            })
        ));
    }

    #[test]
    fn serialized_eligible_plan_requires_exact_ownership() {
        let mut plan = plan_capacity_orchestration(&full_input()).unwrap();
        plan.components
            .iter_mut()
            .find(|item| item.component == CapacityComponent::CompressionZram)
            .unwrap()
            .ownership = CapacityOwnershipBoundary::ReadOnlyHost;
        assert_eq!(
            validate_capacity_orchestration_plan(&plan),
            Err(CapacityContractError::InconsistentComponentState(
                CapacityComponent::CompressionZram
            ))
        );
    }

    #[test]
    fn serialized_plan_cannot_rewrite_canonical_dependencies() {
        let mut plan = plan_capacity_orchestration(&full_input()).unwrap();
        plan.components
            .iter_mut()
            .find(|item| item.component == CapacityComponent::DamosReclaim)
            .unwrap()
            .dependencies
            .clear();
        assert_eq!(
            validate_capacity_orchestration_plan(&plan),
            Err(CapacityContractError::InconsistentComponentState(
                CapacityComponent::DamosReclaim
            ))
        );
    }

    #[test]
    fn rollback_order_is_exact_reverse() {
        let plan = plan_capacity_orchestration(&full_input()).unwrap();
        assert_eq!(
            plan.rollback_order,
            plan.apply_order.iter().rev().copied().collect::<Vec<_>>()
        );
        let mut invalid = plan;
        invalid.rollback_order.swap(0, 1);
        assert_eq!(
            validate_capacity_orchestration_plan(&invalid),
            Err(CapacityContractError::InvalidRollbackOrder)
        );
    }

    #[test]
    fn incompatible_damos_and_ksm_target_is_rejected() {
        let mut input = full_input();
        input
            .components
            .get_mut(&CapacityComponent::KsmEligibility)
            .unwrap()
            .ownership = request("capacity-damos").ownership;
        assert_eq!(
            plan_capacity_orchestration(&input),
            Err(CapacityContractError::IncompatibleOwnedTarget)
        );
    }

    #[test]
    fn observe_default_and_automatic_action_invariant_are_enforced() {
        let mut input = full_input();
        input.production_mode = "capacity".into();
        assert_eq!(
            plan_capacity_orchestration(&input),
            Err(CapacityContractError::ProductionModeChanged)
        );
        input.production_mode = "observe".into();
        input.allow_automatic_actions = true;
        assert_eq!(
            plan_capacity_orchestration(&input),
            Err(CapacityContractError::AutomaticActionsEnabled)
        );
    }

    #[test]
    fn planner_and_validator_are_pure_data_operations() {
        let input = full_input();
        let before = input.clone();
        let plan = plan_capacity_orchestration(&input).unwrap();
        validate_capacity_orchestration_plan(&plan).unwrap();
        assert_eq!(input, before);
    }

    #[test]
    fn unavailable_optional_component_is_not_promoted() {
        let mut input = full_input();
        let component = input
            .components
            .get_mut(&CapacityComponent::StorageTiering)
            .unwrap();
        component.required = false;
        input
            .capabilities
            .remove(&CapacityCapability::ValidatedBootTiering);
        let plan = plan_capacity_orchestration(&input).unwrap();
        assert_eq!(
            plan.components
                .iter()
                .find(|item| item.component == CapacityComponent::StorageTiering)
                .unwrap()
                .state,
            CapacityComponentState::Unavailable
        );
        assert!(!plan
            .apply_order
            .contains(&CapacityComponent::StorageTiering));
    }

    #[test]
    fn missing_evidence_prevents_required_eligibility() {
        let mut input = full_input();
        input
            .evidence
            .remove(&CapacityEvidencePrerequisite::KsmSelective);
        assert_eq!(
            plan_capacity_orchestration(&input),
            Err(CapacityContractError::RequiredEvidenceMissing {
                component: CapacityComponent::KsmEligibility,
                evidence: CapacityEvidencePrerequisite::KsmSelective,
            })
        );
    }

    #[test]
    fn isolated_component_evidence_does_not_prove_combination() {
        let mut input = full_input();
        input
            .evidence
            .remove(&CapacityEvidencePrerequisite::CombinedProfileCompatibility);
        assert_eq!(
            plan_capacity_orchestration(&input),
            Err(CapacityContractError::CombinedEvidenceMissing)
        );
    }

    #[test]
    fn plan_never_claims_capacity_or_effectiveness() {
        let plan = plan_capacity_orchestration(&full_input()).unwrap();
        assert_eq!(
            plan.capacity_evaluation,
            CapacityEvaluationState::NotEvaluated
        );
        assert_eq!(
            plan.effectiveness_evaluation,
            CapacityEvaluationState::NotEvaluated
        );
        assert!(!plan.activation_authorized);
    }

    #[test]
    fn serialized_plan_cannot_drop_safety_invariants() {
        let mut plan = plan_capacity_orchestration(&full_input()).unwrap();
        plan.host_oom_prohibited = false;
        assert_eq!(
            validate_capacity_orchestration_plan(&plan),
            Err(CapacityContractError::SafetyInvariantViolated)
        );
    }

    #[test]
    fn serialized_plan_requires_every_component_exactly_once() {
        let mut plan = plan_capacity_orchestration(&full_input()).unwrap();
        plan.components.pop();
        assert_eq!(
            validate_capacity_orchestration_plan(&plan),
            Err(CapacityContractError::InvalidComponentSet)
        );
    }

    #[test]
    fn unknown_contract_version_is_rejected() {
        let mut input = full_input();
        input.contract_version += 1;
        assert!(matches!(
            plan_capacity_orchestration(&input),
            Err(CapacityContractError::UnsupportedVersion(_))
        ));
    }
}
