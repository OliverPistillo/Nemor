use crate::{ActionKind, PlannedAction, PolicyInput, PressureState, RejectedAction};
use actuator::{plan as actuator_plan, CgroupPlan, PlanInput};
use common::CgroupsConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionPlan {
    pub planned: Vec<PlannedAction>,
    pub rejected: Vec<RejectedAction>,
}

#[must_use]
pub fn plan_actions(state: PressureState, input: &PolicyInput, observe: bool) -> ActionPlan {
    let mut planned = Vec::new();
    let mut rejected = Vec::new();
    let capabilities_ready = input
        .cgroup_capabilities
        .as_ref()
        .is_some_and(actuator::CgroupCapabilities::mutation_ready);

    match state {
        PressureState::Normal => planned.push(action(ActionKind::NoAction, "system_stable", false)),
        PressureState::Watch => planned.push(action(
            ActionKind::PrepareForegroundProtection,
            "early_pressure_signals",
            false,
        )),
        PressureState::Pressure | PressureState::Critical | PressureState::Emergency => {
            planned.push(action(
                ActionKind::ProtectForeground,
                "preserve_confirmed_foreground_and_protected_workloads",
                true,
            ));
            planned.push(action(
                ActionKind::ApplyBackgroundSoftLimit,
                "limit_only_explicitly_allow_listed_background_workloads",
                true,
            ));
            if input.recent_safety_events > 0 {
                reject_mutations(&mut planned, &mut rejected, "recent_cgroup_safety_event");
            } else if !capabilities_ready {
                reject_mutations(&mut planned, &mut rejected, "cgroup_capability_unavailable");
            } else if observe {
                reject_mutations(&mut planned, &mut rejected, "observe_mode");
            } else if !input.actuator_available {
                reject_mutations(&mut planned, &mut rejected, "actuator_unavailable");
            }
        }
        PressureState::Stabilizing => {
            planned.push(action(
                ActionKind::RollbackCgroupMeasures,
                "conservative_recovery_after_pressure",
                true,
            ));
            if input.recent_safety_events > 0 {
                reject_mutations(&mut planned, &mut rejected, "recent_cgroup_safety_event");
            } else if observe {
                reject_mutations(&mut planned, &mut rejected, "observe_mode");
            }
        }
    }
    if input.unknown_processes > 0 {
        rejected.push(RejectedAction {
            requested: "target_unknown_processes".to_owned(),
            reason_code: "unknown_do_not_touch".to_owned(),
            explanation: "unknown processes are never background targets".to_owned(),
        });
    }
    ActionPlan { planned, rejected }
}

fn action(kind: ActionKind, reason: &str, mutating: bool) -> PlannedAction {
    PlannedAction {
        kind,
        reason: reason.to_owned(),
        mutating,
        actuator_plan: None,
    }
}

fn reject_mutations(
    planned: &mut Vec<PlannedAction>,
    rejected: &mut Vec<RejectedAction>,
    code: &str,
) {
    for item in std::mem::take(planned) {
        if item.mutating {
            rejected.push(RejectedAction {
                requested: format!("{:?}", item.kind),
                reason_code: code.to_owned(),
                explanation: "mutation stopped before the actuator apply boundary".to_owned(),
            });
        } else {
            planned.push(item);
        }
    }
}

#[must_use]
pub fn validate_cgroup_plan(
    input: &PlanInput<'_>,
    config: &CgroupsConfig,
    mode: &str,
) -> CgroupPlan {
    actuator_plan(input, config, mode)
}

#[must_use]
pub fn reject_unsupported(name: &str) -> RejectedAction {
    RejectedAction {
        requested: name.to_owned(),
        reason_code: "unsupported_action".to_owned(),
        explanation: "action is outside the Phase 4 allow-list".to_owned(),
    }
}
