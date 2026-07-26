use crate::{CandidateRejection, PersistentState, PolicyEvidence, PolicyInput, PressureState};
use common::PressureConfig;

#[derive(Debug)]
pub struct TransitionResult {
    pub state: PersistentState,
    pub changed: bool,
    pub evidence: Vec<PolicyEvidence>,
    pub rejected: Vec<CandidateRejection>,
}

pub fn transition(
    previous: &PersistentState,
    input: &PolicyInput,
    config: &PressureConfig,
) -> TransitionResult {
    let (target, evidence, sufficient) = target_state(input, config);
    let mut state = previous.clone();
    let mut rejected = Vec::new();
    if !sufficient {
        state.candidate = None;
        state.candidate_since_ns = None;
        state.transition_reason = "insufficient_or_unavailable_telemetry".to_owned();
        return TransitionResult {
            state,
            changed: false,
            evidence,
            rejected,
        };
    }

    let desired = recovery_target(previous.current, target);
    if desired == previous.current {
        state.candidate = None;
        state.candidate_since_ns = None;
        state.transition_reason = "state_evidence_stable".to_owned();
        return TransitionResult {
            state,
            changed: false,
            evidence,
            rejected,
        };
    }
    let immediate = desired == PressureState::Emergency
        && input.available_percent <= f64::from(config.emergency_available_percent)
        && input
            .psi_memory_full_avg10
            .is_some_and(|v| v >= config.emergency_psi_full_avg10_threshold);
    let hold_seconds = if is_recovery(previous.current, desired) {
        config.recovery_hold_seconds
    } else {
        config.state_hold_seconds
    };
    let candidate_since = if previous.candidate == Some(desired) {
        previous.candidate_since_ns.unwrap_or(input.timestamp_ns)
    } else {
        input.timestamp_ns
    };
    let elapsed = input.timestamp_ns.saturating_sub(candidate_since);
    let held = elapsed >= seconds_ns(hold_seconds);
    if immediate || held {
        state.previous = Some(previous.current);
        state.current = desired;
        state.entered_at_ns = input.timestamp_ns;
        state.last_transition_ns = Some(input.timestamp_ns);
        state.candidate = None;
        state.candidate_since_ns = None;
        state.transition_reason = if immediate {
            "immediate_multi_signal_emergency".to_owned()
        } else {
            "candidate_hold_completed".to_owned()
        };
        TransitionResult {
            state,
            changed: true,
            evidence,
            rejected,
        }
    } else {
        state.candidate = Some(desired);
        state.candidate_since_ns = Some(candidate_since);
        state.transition_reason = "hysteresis_hold_in_progress".to_owned();
        rejected.push(CandidateRejection {
            candidate: desired,
            reason: format!("hold requires {hold_seconds}s"),
        });
        TransitionResult {
            state,
            changed: false,
            evidence,
            rejected,
        }
    }
}

fn recovery_target(current: PressureState, observed: PressureState) -> PressureState {
    match current {
        PressureState::Pressure | PressureState::Critical | PressureState::Emergency
            if observed < current =>
        {
            PressureState::Stabilizing
        }
        PressureState::Stabilizing if observed == PressureState::Normal => PressureState::Normal,
        PressureState::Stabilizing if observed > PressureState::Watch => observed,
        PressureState::Stabilizing => PressureState::Stabilizing,
        _ => observed,
    }
}

fn is_recovery(current: PressureState, desired: PressureState) -> bool {
    desired == PressureState::Stabilizing
        || (current == PressureState::Stabilizing && desired == PressureState::Normal)
}

fn seconds_ns(seconds: u64) -> i64 {
    i64::try_from(u128::from(seconds) * 1_000_000_000).unwrap_or(i64::MAX)
}

fn target_state(
    input: &PolicyInput,
    config: &PressureConfig,
) -> (PressureState, Vec<PolicyEvidence>, bool) {
    let mut evidence = Vec::new();
    let available = input.available_percent;
    evidence.push(ev(
        "mem_available_percent",
        Some(available),
        Some(f64::from(config.watch_available_percent)),
    ));
    evidence.push(ev(
        "psi_memory_some_avg10",
        input.psi_memory_some_avg10,
        Some(config.psi_some_avg10_threshold),
    ));
    evidence.push(ev(
        "psi_memory_full_avg10",
        input.psi_memory_full_avg10,
        Some(config.psi_full_avg10_threshold),
    ));
    evidence.push(ev(
        "major_faults_per_second",
        input.major_faults_per_second,
        Some(config.major_fault_rate_threshold),
    ));
    evidence.push(ev(
        "swap_in_per_second",
        input.swap_in_per_second,
        Some(config.swap_in_rate_threshold),
    ));
    evidence.push(ev(
        "swap_out_per_second",
        input.swap_out_per_second,
        Some(config.swap_out_rate_threshold),
    ));
    let corroborating = [
        input
            .psi_memory_some_avg10
            .is_some_and(|v| v >= config.psi_some_avg10_threshold),
        input
            .psi_memory_full_avg10
            .is_some_and(|v| v >= config.psi_full_avg10_threshold),
        input
            .major_faults_per_second
            .is_some_and(|v| v >= config.major_fault_rate_threshold),
        input
            .swap_in_per_second
            .is_some_and(|v| v >= config.swap_in_rate_threshold),
        input
            .swap_out_per_second
            .is_some_and(|v| v >= config.swap_out_rate_threshold),
    ]
    .into_iter()
    .filter(|value| *value)
    .count();
    let full_emergency = input
        .psi_memory_full_avg10
        .is_some_and(|v| v >= config.emergency_psi_full_avg10_threshold);
    let target = if available <= f64::from(config.emergency_available_percent)
        && (full_emergency || corroborating >= 2)
    {
        PressureState::Emergency
    } else if available <= f64::from(config.critical_available_percent) && corroborating >= 2 {
        PressureState::Critical
    } else if available <= f64::from(config.pressure_available_percent) && corroborating >= 1 {
        PressureState::Pressure
    } else if available <= f64::from(config.watch_available_percent) || corroborating >= 1 {
        PressureState::Watch
    } else {
        PressureState::Normal
    };
    let sufficient = input.psi_memory_some_avg10.is_some()
        || input.psi_memory_full_avg10.is_some()
        || input.major_faults_per_second.is_some()
        || input.swap_in_per_second.is_some()
        || input.swap_out_per_second.is_some();
    (target, evidence, sufficient)
}

fn ev(signal: &str, value: Option<f64>, threshold: Option<f64>) -> PolicyEvidence {
    PolicyEvidence {
        signal: signal.to_owned(),
        value,
        threshold,
        relation: "observed_against_configured_threshold".to_owned(),
        available: value.is_some(),
    }
}
