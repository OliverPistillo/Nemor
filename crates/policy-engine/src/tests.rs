use super::*;
use actuator::CgroupCapabilities;
use classifier::{ForegroundState, WorkloadClass};
use common::{Config, PressureConfig};

fn pressure() -> PressureConfig {
    Config::from_toml(include_str!("../../../config/default.toml"))
        .expect("config")
        .pressure
}

fn input(at_seconds: i64, available: f64, some: f64, full: f64) -> PolicyInput {
    PolicyInput {
        timestamp_ns: at_seconds * 1_000_000_000,
        ram_total_bytes: 1_000,
        mem_available_bytes: (available * 10.0) as u64,
        available_percent: available,
        swap_total_bytes: Some(100),
        swap_used_bytes: Some(10),
        swap_in_per_second: Some(0.0),
        swap_out_per_second: Some(0.0),
        major_faults_per_second: Some(0.0),
        pgscan_per_second: Some(0.0),
        pgsteal_per_second: Some(0.0),
        psi_memory_some_avg10: Some(some),
        psi_memory_full_avg10: Some(full),
        workload_class: Some(WorkloadClass::Desktop),
        workload_confidence: Some(0.9),
        gaming: false,
        critical_processes: 0,
        protected_processes: 1,
        unknown_processes: 0,
        foreground: ForegroundState::Foreground,
        cgroup_capabilities: Some(CgroupCapabilities {
            cgroup_v2: true,
            memory_controller: true,
            hierarchy: "/sys/fs/cgroup".into(),
            writable: true,
            memory_low: true,
            memory_high: true,
            attach: true,
        }),
        actuator_available: true,
        recent_safety_events: 0,
        recent_decisions: 0,
    }
}

fn settled(engine: &mut PolicyEngine, first: PolicyInput, second: PolicyInput) -> PolicyDecision {
    engine.evaluate(first, true).expect("first");
    engine.evaluate(second, true).expect("second")
}

#[test]
fn state_machine_escalates_through_all_pressure_states() {
    let mut engine = PolicyEngine::new(pressure(), 0);
    let watch = settled(
        &mut engine,
        input(0, 19.0, 0.0, 0.0),
        input(10, 19.0, 0.0, 0.0),
    );
    assert_eq!(watch.current_state, PressureState::Watch);
    let pressure = settled(
        &mut engine,
        input(11, 11.0, 11.0, 0.0),
        input(21, 11.0, 11.0, 0.0),
    );
    assert_eq!(pressure.current_state, PressureState::Pressure);
    let critical = settled(
        &mut engine,
        input(22, 6.0, 11.0, 3.0),
        input(32, 6.0, 11.0, 3.0),
    );
    assert_eq!(critical.current_state, PressureState::Critical);
    let emergency = engine
        .evaluate(input(33, 2.0, 20.0, 11.0), true)
        .expect("emergency");
    assert_eq!(emergency.current_state, PressureState::Emergency);
}

#[test]
fn recovered_pressure_passes_through_stabilizing() {
    let state = PersistentState {
        current: PressureState::Critical,
        previous: Some(PressureState::Pressure),
        entered_at_ns: 0,
        candidate: None,
        candidate_since_ns: None,
        last_transition_ns: Some(0),
        transition_reason: String::new(),
    };
    let mut engine = PolicyEngine::from_state(pressure(), state);
    engine
        .evaluate(input(1, 80.0, 0.0, 0.0), true)
        .expect("hold");
    let stabilizing = engine
        .evaluate(input(31, 80.0, 0.0, 0.0), true)
        .expect("stabilizing");
    assert_eq!(stabilizing.current_state, PressureState::Stabilizing);
    engine
        .evaluate(input(32, 80.0, 0.0, 0.0), true)
        .expect("hold");
    let normal = engine
        .evaluate(input(62, 80.0, 0.0, 0.0), true)
        .expect("normal");
    assert_eq!(normal.current_state, PressureState::Normal);
}

#[test]
fn hysteresis_rejects_oscillation_before_hold() {
    let mut engine = PolicyEngine::new(pressure(), 0);
    let first = engine
        .evaluate(input(0, 19.9, 0.0, 0.0), true)
        .expect("first");
    assert_eq!(first.current_state, PressureState::Watch);
    let normal = engine
        .evaluate(input(5, 21.0, 0.0, 0.0), true)
        .expect("normal");
    assert_eq!(normal.current_state, PressureState::Watch);
    assert_eq!(normal.candidate_state, Some(PressureState::Normal));
}

#[test]
fn rate_tracker_handles_first_zero_reset_and_irregular_intervals() {
    let mut tracker = RateTracker::default();
    let first = CounterSample {
        timestamp_ns: 1,
        swap_in: Some(10),
        swap_out: Some(20),
        major_faults: Some(30),
        pgscan: Some(40),
        pgsteal: Some(50),
    };
    assert_eq!(tracker.update(first), RateFeatures::default());
    let zero = tracker.update(first);
    assert_eq!(zero.swap_in_per_second, None);
    let later = tracker.update(CounterSample {
        timestamp_ns: 2_000_000_001,
        swap_in: Some(14),
        swap_out: Some(20),
        major_faults: Some(32),
        pgscan: Some(42),
        pgsteal: Some(54),
    });
    assert_eq!(later.swap_in_per_second, Some(2.0));
    assert_eq!(later.swap_out_per_second, Some(0.0));
    let reset = tracker.update(CounterSample {
        timestamp_ns: 3_000_000_001,
        swap_in: Some(1),
        swap_out: Some(1),
        major_faults: Some(1),
        pgscan: Some(1),
        pgsteal: Some(1),
    });
    assert_eq!(reset.swap_in_per_second, None);
}

#[test]
fn invalid_ranges_and_non_finite_values_are_rejected() {
    for invalid_value in [f64::NAN, f64::INFINITY, -1.0, 101.0] {
        let mut value = input(1, 50.0, 0.0, 0.0);
        value.available_percent = invalid_value;
        assert!(value.validate().is_err());
    }
    let mut inconsistent = input(1, 50.0, 0.0, 0.0);
    inconsistent.mem_available_bytes = 1_001;
    assert!(inconsistent.validate().is_err());
}

#[test]
fn identical_evaluations_serialize_identically() {
    let state = PersistentState::conservative(0);
    let value = input(0, 50.0, 0.0, 0.0);
    let expected = {
        let mut engine = PolicyEngine::from_state(pressure(), state.clone());
        serde_json::to_vec(&engine.evaluate(value.clone(), true).expect("decision"))
            .expect("serialize")
    };
    for _ in 0..1_000 {
        let mut engine = PolicyEngine::from_state(pressure(), state.clone());
        let actual = serde_json::to_vec(&engine.evaluate(value.clone(), true).expect("decision"))
            .expect("serialize");
        assert_eq!(actual, expected);
    }
}

#[test]
fn observe_rejects_every_mutating_action_in_severe_states() {
    for state in [
        PressureState::Pressure,
        PressureState::Critical,
        PressureState::Emergency,
        PressureState::Stabilizing,
    ] {
        let plan = crate::planner::plan_actions(state, &input(1, 5.0, 20.0, 5.0), true);
        assert!(plan.planned.iter().all(|action| !action.mutating));
        assert!(plan
            .rejected
            .iter()
            .any(|action| action.reason_code == "observe_mode"));
    }
}

#[test]
fn gaming_is_protected_but_does_not_hide_pressure() {
    let mut value = input(11, 6.0, 20.0, 3.0);
    value.gaming = true;
    value.workload_class = Some(WorkloadClass::Gaming);
    let state = PersistentState {
        current: PressureState::Pressure,
        previous: Some(PressureState::Watch),
        entered_at_ns: 0,
        candidate: Some(PressureState::Critical),
        candidate_since_ns: Some(0),
        last_transition_ns: Some(0),
        transition_reason: String::new(),
    };
    let mut engine = PolicyEngine::from_state(pressure(), state);
    let decision = engine.evaluate(value, true).expect("decision");
    assert_eq!(decision.current_state, PressureState::Critical);
    assert!(decision
        .rejected_actions
        .iter()
        .all(|action| action.requested != "target_game"));
}

#[test]
fn unknown_processes_are_rejected_in_every_state() {
    let mut value = input(1, 50.0, 0.0, 0.0);
    value.unknown_processes = 3;
    for state in [
        PressureState::Normal,
        PressureState::Watch,
        PressureState::Pressure,
        PressureState::Critical,
        PressureState::Emergency,
        PressureState::Stabilizing,
    ] {
        let plan = crate::planner::plan_actions(state, &value, true);
        assert!(plan
            .rejected
            .iter()
            .any(|item| item.reason_code == "unknown_do_not_touch"));
    }
}

#[test]
fn future_actions_are_structurally_rejected() {
    let rejected = crate::planner::reject_unsupported("TuneZram");
    assert_eq!(rejected.reason_code, "unsupported_action");
}

#[test]
fn normal_to_watch_and_each_pressure_recovery_are_explicit() {
    let normal = PersistentState {
        current: PressureState::Normal,
        previous: None,
        entered_at_ns: 0,
        candidate: Some(PressureState::Watch),
        candidate_since_ns: Some(0),
        last_transition_ns: None,
        transition_reason: String::new(),
    };
    let mut engine = PolicyEngine::from_state(pressure(), normal);
    assert_eq!(
        engine
            .evaluate(input(10, 19.0, 0.0, 0.0), true)
            .expect("watch")
            .current_state,
        PressureState::Watch
    );

    for current in [PressureState::Pressure, PressureState::Emergency] {
        let state = PersistentState {
            current,
            previous: None,
            entered_at_ns: 0,
            candidate: Some(PressureState::Stabilizing),
            candidate_since_ns: Some(0),
            last_transition_ns: None,
            transition_reason: String::new(),
        };
        let mut engine = PolicyEngine::from_state(pressure(), state);
        assert_eq!(
            engine
                .evaluate(input(30, 80.0, 0.0, 0.0), true)
                .expect("stabilizing")
                .current_state,
            PressureState::Stabilizing
        );
    }
}

#[test]
fn relevant_safety_event_suppresses_cgroup_family() {
    let mut value = input(1, 5.0, 20.0, 5.0);
    value.recent_safety_events = 1;
    let plan = crate::planner::plan_actions(PressureState::Critical, &value, false);
    assert!(plan.planned.iter().all(|action| !action.mutating));
    assert!(plan
        .rejected
        .iter()
        .any(|action| action.reason_code == "recent_cgroup_safety_event"));
}

#[test]
fn insufficient_input_keeps_state_and_plans_no_mutation() {
    let mut value = input(1, 50.0, 0.0, 0.0);
    value.psi_memory_some_avg10 = None;
    value.psi_memory_full_avg10 = None;
    value.major_faults_per_second = None;
    value.swap_in_per_second = None;
    value.swap_out_per_second = None;
    let mut engine = PolicyEngine::new(pressure(), 0);
    let decision = engine.evaluate(value, true).expect("fallback");
    assert_eq!(decision.current_state, PressureState::Watch);
    assert_eq!(
        decision.transition_reason,
        "insufficient_or_unavailable_telemetry"
    );
    assert!(decision.planned_actions.iter().all(|item| !item.mutating));
}
