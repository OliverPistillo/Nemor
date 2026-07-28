use super::*;
use crate::harness::{
    evaluate_watchdog, finalize_harness, identity_matches, missing_required_memory_files,
    recover_simulated, validate_exclusive_membership, worker_transition_allowed,
    CgroupCapabilityEvidence, CgroupHarnessPlan, GateState, HarnessGate, OperationDiagnostic,
    OwnedProcessIdentity, SimulatedRecoveryState, WatchdogInputs, WorkerProtocolState,
    CHECKPOINT2_REQUIRED_GATES,
};
use crate::performance::*;
use crate::systemd::{
    interface_contract_matches, require_successful_job, transient_aux_signature,
    validate_unit_name, RecoveryOwnership, ScopeState, SimulatedSystemdBackend, SystemdJobOutcome,
    SystemdOperationFailure, TransientScopeBackend, TransientScopePlan, READBACK_PROPERTY_CONTRACT,
    UNIT_PREFIX,
};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn all_required_scenarios_are_defined_once() {
    let scenarios = required_scenarios();
    assert_eq!(scenarios.len(), 8);
    assert_eq!(
        scenarios
            .iter()
            .map(|s| s.scenario_id)
            .collect::<BTreeSet<_>>()
            .len(),
        8
    );
}

#[test]
fn scenario_ids_round_trip_and_unknown_is_rejected() {
    for scenario in ScenarioId::ALL {
        assert_eq!(scenario.as_str().parse::<ScenarioId>().unwrap(), scenario);
    }
    assert!("unknown".parse::<ScenarioId>().is_err());
}

#[test]
fn scenarios_are_versioned_and_have_three_repetitions() {
    for scenario in required_scenarios() {
        assert_eq!(scenario.schema_version, 1);
        assert_eq!(scenario.scenario_version, 1);
        assert!(scenario.repetition_count >= 3);
        assert!(scenario.maximum_duration_ms > scenario.measurement_interval_ms);
    }
}

#[test]
fn real_application_scenarios_are_manual() {
    for id in [
        ScenarioId::BrowserManyTabs,
        ScenarioId::GamingBackground,
        ScenarioId::IdeContainers,
        ScenarioId::MultipleVms,
    ] {
        let item = required_scenarios()
            .into_iter()
            .find(|s| s.scenario_id == id)
            .unwrap();
        assert_eq!(item.automation_level, AutomationLevel::ManualCooperative);
        assert_eq!(item.workload_source, WorkloadSource::ManualExternal);
    }
}

#[test]
fn zswap_remains_pending_validation() {
    let state = default_variant_availability()
        .into_iter()
        .find(|v| v.variant == BenchmarkVariant::Zswap)
        .unwrap();
    assert_eq!(state.state, AvailabilityState::PendingValidation);
    assert!(state.requires_reboot);
    assert!(state.reason.unwrap().contains("Phase 6"));
}

#[test]
fn run_state_happy_path_is_legal() {
    let mut state = RunState::Created;
    for next in [
        RunState::Preflight,
        RunState::Warmup,
        RunState::Stabilizing,
        RunState::Measuring,
        RunState::Cooldown,
        RunState::Restoring,
        RunState::Completed,
    ] {
        state = state.transition(next).unwrap();
    }
    assert_eq!(state, RunState::Completed);
}

#[test]
fn illegal_run_transition_is_rejected() {
    assert!(RunState::Created.transition(RunState::Measuring).is_err());
    assert!(RunState::Completed.transition(RunState::Warmup).is_err());
}

#[test]
fn failure_transition_is_always_explicit() {
    assert_eq!(
        RunState::Measuring
            .transition(RunState::SafetyAbort)
            .unwrap(),
        RunState::SafetyAbort
    );
}

#[test]
fn missing_metric_is_not_zero() {
    let metric =
        MetricValue::unavailable("energy", "joules", MetricScope::Host, "powercap", "missing");
    assert!(!metric.available);
    assert_eq!(metric.value, None);
    assert!(metric.reason.is_some());
}

#[test]
fn measured_metric_has_unit_scope_and_source() {
    let metric = MetricValue::measured("rss", 1.0, "bytes", MetricScope::Process, "procfs");
    assert!(metric.available);
    assert_eq!(metric.unit, "bytes");
    assert_eq!(metric.scope, MetricScope::Process);
    assert_eq!(metric.source, "procfs");
}

#[test]
fn psi_parser_handles_some_and_full() {
    let parsed = parse_psi("some avg10=1.00 avg60=2.00 avg300=3.00 total=42\nfull avg10=0.10 avg60=0.20 avg300=0.30 total=7\n").unwrap();
    assert_eq!(parsed.some.total_us, 42);
    assert_eq!(parsed.full.unwrap().avg10, 0.1);
}

#[test]
fn psi_parser_allows_missing_full() {
    let parsed = parse_psi("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").unwrap();
    assert!(parsed.full.is_none());
}

#[test]
fn vmstat_style_parser_is_bounded() {
    let parsed = parse_key_u64("pgmajfault 8\npswpin 3\npswpout 4\nbad nope\n");
    assert_eq!(parsed["pgmajfault"], 8);
    assert!(!parsed.contains_key("bad"));
}

#[test]
fn swap_parser_preserves_type_size_usage_and_priority() {
    let swaps = parse_swaps("Filename Type Size Used Priority\n/dev/zram0 partition 1024 12 100\n")
        .unwrap();
    assert_eq!(swaps.len(), 1);
    assert_eq!(swaps[0].kind, "partition");
    assert_eq!(swaps[0].used_kib, 12);
    assert_eq!(swaps[0].priority, 100);
}

#[test]
fn malformed_swap_row_is_rejected() {
    assert!(parse_swaps("Filename Type Size Used Priority\nbad row\n").is_err());
}

#[test]
fn cgroup_scalar_metrics_parse() {
    let parsed = parse_cgroup_key_values("anon 10\nfile 20\n").unwrap();
    assert_eq!(parsed["anon"], 10);
    assert_eq!(parsed["file"], 20);
}

#[test]
fn cgroup_io_stat_aggregates_devices() {
    let parsed = parse_io_stat("8:0 rbytes=1 wbytes=2\n8:1 rbytes=3 wbytes=4\n").unwrap();
    assert_eq!(parsed["rbytes"], 4);
    assert_eq!(parsed["wbytes"], 6);
}

#[test]
fn read_only_provider_labels_sources_and_scopes() {
    let metrics = collect_read_only_metrics();
    assert!(!metrics.values.is_empty());
    assert!(metrics
        .values
        .iter()
        .all(|metric| !metric.source.is_empty() && !metric.unit.is_empty()));
}

#[test]
fn meminfo_colon_parser_works() {
    let parsed = parse_key_u64("MemTotal: 100 kB\nMemAvailable: 50 kB\n");
    assert_eq!(parsed["MemAvailable"], 50);
}

#[test]
fn counter_delta_detects_decrease_or_wrap() {
    assert_eq!(checked_counter_delta(4, 9).unwrap(), 5);
    assert!(checked_counter_delta(9, 4).is_err());
}

#[test]
fn performance_counters_are_derived_as_run_relative_deltas() {
    let before = BTreeMap::from([
        ("cpu_usage_usec".into(), 1_000),
        ("io_rbytes".into(), 2_000),
        ("major_faults".into(), 30),
        ("psi_total_usec".into(), 40),
        ("swap_in_pages".into(), 50),
        ("swap_out_pages".into(), 60),
    ]);
    let after = BTreeMap::from([
        ("cpu_usage_usec".into(), 1_100),
        ("io_rbytes".into(), 2_200),
        ("major_faults".into(), 33),
        ("psi_total_usec".into(), 44),
        ("swap_in_pages".into(), 55),
        ("swap_out_pages".into(), 66),
    ]);
    assert_eq!(
        run_relative_counter_deltas(&before, &after).unwrap(),
        BTreeMap::from([
            ("cpu_usage_usec".into(), 100),
            ("io_rbytes".into(), 200),
            ("major_faults".into(), 3),
            ("psi_total_usec".into(), 4),
            ("swap_in_pages".into(), 5),
            ("swap_out_pages".into(), 6),
        ])
    );
}

#[test]
fn performance_counter_delta_rejects_field_drift_and_decrease() {
    assert!(run_relative_counter_deltas(
        &BTreeMap::from([("major_faults".into(), 9)]),
        &BTreeMap::from([("major_faults".into(), 8)]),
    )
    .is_err());
    assert!(run_relative_counter_deltas(
        &BTreeMap::from([("major_faults".into(), 9)]),
        &BTreeMap::from([("swap_in_pages".into(), 10)]),
    )
    .is_err());
}

#[test]
fn cpu_tick_resolution_is_reported() {
    let sample = cpu_observation(100, 1, 4.0).unwrap();
    assert_eq!(sample.tick_seconds, 0.01);
    assert_eq!(sample.cpu_percent, 0.25);
    assert_eq!(sample.resolution_percent, 0.25);
}

#[test]
fn cpu_tick_invalid_denominator_is_rejected() {
    assert!(cpu_observation(0, 1, 1.0).is_err());
    assert!(cpu_observation(100, 1, 0.0).is_err());
}

#[test]
fn statistics_are_deterministic() {
    let stats = summarize(&[1.0, 2.0, 3.0, 4.0]).unwrap();
    assert_eq!(stats.count, 4);
    assert_eq!(stats.mean, 2.5);
    assert_eq!(stats.median, 3.0);
    assert_eq!(stats.minimum, 1.0);
    assert_eq!(stats.maximum, 4.0);
    assert_eq!(stats.p95, 4.0);
    assert_eq!(stats.p99, 4.0);
}

#[test]
fn statistics_reject_empty_or_non_finite() {
    assert!(summarize(&[]).is_err());
    assert!(summarize(&[f64::NAN]).is_err());
}

#[test]
fn capacity_ratio_and_gain_are_logical() {
    let (ratio, gain) = capacity_comparison(100, 130).unwrap();
    assert_eq!(ratio, 1.3);
    assert!((gain - 30.0).abs() < 1e-12);
}

#[test]
fn zero_baseline_capacity_is_rejected() {
    assert!(capacity_comparison(0, 100).is_err());
}

#[test]
fn minimum_three_valid_runs_is_enforced() {
    let runs = vec![
        RunValue {
            run_id: "a".into(),
            valid: true,
            invalid_reason: None,
            value: Some(1.0),
        },
        RunValue {
            run_id: "b".into(),
            valid: true,
            invalid_reason: None,
            value: Some(2.0),
        },
    ];
    assert!(aggregate_runs(&runs).is_err());
}

#[test]
fn invalid_runs_are_retained_but_excluded() {
    let runs = vec![
        RunValue {
            run_id: "a".into(),
            valid: true,
            invalid_reason: None,
            value: Some(1.0),
        },
        RunValue {
            run_id: "b".into(),
            valid: false,
            invalid_reason: Some("watchdog".into()),
            value: None,
        },
        RunValue {
            run_id: "c".into(),
            valid: true,
            invalid_reason: None,
            value: Some(2.0),
        },
        RunValue {
            run_id: "d".into(),
            valid: true,
            invalid_reason: None,
            value: Some(3.0),
        },
    ];
    let (summary, invalid) = aggregate_runs(&runs).unwrap();
    assert_eq!(summary.count, 3);
    assert_eq!(invalid, 1);
    assert_eq!(runs.len(), 4);
}

#[test]
fn random_order_is_seeded_and_reproducible() {
    let variants = [
        BenchmarkVariant::CachyosBaseline,
        BenchmarkVariant::NemorSafe,
    ];
    assert_eq!(
        deterministic_order(&variants, 3, 42),
        deterministic_order(&variants, 3, 42)
    );
    assert_ne!(
        deterministic_order(&variants, 3, 42),
        deterministic_order(&variants, 3, 43)
    );
}

#[test]
fn random_order_contains_every_repetition() {
    let variants = [
        BenchmarkVariant::CachyosBaseline,
        BenchmarkVariant::NemorSafe,
    ];
    let result = deterministic_order(&variants, 3, 1);
    assert_eq!(result.len(), 6);
    for variant in variants {
        assert_eq!(result.iter().filter(|(v, _)| *v == variant).count(), 3);
    }
}

#[test]
fn compressible_and_incompressible_generators_differ_materially() {
    let (compressible, _) = run_synthetic(SyntheticPattern::Compressible, 1024 * 1024, 7).unwrap();
    let (incompressible, _) =
        run_synthetic(SyntheticPattern::Incompressible, 1024 * 1024, 7).unwrap();
    assert!(compressible.encoded_sanity_bytes * 16 < incompressible.encoded_sanity_bytes);
    assert_ne!(compressible.fingerprint, incompressible.fingerprint);
}

#[test]
fn synthetic_is_deterministic_and_prefaulted() {
    let (a, bytes_a) = run_synthetic(SyntheticPattern::Incompressible, 64 * 1024, 9).unwrap();
    let (b, bytes_b) = run_synthetic(SyntheticPattern::Incompressible, 64 * 1024, 9).unwrap();
    assert_eq!(a.fingerprint, b.fingerprint);
    assert_eq!(bytes_a, bytes_b);
    assert_eq!(a.logical_bytes, a.touched_bytes);
    assert!(a.integrity_valid);
}

#[test]
fn synthetic_bounds_and_timeout_preconditions_are_enforced() {
    assert!(run_synthetic(SyntheticPattern::Compressible, 0, 1).is_err());
    assert!(run_synthetic(SyntheticPattern::Compressible, SMOKE_MAX_BYTES + 1, 1).is_err());
}

#[test]
fn incompressible_pages_have_low_duplication() {
    let (_, bytes) = run_synthetic(SyntheticPattern::Incompressible, 512 * 1024, 99).unwrap();
    let pages: BTreeSet<_> = bytes
        .chunks(4096)
        .map(|p| hex::encode(Sha256::digest(p)))
        .collect();
    assert_eq!(pages.len(), bytes.len() / 4096);
}

#[test]
fn frametime_summary_contains_requested_quantiles() {
    let result = summarize_frametimes("csv", &[10.0, 11.0, 12.0, 20.0]).unwrap();
    assert_eq!(result.sample_count, 4);
    assert_eq!(result.p95_ms, 20.0);
    assert_eq!(result.one_percent_low_fps, 50.0);
}

#[test]
fn host_oom_is_always_safety_failure() {
    assert!(OomOutcome::HostOom.safety_failure());
    assert!(!OomOutcome::ControlledCgroupOom.safety_failure());
}

#[test]
fn oom_avoided_requires_ab_context_by_model() {
    assert_ne!(OomOutcome::None, OomOutcome::ControlledCgroupOom);
}

#[test]
fn thrashing_requires_documented_multi_signal_cycle() {
    let limits = ThrashingThresholds {
        psi_full_avg10: 1.0,
        major_faults_per_second: 10.0,
        swap_in_pages_per_second: 10.0,
        swap_out_pages_per_second: 10.0,
        response_latency_ms: 100.0,
    };
    let values = BTreeMap::from([
        ("psi_full_avg10".into(), 2.0),
        ("major_faults_per_second".into(), 20.0),
        ("swap_in_pages_per_second".into(), 20.0),
        ("swap_out_pages_per_second".into(), 20.0),
    ]);
    let (detected, evidence) = detect_thrashing(&values, &limits);
    assert!(detected);
    assert_eq!(evidence.len(), 4);
}

#[test]
fn threshold_acceptance_supports_not_evaluated() {
    assert_eq!(
        evaluate_threshold(None, 30.0, true),
        EvaluationState::NotEvaluated
    );
    assert_eq!(
        evaluate_threshold(Some(30.0), 30.0, true),
        EvaluationState::Pass
    );
    assert_eq!(
        evaluate_threshold(Some(29.9), 30.0, true),
        EvaluationState::Fail
    );
}

#[test]
fn cpu_and_gaming_limits_use_at_most_semantics() {
    assert_eq!(
        evaluate_threshold(Some(5.0), 5.0, false),
        EvaluationState::Pass
    );
    assert_eq!(
        evaluate_threshold(Some(5.1), 5.0, false),
        EvaluationState::Fail
    );
    assert_eq!(
        evaluate_threshold(Some(10.0), 10.0, false),
        EvaluationState::Pass
    );
    assert_eq!(
        evaluate_threshold(Some(10.1), 10.0, false),
        EvaluationState::Fail
    );
}

#[test]
fn favorable_and_gaming_capacity_targets_are_explicit() {
    assert_eq!(
        evaluate_threshold(Some(30.0), 30.0, true),
        EvaluationState::Pass
    );
    assert_eq!(
        evaluate_threshold(Some(15.0), 15.0, true),
        EvaluationState::Pass
    );
}

#[test]
fn environment_hash_is_stable_for_fixture() {
    let fixture = fixture_environment();
    assert_eq!(fixture.hash().unwrap(), fixture.hash().unwrap());
}

#[test]
fn fingerprint_has_no_sensitive_identifier_fields() {
    let json = serde_json::to_string(&fixture_environment()).unwrap();
    for forbidden in ["machine_id", "username", "home_path", "serial_number"] {
        assert!(!json.contains(forbidden));
    }
}

#[test]
fn environment_kernel_mismatch_blocks_comparison() {
    let a = fixture_environment();
    let mut b = a.clone();
    b.kernel_release = "other".into();
    assert!(a.comparable_with(&b).is_err());
}

#[test]
fn environment_config_mismatch_blocks_comparison() {
    let a = fixture_environment();
    let mut b = a.clone();
    b.config_hash = "other".into();
    assert!(a.comparable_with(&b).is_err());
}

#[test]
fn thermal_unverified_propagates_in_fingerprint() {
    assert!(fixture_environment().thermal_state_unverified);
}

#[test]
fn allowed_command_rejects_shell_or_unlisted_executable() {
    let allowed = BTreeSet::from([PathBuf::from("/usr/bin/cargo")]);
    assert!(AllowedCommand {
        executable: PathBuf::from("/bin/sh"),
        argv: vec!["-c".into(), "evil".into()]
    }
    .validate(&allowed)
    .is_err());
    assert!(AllowedCommand {
        executable: PathBuf::from("/usr/bin/cargo"),
        argv: vec!["build".into()]
    }
    .validate(&allowed)
    .is_ok());
}

#[test]
fn controlled_pressure_must_be_below_headroom() {
    let safe = ControlledPressurePlan {
        owned_cgroup: "nemor-benchmark/test".into(),
        memory_max_bytes: 128,
        host_headroom_bytes: 1024,
        watchdog_ms: 100,
        timeout_ms: 1000,
        privileged_execution_required: true,
        host_oom_forbidden: true,
    };
    assert!(safe.validate().is_ok());
    let mut unsafe_plan = safe.clone();
    unsafe_plan.memory_max_bytes = unsafe_plan.host_headroom_bytes;
    assert!(unsafe_plan.validate().is_err());
}

#[test]
fn no_pressure_plan_can_allow_host_oom() {
    let plan = ControlledPressurePlan {
        owned_cgroup: "owned".into(),
        memory_max_bytes: 1,
        host_headroom_bytes: 2,
        watchdog_ms: 1,
        timeout_ms: 1,
        privileged_execution_required: true,
        host_oom_forbidden: false,
    };
    assert!(plan.validate().is_err());
}

#[test]
fn compile_adapter_requires_deterministic_allowlisted_fixture() {
    let command = AllowedCommand {
        executable: PathBuf::from("/usr/bin/cargo"),
        argv: vec!["build".into(), "--release".into()],
    };
    let plan = CompileAdapterPlan {
        fixture_id: "rust-memory-fixture-v1".into(),
        fixture_hash: "a".repeat(64),
        language: "rust".into(),
        build_type: "release".into(),
        parallelism: 4,
        cache_state: CacheState::NotControlled,
        command,
        required_metrics: vec!["wall_time".into(), "cpu_time".into()],
    };
    assert!(plan
        .validate(&BTreeSet::from([PathBuf::from("/usr/bin/cargo")]))
        .is_ok());
}

#[test]
fn warmup_samples_are_excluded_from_measurement() {
    let metric = MetricValue::measured("rss", 1.0, "bytes", MetricScope::Process, "fixture");
    let samples = vec![
        LifecycleSample {
            timestamp_monotonic_ns: 1,
            phase: RunState::Warmup,
            metric: metric.clone(),
        },
        LifecycleSample {
            timestamp_monotonic_ns: 2,
            phase: RunState::Measuring,
            metric,
        },
    ];
    assert_eq!(measurement_samples(&samples).unwrap().len(), 1);
}

#[test]
fn non_monotonic_samples_are_rejected() {
    let metric = MetricValue::measured("rss", 1.0, "bytes", MetricScope::Process, "fixture");
    let samples = vec![
        LifecycleSample {
            timestamp_monotonic_ns: 2,
            phase: RunState::Measuring,
            metric: metric.clone(),
        },
        LifecycleSample {
            timestamp_monotonic_ns: 1,
            phase: RunState::Measuring,
            metric,
        },
    ];
    assert!(measurement_samples(&samples).is_err());
}

#[test]
fn response_latency_uses_monotonic_delta() {
    let event = ResponseEvent {
        event_type: "ready".into(),
        probe_version: 1,
        started_monotonic_ns: 1_000_000,
        completed_monotonic_ns: 3_500_000,
    };
    assert_eq!(event.latency_ms().unwrap(), 2.5);
}

#[test]
fn oom_avoided_requires_same_demand_and_valid_ab() {
    assert_eq!(
        oom_avoided(
            OomOutcome::ControlledCgroupOom,
            OomOutcome::None,
            true,
            true
        ),
        EvaluationState::Pass
    );
    assert_eq!(
        oom_avoided(
            OomOutcome::ControlledCgroupOom,
            OomOutcome::None,
            false,
            true
        ),
        EvaluationState::NotEvaluated
    );
}

#[test]
fn sqlite_smoke_pipeline_is_bounded_and_readable() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("benchmark.sqlite");
    let mut store = BenchmarkStore::create(
        &db,
        include_str!("../../../migrations/0008_benchmark.sql"),
        2,
    )
    .unwrap();
    let report = fixture_report();
    store.persist_smoke(&report).unwrap();
    assert_eq!(store.list_summaries(10).unwrap().len(), 1);
    assert_eq!(store.latest().unwrap()["run_id"], report.run_id);
    assert_eq!(
        store.report(&report.run_id).unwrap()["run_id"],
        report.run_id
    );
    let sample_count: i64 = store
        .connection
        .query_row("SELECT COUNT(*) FROM benchmark_samples", [], |r| r.get(0))
        .unwrap();
    assert_eq!(sample_count, 1);
}

#[test]
fn structural_restore_detects_mismatch() {
    let a = StructuralSnapshot {
        swaps: "a".into(),
        swap_topology: vec![],
        swap_runtime_used_kib: BTreeMap::new(),
        zram_configuration: BTreeMap::new(),
        zram_runtime: BTreeMap::new(),
        zswap_enabled: None,
        ksm_configuration: BTreeMap::new(),
        damon_tree_shape: vec![],
    };
    let mut b = a.clone();
    b.zram_configuration
        .insert("zram0.disksize".into(), "1".into());
    assert!(!a.matches(&b));
}

#[test]
fn completed_does_not_imply_accepted() {
    let report = fixture_report();
    assert_eq!(report.state, RunState::Completed);
    assert_eq!(
        report.acceptance.favorable_capacity,
        EvaluationState::NotEvaluated
    );
}

#[test]
fn source_state_changes_with_worktree_content() {
    let clean = calculate_source_state_id("head", b"", &[]);
    let dirty = calculate_source_state_id("head", b"diff", &[]);
    let untracked = calculate_source_state_id("head", b"", &[("new.rs".into(), "digest".into())]);
    assert_ne!(clean, dirty);
    assert_ne!(clean, untracked);
}

#[test]
fn provenance_serializes_binary_sha_and_development_state() {
    let report = fixture_report();
    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["provenance"]["binary_sha256"], "binary");
    assert_eq!(value["provenance"]["development_build"], true);
}

#[test]
fn only_clean_performance_evidence_is_claim_eligible() {
    let mut provenance = fixture_report().provenance;
    provenance.git_dirty = false;
    assert!(EvidenceKind::PerformanceBenchmark.performance_claim_eligible(&provenance));
    provenance.git_dirty = true;
    assert!(!EvidenceKind::PerformanceBenchmark.performance_claim_eligible(&provenance));
    assert!(!EvidenceKind::HarnessValidation.performance_claim_eligible(&provenance));
}

#[test]
fn smoke_and_harness_evidence_are_isolated_from_performance_aggregate() {
    let run = RunValue {
        run_id: "a".into(),
        valid: true,
        invalid_reason: None,
        value: Some(1.0),
    };
    let evidence = vec![
        EvidenceRun {
            evidence_kind: EvidenceKind::FrameworkSmoke,
            run: run.clone(),
        },
        EvidenceRun {
            evidence_kind: EvidenceKind::HarnessValidation,
            run: run.clone(),
        },
        EvidenceRun {
            evidence_kind: EvidenceKind::PerformanceBenchmark,
            run,
        },
    ];
    assert!(aggregate_performance_runs(&evidence).is_err());
}

fn variant_context() -> VariantResolutionContext {
    VariantResolutionContext {
        baseline_state: BTreeMap::from([
            ("zram".into(), "zstd:16GiB".into()),
            ("zswap".into(), "disabled".into()),
        ]),
        observe_executable: true,
        safe_executable: false,
        gaming_executable: false,
        capacity_executable: false,
        distinct_zram_configuration: None,
        zswap_boot_validated: false,
    }
}

#[test]
fn host_zram_variant_resolves_to_baseline_alias() {
    let baseline = resolve_variant(BenchmarkVariant::CachyosBaseline, &variant_context());
    let zram = resolve_variant(BenchmarkVariant::Zram, &variant_context());
    assert_eq!(zram.resolved_variant_state, ResolvedVariantState::Alias);
    assert_eq!(zram.effective_state_hash, baseline.effective_state_hash);
}

#[test]
fn identical_effective_state_comparison_is_rejected() {
    let baseline = resolve_variant(BenchmarkVariant::CachyosBaseline, &variant_context());
    let mut same = baseline.clone();
    same.requested_variant = BenchmarkVariant::Zram;
    let result = validate_variant_comparison(&baseline, &same, false);
    assert!(!result.valid);
    assert_eq!(result.reason.as_deref(), Some("equivalent_effective_state"));
}

#[test]
fn observe_overhead_comparison_requires_explicit_scope() {
    let baseline = resolve_variant(BenchmarkVariant::CachyosBaseline, &variant_context());
    let observe = resolve_variant(BenchmarkVariant::NemorObserve, &variant_context());
    assert!(!validate_variant_comparison(&baseline, &observe, false).valid);
    assert!(validate_variant_comparison(&baseline, &observe, true).valid);
}

#[test]
fn unvalidated_nemor_profiles_are_pending() {
    for variant in [
        BenchmarkVariant::NemorSafe,
        BenchmarkVariant::NemorGaming,
        BenchmarkVariant::NemorCapacity,
    ] {
        assert_eq!(
            resolve_variant(variant, &variant_context()).resolved_variant_state,
            ResolvedVariantState::PendingValidation
        );
    }
}

#[test]
fn setup_cpu_is_preserved_but_not_measurement_cpu() {
    let accounting = SyntheticCpuAccounting {
        setup: vec![PhaseTiming {
            phase: SyntheticWorkerPhase::Generating,
            wall_seconds: 1.0,
            cpu_seconds: Some(0.9),
        }],
        measurement_worker_cpu_seconds: Some(0.01),
        benchmark_runner_cpu_seconds: Some(0.01),
        nemord_cpu_seconds: None,
        kernel_helper_cpu_seconds: None,
        measurement_started_after_ready_and_stabilization: true,
    };
    assert_eq!(accounting.setup[0].cpu_seconds, Some(0.9));
    assert_eq!(accounting.measurement_worker_cpu_seconds, Some(0.01));
    assert!(accounting.measurement_started_after_ready_and_stabilization);
}

#[test]
fn steady_worker_never_regenerates_or_rewrites_allocation() {
    let state = SteadyWorkerState {
        allocation_bytes: 64 * 1024 * 1024,
        full_generation_passes: 1,
        full_prefault_passes: 1,
        heartbeat_count: 10,
        bounded_integrity_pages_checked: 10,
        full_rewrite_passes_during_measurement: 0,
    };
    assert!(state.validate().is_ok());
    let mut rewriting = state;
    rewriting.full_rewrite_passes_during_measurement = 1;
    assert!(rewriting.validate().is_err());
}

#[test]
fn checkpoint_plan_accepts_64_mib_with_conservative_headroom() {
    let plan = CgroupHarnessPlan::derive(
        64 * 1024 * 1024,
        4 * 1024 * 1024 * 1024,
        16 * 1024 * 1024 * 1024,
        PathBuf::from("/sys/fs/cgroup/test"),
        "run1",
    )
    .unwrap();
    assert_eq!(plan.memory_max_bytes, 128 * 1024 * 1024);
    assert!(plan.memory_max_bytes > plan.worker_bytes);
    assert!(!plan.oom_requested);
}

#[test]
fn checkpoint_plan_rejects_insufficient_headroom_or_oom() {
    assert!(CgroupHarnessPlan::derive(
        64 * 1024 * 1024,
        100 * 1024 * 1024,
        16 * 1024 * 1024 * 1024,
        PathBuf::from("/fake"),
        "run",
    )
    .is_err());
    let mut plan = CgroupHarnessPlan::derive(
        64 * 1024 * 1024,
        4 * 1024 * 1024 * 1024,
        16 * 1024 * 1024 * 1024,
        PathBuf::from("/fake"),
        "run",
    )
    .unwrap();
    plan.oom_requested = true;
    assert!(plan.validate().is_err());
}

#[test]
fn exact_pid_and_start_ticks_identity_key_is_collision_safe() {
    let a = OwnedProcessIdentity {
        run_id: "r".into(),
        pid: 100,
        start_ticks: 10,
    };
    let b = OwnedProcessIdentity {
        run_id: "r".into(),
        pid: 101,
        start_ticks: 10,
    };
    assert_ne!(a.stable_key(), b.stable_key());
    assert!(identity_matches(&a, 100, 10));
    assert!(!identity_matches(&a, 100, 11));
    assert!(!identity_matches(&a, 101, 10));
}

#[test]
fn exclusive_membership_rejects_foreign_process() {
    assert!(validate_exclusive_membership(10, &BTreeSet::from([10])).is_ok());
    assert!(validate_exclusive_membership(10, &BTreeSet::from([10, 11])).is_err());
}

#[test]
fn globally_available_memory_without_subtree_delegation_is_unusable() {
    let evidence = CgroupCapabilityEvidence::from_values(
        true,
        Some("domain".into()),
        Some(true),
        Some(3),
        vec!["cpu".into(), "memory".into()],
        vec!["cpu".into()],
    );
    assert!(evidence.memory_supported);
    assert!(!evidence.memory_enabled_for_children);
    assert!(!evidence.parent_usable);
    assert_eq!(evidence.reason, "parent_memory_controller_not_enabled");
}

#[test]
fn delegated_domain_parent_is_potentially_usable() {
    let evidence = CgroupCapabilityEvidence::from_values(
        true,
        Some("domain".into()),
        Some(false),
        Some(0),
        vec!["cpu".into(), "memory".into()],
        vec!["cpu".into(), "memory".into()],
    );
    assert!(evidence.parent_usable);
    assert!(evidence.child_memory_interface_expected);
}

#[test]
fn invalid_topology_is_rejected_even_with_memory_delegated() {
    let evidence = CgroupCapabilityEvidence::from_values(
        true,
        Some("threaded".into()),
        Some(true),
        Some(1),
        vec!["memory".into()],
        vec!["memory".into()],
    );
    assert!(!evidence.parent_usable);
    assert_eq!(evidence.reason, "cgroup_topology_invalid");
}

#[test]
fn directory_creation_does_not_imply_memory_interface() {
    let missing = missing_required_memory_files(["cgroup.procs"]);
    assert!(missing.contains(&"memory.max"));
    assert!(missing.contains(&"memory.current"));
    assert_eq!(missing.len(), 5);
}

#[test]
fn complete_child_memory_interface_is_recognized() {
    assert!(missing_required_memory_files([
        "memory.max",
        "memory.current",
        "memory.events",
        "memory.stat",
        "memory.pressure",
    ])
    .is_empty());
}

#[test]
fn operation_diagnostic_is_bounded_and_uses_path_role() {
    let diagnostic = OperationDiagnostic {
        operation: "write_memory_max".into(),
        path_role: "owned_benchmark_cgroup/memory.max".into(),
        error_kind: Some("not_found".into()),
        errno: Some(2),
        message: "No such file or directory".into(),
        mutation_started: true,
        cleanup_required: true,
        systemd_failure: None,
    };
    let value = serde_json::to_value(diagnostic).unwrap();
    assert!(value.get("path").is_none());
    assert_eq!(value["errno"], 2);
}

fn scope_identity() -> OwnedProcessIdentity {
    OwnedProcessIdentity {
        run_id: "checkpoint2test".into(),
        pid: 42,
        start_ticks: 99,
    }
}

#[test]
fn transient_scope_plan_is_fixed_and_bounded() {
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    assert!(plan.unit_name.starts_with(UNIT_PREFIX));
    assert_eq!(plan.memory_max, 128 * 1024 * 1024);
    assert_eq!(plan.runtime_max_usec, 15_000_000);
    assert!(plan.memory_accounting && plan.cpu_accounting && plan.io_accounting);
    assert_eq!(plan.identity.pid, 42);
    plan.validate().unwrap();
}

#[test]
fn transient_request_has_exact_dbus_variant_signatures() {
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    assert_eq!(
        plan.encoded_property_signatures().unwrap(),
        vec![
            ("Description".into(), "s".into()),
            ("PIDs".into(), "au".into()),
            ("MemoryAccounting".into(), "b".into()),
            ("CPUAccounting".into(), "b".into()),
            ("IOAccounting".into(), "b".into()),
            ("MemoryMax".into(), "t".into()),
            ("RuntimeMaxUSec".into(), "t".into()),
            ("CollectMode".into(), "s".into()),
        ]
    );
    assert_eq!(transient_aux_signature(), "a(sa(sv))");
}

#[test]
fn cpu_accounting_request_is_not_read_back_as_removed_dbus_property() {
    let source = include_str!("systemd.rs");
    assert!(source.contains("(\"CPUAccounting\", Value::from(self.cpu_accounting))"));
    assert!(!source.contains("scope.get_property(\"CPUAccounting\")"));
    assert!(source.contains("kernel_path.join(\"cpu.stat\").is_file()"));
}

#[test]
fn transient_request_has_one_exact_u32_pid_and_fixed_property_set() {
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    assert_eq!(plan.identity.pid, 42u32);
    let signatures = plan.encoded_property_signatures().unwrap();
    assert_eq!(signatures.len(), 8);
    assert_eq!(
        signatures
            .iter()
            .map(|item| &item.0)
            .collect::<BTreeSet<_>>()
            .len(),
        8
    );
}

#[test]
fn maximum_generated_run_id_remains_valid() {
    let run_id = "x".repeat(4096);
    let plan = TransientScopePlan::new(&run_id, scope_identity()).unwrap();
    validate_unit_name(&plan.unit_name).unwrap();
    assert_eq!(
        plan.unit_name,
        format!("{}{}.scope", UNIT_PREFIX, "x".repeat(32))
    );
}

#[test]
fn method_failure_diagnostic_preserves_name_and_has_no_job_path() {
    let failure = SystemdOperationFailure {
        stage: "start_transient_unit_method".into(),
        dbus_error_name: Some("org.freedesktop.DBus.Error.AccessDenied".into()),
        error_category: "start_transient_method_failed".into(),
        bounded_message: "denied".into(),
        method: "StartTransientUnit".into(),
        interface: Some("org.freedesktop.systemd1.Manager".into()),
        property: None,
        job_path: None,
        job_result: None,
        unit_object_path: None,
        worker_unit_object_path: None,
        unit_absent_after_method_failure: Some(true),
        mutation_may_have_started: false,
        cleanup_required: false,
    };
    let value = serde_json::to_value(failure).unwrap();
    assert_eq!(
        value["dbus_error_name"],
        "org.freedesktop.DBus.Error.AccessDenied"
    );
    assert!(value["job_path"].is_null());
    assert_eq!(value["unit_absent_after_method_failure"], true);
}

#[test]
fn malformed_or_foreign_transient_unit_is_rejected() {
    assert!(validate_unit_name("foreign.scope").is_err());
    assert!(validate_unit_name("nemor-benchmark-../../x.scope").is_err());
    assert!(validate_unit_name("nemor-benchmark-.scope").is_err());
}

#[test]
fn systemd_unavailable_fails_before_start() {
    let backend = SimulatedSystemdBackend::default();
    assert!(!backend.capability().unwrap().supported);
    assert_eq!(backend.starts, 0);
}

#[test]
fn existing_unit_collision_never_replaces() {
    let mut backend = SimulatedSystemdBackend {
        available: true,
        collision: true,
        ..Default::default()
    };
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    assert!(backend.start_owned_scope(&plan).is_err());
    assert_eq!(backend.starts, 0);
}

#[test]
fn simulated_scope_uses_exact_pid_and_properties() {
    let mut backend = SimulatedSystemdBackend {
        available: true,
        ..Default::default()
    };
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    let state = backend.start_owned_scope(&plan).unwrap();
    assert_eq!(state.members, BTreeSet::from([42]));
    assert_eq!(state.memory_max, 128 * 1024 * 1024);
    assert!(state.memory_accounting);
}

#[test]
fn scope_resource_or_control_group_mismatch_fails() {
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    let mut state = ScopeState {
        unit_name: plan.unit_name.clone(),
        object_path: "/test".into(),
        control_group: String::new(),
        memory_max: plan.memory_max,
        memory_accounting: true,
        cpu_accounting: true,
        io_accounting: true,
        runtime_max_usec: plan.runtime_max_usec,
        active_state: "active".into(),
        sub_state: "running".into(),
        members: BTreeSet::from([42]),
    };
    assert!(state.verify(&plan).is_err());
    state.control_group = "/test".into();
    state.memory_max += 1;
    assert!(state.verify(&plan).is_err());
}

#[test]
fn foreign_scope_member_is_rejected() {
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    let state = ScopeState {
        unit_name: plan.unit_name.clone(),
        object_path: "/test".into(),
        control_group: "/test".into(),
        memory_max: plan.memory_max,
        memory_accounting: true,
        cpu_accounting: true,
        io_accounting: true,
        runtime_max_usec: plan.runtime_max_usec,
        active_state: "active".into(),
        sub_state: "running".into(),
        members: BTreeSet::from([42, 43]),
    };
    assert!(state.verify(&plan).is_err());
}

#[test]
fn recovery_is_owned_only_and_collected_is_idempotent() {
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    let mut backend = SimulatedSystemdBackend {
        available: true,
        ..Default::default()
    };
    backend.start_owned_scope(&plan).unwrap();
    backend
        .recover_owned_scope(&plan, RecoveryOwnership::ExactOwned)
        .unwrap();
    backend
        .recover_owned_scope(&plan, RecoveryOwnership::Absent)
        .unwrap();
    assert_eq!(backend.stops, 1);
    assert!(backend
        .recover_owned_scope(&plan, RecoveryOwnership::Ambiguous)
        .is_err());
}

#[test]
fn dbus_disconnect_is_a_safety_failure() {
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    let mut backend = SimulatedSystemdBackend {
        available: true,
        disconnect: true,
        ..Default::default()
    };
    assert!(backend.start_owned_scope(&plan).is_err());
}

#[test]
fn systemd_job_accepts_only_done() {
    for result in ["failed", "canceled", "timeout", "dependency", "skipped"] {
        assert!(require_successful_job(&SystemdJobOutcome {
            job_path: "/job".into(),
            unit_name: "nemor-benchmark-test.scope".into(),
            result: result.into(),
            successful: false,
        })
        .is_err());
    }
    require_successful_job(&SystemdJobOutcome {
        job_path: "/job".into(),
        unit_name: "nemor-benchmark-test.scope".into(),
        result: "done".into(),
        successful: true,
    })
    .unwrap();
}

#[test]
fn start_job_failure_cancel_or_timeout_never_queries_unit() {
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    for result in ["failed", "canceled"] {
        let mut backend = SimulatedSystemdBackend {
            available: true,
            start_job_result: Some(result.into()),
            ..Default::default()
        };
        assert!(backend.start_owned_scope(&plan).is_err());
        assert_eq!(backend.unit_queries, 0);
        assert_eq!(backend.property_reads, 0);
        assert!(backend.scope.is_none());
    }
    let mut timeout = SimulatedSystemdBackend {
        available: true,
        start_job_timeout: true,
        ..Default::default()
    };
    assert!(timeout.start_owned_scope(&plan).is_err());
    assert_eq!(timeout.unit_queries, 0);
    assert_eq!(timeout.property_reads, 0);
    let mut disconnected = SimulatedSystemdBackend {
        available: true,
        disconnect_while_start_pending: true,
        ..Default::default()
    };
    assert!(disconnected.start_owned_scope(&plan).is_err());
    assert_eq!(disconnected.unit_queries, 0);
}

#[test]
fn successful_start_job_precedes_unit_and_property_queries() {
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    let mut backend = SimulatedSystemdBackend {
        available: true,
        start_job_result: Some("done".into()),
        ..Default::default()
    };
    backend.start_owned_scope(&plan).unwrap();
    assert_eq!(backend.starts, 1);
    assert_eq!(backend.unit_queries, 1);
    assert_eq!(backend.property_reads, 1);
    let evidence = backend.start_evidence().unwrap();
    assert!(evidence.mutation_may_have_started);
    assert!(evidence.cleanup_required);
    assert!(evidence.job_done());
    assert_eq!(evidence.unit_object_path, evidence.worker_unit_object_path);
}

#[test]
fn post_start_failure_retains_incremental_evidence_and_is_recoverable() {
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    let mut backend = SimulatedSystemdBackend {
        available: true,
        post_start_read_failure: true,
        ..Default::default()
    };
    assert!(backend.start_owned_scope(&plan).is_err());
    let evidence = backend.start_evidence().unwrap();
    assert!(evidence.job_done());
    assert!(evidence.mutation_may_have_started && evidence.cleanup_required);
    assert!(evidence.unit_object_path.is_some());
    assert!(evidence.control_group.is_none());
    assert!(backend.scope.is_some());
    backend
        .recover_owned_scope(&plan, RecoveryOwnership::ExactOwned)
        .unwrap();
    assert!(backend.scope.is_none());
}

#[test]
fn systemd_readback_contract_routes_unit_and_scope_properties() {
    let expected = [
        ("org.freedesktop.systemd1.Unit", "Id", "s", true),
        ("org.freedesktop.systemd1.Unit", "LoadState", "s", true),
        ("org.freedesktop.systemd1.Unit", "ActiveState", "s", true),
        ("org.freedesktop.systemd1.Unit", "SubState", "s", true),
        ("org.freedesktop.systemd1.Scope", "ControlGroup", "s", true),
        ("org.freedesktop.systemd1.Scope", "MemoryMax", "t", true),
        (
            "org.freedesktop.systemd1.Scope",
            "MemoryAccounting",
            "b",
            true,
        ),
        ("org.freedesktop.systemd1.Scope", "IOAccounting", "b", true),
        (
            "org.freedesktop.systemd1.Scope",
            "RuntimeMaxUSec",
            "t",
            true,
        ),
        (
            "org.freedesktop.systemd1.Scope",
            "MemoryCurrent",
            "t",
            false,
        ),
        ("org.freedesktop.systemd1.Scope", "MemoryPeak", "t", false),
        ("org.freedesktop.systemd1.Scope", "CPUUsageNSec", "t", false),
    ];
    assert_eq!(READBACK_PROPERTY_CONTRACT.len(), expected.len());
    for (interface, property, signature, required) in expected {
        assert!(READBACK_PROPERTY_CONTRACT.iter().any(|entry| {
            entry.interface == interface
                && entry.property == property
                && entry.signature == signature
                && entry.required == required
        }));
    }
    assert!(!READBACK_PROPERTY_CONTRACT.iter().any(|entry| {
        entry.interface == "org.freedesktop.systemd1.Unit"
            && matches!(entry.property, "ControlGroup" | "MemoryMax")
    }));
}

#[test]
fn systemd_261_scope_contract_never_requires_unit_control_group() {
    let xml = r#"
      <interface name="org.freedesktop.systemd1.Unit">
        <property name="Id" type="s" access="read"/>
        <property name="LoadState" type="s" access="read"/>
        <property name="ActiveState" type="s" access="read"/>
        <property name="SubState" type="s" access="read"/>
      </interface>
      <interface name="org.freedesktop.systemd1.Scope">
        <property name="ControlGroup" type="s" access="read"/>
        <property name="MemoryMax" type="t" access="read"/>
        <property name="MemoryAccounting" type="b" access="read"/>
        <property name="IOAccounting" type="b" access="read"/>
        <property name="RuntimeMaxUSec" type="t" access="read"/>
      </interface>
    "#;
    assert!(interface_contract_matches(
        xml,
        "org.freedesktop.systemd1.Unit"
    ));
    assert!(interface_contract_matches(
        xml,
        "org.freedesktop.systemd1.Scope"
    ));
    let source = include_str!("systemd.rs");
    assert!(!source.contains("unit.get_property(\"ControlGroup\")"));
    assert!(!source.contains("unit.get_property(\"MemoryMax\")"));
}

#[test]
fn get_unit_by_pid_mismatch_fails_after_job_done_without_losing_evidence() {
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    let mut backend = SimulatedSystemdBackend {
        available: true,
        worker_unit_mismatch: true,
        ..Default::default()
    };
    assert!(backend.start_owned_scope(&plan).is_err());
    let evidence = backend.start_evidence().unwrap();
    assert!(evidence.job_done());
    assert_ne!(evidence.unit_object_path, evidence.worker_unit_object_path);
}

#[test]
fn configuration_restore_can_pass_while_owned_residue_fails_host_unchanged() {
    let mut gates = CHECKPOINT2_REQUIRED_GATES
        .iter()
        .map(|name| HarnessGate {
            name: (*name).into(),
            state: GateState::Pass,
            detail: "pass".into(),
        })
        .collect::<Vec<_>>();
    gates
        .iter_mut()
        .find(|gate| gate.name == "owned_unit_absent_final")
        .unwrap()
        .state = GateState::Fail;
    gates
        .iter_mut()
        .find(|gate| gate.name == "host_unchanged")
        .unwrap()
        .state = GateState::Fail;
    assert_eq!(
        gates
            .iter()
            .find(|gate| gate.name == "configuration_restored")
            .unwrap()
            .state,
        GateState::Pass
    );
    assert!(!finalize_harness(&gates).required_gates_passed);
}

#[test]
fn unit_disappearance_after_start_job_fails_before_property_read() {
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    let mut backend = SimulatedSystemdBackend {
        available: true,
        unit_disappears_after_start: true,
        ..Default::default()
    };
    assert!(backend.start_owned_scope(&plan).is_err());
    assert_eq!(backend.unit_queries, 1);
    assert_eq!(backend.property_reads, 0);
    assert!(backend.scope.is_none());
}

#[test]
fn stop_method_success_still_requires_job_success() {
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    for result in ["failed", "canceled"] {
        let mut backend = SimulatedSystemdBackend {
            available: true,
            stop_job_result: Some(result.into()),
            ..Default::default()
        };
        backend.start_owned_scope(&plan).unwrap();
        assert!(backend.stop_owned_scope(&plan).is_err());
        assert!(backend.scope.is_some());
    }
    let mut timeout = SimulatedSystemdBackend {
        available: true,
        stop_job_timeout: true,
        ..Default::default()
    };
    timeout.start_owned_scope(&plan).unwrap();
    assert!(timeout.stop_owned_scope(&plan).is_err());
    assert!(timeout.scope.is_some());
}

#[test]
fn collected_before_stop_is_normal_idempotent_state() {
    let plan = TransientScopePlan::new("checkpoint2test", scope_identity()).unwrap();
    let mut backend = SimulatedSystemdBackend {
        available: true,
        ..Default::default()
    };
    assert!(!backend.unit_exists(&plan.unit_name).unwrap());
    backend
        .recover_owned_scope(&plan, RecoveryOwnership::Absent)
        .unwrap();
    assert_eq!(backend.stops, 0);
}

#[test]
fn real_backend_subscribes_before_start_and_queries_after_job_success() {
    let source = include_str!("systemd.rs");
    let run_job_start = source.find("fn run_job(").unwrap();
    let run_job = &source[run_job_start
        ..source
            .find("impl TransientScopeBackend for SystemdDbusBackend")
            .unwrap()];
    assert!(
        run_job.find("\"Subscribe\"").unwrap() < run_job.find("receive_signal_with_args").unwrap()
    );
    assert!(
        run_job.find("receive_signal_with_args").unwrap()
            < run_job.find("\"StartTransientUnit\"").unwrap()
    );
    assert!(run_job.contains("require_successful_job(&outcome)"));

    let implementation = &source[source
        .find("impl TransientScopeBackend for SystemdDbusBackend")
        .unwrap()..];
    let start = &implementation[implementation.find("fn start_owned_scope").unwrap()..];
    assert!(
        start.find("run_job(\"StartTransientUnit\"").unwrap()
            < start.find("unit_path(&plan.unit_name)").unwrap()
    );
    assert!(
        start.find("unit_path(&plan.unit_name)").unwrap() < start.find("unit_path_by_pid").unwrap()
    );
}

#[test]
fn checkpoint2_has_no_raw_cgroup_or_systemd_cli_mutation() {
    let harness = include_str!("harness.rs");
    let systemd = include_str!("systemd.rs");
    assert!(!harness.contains("create_managed_group"));
    assert!(!harness.contains("attach_pid"));
    assert!(!harness.contains("cleanup_empty_owned_group"));
    assert!(!harness.contains("fs::write(&memory_max"));
    assert!(!harness.contains("systemd-run"));
    assert!(!harness.contains("systemctl"));
    assert!(!systemd.contains("Command::new"));
    assert!(!systemd.contains("cgroup.subtree_control"));
    assert!(!systemd.contains("cgroup.procs\"), pid"));
}

#[test]
fn payload_signal_is_ordered_after_scope_verification_in_source() {
    let source = include_str!("harness.rs");
    let property_gate = source
        .find("\"memory_limit_kernel_verified\"")
        .expect("kernel limit gate");
    let allocation_signal = source
        .find("control_dir.join(\"allocate\")")
        .expect("allocation signal");
    assert!(property_gate < allocation_signal);
}

#[test]
fn worker_protocol_forbids_allocation_before_scope_attachment() {
    assert!(!worker_transition_allowed(
        WorkerProtocolState::ReadyOutsideScope,
        WorkerProtocolState::Allocate
    ));
    assert!(worker_transition_allowed(
        WorkerProtocolState::ReadyOutsideScope,
        WorkerProtocolState::ScopeAttached
    ));
    assert!(worker_transition_allowed(
        WorkerProtocolState::ScopeAttached,
        WorkerProtocolState::Allocate
    ));
}

#[test]
fn owned_recovery_is_idempotent_and_foreign_group_is_preserved() {
    let mut owned = SimulatedRecoveryState {
        owned_group: Some("nemor-validation-benchmark-test.scope".into()),
        owned_identity: Some(OwnedProcessIdentity {
            run_id: "r".into(),
            pid: 10,
            start_ticks: 20,
        }),
        group_empty: true,
        foreign_group: false,
        cleaned: false,
    };
    recover_simulated(&mut owned).unwrap();
    recover_simulated(&mut owned).unwrap();
    assert!(owned.cleaned);
    let mut foreign = SimulatedRecoveryState {
        owned_group: Some("foreign.scope".into()),
        owned_identity: None,
        group_empty: true,
        foreign_group: true,
        cleaned: false,
    };
    assert!(recover_simulated(&mut foreign).is_err());
    assert!(foreign.owned_group.is_some());
}

#[test]
fn authoritative_harness_outcome_requires_every_gate() {
    let mut gates = CHECKPOINT2_REQUIRED_GATES
        .iter()
        .map(|name| HarnessGate {
            name: (*name).into(),
            state: GateState::Pass,
            detail: "ok".into(),
        })
        .collect::<Vec<_>>();
    assert_eq!(finalize_harness(&gates).exit_code, 0);
    gates[5].state = GateState::Fail;
    let failed = finalize_harness(&gates);
    assert_eq!(failed.exit_code, 1);
    assert!(!failed.required_gates_passed);
    assert!(!failed.errors.is_empty());
}

fn safe_watchdog_inputs() -> WatchdogInputs {
    WatchdogInputs {
        heartbeat_age_ms: 10,
        heartbeat_timeout_ms: 1_000,
        identity_valid: true,
        observed_pids: BTreeSet::from([10]),
        expected_pid: 10,
        memory_current: 64,
        memory_expectation: 128,
        oom: 0,
        oom_kill: 0,
        host_psi_full_avg10: 0.0,
        host_psi_full_emergency_threshold: 5.0,
        ownership_valid: true,
        unit_present: true,
        unit_state_valid: true,
        control_group_stable: true,
        systemd_connection_valid: true,
        systemd_job_failed: false,
        timed_out: false,
    }
}

#[test]
fn watchdog_timeout_oom_and_host_psi_are_safety_aborts() {
    let mut timeout = safe_watchdog_inputs();
    timeout.heartbeat_age_ms = 1_001;
    assert_eq!(
        evaluate_watchdog(&timeout).reason.as_deref(),
        Some("heartbeat_timeout")
    );
    let mut oom = safe_watchdog_inputs();
    oom.oom = 1;
    assert_eq!(
        evaluate_watchdog(&oom).reason.as_deref(),
        Some("unexpected_oom")
    );
    let mut psi = safe_watchdog_inputs();
    psi.host_psi_full_avg10 = 5.1;
    assert_eq!(
        evaluate_watchdog(&psi).reason.as_deref(),
        Some("host_psi_emergency")
    );
    let mut missing_unit = safe_watchdog_inputs();
    missing_unit.unit_present = false;
    assert_eq!(
        evaluate_watchdog(&missing_unit).reason.as_deref(),
        Some("unit_disappeared_unexpectedly")
    );
    let mut disconnected = safe_watchdog_inputs();
    disconnected.systemd_connection_valid = false;
    assert_eq!(
        evaluate_watchdog(&disconnected).reason.as_deref(),
        Some("systemd_connection_lost")
    );
}

#[test]
fn topology_restore_ignores_cumulative_metric_values() {
    let baseline = StructuralSnapshot {
        swaps: "same".into(),
        swap_topology: vec![],
        swap_runtime_used_kib: BTreeMap::new(),
        zram_configuration: BTreeMap::new(),
        zram_runtime: BTreeMap::new(),
        zswap_enabled: Some("N".into()),
        ksm_configuration: BTreeMap::from([("run".into(), "0".into())]),
        damon_tree_shape: vec![],
    };
    let final_snapshot = baseline.clone();
    let cumulative_before = 1u64;
    let cumulative_after = 2u64;
    assert!(baseline.matches(&final_snapshot));
    assert_ne!(cumulative_before, cumulative_after);
}

fn swap_snapshot(used: u64, size: u64, priority: i32) -> StructuralSnapshot {
    let raw = format!(
        "Filename Type Size Used Priority\n/dev/zram0 partition {size} {used} {priority}\n"
    );
    let (swap_topology, swap_runtime_used_kib) = parse_swap_snapshot(&raw).unwrap();
    StructuralSnapshot {
        swaps: raw,
        swap_topology,
        swap_runtime_used_kib,
        zram_configuration: BTreeMap::from([("zram0.disksize".into(), "16640897024".into())]),
        zram_runtime: BTreeMap::from([("zram0.mm_stat".into(), "runtime".into())]),
        zswap_enabled: Some("N".into()),
        ksm_configuration: BTreeMap::new(),
        damon_tree_shape: vec![],
    }
}

#[test]
fn swap_used_only_change_is_runtime_not_topology() {
    let before = swap_snapshot(1_192_612, 16_250_876, 100);
    let after = swap_snapshot(1_192_580, 16_250_876, 100);
    assert!(before.matches(&after));
    assert_eq!(
        before.runtime_counter_deltas(&after)["swap_used_kib:/dev/zram0"],
        -32
    );
}

#[test]
fn swap_size_priority_and_membership_are_structural() {
    let baseline = swap_snapshot(1, 100, 100);
    assert!(!baseline.matches(&swap_snapshot(1, 101, 100)));
    assert!(!baseline.matches(&swap_snapshot(1, 100, 99)));
    let mut removed = baseline.clone();
    removed.swap_topology.clear();
    assert!(!baseline.matches(&removed));
}

#[test]
fn zram_runtime_change_is_not_structural_but_configuration_is() {
    let baseline = swap_snapshot(1, 100, 100);
    let mut runtime = baseline.clone();
    runtime
        .zram_runtime
        .insert("zram0.mm_stat".into(), "changed".into());
    assert!(baseline.matches(&runtime));
    let mut configuration = baseline.clone();
    configuration
        .zram_configuration
        .insert("zram0.disksize".into(), "different".into());
    assert!(!baseline.matches(&configuration));
}

#[test]
fn checkpoint3a_profile_is_fixed_load_non_pressure_and_bounded() {
    let profile = PerformanceProfile::checkpoint3a(CHECKPOINT3A_DEFAULT_PAYLOAD_BYTES).unwrap();
    assert_eq!(profile.logical_payload_bytes, 128 * 1024 * 1024);
    assert_eq!(profile.worker_memory_max_bytes, 256 * 1024 * 1024);
    assert!(profile.measurement_ms >= 20_000);
    assert!(profile.stabilization_ms >= 2_000);
    assert!(!profile.request_oom);
    assert!(!profile.pressure_mode);
    assert!(PerformanceProfile::checkpoint3a(CHECKPOINT3A_MAX_PAYLOAD_BYTES + 1).is_err());
}

#[test]
fn validation_artifact_policy_is_narrow_and_content_bounded() {
    assert!(recognized_validation_artifact_name(
        "ksm-attempt5-report.json"
    ));
    assert!(recognized_validation_artifact_name(
        "phase10-checkpoint2-attempt5-report.json"
    ));
    assert!(recognized_validation_artifact_name(
        "phase10-checkpoint2-report.json"
    ));
    assert!(!recognized_validation_artifact_name(
        "arbitrary-report.json"
    ));
    assert!(!recognized_validation_artifact_name(
        "phase10-checkpoint3-report.json"
    ));
    assert!(validation_artifact_content_is_bounded_json(
        br#"{"run_id":"bounded"}"#
    ));
    assert!(!validation_artifact_content_is_bounded_json(b"not-json"));

    let root = tempfile::tempdir().unwrap();
    let valid = root.path().join("ksm-attempt5-report.json");
    std::fs::write(&valid, br#"{"run_id":"bounded"}"#).unwrap();
    assert!(is_known_validation_artifact_at(
        root.path(),
        Path::new("ksm-attempt5-report.json")
    ));
    assert!(!status_entry_is_relevant(
        root.path(),
        "?? ksm-attempt5-report.json"
    ));

    std::fs::write(&valid, b"not-json").unwrap();
    assert!(!is_known_validation_artifact_at(
        root.path(),
        Path::new("ksm-attempt5-report.json")
    ));
    assert!(status_entry_is_relevant(
        root.path(),
        "?? ksm-attempt5-report.json"
    ));

    let oversized = vec![b' '; 16 * 1024 * 1024 + 1];
    std::fs::write(&valid, oversized).unwrap();
    assert!(!is_known_validation_artifact_at(
        root.path(),
        Path::new("ksm-attempt5-report.json")
    ));

    std::fs::write(root.path().join("unknown.json"), b"{}").unwrap();
    assert!(status_entry_is_relevant(root.path(), "?? unknown.json"));
    std::fs::create_dir(root.path().join("nested")).unwrap();
    std::fs::write(root.path().join("nested/ksm-attempt5-report.json"), b"{}").unwrap();
    assert!(status_entry_is_relevant(
        root.path(),
        "?? nested/ksm-attempt5-report.json"
    ));
    assert!(status_entry_is_relevant(root.path(), "?? untracked.rs"));
    assert!(status_entry_is_relevant(root.path(), "?? untracked.toml"));
    assert!(status_entry_is_relevant(root.path(), " M README.md"));
}

#[test]
fn relevant_untracked_source_changes_source_state_and_artifacts_do_not() {
    let clean = calculate_source_state_id("head", b"", &[]);
    let source = calculate_source_state_id(
        "head",
        b"",
        &[("crates/new/src/lib.rs".into(), "digest".into())],
    );
    assert_ne!(clean, source);
    assert_eq!(clean, calculate_source_state_id("head", b"", &[]));
}

#[test]
fn baseline_and_observe_reject_foreign_nemord() {
    let foreign = DetectedNemorProcess {
        identity: ProcessIdentity {
            pid: 10,
            start_ticks: 20,
        },
        executable_matches_expected: true,
        owned_by_transaction: false,
    };
    assert!(reject_foreign_nemord(std::slice::from_ref(&foreign), None).is_err());
    assert!(reject_foreign_nemord(
        &[foreign],
        Some(&ProcessIdentity {
            pid: 11,
            start_ticks: 21
        })
    )
    .is_err());
}

#[test]
fn exact_owned_observer_identity_is_accepted_and_never_adopted() {
    let identity = ProcessIdentity {
        pid: 10,
        start_ticks: 20,
    };
    let owned = DetectedNemorProcess {
        identity: identity.clone(),
        executable_matches_expected: true,
        owned_by_transaction: true,
    };
    assert!(reject_foreign_nemord(&[owned], Some(&identity)).is_ok());
    assert!(reject_foreign_nemord(&[], Some(&identity)).is_err());
    assert!(observer_cleanup_allowed(&identity, &identity));
    assert!(!observer_cleanup_allowed(
        &identity,
        &ProcessIdentity {
            pid: identity.pid,
            start_ticks: identity.start_ticks + 1
        }
    ));
}

#[test]
fn observe_configuration_has_zero_mutation_invariant() {
    let safe = ObserverInvariant {
        mode_observe: true,
        automatic_actions_disabled: true,
        cgroup_moves_disabled: true,
        zram_mutation_disabled: true,
        zswap_mutation_disabled: true,
        ksm_live_apply_disabled: true,
        damon_monitor_only: true,
        damos_live_apply_disabled: true,
    };
    safe.validate().unwrap();
    let mut unsafe_config = safe;
    unsafe_config.ksm_live_apply_disabled = false;
    assert!(unsafe_config.validate().is_err());
}

fn checkpoint3a_fixture_plan() -> ExperimentPlan {
    let environment = fixture_environment();
    ExperimentPlan {
        schema_version: BENCHMARK_SCHEMA_VERSION,
        experiment_id: "checkpoint3a-test".into(),
        scenario: CHECKPOINT3A_SCENARIO.into(),
        scenario_version: 1,
        evidence_kind: EvidenceKind::PerformanceBenchmark,
        comparison_purpose: ComparisonPurpose::ObserverOverhead,
        variants: vec![
            BenchmarkVariant::CachyosBaseline,
            BenchmarkVariant::NemorObserve,
        ],
        repetitions: 3,
        experiment_seed: 42,
        randomized_order: deterministic_order(
            &[
                BenchmarkVariant::CachyosBaseline,
                BenchmarkVariant::NemorObserve,
            ],
            3,
            42,
        )
        .into_iter()
        .enumerate()
        .map(|(order_index, (variant, repetition_index))| PlannedRun {
            order_index,
            variant,
            repetition_index,
            run_seed: 42u64.rotate_left(17) ^ repetition_index as u64,
            state: PlannedRunState::Planned,
        })
        .collect(),
        profile: PerformanceProfile::checkpoint3a(CHECKPOINT3A_DEFAULT_PAYLOAD_BYTES).unwrap(),
        provenance: BuildProvenance {
            git_head: "head".into(),
            git_dirty: false,
            source_state_id: "source".into(),
            binary_sha256: "benchmark".into(),
            build_profile: "release".into(),
            benchmark_schema_version: BENCHMARK_SCHEMA_VERSION,
            development_build: false,
        },
        benchmark_binary: BinaryIdentity {
            path_role: "nemor_benchmark".into(),
            sha256: "benchmark".into(),
            build_profile: "release".into(),
            source_state_id: "source".into(),
            embedded_git_head: "head".into(),
        },
        observer_binary: BinaryIdentity {
            path_role: "nemord".into(),
            sha256: "observer".into(),
            build_profile: "release".into(),
            source_state_id: "source".into(),
            embedded_git_head: "head".into(),
        },
        config_hash: "config".into(),
        environment_hash: environment.hash().unwrap(),
        thermal_state_unverified: environment.thermal_state_unverified,
        environment,
        performance_claim_eligible: true,
        capacity_gain_percent: EvaluationState::NotEvaluated,
    }
}

fn checkpoint3a_run(plan: &ExperimentPlan, planned: PlannedRun) -> RunEvidence {
    let snapshot = swap_snapshot(1, 100, 100);
    let observer = (planned.variant == BenchmarkVariant::NemorObserve).then(|| ObserverEvidence {
        identity: ProcessIdentity {
            pid: 50,
            start_ticks: 60,
        },
        binary_sha256: plan.observer_binary.sha256.clone(),
        config_hash: plan.config_hash.clone(),
        started_monotonic_ns: 1,
        measurement_started_monotonic_ns: 2,
        measurement_ended_monotonic_ns: 22_000_000_002,
        stopped_monotonic_ns: 22_000_000_003,
        exit_status: Some(0),
        setup_wall_seconds: 1.0,
        setup_cpu_seconds: 0.1,
        measurement_cpu_seconds: 0.2,
        measurement_cpu_percent: 1.0,
        rss_mean_bytes: Some(1024.0),
        rss_peak_bytes: Some(2048),
        pss_mean_bytes: Some(768.0),
        pss_peak_bytes: Some(1024),
        outside_worker_scope: true,
        isolated_storage_closed: true,
        service_unit: None,
        control_group: None,
        effective_uid: None,
        effective_gid: None,
        settling: None,
        readiness_duration_seconds: None,
    });
    RunEvidence {
        run_id: format!("run-{}", planned.order_index),
        experiment_id: plan.experiment_id.clone(),
        planned,
        valid: true,
        invalid_reason: None,
        safety_failure: false,
        environment_hash: plan.environment_hash.clone(),
        benchmark_binary_sha256: plan.benchmark_binary.sha256.clone(),
        observer_binary_sha256: observer
            .as_ref()
            .map(|_| plan.observer_binary.sha256.clone()),
        worker_manifest_hash: "same-worker".into(),
        worker_cgroup_memory_max: plan.profile.worker_memory_max_bytes,
        logical_payload_bytes: plan.profile.logical_payload_bytes,
        measurement_ms: plan.profile.measurement_ms,
        sample_interval_ms: plan.profile.sample_interval_ms,
        sample_count: 20,
        raw_samples: vec![],
        worker_cpu_seconds: Some(0.1),
        worker_memory_mean_bytes: Some(plan.profile.logical_payload_bytes as f64),
        worker_memory_peak_bytes: Some(plan.profile.logical_payload_bytes),
        runner_cpu_seconds: Some(0.1),
        observer,
        deltas: None,
        watchdog_triggered: false,
        oom: 0,
        oom_kill: 0,
        worker_integrity_valid: true,
        restore_passed: true,
        structural_before: snapshot.clone(),
        structural_after: snapshot,
    }
}

#[test]
fn baseline_and_observe_share_worker_manifest_seed_load_and_envelope() {
    let plan = checkpoint3a_fixture_plan();
    let baseline = checkpoint3a_run(
        &plan,
        PlannedRun {
            order_index: 0,
            variant: BenchmarkVariant::CachyosBaseline,
            repetition_index: 0,
            run_seed: 7,
            state: PlannedRunState::Planned,
        },
    );
    let observe = checkpoint3a_run(
        &plan,
        PlannedRun {
            variant: BenchmarkVariant::NemorObserve,
            ..baseline.planned.clone()
        },
    );
    assert_eq!(baseline.worker_manifest_hash, observe.worker_manifest_hash);
    assert_eq!(baseline.planned.run_seed, observe.planned.run_seed);
    assert_eq!(
        baseline.logical_payload_bytes,
        observe.logical_payload_bytes
    );
    assert_eq!(
        baseline.worker_cgroup_memory_max,
        observe.worker_cgroup_memory_max
    );
    assert!(baseline.observer.is_none());
    assert!(observe.observer.as_ref().unwrap().outside_worker_scope);
}

#[test]
fn observer_setup_cpu_is_separate_from_measurement_cpu_and_memory_is_captured() {
    let plan = checkpoint3a_fixture_plan();
    let run = checkpoint3a_run(
        &plan,
        PlannedRun {
            order_index: 0,
            variant: BenchmarkVariant::NemorObserve,
            repetition_index: 0,
            run_seed: 7,
            state: PlannedRunState::Planned,
        },
    );
    let observer = run.observer.unwrap();
    assert_ne!(observer.setup_cpu_seconds, observer.measurement_cpu_seconds);
    assert!(observer.rss_mean_bytes.is_some());
    assert!(observer.rss_peak_bytes.is_some());
    assert!(observer.pss_mean_bytes.is_some());
    assert!(observer.pss_peak_bytes.is_some());
}

#[test]
fn all_performance_cumulative_sources_use_run_relative_deltas() {
    let before = CounterSnapshot {
        vmstat: BTreeMap::from([
            ("pgmajfault".into(), 10),
            ("pswpin".into(), 20),
            ("pswpout".into(), 30),
        ]),
        psi_totals_usec: BTreeMap::from([("host_some".into(), 40), ("worker_full".into(), 50)]),
        cpu: BTreeMap::from([
            ("runner_ticks".into(), 60),
            ("worker_usage_usec".into(), 70),
        ]),
        io: BTreeMap::from([("rbytes".into(), 80), ("wbytes".into(), 90)]),
    };
    let mut after = before.clone();
    for values in [
        &mut after.vmstat,
        &mut after.psi_totals_usec,
        &mut after.cpu,
        &mut after.io,
    ] {
        for value in values.values_mut() {
            *value += 1;
        }
    }
    let deltas = derive_performance_deltas(&before, &after).unwrap();
    assert!(deltas
        .vmstat
        .values()
        .chain(deltas.psi_totals_usec.values())
        .chain(deltas.cpu.values())
        .chain(deltas.io.values())
        .all(|value| *value == 1));
}

#[test]
fn fixed_load_never_calculates_capacity_acceptance() {
    let plan = checkpoint3a_fixture_plan();
    assert_eq!(plan.capacity_gain_percent, EvaluationState::NotEvaluated);
    let comparison = compare_observer_overhead(
        &plan
            .randomized_order
            .iter()
            .cloned()
            .map(|planned| checkpoint3a_run(&plan, planned))
            .collect::<Vec<_>>(),
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(
        comparison.capacity_gain_percent,
        EvaluationState::NotEvaluated
    );
    assert!(!comparison.significance_claimed);
}

#[test]
fn checkpoint3a_order_is_deterministic_interleaved_and_has_six_runs() {
    let plan = checkpoint3a_fixture_plan();
    assert_eq!(plan.randomized_order.len(), 6);
    assert_eq!(
        plan.randomized_order,
        checkpoint3a_fixture_plan().randomized_order
    );
    assert!(plan
        .randomized_order
        .windows(2)
        .any(|pair| pair[0].variant != pair[1].variant));
    for repetition in 0..3 {
        let seeds = plan
            .randomized_order
            .iter()
            .filter(|run| run.repetition_index == repetition)
            .map(|run| run.run_seed)
            .collect::<BTreeSet<_>>();
        assert_eq!(seeds.len(), 1);
    }
}

#[test]
fn observer_comparison_requires_three_valid_runs_per_variant() {
    let plan = checkpoint3a_fixture_plan();
    let mut runs = plan
        .randomized_order
        .iter()
        .cloned()
        .map(|planned| checkpoint3a_run(&plan, planned))
        .collect::<Vec<_>>();
    runs.retain(|run| {
        run.planned.variant != BenchmarkVariant::NemorObserve || run.planned.repetition_index != 2
    });
    assert!(compare_observer_overhead(&runs, &BTreeMap::new()).is_err());
}

#[test]
fn invalid_runs_are_retained_and_safety_failure_marks_remaining_unexecuted() {
    let plan = checkpoint3a_fixture_plan();
    let mut outcome = ExperimentOutcome {
        plan: plan.clone(),
        runs: vec![],
        aborted_after_order: None,
        comparison: None,
        capacity_gain_percent: EvaluationState::NotEvaluated,
        execution_error: None,
    };
    let mut failed = checkpoint3a_run(&plan, plan.randomized_order[1].clone());
    failed.valid = false;
    failed.safety_failure = true;
    failed.invalid_reason = Some("watchdog".into());
    outcome.record_run(failed);
    assert_eq!(outcome.runs.len(), 1);
    assert!(!outcome.may_continue());
    assert!(outcome
        .plan
        .randomized_order
        .iter()
        .skip(2)
        .all(|run| run.state == PlannedRunState::NotExecutedAfterAbort));
}

#[test]
fn dirty_or_binary_source_mismatch_is_ineligible() {
    let mut plan = checkpoint3a_fixture_plan();
    plan.provenance.git_dirty = true;
    assert!(require_live_eligibility(&plan).is_err());
    plan.provenance.git_dirty = false;
    plan.observer_binary.source_state_id = "other".into();
    assert!(require_live_eligibility(&plan).is_err());
    plan.observer_binary.source_state_id = "source".into();
    plan.observer_binary.embedded_git_head = "other".into();
    assert!(require_live_eligibility(&plan).is_err());
}

#[test]
fn environment_or_worker_manifest_mismatch_blocks_comparison() {
    let plan = checkpoint3a_fixture_plan();
    let mut runs = plan
        .randomized_order
        .iter()
        .cloned()
        .map(|planned| checkpoint3a_run(&plan, planned))
        .collect::<Vec<_>>();
    runs[0].environment_hash = "different".into();
    assert!(compare_observer_overhead(&runs, &BTreeMap::new()).is_err());
    runs[0].environment_hash = plan.environment_hash.clone();
    runs[0].worker_manifest_hash = "different".into();
    assert!(compare_observer_overhead(&runs, &BTreeMap::new()).is_err());
}

#[test]
fn observer_comparison_requires_paired_repetition_seeds() {
    let plan = checkpoint3a_fixture_plan();
    let runs = plan
        .randomized_order
        .iter()
        .cloned()
        .map(|planned| checkpoint3a_run(&plan, planned))
        .collect::<Vec<_>>();
    assert!(compare_observer_overhead(&runs, &BTreeMap::new()).is_ok());
    let mut mismatched = runs;
    if let Some(run) = mismatched
        .iter_mut()
        .find(|run| run.planned.variant == BenchmarkVariant::NemorObserve)
    {
        run.planned.run_seed = run.planned.run_seed.wrapping_add(1);
    }
    assert!(compare_observer_overhead(&mismatched, &BTreeMap::new()).is_err());
}

#[test]
fn thermal_and_optional_energy_are_never_fabricated() {
    let plan = checkpoint3a_fixture_plan();
    assert_eq!(
        plan.thermal_state_unverified,
        plan.environment.thermal_state_unverified
    );
    assert!(MetricValue::unavailable(
        "energy",
        "joules",
        MetricScope::Host,
        "powercap",
        "unavailable"
    )
    .value
    .is_none());
}

#[test]
fn checkpoint3a_persistence_keeps_six_manifests_and_comparison() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("performance.sqlite");
    let plan = checkpoint3a_fixture_plan();
    let runs = plan
        .randomized_order
        .iter()
        .cloned()
        .map(|planned| checkpoint3a_run(&plan, planned))
        .collect::<Vec<_>>();
    let comparison = compare_observer_overhead(&runs, &comparison_metric_inputs(&runs)).unwrap();
    let outcome = ExperimentOutcome {
        plan: plan.clone(),
        runs,
        aborted_after_order: None,
        comparison: Some(comparison),
        capacity_gain_percent: EvaluationState::NotEvaluated,
        execution_error: None,
    };
    persist_experiment(
        &database,
        include_str!("../../../migrations/0008_benchmark.sql"),
        include_str!("../../../migrations/0009_benchmark_performance.sql"),
        &outcome,
    )
    .unwrap();
    let store = BenchmarkStore::open_read_only(&database).unwrap();
    assert_eq!(store.experiment_runs(&plan.experiment_id).unwrap().len(), 6);
    assert_eq!(
        store.comparison(&plan.experiment_id).unwrap()["purpose"],
        "observer_overhead"
    );
}

#[test]
fn capacity_search_refines_only_between_tested_pass_and_fail() {
    let plan = plan_capacity_search(
        &[
            TestedLoadLevel {
                logical_bytes: 100,
                touched_bytes: 100,
                sustainable: true,
                reason: "healthy".into(),
                duration_ms: 1,
                health_metrics_available: true,
            },
            TestedLoadLevel {
                logical_bytes: 200,
                touched_bytes: 200,
                sustainable: false,
                reason: "owned_limit".into(),
                duration_ms: 1,
                health_metrics_available: true,
            },
        ],
        100,
        10,
    )
    .unwrap();
    assert_eq!(plan.refinement_levels, vec![150]);
    assert!(!plan.interpolation_allowed);
    assert!(plan.owned_cgroup_required);
}

#[test]
fn fairness_requires_identical_cgroup_envelope() {
    let baseline = FairnessManifest {
        generator_hash: "g".into(),
        logical_loads: vec![1],
        seeds: vec![2],
        worker_binary_sha256: "b".into(),
        warmup_ms: 1,
        stabilization_ms: 1,
        cgroup_memory_max: 10,
        kernel: "k".into(),
        host_fingerprint_hash: "h".into(),
        thermal_procedure: "same".into(),
    };
    assert!(baseline.comparable_with(&baseline).is_ok());
    let mut unfair = baseline.clone();
    unfair.cgroup_memory_max = 20;
    assert!(baseline.comparable_with(&unfair).is_err());
}

fn fixture_environment() -> EnvironmentFingerprint {
    EnvironmentFingerprint {
        schema_version: 1,
        nemor_commit: "abc".into(),
        nemor_version: "0".into(),
        config_hash: "cfg".into(),
        kernel_release: "kernel".into(),
        distro_id: "cachyos".into(),
        distro_version: "1".into(),
        cpu_model: "cpu".into(),
        logical_cpus: 8,
        total_ram_bytes: 16,
        swap_topology: vec![],
        zram_inventory: vec![],
        zswap_state: "N".into(),
        root_filesystem: "ext4".into(),
        storage_class: "nvme_present".into(),
        gpu_identity: None,
        cgroup_v2: true,
        psi: true,
        damon: true,
        ksm: true,
        ksm_run: Some(0),
        cpu_governor: None,
        power_profile: None,
        thermal_sensor_available: false,
        energy_provider: None,
        thermal_state_unverified: true,
    }
}

fn fixture_report() -> BenchmarkReport {
    let environment = fixture_environment();
    let provenance = BuildProvenance {
        git_head: "abc".into(),
        git_dirty: true,
        source_state_id: "source".into(),
        binary_sha256: "binary".into(),
        build_profile: "debug".into(),
        benchmark_schema_version: 1,
        development_build: true,
    };
    BenchmarkReport {
        schema_version: 1,
        evidence_kind: EvidenceKind::FrameworkSmoke,
        performance_claim_eligible: false,
        provenance,
        run_id: "run-1".into(),
        scenario: required_scenarios()
            .into_iter()
            .find(|s| s.scenario_id == ScenarioId::SyntheticCompressible)
            .unwrap(),
        variant: BenchmarkVariant::CachyosBaseline,
        variant_resolution: resolve_variant(
            BenchmarkVariant::CachyosBaseline,
            &VariantResolutionContext {
                baseline_state: BTreeMap::new(),
                observe_executable: true,
                safe_executable: false,
                gaming_executable: false,
                capacity_executable: false,
                distinct_zram_configuration: None,
                zswap_boot_validated: false,
            },
        ),
        repetition: 0,
        seed: 1,
        run_order: 0,
        state: RunState::Completed,
        valid: true,
        invalid_reason: None,
        environment_hash: environment.hash().unwrap(),
        environment,
        metrics: vec![MetricValue::measured(
            "rss",
            1.0,
            "bytes",
            MetricScope::Process,
            "fixture",
        )],
        synthetic: None,
        synthetic_cpu: None,
        logical_workload_bytes: 1,
        physical_memory_bytes: Some(1),
        restore_verified: true,
        limitations: vec![],
        acceptance: AcceptanceResult {
            favorable_capacity: EvaluationState::NotEvaluated,
            gaming_capacity: EvaluationState::NotEvaluated,
            cpu_bound: EvaluationState::NotEvaluated,
            gaming_frametime: EvaluationState::NotEvaluated,
            incompressible_regression: EvaluationState::NotEvaluated,
            restore: EvaluationState::Pass,
        },
        started_monotonic_ns: 0,
        ended_monotonic_ns: 1,
    }
}

#[test]
fn checkpoint3a_execution_requires_prepared_manifest_and_service_backend() {
    let source = include_str!("performance.rs");
    let cli = include_str!("main.rs");
    let harness = include_str!("harness.rs");
    assert!(cli.contains("PrepareExperiment"));
    assert!(cli.contains("ExecuteExperiment"));
    assert!(cli.contains("ExperimentPreflight"));
    assert!(source.contains("PreparedExperimentManifest"));
    assert!(source.contains("execute_prepared_experiment"));
    assert!(source.contains("unsupported validated observer service contract version"));
    assert!(!harness.contains("cannot spawn exact owned nemord observer"));
    assert!(harness.contains("start_performance_observer"));
}

#[test]
fn checkpoint3a_runtime_bound_exceeds_measurement_and_is_finite() {
    let profile = crate::performance::PerformanceProfile::checkpoint3a(
        crate::performance::CHECKPOINT3A_DEFAULT_PAYLOAD_BYTES,
    )
    .unwrap();
    let runtime = crate::performance::performance_runtime_max_usec(&profile);
    assert!(runtime > profile.measurement_ms * 1_000);
    assert!(runtime <= crate::observer_service::PERFORMANCE_SERVICE_RUNTIME_MAX_USEC);
}
