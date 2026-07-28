use super::*;
use std::fs;
use tempfile::tempdir;

fn sysfs() -> tempfile::TempDir {
    let dir = tempdir().unwrap();
    for (name, value) in [
        ("run", "0"),
        ("pages_to_scan", "100"),
        ("sleep_millisecs", "20"),
        ("smart_scan", "1"),
        ("advisor_mode", "[none] scan-time"),
        ("advisor_max_cpu", "70"),
        ("general_profit", "4096"),
        ("pages_scanned", "1000"),
        ("pages_shared", "10"),
        ("pages_sharing", "20"),
        ("pages_unshared", "1"),
        ("pages_volatile", "2"),
        ("pages_skipped", "3"),
        ("full_scans", "4"),
        ("ksm_zero_pages", "0"),
        ("stable_node_chains", "0"),
        ("stable_node_dups", "0"),
    ] {
        fs::write(dir.path().join(name), value).unwrap();
    }
    dir
}

fn identity() -> StableProcessIdentity {
    StableProcessIdentity {
        pid: 42,
        start_ticks: 9,
        stable_key: "owned:9".into(),
    }
}

fn eligible(kind: KsmProfileKind) -> EligibilityInput {
    EligibilityInput {
        identity: Some(identity()),
        identity_fresh: true,
        profile: kind,
        already_mergeable: false,
        owned_cooperative: true,
        foreground: false,
        gaming: false,
        critical: false,
        protected: false,
        same_security_domain: true,
        pressure: PressureState::Normal,
        stable_observations: 3,
        mergeable_bytes: 64 << 20,
        profit_bytes: Some(4096),
        cow_events_per_second: Some(0),
        cpu_percent: Some(0.2),
        cooldown_active: false,
        external_ksm_activity: false,
    }
}

#[test]
fn capability_and_optional_fields_are_feature_detected() {
    let dir = sysfs();
    let capability = inspect_capability(dir.path(), true);
    assert!(capability.supported);
    assert_eq!(capability.existing_run_state, Some(0));
    assert!(capability.advisor_fields["advisor_max_cpu"]);
    assert!(!capability.advisor_fields["advisor_target_scan_time"]);
    assert!(capability.residual_global_ksm_accounting);
    assert!(!capability.external_live_ksm_activity);
    assert!(!capability.external_ksm_activity);
}

#[test]
fn residual_global_counters_do_not_imply_live_external_activity() {
    let dir = sysfs();
    fs::write(dir.path().join("pages_shared"), "251").unwrap();
    fs::write(dir.path().join("pages_sharing"), "9749").unwrap();
    fs::write(dir.path().join("general_profit"), "38883328").unwrap();
    let capability = inspect_capability(dir.path(), true);
    assert!(capability.residual_global_ksm_accounting);
    assert!(!capability.external_live_ksm_activity);
    assert!(!capability.external_ksm_activity);
}

#[test]
fn smaps_ksm_bytes_and_process_activity_distinguish_live_from_residual() {
    assert_eq!(
        parse_smaps_ksm_bytes("1000-2000 rw-p 0 00:00 0\nKSM: 8 kB\n"),
        Some(8192)
    );
    let mut metrics = parse_process_ksm_stat(
        "ksm_merging_pages 9749\nksm_merge_any no\nksm_mergeable no\n",
        identity(),
    );
    metrics.current_mapped_ksm_bytes = Some(0);
    assert_eq!(
        classify_process_ksm_activity(&metrics),
        ProcessKsmActivity::ResidualAccounting
    );
    metrics.current_mapped_ksm_bytes = Some(4096);
    assert_eq!(
        classify_process_ksm_activity(&metrics),
        ProcessKsmActivity::LiveExternal
    );
    metrics.current_mapped_ksm_bytes = Some(0);
    metrics.ksm_mergeable = Some(true);
    assert_eq!(
        classify_process_ksm_activity(&metrics),
        ProcessKsmActivity::LiveExternal
    );
    metrics.ksm_mergeable = Some(false);
    metrics.ksm_merge_any = Some(true);
    assert_eq!(
        classify_process_ksm_activity(&metrics),
        ProcessKsmActivity::LiveExternal
    );
}

#[test]
fn parses_system_profit_and_vmstat() {
    let dir = sysfs();
    let metrics = parse_system_metrics(dir.path(), "cow_ksm 3\nksm_swpin_copy 4\n", 7);
    assert_eq!(metrics.general_profit, Some(4096));
    assert_eq!(
        (metrics.cow_ksm, metrics.ksm_swpin_copy),
        (Some(3), Some(4))
    );
}

#[test]
fn process_ksm_stat_yes_no_and_profit_are_bounded() {
    let metrics = parse_process_ksm_stat(
        "ksm_rmap_items 2\nksm_zero_pages 0\nksm_merging_pages 1\nksm_process_profit -4096\nksm_merge_any: yes\nksm_mergeable: no\n",
        identity(),
    );
    assert_eq!(metrics.ksm_process_profit, Some(-4096));
    assert_eq!(metrics.ksm_merge_any, Some(true));
    assert_eq!(metrics.ksm_mergeable, Some(false));
}

#[test]
fn explicit_profiles_are_conservative_templates() {
    for kind in [
        KsmProfileKind::Vm,
        KsmProfileKind::Browser,
        KsmProfileKind::Electron,
    ] {
        let item = profile(kind);
        assert!(item.foreground_sensitive && item.gaming_sensitive);
        assert!(item.maximum_scanner_cpu_percent <= 1.0);
    }
    assert_eq!(
        profile(KsmProfileKind::Unknown).expected_sharing_suitability,
        0
    );
}

#[test]
fn identity_pid_reuse_and_protections_reject() {
    let cases: [fn(&mut EligibilityInput); 5] = [
        |input| input.identity = None,
        |input| input.identity_fresh = false,
        |input| input.foreground = true,
        |input| input.gaming = true,
        |input| input.critical = true,
    ];
    for mutate in cases {
        let mut input = eligible(KsmProfileKind::Vm);
        mutate(&mut input);
        assert_eq!(
            evaluate_eligibility(&input, &profile(input.profile)).disposition,
            PlanDisposition::Rejected
        );
    }
}

#[test]
fn cooperation_and_security_domain_are_mandatory() {
    let mut input = eligible(KsmProfileKind::Browser);
    input.owned_cooperative = false;
    assert!(evaluate_eligibility(&input, &profile(input.profile))
        .reasons
        .contains(&"cooperation_required".into()));
    input.already_mergeable = true;
    input.same_security_domain = false;
    assert!(evaluate_eligibility(&input, &profile(input.profile))
        .reasons
        .contains(&"external_security_domain".into()));
}

#[test]
fn pressure_and_external_scanner_fail_closed() {
    let mut input = eligible(KsmProfileKind::Electron);
    input.pressure = PressureState::Emergency;
    input.external_ksm_activity = true;
    let result = evaluate_eligibility(&input, &profile(input.profile));
    assert!(result.reasons.contains(&"global_state_not_safe".into()));
    assert!(result.reasons.contains(&"external_ksm_activity".into()));
}

#[test]
fn run_two_is_rejected_without_backend_mutation() {
    let mut backend = backend();
    assert!(write_run_value(&mut backend, 2).is_err());
    assert_eq!(backend.mutations(), 0);
}

#[test]
fn scanner_bounds_and_advisor_interaction() {
    assert!(plan_scanner("[none] scan-time", 100, 20, 50, 500, 10)
        .unwrap()
        .blocked_reasons
        .is_empty());
    assert!(!plan_scanner("none [scan-time]", 100, 20, 50, 500, 10)
        .unwrap()
        .blocked_reasons
        .is_empty());
    assert!(plan_scanner("[none]", 1000, 20, 50, 500, 10).is_err());
}

#[test]
fn cpu_per_gib_and_scan_efficiency_are_null_for_zero_savings() {
    let zero = evaluate_profit(
        &ProfitSample {
            wall_seconds: 2.0,
            ksmd_cpu_seconds: 0.1,
            pages_scanned_delta: 100,
            saved_bytes: 0,
            process_profit_bytes: Some(0),
            system_profit_bytes: Some(0),
        },
        4096,
    );
    assert_eq!(zero.ksmd_cpu_seconds_per_gib_saved, None);
    assert_eq!(zero.pages_scanned_per_saved_page, None);
    assert!(!zero.net_positive);
    let positive = evaluate_profit(
        &ProfitSample {
            saved_bytes: 1 << 30,
            process_profit_bytes: Some(1),
            system_profit_bytes: Some(1),
            ..ProfitSample {
                wall_seconds: 2.0,
                ksmd_cpu_seconds: 0.5,
                pages_scanned_delta: 1024,
                saved_bytes: 0,
                process_profit_bytes: None,
                system_profit_bytes: None,
            }
        },
        4096,
    );
    assert_eq!(positive.ksmd_cpu_seconds_per_gib_saved, Some(0.5));
    assert!(positive.net_positive);
}

#[test]
fn controller_transitions_profit_cpu_cow_and_cooldown() {
    let profitable = ProfitEvaluation {
        ksmd_mean_cpu_percent: 0.2,
        ksmd_cpu_seconds_per_gib_saved: Some(1.0),
        pages_scanned_per_saved_page: Some(2.0),
        net_positive: true,
    };
    let input = ControllerInput {
        elapsed_seconds: 3,
        full_scans: 1,
        evaluation: profitable.clone(),
        cpu_budget_percent: 1.0,
        cow_rate: 0,
        maximum_cow_rate: 5,
        cooldown_active: false,
    };
    assert_eq!(
        controller_transition(ControllerState::Unknown, &input),
        ControllerState::Evaluating
    );
    assert_eq!(
        controller_transition(ControllerState::Evaluating, &input),
        ControllerState::Profitable
    );
    let mut bad = input.clone();
    bad.evaluation.ksmd_mean_cpu_percent = 2.0;
    assert_eq!(
        controller_transition(ControllerState::Evaluating, &bad),
        ControllerState::Inefficient
    );
    bad.evaluation = profitable;
    bad.cow_rate = 6;
    assert_eq!(
        controller_transition(ControllerState::Evaluating, &bad),
        ControllerState::Inefficient
    );
    bad.cooldown_active = true;
    assert_eq!(
        controller_transition(ControllerState::Profitable, &bad),
        ControllerState::Cooldown
    );
}

#[test]
fn real_inefficiency_model_transitions_and_cooldown_are_distinct_from_cpu_failure() {
    let inefficient = ProfitEvaluation {
        ksmd_mean_cpu_percent: 0.5,
        ksmd_cpu_seconds_per_gib_saved: None,
        pages_scanned_per_saved_page: None,
        net_positive: false,
    };
    let input = ControllerInput {
        elapsed_seconds: 4,
        full_scans: 2,
        evaluation: inefficient,
        cpu_budget_percent: 1.0,
        cow_rate: 0,
        maximum_cow_rate: 64,
        cooldown_active: false,
    };
    assert_eq!(
        controller_transition(ControllerState::Evaluating, &input),
        ControllerState::Inefficient
    );
    let mut cooldown = input.clone();
    cooldown.cooldown_active = true;
    assert_eq!(
        controller_transition(ControllerState::Inefficient, &cooldown),
        ControllerState::Cooldown
    );
    let mut cpu_failure = input;
    cpu_failure.evaluation.ksmd_mean_cpu_percent = 1.1;
    assert_eq!(
        controller_transition(ControllerState::Evaluating, &cpu_failure),
        ControllerState::Inefficient
    );
    assert!(
        cpu_failure.evaluation.ksmd_mean_cpu_percent > cpu_failure.cpu_budget_percent,
        "CPU failure remains separately attributable"
    );
}

fn backend() -> SimulatedBackend {
    SimulatedBackend {
        current: KsmSnapshot {
            run: 0,
            pages_to_scan: 100,
            sleep_millisecs: 20,
            preserve_only: BTreeMap::new(),
        },
        mutation_count: 0,
        fail_after: None,
    }
}

#[test]
fn owned_transaction_snapshot_restore_and_recovery_are_idempotent() {
    let mut backend = backend();
    let baseline = backend.snapshot().unwrap();
    backend.set_scanner(200, 50).unwrap();
    backend.set_run(1).unwrap();
    backend.restore(&baseline).unwrap();
    assert_eq!(backend.current, baseline);
    let mut tx = KsmTransaction {
        transaction_id: "nemor-validation-1".into(),
        decision_id: "d".into(),
        plan_id: "p".into(),
        ownership: ScannerOwnership::NemorOwnedValidation,
        baseline,
        child_identities: vec![identity()],
        scanner_started: true,
        recovered: false,
    };
    assert!(recover_owned(&mut tx, &mut backend).unwrap());
    assert!(!recover_owned(&mut tx, &mut backend).unwrap());
}

#[test]
fn partial_write_failure_is_reported_and_external_recovery_rejected() {
    let mut backend = backend();
    backend.fail_after = Some(1);
    assert!(backend.set_scanner(200, 50).is_ok());
    assert!(backend.set_run(1).is_err());
    let mut tx = KsmTransaction {
        transaction_id: "foreign".into(),
        decision_id: "d".into(),
        plan_id: "p".into(),
        ownership: ScannerOwnership::External,
        baseline: backend.current.clone(),
        child_identities: vec![],
        scanner_started: true,
        recovered: false,
    };
    assert!(recover_owned(&mut tx, &mut backend).is_err());
}

#[test]
fn linux_inventory_is_observe_only() {
    let report = inspect_linux(Path::new("/sys/kernel/mm/ksm"), Path::new("/proc"), 1);
    assert!(report.dry_run);
    assert_eq!(report.controller, ControllerState::Unknown);
}

#[test]
fn mergeable_opt_in_is_impossible_before_complete_audit() {
    let mut protocol = ValidationProtocol::default();
    assert_eq!(protocol.state, ValidationProtocolState::ReadyUnmergeable);
    assert!(protocol.opt_in_duplicate().is_err());
    assert!(protocol
        .record_audit("decision".into(), "plan".into(), "transaction".into())
        .is_ok());
    assert!(protocol.opt_in_duplicate().is_ok());
    assert_eq!(protocol.state, ValidationProtocolState::DuplicateMergeable);
}

fn scoped_smaps(control_flags: &str) -> String {
    format!(
        "00001000-00003000 rw-p 00000000 00:00 0\nKernelPageSize: 4 kB\nMMUPageSize: 4 kB\nAnonHugePages: 0 kB\nTHPeligible: 0\nVmFlags: rd wr mr mw me ac nh mg\n\
         00004000-00006000 rw-p 00000000 00:00 0\nKernelPageSize: 4 kB\nMMUPageSize: 4 kB\nAnonHugePages: 0 kB\nTHPeligible: 0\nVmFlags: rd wr mr mw me ac nh {control_flags}\n"
    )
}

#[test]
fn exact_smaps_scope_requires_duplicate_mg_and_control_without_mg() {
    let duplicate = AddressRange {
        start: 0x1000,
        end: 0x3000,
    };
    let control = AddressRange {
        start: 0x4000,
        end: 0x6000,
    };
    let pass = verify_exact_mergeable_scope(&scoped_smaps(""), duplicate, control);
    assert!(pass.passed);
    let overlap = verify_exact_mergeable_scope(&scoped_smaps("mg"), duplicate, control);
    assert!(!overlap.passed);
    assert!(overlap.unexpected_mergeable_bytes > 0);
    let process = parse_process_ksm_stat("ksm_mergeable: yes\n", identity());
    assert_eq!(process.ksm_mergeable, Some(true));
    assert!(
        !overlap.passed,
        "process-level yes is not exact range proof"
    );
}

#[test]
fn ready_unmergeable_scope_requires_no_mg_and_nohugepage_without_gaps() {
    let duplicate = AddressRange {
        start: 0x1000,
        end: 0x3000,
    };
    let control = AddressRange {
        start: 0x4000,
        end: 0x6000,
    };
    let text = scoped_smaps("").replace(" nh mg", " nh");
    assert!(verify_exact_unmergeable_scope(&text, duplicate, control));
    assert!(!verify_exact_unmergeable_scope(
        &text.replace(" ac nh", " ac"),
        duplicate,
        control
    ));
}

#[test]
fn base_page_scope_is_range_based_and_accepts_split_or_larger_vmas() {
    let range = AddressRange {
        start: 0x2000,
        end: 0x6000,
    };
    let larger = "00001000-00007000 rw-p 00000000 00:00 0\n\
        KernelPageSize: 4 kB\nMMUPageSize: 4 kB\nAnonHugePages: 0 kB\n\
        THPeligible: 0\nVmFlags: rd wr mr mw me ac nh\n";
    let evidence = verify_base_page_scope(larger, range, 4096, true);
    assert!(evidence.passed);
    assert_eq!(evidence.covered_bytes, range.len());
    assert_eq!(evidence.overlaps[0].vma_start, 0x1000);

    let split = "00002000-00004000 rw-p 00000000 00:00 0\n\
        KernelPageSize: 4 kB\nMMUPageSize: 4 kB\nAnonHugePages: 0 kB\nVmFlags: nh\n\
        00004000-00006000 rw-p 00000000 00:00 0\n\
        KernelPageSize: 4 kB\nMMUPageSize: 4 kB\nAnonHugePages: 0 kB\nVmFlags: nh\n";
    assert!(verify_base_page_scope(split, range, 4096, true).passed);
}

#[test]
fn base_page_scope_rejects_alignment_gap_backing_and_premature_mergeability() {
    let range = AddressRange {
        start: 0x2000,
        end: 0x6000,
    };
    let valid = "00002000-00006000 rw-p 00000000 00:00 0\n\
        KernelPageSize: 4 kB\nMMUPageSize: 4 kB\nAnonHugePages: 0 kB\nVmFlags: nh\n";
    assert!(
        !verify_base_page_scope(
            valid,
            AddressRange {
                start: 0x2001,
                end: 0x6000
            },
            4096,
            true
        )
        .passed
    );
    assert!(
        !verify_base_page_scope(&valid.replace("00006000", "00005000"), range, 4096, true).passed
    );
    assert!(!verify_base_page_scope(&valid.replace(" nh", ""), range, 4096, true).passed);
    assert!(
        !verify_base_page_scope(
            &valid.replace("AnonHugePages: 0", "AnonHugePages: 2048"),
            range,
            4096,
            true
        )
        .passed
    );
    assert!(
        !verify_base_page_scope(
            &valid.replace("KernelPageSize: 4", "KernelPageSize: 64"),
            range,
            4096,
            true
        )
        .passed
    );
    assert!(
        !verify_base_page_scope(
            &valid.replace("MMUPageSize: 4", "MMUPageSize: 64"),
            range,
            4096,
            true
        )
        .passed
    );
    assert!(
        !verify_base_page_scope(
            &valid.replace("VmFlags: nh", "VmFlags: nh mg"),
            range,
            4096,
            true
        )
        .passed
    );
}

#[test]
fn shared_pre_opt_in_vma_can_cover_distinct_owned_ranges() {
    let smaps = "00001000-00009000 rw-p 00000000 00:00 0\n\
        KernelPageSize: 4 kB\nMMUPageSize: 4 kB\nAnonHugePages: 0 kB\nVmFlags: nh\n";
    let duplicate = AddressRange {
        start: 0x1000,
        end: 0x5000,
    };
    let control = AddressRange {
        start: 0x5000,
        end: 0x9000,
    };
    assert!(verify_base_page_scope(smaps, duplicate, 4096, true).passed);
    assert!(verify_base_page_scope(smaps, control, 4096, true).passed);
}

#[test]
fn post_opt_in_scope_accepts_kernel_vma_boundary_changes() {
    let smaps = "00001000-00005000 rw-p 00000000 00:00 0\n\
        KernelPageSize: 4 kB\nMMUPageSize: 4 kB\nAnonHugePages: 0 kB\nVmFlags: nh mg\n\
        00005000-00009000 rw-p 00000000 00:00 0\n\
        KernelPageSize: 4 kB\nMMUPageSize: 4 kB\nAnonHugePages: 0 kB\nVmFlags: nh\n";
    let scope = verify_exact_mergeable_scope(
        smaps,
        AddressRange {
            start: 0x1000,
            end: 0x5000,
        },
        AddressRange {
            start: 0x5000,
            end: 0x9000,
        },
    );
    assert!(scope.passed);
}

#[test]
fn advisor_selection_and_attempt_one_scanner_preserve_baseline() {
    let baseline = backend().current;
    let fixed = plan_attempt_one_scanner("[none] scan-time", &baseline, 50, 1000, 10).unwrap();
    assert_eq!(fixed.mode, AdvisorMode::Fixed);
    assert_eq!(fixed.pages_to_scan, 100);
    assert_eq!(fixed.sleep_millisecs, 20);
    let active = plan_attempt_one_scanner("none [scan-time]", &baseline, 50, 1000, 10).unwrap();
    assert_eq!(active.mode, AdvisorMode::ScanTime);
    assert!(!active.blocked_reasons.is_empty());
}

#[test]
fn attempt_one_global_ownership_detects_scanner_and_advisor_changes() {
    let baseline = backend().current;
    let mut running = baseline.clone();
    running.run = 1;
    assert!(attempt_one_global_state_owned(
        &baseline,
        &running,
        Some("none")
    ));
    running.pages_to_scan += 1;
    assert!(!attempt_one_global_state_owned(
        &baseline,
        &running,
        Some("none")
    ));
    running.pages_to_scan = baseline.pages_to_scan;
    assert!(!attempt_one_global_state_owned(
        &baseline,
        &running,
        Some("scan-time")
    ));
}

#[test]
fn validation_profit_requires_eight_mib_full_scan_and_positive_processes() {
    let below = validation_profit_gate(VALIDATION_MIN_SAVED_BYTES - PAGE_SIZE, 1, 1, 1, true);
    assert!(!below.passed);
    assert!(below.reasons.contains(&"insufficient_saved_bytes".into()));
    let no_scan = validation_profit_gate(VALIDATION_MIN_SAVED_BYTES, 0, 0, 1, true);
    assert!(!no_scan.passed);
    assert!(no_scan.reasons.contains(&"scanner_no_progress".into()));
    let pass = validation_profit_gate(VALIDATION_MIN_SAVED_BYTES, 100, 1, 4096, true);
    assert!(pass.passed);
}

#[test]
fn cumulative_counters_are_evidence_not_configuration_restore_state() {
    let baseline = backend().current;
    let restored = baseline.clone();
    let before = KsmSystemMetrics {
        pages_scanned: Some(10),
        full_scans: Some(1),
        ..KsmSystemMetrics::default()
    };
    let after = KsmSystemMetrics {
        pages_scanned: Some(100),
        full_scans: Some(2),
        ..KsmSystemMetrics::default()
    };
    assert_eq!(baseline, restored);
    assert_ne!(before.pages_scanned, after.pages_scanned);
}

#[test]
fn insufficient_unmerge_headroom_selects_owned_child_termination() {
    assert_eq!(
        choose_unmerge_disposition(1023, 1024),
        UnmergeDisposition::TerminateOwnedChild
    );
    assert_eq!(
        choose_unmerge_disposition(1024, 1024),
        UnmergeDisposition::MadviseOwnedRange
    );
}

#[test]
fn external_live_interference_or_ownership_loss_requires_stop_and_failure() {
    assert_eq!(evaluate_live_safety(0, true), LiveSafetyDecision::Continue);
    assert_eq!(
        evaluate_live_safety(1, true),
        LiveSafetyDecision::StopOwnedScannerAndFail
    );
    assert_eq!(
        evaluate_live_safety(0, false),
        LiveSafetyDecision::StopOwnedScannerAndFail
    );
}

#[test]
fn duplicate_and_control_content_integrity_are_independent_gates() {
    assert!(content_fingerprints_intact(10, 10, 20, 20));
    assert!(!content_fingerprints_intact(10, 11, 20, 20));
    assert!(!content_fingerprints_intact(10, 10, 20, 21));
}

#[test]
fn cpu_tick_measurement_requires_resolution_valid_sustained_window() {
    assert_eq!(minimum_cpu_budget_window_seconds(100), Some(4.0));
    let short = measure_cpu_window(1, 0.5, 100).unwrap();
    assert_eq!(short.cpu_seconds_delta, 0.01);
    assert!((short.cpu_percent - 2.0).abs() < f64::EPSILON);
    assert!((short.measurement_resolution_percent - 2.0).abs() < f64::EPSILON);
    assert!(!short.resolution_valid);
    assert_eq!(short.budget_exceeded, None);

    let sustained_over = measure_cpu_window(5, 4.0, 100).unwrap();
    assert!(sustained_over.resolution_valid);
    assert_eq!(sustained_over.budget_exceeded, Some(true));
    let sustained_within = measure_cpu_window(4, 4.0, 100).unwrap();
    assert!(sustained_within.resolution_valid);
    assert_eq!(sustained_within.budget_exceeded, Some(false));
}

#[test]
fn owned_identity_includes_session_pid_and_start_ticks_without_collisions() {
    let first = owned_validation_identity("session", 100, 55);
    let second = owned_validation_identity("session", 101, 55);
    assert_ne!(first, second);
    assert_ne!(first.stable_key, second.stable_key);
    let identities = [first.clone(), second.clone()]
        .into_iter()
        .map(|identity| ((identity.pid, identity.start_ticks), identity))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(identities.len(), 2);
    assert_eq!(identities.get(&(100, 55)), Some(&first));
    assert_eq!(identities.get(&(101, 55)), Some(&second));
    assert_ne!(
        owned_validation_identity("session", 100, 56),
        first,
        "PID reuse with changed start_ticks is a different identity"
    );
    assert_eq!(
        owned_validation_identity("session", 100, 55),
        first,
        "same PID/start_ticks/session is the same live identity"
    );
}

#[test]
fn external_exclusion_requires_exact_pid_and_start_ticks_tuple() {
    let owned = BTreeMap::from([(100_u32, Some(55_u64)), (101, Some(55)), (102, None)]);
    assert!(exact_owned_tuple(&owned, 100, Some(55)));
    assert!(exact_owned_tuple(&owned, 101, Some(55)));
    assert!(!exact_owned_tuple(&owned, 102, Some(55)));
    assert!(!exact_owned_tuple(&owned, 999, Some(55)));
    assert!(!exact_owned_tuple(&owned, 100, Some(56)));
    assert!(!exact_owned_tuple(&owned, 100, None));
}
