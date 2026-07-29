use super::*;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

fn attrs() -> MonitoringAttrs {
    MonitoringAttrs {
        operation: "vaddr".to_owned(),
        sample_us: 5_000,
        aggr_us: 100_000,
        update_us: 1_000_000,
        min_regions: 10,
        max_regions: 1_000,
        addr_unit: None,
    }
}

#[test]
fn capability_absent_and_present_are_safe() {
    let root = TempDir::new().unwrap();
    assert!(!inspect_linux(root.path(), None).supported);
    fs::create_dir_all(root.path().join("sys/kernel/mm/damon/admin/kdamonds")).unwrap();
    fs::write(
        root.path()
            .join("sys/kernel/mm/damon/admin/kdamonds/nr_kdamonds"),
        "0\n",
    )
    .unwrap();
    let found = inspect_linux(root.path(), Some("test".to_owned()));
    assert!(found.supported && found.readable && !found.active_external_session);
}

#[test]
fn observability_distinguishes_absent_hidden_and_inspection_error() {
    assert!(matches!(
        classify_error(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        Observation::PrivilegeHidden
    ));
    assert!(matches!(
        classify_error(&std::io::Error::from(std::io::ErrorKind::NotFound)),
        Observation::Absent
    ));
    assert!(matches!(
        classify_error(&std::io::Error::from(std::io::ErrorKind::InvalidData)),
        Observation::InspectionError(_)
    ));
}

#[test]
fn observability_reports_tracepoint_presence_and_absence_without_boolean_collapse() {
    let root = TempDir::new().unwrap();
    let base = root.path().join("sys/kernel/mm/damon/admin/kdamonds");
    fs::create_dir_all(&base).unwrap();
    fs::write(base.join("nr_kdamonds"), "0\n").unwrap();
    let tracepoint = root
        .path()
        .join("sys/kernel/tracing/events/damon/damon_aggregated");
    fs::create_dir_all(&tracepoint).unwrap();
    let observed = inspect_linux_observability(root.path());
    assert_eq!(observed.tracefs, Observation::Observed(true));
    assert_eq!(observed.aggregated_tracepoint, Observation::Observed(true));

    fs::remove_dir_all(tracepoint).unwrap();
    let absent = inspect_linux_observability(root.path());
    assert_eq!(absent.aggregated_tracepoint, Observation::Absent);
}

#[test]
fn observability_reports_permission_hidden_nr_and_tracepoint() {
    let root = TempDir::new().unwrap();
    let base = root.path().join("sys/kernel/mm/damon/admin/kdamonds");
    fs::create_dir_all(&base).unwrap();
    let nr = base.join("nr_kdamonds");
    fs::write(&nr, "0\n").unwrap();
    fs::set_permissions(&nr, fs::Permissions::from_mode(0o000)).unwrap();
    let tracefs = root.path().join("sys/kernel/tracing");
    fs::create_dir_all(&tracefs).unwrap();
    fs::set_permissions(&tracefs, fs::Permissions::from_mode(0o000)).unwrap();
    let observed = inspect_linux_observability(root.path());
    assert_eq!(observed.nr_kdamonds, Observation::PrivilegeHidden);
    assert_eq!(observed.tracefs, Observation::Observed(true));
    fs::set_permissions(&nr, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&tracefs, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn capability_detects_operations_tracepoint_external_and_module_conflict() {
    let root = TempDir::new().unwrap();
    let kd = root.path().join("sys/kernel/mm/damon/admin/kdamonds/0");
    fs::create_dir_all(kd.join("contexts/0/monitoring_attrs/intervals_goal")).unwrap();
    fs::write(kd.parent().unwrap().join("nr_kdamonds"), "1\n").unwrap();
    fs::write(kd.join("state"), "on\n").unwrap();
    fs::write(kd.join("pid"), "44\n").unwrap();
    fs::write(
        kd.join("contexts/0/avail_operations"),
        "vaddr fvaddr paddr\n",
    )
    .unwrap();
    fs::write(kd.join("refresh_ms"), "0\n").unwrap();
    fs::create_dir_all(
        root.path()
            .join("sys/kernel/tracing/events/damon/damon_aggregated"),
    )
    .unwrap();
    fs::create_dir_all(root.path().join("sys/module/damon_reclaim/parameters")).unwrap();
    fs::write(
        root.path()
            .join("sys/module/damon_reclaim/parameters/enabled"),
        "Y\n",
    )
    .unwrap();
    let found = inspect_linux(root.path(), None);
    assert!(found.vaddr_supported && found.fvaddr_supported && found.paddr_supported);
    assert!(found.aggregated_tracepoint_available);
    assert!(found.active_external_session);
    assert!(found.special_module_conflict);
    assert_eq!(found.existing_kdamond_pids, vec![44]);
    assert!(found.optional_features["refresh_ms"]);
    assert!(found.optional_features["intervals_goal"]);
}

#[test]
fn attrs_validate_bounds_and_expected_samples() {
    assert!(attrs().validate().is_ok());
    assert_eq!(attrs().expected_samples(), 20);
    let mut invalid = attrs();
    invalid.aggr_us = 1;
    assert!(invalid.validate().is_err());
    invalid = attrs();
    invalid.min_regions = invalid.max_regions + 1;
    assert!(invalid.validate().is_err());
}

#[test]
fn trace_parser_handles_hex_extra_whitespace_and_rejects_bad_input() {
    let parsed = parse_aggregated(
        "cpu x damon:damon_aggregated: target_id=2 nr_regions=3 start=0x1000 end=0x2000 nr_accesses=8 age=4 extra=yes",
    )
    .unwrap();
    assert_eq!(parsed.start, 4096);
    assert_eq!(parsed.nr_accesses, 8);
    assert!(parse_aggregated("target_id=1 start=2").is_err());
    assert!(parse_aggregated(
        "target_id=1 nr_regions=99999999999 start=1 end=2 nr_accesses=1 age=1"
    )
    .is_err());
    let real = parse_aggregated(
        "kdamond.0 [027] 79357.842179: damon:damon_aggregated: target_id=0 nr_regions=11 122509119488-135708762112: 7 864",
    )
    .unwrap();
    assert_eq!(real.target_id, 0);
    assert_eq!(real.start, 122_509_119_488);
    assert_eq!(real.nr_accesses, 7);
    assert_eq!(real.age, 864);
}

#[test]
fn normalization_is_clamped_versioned_and_needs_history_for_cold() {
    let cold = TraceRegion {
        target_id: 1,
        nr_regions: 1,
        start: 1,
        end: 4097,
        nr_accesses: 0,
        age: 10,
    };
    assert_eq!(
        normalize(&cold, &attrs(), 1).observational_label,
        ObservationalLabel::InsufficientHistory
    );
    assert_eq!(
        normalize(&cold, &attrs(), 3).observational_label,
        ObservationalLabel::Cold
    );
    let mut hot = cold;
    hot.nr_accesses = 999;
    assert_eq!(normalize(&hot, &attrs(), 3).normalized_access_ratio, 1.0);
    assert_eq!(
        normalize(
            &TraceRegion {
                nr_accesses: 8,
                ..hot
            },
            &attrs(),
            3
        )
        .observational_label,
        ObservationalLabel::Warm
    );
}

#[test]
fn export_is_bounded_no_overwrite_and_contains_no_memory_content_field() {
    let root = TempDir::new().unwrap();
    let path = root.path().join("dataset.jsonl");
    let record = normalize(
        &TraceRegion {
            target_id: 1,
            nr_regions: 1,
            start: 1,
            end: 2,
            nr_accesses: 1,
            age: 1,
        },
        &attrs(),
        3,
    );
    export_dataset(&path, ExportFormat::Jsonl, &[record], 1_000_000).unwrap();
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains(DATASET_SCHEMA_VERSION));
    assert!(!text.contains("memory_content"));
    assert!(export_dataset(&path, ExportFormat::Jsonl, &[], 1).is_err());
    let csv = root.path().join("dataset.csv");
    export_dataset(
        &csv,
        ExportFormat::Csv,
        &[normalize(
            &TraceRegion {
                target_id: 1,
                nr_regions: 1,
                start: 1,
                end: 2,
                nr_accesses: 1,
                age: 1,
            },
            &attrs(),
            3,
        )],
        1_000_000,
    )
    .unwrap();
    assert!(fs::read_to_string(csv)
        .unwrap()
        .starts_with("schema_version,session_id"));
}

#[test]
fn overhead_budget_respects_damon_and_global_ceilings() {
    let config = DamonConfig {
        enabled: false,
        mode: "monitor_only".to_owned(),
        allow_monitor_session: false,
        preferred_operation: "vaddr".to_owned(),
        sample_us: 5_000,
        aggr_us: 100_000,
        update_us: 1_000_000,
        min_regions: 10,
        max_regions: 1_000,
        max_cpu_overhead_percent: 1.0,
        max_session_seconds: 120,
        max_samples_per_session: 100_000,
        retention_days: 7,
        export_max_bytes: 67_108_864,
        max_action_time_ms: 5,
        max_action_bytes: 268_435_456,
    };
    let mut sample = OverheadSample {
        kdamond_cpu_percent: 0.4,
        capture_cpu_percent: 0.5,
        target_slowdown_percent: 0.2,
        events_per_second: 10.0,
        regions_per_second: 100.0,
        dropped_samples: 0,
    };
    assert!(overhead_allowed(&sample, &config, 5.0));
    sample.capture_cpu_percent = 0.6;
    assert!(overhead_allowed(&sample, &config, 5.0));
    sample.capture_cpu_percent = 0.7;
    assert!(!overhead_allowed(&sample, &config, 5.0));
    sample.capture_cpu_percent = 0.5;
    sample.dropped_samples = 1;
    assert!(!overhead_allowed(&sample, &config, 5.0));
    assert!(!overhead_allowed(&sample, &config, 0.5));
}

#[test]
fn observe_report_has_zero_regions_and_zero_damos() {
    let root = TempDir::new().unwrap();
    let capability = inspect_linux(root.path(), None);
    assert!(!capability.supported);
    let config = DamonConfig {
        enabled: false,
        mode: "monitor_only".to_owned(),
        allow_monitor_session: false,
        preferred_operation: "vaddr".to_owned(),
        sample_us: 5_000,
        aggr_us: 100_000,
        update_us: 1_000_000,
        min_regions: 10,
        max_regions: 1_000,
        max_cpu_overhead_percent: 1.0,
        max_session_seconds: 120,
        max_samples_per_session: 100_000,
        retention_days: 7,
        export_max_bytes: 67_108_864,
        max_action_time_ms: 5,
        max_action_bytes: 268_435_456,
    };
    let report = observe_report(&config, None);
    assert!(report.zero_damos);
    assert_eq!(report.regions, 0);
    assert!(report.dry_run);
}

#[test]
fn linux_capability_inspection_is_read_only_and_never_panics() {
    let before = fs::read_to_string("/sys/kernel/mm/damon/admin/kdamonds/nr_kdamonds").ok();
    let capability = inspect_linux(Path::new("/"), None);
    let after = fs::read_to_string("/sys/kernel/mm/damon/admin/kdamonds/nr_kdamonds").ok();
    assert_eq!(before, after);
    assert!(capability.dry_run);
}

fn zone_attrs() -> MonitoringAttrs {
    MonitoringAttrs {
        aggr_us: 500_000,
        ..attrs()
    }
}

fn region(start: u64, end: u64, accesses: u64) -> TraceRegion {
    TraceRegion {
        target_id: 1,
        nr_regions: 3,
        start,
        end,
        nr_accesses: accesses,
        age: 4,
    }
}

fn zone_windows(hot: u64, warm: u64, cold: u64) -> Vec<Vec<TraceRegion>> {
    (0..5)
        .map(|_| {
            vec![
                region(0, 100, hot),
                region(100, 200, warm),
                region(200, 300, cold),
            ]
        })
        .collect()
}

#[test]
fn zone_gate_rejects_false_positive_equivalence_and_missing_overlap() {
    let ranges = [
        AddressRange { start: 0, end: 100 },
        AddressRange {
            start: 100,
            end: 200,
        },
        AddressRange {
            start: 200,
            end: 300,
        },
    ];
    let zero_hot = analyze_zones(
        &zone_windows(0, 5, 10),
        &zone_attrs(),
        ranges[0],
        ranges[1],
        ranges[2],
    );
    assert!(!zero_hot.accepted);
    assert!(!zero_hot.hot_cold_distinguished);
    let equal = analyze_zones(
        &zone_windows(10, 10, 10),
        &zone_attrs(),
        ranges[0],
        ranges[1],
        ranges[2],
    );
    assert!(!equal.accepted);
    let other = vec![vec![region(1_000, 2_000, 90)]; 5];
    let no_overlap = analyze_zones(&other, &zone_attrs(), ranges[0], ranges[1], ranges[2]);
    assert!(!no_overlap.accepted);
    assert_eq!(no_overlap.other_region_samples, 5);
}

#[test]
fn zone_stats_do_not_present_repeated_window_bytes_as_footprint() {
    let windows = zone_windows(90, 30, 0);
    let evidence = analyze_zones(
        &windows,
        &zone_attrs(),
        AddressRange { start: 0, end: 100 },
        AddressRange {
            start: 100,
            end: 200,
        },
        AddressRange {
            start: 200,
            end: 300,
        },
    );
    assert!(evidence.accepted);
    assert_eq!(evidence.region_sample_bytes, 1_500);
    assert_eq!(evidence.snapshot_observed_bytes_median, 300);
    assert_eq!(evidence.hot.overlap_sample_bytes, 500);
    assert_eq!(evidence.hot.snapshot_overlap_bytes_median, 100);
}

#[test]
fn split_merge_and_mixed_overlap_are_size_weighted() {
    let windows = vec![
        vec![region(0, 150, 90), region(150, 300, 0)],
        vec![region(0, 50, 90), region(50, 200, 30), region(200, 300, 0)],
        vec![
            region(0, 100, 90),
            region(100, 200, 30),
            region(200, 300, 0),
        ],
    ];
    let evidence = analyze_zones(
        &windows,
        &zone_attrs(),
        AddressRange { start: 0, end: 100 },
        AddressRange {
            start: 100,
            end: 200,
        },
        AddressRange {
            start: 200,
            end: 300,
        },
    );
    assert_eq!(evidence.hot.snapshot_overlap_bytes_median, 100);
    assert_eq!(evidence.warm.snapshot_overlap_bytes_median, 100);
    assert!(evidence.hot.normalized_ratio_mean > evidence.cold.normalized_ratio_mean);
}

#[test]
fn missing_complete_windows_are_dropped_and_cannot_create_confidence() {
    let grouped = group_aggregation_windows(vec![region(0, 100, 1), region(100, 200, 1)]);
    assert!(grouped.is_empty());
}

#[test]
fn initial_region_plan_requires_exact_sorted_nonoverlapping_mapped_ranges() {
    let mappings = [AddressRange {
        start: 1_000,
        end: 5_000,
    }];
    let plan = InitialRegionPlan::new(
        vec![
            AddressRange {
                start: 3_000,
                end: 4_000,
            },
            AddressRange {
                start: 1_000,
                end: 2_000,
            },
            AddressRange {
                start: 2_000,
                end: 3_000,
            },
        ],
        &mappings,
    )
    .unwrap();
    assert_eq!(plan.ranges[0].start, 1_000);
    assert_eq!(plan.requested_bytes(), 3_000);
    assert!(plan.matches_readback(&plan.ranges));
    assert!(!plan.matches_readback(&plan.ranges[..2]));
    assert!(InitialRegionPlan::new(plan.ranges[..2].to_vec(), &mappings).is_err());
    assert!(InitialRegionPlan::new(
        vec![
            AddressRange {
                start: 1_000,
                end: 2_100,
            },
            AddressRange {
                start: 2_000,
                end: 3_000,
            },
            AddressRange {
                start: 3_000,
                end: 4_000,
            },
        ],
        &mappings,
    )
    .is_err());
    assert!(InitialRegionPlan::new(
        vec![
            AddressRange {
                start: 1_000,
                end: 2_000,
            },
            AddressRange {
                start: 2_000,
                end: 3_000,
            },
            AddressRange {
                start: 5_000,
                end: 6_000,
            },
        ],
        &mappings,
    )
    .is_err());
}

#[test]
fn outside_requested_accounting_is_per_snapshot_not_cumulative() {
    let windows = vec![
        vec![
            region(0, 100, 20),
            region(100, 200, 5),
            region(200, 300, 0),
            region(300, 700, 0),
        ];
        5
    ];
    let evidence = analyze_zones(
        &windows,
        &zone_attrs(),
        AddressRange { start: 0, end: 100 },
        AddressRange {
            start: 100,
            end: 200,
        },
        AddressRange {
            start: 200,
            end: 300,
        },
    );
    assert_eq!(evidence.requested_target_bytes, 300);
    assert_eq!(evidence.observed_target_bytes_per_snapshot, 300);
    assert_eq!(evidence.outside_requested_bytes, 400);
    assert!((evidence.outside_requested_ratio - 4.0 / 7.0).abs() < 0.000_001);
    assert_eq!(evidence.window_diagnostics.len(), 5);
}

#[test]
fn huge_region_with_tiny_overlap_is_quality_downweighted() {
    let windows = (0..5)
        .map(|_| {
            vec![
                region(0, 10_000, 20),
                region(100, 200, 5),
                region(200, 300, 0),
            ]
        })
        .collect::<Vec<_>>();
    let evidence = analyze_zones(
        &windows,
        &zone_attrs(),
        AddressRange {
            start: 9_990,
            end: 10_090,
        },
        AddressRange {
            start: 100,
            end: 200,
        },
        AddressRange {
            start: 200,
            end: 300,
        },
    );
    assert!(evidence.outside_requested_ratio > 0.9);
    assert!(!evidence.target_isolated);
    assert!(!evidence.accepted);
    assert_eq!(evidence.hot.region_samples, 5);
    assert_eq!(evidence.hot.snapshot_overlap_bytes_median, 10);
}

#[test]
fn retry_profile_uses_reference_sampling_ratio_and_defers_dynamic_update() {
    let retry = MonitoringAttrs {
        operation: "vaddr".to_owned(),
        sample_us: 25_000,
        aggr_us: 500_000,
        update_us: 10_000_000,
        min_regions: 10,
        max_regions: 1_000,
        addr_unit: None,
    };
    assert!(retry.validate().is_ok());
    assert_eq!(retry.expected_samples(), 20);
    assert!(retry.update_us > 5_000_000);
}

#[test]
fn zone_score_is_invariant_for_equal_ratio_region_splits() {
    let ranges = [
        AddressRange { start: 0, end: 100 },
        AddressRange {
            start: 100,
            end: 200,
        },
        AddressRange {
            start: 200,
            end: 300,
        },
    ];
    let whole = vec![vec![region(0, 100, 10), region(100, 200, 5), region(200, 300, 0),]; 5];
    let split = vec![
        vec![
            region(0, 50, 10),
            region(50, 100, 10),
            region(100, 150, 5),
            region(150, 200, 5),
            region(200, 250, 0),
            region(250, 300, 0),
        ];
        5
    ];
    let whole = analyze_zones(&whole, &zone_attrs(), ranges[0], ranges[1], ranges[2]);
    let split = analyze_zones(&split, &zone_attrs(), ranges[0], ranges[1], ranges[2]);
    assert!(
        (whole.hot.normalized_ratio_mean - split.hot.normalized_ratio_mean).abs() < f64::EPSILON
    );
    assert!(
        (whole.warm.normalized_ratio_mean - split.warm.normalized_ratio_mean).abs() < f64::EPSILON
    );
    assert_eq!(split.window_diagnostics[0].hot_raw_accesses, 20);
    assert_eq!(
        split.window_diagnostics[0].expected_samples_per_region,
        zone_attrs().expected_samples()
    );
    assert_eq!(split.window_diagnostics[0].hot_overlapping_regions, 2);
}

#[test]
fn raw_accesses_remain_visible_when_normalized_ratio_is_small() {
    let windows = vec![vec![region(0, 100, 1), region(100, 200, 0), region(200, 300, 0),]; 5];
    let evidence = analyze_zones(
        &windows,
        &zone_attrs(),
        AddressRange { start: 0, end: 100 },
        AddressRange {
            start: 100,
            end: 200,
        },
        AddressRange {
            start: 200,
            end: 300,
        },
    );
    assert_eq!(evidence.window_diagnostics[0].hot_raw_accesses, 1);
    assert_eq!(
        evidence.window_diagnostics[0].hot_normalized_ratio,
        1.0 / zone_attrs().expected_samples() as f64
    );
}

#[test]
fn diagnostic_size_ladder_is_deterministic_bounded_and_selects_first_stable() {
    assert_eq!(
        bounded_size_ladder(8 * 1024 * 1024 * 1024, 1024 * 1024 * 1024),
        DIAGNOSTIC_ZONE_SIZES
    );
    assert!(DIAGNOSTIC_ZONE_SIZES
        .iter()
        .all(|size| *size <= MAX_DIAGNOSTIC_ZONE_BYTES));
    let reduced = bounded_size_ladder(1200 * 1024 * 1024, 1024 * 1024 * 1024);
    assert_eq!(reduced, vec![8 * 1024 * 1024, 32 * 1024 * 1024]);
    let attempts = vec![
        ProbeEvidence {
            session_id: "probe-8".to_owned(),
            source: "retry6_final_reference".to_owned(),
            zone_size_bytes: 8,
            windows: 3,
            hot_nonzero_windows: 2,
            hot_zero_windows: 1,
            warm_nonzero_windows: 3,
            cold_nonzero_windows: 0,
            hot_ratio_mean: 0.01,
            hot_ratio_p50: 0.01,
            cold_ratio_mean: 0.0,
            cold_ratio_p50: 0.0,
            outside_requested_ratio: 0.0,
            kdamond_cpu_percent: 0.1,
            capture_cpu_percent: 0.1,
            backing_page_size_kib: Some(4),
            anon_huge_pages_kib: 0,
            thp_eligible: Some(false),
            target_isolated: true,
            workload_active: true,
            capture_integrity: true,
            overhead_within_budget: true,
            ..ProbeEvidence::default()
        },
        ProbeEvidence {
            session_id: "probe-32".to_owned(),
            source: "current_probe".to_owned(),
            zone_size_bytes: 32,
            windows: 8,
            hot_nonzero_windows: 8,
            hot_zero_windows: 0,
            warm_nonzero_windows: 6,
            cold_nonzero_windows: 0,
            hot_ratio_mean: 0.4,
            hot_ratio_p50: 0.4,
            cold_ratio_mean: 0.0,
            cold_ratio_p50: 0.0,
            outside_requested_ratio: 0.0,
            kdamond_cpu_percent: 0.1,
            capture_cpu_percent: 0.1,
            backing_page_size_kib: Some(4),
            anon_huge_pages_kib: 0,
            thp_eligible: Some(false),
            target_isolated: true,
            workload_active: true,
            capture_integrity: true,
            overhead_within_budget: true,
            ..ProbeEvidence::default()
        },
    ];
    assert_eq!(select_probe_size(&attempts).unwrap().0, 32);
    assert!(select_probe_size(&attempts[..1]).is_none());
}

#[test]
fn ladder_requires_eight_of_eight_and_historical_measurements_are_not_selectable() {
    let historical = ProbeEvidence {
        source: "retry6_final_reference".to_owned(),
        zone_size_bytes: 8,
        windows: 9,
        hot_nonzero_windows: 6,
        hot_zero_windows: 3,
        hot_ratio_mean: 0.2,
        hot_ratio_p50: 0.2,
        target_isolated: true,
        workload_active: true,
        capture_integrity: true,
        overhead_within_budget: true,
        ..ProbeEvidence::default()
    };
    let unstable_32 = ProbeEvidence {
        source: "current_probe".to_owned(),
        zone_size_bytes: 32,
        windows: 8,
        hot_nonzero_windows: 7,
        hot_zero_windows: 1,
        hot_ratio_mean: 0.1,
        hot_ratio_p50: 0.1,
        target_isolated: true,
        workload_active: true,
        capture_integrity: true,
        overhead_within_budget: true,
        ..ProbeEvidence::default()
    };
    let stable_64 = ProbeEvidence {
        source: "current_probe".to_owned(),
        zone_size_bytes: 64,
        windows: 8,
        hot_nonzero_windows: 8,
        hot_zero_windows: 0,
        hot_ratio_mean: 0.3,
        hot_ratio_p50: 0.3,
        target_isolated: true,
        workload_active: true,
        capture_integrity: true,
        overhead_within_budget: true,
        ..ProbeEvidence::default()
    };
    assert!(!historical.stable_enough());
    assert!(!unstable_32.stable_enough());
    assert!(stable_64.stable_enough());
    let attempts = vec![historical, unstable_32, stable_64];
    assert_eq!(select_probe_size(&attempts).unwrap().0, 64);
    assert!(size_scaling_supports_tlb_hypothesis(&attempts));
    assert!(size_scaling_supports_tlb_hypothesis(&attempts[..2]));
    assert!(!size_scaling_supports_tlb_hypothesis(&attempts[..1]));
}

#[test]
fn hypothesis_state_is_single_and_base_page_comparison_is_consistent() {
    let thp = ProbeEvidence {
        source: "current_probe".to_owned(),
        backing_profile: PageBackingProfile::ThpReference,
        zone_size_bytes: 8,
        windows: 9,
        hot_nonzero_windows: 6,
        hot_zero_windows: 3,
        ..ProbeEvidence::default()
    };
    let base = ProbeEvidence {
        source: "current_probe".to_owned(),
        backing_profile: PageBackingProfile::BasePageNoHuge,
        zone_size_bytes: 8,
        windows: 9,
        hot_nonzero_windows: 9,
        hot_zero_windows: 0,
        hot_ratio_mean: 0.2,
        hot_ratio_p50: 0.2,
        cold_nonzero_windows: 0,
        target_isolated: true,
        workload_active: true,
        capture_integrity: true,
        overhead_within_budget: true,
        base_page_backing_verified: true,
        ..ProbeEvidence::default()
    };
    assert_eq!(
        compare_page_backing(&thp, &base),
        HypothesisStatus::SupportedByBasePageComparison
    );
    let json = serde_json::to_string(&HypothesisStatus::InconclusiveDueToThpBacking).unwrap();
    assert_eq!(json, "\"inconclusive_due_to_thp_backing\"");
    assert!(!json.contains("supported\":"));
}

#[test]
fn base_page_verification_requires_no_thp_for_three_mappings() {
    let valid = |start| ZoneBacking {
        start,
        end: start + 8192,
        kernel_page_size_kib: Some(4),
        mmu_page_size_kib: Some(4),
        anon_huge_pages_kib: 0,
        thp_eligible: Some(false),
        vm_flags: vec!["nh".to_owned()],
        containing_vma_start: Some(start),
        containing_vma_end: Some(start + 8192),
        explicit_nohugepage_requested: true,
        explicit_nohugepage_verified: true,
        ..ZoneBacking::default()
    };
    let mut zones = BTreeMap::from([
        ("hot".to_owned(), valid(0x1000)),
        ("warm".to_owned(), valid(0x4000)),
        ("cold".to_owned(), valid(0x7000)),
    ]);
    assert!(verify_base_page_backing(&zones));
    assert_eq!(
        zones
            .values()
            .filter_map(|zone| zone.containing_vma_start)
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
    zones.get_mut("warm").unwrap().anon_huge_pages_kib = 2048;
    assert!(!verify_base_page_backing(&zones));
}

#[test]
fn base_page_ladder_selects_8_then_32_only_when_needed() {
    let probe = |size, hot, zero| ProbeEvidence {
        source: "current_probe".to_owned(),
        backing_profile: PageBackingProfile::BasePageNoHuge,
        zone_size_bytes: size,
        windows: 8,
        hot_nonzero_windows: hot,
        hot_zero_windows: zero,
        hot_ratio_mean: 0.2,
        hot_ratio_p50: 0.2,
        cold_nonzero_windows: 0,
        target_isolated: true,
        workload_active: true,
        capture_integrity: true,
        overhead_within_budget: true,
        base_page_backing_verified: true,
        ..ProbeEvidence::default()
    };
    assert_eq!(select_base_page_probe(&[probe(8, 8, 0)]).unwrap().0, 8);
    assert_eq!(
        select_base_page_probe(&[probe(8, 7, 1), probe(32, 8, 0)])
            .unwrap()
            .0,
        32
    );
    assert!(select_base_page_probe(&[probe(8, 7, 1), probe(32, 7, 1)]).is_none());
}

#[test]
fn smaps_parser_distinguishes_4k_thp_and_missing_fields() {
    let four_k = "1000-3000 rw-p 00000000 00:00 0\nSize: 8 kB\nRss: 8 kB\nPss: 8 kB\nKernelPageSize: 4 kB\nMMUPageSize: 4 kB\nAnonHugePages: 0 kB\nTHPeligible: 0\nVmFlags: rd wr mr mw me ac sd\n";
    let parsed = parse_smaps_zone(
        four_k,
        AddressRange {
            start: 0x1000,
            end: 0x3000,
        },
    )
    .unwrap();
    assert_eq!(parsed.backing, "4k");
    assert_eq!(parsed.rss_kib, 8);
    assert_eq!(parsed.thp_eligible, Some(false));
    assert_eq!(parsed.containing_vma_start, Some(0x1000));
    assert_eq!(parsed.containing_vma_end, Some(0x3000));
    let thp = "4000-204000 rw-p 00000000 00:00 0\nSize: 2048 kB\nRss: 2048 kB\nPss: 2048 kB\nKernelPageSize: 4 kB\nMMUPageSize: 4 kB\nAnonHugePages: 2048 kB\nTHPeligible: 1\nVmFlags: rd wr hg\n";
    let parsed = parse_smaps_zone(
        thp,
        AddressRange {
            start: 0x4000,
            end: 0x204000,
        },
    )
    .unwrap();
    assert_eq!(parsed.backing, "mixed_or_thp");
    assert_eq!(parsed.anon_huge_pages_kib, 2048);
    assert_eq!(parsed.thp_eligible, Some(true));
    let missing = parse_smaps_zone(
        "8000-9000 rw-p 00000000 00:00 0\nRss: 4 kB\n",
        AddressRange {
            start: 0x8000,
            end: 0x9000,
        },
    )
    .unwrap();
    assert_eq!(missing.kernel_page_size_kib, None);
    assert_eq!(missing.backing, "unknown");
}
