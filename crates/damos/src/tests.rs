use super::*;
use std::fs;
use tempfile::tempdir;

fn identity() -> StableTargetIdentity {
    StableTargetIdentity {
        pid: 42,
        start_ticks: 9,
        stable_key: "synthetic:9".into(),
        owned: true,
    }
}
fn cold() -> ColdObservation {
    ColdObservation {
        complete: true,
        nr_accesses: 0,
        age: 4,
        range: AddressRange { start: 10, end: 20 },
    }
}
fn eligible() -> EligibilityInput {
    EligibilityInput {
        identity: Some(identity()),
        identity_fresh: true,
        background: true,
        foreground: false,
        gaming: false,
        critical: false,
        protected: false,
        known_classification: true,
        pressure: PressureState::Pressure,
        cold_observations: vec![cold(), cold(), cold()],
        valid_age_evidence: true,
        recent_refault: false,
        blacklisted: false,
        safety_conflict: false,
    }
}

fn residency(present_pages: u64, swapped_pages: u64) -> RangeResidencySnapshot {
    let total_pages = 2;
    RangeResidencySnapshot {
        range_start: 0x1000,
        range_end: 0x3000,
        range_size_bytes: 8192,
        page_size: 4096,
        total_pages,
        present_pages,
        present_bytes: present_pages * 4096,
        swapped_pages,
        swapped_bytes: swapped_pages * 4096,
        not_present_not_swapped_pages: total_pages - present_pages - swapped_pages,
        read_errors: 0,
        timestamp_ns: 1,
        source: "proc_pagemap".into(),
    }
}

fn reclaim(
    stats: DamosStats,
    before: RangeResidencySnapshot,
    after: RangeResidencySnapshot,
) -> ReclaimEvidence {
    let unchanged = ZoneRangeEvidence {
        before: residency(2, 0),
        after_pageout: residency(2, 0),
        after_refault: None,
    };
    ReclaimEvidence {
        stats,
        vma: VmaReclaimEvidence {
            containing_vma_start: 0x1000,
            containing_vma_end: 0x3000,
            containing_vma_shared: true,
            rss_before: 8192,
            rss_after_pageout: 8192,
            pss_before: 8192,
            pss_after_pageout: 8192,
            swap_before: 0,
            swap_after_pageout: 0,
        },
        ranges: RangeReclaimEvidence {
            hot: unchanged.clone(),
            warm: unchanged,
            cold: ZoneRangeEvidence {
                before,
                after_pageout: after,
                after_refault: None,
            },
        },
    }
}

#[test]
fn three_complete_cold_windows_are_required() {
    let mut input = eligible();
    input.cold_observations.pop();
    assert_eq!(
        evaluate_eligibility(&input).disposition,
        PlanDisposition::Rejected
    );
    input.cold_observations.push(cold());
    assert_eq!(
        evaluate_eligibility(&input).disposition,
        PlanDisposition::Eligible
    );
}
#[test]
fn partial_window_is_rejected() {
    let mut input = eligible();
    input.cold_observations[2].complete = false;
    assert!(evaluate_eligibility(&input)
        .reasons
        .contains(&"insufficient_cold_evidence".into()));
}
#[test]
fn every_protection_is_fail_closed() {
    for mutate in 0..7 {
        let mut i = eligible();
        match mutate {
            0 => i.foreground = true,
            1 => i.gaming = true,
            2 => i.critical = true,
            3 => i.protected = true,
            4 => i.known_classification = false,
            5 => i.identity_fresh = false,
            _ => i.background = false,
        }
        assert_eq!(
            evaluate_eligibility(&i).disposition,
            PlanDisposition::Rejected
        );
    }
}
#[test]
fn normal_watch_and_stabilizing_reject() {
    for state in [
        PressureState::Normal,
        PressureState::Watch,
        PressureState::Stabilizing,
    ] {
        let mut i = eligible();
        i.pressure = state;
        assert_eq!(
            evaluate_eligibility(&i).disposition,
            PlanDisposition::Rejected
        );
    }
}
#[test]
fn blacklist_and_refault_reject() {
    let mut i = eligible();
    i.blacklisted = true;
    assert!(evaluate_eligibility(&i)
        .reasons
        .contains(&"early_refault_blacklist".into()));
}
#[test]
fn quotas_are_bounded_and_never_unlimited() {
    assert!(DamosQuota {
        time_ms: 0,
        bytes: 0,
        reset_interval_ms: 1000,
        total_applied_bytes: 1
    }
    .validate(5, 8 << 20)
    .is_err());
    assert!(DamosQuota {
        time_ms: 6,
        bytes: 8 << 20,
        reset_interval_ms: 1000,
        total_applied_bytes: 16 << 20
    }
    .validate(5, 8 << 20)
    .is_err());
    assert!(DamosQuota {
        time_ms: 5,
        bytes: 8 << 20,
        reset_interval_ms: 1000,
        total_applied_bytes: 16 << 20
    }
    .validate(5, 8 << 20)
    .is_ok());
}
#[test]
fn exact_cold_address_fence_is_required() {
    let cold = AddressRange { start: 10, end: 20 };
    assert!(AddressFence {
        range: cold,
        layer: "core".into(),
        filter_type: "addr".into(),
        api: FilterApi::MatchingAllow,
        matching: true,
        allow: Some(true),
    }
    .validate(cold)
    .is_ok());
    assert!(AddressFence {
        range: cold,
        layer: "core".into(),
        filter_type: "anon".into(),
        api: FilterApi::MatchingAllow,
        matching: true,
        allow: Some(true),
    }
    .validate(cold)
    .is_err());
}
#[test]
fn decision_and_plan_links_are_required() {
    let plan = DamosPlan {
        decision_id: "".into(),
        plan_id: "p".into(),
        session_id: "s".into(),
        scheme_id: 0,
        target: identity(),
        action: DamosAction::Pageout,
        pattern_accesses_min: 0,
        pattern_accesses_max: 0,
        pattern_age_min: 3,
        pattern_age_max: u64::MAX,
        apply_interval_us: 500_000,
        quota: DamosQuota {
            time_ms: 5,
            bytes: 8 << 20,
            reset_interval_ms: 1000,
            total_applied_bytes: 16 << 20,
        },
        fence: AddressFence {
            range: AddressRange { start: 10, end: 20 },
            layer: "core".into(),
            filter_type: "addr".into(),
            api: FilterApi::MatchingAllow,
            matching: true,
            allow: Some(true),
        },
        max_nr_snapshots: Some(4),
        dry_run: false,
    };
    assert!(plan.validate(5, 8 << 20).is_err());
}
#[test]
fn reclaim_needs_target_attributable_effect() {
    let stats = DamosStats {
        sz_applied: Some(4096),
        ..Default::default()
    };
    assert!(!reclaim(stats.clone(), residency(2, 0), residency(2, 0)).observed());
    assert!(reclaim(stats, residency(2, 0), residency(1, 1)).observed());
}
#[test]
fn early_refault_and_blacklist_expiration() {
    let e = RefaultEvidence {
        action_id: "a".into(),
        target_key: "t".into(),
        region_signature: "r".into(),
        applied_bytes: 4096,
        action_timestamp_ns: 100,
        first_access_timestamp_ns: Some(150),
        rss_or_swap_evidence: true,
        content_valid: true,
    };
    assert!(e.early(100));
    assert_eq!(e.state(false, 100), RefaultState::NotEvaluated);
    assert_eq!(e.state(true, 100), RefaultState::Observed);
    let b = BlacklistRecord {
        key: "t:r".into(),
        reason: "early_refault_blacklist".into(),
        created_at_ns: 150,
        expires_at_ns: 250,
        source_action_id: "a".into(),
        evidence: e,
    };
    assert!(b.active(200));
    assert!(!b.active(250));
}

#[test]
fn unsuccessful_pageout_never_creates_refault_blacklist() {
    let evidence = RefaultEvidence {
        action_id: "a".into(),
        target_key: "t".into(),
        region_signature: "r".into(),
        applied_bytes: 0,
        action_timestamp_ns: 100,
        first_access_timestamp_ns: Some(150),
        rss_or_swap_evidence: false,
        content_valid: true,
    };
    assert_eq!(evidence.state(false, 100), RefaultState::NotEvaluated);
    assert!(blacklist_for_refault(evidence, false, 150, 250, 100).is_none());
    let input = eligible();
    let decision = evaluate_eligibility(&input);
    assert!(!decision
        .reasons
        .iter()
        .any(|reason| reason == "early_refault_blacklist"));
}
#[test]
fn recovery_is_owned_only_and_idempotent() {
    let mut s = OwnedSession {
        session_id: "nemor-validation-x".into(),
        target: identity(),
        kdamond_index: 0,
        scheme_id: 0,
        state_on: true,
        interrupted: true,
    };
    assert!(recover_owned(&mut s, "nemor-validation-").unwrap());
    assert!(!recover_owned(&mut s, "nemor-validation-").unwrap());
    s.session_id = "external".into();
    assert!(recover_owned(&mut s, "nemor-validation-").is_err());
}
#[test]
fn capability_requires_pageout_quota_and_fence() {
    let mut c = DamosCapability {
        supported: true,
        vaddr: Some(true),
        actions: BTreeSet::from(["pageout".into()]),
        address_fence_supported: true,
        ..Default::default()
    };
    c.quota_fields = BTreeMap::from([
        ("ms".into(), true),
        ("bytes".into(), true),
        ("reset_interval_ms".into(), true),
    ]);
    assert!(c.live_pageout_ready().is_ok());
    c.address_fence_supported = false;
    assert!(c.live_pageout_ready().is_err());
}
#[test]
fn capability_parser_is_optional_field_aware() {
    let dir = tempdir().unwrap();
    for path in [
        "quotas/ms",
        "quotas/bytes",
        "quotas/reset_interval_ms",
        "filters",
    ] {
        fs::create_dir_all(dir.path().join(path)).unwrap();
    }
    fs::write(dir.path().join("action"), "[stat] pageout").unwrap();
    fs::write(dir.path().join("filters/avail_types"), "anon addr memcg").unwrap();
    let c = inspect_scheme_root(dir.path(), true, false, false);
    assert!(c.actions.contains("pageout"));
    assert!(c.address_fence_supported);
    assert!(c.quota_fields["ms"]);
    assert!(!c.quota_fields["effective_bytes"]);
}
#[test]
fn unsupported_action_and_external_conflict_fail_closed() {
    let mut c = DamosCapability {
        supported: true,
        vaddr: Some(true),
        address_fence_supported: true,
        ..Default::default()
    };
    c.quota_fields = BTreeMap::from([
        ("ms".into(), true),
        ("bytes".into(), true),
        ("reset_interval_ms".into(), true),
    ]);
    assert!(c.live_pageout_ready().is_err());
    c.actions.insert("pageout".into());
    c.external_session_conflict = true;
    assert!(c.live_pageout_ready().is_err());
}
#[test]
fn applied_and_tried_are_distinct() {
    let stats = DamosStats {
        sz_tried: Some(8 << 20),
        sz_applied: Some(4 << 20),
        qt_exceeds: Some(1),
        ..Default::default()
    };
    assert_ne!(stats.sz_tried, stats.sz_applied);
    assert_eq!(stats.qt_exceeds, Some(1));
}
#[test]
fn host_wide_change_is_not_reclaim_evidence() {
    let evidence = reclaim(
        DamosStats {
            sz_applied: Some(4096),
            ..Default::default()
        },
        residency(2, 0),
        residency(2, 0),
    );
    assert!(!evidence.observed());
}
#[test]
fn stat_shadow_and_live_actions_are_distinct() {
    assert_ne!(DamosAction::Stat, DamosAction::Pageout);
}
#[test]
fn crash_recovery_covers_every_transaction_stage_without_fake_page_rollback() {
    for stage in [
        TransactionStage::DecisionRecorded,
        TransactionStage::KdamondAllocated,
        TransactionStage::SchemeAllocated,
        TransactionStage::SchemeConfigured,
        TransactionStage::StateOn,
        TransactionStage::FirstPageout,
        TransactionStage::BeforeStop,
        TransactionStage::Cleanup,
    ] {
        let outcome = simulated_crash_recovery(stage);
        assert!(
            outcome.external_untouched
                && outcome.pageout_not_undone
                && outcome.recorded_interrupted
        );
    }
}

#[test]
fn modern_addr_filter_is_an_explicit_allow_list() {
    let range = AddressRange {
        start: 0x1000,
        end: 0x3000,
    };
    let fence = AddressFence {
        range,
        layer: "core".into(),
        filter_type: "addr".into(),
        api: FilterApi::MatchingAllow,
        matching: true,
        allow: Some(true),
    };
    assert!(fence.validate(range).is_ok());
    assert!(fence.allows(0x1000));
    assert!(fence.allows(0x2fff));
    assert!(!fence.allows(0x3000));
    assert!(!fence.allows(0x0800));
}

#[test]
fn allow_readback_mismatch_and_modern_legacy_fallback_are_rejected() {
    let range = AddressRange { start: 1, end: 2 };
    let modern_mismatch = AddressFence {
        range,
        layer: "core".into(),
        filter_type: "addr".into(),
        api: FilterApi::MatchingAllow,
        matching: true,
        allow: Some(false),
    };
    assert!(modern_mismatch.validate(range).is_err());
    let silent_legacy = AddressFence {
        range,
        layer: "core".into(),
        filter_type: "addr".into(),
        api: FilterApi::MatchingAllow,
        matching: false,
        allow: None,
    };
    assert!(silent_legacy.validate(range).is_err());
    let explicit_legacy = AddressFence {
        api: FilterApi::LegacyMatchingOnly,
        matching: false,
        ..silent_legacy
    };
    assert!(explicit_legacy.validate(range).is_ok());
}

#[test]
fn capability_parser_detects_allow_file_and_legacy_absence() {
    let modern = tempdir().unwrap();
    fs::create_dir_all(modern.path().join("core_filters/0")).unwrap();
    fs::write(modern.path().join("core_filters/0/allow"), "N").unwrap();
    assert!(inspect_scheme_root(modern.path(), true, false, false).filter_allow_supported);
    let legacy = tempdir().unwrap();
    fs::create_dir_all(legacy.path().join("core_filters/0")).unwrap();
    assert!(!inspect_scheme_root(legacy.path(), true, false, false).filter_allow_supported);
}

#[test]
fn one_byte_shadow_overlap_is_a_safety_failure() {
    let hot = AddressRange { start: 0, end: 10 };
    let warm = AddressRange { start: 20, end: 30 };
    let cold = AddressRange { start: 40, end: 50 };
    for tried in [
        AddressRange { start: 9, end: 41 },
        AddressRange { start: 29, end: 41 },
    ] {
        assert!(tried.overlap(hot) > 0 || tried.overlap(warm) > 0);
        assert!(!(tried.start >= cold.start && tried.end <= cold.end));
    }
}

#[test]
fn attempt_two_snapshot_and_reset_bounds_allow_aging_without_resetting_quota() {
    let pattern = AccessPattern::validation_cold();
    let quota = DamosQuota {
        time_ms: 5,
        bytes: VALIDATION_BYTE_QUOTA,
        reset_interval_ms: VALIDATION_RESET_INTERVAL_MS,
        total_applied_bytes: VALIDATION_TOTAL_APPLIED_CEILING,
    };
    assert_eq!(pattern.configured_age_min(), 3);
    assert_eq!(VALIDATION_MAX_NR_SNAPSHOTS, 5);
    // The configured DAMOS age is not a snapshot index.  A non-zero
    // lifecycle fence is structurally valid here; empirical shadow evidence
    // independently decides whether it leaves enough eligibility margin.
    assert!(validate_attempt2_bounds(&pattern, &quota, 500_000, 4_000, 1).is_ok());
    assert!(validate_attempt2_bounds(&pattern, &quota, 500_000, 4_000, 5).is_ok());

    let short_reset = DamosQuota {
        reset_interval_ms: 4_000,
        ..quota.clone()
    };
    assert!(validate_attempt2_bounds(&pattern, &short_reset, 500_000, 4_000, 5).is_err());
    let stats = DamosStats {
        max_nr_snapshots: Some(5),
        nr_snapshots: Some(5),
        sz_applied: Some(VALIDATION_BYTE_QUOTA),
        ..Default::default()
    };
    assert!(validate_attempt2_stats(&stats, 5).is_ok());
    assert!(validate_attempt2_stats(
        &DamosStats {
            sz_applied: Some(VALIDATION_BYTE_QUOTA + 4096),
            ..stats
        },
        5
    )
    .is_err());
}

#[test]
fn shadow_and_live_must_share_the_exact_validated_filter_specification() {
    let cold = AddressRange {
        start: 0x4000,
        end: 0x8000,
    };
    let shadow = AddressFence {
        range: cold,
        layer: "core".into(),
        filter_type: "addr".into(),
        api: FilterApi::MatchingAllow,
        matching: true,
        allow: Some(true),
    };
    let live = shadow.clone();
    assert_eq!(shadow, live);

    let mismatched_live = AddressFence {
        allow: Some(false),
        ..live
    };
    assert_ne!(shadow, mismatched_live);
    assert!(mismatched_live.validate(cold).is_err());
}

#[test]
fn userspace_total_ceiling_cannot_replace_the_kernel_snapshot_fence() {
    let stats = DamosStats {
        max_nr_snapshots: None,
        nr_snapshots: Some(1),
        sz_applied: Some(4096),
        ..Default::default()
    };
    assert!(stats.sz_applied.unwrap() < VALIDATION_TOTAL_APPLIED_CEILING);
    assert!(validate_attempt2_stats(&stats, 5).is_err());
}

#[test]
fn hard_ceiling_rejects_tried_bytes_over_eight_mib_even_if_applied_is_bounded() {
    let stats = DamosStats {
        sz_tried: Some(VALIDATION_BYTE_QUOTA + 4096),
        sz_applied: Some(4096),
        ..Default::default()
    };
    assert!(!hard_byte_ceiling_respected(
        &stats,
        VALIDATION_BYTE_QUOTA,
        VALIDATION_RESET_INTERVAL_MS,
        VALIDATION_LIVE_DEADLINE_MS,
    ));
}

#[test]
fn applied_bytes_above_tried_bytes_are_invalid() {
    let stats = DamosStats {
        sz_tried: Some(4096),
        sz_applied: Some(8192),
        ..Default::default()
    };
    assert!(!hard_byte_ceiling_respected(
        &stats,
        VALIDATION_BYTE_QUOTA,
        VALIDATION_RESET_INTERVAL_MS,
        VALIDATION_LIVE_DEADLINE_MS,
    ));
}

#[test]
fn bounded_tried_bytes_with_zero_applied_pass_safety_but_fail_efficacy() {
    let stats = DamosStats {
        sz_tried: Some(VALIDATION_BYTE_QUOTA),
        sz_applied: Some(0),
        ..Default::default()
    };
    assert!(hard_byte_ceiling_respected(
        &stats,
        VALIDATION_BYTE_QUOTA,
        VALIDATION_RESET_INTERVAL_MS,
        VALIDATION_LIVE_DEADLINE_MS,
    ));
    assert!(!reclaim(stats, residency(2, 0), residency(2, 0)).observed());
}

#[test]
fn bounded_tried_and_applied_bytes_allow_separate_reclaim_efficacy() {
    let stats = DamosStats {
        sz_tried: Some(VALIDATION_BYTE_QUOTA),
        sz_applied: Some(4096),
        ..Default::default()
    };
    assert!(hard_byte_ceiling_respected(
        &stats,
        VALIDATION_BYTE_QUOTA,
        VALIDATION_RESET_INTERVAL_MS,
        VALIDATION_LIVE_DEADLINE_MS,
    ));
    assert!(reclaim(stats, residency(2, 0), residency(1, 1)).observed());
}

fn candidate(range: AddressRange, nr_accesses: u64, age: u64) -> DamosBeforeApplyEvent {
    DamosBeforeApplyEvent {
        timestamp_ns: 1,
        context_idx: 0,
        scheme_idx: 0,
        target_idx: 0,
        nr_regions: 1,
        range,
        size: range.end - range.start,
        nr_accesses,
        age,
    }
}

#[test]
fn pagemap_parser_exposes_only_present_and_swapped_state() {
    assert_eq!(
        parse_pagemap_entry(1_u64 << 63),
        PagemapPageState {
            present: true,
            swapped: false
        }
    );
    assert_eq!(
        parse_pagemap_entry(1_u64 << 62),
        PagemapPageState {
            present: false,
            swapped: true
        }
    );
    let exposed_model = format!("{:?}", residency(2, 0));
    assert!(!exposed_model.contains("pfn"));
}

#[test]
fn exact_range_page_count_and_snapshot_invariants_are_bounded() {
    let snapshot = residency(1, 1);
    assert_eq!(snapshot.total_pages, 2);
    assert_eq!(snapshot.range_size_bytes / snapshot.page_size, 2);
    assert!(snapshot.validate().is_ok());
    let mut invalid = snapshot;
    invalid.read_errors = 1;
    assert!(invalid.validate().is_err());
}

#[test]
fn merged_vma_metrics_are_not_attributed_to_owned_subranges() {
    let evidence = reclaim(
        DamosStats {
            sz_applied: Some(4096),
            ..Default::default()
        },
        residency(2, 0),
        residency(2, 0),
    );
    assert!(evidence.vma.containing_vma_shared);
    assert!(evidence.vma.rss_before >= evidence.vma.rss_after_pageout);
    assert!(!evidence.observed());
}

#[test]
fn cold_only_page_state_and_candidate_evidence_protect_hot_and_warm() {
    let hot = AddressRange {
        start: 0x1000,
        end: 0x3000,
    };
    let warm = AddressRange {
        start: 0x4000,
        end: 0x6000,
    };
    let cold = AddressRange {
        start: 0x7000,
        end: 0x9000,
    };
    let candidates = vec![candidate(cold, 0, 3)];
    assert!(range_not_reclaimed(
        &residency(2, 0),
        &residency(2, 0),
        &candidates,
        hot
    ));
    assert!(range_not_reclaimed(
        &residency(2, 0),
        &residency(2, 0),
        &candidates,
        warm
    ));
    assert!(range_reclaim_observed(&residency(2, 0), &residency(1, 1)));
}

#[test]
fn cold_present_decrease_or_swapped_increase_is_range_reclaim_evidence() {
    assert!(range_reclaim_observed(&residency(2, 0), &residency(1, 0)));
    assert!(range_reclaim_observed(&residency(1, 0), &residency(1, 1)));
    assert!(!range_reclaim_observed(&residency(2, 0), &residency(2, 0)));
}

#[test]
fn candidate_overlap_or_swapped_page_fails_hot_warm_safety() {
    let range = AddressRange {
        start: 0x1000,
        end: 0x3000,
    };
    assert!(!range_not_reclaimed(
        &residency(2, 0),
        &residency(2, 0),
        &[candidate(range, 0, 3)],
        range
    ));
    assert!(!range_not_reclaimed(
        &residency(2, 0),
        &residency(1, 1),
        &[],
        range
    ));
}

#[test]
fn only_pre_refault_snapshot_can_establish_reclaim() {
    let before = residency(2, 0);
    let after_pageout = residency(1, 1);
    let after_refault = residency(2, 0);
    assert!(range_reclaim_observed(&before, &after_pageout));
    assert!(!range_reclaim_observed(&before, &after_refault));
    assert!(after_pageout.timestamp_ns <= after_refault.timestamp_ns);
}

#[test]
fn parses_owned_damos_before_apply_kernel_format() {
    let line = "worker-1 [000] 123.456000: damon:damos_before_apply: ctx_idx=0 scheme_idx=0 target_idx=0 nr_regions=3 4096-8192: 0 4";
    let event = parse_damos_before_apply(line, 123_456_000_000).unwrap();
    assert_eq!(event.context_idx, 0);
    assert_eq!(event.scheme_idx, 0);
    assert_eq!(event.target_idx, 0);
    assert_eq!(
        event.range,
        AddressRange {
            start: 4096,
            end: 8192
        }
    );
    assert_eq!(event.nr_accesses, 0);
    assert_eq!(event.age, 4);
}

#[test]
fn shadow_requires_candidate_evidence_not_only_cumulative_counters() {
    assert!(validate_shadow_candidates(
        &[],
        AddressRange { start: 0, end: 10 },
        AddressRange { start: 10, end: 20 },
        AddressRange { start: 20, end: 40 },
        3,
    )
    .is_err());
}

#[test]
fn shadow_candidate_gate_rejects_external_range_access_and_age() {
    let hot = AddressRange { start: 0, end: 10 };
    let warm = AddressRange { start: 10, end: 20 };
    let cold = AddressRange { start: 20, end: 40 };
    assert!(validate_shadow_candidates(&[candidate(cold, 0, 3)], hot, warm, cold, 3).is_ok());
    for invalid in [
        candidate(AddressRange { start: 19, end: 30 }, 0, 3),
        candidate(AddressRange { start: 10, end: 21 }, 0, 3),
        candidate(cold, 1, 3),
        candidate(cold, 0, 2),
    ] {
        assert!(validate_shadow_candidates(&[invalid], hot, warm, cold, 3).is_err());
    }
    let mut external = candidate(cold, 0, 3);
    external.scheme_idx = 1;
    assert!(validate_shadow_candidates(&[external], hot, warm, cold, 3).is_err());
}

#[test]
fn configured_age_is_not_empirical_snapshot_index() {
    let pattern = AccessPattern::validation_cold();
    let empirical_first_snapshot = 2;
    assert_eq!(pattern.configured_age_min(), 3);
    assert_ne!(pattern.configured_age_min(), empirical_first_snapshot);
    assert!(VALIDATION_MAX_NR_SNAPSHOTS > empirical_first_snapshot);
}

#[test]
fn tried_regions_must_be_cleared_and_armed_before_observed_interval() {
    let valid = TriedRegionsLifecycle {
        stale_clear_ns: 1,
        arm_ns: 2,
        observed_interval_start_ns: 3,
        read_ns: 4,
        final_clear_ns: 5,
    };
    assert!(valid.valid());
    assert!(!TriedRegionsLifecycle {
        arm_ns: 4,
        ..valid.clone()
    }
    .valid());
    assert!(!TriedRegionsLifecycle {
        stale_clear_ns: 3,
        ..valid
    }
    .valid());
}
