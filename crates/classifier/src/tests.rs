use super::*;
use collector::psi::{PsiLine, PsiSample};
use collector::swap::{SwapConfiguration, SwapState};
use collector::zram::ZramState;
use collector::zswap::ZswapState;
use collector::{ProcessSample, SystemSample};
use common::Config;

fn config() -> Config {
    Config::from_toml(include_str!("../../../config/default.toml")).expect("configuration")
}

fn process(pid: u32, name: Option<&str>) -> ProcessSample {
    ProcessSample {
        timestamp_ns: 1,
        pid,
        executable: name.map(|name| format!("/usr/bin/{name}")),
        executable_name: name.map(str::to_owned),
        parent_pid: Some(1),
        process_group_id: Some(i32::try_from(pid).expect("fixture PID")),
        session_id: Some(1),
        tty_nr: None,
        foreground_process_group_id: None,
        start_time_ticks: Some(u64::from(pid)),
        cgroup_path: Some("/user.slice/app.scope".to_owned()),
        rss_bytes: Some(10),
        pss_bytes: None,
        uss_bytes: None,
        swap_bytes: Some(0),
        minor_faults: Some(0),
        major_faults: Some(0),
        cpu_percent: Some(1.0),
        io_read_bytes: Some(0),
        io_write_bytes: Some(0),
    }
}

fn system(available_percent: u64) -> SystemSample {
    SystemSample {
        timestamp_ns: 1,
        mem_total_bytes: 1_000,
        mem_available_bytes: available_percent * 10,
        anon_bytes: None,
        file_cache_bytes: None,
        slab_bytes: None,
        swap_used_bytes: Some(0),
        swap_in_pages: Some(0),
        swap_out_pages: Some(0),
        major_faults: Some(0),
        minor_faults: Some(0),
        pgscan: Some(0),
        pgsteal: Some(0),
        workingset_refault: Some(0),
        psi_memory: None,
        psi_cpu: None,
        psi_io: None,
        swap: SwapState {
            entries: Vec::new(),
            configuration: SwapConfiguration::None,
        },
        zram: ZramState {
            available: false,
            devices: Vec::new(),
        },
        zswap: ZswapState {
            available: false,
            enabled: None,
            stored_pages: None,
            pool_bytes: None,
        },
        capabilities_unavailable: Vec::new(),
    }
}

fn classified(outcome: &ClassificationOutcome) -> WorkloadClass {
    outcome.class().expect("classified workload")
}

#[test]
fn process_categories_protection_and_cold_invariants_are_conservative() {
    let configuration = config();
    let mut background = process(2, Some("tracker-miner-fs-3"));
    background.tty_nr = Some(1);
    background.process_group_id = Some(2);
    background.foreground_process_group_id = Some(99);
    let samples = [process(1, Some("systemd")), process(3, None), background];
    let classifier = Classifier::new(
        configuration.classification.clone(),
        configuration.pressure.clone(),
    );
    let values = classifier.classify_processes(&samples);
    assert_eq!(values[0].category, ProcessCategory::Critical);
    assert!(values[0].protected && !values[0].cold_candidate);
    assert_eq!(values[1].category, ProcessCategory::Unknown);
    assert!(values[1].protected && !values[1].cold_candidate);
    assert_eq!(values[2].category, ProcessCategory::Background);
    assert!(values[2].cold_candidate);
}

#[test]
fn foreground_uses_tty_and_keeps_missing_evidence_unknown() {
    let configuration = config();
    let mut foreground = process(10, Some("konsole"));
    foreground.tty_nr = Some(1);
    foreground.process_group_id = Some(10);
    foreground.foreground_process_group_id = Some(10);
    let mut background = foreground.clone();
    background.pid = 11;
    background.process_group_id = Some(11);
    let unknown = process(12, Some("konsole"));
    let classifier = Classifier::new(
        configuration.classification.clone(),
        configuration.pressure.clone(),
    );
    let values = classifier.classify_processes(&[foreground, background, unknown]);
    assert_eq!(values[0].foreground, ForegroundState::Foreground);
    assert_eq!(values[0].foreground_confidence, 0.98);
    assert_eq!(values[1].foreground, ForegroundState::Background);
    assert_eq!(values[1].foreground_confidence, 0.95);
    assert_eq!(values[2].foreground, ForegroundState::Unknown);
    assert_eq!(values[2].foreground_confidence, 0.0);
}

#[test]
fn steam_wine_and_proton_helpers_alone_are_not_games() {
    let configuration = config();
    let classifier = Classifier::new(
        configuration.classification.clone(),
        configuration.pressure.clone(),
    );
    for name in ["steam", "steamwebhelper", "wine64", "proton"] {
        let values = classifier.classify_processes(&[process(1, Some(name))]);
        assert!(!values[0].is_game, "{name} alone must not be a game");
        assert!(!values[0].protected_game);
    }
    let named_game = classifier.classify_processes(&[process(2, Some("game-launcher"))]);
    assert!(!named_game[0].is_game);
}

#[test]
fn generic_desktop_app_scope_is_not_steam_game_evidence() {
    let configuration = config();
    let classifier = Classifier::new(
        configuration.classification.clone(),
        configuration.pressure.clone(),
    );
    let mut sample = process(10, Some("unrecognized"));
    sample.cgroup_path = Some(
        "/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.example.App.scope"
            .to_owned(),
    );
    let classified = classifier.classify_processes(&[sample]);
    assert!(!classified[0].is_game);
    assert!(!classified[0]
        .reasons
        .iter()
        .any(|reason| reason == "steam_app_cgroup"));
}

#[test]
fn native_steam_proton_and_gamescope_scenarios_require_context() {
    let mut configuration = config();
    configuration.classification.game_executables = vec!["native-game".to_owned()];
    let classifier = Classifier::new(
        configuration.classification.clone(),
        configuration.pressure.clone(),
    );
    let native = classifier.classify_processes(&[process(1, Some("native-game"))]);
    assert!(native[0].is_game && !native[0].cold_candidate);

    let steam = process(10, Some("steam"));
    let mut steam_game = process(11, Some("game-bin"));
    steam_game.parent_pid = Some(10);
    steam_game.cgroup_path = Some("/user.slice/steam_app_123.scope".to_owned());
    let values = classifier.classify_processes(&[steam, steam_game]);
    assert!(values[1].is_game);

    let mut proton = process(12, Some("proton"));
    proton.cgroup_path = Some("/user.slice/steam_app_456.scope".to_owned());
    assert!(classifier.classify_processes(&[proton])[0].is_game);

    let gamescope = process(20, Some("gamescope"));
    let mut child = process(21, Some("native-child"));
    child.parent_pid = Some(20);
    let mut browser = process(22, Some("firefox"));
    browser.parent_pid = Some(20);
    let values = classifier.classify_processes(&[gamescope, child, browser]);
    assert!(values[1].is_game);
    assert_eq!(values[1].foreground, ForegroundState::Foreground);
    assert!(!values[2].is_game);

    for mut game in [process(31, Some("native-game")), {
        let mut value = process(32, Some("proton"));
        value.cgroup_path = Some("/user.slice/steam_app_789.scope".to_owned());
        value
    }] {
        game.cpu_percent = Some(0.0);
        game.io_read_bytes = Some(0);
        game.io_write_bytes = Some(0);
        game.major_faults = Some(0);
        let classified = classifier.classify_processes(&[game]);
        assert!(classified[0].is_game);
        assert!(!classified[0].cold_candidate);
    }
    let mut critical = process(40, Some("systemd"));
    critical.cpu_percent = Some(0.0);
    critical.io_read_bytes = Some(0);
    critical.io_write_bytes = Some(0);
    critical.major_faults = Some(0);
    assert!(!classifier.classify_processes(&[critical])[0].cold_candidate);
}

#[test]
fn shell_alone_is_not_development_but_toolset_is() {
    let configuration = config();
    let mut classifier = Classifier::new(
        configuration.classification.clone(),
        configuration.pressure.clone(),
    );
    let shell = classifier.classify(1, Some(&system(80)), &[process(1, Some("bash"))]);
    assert!(matches!(shell.outcome, ClassificationOutcome::Unknown(_)));
    let tools = [process(2, Some("code")), process(3, Some("rust-analyzer"))];
    let result = classifier.classify(2, Some(&system(80)), &tools);
    assert_eq!(classified(&result.outcome), WorkloadClass::Development);
}

#[test]
fn browser_heavy_is_quantitative_and_light_browser_is_desktop_only_with_activity() {
    let mut configuration = config();
    configuration.classification.browser_heavy_process_count = 2;
    configuration.classification.browser_heavy_memory_percent = 15.0;
    let mut classifier = Classifier::new(
        configuration.classification.clone(),
        configuration.pressure.clone(),
    );
    let mut first = process(1, Some("firefox"));
    first.rss_bytes = Some(100);
    let mut second = process(2, Some("firefox"));
    second.rss_bytes = Some(100);
    let result = classifier.classify(1, Some(&system(80)), &[first, second]);
    assert_eq!(classified(&result.outcome), WorkloadClass::BrowserHeavy);
    let light = classifier.classify(2, Some(&system(80)), &[process(3, Some("firefox"))]);
    assert_eq!(classified(&light.outcome), WorkloadClass::Desktop);
}

#[test]
fn virtualization_requires_a_quantitative_memory_share() {
    let mut configuration = config();
    configuration.classification.virtualization_memory_percent = 10.0;
    let mut classifier = Classifier::new(
        configuration.classification.clone(),
        configuration.pressure.clone(),
    );
    let mut qemu = process(1, Some("qemu-system-x86_64"));
    qemu.rss_bytes = Some(200);
    let result = classifier.classify(1, Some(&system(80)), &[qemu]);
    assert_eq!(classified(&result.outcome), WorkloadClass::Virtualization);
    let container = classifier.classify(2, Some(&system(80)), &[process(2, Some("containerd"))]);
    assert!(matches!(
        container.outcome,
        ClassificationOutcome::Unknown(_)
    ));
}

#[test]
fn pressure_has_deterministic_precedence_and_preserves_rejected_game_evidence() {
    let mut configuration = config();
    configuration.classification.game_executables = vec!["native-game".to_owned()];
    let mut classifier = Classifier::new(
        configuration.classification.clone(),
        configuration.pressure.clone(),
    );
    let result = classifier.classify(
        1,
        Some(&system(u64::from(
            configuration.pressure.critical_available_percent,
        ))),
        &[process(1, Some("native-game"))],
    );
    assert_eq!(classified(&result.outcome), WorkloadClass::CriticalPressure);
    assert!(result
        .outcome
        .explanation()
        .rejected_candidates
        .iter()
        .any(|candidate| candidate.candidate == WorkloadClass::Gaming));
}

#[test]
fn psi_pressure_is_used_and_unknown_never_becomes_idle() {
    let configuration = config();
    let mut pressured = system(80);
    pressured.psi_memory = Some(PsiSample {
        some: Some(PsiLine {
            avg10: configuration.pressure.psi_some_avg10_threshold,
            avg60: 0.0,
            avg300: 0.0,
            total_us: 1,
        }),
        full: None,
    });
    let mut classifier = Classifier::new(
        configuration.classification.clone(),
        configuration.pressure.clone(),
    );
    assert_eq!(
        classified(
            &classifier
                .classify(1, Some(&pressured), &[process(1, None)])
                .outcome
        ),
        WorkloadClass::MemoryPressure
    );
    let uncertain = classifier.classify(2, Some(&system(80)), &[process(1, None)]);
    assert!(matches!(
        uncertain.outcome,
        ClassificationOutcome::Unknown(_)
    ));
    let idle = classifier.classify(3, Some(&system(80)), &[]);
    assert_eq!(classified(&idle.outcome), WorkloadClass::Idle);
}

#[test]
fn stabilization_suppresses_flapping_duplicates_and_makes_critical_immediate() {
    let configuration = config();
    let mut stabilizer = WorkloadStabilizer::new(3);
    let desktop = WorkloadDecision {
        class: WorkloadClass::Desktop,
        confidence: 0.8,
        explanation: WorkloadExplanation {
            rule_version: RULE_VERSION.to_owned(),
            selected_class: "desktop".to_owned(),
            confidence: 0.8,
            evidence: Vec::new(),
            rejected_candidates: Vec::new(),
            protection_reasons: Vec::new(),
        },
    };
    let outcome = ClassificationOutcome::Classified(desktop.clone());
    assert!(stabilizer.observe(1, &outcome).is_none());
    assert!(stabilizer.observe(2, &outcome).is_none());
    assert!(stabilizer.observe(3, &outcome).is_some());
    assert!(stabilizer.observe(4, &outcome).is_none());
    let critical = ClassificationOutcome::Classified(WorkloadDecision {
        class: WorkloadClass::CriticalPressure,
        ..desktop
    });
    let transition = stabilizer
        .observe(5, &critical)
        .expect("critical immediate");
    assert_eq!(transition.previous_class, Some(WorkloadClass::Desktop));
    assert_eq!(
        configuration.classification.confirmation_samples, 3,
        "default fixture documents stabilization"
    );
}

#[test]
fn explanation_is_stable_serializable_and_contains_no_command_line() {
    let mut configuration = config();
    configuration.classification.game_executables = vec!["private-game".to_owned()];
    let mut classifier = Classifier::new(
        configuration.classification.clone(),
        configuration.pressure.clone(),
    );
    let result = classifier.classify(1, Some(&system(80)), &[process(1, Some("private-game"))]);
    let json = serde_json::to_string(result.outcome.explanation()).expect("valid JSON");
    assert!(json.contains(RULE_VERSION));
    assert!(!json.contains("/home/"));
    assert!(!json.contains("cmdline"));
}

#[test]
fn process_identity_distinguishes_paths_and_has_private_fallbacks() {
    let configuration = config();
    let classifier = Classifier::new(
        configuration.classification.clone(),
        configuration.pressure.clone(),
    );
    let mut system_tool = process(1, Some("same-tool"));
    system_tool.executable = Some("/usr/bin/same-tool".to_owned());
    let mut vendor_tool = process(2, Some("same-tool"));
    vendor_tool.executable = Some("/opt/vendor/same-tool".to_owned());
    let values =
        classifier.classify_processes(&[system_tool.clone(), vendor_tool, system_tool.clone()]);
    assert_ne!(values[0].command_signature, values[1].command_signature);
    assert_ne!(values[0].executable, values[1].executable);
    assert_eq!(values[0].command_signature, values[2].command_signature);
    assert_eq!(values[0].executable, values[2].executable);

    let mut private = process(3, Some("private-tool"));
    private.executable = Some("/home/alice/secret/private-tool".to_owned());
    let private = classifier.classify_processes(&[private]);
    assert_eq!(private[0].executable, "private:private-tool");
    assert!(!private[0].command_signature.contains("alice"));
    assert!(!private[0]
        .reasons
        .iter()
        .any(|reason| reason.contains("alice")));

    let mut fallback = process(4, Some("fallback-tool"));
    fallback.executable = None;
    let fallback = classifier.classify_processes(&[fallback]);
    assert_eq!(fallback[0].executable, "fallback-tool");
    assert_eq!(fallback[0].command_signature.len(), 64);
}

#[test]
fn below_threshold_and_partial_data_use_safe_unknown_fallback() {
    let mut configuration = config();
    configuration.classification.minimum_confidence = 0.99;
    configuration.classification.game_executables = vec!["configured-game".to_owned()];
    let mut classifier = Classifier::new(
        configuration.classification.clone(),
        configuration.pressure.clone(),
    );
    let result = classifier.classify(1, Some(&system(80)), &[process(1, Some("configured-game"))]);
    assert!(matches!(result.outcome, ClassificationOutcome::Unknown(_)));
    assert_eq!(result.processes[0].category, ProcessCategory::Unknown);
    assert!(result.processes[0].protected);
    let partial = classifier.classify(2, None, &[process(2, None)]);
    assert!(matches!(partial.outcome, ClassificationOutcome::Unknown(_)));
}

#[test]
fn required_workload_transition_sequence_preserves_previous_and_new() {
    let explanation = |class: WorkloadClass| WorkloadExplanation {
        rule_version: RULE_VERSION.to_owned(),
        selected_class: class.to_string(),
        confidence: 0.9,
        evidence: vec![Evidence {
            code: "fixture".to_owned(),
            description: "fixture transition".to_owned(),
            observed: "true".to_owned(),
            threshold: None,
            contribution: 0.9,
        }],
        rejected_candidates: Vec::new(),
        protection_reasons: Vec::new(),
    };
    let classes = [
        WorkloadClass::Desktop,
        WorkloadClass::BrowserHeavy,
        WorkloadClass::Gaming,
        WorkloadClass::GamingBackgroundHeavy,
        WorkloadClass::Gaming,
        WorkloadClass::MemoryPressure,
        WorkloadClass::CriticalPressure,
        WorkloadClass::Desktop,
    ];
    let mut stabilizer = WorkloadStabilizer::new(1);
    let mut previous = None;
    for (timestamp, class) in classes.into_iter().enumerate() {
        let outcome = ClassificationOutcome::Classified(WorkloadDecision {
            class,
            confidence: 0.9,
            explanation: explanation(class),
        });
        let transition = stabilizer
            .observe(i64::try_from(timestamp).expect("timestamp"), &outcome)
            .expect("class change");
        assert_eq!(transition.previous_class, previous);
        assert_eq!(transition.new_class, class);
        assert!((0.0..=1.0).contains(&transition.confidence));
        serde_json::to_string(&transition.explanation).expect("valid reason JSON");
        previous = Some(class);
        assert!(stabilizer.observe(100, &outcome).is_none());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn real_linux_process_identity_can_be_classified_read_only() {
    let configuration = config();
    let mut collector = collector::SystemCollector::production();
    let timestamp = collector::unix_timestamp_ns().expect("timestamp");
    let system = collector
        .sample_system(timestamp)
        .expect("real system telemetry");
    let processes = collector
        .sample_processes(timestamp, false, 0)
        .expect("real process telemetry");
    let mut classifier = Classifier::new(
        configuration.classification.clone(),
        configuration.pressure.clone(),
    );
    let batch = classifier.classify(timestamp, Some(&system), &processes.samples);
    assert_eq!(batch.processes.len(), processes.samples.len());
    assert!(batch
        .processes
        .iter()
        .all(|process| !process.command_signature.is_empty()));
}
