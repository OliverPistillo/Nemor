use super::*;
use collector::ProcessSample;
use common::Config;

fn config() -> Config {
    Config::from_toml(include_str!("../../../config/default.toml")).expect("config")
}

fn classified(category: ProcessCategory, foreground: ForegroundState) -> ProcessClassification {
    let protected = category == ProcessCategory::Unknown
        || category == ProcessCategory::Critical
        || foreground == ForegroundState::Foreground;
    ProcessClassification {
        sample: ProcessSample {
            timestamp_ns: 1,
            pid: 42,
            executable: Some("/usr/bin/fixture".to_owned()),
            executable_name: Some("fixture".to_owned()),
            parent_pid: Some(1),
            process_group_id: Some(42),
            session_id: Some(1),
            tty_nr: Some(1),
            foreground_process_group_id: Some(if foreground == ForegroundState::Foreground {
                42
            } else {
                7
            }),
            start_time_ticks: Some(100),
            cgroup_path: Some("/user.slice/fixture.scope".to_owned()),
            rss_bytes: Some(10),
            pss_bytes: Some(8),
            uss_bytes: Some(6),
            swap_bytes: Some(0),
            minor_faults: Some(0),
            major_faults: Some(0),
            cpu_percent: Some(0.0),
            io_read_bytes: Some(0),
            io_write_bytes: Some(0),
        },
        executable: "/usr/bin/fixture".to_owned(),
        command_signature: "a".repeat(64),
        application_name: Some("/usr/bin/fixture".to_owned()),
        category,
        is_game: category == ProcessCategory::Game,
        is_critical: category == ProcessCategory::Critical,
        protected,
        protected_game: category == ProcessCategory::Game,
        cold_candidate: category == ProcessCategory::Background && !protected,
        foreground,
        foreground_confidence: 0.95,
        confidence: 0.9,
        reasons: vec!["fixture".to_owned()],
    }
}

fn candidate<'a>(classification: &'a ProcessClassification) -> PlanInput<'a> {
    PlanInput {
        process_catalog_id: 7,
        identity: &classification.command_signature,
        current_start_time_ticks: Some(100),
        source_group: "/user.slice/fixture.scope",
        classification,
        total_ram_bytes: 1_000,
        protected_workload_bytes: 200,
    }
}

fn allowed_config() -> CgroupsConfig {
    let mut value = config().cgroups;
    value.enabled = true;
    value.dry_run = false;
    value.allow_move = true;
    value.allowed_identities = vec!["a".repeat(64)];
    value
}

fn ready_backend() -> FakeCgroupBackend {
    let mut backend = FakeCgroupBackend::default();
    backend.starts.insert(42, 100);
    backend
        .placements
        .insert(42, "/user.slice/fixture.scope".to_owned());
    backend.groups.insert(
        "/user.slice/fixture.scope".to_owned(),
        GroupState {
            name: "/user.slice/fixture.scope".to_owned(),
            path: PathBuf::from("/fake/source"),
            owned_by_nemor: false,
            memory_low: None,
            memory_high: None,
            pids: BTreeSet::from([42]),
        },
    );
    backend
}

#[test]
fn capability_matrix_is_fail_closed() {
    let mut capability = FakeCgroupBackend::default().capabilities;
    assert!(capability.mutation_ready());
    capability.cgroup_v2 = false;
    assert!(!capability.mutation_ready());
    capability.cgroup_v2 = true;
    capability.memory_controller = false;
    assert!(!capability.mutation_ready());
    capability.memory_controller = true;
    capability.memory_high = false;
    assert!(!capability.mutation_ready());
    capability.memory_high = true;
    capability.writable = false;
    assert!(!capability.mutation_ready());
}

#[test]
fn memory_low_and_high_are_dynamic_and_bounded() {
    let mut value = allowed_config();
    assert_eq!(memory_low_bytes(1_000, 10, &value), 110);
    assert_eq!(memory_low_bytes(1_000, 900, &value), 400);
    assert_eq!(memory_high_bytes(1_000, 300, &value), 600);
    value.foreground_min_percent = 20;
    assert_eq!(memory_low_bytes(2_000, 1, &value), 400);
    assert_eq!(memory_high_bytes(2_000, 1_900, &value), 400);
}

#[test]
fn observe_always_generates_dry_run_and_zero_mutations() {
    let process = classified(ProcessCategory::Background, ForegroundState::Background);
    let plan = plan(&candidate(&process), &allowed_config(), "observe");
    assert!(plan.allowed && plan.dry_run);
    let mut backend = ready_backend();
    let mut store = MemorySnapshotStore::default();
    assert!(apply_one(&mut backend, &mut store, 1, 1, &plan)
        .expect("dry run")
        .is_none());
    assert!(backend.operations.is_empty());
    assert!(store.pending().expect("pending").is_empty());
}

#[test]
fn placement_invariants_block_unsafe_candidates() {
    let mut configuration = allowed_config();
    configuration.allowed_identities.clear();
    for (category, foreground) in [
        (ProcessCategory::Game, ForegroundState::Background),
        (ProcessCategory::Critical, ForegroundState::Background),
        (ProcessCategory::Unknown, ForegroundState::Unknown),
    ] {
        let process = classified(category, foreground);
        let result = plan(&candidate(&process), &configuration, "mutating-test");
        assert!(!result.allowed, "{category:?}");
        assert!(result
            .block_reasons
            .iter()
            .any(|item| item == "identity_not_allow_listed" || item == "unknown_process"));
    }
}

#[test]
fn allow_listed_foreground_game_and_critical_get_only_memory_low() {
    for (category, foreground) in [
        (ProcessCategory::Desktop, ForegroundState::Foreground),
        (ProcessCategory::Game, ForegroundState::Background),
        (ProcessCategory::Critical, ForegroundState::Unknown),
    ] {
        let process = classified(category, foreground);
        let result = plan(&candidate(&process), &allowed_config(), "test");
        assert!(result.allowed, "{category:?}");
        assert_eq!(result.target_group, FOREGROUND_GROUP);
        assert!(result.properties.memory_low.is_some());
        assert!(result.properties.memory_high.is_none());
    }
}

#[test]
fn allow_list_identity_and_pid_reuse_are_not_pid_based() {
    let process = classified(ProcessCategory::Background, ForegroundState::Background);
    let mut configuration = allowed_config();
    configuration.allowed_identities.clear();
    assert!(!plan(&candidate(&process), &configuration, "test").allowed);
    let mut input = candidate(&process);
    input.current_start_time_ticks = Some(101);
    assert!(!plan(&input, &allowed_config(), "test").allowed);
}

#[test]
fn apply_verifies_and_rollback_is_idempotent() {
    let process = classified(ProcessCategory::Background, ForegroundState::Background);
    let plan = plan(&candidate(&process), &allowed_config(), "test");
    let mut backend = ready_backend();
    let mut store = MemorySnapshotStore::default();
    let mut snapshot = apply_one(&mut backend, &mut store, 1, 1, &plan)
        .expect("apply")
        .expect("snapshot");
    assert!(snapshot.verified);
    assert_eq!(backend.placements[&42], BACKGROUND_GROUP);
    rollback_one(&mut backend, &mut store, &mut snapshot).expect("rollback");
    rollback_one(&mut backend, &mut store, &mut snapshot).expect("retry");
    assert_eq!(backend.placements[&42], "/user.slice/fixture.scope");
}

#[test]
fn failures_do_not_leave_unverified_mutations() {
    for failure in [
        FakeFailure::Create,
        FakeFailure::Property,
        FakeFailure::Move,
        FakeFailure::Verify,
    ] {
        let process = classified(ProcessCategory::Background, ForegroundState::Background);
        let plan = plan(&candidate(&process), &allowed_config(), "test");
        let mut backend = ready_backend();
        backend.failure = Some(failure);
        let mut store = MemorySnapshotStore::default();
        assert!(apply_one(&mut backend, &mut store, 1, 1, &plan).is_err());
    }
}

#[test]
fn recovery_handles_terminated_reused_and_missing_original_processes() {
    let process = classified(ProcessCategory::Background, ForegroundState::Background);
    let plan = plan(&candidate(&process), &allowed_config(), "test");
    for start in [None, Some(101), Some(100)] {
        let mut backend = ready_backend();
        let mut store = MemorySnapshotStore::default();
        let _ = apply_one(&mut backend, &mut store, 1, 1, &plan).expect("apply");
        match start {
            Some(value) => {
                backend.starts.insert(42, value);
            }
            None => {
                backend.starts.remove(&42);
                backend.placements.remove(&42);
            }
        }
        let first = recover(&mut backend, &mut store);
        assert_eq!(first.len(), 1);
        assert!(first[0].is_ok());
        assert!(recover(&mut backend, &mut store).is_empty());
    }
}

#[test]
fn recovery_leaves_live_process_untouched_when_original_group_disappeared() {
    let process = classified(ProcessCategory::Background, ForegroundState::Background);
    let plan = plan(&candidate(&process), &allowed_config(), "test");
    let mut backend = ready_backend();
    let mut store = MemorySnapshotStore::default();
    let _ = apply_one(&mut backend, &mut store, 1, 1, &plan).expect("apply");
    backend.groups.remove("/user.slice/fixture.scope");
    let result = recover(&mut backend, &mut store);
    assert_eq!(result.len(), 1);
    assert!(result[0].is_err());
    assert_eq!(backend.placements[&42], BACKGROUND_GROUP);
    assert_eq!(store.pending().expect("pending").len(), 1);
}

#[test]
fn ownership_and_names_reject_external_groups_and_injection() {
    for name in [
        "system.slice",
        "user.slice",
        "../nemor-test-x.scope",
        "nemor-other.slice",
    ] {
        assert!(!is_managed_name(name));
    }
    assert!(is_managed_name(FOREGROUND_GROUP));
    assert!(is_managed_name(BACKGROUND_GROUP));
    assert!(is_managed_name("nemor-test-123.scope"));
}

#[test]
fn serialized_plan_is_explainable_and_never_requests_memory_max() {
    let process = classified(ProcessCategory::Background, ForegroundState::Background);
    let value =
        serde_json::to_value(plan(&candidate(&process), &allowed_config(), "test")).expect("JSON");
    assert_eq!(value["target_group"], BACKGROUND_GROUP);
    assert!(value["properties"].get("memory_high").is_some());
    assert!(value["properties"].get("memory_max").is_none());
}

#[test]
fn linux_backend_reads_real_cachyos_capabilities_without_mutation() {
    if cfg!(target_os = "linux") {
        let backend = LinuxCgroupBackend::default();
        let capability = backend.capabilities().expect("real cgroup capability");
        assert!(capability.cgroup_v2);
        assert!(capability.memory_controller);
    }
}
