#![forbid(unsafe_code)]

use std::process::Command;
use storage::Storage;
use test_support::LinuxFixture;

#[test]
fn real_report_latest_json_command_reads_fixture_database() {
    let fixture = LinuxFixture::telemetry_complete().expect("fixture");
    let storage = Storage::open(fixture.database_path()).expect("database");
    let host = common::HostMetadata {
        machine_id: "cli-report-fixture".to_owned(),
        hostname: "fixture".to_owned(),
        distro: "cachyos".to_owned(),
        distro_version: Some("fixture".to_owned()),
        kernel_version: "6.12-fixture".to_owned(),
        cpu_model: None,
        cpu_cores: Some(1),
        ram_total_bytes: 1024,
        swap_total_bytes: 0,
        gpu_model: None,
        storage_model: None,
    };
    let host_id = storage.upsert_host(&host).expect("host");
    let session = storage
        .open_session(host_id, "0.1.0", "fixture-hash")
        .expect("session");
    storage
        .connection()
        .execute(
            "INSERT INTO system_samples (
                session_id, timestamp_ns, mem_total_bytes, mem_available_bytes,
                swap_used_bytes, major_faults, swap_in_pages, swap_out_pages,
                psi_memory_some_avg10, psi_memory_full_avg10,
                zram_present, zswap_present, capabilities_unavailable_json
             ) VALUES (?1, 1, 1024, 768, 64, 5, 2, 3, 0.25, 0.05, 1, 1, '[]')",
            [session],
        )
        .expect("sample");
    drop(storage);

    let output = Command::new(env!("CARGO_BIN_EXE_nemorctl"))
        .arg("--config")
        .arg(fixture.config_path())
        .args(["report", "latest", "--json"])
        .output()
        .expect("run report command");
    assert!(
        output.status.success(),
        "report failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid command JSON");
    assert_eq!(json["session_id"], session);
    assert_eq!(json["system_samples"], 1);
    assert_eq!(json["min_mem_available_bytes"], 768);
    assert_eq!(json["zram_observed"], true);
    assert_eq!(json["zswap_observed"], true);
}

#[test]
fn real_workload_latest_json_command_is_read_only_and_valid() {
    let fixture = LinuxFixture::telemetry_complete().expect("fixture");
    let storage = Storage::open(fixture.database_path()).expect("database");
    let host = common::HostMetadata {
        machine_id: "cli-workload-fixture".to_owned(),
        hostname: "fixture".to_owned(),
        distro: "cachyos".to_owned(),
        distro_version: Some("fixture".to_owned()),
        kernel_version: "6.12-fixture".to_owned(),
        cpu_model: None,
        cpu_cores: Some(1),
        ram_total_bytes: 1024,
        swap_total_bytes: 0,
        gpu_model: None,
        storage_model: None,
    };
    let host_id = storage.upsert_host(&host).expect("host");
    let session = storage
        .open_session(host_id, "0.1.0", "fixture-hash")
        .expect("session");
    storage
        .connection()
        .execute(
            "INSERT INTO workload_events (
                session_id, timestamp_ns, previous_class, new_class,
                confidence, reason_json
             ) VALUES (
                ?1, 42, NULL, 'gaming', 0.9,
                '{\"rule_version\":\"heuristic-v1\",\"selected_class\":\"gaming\",\"confidence\":0.9,\"evidence\":[{\"code\":\"protected_game_process\",\"description\":\"fixture\",\"observed\":\"1 game process\",\"threshold\":null,\"contribution\":0.9}],\"rejected_candidates\":[],\"protection_reasons\":[\"game_process_protected\"]}'
             )",
            [session],
        )
        .expect("workload event");
    drop(storage);
    let before = std::fs::read(fixture.database_path()).expect("database bytes");

    let output = Command::new(env!("CARGO_BIN_EXE_nemorctl"))
        .arg("--config")
        .arg(fixture.config_path())
        .args(["workload", "latest", "--json"])
        .output()
        .expect("run workload command");
    assert!(
        output.status.success(),
        "workload failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid command JSON");
    assert_eq!(json["session_id"], session);
    assert_eq!(json["current_class"], "gaming");
    assert_eq!(json["rule_version"], "heuristic-v1");
    assert_eq!(
        std::fs::read(fixture.database_path()).expect("database bytes"),
        before
    );
}

#[test]
fn workload_latest_without_events_returns_controlled_json_state() {
    let fixture = LinuxFixture::telemetry_complete().expect("fixture");
    let storage = Storage::open(fixture.database_path()).expect("database");
    let host = common::HostMetadata {
        machine_id: "cli-empty-workload".to_owned(),
        hostname: "fixture".to_owned(),
        distro: "cachyos".to_owned(),
        distro_version: None,
        kernel_version: "6.12-fixture".to_owned(),
        cpu_model: None,
        cpu_cores: Some(1),
        ram_total_bytes: 1024,
        swap_total_bytes: 0,
        gpu_model: None,
        storage_model: None,
    };
    let host_id = storage.upsert_host(&host).expect("host");
    storage
        .open_session(host_id, "0.1.0", "fixture-hash")
        .expect("session");
    drop(storage);
    let output = Command::new(env!("CARGO_BIN_EXE_nemorctl"))
        .arg("--config")
        .arg(fixture.config_path())
        .args(["workload", "latest", "--json"])
        .output()
        .expect("run workload command");
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("controlled JSON");
    assert_eq!(json["available"], false);
    assert_eq!(json["current_class"], serde_json::Value::Null);
}
