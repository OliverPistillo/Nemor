use nemor_benchmark::pressure::{PlannedLevelState, PlannedPressureLevel};
use nemor_benchmark::pressure_worker::{
    command_for_level, PressureWorkerClient, WorkerIpcMessage, PRESSURE_WORKER_PROTOCOL_VERSION,
};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

fn start_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let close = stat.rfind(')').unwrap();
    stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn tiny_real_worker_subprocess_uses_typed_ipc_and_starts_unallocated() {
    let temporary = tempfile::tempdir().unwrap();
    let socket = temporary.path().join("worker.sock");
    let binary = env!("CARGO_BIN_EXE_nemor-benchmark");
    let mut child = Command::new(binary)
        .arg("pressure-worker")
        .arg("--socket")
        .arg(&socket)
        .arg("--experiment-id")
        .arg("exp")
        .arg("--run-id")
        .arg("run")
        .arg("--seed")
        .arg("7")
        .spawn()
        .unwrap();
    let pid = child.id();
    let ticks = start_ticks(pid);
    let deadline = Instant::now() + Duration::from_secs(3);
    while !socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let metadata = std::fs::symlink_metadata(&socket).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let mut client = PressureWorkerClient::connect(&socket).unwrap();
    assert_eq!(
        client.receive().unwrap(),
        WorkerIpcMessage::Hello {
            version: PRESSURE_WORKER_PROTOCOL_VERSION,
            experiment_id: "exp".into(),
            run_id: "run".into(),
            pid,
            start_ticks: ticks,
            touched_bytes: 0,
        }
    );
    let boundary = WorkerIpcMessage::VerifyBoundary {
        version: PRESSURE_WORKER_PROTOCOL_VERSION,
        experiment_id: "exp".into(),
        run_id: "run".into(),
        pid,
        start_ticks: ticks,
        memory_max_bytes: 1024 * 1024,
    };
    assert!(matches!(
        client.send(&boundary).unwrap(),
        WorkerIpcMessage::BoundaryVerified { .. }
    ));
    let level = PlannedPressureLevel {
        level_index: 0,
        target_logical_bytes: 64 * 1024,
        target_touched_bytes: 64 * 1024,
        seed: 7,
        state: PlannedLevelState::Planned,
    };
    let ack = client
        .send(&WorkerIpcMessage::LevelRequest {
            version: PRESSURE_WORKER_PROTOCOL_VERSION,
            experiment_id: "exp".into(),
            run_id: "run".into(),
            pid,
            start_ticks: ticks,
            command: command_for_level("exp", "run", &level, 0).unwrap(),
            monotonic_ns: 1,
        })
        .unwrap();
    assert!(matches!(
        ack,
        WorkerIpcMessage::LevelAck {
            acknowledgement,
            ..
        } if acknowledgement.actual_touched_bytes == 64 * 1024
    ));
    let stopped = client
        .send(&WorkerIpcMessage::Stop {
            version: PRESSURE_WORKER_PROTOCOL_VERSION,
            experiment_id: "exp".into(),
            run_id: "run".into(),
            pid,
            start_ticks: ticks,
        })
        .unwrap();
    assert!(matches!(stopped, WorkerIpcMessage::Stopped { .. }));
    assert!(child.wait().unwrap().success());
}
