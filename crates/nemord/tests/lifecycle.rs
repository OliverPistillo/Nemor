#![forbid(unsafe_code)]
#![cfg(unix)]

use common::StatusState;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use test_support::LinuxFixture;

fn assert_clean_shutdown(signal: Signal) {
    let fixture = LinuxFixture::compatible().expect("fixture");
    let executable = env!("CARGO_BIN_EXE_nemord");
    let child = Command::new(executable)
        .arg("--config")
        .arg(fixture.config_path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("real daemon should start");

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(report) = storage::inspect_status(fixture.database_path()) {
            if report.state == StatusState::SessionOpen {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not create an open session within ten seconds"
        );
        thread::sleep(Duration::from_millis(50));
    }

    let raw_pid = i32::try_from(child.id()).expect("PID fits i32");
    kill(Pid::from_raw(raw_pid), signal).expect("send shutdown signal safely");
    let output = child.wait_with_output().expect("wait for daemon");
    assert!(
        output.status.success(),
        "daemon failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = nemorctl::status(fixture.config_path()).expect("status after shutdown");
    assert_eq!(report.state, StatusState::ClosedClean);
    let session = report.last_session.expect("session after shutdown");
    assert!(session.ended_at.is_some());
    assert!(session.clean_shutdown);
    let json = nemorctl::render_status(
        &nemorctl::status(fixture.config_path()).expect("status --json data"),
        true,
    )
    .expect("status --json rendering");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid status JSON");
    assert_eq!(parsed["state"], "closed_clean");
}

#[test]
fn real_daemon_closes_session_on_sigterm_and_status_reads_it() {
    assert_clean_shutdown(Signal::SIGTERM);
}

#[test]
fn real_daemon_closes_session_on_sigint_and_status_reads_it() {
    assert_clean_shutdown(Signal::SIGINT);
}
