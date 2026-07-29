#![forbid(unsafe_code)]

use std::fs;
use std::process::Command;

const EXPECTED_GIT_HEAD: &str = env!("NEMOR_BUILD_GIT_HEAD");
const VALIDATOR: &str = env!("CARGO_BIN_EXE_nemor-privileged-validation");

fn is_full_git_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[test]
fn validator_exposes_full_build_git_head_and_embeds_it_in_binary() {
    assert!(is_full_git_object_id(EXPECTED_GIT_HEAD));
    assert_eq!(nemor_test_support::BUILD_GIT_HEAD, EXPECTED_GIT_HEAD);

    let bytes = fs::read(VALIDATOR).expect("read Cargo-built privileged validator");
    assert!(bytes
        .windows(EXPECTED_GIT_HEAD.len())
        .any(|window| window == EXPECTED_GIT_HEAD.as_bytes()));

    let output = Command::new(VALIDATOR)
        .arg("--build-git-head")
        .output()
        .expect("query privileged validator provenance");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)
            .expect("validator provenance is UTF-8")
            .trim(),
        EXPECTED_GIT_HEAD
    );
}

#[test]
fn validator_binary_rejects_a_different_expected_commit_identity() {
    let replacement = if EXPECTED_GIT_HEAD.as_bytes()[0] == b'0' {
        '1'
    } else {
        '0'
    };
    let wrong = format!("{replacement}{}", &EXPECTED_GIT_HEAD[1..]);
    let bytes = fs::read(VALIDATOR).expect("read Cargo-built privileged validator");
    assert!(!bytes
        .windows(wrong.len())
        .any(|window| window == wrong.as_bytes()));
}
