use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    let output = Command::new("/usr/bin/git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git is required to stamp benchmark build provenance");
    assert!(
        output.status.success(),
        "cannot read benchmark build commit"
    );
    let head = String::from_utf8(output.stdout).expect("Git HEAD is UTF-8");
    println!("cargo:rustc-env=NEMOR_BUILD_GIT_HEAD={}", head.trim());
}
