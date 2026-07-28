#[path = "../../../build-support/git_stamp.rs"]
mod git_stamp;

use git_stamp::resolve;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn git(repository: &Path, arguments: &[&str]) -> String {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn repository() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let repository = root.path().join("repository");
    fs::create_dir(&repository).unwrap();
    git(&repository, &["init", "-b", "main"]);
    commit(&repository, "one");
    (root, repository)
}

fn commit(repository: &Path, content: &str) -> String {
    fs::write(repository.join("tracked.txt"), content).unwrap();
    git(repository, &["add", "tracked.txt"]);
    git(
        repository,
        &[
            "-c",
            "user.name=Nemor Test",
            "-c",
            "user.email=nemor-test@example.invalid",
            "commit",
            "-m",
            content,
        ],
    );
    git(repository, &["rev-parse", "HEAD"])
}

#[test]
fn symbolic_head_watches_head_loose_ref_and_advances() {
    let (_root, repository) = repository();
    let first = resolve(&repository).unwrap();
    assert_eq!(first.symbolic_ref.as_deref(), Some("refs/heads/main"));
    let reference = first.symbolic_ref_path.as_ref().unwrap();
    assert!(reference.is_file());
    assert!(first.dependency_paths().contains(&first.head_path));
    assert!(first.dependency_paths().contains(reference));

    let second_commit = commit(&repository, "two");
    let second = resolve(&repository).unwrap();
    assert_eq!(second.commit, second_commit);
    assert_ne!(first.commit, second.commit);
    assert_eq!(first.symbolic_ref_path, second.symbolic_ref_path);
}

#[test]
fn detached_head_watches_worktree_head_and_advances() {
    let (_root, repository) = repository();
    git(&repository, &["checkout", "--detach", "HEAD"]);
    let first = resolve(&repository).unwrap();
    assert!(first.symbolic_ref.is_none());
    assert!(first.symbolic_ref_path.is_none());
    assert!(first.dependency_paths().contains(&first.head_path));

    let second_commit = commit(&repository, "detached-two");
    let second = resolve(&repository).unwrap();
    assert_eq!(second.commit, second_commit);
    assert_ne!(first.commit, second.commit);
    assert_eq!(first.head_path, second.head_path);
}

#[test]
fn packed_symbolic_ref_watches_packed_state_and_loose_creation_parent() {
    let (_root, repository) = repository();
    git(&repository, &["pack-refs", "--all", "--prune"]);
    let packed = resolve(&repository).unwrap();
    let loose = packed.symbolic_ref_path.as_ref().unwrap();
    assert!(!loose.exists());
    assert!(!packed.dependency_paths().contains(loose));
    assert!(packed.packed_refs_path.as_ref().unwrap().is_file());
    assert!(packed
        .dependency_paths()
        .contains(packed.packed_refs_path.as_ref().unwrap()));
    let parent = packed.ref_parent_path.as_ref().unwrap();
    assert!(parent.is_dir());
    assert!(packed.dependency_paths().contains(parent));

    let next = commit(&repository, "loose-after-packed");
    assert!(loose.is_file());
    let loose_stamp = resolve(&repository).unwrap();
    assert_eq!(loose_stamp.commit, next);
    assert!(loose_stamp.dependency_paths().contains(loose));
}

#[test]
fn linked_worktree_uses_worktree_head_and_shared_ref_storage() {
    let (root, repository) = repository();
    let linked = root.path().join("linked");
    git(
        &repository,
        &[
            "worktree",
            "add",
            "-b",
            "linked",
            linked.to_str().unwrap(),
            "HEAD",
        ],
    );
    let stamp = resolve(&linked).unwrap();
    assert_eq!(stamp.repository_root, linked);
    assert!(stamp
        .head_path
        .to_string_lossy()
        .contains("/.git/worktrees/"));
    assert!(!stamp.head_path.starts_with(linked.join(".git")));
    assert_eq!(stamp.symbolic_ref.as_deref(), Some("refs/heads/linked"));
    assert!(stamp
        .symbolic_ref_path
        .as_ref()
        .unwrap()
        .starts_with(repository.join(".git/refs")));
}

#[test]
fn both_binary_build_scripts_delegate_to_the_same_stamp_helper() {
    let _shared_emit: fn(&Path) = git_stamp::emit;
    let benchmark = include_str!("../build.rs");
    let nemord = include_str!("../../nemord/build.rs");
    for script in [benchmark, nemord] {
        assert!(script.contains("../../build-support/git_stamp.rs"));
        assert!(script.contains("git_stamp::emit"));
        assert!(!script.contains(".git/HEAD"));
        assert!(!script.contains("Command::new"));
    }
}
