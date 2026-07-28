use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitStamp {
    pub repository_root: PathBuf,
    pub head_path: PathBuf,
    pub symbolic_ref: Option<String>,
    pub symbolic_ref_path: Option<PathBuf>,
    pub packed_refs_path: Option<PathBuf>,
    pub ref_parent_path: Option<PathBuf>,
    pub commit: String,
}

impl GitStamp {
    pub fn dependency_paths(&self) -> BTreeSet<PathBuf> {
        [
            Some(self.head_path.clone()),
            self.symbolic_ref_path
                .as_ref()
                .filter(|path| path.is_file())
                .cloned(),
            self.packed_refs_path.clone(),
            self.ref_parent_path.clone(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

pub fn resolve(repository_hint: &Path) -> Result<GitStamp, String> {
    let repository_root = absolute_git_path(
        repository_hint,
        &git_text(repository_hint, &["rev-parse", "--show-toplevel"])?,
    );
    let head_path = git_metadata_path(&repository_root, &["rev-parse", "--git-path", "HEAD"])?;
    let symbolic_ref = git_optional_text(&repository_root, &["symbolic-ref", "-q", "HEAD"])?;
    let symbolic_ref_path = symbolic_ref
        .as_deref()
        .map(|name| git_metadata_path(&repository_root, &["rev-parse", "--git-path", name]))
        .transpose()?;
    let packed_refs_candidate = git_metadata_path(
        &repository_root,
        &["rev-parse", "--git-path", "packed-refs"],
    )?;
    let packed_refs_path = packed_refs_candidate
        .is_file()
        .then_some(packed_refs_candidate);
    let ref_parent_path = symbolic_ref_path
        .as_deref()
        .and_then(|path| nearest_existing_directory(path.parent(), &repository_root));
    let commit = git_text(
        &repository_root,
        &["rev-parse", "--verify", "HEAD^{commit}"],
    )?;
    validate_commit(&commit)?;
    Ok(GitStamp {
        repository_root,
        head_path,
        symbolic_ref,
        symbolic_ref_path,
        packed_refs_path,
        ref_parent_path,
        commit,
    })
}

pub fn emit(repository_hint: &Path) {
    println!("cargo:rerun-if-changed={}", file!());
    let stamp = resolve(repository_hint)
        .unwrap_or_else(|error| panic!("git is required to stamp Nemor build provenance: {error}"));
    for path in stamp.dependency_paths() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:rustc-env=NEMOR_BUILD_GIT_HEAD={}", stamp.commit);
}

fn git_metadata_path(repository_root: &Path, arguments: &[&str]) -> Result<PathBuf, String> {
    Ok(absolute_git_path(
        repository_root,
        &git_text(repository_root, arguments)?,
    ))
}

fn absolute_git_path(command_directory: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        command_directory.join(path)
    }
}

fn nearest_existing_directory(mut candidate: Option<&Path>, floor: &Path) -> Option<PathBuf> {
    while let Some(path) = candidate {
        if path.is_dir() {
            return Some(path.to_path_buf());
        }
        if path == floor {
            break;
        }
        candidate = path.parent();
    }
    None
}

fn git_text(repository: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = git_output(repository, arguments)?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|error| format!("git output is not UTF-8: {error}"))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(format!(
            "git {} returned an empty value",
            arguments.join(" ")
        ));
    }
    Ok(value.to_owned())
}

fn git_optional_text(repository: &Path, arguments: &[&str]) -> Result<Option<String>, String> {
    let output = git_output(repository, arguments)?;
    if output.status.success() {
        let value = String::from_utf8(output.stdout)
            .map_err(|error| format!("git output is not UTF-8: {error}"))?;
        let value = value.trim();
        return if value.is_empty() {
            Err(format!(
                "git {} returned an empty value",
                arguments.join(" ")
            ))
        } else {
            Ok(Some(value.to_owned()))
        };
    }
    if output.status.code() == Some(1) {
        Ok(None)
    } else {
        Err(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn git_output(repository: &Path, arguments: &[&str]) -> Result<Output, String> {
    Command::new("/usr/bin/git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .map_err(|error| format!("cannot execute /usr/bin/git: {error}"))
}

fn validate_commit(commit: &str) -> Result<(), String> {
    if !matches!(commit.len(), 40 | 64) || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Git HEAD is not a full hexadecimal commit object ID".into());
    }
    Ok(())
}
