use crate::{FilesystemKind, SwapfilePlan};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("tiering mutation blocked: {0}")]
    Blocked(String),
    #[error("tiering operation `{operation}` failed: {message}")]
    Operation {
        operation: &'static str,
        message: String,
    },
    #[error("tiering verification failed: {0}")]
    Verification(String),
}

pub trait SwapfileBackend {
    fn active_swaps(&self) -> Result<BTreeSet<PathBuf>, BackendError>;
    fn create_owned(
        &mut self,
        path: &Path,
        filesystem: FilesystemKind,
        size: u64,
    ) -> Result<(), BackendError>;
    fn activate_owned(&mut self, path: &Path, priority: i32) -> Result<(), BackendError>;
    fn deactivate_owned(&mut self, path: &Path) -> Result<(), BackendError>;
    fn remove_owned(&mut self, path: &Path) -> Result<(), BackendError>;
    fn is_owned(&self, path: &Path) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationSnapshot {
    pub path: PathBuf,
    pub baseline_swaps: BTreeSet<PathBuf>,
    pub created: bool,
    pub activated: bool,
    pub rollback_pending: bool,
    pub rolled_back: bool,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionOutcome {
    pub created: bool,
    pub activated: bool,
    pub verified: bool,
    pub rolled_back: bool,
}

pub fn apply_swapfile<B: SwapfileBackend>(
    backend: &mut B,
    plan: &SwapfilePlan,
    snapshot: &mut MutationSnapshot,
) -> Result<TransactionOutcome, BackendError> {
    if plan.dry_run {
        return Ok(TransactionOutcome {
            created: false,
            activated: false,
            verified: false,
            rolled_back: false,
        });
    }
    if !plan.allowed {
        return Err(BackendError::Blocked(plan.blocked_reasons.join(",")));
    }
    let result = (|| {
        backend.create_owned(&plan.path, plan.filesystem, plan.proposed_size)?;
        snapshot.created = true;
        snapshot.rollback_pending = true;
        backend.activate_owned(&plan.path, plan.priority)?;
        snapshot.activated = true;
        let active = backend.active_swaps()?;
        if !active.contains(&plan.path) {
            return Err(BackendError::Verification(
                "owned swapfile is not active".to_owned(),
            ));
        }
        if !snapshot.baseline_swaps.is_empty()
            && !snapshot
                .baseline_swaps
                .iter()
                .any(|path| active.contains(path))
        {
            return Err(BackendError::Verification(
                "no-swap-loss invariant violated".to_owned(),
            ));
        }
        Ok(TransactionOutcome {
            created: true,
            activated: true,
            verified: true,
            rolled_back: false,
        })
    })();
    if let Err(error) = &result {
        snapshot.last_error = Some(error.to_string());
        let _ = rollback_swapfile(backend, snapshot);
    }
    result
}

pub fn rollback_swapfile<B: SwapfileBackend>(
    backend: &mut B,
    snapshot: &mut MutationSnapshot,
) -> Result<TransactionOutcome, BackendError> {
    if snapshot.rolled_back {
        return Ok(TransactionOutcome {
            created: false,
            activated: false,
            verified: true,
            rolled_back: true,
        });
    }
    if !backend.is_owned(&snapshot.path) && (snapshot.created || snapshot.activated) {
        return Err(BackendError::Blocked(
            "rollback ownership is ambiguous".to_owned(),
        ));
    }
    if snapshot.activated && backend.active_swaps()?.contains(&snapshot.path) {
        backend.deactivate_owned(&snapshot.path)?;
        let active = backend.active_swaps()?;
        if !snapshot.baseline_swaps.is_empty()
            && !snapshot
                .baseline_swaps
                .iter()
                .any(|path| active.contains(path))
        {
            return Err(BackendError::Verification(
                "rollback would lose all baseline swap".to_owned(),
            ));
        }
    }
    if snapshot.created {
        backend.remove_owned(&snapshot.path)?;
    }
    snapshot.rollback_pending = false;
    snapshot.rolled_back = true;
    Ok(TransactionOutcome {
        created: false,
        activated: false,
        verified: true,
        rolled_back: true,
    })
}

pub struct LinuxSwapfileBackend {
    owned: BTreeSet<PathBuf>,
    timeout: Duration,
}

impl Default for LinuxSwapfileBackend {
    fn default() -> Self {
        Self {
            owned: BTreeSet::new(),
            timeout: Duration::from_secs(15),
        }
    }
}

impl LinuxSwapfileBackend {
    pub fn resume_owned(&mut self, path: &Path) -> Result<(), BackendError> {
        Self::require_path(path)?;
        let metadata = fs::symlink_metadata(path).map_err(|error| BackendError::Operation {
            operation: "inspect_owned_swapfile",
            message: error.to_string(),
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(BackendError::Blocked(
                "persisted swapfile ownership or permissions are invalid".to_owned(),
            ));
        }
        self.owned.insert(path.to_path_buf());
        Ok(())
    }

    fn require_path(path: &Path) -> Result<(), BackendError> {
        let value = path
            .to_str()
            .ok_or_else(|| BackendError::Blocked("swapfile path is not UTF-8".to_owned()))?;
        let validation = value.starts_with("/var/tmp/nemor-validation-tiering-")
            && value.ends_with(".swap")
            && !value["/var/tmp/".len()..].contains('/');
        let production = value == "/var/lib/nemor/swap/nemor-tiering.swap";
        if (validation || production)
            && path.is_absolute()
            && !path
                .components()
                .any(|item| matches!(item, std::path::Component::ParentDir))
        {
            Ok(())
        } else {
            Err(BackendError::Blocked(
                "path is outside the closed Nemor swapfile namespace".to_owned(),
            ))
        }
    }

    fn helper(&self, executable: &'static str, args: &[String]) -> Result<(), BackendError> {
        let allowed = [
            "/usr/bin/btrfs",
            "/usr/bin/fallocate",
            "/usr/bin/chmod",
            "/usr/bin/mkswap",
            "/usr/bin/swapon",
            "/usr/bin/swapoff",
        ];
        if !allowed.contains(&executable) {
            return Err(BackendError::Blocked(
                "helper is outside the executable allow-list".to_owned(),
            ));
        }
        let mut child = Command::new(executable)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| BackendError::Operation {
                operation: "spawn_helper",
                message: error.to_string(),
            })?;
        let deadline = Instant::now() + self.timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => {
                    return Err(BackendError::Operation {
                        operation: "helper",
                        message: format!("{executable} exited with {status}"),
                    })
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(BackendError::Operation {
                        operation: "helper_timeout",
                        message: executable.to_owned(),
                    });
                }
                Err(error) => {
                    return Err(BackendError::Operation {
                        operation: "wait_helper",
                        message: error.to_string(),
                    })
                }
            }
        }
    }
}

impl SwapfileBackend for LinuxSwapfileBackend {
    fn active_swaps(&self) -> Result<BTreeSet<PathBuf>, BackendError> {
        let text = fs::read_to_string("/proc/swaps").map_err(|error| BackendError::Operation {
            operation: "read_proc_swaps",
            message: error.to_string(),
        })?;
        Ok(text
            .lines()
            .skip(1)
            .filter_map(|line| line.split_whitespace().next())
            .map(PathBuf::from)
            .collect())
    }

    fn create_owned(
        &mut self,
        path: &Path,
        filesystem: FilesystemKind,
        size: u64,
    ) -> Result<(), BackendError> {
        Self::require_path(path)?;
        if path.exists() {
            return Err(BackendError::Blocked(
                "refusing to adopt an existing swapfile".to_owned(),
            ));
        }
        let path_text = path.display().to_string();
        let result = match filesystem {
            FilesystemKind::Btrfs => self.helper(
                "/usr/bin/btrfs",
                &[
                    "filesystem".to_owned(),
                    "mkswapfile".to_owned(),
                    "--size".to_owned(),
                    size.to_string(),
                    path_text,
                ],
            ),
            FilesystemKind::Ext4 => {
                self.helper(
                    "/usr/bin/fallocate",
                    &["--length".to_owned(), size.to_string(), path_text.clone()],
                )?;
                self.helper("/usr/bin/chmod", &["0600".to_owned(), path_text.clone()])?;
                self.helper("/usr/bin/mkswap", &[path_text])
            }
            FilesystemKind::Unsupported => {
                return Err(BackendError::Blocked("unsupported filesystem".to_owned()))
            }
        };
        if let Err(error) = result {
            if path.exists() {
                let _ = fs::remove_file(path);
            }
            return Err(error);
        }
        self.owned.insert(path.to_path_buf());
        Ok(())
    }

    fn activate_owned(&mut self, path: &Path, priority: i32) -> Result<(), BackendError> {
        Self::require_path(path)?;
        if !self.owned.contains(path) {
            return Err(BackendError::Blocked("swapfile is not owned".to_owned()));
        }
        self.helper(
            "/usr/bin/swapon",
            &[
                "--priority".to_owned(),
                priority.to_string(),
                path.display().to_string(),
            ],
        )
    }

    fn deactivate_owned(&mut self, path: &Path) -> Result<(), BackendError> {
        Self::require_path(path)?;
        if !self.owned.contains(path) {
            return Err(BackendError::Blocked("swapfile is not owned".to_owned()));
        }
        self.helper("/usr/bin/swapoff", &[path.display().to_string()])
    }

    fn remove_owned(&mut self, path: &Path) -> Result<(), BackendError> {
        Self::require_path(path)?;
        if !self.owned.remove(path) {
            return Err(BackendError::Blocked("swapfile is not owned".to_owned()));
        }
        fs::remove_file(path).map_err(|error| BackendError::Operation {
            operation: "remove_owned_swapfile",
            message: error.to_string(),
        })
    }

    fn is_owned(&self, path: &Path) -> bool {
        self.owned.contains(path)
    }
}
