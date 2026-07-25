#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxPaths {
    root: PathBuf,
}

impl Default for LinuxPaths {
    fn default() -> Self {
        Self::new("/")
    }
}

impl LinuxPaths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn resolve(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    pub fn machine_id(&self) -> PathBuf {
        self.resolve("/etc/machine-id")
    }

    pub fn os_release(&self) -> PathBuf {
        self.resolve("/etc/os-release")
    }

    pub fn proc_dir(&self) -> PathBuf {
        self.resolve("/proc")
    }

    pub fn meminfo(&self) -> PathBuf {
        self.resolve("/proc/meminfo")
    }

    pub fn vmstat(&self) -> PathBuf {
        self.resolve("/proc/vmstat")
    }

    pub fn proc_stat(&self) -> PathBuf {
        self.resolve("/proc/stat")
    }

    pub fn swaps(&self) -> PathBuf {
        self.resolve("/proc/swaps")
    }

    pub fn kernel_release(&self) -> PathBuf {
        self.resolve("/proc/sys/kernel/osrelease")
    }

    pub fn psi_memory(&self) -> PathBuf {
        self.resolve("/proc/pressure/memory")
    }

    pub fn psi_cpu(&self) -> PathBuf {
        self.resolve("/proc/pressure/cpu")
    }

    pub fn psi_io(&self) -> PathBuf {
        self.resolve("/proc/pressure/io")
    }

    pub fn cgroup_controllers(&self) -> PathBuf {
        self.resolve("/sys/fs/cgroup/cgroup.controllers")
    }

    pub fn zram_block_dir(&self) -> PathBuf {
        self.resolve("/sys/block")
    }

    pub fn zswap_module_dir(&self) -> PathBuf {
        self.resolve("/sys/module/zswap")
    }
}
