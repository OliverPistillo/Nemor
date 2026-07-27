use crate::{inspect_linux, DeviceInventory, Inventory, Ownership, ZramError};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub trait ZramBackend {
    fn inspect(&self) -> Result<Inventory, ZramError>;
    fn create_isolated_managed_device(&mut self) -> Result<DeviceInventory, ZramError>;
    fn configure_uninitialized(&mut self, name: &str, algorithm: &str) -> Result<(), ZramError>;
    fn initialize(&mut self, name: &str, disksize: u64) -> Result<(), ZramError>;
    fn activate(&mut self, name: &str, priority: i32) -> Result<(), ZramError>;
    fn deactivate(&mut self, name: &str) -> Result<(), ZramError>;
    fn verify(&self, name: &str) -> Result<DeviceInventory, ZramError>;
    fn reset_managed_device(&mut self, name: &str) -> Result<(), ZramError>;
    fn remove_managed_device(&mut self, name: &str) -> Result<(), ZramError>;
    fn effective_valid_swap_capacity(&self) -> Result<u64, ZramError>;
    fn is_owned(&self, name: &str) -> bool;
}

pub struct LinuxZramBackend {
    root: PathBuf,
    owned: BTreeSet<String>,
    command_timeout: Duration,
}

impl Default for LinuxZramBackend {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
            owned: BTreeSet::new(),
            command_timeout: Duration::from_secs(10),
        }
    }
}

impl LinuxZramBackend {
    #[must_use]
    pub fn rooted_at(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            owned: BTreeSet::new(),
            command_timeout: Duration::from_secs(10),
        }
    }

    /// Re-registers a hot-added device after a validation worker restart.
    ///
    /// The caller must supply the device names captured before the original
    /// hot-add. Existing devices and zram0 are never eligible.
    pub fn resume_isolated_managed_device(
        &mut self,
        name: &str,
        baseline_names: &BTreeSet<String>,
    ) -> Result<DeviceInventory, ZramError> {
        if !valid_name(name) || name == "zram0" || baseline_names.contains(name) {
            return Err(ZramError::Blocked(
                "recovery device was present at baseline or is protected".to_owned(),
            ));
        }
        if !self
            .path(&format!("/sys/block/{name}"))
            .canonicalize()
            .is_ok_and(|path| path.ends_with(format!("block/{name}")))
        {
            return Err(ZramError::Blocked(
                "recovery device is not a live canonical zram device".to_owned(),
            ));
        }
        self.owned.insert(name.to_owned());
        self.verify(name)
    }

    fn path(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    fn require_owned(&self, name: &str) -> Result<(), ZramError> {
        if valid_name(name) && self.owned.contains(name) {
            Ok(())
        } else {
            Err(ZramError::Blocked(
                "device is not registered as Nemor-owned".to_owned(),
            ))
        }
    }

    fn write_owned(&self, name: &str, field: &str, value: &str) -> Result<(), ZramError> {
        self.require_owned(name)?;
        if !matches!(field, "comp_algorithm" | "disksize" | "reset") {
            return Err(ZramError::Blocked(
                "sysfs property is not allow-listed".to_owned(),
            ));
        }
        fs::write(
            self.path(&format!("/sys/block/{name}/{field}")),
            value.as_bytes(),
        )
        .map_err(|error| ZramError::Backend {
            operation: "sysfs_write",
            message: error.to_string(),
        })
    }

    fn command(
        &self,
        executable: &'static str,
        device: &Path,
        extra: &[String],
    ) -> Result<(), ZramError> {
        let allowed = ["/usr/bin/mkswap", "/usr/bin/swapon", "/usr/bin/swapoff"];
        if !allowed.contains(&executable) {
            return Err(ZramError::Blocked(
                "helper executable is not allow-listed".to_owned(),
            ));
        }
        let name = device
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| ZramError::Blocked("invalid device path".to_owned()))?;
        self.require_owned(name)?;
        if device != Path::new(&format!("/dev/{name}")) {
            return Err(ZramError::Blocked(
                "device path is not canonical zram".to_owned(),
            ));
        }
        let deadline = Instant::now() + self.command_timeout;
        while !device.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if !device.exists() {
            return Err(ZramError::Backend {
                operation: "wait_for_device_node",
                message: format!("{} did not appear", device.display()),
            });
        }
        let mut child = Command::new(executable)
            .args(extra)
            .arg(device)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| ZramError::Backend {
                operation: "spawn_allowlisted_helper",
                message: error.to_string(),
            })?;
        let deadline = Instant::now() + self.command_timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => {
                    return Err(ZramError::Backend {
                        operation: "allowlisted_helper",
                        message: format!("{executable} exited with {status}"),
                    });
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ZramError::Backend {
                        operation: "allowlisted_helper_timeout",
                        message: format!("{executable} exceeded timeout"),
                    });
                }
                Err(error) => {
                    return Err(ZramError::Backend {
                        operation: "wait_allowlisted_helper",
                        message: error.to_string(),
                    });
                }
            }
        }
    }
}

impl ZramBackend for LinuxZramBackend {
    fn inspect(&self) -> Result<Inventory, ZramError> {
        let mut inventory = inspect_linux(&self.root)?;
        for device in &mut inventory.devices {
            if self.owned.contains(&device.name) {
                device.ownership = Ownership::NemorOwned;
            }
        }
        Ok(inventory)
    }

    fn create_isolated_managed_device(&mut self) -> Result<DeviceInventory, ZramError> {
        let hot_add = self.path("/sys/class/zram-control/hot_add");
        let index = fs::read_to_string(&hot_add)
            .map_err(|error| ZramError::Backend {
                operation: "hot_add",
                message: error.to_string(),
            })?
            .trim()
            .parse::<u32>()
            .map_err(|error| ZramError::Backend {
                operation: "parse_hot_add_result",
                message: error.to_string(),
            })?;
        let name = format!("zram{index}");
        self.owned.insert(name.clone());
        self.verify(&name)
    }

    fn configure_uninitialized(&mut self, name: &str, algorithm: &str) -> Result<(), ZramError> {
        let device = self.verify(name)?;
        if device.initstate == Some(true) {
            return Err(ZramError::Blocked(
                "algorithm must be configured before initialization".to_owned(),
            ));
        }
        if !device.available_algorithms.contains(&algorithm.to_owned()) {
            return Err(ZramError::Blocked("algorithm is unavailable".to_owned()));
        }
        self.write_owned(name, "comp_algorithm", algorithm)
    }

    fn initialize(&mut self, name: &str, disksize: u64) -> Result<(), ZramError> {
        if disksize == 0 {
            return Err(ZramError::Blocked(
                "disksize must be greater than zero".to_owned(),
            ));
        }
        self.write_owned(name, "disksize", &disksize.to_string())
    }

    fn activate(&mut self, name: &str, priority: i32) -> Result<(), ZramError> {
        self.require_owned(name)?;
        let device = PathBuf::from(format!("/dev/{name}"));
        self.command("/usr/bin/mkswap", &device, &[])?;
        self.command(
            "/usr/bin/swapon",
            &device,
            &["--priority".to_owned(), priority.to_string()],
        )
    }

    fn deactivate(&mut self, name: &str) -> Result<(), ZramError> {
        self.require_owned(name)?;
        self.command("/usr/bin/swapoff", Path::new(&format!("/dev/{name}")), &[])
    }

    fn verify(&self, name: &str) -> Result<DeviceInventory, ZramError> {
        if !valid_name(name) {
            return Err(ZramError::Blocked("invalid zram device name".to_owned()));
        }
        self.inspect()?
            .devices
            .into_iter()
            .find(|device| device.name == name)
            .ok_or_else(|| ZramError::Verification(format!("{name} is absent")))
    }

    fn reset_managed_device(&mut self, name: &str) -> Result<(), ZramError> {
        let device = self.verify(name)?;
        if device.active_swap {
            return Err(ZramError::Blocked("never reset active swap".to_owned()));
        }
        self.require_owned(name)?;
        let path = self.path(&format!("/sys/block/{name}/reset"));
        let deadline = Instant::now() + self.command_timeout;
        loop {
            match fs::write(&path, b"1") {
                Ok(()) => return Ok(()),
                Err(error) if error.raw_os_error() == Some(16) && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(error) => {
                    return Err(ZramError::Backend {
                        operation: "reset",
                        message: error.to_string(),
                    })
                }
            }
        }
    }

    fn remove_managed_device(&mut self, name: &str) -> Result<(), ZramError> {
        let device = self.verify(name)?;
        if device.active_swap {
            return Err(ZramError::Blocked("never remove active swap".to_owned()));
        }
        self.reset_managed_device(name)?;
        let suffix = name
            .strip_prefix("zram")
            .ok_or_else(|| ZramError::Blocked("invalid zram name".to_owned()))?;
        fs::write(
            self.path("/sys/class/zram-control/hot_remove"),
            suffix.as_bytes(),
        )
        .map_err(|error| ZramError::Backend {
            operation: "hot_remove",
            message: error.to_string(),
        })?;
        self.owned.remove(name);
        Ok(())
    }

    fn effective_valid_swap_capacity(&self) -> Result<u64, ZramError> {
        self.inspect()?
            .devices
            .into_iter()
            .try_fold(0_u64, |total, device| {
                if device.active_swap {
                    total
                        .checked_add(device.disksize.unwrap_or(0))
                        .ok_or_else(|| ZramError::Verification("swap capacity overflow".to_owned()))
                } else {
                    Ok(total)
                }
            })
    }

    fn is_owned(&self, name: &str) -> bool {
        self.owned.contains(name)
    }
}

fn valid_name(name: &str) -> bool {
    name.strip_prefix("zram").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}
