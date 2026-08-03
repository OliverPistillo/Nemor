use crate::StorageClass;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const STORAGE_PROFILE_VERSION: &str = "nemor-storage-profile-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageProfile {
    NvmeSsd,
    SataSsd,
    SasSsd,
    UsbSsd,
    OtherNonRotational,
    Rotational,
    Composite,
    Virtual,
    Ambiguous,
}

impl StorageProfile {
    #[must_use]
    pub fn boot_supported(self) -> bool {
        matches!(self, Self::NvmeSsd | Self::SataSsd)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDevice {
    pub name: String,
    pub class: StorageClass,
    pub rotational: Option<bool>,
    pub logical_block_size: Option<u64>,
    pub physical_block_size: Option<u64>,
    pub discard_max_bytes: Option<u64>,
    pub model: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default)]
    pub wwn: Option<String>,
    #[serde(default)]
    pub capacity_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageTopology {
    pub mount_source: String,
    pub filesystem: String,
    pub chain: Vec<String>,
    pub physical: Option<BlockDevice>,
    pub ambiguous: bool,
    #[serde(default = "default_profile_version")]
    pub profile_version: String,
    #[serde(default)]
    pub profile: Option<StorageProfile>,
    #[serde(default)]
    pub device_identity: Option<String>,
    #[serde(default)]
    pub filesystem_identity: Option<String>,
}

fn default_profile_version() -> String {
    STORAGE_PROFILE_VERSION.to_owned()
}

pub fn inspect_storage(root: &Path, mount_source: &str, filesystem: &str) -> StorageTopology {
    let mut chain = Vec::new();
    let mut current = mount_source
        .strip_prefix("/dev/")
        .unwrap_or(mount_source)
        .to_owned();
    let mut seen = BTreeSet::new();
    let mut ambiguous = false;
    let mut composite = false;
    for _ in 0..8 {
        if !valid_block_name(&current) || !seen.insert(current.clone()) {
            ambiguous = true;
            break;
        }
        chain.push(current.clone());
        let class_path = resolve(root, &format!("/sys/class/block/{current}"));
        if !class_path.exists() {
            ambiguous = true;
            break;
        }
        if let Some(parent) = partition_parent(&class_path) {
            current = parent;
            continue;
        }
        let slaves = read_names(&class_path.join("slaves"));
        match slaves.as_slice() {
            [] => break,
            [one] => current = one.clone(),
            _ => {
                chain.extend(slaves);
                ambiguous = true;
                composite = true;
                break;
            }
        }
    }
    let physical = (!ambiguous)
        .then(|| chain.last())
        .flatten()
        .and_then(|name| inspect_block(root, name));
    let profile = if composite {
        Some(StorageProfile::Composite)
    } else if ambiguous {
        Some(StorageProfile::Ambiguous)
    } else {
        physical.as_ref().map(profile_for)
    };
    let device_identity = physical.as_ref().map(|device| {
        format!(
            "{}:{}:{}:{}",
            device.name,
            device.serial.as_deref().unwrap_or("unavailable"),
            device.wwn.as_deref().unwrap_or("unavailable"),
            device.capacity_bytes.unwrap_or(0)
        )
    });
    StorageTopology {
        mount_source: mount_source.to_owned(),
        filesystem: filesystem.to_owned(),
        chain,
        physical,
        ambiguous,
        profile_version: STORAGE_PROFILE_VERSION.to_owned(),
        profile,
        device_identity,
        filesystem_identity: Some(format!("{filesystem}:{mount_source}")),
    }
}

fn inspect_block(root: &Path, name: &str) -> Option<BlockDevice> {
    let base = resolve(root, &format!("/sys/class/block/{name}"));
    let rotational = read_u64(&base.join("queue/rotational")).map(|value| value != 0);
    let subsystem_is_nvme = fs::canonicalize(base.join("device/subsystem"))
        .ok()
        .and_then(|path| path.to_str().map(str::to_owned))
        .is_some_and(|path| path.contains("/nvme"))
        || fs::read_to_string(base.join("device/subsystem"))
            .unwrap_or_default()
            .contains("nvme");
    let udev = udev_properties(root, name);
    let transport = udev
        .get("ID_BUS")
        .cloned()
        .or_else(|| read_trimmed(&base.join("device/transport")))
        .or_else(|| {
            fs::canonicalize(&base).ok().and_then(|path| {
                let text = path.to_string_lossy();
                if text.contains("/nvme/") || text.contains("/nvme") {
                    Some("nvme".to_owned())
                } else if text.contains("/ata") {
                    Some("sata".to_owned())
                } else if text.contains("/usb") {
                    Some("usb".to_owned())
                } else if text.contains("/virtual/") {
                    Some("virtual".to_owned())
                } else {
                    None
                }
            })
        });
    let class = if subsystem_is_nvme && transport.as_deref() == Some("nvme") {
        StorageClass::Nvme
    } else if rotational == Some(false) {
        StorageClass::SolidStateNonNvme
    } else if rotational == Some(true) {
        StorageClass::Rotational
    } else {
        StorageClass::Unknown
    };
    Some(BlockDevice {
        name: name.to_owned(),
        class,
        rotational,
        logical_block_size: read_u64(&base.join("queue/logical_block_size")),
        physical_block_size: read_u64(&base.join("queue/physical_block_size")),
        discard_max_bytes: read_u64(&base.join("queue/discard_max_bytes")),
        model: fs::read_to_string(base.join("device/model"))
            .ok()
            .map(|value| value.trim().chars().take(80).collect())
            .filter(|value: &String| !value.is_empty()),
        transport,
        serial: udev
            .get("ID_SERIAL_SHORT")
            .cloned()
            .or_else(|| read_trimmed(&base.join("device/serial"))),
        wwn: udev
            .get("ID_WWN")
            .cloned()
            .or_else(|| read_trimmed(&base.join("device/wwid"))),
        capacity_bytes: read_u64(&base.join("size")).map(|sectors| sectors.saturating_mul(512)),
    })
}

fn udev_properties(root: &Path, name: &str) -> std::collections::BTreeMap<String, String> {
    if root != Path::new("/") || !valid_block_name(name) {
        return std::collections::BTreeMap::new();
    }
    let Ok(output) = Command::new("/usr/bin/udevadm")
        .args([
            "info",
            "--query=property",
            "--name",
            &format!("/dev/{name}"),
        ])
        .output()
    else {
        return std::collections::BTreeMap::new();
    };
    if !output.status.success() {
        return std::collections::BTreeMap::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(key, _)| matches!(*key, "ID_BUS" | "ID_SERIAL_SHORT" | "ID_WWN"))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

fn profile_for(device: &BlockDevice) -> StorageProfile {
    if device.transport.as_deref() == Some("virtual") {
        return StorageProfile::Virtual;
    }
    if device.rotational == Some(true) {
        return StorageProfile::Rotational;
    }
    if device.rotational != Some(false) {
        return StorageProfile::Ambiguous;
    }
    match device.transport.as_deref() {
        Some("nvme") if device.class == StorageClass::Nvme => StorageProfile::NvmeSsd,
        Some("sata" | "ata") => StorageProfile::SataSsd,
        Some("sas") => StorageProfile::SasSsd,
        Some("usb") => StorageProfile::UsbSsd,
        _ => StorageProfile::OtherNonRotational,
    }
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn partition_parent(path: &Path) -> Option<String> {
    if !path.join("partition").exists() {
        return None;
    }
    path.canonicalize()
        .ok()?
        .parent()?
        .file_name()?
        .to_str()
        .map(str::to_owned)
}

fn read_names(path: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(path) else {
        return Vec::new();
    };
    let mut names: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| valid_block_name(name))
        .collect();
    names.sort();
    names
}

fn read_u64(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn resolve(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}

fn valid_block_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}
