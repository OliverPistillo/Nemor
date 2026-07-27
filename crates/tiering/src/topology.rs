use crate::StorageClass;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDevice {
    pub name: String,
    pub class: StorageClass,
    pub rotational: Option<bool>,
    pub logical_block_size: Option<u64>,
    pub physical_block_size: Option<u64>,
    pub discard_max_bytes: Option<u64>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageTopology {
    pub mount_source: String,
    pub filesystem: String,
    pub chain: Vec<String>,
    pub physical: Option<BlockDevice>,
    pub ambiguous: bool,
}

pub fn inspect_storage(root: &Path, mount_source: &str, filesystem: &str) -> StorageTopology {
    let mut chain = Vec::new();
    let mut current = mount_source
        .strip_prefix("/dev/")
        .unwrap_or(mount_source)
        .to_owned();
    let mut seen = BTreeSet::new();
    let mut ambiguous = false;
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
                break;
            }
        }
    }
    let physical = (!ambiguous)
        .then(|| chain.last())
        .flatten()
        .and_then(|name| inspect_block(root, name));
    StorageTopology {
        mount_source: mount_source.to_owned(),
        filesystem: filesystem.to_owned(),
        chain,
        physical,
        ambiguous,
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
    let class = if name.starts_with("nvme") && subsystem_is_nvme {
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
    })
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
