use crate::{CompressionMetrics, ZramError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    SystemdGenerator,
    DistroUdev,
    Manual,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
    NemorOwned,
    Adopted,
    External,
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritableCapabilities {
    pub hot_add: bool,
    pub hot_remove: bool,
    pub algorithm: bool,
    pub disksize: bool,
    pub reset: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmStat {
    pub orig_data_size: Option<u64>,
    pub compr_data_size: Option<u64>,
    pub mem_used_total: Option<u64>,
    pub mem_limit: Option<u64>,
    pub mem_used_max: Option<u64>,
    pub same_pages: Option<u64>,
    pub pages_compacted: Option<u64>,
    pub huge_pages: Option<u64>,
    pub huge_pages_since: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInventory {
    pub name: String,
    pub sysfs_path: PathBuf,
    pub device_path: PathBuf,
    pub active_swap: bool,
    pub priority: Option<i32>,
    pub disksize: Option<u64>,
    pub initstate: Option<bool>,
    pub current_algorithm: Option<String>,
    pub available_algorithms: Vec<String>,
    pub mm_stat: MmStat,
    pub io_stat: Option<Vec<u64>>,
    pub block_stat: Option<Vec<u64>>,
    pub bd_stat: Option<Vec<u64>>,
    pub recompression_available: bool,
    pub provider: Provider,
    pub ownership: Ownership,
    pub writable: WritableCapabilities,
}

impl DeviceInventory {
    #[must_use]
    pub fn metrics(&self) -> CompressionMetrics {
        CompressionMetrics::from_mm_stat(&self.mm_stat, self.disksize)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    pub available: bool,
    pub devices: Vec<DeviceInventory>,
    pub unavailable: Vec<String>,
}

pub fn inspect_linux(root: &Path) -> Result<Inventory, ZramError> {
    let sys_block = resolve(root, "/sys/block");
    let entries = match fs::read_dir(&sys_block) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Inventory {
                available: false,
                devices: Vec::new(),
                unavailable: vec!["sys_block".to_owned()],
            });
        }
        Err(source) => {
            return Err(ZramError::Read {
                path: sys_block,
                source,
            });
        }
    };
    let swaps = parse_swaps(&fs::read_to_string(resolve(root, "/proc/swaps")).unwrap_or_default())?;
    let mut devices = Vec::new();
    let mut unavailable = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| ZramError::Read {
            path: resolve(root, "/sys/block"),
            source,
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !valid_name(&name) {
            continue;
        }
        let base = resolve(root, &format!("/sys/block/{name}"));
        let algorithms = optional_text(&base.join("comp_algorithm"))?
            .map(|value| parse_algorithms(&value))
            .transpose()?
            .unwrap_or_default();
        let current_algorithm = algorithms.0;
        let available_algorithms = algorithms.1;
        let mm_stat = optional_text(&base.join("mm_stat"))?
            .map(|value| parse_mm_stat(&value))
            .transpose()?
            .unwrap_or_default();
        let swap = swaps.get(&format!("/dev/{name}"));
        let provider = detect_provider(root, &name);
        let ownership = match provider {
            Provider::Unknown => Ownership::Unknown,
            _ => Ownership::External,
        };
        let recompression_available = base.join("recomp_algorithm").exists();
        if !recompression_available {
            unavailable.push(format!("{name}.recompression"));
        }
        devices.push(DeviceInventory {
            name: name.clone(),
            sysfs_path: PathBuf::from(format!("/sys/block/{name}")),
            device_path: PathBuf::from(format!("/dev/{name}")),
            active_swap: swap.is_some(),
            priority: swap.map(|value| value.0),
            disksize: optional_u64(&base.join("disksize"))?,
            initstate: optional_u64(&base.join("initstate"))?.map(|value| value != 0),
            current_algorithm,
            available_algorithms,
            mm_stat,
            io_stat: optional_numbers(&base.join("io_stat"))?,
            block_stat: optional_numbers(&base.join("stat"))?,
            bd_stat: optional_numbers(&base.join("bd_stat"))?,
            recompression_available,
            provider,
            ownership,
            writable: WritableCapabilities {
                hot_add: writable(&resolve(root, "/sys/class/zram-control/hot_add")),
                hot_remove: writable(&resolve(root, "/sys/class/zram-control/hot_remove")),
                algorithm: writable(&base.join("comp_algorithm")),
                disksize: writable(&base.join("disksize")),
                reset: writable(&base.join("reset")),
            },
        });
    }
    devices.sort_by(|left, right| left.name.cmp(&right.name));
    unavailable.sort();
    Ok(Inventory {
        available: !devices.is_empty(),
        devices,
        unavailable,
    })
}

fn resolve(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}

fn optional_text(path: &Path) -> Result<Option<String>, ZramError> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ZramError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn optional_u64(path: &Path) -> Result<Option<u64>, ZramError> {
    optional_text(path)?
        .map(|value| parse_u64("sysfs_u64", value.trim()))
        .transpose()
}

fn optional_numbers(path: &Path) -> Result<Option<Vec<u64>>, ZramError> {
    optional_text(path)?
        .map(|value| parse_numbers("sysfs_statistics", &value))
        .transpose()
}

pub fn parse_algorithms(input: &str) -> Result<(Option<String>, Vec<String>), ZramError> {
    let mut current = None;
    let mut available = Vec::new();
    for token in input.split_whitespace() {
        let (name, selected) = token
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .map_or((token, false), |value| (value, true));
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(parse_error("comp_algorithm", "invalid algorithm token"));
        }
        if selected && current.replace(name.to_owned()).is_some() {
            return Err(parse_error(
                "comp_algorithm",
                "multiple selected algorithms",
            ));
        }
        available.push(name.to_owned());
    }
    available.sort();
    available.dedup();
    Ok((current, available))
}

pub fn parse_mm_stat(input: &str) -> Result<MmStat, ZramError> {
    let values = parse_numbers("mm_stat", input)?;
    Ok(MmStat {
        orig_data_size: values.first().copied(),
        compr_data_size: values.get(1).copied(),
        mem_used_total: values.get(2).copied(),
        mem_limit: values.get(3).copied(),
        mem_used_max: values.get(4).copied(),
        same_pages: values.get(5).copied(),
        pages_compacted: values.get(6).copied(),
        huge_pages: values.get(7).copied(),
        huge_pages_since: values.get(8).copied(),
    })
}

fn parse_numbers(field: &'static str, input: &str) -> Result<Vec<u64>, ZramError> {
    input
        .split_whitespace()
        .map(|value| parse_u64(field, value))
        .collect()
}

fn parse_u64(field: &'static str, value: &str) -> Result<u64, ZramError> {
    value
        .parse::<u64>()
        .map_err(|error| parse_error(field, error.to_string()))
}

fn parse_swaps(input: &str) -> Result<BTreeMap<String, (i32, u64, u64)>, ZramError> {
    let mut swaps = BTreeMap::new();
    for (index, line) in input.lines().enumerate() {
        if index == 0 || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(parse_error("proc_swaps", "expected five columns"));
        }
        let size = parse_u64("proc_swaps", fields[2])?
            .checked_mul(1024)
            .ok_or_else(|| parse_error("proc_swaps", "size overflow"))?;
        let used = parse_u64("proc_swaps", fields[3])?
            .checked_mul(1024)
            .ok_or_else(|| parse_error("proc_swaps", "used overflow"))?;
        let priority = fields[4]
            .parse::<i32>()
            .map_err(|error| parse_error("proc_swaps", error.to_string()))?;
        swaps.insert(fields[0].to_owned(), (priority, size, used));
    }
    Ok(swaps)
}

fn detect_provider(root: &Path, name: &str) -> Provider {
    let unit = format!("systemd-zram-setup@{name}.service");
    let swap_unit = format!("dev-{name}.swap");
    if resolve(root, &format!("/run/systemd/generator/{unit}")).exists()
        || resolve(root, &format!("/run/systemd/system/{unit}")).exists()
        || resolve(root, &format!("/run/systemd/generator/{swap_unit}")).exists()
        || resolve(
            root,
            &format!("/run/systemd/generator/systemd-zram-setup@{name}.service.d"),
        )
        .exists()
    {
        Provider::SystemdGenerator
    } else if root == Path::new("/") {
        Provider::Unknown
    } else if resolve(root, "/run/udev").exists() {
        Provider::DistroUdev
    } else {
        Provider::Manual
    }
}

fn writable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        let Ok(metadata) = fs::metadata(path) else {
            return false;
        };
        let Some(effective_uid) = effective_uid() else {
            return false;
        };
        let mode = metadata.permissions().mode();
        (effective_uid == metadata.uid() && mode & 0o200 != 0)
            || (effective_uid != metadata.uid() && mode & 0o002 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

#[cfg(unix)]
fn effective_uid() -> Option<u32> {
    fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn valid_name(name: &str) -> bool {
    name.strip_prefix("zram").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn parse_error(field: &'static str, message: impl Into<String>) -> ZramError {
    ZramError::Parse {
        field,
        message: message.into(),
    }
}
