use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZswapParameters {
    pub enabled: Option<bool>,
    pub compressor: Option<String>,
    pub zpool: Option<String>,
    pub max_pool_percent: Option<u8>,
    pub accept_threshold_percent: Option<u8>,
    pub shrinker_enabled: Option<bool>,
    pub same_filled_pages_enabled: Option<bool>,
    pub non_same_filled_pages_enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugCounter {
    pub name: String,
    pub value: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderState {
    pub kernel_cmdline_zswap: Vec<String>,
    pub systemd_zram: bool,
    pub zram_generator_vendor_config: bool,
    pub zram_generator_etc_config: bool,
    pub cachyos_zswap_disable_rule: bool,
    pub persistence_sources: Vec<PathBuf>,
    pub conflict: bool,
    pub bootloader: Option<String>,
    #[serde(default)]
    pub command_line_source: Option<PathBuf>,
    #[serde(default)]
    pub systemd_boot: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZswapInventory {
    pub supported: bool,
    pub parameters: ZswapParameters,
    pub parameter_writable: BTreeMap<String, bool>,
    pub debugfs_available: bool,
    pub debug_counters: Vec<DebugCounter>,
    pub cgroup_values: BTreeMap<String, String>,
    pub provider: ProviderState,
    pub unavailable: Vec<String>,
    pub dry_run: bool,
}

pub fn inspect_linux(root: &Path, dry_run: bool) -> Result<ZswapInventory, std::io::Error> {
    let parameters_root = resolve(root, "/sys/module/zswap/parameters");
    let supported = parameters_root.is_dir();
    let mut unavailable = Vec::new();
    let mut writable = BTreeMap::new();
    for name in [
        "enabled",
        "compressor",
        "zpool",
        "max_pool_percent",
        "accept_threshold_percent",
        "shrinker_enabled",
        "same_filled_pages_enabled",
        "non_same_filled_pages_enabled",
    ] {
        let path = parameters_root.join(name);
        writable.insert(name.to_owned(), is_writable(&path));
        if !path.exists() {
            unavailable.push(format!("zswap.parameters.{name}"));
        }
    }
    let parameters = ZswapParameters {
        enabled: optional_bool(&parameters_root.join("enabled"))?,
        compressor: optional_string(&parameters_root.join("compressor"))?,
        zpool: optional_string(&parameters_root.join("zpool"))?,
        max_pool_percent: optional_u8(&parameters_root.join("max_pool_percent"))?,
        accept_threshold_percent: optional_u8(&parameters_root.join("accept_threshold_percent"))?,
        shrinker_enabled: optional_bool(&parameters_root.join("shrinker_enabled"))?,
        same_filled_pages_enabled: optional_bool(
            &parameters_root.join("same_filled_pages_enabled"),
        )?,
        non_same_filled_pages_enabled: optional_bool(
            &parameters_root.join("non_same_filled_pages_enabled"),
        )?,
    };
    let debug_root = resolve(root, "/sys/kernel/debug/zswap");
    let debugfs_available = debug_root.is_dir();
    let mut debug_counters = Vec::new();
    if debugfs_available {
        for entry in fs::read_dir(&debug_root)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let value = fs::read_to_string(entry.path())
                    .ok()
                    .and_then(|value| value.trim().parse().ok());
                debug_counters.push(DebugCounter { name, value });
            }
        }
        debug_counters.sort_by(|left, right| left.name.cmp(&right.name));
    } else {
        unavailable.push("zswap.debugfs".to_owned());
    }
    let mut cgroup_values = BTreeMap::new();
    for name in [
        "memory.zswap.current",
        "memory.zswap.max",
        "memory.zswap.writeback",
        "memory.swap.current",
        "memory.swap.peak",
        "memory.swap.events",
    ] {
        if let Ok(value) = fs::read_to_string(resolve(root, &format!("/sys/fs/cgroup/{name}"))) {
            cgroup_values.insert(name.to_owned(), value.trim().to_owned());
        }
    }
    unavailable.sort();
    Ok(ZswapInventory {
        supported,
        parameters,
        parameter_writable: writable,
        debugfs_available,
        debug_counters,
        cgroup_values,
        provider: inspect_provider(root),
        unavailable,
        dry_run,
    })
}

fn inspect_provider(root: &Path) -> ProviderState {
    let cmdline = fs::read_to_string(resolve(root, "/proc/cmdline")).unwrap_or_default();
    let kernel_cmdline_zswap: Vec<_> = cmdline
        .split_whitespace()
        .filter(|value| value.starts_with("zswap."))
        .map(str::to_owned)
        .collect();
    let vendor = resolve(root, "/usr/lib/systemd/zram-generator.conf");
    let etc = resolve(root, "/etc/systemd/zram-generator.conf");
    let vendor_rule = resolve(root, "/usr/lib/udev/rules.d/30-zram.rules");
    let rule_text = fs::read_to_string(&vendor_rule).unwrap_or_default();
    let systemd_zram = resolve(root, "/run/systemd/generator/dev-zram0.swap").exists()
        || vendor.exists()
        || etc.exists();
    let cachyos_zswap_disable_rule = rule_text.contains("/sys/module/zswap/parameters/enabled");
    let mut persistence_sources = [
        "/etc/kernel/cmdline",
        "/etc/default/grub",
        "/boot/loader/loader.conf",
        "/etc/systemd/zram-generator.conf",
        "/etc/udev/rules.d/30-zram.rules",
    ]
    .into_iter()
    .map(|path| resolve(root, path))
    .filter(|path| path.exists())
    .collect::<Vec<_>>();
    persistence_sources.sort();
    let kernel_cmdline_path = resolve(root, "/etc/kernel/cmdline");
    let systemd_boot = resolve(root, "/boot/loader/loader.conf").exists()
        || resolve(
            root,
            "/sys/firmware/efi/efivars/LoaderInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f",
        )
        .exists();
    let bootloader = if kernel_cmdline_path.exists() && systemd_boot {
        Some("systemd-boot/kernel-install-uki".to_owned())
    } else if kernel_cmdline_path.exists() {
        Some("kernel-install/uki".to_owned())
    } else if resolve(root, "/etc/default/grub").exists() {
        Some("grub".to_owned())
    } else if resolve(root, "/boot/loader/loader.conf").exists() {
        Some("systemd-boot".to_owned())
    } else {
        None
    };
    let cmdline_disabled = kernel_cmdline_zswap
        .iter()
        .any(|value| matches!(value.as_str(), "zswap.enabled=0" | "zswap.enabled=N"));
    ProviderState {
        kernel_cmdline_zswap,
        systemd_zram,
        zram_generator_vendor_config: vendor.exists(),
        zram_generator_etc_config: etc.exists(),
        cachyos_zswap_disable_rule,
        persistence_sources,
        conflict: systemd_zram && (cmdline_disabled || cachyos_zswap_disable_rule),
        bootloader,
        command_line_source: kernel_cmdline_path.exists().then_some(kernel_cmdline_path),
        systemd_boot,
    }
}

fn optional_string(path: &Path) -> Result<Option<String>, std::io::Error> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(Some(value.trim().to_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn optional_bool(path: &Path) -> Result<Option<bool>, std::io::Error> {
    optional_string(path).map(|value| {
        value.and_then(|value| match value.as_str() {
            "Y" | "1" | "y" => Some(true),
            "N" | "0" | "n" => Some(false),
            _ => None,
        })
    })
}

fn optional_u8(path: &Path) -> Result<Option<u8>, std::io::Error> {
    optional_string(path).map(|value| value.and_then(|value| value.parse().ok()))
}

fn resolve(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}

fn is_writable(path: &Path) -> bool {
    fs::OpenOptions::new().write(true).open(path).is_ok()
}
