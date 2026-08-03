use crate::{StorageClass, StorageTopology};
use common::TieringConfig;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemKind {
    Ext4,
    Btrfs,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapfileOwnership {
    NemorOwned,
    Adopted,
    External,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct SwapfileContext<'a> {
    pub path: &'a Path,
    pub parent_canonical: &'a Path,
    pub mountpoint: &'a Path,
    pub filesystem: FilesystemKind,
    pub topology: StorageTopology,
    pub total_ram_bytes: u64,
    pub zram_size_bytes: u64,
    pub free_bytes: u64,
    pub filesystem_size_bytes: u64,
    pub capacity_target_bytes: u64,
    pub btrfs_nocow: bool,
    pub btrfs_preallocated: bool,
    pub has_holes: bool,
    pub active_external: bool,
    pub ownership: SwapfileOwnership,
    pub gaming: bool,
    pub severe_pressure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapfilePlan {
    pub path: PathBuf,
    pub mountpoint: PathBuf,
    pub filesystem: FilesystemKind,
    pub backing_device: String,
    pub physical_device_class: StorageClass,
    pub proposed_size: u64,
    pub priority: i32,
    pub free_bytes: u64,
    pub required_headroom_bytes: u64,
    pub ownership: SwapfileOwnership,
    pub create_required: bool,
    pub format_required: bool,
    pub activate_required: bool,
    pub persistence_requested: bool,
    pub allowed: bool,
    pub blocked_reasons: Vec<String>,
    pub dry_run: bool,
}

pub fn validate_candidate_path(path: &Path, parent_canonical: &Path) -> Result<(), &'static str> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err("swapfile path must be absolute and normalized");
    }
    if path.file_name().and_then(|name| name.to_str()) != Some("nemor-tiering.swap") {
        return Err("swapfile name is outside the Nemor-owned namespace");
    }
    let parent = path.parent().ok_or("swapfile parent is missing")?;
    if parent != parent_canonical || !parent_canonical.is_absolute() {
        return Err("swapfile parent canonicalization mismatch");
    }
    Ok(())
}

#[must_use]
pub fn plan_swapfile(context: &SwapfileContext<'_>, config: &TieringConfig) -> SwapfilePlan {
    let mut blocked = Vec::new();
    if let Err(error) = validate_candidate_path(context.path, context.parent_canonical) {
        blocked.push(error.to_owned());
    }
    if context.active_external {
        blocked.push("candidate_is_external_active_swap".to_owned());
    }
    if context.ownership != SwapfileOwnership::NemorOwned {
        blocked.push("swapfile_not_nemor_owned".to_owned());
    }
    match context.filesystem {
        FilesystemKind::Ext4 => {
            if context.has_holes {
                blocked.push("ext4_swapfile_has_holes".to_owned());
            }
        }
        FilesystemKind::Btrfs => {
            if !context.btrfs_nocow {
                blocked.push("btrfs_swapfile_requires_nocow".to_owned());
            }
            if !context.btrfs_preallocated || context.has_holes {
                blocked.push("btrfs_swapfile_requires_valid_preallocation".to_owned());
            }
        }
        FilesystemKind::Unsupported => blocked.push("unsupported_filesystem".to_owned()),
    }
    if context.topology.ambiguous || context.topology.physical.is_none() {
        blocked.push("backing_storage_ambiguous".to_owned());
    }
    let class = context
        .topology
        .physical
        .as_ref()
        .map_or(StorageClass::Unknown, |device| device.class);
    let profile_name = context
        .topology
        .profile
        .and_then(|profile| serde_json::to_value(profile).ok())
        .and_then(|value| value.as_str().map(str::to_owned));
    if profile_name.as_ref().is_none_or(|profile| {
        !config
            .supported_storage_profiles
            .iter()
            .any(|allowed| allowed == profile)
    }) {
        blocked.push("storage_profile_not_authorized".to_owned());
    }
    if context.gaming {
        blocked.push("gaming_defers_structural_io".to_owned());
    }
    if context.severe_pressure {
        blocked.push("severe_pressure_blocks_reconfiguration".to_owned());
    }
    if !config.allow_swapfile_create {
        blocked.push("swapfile_creation_disabled".to_owned());
    }
    let percent_limit = context
        .filesystem_size_bytes
        .saturating_mul(u64::from(config.max_swapfile_percent_disk))
        / 100;
    let proposed_size = context
        .capacity_target_bytes
        .max(context.total_ram_bytes / 4)
        .min(context.total_ram_bytes.saturating_mul(2))
        .min(percent_limit);
    let headroom = config.min_free_disk_gib.saturating_mul(1_073_741_824);
    if context.free_bytes < proposed_size.saturating_add(headroom) {
        blocked.push("insufficient_disk_headroom".to_owned());
    }
    SwapfilePlan {
        path: context.path.to_path_buf(),
        mountpoint: context.mountpoint.to_path_buf(),
        filesystem: context.filesystem,
        backing_device: context.topology.mount_source.clone(),
        physical_device_class: class,
        proposed_size,
        priority: 10,
        free_bytes: context.free_bytes,
        required_headroom_bytes: headroom,
        ownership: context.ownership,
        create_required: true,
        format_required: true,
        activate_required: true,
        persistence_requested: config.allow_persistent_reconfigure,
        allowed: blocked.is_empty(),
        blocked_reasons: blocked,
        dry_run: config.dry_run,
    }
}
