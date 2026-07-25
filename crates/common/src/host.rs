#![forbid(unsafe_code)]

use crate::LinuxPaths;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostMetadata {
    pub machine_id: String,
    pub hostname: String,
    pub distro: String,
    pub distro_version: Option<String>,
    pub kernel_version: String,
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<u32>,
    pub ram_total_bytes: u64,
    pub swap_total_bytes: u64,
    pub gpu_model: Option<String>,
    pub storage_model: Option<String>,
}

#[derive(Debug, Error)]
pub enum HostMetadataError {
    #[error("cannot read required host metadata `{field}` at {path}: {source}")]
    Read {
        field: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("required host metadata field `{field}` is missing or invalid: {message}")]
    Invalid {
        field: &'static str,
        message: String,
    },
}

impl HostMetadata {
    pub fn read_once(paths: &LinuxPaths) -> Result<Self, HostMetadataError> {
        let machine_id = read_required("machine_id", paths.machine_id())?;
        let os_release_text = read_required("os_release", paths.os_release())?;
        let os_release = parse_os_release(&os_release_text);
        let distro = required_map_value(&os_release, "ID", "distro")?;
        let distro_version = os_release.get("VERSION_ID").cloned();
        let kernel_version = read_required("kernel_version", paths.kernel_release())?;
        let meminfo = read_required("meminfo", paths.meminfo())?;
        let ram_total_bytes = meminfo_kib(&meminfo, "MemTotal")?;
        let swap_total_bytes = meminfo_kib(&meminfo, "SwapTotal")?;
        let hostname = hostname::get()
            .map_err(|source| HostMetadataError::Read {
                field: "hostname",
                path: PathBuf::from("<system hostname>"),
                source,
            })?
            .into_string()
            .map_err(|_| HostMetadataError::Invalid {
                field: "hostname",
                message: "hostname is not valid UTF-8".to_owned(),
            })?;
        if hostname.trim().is_empty() {
            return Err(HostMetadataError::Invalid {
                field: "hostname",
                message: "hostname is empty".to_owned(),
            });
        }
        let cpu_cores = std::thread::available_parallelism()
            .ok()
            .and_then(|count| u32::try_from(count.get()).ok());

        Ok(Self {
            machine_id,
            hostname,
            distro,
            distro_version,
            kernel_version,
            cpu_model: None,
            cpu_cores,
            ram_total_bytes,
            swap_total_bytes,
            gpu_model: None,
            storage_model: None,
        })
    }
}

fn read_required(field: &'static str, path: PathBuf) -> Result<String, HostMetadataError> {
    let value = fs::read_to_string(&path).map_err(|source| HostMetadataError::Read {
        field,
        path,
        source,
    })?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(HostMetadataError::Invalid {
            field,
            message: "value is empty".to_owned(),
        });
    }
    Ok(value)
}

fn parse_os_release(input: &str) -> HashMap<String, String> {
    input
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            let value = value.trim().trim_matches('"').trim_matches('\'');
            Some((key.trim().to_owned(), value.to_owned()))
        })
        .collect()
}

fn required_map_value(
    values: &HashMap<String, String>,
    key: &str,
    field: &'static str,
) -> Result<String, HostMetadataError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| HostMetadataError::Invalid {
            field,
            message: format!("`{key}` is absent from os-release"),
        })
}

fn meminfo_kib(input: &str, key: &'static str) -> Result<u64, HostMetadataError> {
    let value = input
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name == key).then_some(value)
        })
        .ok_or_else(|| HostMetadataError::Invalid {
            field: "meminfo",
            message: format!("`{key}` is missing"),
        })?;
    let kib = value
        .split_whitespace()
        .next()
        .ok_or_else(|| HostMetadataError::Invalid {
            field: "meminfo",
            message: format!("`{key}` has no numeric value"),
        })?
        .parse::<u64>()
        .map_err(|error| HostMetadataError::Invalid {
            field: "meminfo",
            message: format!("`{key}` is invalid: {error}"),
        })?;
    kib.checked_mul(1024)
        .ok_or_else(|| HostMetadataError::Invalid {
            field: "meminfo",
            message: format!("`{key}` overflows bytes"),
        })
}
