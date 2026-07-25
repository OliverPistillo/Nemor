use crate::source::read_optional;
use crate::{CollectorError, TelemetrySource};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZramDevice {
    pub name: String,
    pub disk_size_bytes: Option<u64>,
    pub algorithm: Option<String>,
    pub original_data_bytes: Option<u64>,
    pub compressed_data_bytes: Option<u64>,
    pub memory_used_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZramState {
    pub available: bool,
    pub devices: Vec<ZramDevice>,
}

pub fn collect(source: &dyn TelemetrySource) -> Result<ZramState, CollectorError> {
    let names = match source.read_dir_names("/sys/block") {
        Ok(names) => names,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ZramState {
                available: false,
                devices: Vec::new(),
            });
        }
        Err(error) => {
            return Err(CollectorError::RequiredRead {
                metric: "zram",
                path: "/sys/block".to_owned(),
                source: error,
            });
        }
    };
    let mut devices = Vec::new();
    for name in names.into_iter().filter(|name| name.starts_with("zram")) {
        let base = format!("/sys/block/{name}");
        let disk_size_bytes = optional_u64(source, &format!("{base}/disksize"))?;
        let algorithm = read_optional(source, &format!("{base}/comp_algorithm"))
            .map_err(|source| CollectorError::RequiredRead {
                metric: "zram",
                path: format!("{base}/comp_algorithm"),
                source,
            })?
            .and_then(|value| current_algorithm(&value));
        let mm_stat = match read_optional(source, &format!("{base}/mm_stat")).map_err(|source| {
            CollectorError::RequiredRead {
                metric: "zram",
                path: format!("{base}/mm_stat"),
                source,
            }
        })? {
            Some(value) => parse_mm_stat(&value)?,
            None => MmStat::default(),
        };
        devices.push(ZramDevice {
            name,
            disk_size_bytes,
            algorithm,
            original_data_bytes: mm_stat.original_data_bytes,
            compressed_data_bytes: mm_stat.compressed_data_bytes,
            memory_used_bytes: mm_stat.memory_used_bytes,
        });
    }
    Ok(ZramState {
        available: !devices.is_empty(),
        devices,
    })
}

fn optional_u64(source: &dyn TelemetrySource, path: &str) -> Result<Option<u64>, CollectorError> {
    read_optional(source, path)
        .map_err(|source| CollectorError::RequiredRead {
            metric: "zram",
            path: path.to_owned(),
            source,
        })?
        .map(|value| {
            value.trim().parse::<u64>().map_err(|error| {
                CollectorError::invalid("zram", format!("invalid value at `{path}`: {error}"))
            })
        })
        .transpose()
}

fn current_algorithm(value: &str) -> Option<String> {
    value.split_whitespace().find_map(|token| {
        token
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .map(str::to_owned)
    })
}

#[derive(Debug, Default)]
struct MmStat {
    original_data_bytes: Option<u64>,
    compressed_data_bytes: Option<u64>,
    memory_used_bytes: Option<u64>,
}

fn parse_mm_stat(input: &str) -> Result<MmStat, CollectorError> {
    let values = input
        .split_whitespace()
        .map(|value| {
            value.parse::<u64>().map_err(|error| {
                CollectorError::invalid("zram", format!("invalid mm_stat value: {error}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MmStat {
        original_data_bytes: values.first().copied(),
        compressed_data_bytes: values.get(1).copied(),
        memory_used_bytes: values.get(2).copied(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FsSource;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn detects_multiple_devices_and_optional_metrics() {
        let root = tempdir().expect("tempdir");
        for name in ["zram0", "zram1"] {
            fs::create_dir_all(root.path().join(format!("sys/block/{name}"))).expect("directory");
        }
        fs::write(root.path().join("sys/block/zram0/disksize"), "4096\n").expect("disksize");
        fs::write(
            root.path().join("sys/block/zram0/comp_algorithm"),
            "lzo [zstd] lz4\n",
        )
        .expect("algorithm");
        fs::write(
            root.path().join("sys/block/zram0/mm_stat"),
            "100 50 60 0 0\n",
        )
        .expect("mm_stat");
        let state = collect(&FsSource::rooted_at(root.path())).expect("zram");
        assert!(state.available);
        assert_eq!(state.devices.len(), 2);
        assert_eq!(state.devices[0].algorithm.as_deref(), Some("zstd"));
        assert_eq!(state.devices[0].original_data_bytes, Some(100));
        assert_eq!(state.devices[1].memory_used_bytes, None);
    }
}
