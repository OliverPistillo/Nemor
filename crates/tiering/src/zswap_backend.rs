use crate::{parse_block_stat, BackendError, BlockStat};
use std::fs;
use std::path::{Path, PathBuf};

const PARAMETERS: &[&str] = &[
    "enabled",
    "compressor",
    "zpool",
    "max_pool_percent",
    "accept_threshold_percent",
    "shrinker_enabled",
];

pub trait ZswapBackend {
    fn read_parameter(&self, name: &str) -> Result<Option<String>, BackendError>;
    fn set_parameter(&mut self, name: &str, value: &str) -> Result<(), BackendError>;
}

pub trait StorageMetricsBackend {
    fn read_block_stat(&self, device: &str) -> Result<BlockStat, BackendError>;
}

pub struct LinuxZswapBackend {
    root: PathBuf,
    allow_mutation: bool,
}

impl LinuxZswapBackend {
    #[must_use]
    pub fn observe() -> Self {
        Self {
            root: PathBuf::from("/"),
            allow_mutation: false,
        }
    }

    #[must_use]
    pub fn for_explicit_transaction(allow_mutation: bool) -> Self {
        Self {
            root: PathBuf::from("/"),
            allow_mutation,
        }
    }

    fn parameter_path(&self, name: &str) -> Result<PathBuf, BackendError> {
        if !PARAMETERS.contains(&name) {
            return Err(BackendError::Blocked(
                "zswap parameter is outside the closed allow-list".to_owned(),
            ));
        }
        Ok(resolve(&self.root, "/sys/module/zswap/parameters").join(name))
    }
}

impl ZswapBackend for LinuxZswapBackend {
    fn read_parameter(&self, name: &str) -> Result<Option<String>, BackendError> {
        let path = self.parameter_path(name)?;
        match fs::read_to_string(path) {
            Ok(value) => Ok(Some(value.trim().to_owned())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(BackendError::Operation {
                operation: "read_zswap_parameter",
                message: error.to_string(),
            }),
        }
    }

    fn set_parameter(&mut self, name: &str, value: &str) -> Result<(), BackendError> {
        if !self.allow_mutation {
            return Err(BackendError::Blocked(
                "zswap runtime mutation was not explicitly enabled".to_owned(),
            ));
        }
        validate_value(name, value)?;
        let path = self.parameter_path(name)?;
        fs::write(&path, value).map_err(|error| BackendError::Operation {
            operation: "write_zswap_parameter",
            message: error.to_string(),
        })?;
        let readback = self.read_parameter(name)?;
        if readback.as_deref() != Some(value) {
            return Err(BackendError::Verification(format!(
                "zswap {name} readback mismatch"
            )));
        }
        Ok(())
    }
}

impl StorageMetricsBackend for LinuxZswapBackend {
    fn read_block_stat(&self, device: &str) -> Result<BlockStat, BackendError> {
        if device.is_empty()
            || device.contains('/')
            || !device
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
        {
            return Err(BackendError::Blocked(
                "block device name is outside the closed allow-list".to_owned(),
            ));
        }
        let path = resolve(&self.root, "/sys/class/block")
            .join(device)
            .join("stat");
        let value = fs::read_to_string(path).map_err(|error| BackendError::Operation {
            operation: "read_block_stat",
            message: error.to_string(),
        })?;
        parse_block_stat(&value).map_err(|error| BackendError::Verification(error.to_owned()))
    }
}

fn validate_value(name: &str, value: &str) -> Result<(), BackendError> {
    if value.is_empty()
        || value.len() > 32
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(BackendError::Blocked(
            "zswap parameter value is malformed".to_owned(),
        ));
    }
    if matches!(name, "enabled" | "shrinker_enabled") && !matches!(value, "Y" | "N" | "1" | "0") {
        return Err(BackendError::Blocked(
            "zswap boolean value is invalid".to_owned(),
        ));
    }
    if matches!(name, "max_pool_percent" | "accept_threshold_percent") {
        let number = value
            .parse::<u8>()
            .map_err(|_| BackendError::Blocked("zswap percentage is invalid".to_owned()))?;
        if number == 0 || number > 100 {
            return Err(BackendError::Blocked(
                "zswap percentage is outside 1..=100".to_owned(),
            ));
        }
    }
    Ok(())
}

fn resolve(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}
