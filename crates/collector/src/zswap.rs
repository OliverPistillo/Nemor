use crate::source::read_optional;
use crate::{CollectorError, TelemetrySource};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZswapState {
    pub available: bool,
    pub enabled: Option<bool>,
    pub stored_pages: Option<u64>,
    pub pool_bytes: Option<u64>,
}

pub fn collect(source: &dyn TelemetrySource) -> Result<ZswapState, CollectorError> {
    let enabled_text =
        read_optional(source, "/sys/module/zswap/parameters/enabled").map_err(|source| {
            CollectorError::RequiredRead {
                metric: "zswap",
                path: "/sys/module/zswap/parameters/enabled".to_owned(),
                source,
            }
        })?;
    if enabled_text.is_none() {
        return Ok(ZswapState {
            available: false,
            enabled: None,
            stored_pages: None,
            pool_bytes: None,
        });
    }
    let enabled = enabled_text.as_deref().and_then(parse_enabled);
    let stored_pages = first_optional_u64(
        source,
        &[
            "/sys/kernel/debug/zswap/stored_pages",
            "/sys/kernel/mm/zswap/stored_pages",
        ],
    )?;
    let pool_bytes = first_optional_u64(
        source,
        &[
            "/sys/kernel/debug/zswap/pool_total_size",
            "/sys/kernel/mm/zswap/pool_total_size",
        ],
    )?;
    Ok(ZswapState {
        available: true,
        enabled,
        stored_pages,
        pool_bytes,
    })
}

fn parse_enabled(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" | "1" | "true" => Some(true),
        "n" | "no" | "0" | "false" => Some(false),
        _ => None,
    }
}

fn first_optional_u64(
    source: &dyn TelemetrySource,
    paths: &[&str],
) -> Result<Option<u64>, CollectorError> {
    for path in paths {
        if let Some(value) =
            read_optional(source, path).map_err(|source| CollectorError::RequiredRead {
                metric: "zswap",
                path: (*path).to_owned(),
                source,
            })?
        {
            return value.trim().parse::<u64>().map(Some).map_err(|error| {
                CollectorError::invalid("zswap", format!("invalid value at `{path}`: {error}"))
            });
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FsSource;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn distinguishes_present_and_absent_with_optional_stats() {
        let root = tempdir().expect("tempdir");
        fs::create_dir_all(root.path().join("sys/module/zswap/parameters")).expect("directory");
        let source = FsSource::rooted_at(root.path());
        assert!(!collect(&source).expect("absent").available);
        fs::write(
            root.path().join("sys/module/zswap/parameters/enabled"),
            "Y\n",
        )
        .expect("enabled");
        let state = collect(&source).expect("present");
        assert!(state.available);
        assert_eq!(state.enabled, Some(true));
        assert_eq!(state.stored_pages, None);
    }
}
