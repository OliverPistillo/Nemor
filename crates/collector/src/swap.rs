use crate::{CollectorError, TelemetrySource};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapEntry {
    pub path: String,
    pub kind: String,
    pub size_bytes: u64,
    pub used_bytes: u64,
    pub priority: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapConfiguration {
    None,
    Swapfile,
    Partition,
    Zram,
    Mixed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapState {
    pub entries: Vec<SwapEntry>,
    pub configuration: SwapConfiguration,
}

pub fn parse(input: &str) -> Result<SwapState, CollectorError> {
    let mut entries = Vec::new();
    for (index, line) in input.lines().enumerate() {
        if index == 0 && line.to_ascii_lowercase().contains("filename") {
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 5 {
            return Err(CollectorError::invalid(
                "swaps",
                format!("line {} must contain five fields", index + 1),
            ));
        }
        let size_kib = parse_u64(fields[2], index)?;
        let used_kib = parse_u64(fields[3], index)?;
        let priority = fields[4].parse::<i32>().map_err(|error| {
            CollectorError::invalid(
                "swaps",
                format!("line {} has invalid priority: {error}", index + 1),
            )
        })?;
        entries.push(SwapEntry {
            path: fields[0].to_owned(),
            kind: fields[1].to_owned(),
            size_bytes: kib_to_bytes(size_kib, index)?,
            used_bytes: kib_to_bytes(used_kib, index)?,
            priority,
        });
    }
    let configuration = summarize(&entries);
    Ok(SwapState {
        entries,
        configuration,
    })
}

pub fn collect(source: &dyn TelemetrySource) -> Result<SwapState, CollectorError> {
    let text =
        source
            .read_to_string("/proc/swaps")
            .map_err(|source| CollectorError::RequiredRead {
                metric: "swaps",
                path: "/proc/swaps".to_owned(),
                source,
            })?;
    parse(&text)
}

fn summarize(entries: &[SwapEntry]) -> SwapConfiguration {
    if entries.is_empty() {
        return SwapConfiguration::None;
    }
    let mut has_file = false;
    let mut has_partition = false;
    let mut has_zram = false;
    for entry in entries {
        if entry.path.contains("/zram") {
            has_zram = true;
        } else if entry.kind.eq_ignore_ascii_case("file") {
            has_file = true;
        } else {
            has_partition = true;
        }
    }
    match (has_file, has_partition, has_zram) {
        (true, false, false) => SwapConfiguration::Swapfile,
        (false, true, false) => SwapConfiguration::Partition,
        (false, false, true) => SwapConfiguration::Zram,
        _ => SwapConfiguration::Mixed,
    }
}

fn parse_u64(value: &str, index: usize) -> Result<u64, CollectorError> {
    value.parse::<u64>().map_err(|error| {
        CollectorError::invalid(
            "swaps",
            format!("line {} has invalid size: {error}", index + 1),
        )
    })
}

fn kib_to_bytes(value: u64, index: usize) -> Result<u64, CollectorError> {
    value.checked_mul(1024).ok_or_else(|| {
        CollectorError::invalid("swaps", format!("line {} size overflows bytes", index + 1))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "Filename Type Size Used Priority\n";

    #[test]
    fn detects_no_swap_swapfile_zram_and_mixed() {
        assert_eq!(
            parse(HEADER).expect("none").configuration,
            SwapConfiguration::None
        );
        let file = format!("{HEADER}/swapfile file 100 5 -2\n");
        assert_eq!(
            parse(&file).expect("file").configuration,
            SwapConfiguration::Swapfile
        );
        let zram = format!("{HEADER}/dev/zram0 partition 100 5 100\n");
        assert_eq!(
            parse(&zram).expect("zram").configuration,
            SwapConfiguration::Zram
        );
        let mixed = format!("{file}/dev/zram0 partition 100 5 100\n");
        assert_eq!(
            parse(&mixed).expect("mixed").configuration,
            SwapConfiguration::Mixed
        );
    }

    #[test]
    fn converts_entry_units() {
        let value = parse(&format!("{HEADER}/dev/sda2 partition 2 1 -1\n")).expect("swap");
        assert_eq!(value.entries[0].size_bytes, 2048);
        assert_eq!(value.entries[0].used_bytes, 1024);
    }
}
