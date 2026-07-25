use crate::CollectorError;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemInfo {
    pub mem_total_bytes: u64,
    pub mem_available_bytes: u64,
    pub anon_bytes: Option<u64>,
    pub file_cache_bytes: Option<u64>,
    pub slab_bytes: Option<u64>,
    pub swap_total_bytes: Option<u64>,
    pub swap_free_bytes: Option<u64>,
    pub swap_used_bytes: Option<u64>,
}

pub fn parse(input: &str) -> Result<MemInfo, CollectorError> {
    let wanted = [
        "MemTotal",
        "MemAvailable",
        "AnonPages",
        "Cached",
        "Buffers",
        "Slab",
        "SwapTotal",
        "SwapFree",
    ];
    let mut values = HashMap::new();
    for line in input.lines() {
        let Some((raw_key, raw_value)) = line.split_once(':') else {
            continue;
        };
        let key = raw_key.trim();
        if !wanted.contains(&key) {
            continue;
        }
        let parts = raw_value.split_whitespace().collect::<Vec<_>>();
        if parts.len() != 2 || parts[1] != "kB" {
            return Err(CollectorError::invalid(
                "meminfo",
                format!("`{key}` must contain one value in kB"),
            ));
        }
        let kib = parts[0].parse::<u64>().map_err(|error| {
            CollectorError::invalid("meminfo", format!("`{key}` has invalid value: {error}"))
        })?;
        let bytes = kib.checked_mul(1024).ok_or_else(|| {
            CollectorError::invalid("meminfo", format!("`{key}` overflows bytes"))
        })?;
        values.insert(key, bytes);
    }

    let required = |key: &'static str| {
        values.get(key).copied().ok_or_else(|| {
            CollectorError::invalid("meminfo", format!("required field `{key}` is missing"))
        })
    };
    let add_optional = |left_key: &str, right_key: &str| -> Result<Option<u64>, CollectorError> {
        match (values.get(left_key), values.get(right_key)) {
            (None, None) => Ok(None),
            (left_value, right_value) => left_value
                .copied()
                .unwrap_or_default()
                .checked_add(right_value.copied().unwrap_or_default())
                .map(Some)
                .ok_or_else(|| {
                    CollectorError::invalid(
                        "meminfo",
                        format!("`{left_key}` plus `{right_key}` overflows bytes"),
                    )
                }),
        }
    };

    let swap_total = values.get("SwapTotal").copied();
    let swap_free = values.get("SwapFree").copied();
    let swap_used =
        match (swap_total, swap_free) {
            (Some(total), Some(free)) => Some(total.checked_sub(free).ok_or_else(|| {
                CollectorError::invalid("meminfo", "`SwapFree` exceeds `SwapTotal`")
            })?),
            _ => None,
        };
    Ok(MemInfo {
        mem_total_bytes: required("MemTotal")?,
        mem_available_bytes: required("MemAvailable")?,
        anon_bytes: values.get("AnonPages").copied(),
        file_cache_bytes: add_optional("Cached", "Buffers")?,
        slab_bytes: values.get("Slab").copied(),
        swap_total_bytes: swap_total,
        swap_free_bytes: swap_free,
        swap_used_bytes: swap_used,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPLETE: &str = "MemTotal: 1000 kB\nMemAvailable: 400 kB\nAnonPages: 100 kB\nCached: 80 kB\nBuffers: 20 kB\nSlab: 10 kB\nSwapTotal: 200 kB\nSwapFree: 50 kB\nUnknown: 1 kB\n";

    #[test]
    fn parses_complete_and_converts_kib_to_bytes() {
        let value = parse(COMPLETE).expect("meminfo");
        assert_eq!(value.mem_total_bytes, 1_024_000);
        assert_eq!(value.file_cache_bytes, Some(102_400));
        assert_eq!(value.swap_used_bytes, Some(153_600));
    }

    #[test]
    fn does_not_depend_on_line_order() {
        let reversed = COMPLETE.lines().rev().collect::<Vec<_>>().join("\n");
        assert_eq!(
            parse(&reversed).expect("reordered"),
            parse(COMPLETE).expect("normal")
        );
    }

    #[test]
    fn rejects_missing_required_field() {
        assert!(parse("MemTotal: 1 kB\n").is_err());
    }

    #[test]
    fn rejects_invalid_value_and_unit() {
        assert!(parse("MemTotal: no kB\nMemAvailable: 1 kB\n").is_err());
        assert!(parse("MemTotal: 1 MB\nMemAvailable: 1 kB\n").is_err());
    }

    #[test]
    fn rejects_byte_overflow() {
        let input = format!("MemTotal: {} kB\nMemAvailable: 1 kB\n", u64::MAX);
        assert!(parse(&input).is_err());
    }
}
