use crate::CollectorError;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VmStat {
    pub swap_in_pages: Option<u64>,
    pub swap_out_pages: Option<u64>,
    pub page_faults: Option<u64>,
    pub major_faults: Option<u64>,
    pub minor_faults: Option<u64>,
    pub pgscan: Option<u64>,
    pub pgsteal: Option<u64>,
    pub workingset_refault: Option<u64>,
}

pub fn parse(input: &str) -> Result<VmStat, CollectorError> {
    let mut result = VmStat::default();
    for line in input.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let relevant = matches!(key, "pswpin" | "pswpout" | "pgfault" | "pgmajfault")
            || key == "pgscan"
            || key.starts_with("pgscan_")
            || key == "pgsteal"
            || key.starts_with("pgsteal_")
            || key == "workingset_refault"
            || key.starts_with("workingset_refault_");
        if !relevant {
            continue;
        }
        let raw = parts
            .next()
            .ok_or_else(|| CollectorError::invalid("vmstat", format!("`{key}` has no counter")))?;
        if parts.next().is_some() {
            return Err(CollectorError::invalid(
                "vmstat",
                format!("`{key}` contains trailing data"),
            ));
        }
        let value = raw.parse::<u64>().map_err(|error| {
            CollectorError::invalid("vmstat", format!("`{key}` is invalid: {error}"))
        })?;
        match key {
            "pswpin" => result.swap_in_pages = Some(value),
            "pswpout" => result.swap_out_pages = Some(value),
            "pgfault" => result.page_faults = Some(value),
            "pgmajfault" => result.major_faults = Some(value),
            key if key == "pgscan" || key.starts_with("pgscan_") => {
                checked_accumulate(&mut result.pgscan, value, key)?
            }
            key if key == "pgsteal" || key.starts_with("pgsteal_") => {
                checked_accumulate(&mut result.pgsteal, value, key)?
            }
            key if key == "workingset_refault" || key.starts_with("workingset_refault_") => {
                checked_accumulate(&mut result.workingset_refault, value, key)?
            }
            _ => {}
        }
    }
    result.minor_faults = match (result.page_faults, result.major_faults) {
        (Some(all), Some(major)) => all.checked_sub(major),
        _ => None,
    };
    Ok(result)
}

fn checked_accumulate(
    target: &mut Option<u64>,
    value: u64,
    key: &str,
) -> Result<(), CollectorError> {
    *target = Some(
        target
            .unwrap_or_default()
            .checked_add(value)
            .ok_or_else(|| {
                CollectorError::invalid("vmstat", format!("aggregate including `{key}` overflows"))
            })?,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_required_and_aggregates_prefix_families() {
        let input = "pswpin 1\npswpout 2\npgfault 100\npgmajfault 4\npgscan_kswapd 3\npgscan_direct 5\npgsteal_kswapd 7\npgsteal_direct 11\nworkingset_refault_anon 13\nworkingset_refault_file 17\nunknown 99\n";
        let value = parse(input).expect("vmstat");
        assert_eq!(value.swap_in_pages, Some(1));
        assert_eq!(value.swap_out_pages, Some(2));
        assert_eq!(value.major_faults, Some(4));
        assert_eq!(value.minor_faults, Some(96));
        assert_eq!(value.pgscan, Some(8));
        assert_eq!(value.pgsteal, Some(18));
        assert_eq!(value.workingset_refault, Some(30));
    }

    #[test]
    fn unknown_keys_are_ignored() {
        assert_eq!(
            parse("unknown invalid\n").expect("unknown"),
            VmStat::default()
        );
    }

    #[test]
    fn invalid_known_counter_is_rejected() {
        assert!(parse("pswpin nope\n").is_err());
    }
}
