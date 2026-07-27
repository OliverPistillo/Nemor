use serde::{Deserialize, Serialize};

const SECTOR_BYTES: u64 = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockStat {
    pub reads_completed: u64,
    pub sectors_read: u64,
    pub writes_completed: u64,
    pub sectors_written: u64,
    pub write_ticks_ms: u64,
    pub io_ticks_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockIoDelta {
    pub interval_ns: u64,
    pub writes_completed: u64,
    pub write_sectors: u64,
    pub write_bytes: u64,
    pub write_iops: f64,
    pub write_throughput_bytes_sec: f64,
    pub write_ticks_ms: u64,
    pub io_ticks_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteSample {
    pub timestamp_ns: u64,
    pub bytes: u64,
    pub attributable: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WriteBudget {
    pub max_mib_per_second: u64,
    pub daily_budget_gib: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetDecision {
    pub allowed: bool,
    pub instantaneous_mib_per_second: f64,
    pub rolling_minute_mib_per_second: f64,
    pub rolling_hour_gib: f64,
    pub daily_gib: f64,
    pub annual_tb: f64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TbEstimate {
    pub measurement_seconds: f64,
    pub bytes_per_day: f64,
    pub gib_per_day: f64,
    pub decimal_tb_per_year: f64,
    pub rated_tbw: Option<f64>,
    pub endurance_percent_per_year: Option<f64>,
    pub source: String,
    pub confidence: String,
    pub attributable: bool,
}

pub fn parse_block_stat(input: &str) -> Result<BlockStat, &'static str> {
    let fields: Vec<u64> = input
        .split_whitespace()
        .map(|value| value.parse().map_err(|_| "invalid block stat value"))
        .collect::<Result<_, _>>()?;
    if fields.len() < 11 {
        return Err("block stat requires at least eleven fields");
    }
    Ok(BlockStat {
        reads_completed: fields[0],
        sectors_read: fields[2],
        writes_completed: fields[4],
        sectors_written: fields[6],
        write_ticks_ms: fields[7],
        io_ticks_ms: fields[9],
    })
}

impl BlockStat {
    #[must_use]
    pub fn delta(self, previous: Self, interval_ns: u64) -> Option<BlockIoDelta> {
        if interval_ns == 0
            || self.writes_completed < previous.writes_completed
            || self.sectors_written < previous.sectors_written
            || self.write_ticks_ms < previous.write_ticks_ms
            || self.io_ticks_ms < previous.io_ticks_ms
        {
            return None;
        }
        let writes = self.writes_completed - previous.writes_completed;
        let sectors = self.sectors_written - previous.sectors_written;
        let bytes = sectors.checked_mul(SECTOR_BYTES)?;
        let seconds = interval_ns as f64 / 1_000_000_000.0;
        Some(BlockIoDelta {
            interval_ns,
            writes_completed: writes,
            write_sectors: sectors,
            write_bytes: bytes,
            write_iops: writes as f64 / seconds,
            write_throughput_bytes_sec: bytes as f64 / seconds,
            write_ticks_ms: self.write_ticks_ms - previous.write_ticks_ms,
            io_ticks_ms: self.io_ticks_ms - previous.io_ticks_ms,
        })
    }
}

impl WriteBudget {
    #[must_use]
    pub fn evaluate(&self, samples: &[WriteSample], now_ns: u64) -> BudgetDecision {
        let bytes = |window_ns: u64| -> u64 {
            samples
                .iter()
                .filter(|sample| now_ns.saturating_sub(sample.timestamp_ns) <= window_ns)
                .map(|sample| sample.bytes)
                .fold(0_u64, u64::saturating_add)
        };
        let second = bytes(1_000_000_000);
        let minute = bytes(60_000_000_000);
        let hour = bytes(3_600_000_000_000);
        let day = bytes(86_400_000_000_000);
        let mib = 1_048_576.0;
        let gib = 1_073_741_824.0;
        let instantaneous = second as f64 / mib;
        let rolling_minute = minute as f64 / mib / 60.0;
        let rolling_hour = hour as f64 / gib;
        let daily = day as f64 / gib;
        let annual_tb = day as f64 * 365.0 / 1_000_000_000_000.0;
        let mut reasons = Vec::new();
        if instantaneous > self.max_mib_per_second as f64 {
            reasons.push("instantaneous_write_budget_exceeded".to_owned());
        }
        if rolling_minute > self.max_mib_per_second as f64 {
            reasons.push("rolling_minute_write_budget_exceeded".to_owned());
        }
        if daily > self.daily_budget_gib as f64 {
            reasons.push("daily_write_budget_exceeded".to_owned());
        }
        BudgetDecision {
            allowed: reasons.is_empty(),
            instantaneous_mib_per_second: instantaneous,
            rolling_minute_mib_per_second: rolling_minute,
            rolling_hour_gib: rolling_hour,
            daily_gib: daily,
            annual_tb,
            reasons,
        }
    }
}

#[must_use]
pub fn estimate_tbw(
    bytes: u64,
    measurement_seconds: f64,
    rated_tbw: Option<f64>,
    source: &str,
    attributable: bool,
) -> Option<TbEstimate> {
    if bytes == 0 || !measurement_seconds.is_finite() || measurement_seconds <= 0.0 {
        return None;
    }
    let bytes_per_day = bytes as f64 * 86_400.0 / measurement_seconds;
    let decimal_tb_per_year = bytes_per_day * 365.0 / 1_000_000_000_000.0;
    Some(TbEstimate {
        measurement_seconds,
        bytes_per_day,
        gib_per_day: bytes_per_day / 1_073_741_824.0,
        decimal_tb_per_year,
        rated_tbw,
        endurance_percent_per_year: rated_tbw
            .filter(|value| value.is_finite() && *value > 0.0)
            .map(|value| decimal_tb_per_year / value * 100.0),
        source: source.to_owned(),
        confidence: if attributable {
            "bounded_attributable".to_owned()
        } else {
            "host_wide_noisy".to_owned()
        },
        attributable,
    })
}
