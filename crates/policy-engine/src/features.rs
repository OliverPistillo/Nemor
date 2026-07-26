use crate::PolicyError;
use actuator::CgroupCapabilities;
use classifier::{ForegroundState, WorkloadClass};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyInput {
    pub timestamp_ns: i64,
    pub ram_total_bytes: u64,
    pub mem_available_bytes: u64,
    pub available_percent: f64,
    pub swap_total_bytes: Option<u64>,
    pub swap_used_bytes: Option<u64>,
    pub swap_in_per_second: Option<f64>,
    pub swap_out_per_second: Option<f64>,
    pub major_faults_per_second: Option<f64>,
    pub pgscan_per_second: Option<f64>,
    pub pgsteal_per_second: Option<f64>,
    pub psi_memory_some_avg10: Option<f64>,
    pub psi_memory_full_avg10: Option<f64>,
    pub workload_class: Option<WorkloadClass>,
    pub workload_confidence: Option<f64>,
    pub gaming: bool,
    pub critical_processes: usize,
    pub protected_processes: usize,
    pub unknown_processes: usize,
    pub foreground: ForegroundState,
    pub cgroup_capabilities: Option<CgroupCapabilities>,
    pub actuator_available: bool,
    pub recent_safety_events: usize,
    pub recent_decisions: usize,
}

impl PolicyInput {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.timestamp_ns < 0 {
            return invalid("timestamp_ns", "must be non-negative");
        }
        if self.ram_total_bytes == 0 {
            return invalid("ram_total_bytes", "must be greater than zero");
        }
        if self.mem_available_bytes > self.ram_total_bytes {
            return invalid("mem_available_bytes", "must not exceed total RAM");
        }
        finite_range("available_percent", self.available_percent, 0.0, 100.0)?;
        if let (Some(total), Some(used)) = (self.swap_total_bytes, self.swap_used_bytes) {
            if used > total {
                return invalid("swap_used_bytes", "must not exceed swap total");
            }
        }
        for (field, value) in [
            ("swap_in_per_second", self.swap_in_per_second),
            ("swap_out_per_second", self.swap_out_per_second),
            ("major_faults_per_second", self.major_faults_per_second),
            ("pgscan_per_second", self.pgscan_per_second),
            ("pgsteal_per_second", self.pgsteal_per_second),
        ] {
            if value.is_some_and(|value| !value.is_finite() || value < 0.0) {
                return invalid(field, "must be finite and non-negative");
            }
        }
        for (field, value) in [
            ("psi_memory_some_avg10", self.psi_memory_some_avg10),
            ("psi_memory_full_avg10", self.psi_memory_full_avg10),
            ("workload_confidence", self.workload_confidence),
        ] {
            if let Some(value) = value {
                let max = if field == "workload_confidence" {
                    1.0
                } else {
                    100.0
                };
                finite_range(field, value, 0.0, max)?;
            }
        }
        Ok(())
    }
}

fn invalid<T>(field: &'static str, message: &'static str) -> Result<T, PolicyError> {
    Err(PolicyError::InvalidInput { field, message })
}

fn finite_range(field: &'static str, value: f64, min: f64, max: f64) -> Result<(), PolicyError> {
    if value.is_finite() && (min..=max).contains(&value) {
        Ok(())
    } else {
        invalid(field, "must be finite and in range")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterSample {
    pub timestamp_ns: i64,
    pub swap_in: Option<u64>,
    pub swap_out: Option<u64>,
    pub major_faults: Option<u64>,
    pub pgscan: Option<u64>,
    pub pgsteal: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct RateFeatures {
    pub swap_in_per_second: Option<f64>,
    pub swap_out_per_second: Option<f64>,
    pub major_faults_per_second: Option<f64>,
    pub pgscan_per_second: Option<f64>,
    pub pgsteal_per_second: Option<f64>,
}

#[derive(Debug, Default)]
pub struct RateTracker {
    previous: Option<CounterSample>,
}

impl RateTracker {
    #[must_use]
    pub fn update(&mut self, current: CounterSample) -> RateFeatures {
        let rates = self
            .previous
            .map_or_else(RateFeatures::default, |previous| {
                let elapsed_ns = current.timestamp_ns.checked_sub(previous.timestamp_ns);
                let seconds = elapsed_ns
                    .filter(|elapsed| *elapsed > 0)
                    .map(|elapsed| elapsed as f64 / 1_000_000_000.0);
                RateFeatures {
                    swap_in_per_second: rate(previous.swap_in, current.swap_in, seconds),
                    swap_out_per_second: rate(previous.swap_out, current.swap_out, seconds),
                    major_faults_per_second: rate(
                        previous.major_faults,
                        current.major_faults,
                        seconds,
                    ),
                    pgscan_per_second: rate(previous.pgscan, current.pgscan, seconds),
                    pgsteal_per_second: rate(previous.pgsteal, current.pgsteal, seconds),
                }
            });
        self.previous = Some(current);
        rates
    }
}

fn rate(previous: Option<u64>, current: Option<u64>, seconds: Option<f64>) -> Option<f64> {
    let (previous, current, seconds) = (previous?, current?, seconds?);
    current
        .checked_sub(previous)
        .map(|delta| delta as f64 / seconds)
}
