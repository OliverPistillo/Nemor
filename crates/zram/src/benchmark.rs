use crate::ZramError;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetKind {
    HighlyCompressible,
    MediumCompressible,
    DeterministicIncompressible,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub algorithm: String,
    pub dataset: DatasetKind,
    pub input_bytes: u64,
    pub compressed_bytes: u64,
    pub memory_used_bytes: u64,
    pub cpu_time_ns: u64,
    pub wall_time_ns: u64,
    pub write_throughput_bytes_sec: Option<f64>,
    pub read_throughput_bytes_sec: Option<f64>,
    pub logical_ratio: Option<f64>,
    pub effective_ratio: Option<f64>,
    pub real_isolated_device: bool,
    pub rounds: u32,
    pub error: Option<String>,
}

impl BenchmarkResult {
    #[must_use]
    pub fn valid(&self) -> bool {
        self.error.is_none()
            && self.real_isolated_device
            && self.rounds >= 3
            && self.input_bytes > 0
            && self.wall_time_ns > 0
            && self.logical_ratio.is_some_and(f64::is_finite)
            && self.effective_ratio.is_some_and(f64::is_finite)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkEvidence {
    pub algorithm: String,
    pub median_write_throughput_bytes_sec: Option<f64>,
    pub median_effective_ratio: Option<f64>,
    pub median_cpu_time_ns: Option<u64>,
    pub cpu_overhead_percent: Option<f64>,
    pub datasets: usize,
    pub real: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkPlan {
    pub algorithms: Vec<String>,
    pub datasets: Vec<DatasetKind>,
    pub bytes_per_dataset: u64,
    pub warmup_rounds: u32,
    pub measured_rounds: u32,
    pub dry_run: bool,
    pub blocked_reasons: Vec<String>,
}

impl BenchmarkPlan {
    pub fn new(
        mut algorithms: Vec<String>,
        bytes: u64,
        maximum: u64,
        observe: bool,
    ) -> Result<Self, ZramError> {
        if bytes == 0 || bytes > maximum || maximum > 268_435_456 {
            return Err(ZramError::Blocked(
                "benchmark dataset exceeds configured bound".to_owned(),
            ));
        }
        algorithms.sort();
        algorithms.dedup();
        let blocked_reasons = if observe {
            vec!["observe_mode".to_owned()]
        } else {
            Vec::new()
        };
        Ok(Self {
            algorithms,
            datasets: vec![
                DatasetKind::HighlyCompressible,
                DatasetKind::MediumCompressible,
                DatasetKind::DeterministicIncompressible,
            ],
            bytes_per_dataset: bytes,
            warmup_rounds: 1,
            measured_rounds: 5,
            dry_run: observe,
            blocked_reasons,
        })
    }
}

#[must_use]
pub fn deterministic_dataset(kind: DatasetKind, length: usize) -> Vec<u8> {
    match kind {
        DatasetKind::HighlyCompressible => vec![0x5a; length],
        DatasetKind::MediumCompressible => (0..length)
            .map(|index| b"nemor-capacity-pattern"[index % 22])
            .collect(),
        DatasetKind::DeterministicIncompressible => {
            let mut state = 0x9e37_79b9_u32;
            (0..length)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                })
                .collect()
        }
    }
}

#[must_use]
pub fn aggregate(results: &[BenchmarkResult]) -> Vec<BenchmarkEvidence> {
    let mut algorithms: Vec<_> = results.iter().map(|item| item.algorithm.clone()).collect();
    algorithms.sort();
    algorithms.dedup();
    algorithms
        .into_iter()
        .filter_map(|algorithm| {
            let valid: Vec<_> = results
                .iter()
                .filter(|item| item.algorithm == algorithm && item.valid())
                .collect();
            (!valid.is_empty()).then(|| BenchmarkEvidence {
                algorithm,
                median_write_throughput_bytes_sec: median_f64(
                    valid
                        .iter()
                        .filter_map(|item| item.write_throughput_bytes_sec)
                        .collect(),
                ),
                median_effective_ratio: median_f64(
                    valid
                        .iter()
                        .filter_map(|item| item.effective_ratio)
                        .collect(),
                ),
                median_cpu_time_ns: median_u64(valid.iter().map(|item| item.cpu_time_ns).collect()),
                cpu_overhead_percent: None,
                datasets: valid.len(),
                real: valid.iter().all(|item| item.real_isolated_device),
            })
        })
        .collect()
}

fn median_f64(mut values: Vec<f64>) -> Option<f64> {
    values.retain(|value| value.is_finite());
    values.sort_by(|left, right| left.partial_cmp(right).unwrap_or(Ordering::Equal));
    values.get(values.len() / 2).copied()
}

fn median_u64(mut values: Vec<u64>) -> Option<u64> {
    values.sort_unstable();
    values.get(values.len() / 2).copied()
}
