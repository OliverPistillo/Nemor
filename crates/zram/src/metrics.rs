use crate::inventory::MmStat;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CompressionMetrics {
    pub logical_compression_ratio: Option<f64>,
    pub effective_memory_ratio: Option<f64>,
    pub allocator_efficiency: Option<f64>,
    pub memory_saved_bytes: Option<u64>,
    pub utilization_percent: Option<f64>,
    pub same_pages: Option<u64>,
    pub huge_pages: Option<u64>,
    pub cpu_cost_percent: Option<f64>,
}

impl CompressionMetrics {
    #[must_use]
    pub fn from_mm_stat(stat: &MmStat, disksize: Option<u64>) -> Self {
        let orig = stat.orig_data_size;
        let compressed = stat.compr_data_size;
        let used = stat.mem_used_total;
        Self {
            logical_compression_ratio: ratio(orig, compressed),
            effective_memory_ratio: ratio(orig, used),
            allocator_efficiency: ratio(compressed, used),
            memory_saved_bytes: orig.zip(used).map(|(orig, used)| orig.saturating_sub(used)),
            utilization_percent: orig
                .zip(disksize)
                .and_then(|(orig, size)| percent(orig, size)),
            same_pages: stat.same_pages,
            huge_pages: stat.huge_pages,
            cpu_cost_percent: None,
        }
    }
}

fn ratio(numerator: Option<u64>, denominator: Option<u64>) -> Option<f64> {
    match (numerator, denominator) {
        (Some(_), Some(0)) | (None, _) | (_, None) => None,
        (Some(numerator), Some(denominator)) => Some(numerator as f64 / denominator as f64),
    }
}

fn percent(value: u64, total: u64) -> Option<f64> {
    (total > 0).then(|| value as f64 * 100.0 / total as f64)
}
