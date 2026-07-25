use crate::process::{self, ProcessCollection, ProcessCpuTracker};
use crate::{meminfo, psi, swap, vmstat, zram, zswap, CollectorError, TelemetrySource};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq)]
pub struct SystemSample {
    pub timestamp_ns: i64,
    pub mem_total_bytes: u64,
    pub mem_available_bytes: u64,
    pub anon_bytes: Option<u64>,
    pub file_cache_bytes: Option<u64>,
    pub slab_bytes: Option<u64>,
    pub swap_used_bytes: Option<u64>,
    pub swap_in_pages: Option<u64>,
    pub swap_out_pages: Option<u64>,
    pub major_faults: Option<u64>,
    pub minor_faults: Option<u64>,
    pub pgscan: Option<u64>,
    pub pgsteal: Option<u64>,
    pub workingset_refault: Option<u64>,
    pub psi_memory: Option<psi::PsiSample>,
    pub psi_cpu: Option<psi::PsiSample>,
    pub psi_io: Option<psi::PsiSample>,
    pub swap: swap::SwapState,
    pub zram: zram::ZramState,
    pub zswap: zswap::ZswapState,
    pub capabilities_unavailable: Vec<String>,
}

pub struct SystemCollector {
    source: Box<dyn TelemetrySource>,
    process_cpu: ProcessCpuTracker,
    smaps_cursor: usize,
}

impl SystemCollector {
    #[must_use]
    pub fn production() -> Self {
        Self::with_source(crate::FsSource::production())
    }

    #[must_use]
    pub fn with_source(source: impl TelemetrySource + 'static) -> Self {
        Self {
            source: Box::new(source),
            process_cpu: ProcessCpuTracker::default(),
            smaps_cursor: 0,
        }
    }

    pub fn sample_system(&self, timestamp_ns: i64) -> Result<SystemSample, CollectorError> {
        let meminfo_text = self
            .source
            .read_to_string("/proc/meminfo")
            .map_err(|source| CollectorError::RequiredRead {
                metric: "meminfo",
                path: "/proc/meminfo".to_owned(),
                source,
            })?;
        let vmstat_text = self
            .source
            .read_to_string("/proc/vmstat")
            .map_err(|source| CollectorError::RequiredRead {
                metric: "vmstat",
                path: "/proc/vmstat".to_owned(),
                source,
            })?;
        let meminfo = meminfo::parse(&meminfo_text)?;
        let vmstat = vmstat::parse(&vmstat_text)?;
        let swap = swap::collect(self.source.as_ref())?;
        let mut unavailable = Vec::new();
        let psi_memory = collect_psi(
            self.source.as_ref(),
            "/proc/pressure/memory",
            "psi_memory",
            &mut unavailable,
        );
        let psi_cpu = collect_psi(
            self.source.as_ref(),
            "/proc/pressure/cpu",
            "psi_cpu",
            &mut unavailable,
        );
        let psi_io = collect_psi(
            self.source.as_ref(),
            "/proc/pressure/io",
            "psi_io",
            &mut unavailable,
        );
        let zram = zram::collect(self.source.as_ref()).unwrap_or_else(|_| {
            unavailable.push("zram_statistics".to_owned());
            zram::ZramState {
                available: false,
                devices: Vec::new(),
            }
        });
        if !zram.available {
            unavailable.push("zram".to_owned());
        }
        let zswap = zswap::collect(self.source.as_ref()).unwrap_or_else(|_| {
            unavailable.push("zswap_statistics".to_owned());
            zswap::ZswapState {
                available: false,
                enabled: None,
                stored_pages: None,
                pool_bytes: None,
            }
        });
        if !zswap.available {
            unavailable.push("zswap".to_owned());
        } else if zswap.stored_pages.is_none() || zswap.pool_bytes.is_none() {
            unavailable.push("zswap_statistics".to_owned());
        }
        unavailable.sort();
        unavailable.dedup();

        Ok(SystemSample {
            timestamp_ns,
            mem_total_bytes: meminfo.mem_total_bytes,
            mem_available_bytes: meminfo.mem_available_bytes,
            anon_bytes: meminfo.anon_bytes,
            file_cache_bytes: meminfo.file_cache_bytes,
            slab_bytes: meminfo.slab_bytes,
            swap_used_bytes: meminfo.swap_used_bytes,
            swap_in_pages: vmstat.swap_in_pages,
            swap_out_pages: vmstat.swap_out_pages,
            major_faults: vmstat.major_faults,
            minor_faults: vmstat.minor_faults,
            pgscan: vmstat.pgscan,
            pgsteal: vmstat.pgsteal,
            workingset_refault: vmstat.workingset_refault,
            psi_memory,
            psi_cpu,
            psi_io,
            swap,
            zram,
            zswap,
            capabilities_unavailable: unavailable,
        })
    }

    pub fn sample_processes(
        &mut self,
        timestamp_ns: i64,
        read_smaps: bool,
        smaps_budget: usize,
    ) -> Result<ProcessCollection, CollectorError> {
        process::collect(
            self.source.as_ref(),
            timestamp_ns,
            read_smaps,
            smaps_budget,
            &mut self.smaps_cursor,
            &mut self.process_cpu,
        )
    }
}

pub fn unix_timestamp_ns() -> Result<i64, CollectorError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CollectorError::Timestamp)?;
    i64::try_from(duration.as_nanos()).map_err(|_| CollectorError::Timestamp)
}

fn collect_psi(
    source: &dyn TelemetrySource,
    path: &str,
    metric: &'static str,
    unavailable: &mut Vec<String>,
) -> Option<psi::PsiSample> {
    match source.read_to_string(path) {
        Ok(value) => match psi::parse(metric, &value) {
            Ok(value) => Some(value),
            Err(_) => {
                unavailable.push(metric.to_owned());
                None
            }
        },
        Err(_) => {
            unavailable.push(metric.to_owned());
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FsSource;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    fn write(root: &Path, relative: &str, value: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("parent")).expect("directory");
        fs::write(path, value).expect("fixture");
    }

    fn baseline(root: &Path) {
        write(
            root,
            "proc/meminfo",
            "MemTotal: 1000 kB\nMemAvailable: 800 kB\nSwapTotal: 100 kB\nSwapFree: 90 kB\n",
        );
        write(
            root,
            "proc/vmstat",
            "pswpin 1\npswpout 2\npgfault 10\npgmajfault 1\n",
        );
        write(root, "proc/swaps", "Filename Type Size Used Priority\n");
        fs::create_dir_all(root.join("sys/block")).expect("sys block");
    }

    #[test]
    fn missing_psi_is_recorded_as_unavailable_without_simulation() {
        let root = tempdir().expect("tempdir");
        baseline(root.path());
        let collector = SystemCollector::with_source(FsSource::rooted_at(root.path()));
        let sample = collector.sample_system(1).expect("sample");
        assert!(sample.psi_memory.is_none());
        assert!(sample.psi_cpu.is_none());
        assert!(sample.psi_io.is_none());
        assert!(sample
            .capabilities_unavailable
            .contains(&"psi_memory".to_owned()));
    }

    #[test]
    fn complete_psi_cpu_memory_io_are_kept_separately() {
        let root = tempdir().expect("tempdir");
        baseline(root.path());
        for (name, avg) in [("memory", "1.00"), ("cpu", "2.00"), ("io", "3.00")] {
            write(
                root.path(),
                &format!("proc/pressure/{name}"),
                &format!("some avg10={avg} avg60=0 avg300=0 total=1\n"),
            );
        }
        let collector = SystemCollector::with_source(FsSource::rooted_at(root.path()));
        let sample = collector.sample_system(1).expect("sample");
        assert_eq!(
            sample
                .psi_memory
                .and_then(|value| value.some)
                .map(|value| value.avg10),
            Some(1.0)
        );
        assert_eq!(
            sample
                .psi_cpu
                .and_then(|value| value.some)
                .map(|value| value.avg10),
            Some(2.0)
        );
        assert_eq!(
            sample
                .psi_io
                .and_then(|value| value.some)
                .map(|value| value.avg10),
            Some(3.0)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn production_collectors_read_real_linux_interfaces() {
        let mut collector = SystemCollector::production();
        let timestamp = unix_timestamp_ns().expect("timestamp");
        let system = collector
            .sample_system(timestamp)
            .expect("real system sample");
        assert!(system.mem_total_bytes > 0);
        let _processes = collector
            .sample_processes(timestamp, false, 0)
            .expect("real process sample");
    }
}
