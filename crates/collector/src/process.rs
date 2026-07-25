use crate::error::{classify_process_io, ProcessReadFailure};
use crate::{CollectorError, TelemetrySource};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

const PAGE_SIZE_BYTES: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessSample {
    pub timestamp_ns: i64,
    pub pid: u32,
    pub executable: Option<String>,
    pub executable_name: Option<String>,
    pub parent_pid: Option<u32>,
    pub process_group_id: Option<i32>,
    pub session_id: Option<i32>,
    pub tty_nr: Option<i64>,
    pub foreground_process_group_id: Option<i32>,
    pub start_time_ticks: Option<u64>,
    pub cgroup_path: Option<String>,
    pub rss_bytes: Option<u64>,
    pub pss_bytes: Option<u64>,
    pub uss_bytes: Option<u64>,
    pub swap_bytes: Option<u64>,
    pub minor_faults: Option<u64>,
    pub major_faults: Option<u64>,
    pub cpu_percent: Option<f64>,
    pub io_read_bytes: Option<u64>,
    pub io_write_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessCollectionStats {
    pub disappeared: usize,
    pub permission_denied: usize,
    pub invalid: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcessCollection {
    pub samples: Vec<ProcessSample>,
    pub stats: ProcessCollectionStats,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedStat {
    pid: u32,
    executable_name: String,
    parent_pid: u32,
    process_group_id: i32,
    session_id: i32,
    tty_nr: i64,
    foreground_process_group_id: i32,
    minor_faults: u64,
    major_faults: u64,
    process_ticks: u64,
    start_time_ticks: u64,
    rss_pages: i64,
}

#[derive(Debug, Clone, Copy)]
struct CpuBaseline {
    start_time_ticks: u64,
    process_ticks: u64,
    system_ticks: u64,
}

#[derive(Debug, Default)]
pub struct ProcessCpuTracker {
    previous: HashMap<u32, CpuBaseline>,
}

impl ProcessCpuTracker {
    fn calculate(
        &mut self,
        pid: u32,
        start_time_ticks: u64,
        process_ticks: u64,
        system_ticks: u64,
        logical_cpus: u32,
    ) -> Option<f64> {
        let current = CpuBaseline {
            start_time_ticks,
            process_ticks,
            system_ticks,
        };
        let previous = self.previous.insert(pid, current)?;
        if previous.start_time_ticks != start_time_ticks {
            return None;
        }
        let process_delta = process_ticks.checked_sub(previous.process_ticks)?;
        let system_delta = system_ticks.checked_sub(previous.system_ticks)?;
        if system_delta == 0 {
            return None;
        }
        Some(process_delta as f64 / system_delta as f64 * f64::from(logical_cpus) * 100.0)
    }

    fn retain(&mut self, live_pids: &HashSet<u32>) {
        self.previous.retain(|pid, _| live_pids.contains(pid));
    }
}

pub(crate) fn collect(
    source: &dyn TelemetrySource,
    timestamp_ns: i64,
    read_smaps: bool,
    smaps_budget: usize,
    smaps_cursor: &mut usize,
    cpu_tracker: &mut ProcessCpuTracker,
) -> Result<ProcessCollection, CollectorError> {
    let mut pids = source
        .read_dir_names("/proc")
        .map_err(|source| CollectorError::RequiredRead {
            metric: "processes",
            path: "/proc".to_owned(),
            source,
        })?
        .into_iter()
        .filter_map(|name| name.parse::<u32>().ok())
        .collect::<Vec<_>>();
    pids.sort_unstable();

    let selected_smaps = select_smaps(&pids, read_smaps, smaps_budget, smaps_cursor);
    let system_cpu = source
        .read_to_string("/proc/stat")
        .ok()
        .and_then(|input| parse_system_cpu(&input).ok());
    let mut collection = ProcessCollection::default();
    let mut live_pids = HashSet::new();

    for pid in pids {
        match collect_one(
            source,
            timestamp_ns,
            pid,
            selected_smaps.contains(&pid),
            system_cpu,
            cpu_tracker,
        ) {
            Ok(sample) => {
                live_pids.insert(pid);
                collection.samples.push(sample);
            }
            Err(failure) => match failure {
                ProcessReadFailure::Disappeared => collection.stats.disappeared += 1,
                ProcessReadFailure::PermissionDenied => collection.stats.permission_denied += 1,
                ProcessReadFailure::Invalid => collection.stats.invalid += 1,
            },
        }
    }
    cpu_tracker.retain(&live_pids);
    Ok(collection)
}

fn select_smaps(pids: &[u32], enabled: bool, budget: usize, cursor: &mut usize) -> HashSet<u32> {
    if !enabled || pids.is_empty() || budget == 0 {
        return HashSet::new();
    }
    let count = budget.min(pids.len());
    let selected = (0..count)
        .map(|offset| pids[(*cursor + offset) % pids.len()])
        .collect();
    *cursor = (*cursor + count) % pids.len();
    selected
}

fn collect_one(
    source: &dyn TelemetrySource,
    timestamp_ns: i64,
    pid: u32,
    read_smaps: bool,
    system_cpu: Option<(u64, u32)>,
    cpu_tracker: &mut ProcessCpuTracker,
) -> Result<ProcessSample, ProcessReadFailure> {
    let stat_text = read_process_file(source, pid, "stat")?;
    let stat = parse_stat(&stat_text).map_err(|_| ProcessReadFailure::Invalid)?;
    if stat.pid != pid {
        return Err(ProcessReadFailure::Invalid);
    }
    let status = read_process_file(source, pid, "status")
        .and_then(|value| parse_status(&value).map_err(|_| ProcessReadFailure::Invalid))?;
    let io = optional_process_file(source, pid, "io")
        .and_then(|value| {
            value
                .map(|text| parse_io(&text).map_err(|_| ProcessReadFailure::Invalid))
                .transpose()
        })
        .unwrap_or(None);
    let cgroup_path = optional_process_file(source, pid, "cgroup")
        .ok()
        .flatten()
        .and_then(|text| parse_cgroup(&text));
    let smaps = if read_smaps {
        optional_process_file(source, pid, "smaps_rollup")
            .ok()
            .flatten()
            .and_then(|text| parse_smaps_rollup(&text).ok())
    } else {
        None
    };
    let cpu_percent = system_cpu.and_then(|(system_ticks, logical_cpus)| {
        cpu_tracker.calculate(
            pid,
            stat.start_time_ticks,
            stat.process_ticks,
            system_ticks,
            logical_cpus,
        )
    });
    let rss_from_stat = u64::try_from(stat.rss_pages)
        .ok()
        .and_then(|pages| pages.checked_mul(PAGE_SIZE_BYTES));

    let executable = source
        .read_link(&format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned());

    Ok(ProcessSample {
        timestamp_ns,
        pid,
        executable,
        executable_name: Some(stat.executable_name),
        parent_pid: Some(stat.parent_pid),
        process_group_id: Some(stat.process_group_id),
        session_id: Some(stat.session_id),
        tty_nr: Some(stat.tty_nr),
        foreground_process_group_id: Some(stat.foreground_process_group_id),
        start_time_ticks: Some(stat.start_time_ticks),
        cgroup_path,
        rss_bytes: status.rss_bytes.or(rss_from_stat),
        pss_bytes: smaps.as_ref().map(|value| value.pss_bytes),
        uss_bytes: smaps.as_ref().and_then(|value| value.uss_bytes),
        swap_bytes: status.swap_bytes,
        minor_faults: Some(stat.minor_faults),
        major_faults: Some(stat.major_faults),
        cpu_percent,
        io_read_bytes: io.as_ref().and_then(|value| value.read_bytes),
        io_write_bytes: io.as_ref().and_then(|value| value.write_bytes),
    })
}

fn read_process_file(
    source: &dyn TelemetrySource,
    pid: u32,
    name: &str,
) -> Result<String, ProcessReadFailure> {
    source
        .read_to_string(&format!("/proc/{pid}/{name}"))
        .map_err(|error| classify_process_io(&error))
}

fn optional_process_file(
    source: &dyn TelemetrySource,
    pid: u32,
    name: &str,
) -> Result<Option<String>, ProcessReadFailure> {
    match read_process_file(source, pid, name) {
        Ok(value) => Ok(Some(value)),
        Err(ProcessReadFailure::Disappeared | ProcessReadFailure::PermissionDenied) => Ok(None),
        Err(failure) => Err(failure),
    }
}

fn parse_stat(input: &str) -> Result<ParsedStat, CollectorError> {
    let open = input
        .find('(')
        .ok_or_else(|| CollectorError::invalid("process_stat", "missing `(`"))?;
    let close = input
        .rfind(')')
        .ok_or_else(|| CollectorError::invalid("process_stat", "missing `)`"))?;
    if close <= open {
        return Err(CollectorError::invalid(
            "process_stat",
            "invalid comm field",
        ));
    }
    let pid = input[..open].trim().parse::<u32>().map_err(|error| {
        CollectorError::invalid("process_stat", format!("invalid PID: {error}"))
    })?;
    let executable_name = input[open + 1..close].to_owned();
    let fields = input[close + 1..].split_whitespace().collect::<Vec<_>>();
    let value = |index: usize, name: &str| -> Result<u64, CollectorError> {
        fields
            .get(index)
            .ok_or_else(|| CollectorError::invalid("process_stat", format!("missing `{name}`")))?
            .parse::<u64>()
            .map_err(|error| {
                CollectorError::invalid("process_stat", format!("invalid `{name}`: {error}"))
            })
    };
    let user_ticks = value(11, "utime")?;
    let system_ticks = value(12, "stime")?;
    let rss_pages = fields
        .get(21)
        .ok_or_else(|| CollectorError::invalid("process_stat", "missing `rss`"))?
        .parse::<i64>()
        .map_err(|error| {
            CollectorError::invalid("process_stat", format!("invalid `rss`: {error}"))
        })?;
    Ok(ParsedStat {
        pid,
        executable_name,
        parent_pid: u32::try_from(value(1, "ppid")?)
            .map_err(|_| CollectorError::invalid("process_stat", "`ppid` overflows u32"))?,
        process_group_id: fields
            .get(2)
            .ok_or_else(|| CollectorError::invalid("process_stat", "missing `pgrp`"))?
            .parse()
            .map_err(|error| {
                CollectorError::invalid("process_stat", format!("invalid `pgrp`: {error}"))
            })?,
        session_id: fields
            .get(3)
            .ok_or_else(|| CollectorError::invalid("process_stat", "missing `session`"))?
            .parse()
            .map_err(|error| {
                CollectorError::invalid("process_stat", format!("invalid `session`: {error}"))
            })?,
        tty_nr: fields
            .get(4)
            .ok_or_else(|| CollectorError::invalid("process_stat", "missing `tty_nr`"))?
            .parse()
            .map_err(|error| {
                CollectorError::invalid("process_stat", format!("invalid `tty_nr`: {error}"))
            })?,
        foreground_process_group_id: fields
            .get(5)
            .ok_or_else(|| CollectorError::invalid("process_stat", "missing `tpgid`"))?
            .parse()
            .map_err(|error| {
                CollectorError::invalid("process_stat", format!("invalid `tpgid`: {error}"))
            })?,
        minor_faults: value(7, "minflt")?,
        major_faults: value(9, "majflt")?,
        process_ticks: user_ticks
            .checked_add(system_ticks)
            .ok_or_else(|| CollectorError::invalid("process_stat", "CPU ticks overflow"))?,
        start_time_ticks: value(19, "starttime")?,
        rss_pages,
    })
}

#[derive(Debug)]
struct StatusValues {
    rss_bytes: Option<u64>,
    swap_bytes: Option<u64>,
}

fn parse_status(input: &str) -> Result<StatusValues, CollectorError> {
    Ok(StatusValues {
        rss_bytes: parse_kib_field("process_status", input, "VmRSS")?,
        swap_bytes: parse_kib_field("process_status", input, "VmSwap")?,
    })
}

#[derive(Debug)]
struct IoValues {
    read_bytes: Option<u64>,
    write_bytes: Option<u64>,
}

fn parse_io(input: &str) -> Result<IoValues, CollectorError> {
    Ok(IoValues {
        read_bytes: parse_plain_field("process_io", input, "read_bytes")?,
        write_bytes: parse_plain_field("process_io", input, "write_bytes")?,
    })
}

#[derive(Debug)]
struct SmapsValues {
    pss_bytes: u64,
    uss_bytes: Option<u64>,
}

fn parse_smaps_rollup(input: &str) -> Result<SmapsValues, CollectorError> {
    let pss_bytes = parse_kib_field("smaps_rollup", input, "Pss")?
        .ok_or_else(|| CollectorError::invalid("smaps_rollup", "missing `Pss`"))?;
    let clean = parse_kib_field("smaps_rollup", input, "Private_Clean")?;
    let dirty = parse_kib_field("smaps_rollup", input, "Private_Dirty")?;
    let uss_bytes = match (clean, dirty) {
        (Some(clean), Some(dirty)) => clean.checked_add(dirty),
        _ => None,
    };
    Ok(SmapsValues {
        pss_bytes,
        uss_bytes,
    })
}

fn parse_kib_field(
    metric: &'static str,
    input: &str,
    key: &str,
) -> Result<Option<u64>, CollectorError> {
    let Some(raw) = find_field(input, key) else {
        return Ok(None);
    };
    let fields = raw.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 2 || fields[1] != "kB" {
        return Err(CollectorError::invalid(
            metric,
            format!("`{key}` must contain a kB value"),
        ));
    }
    let value = fields[0]
        .parse::<u64>()
        .map_err(|error| CollectorError::invalid(metric, format!("invalid `{key}`: {error}")))?;
    value
        .checked_mul(1024)
        .map(Some)
        .ok_or_else(|| CollectorError::invalid(metric, format!("`{key}` overflows bytes")))
}

fn parse_plain_field(
    metric: &'static str,
    input: &str,
    key: &str,
) -> Result<Option<u64>, CollectorError> {
    find_field(input, key)
        .map(|raw| {
            raw.trim().parse::<u64>().map_err(|error| {
                CollectorError::invalid(metric, format!("invalid `{key}`: {error}"))
            })
        })
        .transpose()
}

fn find_field<'a>(input: &'a str, key: &str) -> Option<&'a str> {
    input.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name.trim() == key).then_some(value)
    })
}

fn parse_cgroup(input: &str) -> Option<String> {
    let paths = input
        .lines()
        .filter_map(|line| line.splitn(3, ':').nth(2))
        .filter(|path| !path.trim().is_empty())
        .collect::<Vec<_>>();
    (!paths.is_empty()).then(|| paths.join(";"))
}

fn parse_system_cpu(input: &str) -> Result<(u64, u32), CollectorError> {
    let total = input
        .lines()
        .find(|line| line.starts_with("cpu "))
        .ok_or_else(|| CollectorError::invalid("proc_stat", "aggregate CPU line is missing"))?
        .split_whitespace()
        .skip(1)
        .try_fold(0_u64, |sum, raw| {
            let value = raw.parse::<u64>().map_err(|error| {
                CollectorError::invalid("proc_stat", format!("invalid CPU tick: {error}"))
            })?;
            sum.checked_add(value)
                .ok_or_else(|| CollectorError::invalid("proc_stat", "CPU tick total overflow"))
        })?;
    let logical = input
        .lines()
        .filter(|line| {
            line.strip_prefix("cpu")
                .and_then(|rest| rest.split_whitespace().next())
                .is_some_and(|id| !id.is_empty() && id.chars().all(|value| value.is_ascii_digit()))
        })
        .count();
    let logical = u32::try_from(logical.max(1))
        .map_err(|_| CollectorError::invalid("proc_stat", "logical CPU count overflows"))?;
    Ok((total, logical))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FsSource, TelemetrySource};
    use std::fs;
    use std::io;
    use tempfile::tempdir;

    fn process_stat(pid: u32, minflt: u64, majflt: u64, ticks: u64, start: u64) -> String {
        format!("{pid} (fixture proc) S 1 1 1 0 0 0 {minflt} 0 {majflt} 0 {ticks} 0 0 0 20 0 1 0 {start} 0 2\n")
    }

    #[test]
    fn complete_process_has_memory_fault_io_cgroup_pss_and_uss() {
        let root = tempdir().expect("tempdir");
        let proc = root.path().join("proc/42");
        fs::create_dir_all(&proc).expect("proc");
        fs::write(proc.join("stat"), process_stat(42, 3, 4, 5, 100)).expect("stat");
        fs::write(proc.join("status"), "VmRSS:\t10 kB\nVmSwap:\t2 kB\n").expect("status");
        fs::write(proc.join("io"), "read_bytes: 11\nwrite_bytes: 12\n").expect("io");
        fs::write(proc.join("cgroup"), "0::/user.slice/test\n").expect("cgroup");
        fs::write(
            proc.join("smaps_rollup"),
            "Pss: 8 kB\nPrivate_Clean: 2 kB\nPrivate_Dirty: 3 kB\n",
        )
        .expect("smaps");
        fs::write(root.path().join("proc/stat"), "cpu 1 2 3 4\ncpu0 1 2 3 4\n").expect("cpu");
        let source = FsSource::rooted_at(root.path());
        let mut cursor = 0;
        let mut tracker = ProcessCpuTracker::default();
        let result = collect(&source, 9, true, 1, &mut cursor, &mut tracker).expect("processes");
        let sample = &result.samples[0];
        assert_eq!(sample.rss_bytes, Some(10 * 1024));
        assert_eq!(sample.swap_bytes, Some(2 * 1024));
        assert_eq!(sample.pss_bytes, Some(8 * 1024));
        assert_eq!(sample.uss_bytes, Some(5 * 1024));
        assert_eq!(sample.minor_faults, Some(3));
        assert_eq!(sample.major_faults, Some(4));
        assert_eq!(sample.io_read_bytes, Some(11));
        assert_eq!(sample.io_write_bytes, Some(12));
        assert_eq!(sample.cgroup_path.as_deref(), Some("/user.slice/test"));
        assert_eq!(sample.cpu_percent, None);
        assert_eq!(sample.executable_name.as_deref(), Some("fixture proc"));
        assert_eq!(sample.parent_pid, Some(1));
        assert_eq!(sample.process_group_id, Some(1));
        assert_eq!(sample.session_id, Some(1));
        assert_eq!(sample.tty_nr, Some(0));
        assert_eq!(sample.foreground_process_group_id, Some(0));
        assert_eq!(sample.start_time_ticks, Some(100));
    }

    #[test]
    fn absent_smaps_is_optional() {
        let root = tempdir().expect("tempdir");
        let proc = root.path().join("proc/1");
        fs::create_dir_all(&proc).expect("proc");
        fs::write(proc.join("stat"), process_stat(1, 0, 0, 0, 1)).expect("stat");
        fs::write(proc.join("status"), "VmRSS: 1 kB\n").expect("status");
        let result = collect(
            &FsSource::rooted_at(root.path()),
            1,
            true,
            1,
            &mut 0,
            &mut ProcessCpuTracker::default(),
        )
        .expect("processes");
        assert_eq!(result.samples[0].pss_bytes, None);
    }

    #[test]
    fn partially_readable_process_is_skipped_without_stopping_collection() {
        let root = tempdir().expect("tempdir");
        let proc = root.path().join("proc/7");
        fs::create_dir_all(&proc).expect("proc");
        fs::write(proc.join("stat"), "7 (partial) S 1\n").expect("partial stat");
        fs::write(proc.join("status"), "VmRSS: 1 kB\n").expect("status");
        let result = collect(
            &FsSource::rooted_at(root.path()),
            1,
            false,
            0,
            &mut 0,
            &mut ProcessCpuTracker::default(),
        )
        .expect("collection continues");
        assert!(result.samples.is_empty());
        assert_eq!(result.stats.invalid, 1);
    }

    struct FailingSource {
        kind: io::ErrorKind,
    }

    impl TelemetrySource for FailingSource {
        fn read_to_string(&self, _path: &str) -> io::Result<String> {
            Err(io::Error::new(self.kind, "simulated"))
        }

        fn read_dir_names(&self, _path: &str) -> io::Result<Vec<String>> {
            Ok(vec!["9".to_owned()])
        }
    }

    #[test]
    fn disappearing_and_permission_denied_processes_are_counted() {
        for (kind, disappeared, permission_denied) in [
            (io::ErrorKind::NotFound, 1, 0),
            (io::ErrorKind::PermissionDenied, 0, 1),
        ] {
            let result = collect(
                &FailingSource { kind },
                1,
                false,
                0,
                &mut 0,
                &mut ProcessCpuTracker::default(),
            )
            .expect("collection continues");
            assert_eq!(result.stats.disappeared, disappeared);
            assert_eq!(result.stats.permission_denied, permission_denied);
        }
    }

    #[test]
    fn cpu_requires_two_samples_and_pid_reuse_resets_baseline() {
        let mut tracker = ProcessCpuTracker::default();
        assert_eq!(tracker.calculate(1, 10, 100, 1000, 4), None);
        assert_eq!(tracker.calculate(1, 10, 110, 1100, 4), Some(40.0));
        assert_eq!(tracker.calculate(1, 11, 120, 1200, 4), None);
    }
}
