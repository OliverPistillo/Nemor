#![forbid(unsafe_code)]

use common::LinuxPaths;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tempfile::TempDir;

/// Full source commit embedded by the shared Nemor build-provenance stamp.
pub const BUILD_GIT_HEAD: &str = env!("NEMOR_BUILD_GIT_HEAD");

#[derive(Debug, Clone)]
pub struct ClassifierFixture {
    pub system: collector::SystemSample,
    pub processes: Vec<collector::ProcessSample>,
    pub game_executables: Vec<String>,
}

impl ClassifierFixture {
    #[must_use]
    pub fn idle() -> Self {
        Self::new(Vec::new())
    }

    #[must_use]
    pub fn desktop() -> Self {
        let mut process = classification_process(10, "plasmashell", 10_000);
        process.tty_nr = Some(1);
        process.foreground_process_group_id = process.process_group_id;
        Self::new(vec![process])
    }

    #[must_use]
    pub fn browser_heavy() -> Self {
        let processes = (1..=8)
            .map(|pid| classification_process(pid, "firefox", 25_000_000))
            .collect();
        Self::new(processes)
    }

    #[must_use]
    pub fn browser_light() -> Self {
        Self::new(vec![classification_process(10, "firefox", 10_000_000)])
    }

    #[must_use]
    pub fn development() -> Self {
        Self::new(vec![
            classification_process(10, "code", 10_000),
            classification_process(11, "rust-analyzer", 10_000),
        ])
    }

    #[must_use]
    pub fn gaming() -> Self {
        let mut fixture = Self::new(vec![classification_process(
            10,
            "fixture-native-game",
            20_000,
        )]);
        fixture.game_executables = vec!["fixture-native-game".to_owned()];
        fixture
    }

    #[must_use]
    pub fn steam_open_without_game() -> Self {
        Self::new(vec![classification_process(10, "steam", 10_000)])
    }

    #[must_use]
    pub fn steam_game() -> Self {
        let steam = classification_process(10, "steam", 10_000);
        let mut game = classification_process(11, "fixture-game", 20_000);
        game.parent_pid = Some(10);
        game.cgroup_path = Some("/user.slice/steam_app_123.scope".to_owned());
        Self::new(vec![steam, game])
    }

    #[must_use]
    pub fn proton_game() -> Self {
        let mut proton = classification_process(10, "proton", 20_000);
        proton.cgroup_path = Some("/user.slice/steam_app_456.scope".to_owned());
        Self::new(vec![proton])
    }

    #[must_use]
    pub fn wine_non_game() -> Self {
        Self::new(vec![classification_process(10, "wine64", 10_000)])
    }

    #[must_use]
    pub fn gamescope_game() -> Self {
        let gamescope = classification_process(10, "gamescope", 10_000);
        let mut game = classification_process(11, "fixture-child", 20_000);
        game.parent_pid = Some(10);
        Self::new(vec![gamescope, game])
    }

    #[must_use]
    pub fn gaming_background_heavy() -> Self {
        let mut fixture = Self::gaming();
        fixture
            .processes
            .push(classification_process(11, "firefox", 250_000_000));
        fixture
    }

    #[must_use]
    pub fn virtualization() -> Self {
        Self::new(vec![classification_process(
            10,
            "qemu-system-x86_64",
            200_000_000,
        )])
    }

    #[must_use]
    pub fn memory_pressure() -> Self {
        let mut fixture = Self::desktop();
        fixture.system.mem_available_bytes = 100_000_000;
        fixture
    }

    #[must_use]
    pub fn critical_pressure() -> Self {
        let mut fixture = Self::desktop();
        fixture.system.mem_available_bytes = 50_000_000;
        fixture
    }

    #[must_use]
    pub fn ambiguous() -> Self {
        Self::new(vec![classification_process(10, "unrecognized", 10_000)])
    }

    #[must_use]
    pub fn critical_process() -> Self {
        Self::new(vec![classification_process(1, "systemd", 10_000)])
    }

    #[must_use]
    pub fn pid_reuse() -> Self {
        let first = classification_process(10, "first-process", 10_000);
        let mut replacement = classification_process(10, "replacement-process", 10_000);
        replacement.start_time_ticks = Some(999);
        Self::new(vec![first, replacement])
    }

    #[must_use]
    pub fn process_disappeared() -> Self {
        Self::new(Vec::new())
    }

    #[must_use]
    pub fn foreground_tty() -> Self {
        let mut process = classification_process(10, "konsole", 10_000);
        process.tty_nr = Some(1);
        process.foreground_process_group_id = process.process_group_id;
        Self::new(vec![process])
    }

    #[must_use]
    pub fn foreground_unknown() -> Self {
        Self::new(vec![classification_process(10, "konsole", 10_000)])
    }

    fn new(processes: Vec<collector::ProcessSample>) -> Self {
        Self {
            system: classification_system(),
            processes,
            game_executables: Vec::new(),
        }
    }
}

fn classification_process(pid: u32, name: &str, rss_bytes: u64) -> collector::ProcessSample {
    collector::ProcessSample {
        timestamp_ns: 1,
        pid,
        executable: Some(format!("/usr/bin/{name}")),
        executable_name: Some(name.to_owned()),
        parent_pid: Some(1),
        process_group_id: Some(i32::try_from(pid).expect("fixture PID")),
        session_id: Some(1),
        tty_nr: None,
        foreground_process_group_id: None,
        start_time_ticks: Some(u64::from(pid)),
        cgroup_path: Some("/user.slice/app.scope".to_owned()),
        rss_bytes: Some(rss_bytes),
        pss_bytes: None,
        uss_bytes: None,
        swap_bytes: Some(0),
        minor_faults: Some(0),
        major_faults: Some(0),
        cpu_percent: Some(1.0),
        io_read_bytes: Some(0),
        io_write_bytes: Some(0),
    }
}

fn classification_system() -> collector::SystemSample {
    collector::SystemSample {
        timestamp_ns: 1,
        mem_total_bytes: 1_000_000_000,
        mem_available_bytes: 800_000_000,
        anon_bytes: None,
        file_cache_bytes: None,
        slab_bytes: None,
        swap_used_bytes: Some(0),
        swap_in_pages: Some(0),
        swap_out_pages: Some(0),
        major_faults: Some(0),
        minor_faults: Some(0),
        pgscan: Some(0),
        pgsteal: Some(0),
        workingset_refault: Some(0),
        psi_memory: None,
        psi_cpu: None,
        psi_io: None,
        swap: collector::swap::SwapState {
            entries: Vec::new(),
            configuration: collector::swap::SwapConfiguration::None,
        },
        zram: collector::zram::ZramState {
            available: false,
            devices: Vec::new(),
        },
        zswap: collector::zswap::ZswapState {
            available: false,
            enabled: None,
            stored_pages: None,
            pool_bytes: None,
        },
        capabilities_unavailable: Vec::new(),
    }
}

pub struct LinuxFixture {
    directory: TempDir,
    config_path: PathBuf,
    database_path: PathBuf,
}

impl LinuxFixture {
    pub fn compatible() -> io::Result<Self> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        write_fixture(root, "etc/machine-id", "fixture-machine-id\n")?;
        write_fixture(
            root,
            "etc/os-release",
            "ID=cachyos\nVERSION_ID=\"fixture\"\n",
        )?;
        write_fixture(
            root,
            "proc/meminfo",
            "MemTotal: 16384 kB\nMemAvailable: 12000 kB\nAnonPages: 2048 kB\nCached: 1024 kB\nBuffers: 128 kB\nSlab: 256 kB\nSwapTotal: 2048 kB\nSwapFree: 1536 kB\n",
        )?;
        write_fixture(
            root,
            "proc/vmstat",
            "pswpin 1\npswpout 2\npgfault 100\npgmajfault 3\npgscan_kswapd 4\npgscan_direct 5\npgsteal_kswapd 6\npgsteal_direct 7\nworkingset_refault_anon 8\nworkingset_refault_file 9\n",
        )?;
        write_fixture(
            root,
            "proc/stat",
            "cpu 100 0 50 1000 0 0 0 0 0 0\ncpu0 100 0 50 1000 0 0 0 0 0 0\n",
        )?;
        write_fixture(
            root,
            "proc/swaps",
            "Filename Type Size Used Priority\n/dev/zram0 partition 1024 128 100\n",
        )?;
        write_fixture(root, "proc/sys/kernel/osrelease", "6.12-fixture\n")?;
        write_fixture(
            root,
            "proc/pressure/memory",
            "some avg10=0.10 avg60=0.20 avg300=0.30 total=100\nfull avg10=0.01 avg60=0.02 avg300=0.03 total=10\n",
        )?;
        write_fixture(
            root,
            "proc/pressure/cpu",
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        )?;
        write_fixture(
            root,
            "proc/pressure/io",
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        )?;
        write_fixture(
            root,
            "proc/101/stat",
            "101 (fixture process) S 1 1 1 0 0 0 2 0 1 0 5 3 0 0 20 0 1 0 100 0 4\n",
        )?;
        write_fixture(
            root,
            "proc/101/status",
            "Name:\tfixture\nVmRSS:\t64 kB\nVmSwap:\t4 kB\n",
        )?;
        write_fixture(root, "proc/101/io", "read_bytes: 4096\nwrite_bytes: 2048\n")?;
        write_fixture(root, "proc/101/cgroup", "0::/user.slice/fixture.scope\n")?;
        write_fixture(
            root,
            "proc/101/smaps_rollup",
            "Pss: 48 kB\nPrivate_Clean: 8 kB\nPrivate_Dirty: 16 kB\n",
        )?;
        write_fixture(root, "sys/block/zram0/disksize", "1048576\n")?;
        write_fixture(
            root,
            "sys/block/zram0/comp_algorithm",
            "lzo-rle [zstd] lz4\n",
        )?;
        write_fixture(
            root,
            "sys/block/zram0/mm_stat",
            "524288 262144 300000 0 0\n",
        )?;
        write_fixture(root, "sys/module/zswap/parameters/enabled", "Y\n")?;
        write_fixture(root, "sys/kernel/debug/zswap/stored_pages", "12\n")?;
        write_fixture(root, "sys/kernel/debug/zswap/pool_total_size", "49152\n")?;
        write_fixture(root, "sys/fs/cgroup/cgroup.controllers", "cpu memory io\n")?;

        let database_path = root.join("state/nemor.db");
        fs::create_dir_all(
            database_path
                .parent()
                .expect("fixture database path has a parent"),
        )?;
        let config_path = root.join("config.toml");
        let database_toml = database_path.to_string_lossy().replace('\\', "/");
        let config = include_str!("../../../config/default.toml")
            .replace("/var/lib/nemor/nemor.db", &database_toml);
        fs::write(&config_path, config)?;

        Ok(Self {
            directory,
            config_path,
            database_path,
        })
    }

    pub fn telemetry_complete() -> io::Result<Self> {
        Self::compatible()
    }

    pub fn telemetry_partial() -> io::Result<Self> {
        let fixture = Self::compatible()?;
        fixture.remove("proc/101/smaps_rollup")?;
        fixture.remove("sys/block/zram0/mm_stat")?;
        fixture.remove("sys/kernel/debug/zswap/stored_pages")?;
        fixture.remove("sys/kernel/debug/zswap/pool_total_size")?;
        Ok(fixture)
    }

    pub fn telemetry_malformed() -> io::Result<Self> {
        let fixture = Self::compatible()?;
        fixture.write("proc/meminfo", "MemTotal: invalid kB\nMemAvailable: 1 kB\n")?;
        fixture.write(
            "proc/pressure/memory",
            "some avg10=invalid avg60=0 avg300=0 total=0\n",
        )?;
        Ok(fixture)
    }

    pub fn telemetry_without_capabilities() -> io::Result<Self> {
        let fixture = Self::compatible()?;
        for relative in [
            "proc/pressure/memory",
            "proc/pressure/cpu",
            "proc/pressure/io",
            "sys/block/zram0/disksize",
            "sys/block/zram0/comp_algorithm",
            "sys/block/zram0/mm_stat",
            "sys/module/zswap/parameters/enabled",
            "sys/kernel/debug/zswap/stored_pages",
            "sys/kernel/debug/zswap/pool_total_size",
        ] {
            fixture.remove(relative)?;
        }
        Ok(fixture)
    }

    pub fn root(&self) -> &Path {
        self.directory.path()
    }

    pub fn paths(&self) -> LinuxPaths {
        LinuxPaths::new(self.root())
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub fn remove(&self, relative: &str) -> io::Result<()> {
        fs::remove_file(self.root().join(relative))
    }

    pub fn write(&self, relative: &str, contents: &str) -> io::Result<()> {
        write_fixture(self.root(), relative, contents)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileState {
    pub bytes: Vec<u8>,
    pub length: u64,
    pub modified: Option<SystemTime>,
}

pub fn snapshot_files(root: &Path) -> io::Result<BTreeMap<PathBuf, FileState>> {
    let mut snapshot = BTreeMap::new();
    visit(root, root, &mut snapshot)?;
    Ok(snapshot)
}

fn visit(
    root: &Path,
    directory: &Path,
    snapshot: &mut BTreeMap<PathBuf, FileState>,
) -> io::Result<()> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            visit(root, &path, snapshot)?;
        } else if metadata.is_file() {
            snapshot.insert(
                path.strip_prefix(root)
                    .expect("visited path is within fixture")
                    .to_path_buf(),
                FileState {
                    bytes: fs::read(&path)?,
                    length: metadata.len(),
                    modified: metadata.modified().ok(),
                },
            );
        }
    }
    Ok(())
}

fn write_fixture(root: &Path, relative: &str, contents: &str) -> io::Result<()> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use collector::{FsSource, SystemCollector};

    #[test]
    fn complete_fixture_drives_system_and_process_collectors() {
        let fixture = LinuxFixture::telemetry_complete().expect("fixture");
        let mut collector = SystemCollector::with_source(FsSource::rooted_at(fixture.root()));
        let system = collector.sample_system(1).expect("system");
        assert_eq!(system.mem_total_bytes, 16_384 * 1024);
        assert!(system.zram.available);
        assert!(system.zswap.available);
        let processes = collector.sample_processes(1, true, 32).expect("processes");
        assert_eq!(processes.samples.len(), 1);
        assert_eq!(processes.samples[0].pid, 101);
        assert!(processes.samples[0].pss_bytes.is_some());
    }

    #[test]
    fn partial_malformed_and_missing_capability_fixtures_are_distinct() {
        let partial = LinuxFixture::telemetry_partial().expect("partial");
        let mut collector = SystemCollector::with_source(FsSource::rooted_at(partial.root()));
        assert!(collector.sample_system(1).is_ok());
        let processes = collector
            .sample_processes(1, true, 32)
            .expect("partial processes");
        assert_eq!(processes.samples[0].pss_bytes, None);

        let malformed = LinuxFixture::telemetry_malformed().expect("malformed");
        assert!(
            SystemCollector::with_source(FsSource::rooted_at(malformed.root()))
                .sample_system(1)
                .is_err()
        );

        let missing = LinuxFixture::telemetry_without_capabilities().expect("missing");
        let system = SystemCollector::with_source(FsSource::rooted_at(missing.root()))
            .sample_system(1)
            .expect("missing optional capabilities");
        assert!(system.psi_memory.is_none());
        assert!(!system.zswap.available);
    }

    #[test]
    fn classifier_fixtures_cover_all_workloads_and_ambiguity() {
        for (fixture, expected) in [
            (
                ClassifierFixture::idle(),
                Some(classifier::WorkloadClass::Idle),
            ),
            (
                ClassifierFixture::desktop(),
                Some(classifier::WorkloadClass::Desktop),
            ),
            (
                ClassifierFixture::browser_heavy(),
                Some(classifier::WorkloadClass::BrowserHeavy),
            ),
            (
                ClassifierFixture::development(),
                Some(classifier::WorkloadClass::Development),
            ),
            (
                ClassifierFixture::gaming(),
                Some(classifier::WorkloadClass::Gaming),
            ),
            (
                ClassifierFixture::gaming_background_heavy(),
                Some(classifier::WorkloadClass::GamingBackgroundHeavy),
            ),
            (
                ClassifierFixture::virtualization(),
                Some(classifier::WorkloadClass::Virtualization),
            ),
            (
                ClassifierFixture::memory_pressure(),
                Some(classifier::WorkloadClass::MemoryPressure),
            ),
            (
                ClassifierFixture::critical_pressure(),
                Some(classifier::WorkloadClass::CriticalPressure),
            ),
            (ClassifierFixture::ambiguous(), None),
        ] {
            let mut config =
                common::Config::from_toml(include_str!("../../../config/default.toml"))
                    .expect("config");
            config.classification.game_executables = fixture.game_executables;
            let mut classifier =
                classifier::Classifier::new(config.classification, config.pressure);
            let result = classifier.classify(1, Some(&fixture.system), &fixture.processes);
            assert_eq!(result.processes.len(), fixture.processes.len());
            assert_eq!(result.outcome.class(), expected);
            if let classifier::ClassificationOutcome::Classified(decision) = result.outcome {
                assert!(decision.confidence >= 0.65);
                assert!(!decision.explanation.evidence.is_empty());
                assert_eq!(decision.explanation.rule_version, classifier::RULE_VERSION);
            }
        }
    }

    #[test]
    fn specialized_classifier_fixtures_cover_detector_edge_cases() {
        for fixture in [
            ClassifierFixture::browser_light(),
            ClassifierFixture::steam_open_without_game(),
            ClassifierFixture::steam_game(),
            ClassifierFixture::proton_game(),
            ClassifierFixture::wine_non_game(),
            ClassifierFixture::gamescope_game(),
            ClassifierFixture::critical_process(),
            ClassifierFixture::pid_reuse(),
            ClassifierFixture::process_disappeared(),
            ClassifierFixture::foreground_tty(),
            ClassifierFixture::foreground_unknown(),
        ] {
            assert_eq!(fixture.system.timestamp_ns, 1);
        }
    }
}
