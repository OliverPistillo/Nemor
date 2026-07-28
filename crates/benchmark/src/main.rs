#![forbid(unsafe_code)]

use anyhow::Result;
use clap::{Parser, Subcommand};
use nemor_benchmark::{
    required_scenarios, safe_smoke, BuildProvenance, EnvironmentFingerprint, ScenarioId,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "nemor-benchmark",
    about = "Explicit safe benchmark runner for Nemor"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Provenance {
        #[arg(long)]
        json: bool,
    },
    Preflight {
        #[arg(long)]
        json: bool,
    },
    CgroupPreflight {
        #[arg(long)]
        json: bool,
    },
    SystemdPreflight {
        #[arg(long)]
        json: bool,
    },
    Plan {
        scenario: String,
        #[arg(long)]
        json: bool,
    },
    Smoke {
        #[arg(long)]
        scenario: String,
        #[arg(long, default_value_t = 8 * 1024 * 1024)]
        bytes: u64,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        report_dir: PathBuf,
    },
    ValidateCgroup {
        #[arg(long, default_value = "config/default.toml")]
        config: PathBuf,
        #[arg(long, default_value = "/tmp/nemor-phase10-checkpoint2.sqlite")]
        database: PathBuf,
        #[arg(long, default_value = "/tmp/nemor-phase10-checkpoint2-reports")]
        report_dir: PathBuf,
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        worker_bytes: u64,
    },
    #[command(hide = true)]
    WorkerHold {
        #[arg(long)]
        bytes: u64,
        #[arg(long)]
        control_dir: PathBuf,
    },
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(code) => std::process::ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<i32> {
    match Cli::parse().command {
        Command::Provenance { json } => {
            let provenance = BuildProvenance::capture()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&provenance)?);
            } else {
                println!(
                    "git_head={} git_dirty={} source_state_id={} binary_sha256={} build_profile={}",
                    provenance.git_head,
                    provenance.git_dirty,
                    provenance.source_state_id,
                    provenance.binary_sha256,
                    provenance.build_profile
                );
            }
        }
        Command::Preflight { json } => {
            let fingerprint = EnvironmentFingerprint::capture("runner-preflight")?;
            if json {
                println!("{}", serde_json::to_string_pretty(&fingerprint)?);
            } else {
                println!(
                    "kernel={} ram_bytes={} cgroup_v2={} psi={} damon={} ksm={}",
                    fingerprint.kernel_release,
                    fingerprint.total_ram_bytes,
                    fingerprint.cgroup_v2,
                    fingerprint.psi,
                    fingerprint.damon,
                    fingerprint.ksm
                );
            }
        }
        Command::CgroupPreflight { json } => {
            let cgroup = std::fs::read_to_string("/proc/self/cgroup")?;
            let relative = cgroup
                .lines()
                .find_map(|line| line.strip_prefix("0::"))
                .ok_or_else(|| anyhow::anyhow!("unified cgroup path unavailable"))?;
            let parent = PathBuf::from("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
            let evidence = nemor_benchmark::harness::inspect_cgroup_parent(&parent)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&evidence)?);
            } else {
                println!(
                    "parent_role={} memory_supported={} memory_enabled_for_children={} usable={} reason={}",
                    evidence.candidate_parent_role,
                    evidence.memory_supported,
                    evidence.memory_enabled_for_children,
                    evidence.parent_usable,
                    evidence.reason
                );
            }
        }
        Command::SystemdPreflight { json } => {
            use nemor_benchmark::systemd::TransientScopeBackend;
            let backend = nemor_benchmark::systemd::SystemdDbusBackend::system()?;
            let evidence = backend.capability()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&evidence)?);
            } else {
                println!(
                    "systemd_version={} system_bus={} transient_scope={} memory_max={} runtime_max={} supported={} reason={}",
                    evidence.systemd_version.as_deref().unwrap_or("unknown"),
                    evidence.system_bus_reachable,
                    evidence.start_transient_unit_available,
                    evidence.transient_memory_max_supported,
                    evidence.transient_runtime_max_supported,
                    evidence.supported,
                    evidence.reason
                );
            }
        }
        Command::Plan { scenario, json } => {
            let scenario: ScenarioId = scenario.parse()?;
            let plan = required_scenarios()
                .into_iter()
                .find(|item| item.scenario_id == scenario)
                .expect("required scenario registry");
            if json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                println!(
                    "{} automation={:?} repetitions={} max_duration_ms={}",
                    plan.scenario_id.as_str(),
                    plan.automation_level,
                    plan.repetition_count,
                    plan.maximum_duration_ms
                );
            }
        }
        Command::Smoke {
            scenario,
            bytes,
            seed,
            database,
            report_dir,
        } => {
            let (report, path) =
                safe_smoke(scenario.parse()?, bytes, seed, &database, &report_dir)?;
            println!(
                "run_id={} valid={} restore_verified={} report={}",
                report.run_id,
                report.valid,
                report.restore_verified,
                path.display()
            );
        }
        Command::ValidateCgroup {
            config,
            database,
            report_dir,
            worker_bytes,
        } => {
            let options = nemor_benchmark::harness::HarnessOptions {
                config,
                database,
                report_dir,
                worker_bytes,
            };
            let (report, path) = nemor_benchmark::harness::run_live(&options)?;
            println!(
                "run_id={} required_gates_passed={} report={}",
                report.run_id,
                report.outcome.required_gates_passed,
                path.display()
            );
            return Ok(report.outcome.exit_code);
        }
        Command::WorkerHold { bytes, control_dir } => {
            nemor_benchmark::harness::run_worker(bytes, &control_dir)?;
        }
    }
    Ok(0)
}
