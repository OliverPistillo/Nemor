#![forbid(unsafe_code)]

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use nemor_benchmark::{
    required_scenarios, safe_smoke, BenchmarkVariant, BuildProvenance, EnvironmentFingerprint,
    ScenarioId,
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
        #[arg(long)]
        require_clean_release: bool,
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
    PerformancePreflight {
        #[arg(long, default_value = "config/default.toml")]
        config: PathBuf,
        #[arg(long)]
        observer_binary: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    PrepareObserverService {
        #[arg(long, default_value = ".")]
        repository: PathBuf,
        #[arg(long, default_value = "config/default.toml")]
        config: PathBuf,
        #[arg(long)]
        observer_binary: PathBuf,
        #[arg(long)]
        prepared_dir: PathBuf,
    },
    ObserverServicePreflight {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    ValidateObserverService {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        report: PathBuf,
    },
    Experiment {
        #[arg(long)]
        scenario: String,
        #[arg(long)]
        variants: String,
        #[arg(long, default_value_t = 3)]
        repetitions: usize,
        #[arg(long)]
        seed: u64,
        #[arg(long, default_value_t = 128 * 1024 * 1024)]
        payload_bytes: u64,
        #[arg(long, default_value = "config/default.toml")]
        config: PathBuf,
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        report_dir: PathBuf,
        #[arg(long)]
        observer_binary: Option<PathBuf>,
        #[arg(long)]
        execute: bool,
    },
    PrepareExperiment {
        #[arg(long, default_value = "synthetic_incompressible")]
        scenario: String,
        #[arg(long, default_value = ".")]
        repository: PathBuf,
        #[arg(long, default_value = "config/default.toml")]
        config: PathBuf,
        #[arg(long)]
        observer_binary: PathBuf,
        #[arg(long)]
        prepared_dir: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, default_value_t = 128 * 1024 * 1024)]
        payload_bytes: u64,
    },
    PreparePressureExperiment {
        #[arg(long, default_value = ".")]
        repository: PathBuf,
        #[arg(long, default_value = "config/default.toml")]
        config: PathBuf,
        #[arg(long)]
        observer_binary: PathBuf,
        #[arg(long)]
        prepared_dir: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 1)]
        seed: u64,
    },
    PrepareCapacityCompatibility {
        #[arg(long, default_value = ".")]
        repository: PathBuf,
        #[arg(long, default_value = "config/default.toml")]
        config: PathBuf,
        #[arg(long)]
        validator_binary: PathBuf,
        #[arg(long)]
        prepared_dir: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    CapacityCompatibilityPreflight {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    ValidateCapacityCompatibility {
        #[arg(long)]
        manifest: PathBuf,
    },
    PrepareCapacityExternalTargetValidation {
        #[arg(long, default_value = ".")]
        repository: PathBuf,
        #[arg(long, default_value = "config/default.toml")]
        config: PathBuf,
        #[arg(long)]
        validator_binary: PathBuf,
        #[arg(long)]
        target_binary: Option<PathBuf>,
        #[arg(long)]
        prepared_dir: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    CapacityExternalTargetPreflight {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    ValidateCapacityExternalTarget {
        #[arg(long)]
        manifest: PathBuf,
    },
    PrepareCapacityComposition {
        #[arg(long, default_value = ".")]
        repository: PathBuf,
        #[arg(long, default_value = "config/default.toml")]
        config: PathBuf,
        #[arg(long)]
        validator_binary: PathBuf,
        #[arg(long)]
        target_binary: Option<PathBuf>,
        #[arg(long)]
        external_target_archive: PathBuf,
        #[arg(long)]
        prepared_dir: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    CapacityCompositionPreflight {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    ExecuteCapacityComposition {
        #[arg(long)]
        manifest: PathBuf,
    },
    PrepareCapacityBenchmark {
        #[arg(long)]
        external_target_archive: PathBuf,
        #[arg(long)]
        composition_archive: PathBuf,
        #[arg(long)]
        prepared_dir: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
    CapacityBenchmarkPreflight {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    ExecuteCapacityBenchmark {
        #[arg(long)]
        manifest: PathBuf,
    },
    CapacityBenchmarkRecoveryPreflight {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    RecoverCapacityBenchmark {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        idempotence_check: bool,
    },
    PressurePreflight {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    ExecutePressureExperiment {
        #[arg(long)]
        manifest: PathBuf,
    },
    ExecuteExperiment {
        #[arg(long)]
        manifest: PathBuf,
    },
    ExperimentPreflight {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    RevalidateExperiment {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        json: bool,
    },
    #[command(hide = true)]
    WorkerHold {
        #[arg(long)]
        bytes: u64,
        #[arg(long, default_value_t = 0)]
        seed: u64,
        #[arg(long, default_value = "compressible")]
        pattern: String,
        #[arg(long)]
        control_dir: PathBuf,
    },
    #[command(hide = true)]
    PressureWorker {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        experiment_id: String,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        seed: u64,
    },
    #[command(hide = true)]
    CapacityExternalTargetWorker {
        #[arg(long)]
        transaction_root: PathBuf,
        #[arg(long)]
        transaction_id: String,
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        creator_pid: u32,
        #[arg(long)]
        creator_start_ticks: u64,
        #[arg(long)]
        preparing_uid: u32,
        #[arg(long)]
        preparing_gid: u32,
        #[arg(long)]
        unit_or_cgroup_identity: String,
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
        Command::Provenance {
            json,
            require_clean_release,
        } => {
            let provenance = BuildProvenance::capture()?;
            let performance_source_eligible = provenance.clean_release_eligible();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "git_head": provenance.git_head,
                        "git_dirty": provenance.git_dirty,
                        "source_state_id": provenance.source_state_id,
                        "binary_sha256": provenance.binary_sha256,
                        "build_profile": provenance.build_profile,
                        "benchmark_schema_version": provenance.benchmark_schema_version,
                        "development_build": provenance.development_build,
                        "performance_source_eligible": performance_source_eligible,
                    }))?
                );
            } else {
                println!(
                    "git_head={} git_dirty={} source_state_id={} binary_sha256={} build_profile={} performance_source_eligible={}",
                    provenance.git_head,
                    provenance.git_dirty,
                    provenance.source_state_id,
                    provenance.binary_sha256,
                    provenance.build_profile,
                    performance_source_eligible
                );
            }
            if require_clean_release && !performance_source_eligible {
                bail!("authoritative provenance rejected dirty or non-release source");
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
                performance_profile: None,
                observer: None,
                worker_seed: 0,
                worker_pattern: nemor_benchmark::SyntheticPattern::Compressible,
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
        Command::PerformancePreflight {
            config,
            observer_binary,
            json,
        } => {
            let loaded = common::LoadedConfig::load(&config)?;
            let executable = std::env::current_exe()?;
            let observer_binary =
                observer_binary.unwrap_or_else(|| executable.with_file_name("nemord"));
            let inputs = nemor_benchmark::performance::ExperimentInputs {
                scenario: nemor_benchmark::performance::CHECKPOINT3A_SCENARIO,
                variants: &[
                    BenchmarkVariant::CachyosBaseline,
                    BenchmarkVariant::NemorObserve,
                ],
                repetitions: 3,
                seed: 1,
                payload_bytes: nemor_benchmark::performance::CHECKPOINT3A_DEFAULT_PAYLOAD_BYTES,
                config_hash: &loaded.sha256,
                benchmark_binary_path: &executable,
                observer_binary_path: &observer_binary,
            };
            let plan = nemor_benchmark::performance::plan_experiment(&inputs)?;
            let foreign =
                nemor_benchmark::performance::detect_nemord_processes(&observer_binary, None);
            let contamination_clear =
                nemor_benchmark::performance::reject_foreign_nemord(&foreign, None).is_ok();
            let output = serde_json::json!({
                "scenario": plan.scenario,
                "comparison_purpose": plan.comparison_purpose,
                "performance_claim_eligible": plan.performance_claim_eligible,
                "provenance": plan.provenance,
                "benchmark_binary": plan.benchmark_binary,
                "observer_binary": plan.observer_binary,
                "foreign_nemord_clear": contamination_clear,
                "execute_allowed": plan.performance_claim_eligible && contamination_clear,
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!(
                    "performance_claim_eligible={} foreign_nemord_clear={} scenario=synthetic_compressible purpose=observer_overhead",
                    plan.performance_claim_eligible, contamination_clear
                );
            }
        }
        Command::PrepareObserverService {
            repository,
            config,
            observer_binary,
            prepared_dir,
        } => {
            let path = nemor_benchmark::observer_service::prepare_observer_manifest(
                &repository,
                &config,
                &observer_binary,
                &prepared_dir,
            )?;
            println!("manifest={}", path.display());
        }
        Command::ObserverServicePreflight { manifest, json } => {
            use nemor_benchmark::observer_service::ObserverServiceBackend;
            let bounded: nemor_benchmark::observer_service::IntegrityBoundManifest =
                serde_json::from_slice(&std::fs::read(&manifest)?)?;
            bounded.verify(&manifest)?;
            let backend =
                nemor_benchmark::observer_service::SystemdObserverServiceBackend::system()?;
            let systemd_version = backend.systemd_version()?;
            if let Err(error) = backend.preflight() {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "systemd_version": systemd_version,
                            "systemd_api_capable": false,
                            "property_contract_supported": false,
                            "property_contract_diagnostic": format!("{error:#}"),
                            "preflight_mutated": false,
                        }))?
                    );
                }
                return Err(error);
            }
            let foreign = nemor_benchmark::performance::detect_nemord_processes(
                &bounded.payload.source_observer_path,
                None,
            );
            let foreign_clear =
                nemor_benchmark::performance::reject_foreign_nemord(&foreign, None).is_ok();
            let privileged = nix::unistd::geteuid().is_root();
            let output = serde_json::json!({
                "systemd_api_capable": true,
                "systemd_version": systemd_version,
                "property_contract_version": nemor_benchmark::observer_service::OBSERVER_PROPERTY_CONTRACT_VERSION,
                "property_contract_supported": true,
                "manager": "system",
                "required_authorization": "privileged_root",
                "requires_privileged_execution": true,
                "current_identity_authorized": privileged,
                "foreign_nemord_clear": foreign_clear,
                "source_provenance_verified": true,
                "release_binary_provenance_verified": true,
                "preflight_mutated": false,
                "performance_execution_ready": privileged && foreign_clear,
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!(
                    "systemd_api_capable=true requires_privileged_execution=true current_identity_authorized={} foreign_nemord_clear={} preflight_mutated=false",
                    privileged, foreign_clear
                );
            }
        }
        Command::ValidateObserverService { manifest, report } => {
            let result =
                nemor_benchmark::observer_service::execute_observer_validation(&manifest, &report)?;
            println!(
                "run_id={} evidence_kind=harness_validation performance_claim_eligible=false restore={} report={}",
                result.run_id,
                result.structural_restore_passed,
                report.display()
            );
        }
        Command::Experiment {
            scenario,
            variants,
            repetitions,
            seed,
            payload_bytes,
            config,
            database: _,
            report_dir: _,
            observer_binary,
            execute,
        } => {
            if variants != "cachyos_baseline,nemor_observe" {
                bail!("Checkpoint 3A variants must be cachyos_baseline,nemor_observe");
            }
            let loaded = common::LoadedConfig::load(&config)?;
            let executable = std::env::current_exe()?;
            let observer_binary =
                observer_binary.unwrap_or_else(|| executable.with_file_name("nemord"));
            let variant_set = [
                BenchmarkVariant::CachyosBaseline,
                BenchmarkVariant::NemorObserve,
            ];
            let inputs = nemor_benchmark::performance::ExperimentInputs {
                scenario: &scenario,
                variants: &variant_set,
                repetitions,
                seed,
                payload_bytes,
                config_hash: &loaded.sha256,
                benchmark_binary_path: &executable,
                observer_binary_path: &observer_binary,
            };
            let plan = nemor_benchmark::performance::plan_experiment(&inputs)?;
            if !execute {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                bail!("experiment --execute is retired; use prepare-experiment followed by execute-experiment --manifest")
            }
        }
        Command::PrepareExperiment {
            scenario,
            repository,
            config,
            observer_binary,
            prepared_dir,
            output_dir,
            seed,
            payload_bytes,
        } => {
            let path = nemor_benchmark::performance::prepare_experiment_manifest(
                &scenario,
                &repository,
                &config,
                &observer_binary,
                &prepared_dir,
                &output_dir,
                seed,
                payload_bytes,
            )?;
            println!("manifest={}", path.display());
        }
        Command::PreparePressureExperiment {
            repository,
            config,
            observer_binary,
            prepared_dir,
            output_dir,
            seed,
        } => {
            let path = nemor_benchmark::pressure_prepare::prepare_pressure_experiment(
                &repository,
                &config,
                &observer_binary,
                &prepared_dir,
                &output_dir,
                seed,
            )?;
            println!("manifest={}", path.display());
        }
        Command::PrepareCapacityCompatibility {
            repository,
            config,
            validator_binary,
            prepared_dir,
            output_dir,
        } => {
            let path = nemor_benchmark::capacity_compatibility::prepare_capacity_compatibility(
                &repository,
                &config,
                &validator_binary,
                &prepared_dir,
                &output_dir,
            )?;
            println!("manifest={}", path.display());
        }
        Command::CapacityCompatibilityPreflight { manifest, json } => {
            let report = nemor_benchmark::capacity_compatibility::capacity_compatibility_preflight(
                &manifest,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", serde_json::to_string(&report)?);
            }
        }
        Command::ValidateCapacityCompatibility { manifest } => {
            let report = nemor_benchmark::capacity_compatibility::validate_capacity_compatibility(
                &manifest,
            )?;
            println!(
                "validation_id={} state={:?} capacity=not_evaluated effectiveness=not_evaluated",
                report.validation_id, report.state
            );
        }
        Command::PrepareCapacityExternalTargetValidation {
            repository,
            config,
            validator_binary,
            target_binary,
            prepared_dir,
            output_dir,
        } => {
            let path =
                nemor_benchmark::capacity_external_validation::prepare_external_target_validation(
                    &repository,
                    &config,
                    &validator_binary,
                    target_binary.as_deref(),
                    &prepared_dir,
                    &output_dir,
                )?;
            println!("manifest={}", path.display());
        }
        Command::CapacityExternalTargetPreflight { manifest, json } => {
            let report = nemor_benchmark::capacity_external_validation::external_target_preflight(
                &manifest,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", serde_json::to_string(&report)?);
            }
        }
        Command::ValidateCapacityExternalTarget { manifest } => {
            let report =
                nemor_benchmark::capacity_external_validation::validate_external_target(&manifest)?;
            println!(
                "validation_id={} state={:?} capacity=not_evaluated effectiveness=not_evaluated",
                report.payload.validation_id, report.state
            );
        }
        Command::PrepareCapacityComposition {
            repository,
            config,
            validator_binary,
            target_binary,
            external_target_archive,
            prepared_dir,
            output_dir,
        } => {
            let path = nemor_benchmark::capacity_composition::prepare_capacity_composition(
                &repository,
                &config,
                &validator_binary,
                target_binary.as_deref(),
                &external_target_archive,
                &prepared_dir,
                &output_dir,
            )?;
            println!("manifest={}", path.display());
        }
        Command::CapacityCompositionPreflight { manifest, json } => {
            let report =
                nemor_benchmark::capacity_composition::capacity_composition_preflight(&manifest)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", serde_json::to_string(&report)?);
            }
        }
        Command::ExecuteCapacityComposition { manifest } => {
            let report =
                nemor_benchmark::capacity_composition::execute_capacity_composition(&manifest)?;
            println!(
                "experiment_id={} state={:?} capacity=not_evaluated effectiveness=not_evaluated",
                report.experiment_id, report.state
            );
            return Ok(
                nemor_benchmark::capacity_composition::composition_execution_exit_status(
                    report.state,
                ),
            );
        }
        Command::PrepareCapacityBenchmark {
            external_target_archive,
            composition_archive,
            prepared_dir,
            output_dir,
        } => {
            let path = nemor_benchmark::capacity_benchmark::prepare_capacity_benchmark(
                &external_target_archive,
                &composition_archive,
                &prepared_dir,
                &output_dir,
            )?;
            println!("manifest={}", path.display());
        }
        Command::CapacityBenchmarkPreflight { manifest, json } => {
            let report =
                nemor_benchmark::capacity_benchmark::capacity_benchmark_preflight(&manifest)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", serde_json::to_string(&report)?);
            }
        }
        Command::ExecuteCapacityBenchmark { manifest } => {
            let report =
                nemor_benchmark::capacity_benchmark::execute_capacity_benchmark(&manifest)?;
            println!(
                "experiment_id={} state={:?} capacity={:?} effectiveness=not_evaluated",
                report.experiment_id, report.composition_execution.state, report.evaluation.state
            );
            return Ok(
                if matches!(
                    report.evaluation.state,
                    nemor_benchmark::capacity_benchmark::CapacityEvaluationState::Complete
                        | nemor_benchmark::capacity_benchmark::CapacityEvaluationState::Censored
                        | nemor_benchmark::capacity_benchmark::CapacityEvaluationState::Incomplete
                ) {
                    0
                } else {
                    1
                },
            );
        }
        Command::CapacityBenchmarkRecoveryPreflight { manifest, json } => {
            let report =
                nemor_benchmark::capacity_benchmark::capacity_benchmark_recovery_preflight(
                    &manifest,
                )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", serde_json::to_string(&report)?);
            }
        }
        Command::RecoverCapacityBenchmark {
            manifest,
            idempotence_check,
        } => {
            let report = nemor_benchmark::capacity_benchmark::recover_capacity_benchmark(
                &manifest,
                idempotence_check,
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::PressurePreflight { manifest, json } => {
            let report = nemor_benchmark::pressure_live::pressure_preflight(&manifest)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", serde_json::to_string(&report)?);
            }
        }
        Command::ExecutePressureExperiment { manifest } => {
            let evidence = nemor_benchmark::pressure_live::execute_pressure_experiment(&manifest)?;
            println!(
                "experiment_id={} state={:?} capacity_gain_percent=not_evaluated",
                evidence.experiment_id, evidence.state
            );
            return Ok(
                nemor_benchmark::pressure_live::pressure_execution_exit_status(evidence.state),
            );
        }
        Command::ExecuteExperiment { manifest } => {
            let outcome = nemor_benchmark::performance::execute_prepared_experiment(&manifest)?;
            println!(
                "experiment_id={} runs={} comparison={} capacity_gain_percent=not_evaluated",
                outcome.plan.experiment_id,
                outcome.runs.len(),
                outcome.comparison.is_some()
            );
            return Ok(if outcome.comparison.is_some() { 0 } else { 1 });
        }
        Command::ExperimentPreflight { manifest, json } => {
            let output = nemor_benchmark::performance::preflight_prepared_experiment(&manifest)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{}", serde_json::to_string(&output)?);
            }
        }
        Command::RevalidateExperiment {
            manifest,
            report,
            json,
        } => {
            let result = nemor_benchmark::performance::revalidate_experiment(&manifest, &report)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "classification={} runs={}",
                    result.classification,
                    result.revalidated_runs.len()
                );
            }
        }
        Command::WorkerHold {
            bytes,
            seed,
            pattern,
            control_dir,
        } => {
            let pattern = match pattern.as_str() {
                "compressible" => nemor_benchmark::SyntheticPattern::Compressible,
                "incompressible" => nemor_benchmark::SyntheticPattern::Incompressible,
                _ => bail!("unsupported synthetic worker pattern"),
            };
            nemor_benchmark::harness::run_worker(bytes, seed, pattern, &control_dir)?;
        }
        Command::PressureWorker {
            socket,
            experiment_id,
            run_id,
            seed,
        } => {
            let start_ticks = nemor_benchmark::pressure_worker::current_process_start_ticks()?;
            nemor_benchmark::pressure_worker::run_pressure_worker_server(
                &socket,
                experiment_id,
                run_id,
                seed,
                start_ticks,
            )?;
        }
        Command::CapacityExternalTargetWorker {
            transaction_root,
            transaction_id,
            session_id,
            nonce,
            creator_pid,
            creator_start_ticks,
            preparing_uid,
            preparing_gid,
            unit_or_cgroup_identity,
        } => {
            nemor_benchmark::capacity_external_target::run_target_worker(
                &transaction_root,
                &transaction_id,
                &session_id,
                &nonce,
                creator_pid,
                creator_start_ticks,
                preparing_uid,
                preparing_gid,
                &unit_or_cgroup_identity,
            )?;
        }
    }
    Ok(0)
}
