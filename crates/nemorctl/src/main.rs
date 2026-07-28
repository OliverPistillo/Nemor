#![forbid(unsafe_code)]

use clap::{Parser, Subcommand, ValueEnum};
use nemorctl::{
    benchmark_compare, benchmark_export, benchmark_history, benchmark_list, benchmark_plan,
    benchmark_report, benchmark_status, cgroups_status, damon_export, damon_report_latest,
    damon_sessions, damon_status, damos_blacklist, damos_history, damos_plan_latest, damos_status,
    doctor, ksm_history, ksm_plan_latest, ksm_processes, ksm_report_latest, ksm_status,
    policy_latest, policy_status, render_cgroups_status, render_doctor, render_policy_latest,
    render_policy_status, render_report, render_status, render_workload, render_zram,
    report_latest, status, tiering_recommend, tiering_report_latest, tiering_status,
    workload_latest, zram_profiles, zram_report_latest, zram_status, DoctorEnvironment,
};
use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_CONFIG_PATH: &str = "/etc/nemor/config.toml";

#[derive(Debug, Parser)]
#[command(version, about = "Read-only diagnostics for Nemor")]
struct Cli {
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Doctor {
        #[arg(long)]
        json: bool,
    },
    Status {
        #[arg(long)]
        json: bool,
    },
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    Workload {
        #[command(subcommand)]
        command: WorkloadCommand,
    },
    Cgroups {
        #[command(subcommand)]
        command: CgroupsCommand,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Zram {
        #[command(subcommand)]
        command: ZramCommand,
    },
    Tiering {
        #[command(subcommand)]
        command: TieringCommand,
    },
    Damon {
        #[command(subcommand)]
        command: DamonCommand,
    },
    Damos {
        #[command(subcommand)]
        command: DamosCommand,
    },
    Ksm {
        #[command(subcommand)]
        command: KsmCommand,
    },
    Benchmark {
        #[command(subcommand)]
        command: BenchmarkCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ReportCommand {
    Latest {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum WorkloadCommand {
    Latest {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum CgroupsCommand {
    Status {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Status {
        #[arg(long)]
        json: bool,
    },
    Latest {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ZramCommand {
    Status {
        #[arg(long)]
        json: bool,
    },
    Profiles {
        #[arg(long)]
        json: bool,
    },
    Report {
        #[command(subcommand)]
        command: ZramReportCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ZramReportCommand {
    Latest {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum TieringCommand {
    Status {
        #[arg(long)]
        json: bool,
    },
    Recommend {
        #[arg(long)]
        json: bool,
    },
    Report {
        #[command(subcommand)]
        command: TieringReportCommand,
    },
}

#[derive(Debug, Subcommand)]
enum TieringReportCommand {
    Latest {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DamonExportFormat {
    Jsonl,
    Csv,
}

#[derive(Debug, Subcommand)]
enum DamonCommand {
    Status {
        #[arg(long)]
        json: bool,
    },
    Sessions {
        #[arg(long)]
        json: bool,
    },
    Report {
        #[command(subcommand)]
        command: DamonReportCommand,
    },
    Export {
        #[arg(long, value_enum)]
        format: DamonExportFormat,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum DamonReportCommand {
    Latest {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum DamosCommand {
    Status {
        #[arg(long)]
        json: bool,
    },
    Plan {
        #[command(subcommand)]
        command: DamosPlanCommand,
    },
    History {
        #[arg(long)]
        json: bool,
    },
    Blacklist {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum DamosPlanCommand {
    Latest {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum KsmCommand {
    Status {
        #[arg(long)]
        json: bool,
    },
    Processes {
        #[arg(long)]
        json: bool,
    },
    Plan {
        #[command(subcommand)]
        command: KsmPlanCommand,
    },
    Report {
        #[command(subcommand)]
        command: KsmReportCommand,
    },
    History {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum KsmPlanCommand {
    Latest {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum KsmReportCommand {
    Latest {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum BenchmarkCommand {
    List {
        #[arg(long)]
        json: bool,
    },
    Status {
        #[arg(long)]
        json: bool,
    },
    Plan {
        scenario: String,
        #[arg(long)]
        json: bool,
    },
    Report {
        run_id: String,
        #[arg(long)]
        json: bool,
    },
    Compare {
        experiment_id: String,
        #[arg(long)]
        json: bool,
    },
    History {
        #[arg(long)]
        json: bool,
    },
    Export {
        experiment_id: String,
        #[arg(long, value_enum)]
        format: BenchmarkExportFormat,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BenchmarkExportFormat {
    Json,
    Csv,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> anyhow::Result<i32> {
    let cli = Cli::try_parse().map_err(|error| anyhow::anyhow!(error.to_string()))?;
    match cli.command {
        Command::Doctor { json } => {
            let report = doctor(&cli.config, &DoctorEnvironment::default())?;
            print!("{}", render_doctor(&report, json)?);
            Ok(report.exit_code())
        }
        Command::Status { json } => {
            let report = status(&cli.config)?;
            print!("{}", render_status(&report, json)?);
            Ok(0)
        }
        Command::Report {
            command: ReportCommand::Latest { json },
        } => {
            let report = report_latest(&cli.config)?;
            print!("{}", render_report(&report, json)?);
            Ok(0)
        }
        Command::Workload {
            command: WorkloadCommand::Latest { json },
        } => {
            let report = workload_latest(&cli.config)?;
            print!("{}", render_workload(&report, json)?);
            Ok(0)
        }
        Command::Cgroups {
            command: CgroupsCommand::Status { json },
        } => {
            let report = cgroups_status(&cli.config)?;
            print!("{}", render_cgroups_status(&report, json)?);
            Ok(0)
        }
        Command::Policy {
            command: PolicyCommand::Status { json },
        } => {
            let report = policy_status(&cli.config)?;
            print!("{}", render_policy_status(&report, json)?);
            Ok(0)
        }
        Command::Policy {
            command: PolicyCommand::Latest { json },
        } => {
            let report = policy_latest(&cli.config)?;
            print!("{}", render_policy_latest(&report, json)?);
            Ok(0)
        }
        Command::Zram {
            command: ZramCommand::Status { json },
        } => {
            print!("{}", render_zram(&zram_status(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Zram {
            command: ZramCommand::Profiles { json },
        } => {
            print!("{}", render_zram(&zram_profiles(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Zram {
            command:
                ZramCommand::Report {
                    command: ZramReportCommand::Latest { json },
                },
        } => {
            print!("{}", render_zram(&zram_report_latest(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Tiering {
            command: TieringCommand::Status { json },
        } => {
            print!("{}", render_zram(&tiering_status(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Tiering {
            command: TieringCommand::Recommend { json },
        } => {
            print!("{}", render_zram(&tiering_recommend(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Tiering {
            command:
                TieringCommand::Report {
                    command: TieringReportCommand::Latest { json },
                },
        } => {
            print!(
                "{}",
                render_zram(&tiering_report_latest(&cli.config)?, json)?
            );
            Ok(0)
        }
        Command::Damon {
            command: DamonCommand::Status { json },
        } => {
            print!("{}", render_zram(&damon_status(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Damon {
            command: DamonCommand::Sessions { json },
        } => {
            print!("{}", render_zram(&damon_sessions(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Damon {
            command:
                DamonCommand::Report {
                    command: DamonReportCommand::Latest { json },
                },
        } => {
            print!("{}", render_zram(&damon_report_latest(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Damon {
            command: DamonCommand::Export { format, output },
        } => {
            let format = match format {
                DamonExportFormat::Jsonl => damon::ExportFormat::Jsonl,
                DamonExportFormat::Csv => damon::ExportFormat::Csv,
            };
            println!(
                "exported_bytes={}",
                damon_export(&cli.config, format, &output)?
            );
            Ok(0)
        }
        Command::Damos {
            command: DamosCommand::Status { json },
        } => {
            print!("{}", render_zram(&damos_status(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Damos {
            command:
                DamosCommand::Plan {
                    command: DamosPlanCommand::Latest { json },
                },
        } => {
            print!("{}", render_zram(&damos_plan_latest(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Damos {
            command: DamosCommand::History { json },
        } => {
            print!("{}", render_zram(&damos_history(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Damos {
            command: DamosCommand::Blacklist { json },
        } => {
            print!("{}", render_zram(&damos_blacklist(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Ksm {
            command: KsmCommand::Status { json },
        } => {
            print!("{}", render_zram(&ksm_status(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Ksm {
            command: KsmCommand::Processes { json },
        } => {
            print!("{}", render_zram(&ksm_processes(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Ksm {
            command:
                KsmCommand::Plan {
                    command: KsmPlanCommand::Latest { json },
                },
        } => {
            print!("{}", render_zram(&ksm_plan_latest(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Ksm {
            command:
                KsmCommand::Report {
                    command: KsmReportCommand::Latest { json },
                },
        } => {
            print!("{}", render_zram(&ksm_report_latest(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Ksm {
            command: KsmCommand::History { json },
        } => {
            print!("{}", render_zram(&ksm_history(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Benchmark {
            command: BenchmarkCommand::List { json },
        } => {
            print!("{}", render_zram(&benchmark_list(), json)?);
            Ok(0)
        }
        Command::Benchmark {
            command: BenchmarkCommand::Status { json },
        } => {
            print!("{}", render_zram(&benchmark_status(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Benchmark {
            command: BenchmarkCommand::Plan { scenario, json },
        } => {
            print!("{}", render_zram(&benchmark_plan(&scenario)?, json)?);
            Ok(0)
        }
        Command::Benchmark {
            command: BenchmarkCommand::Report { run_id, json },
        } => {
            let run_id = (run_id != "latest").then_some(run_id.as_str());
            print!(
                "{}",
                render_zram(&benchmark_report(&cli.config, run_id)?, json)?
            );
            Ok(0)
        }
        Command::Benchmark {
            command:
                BenchmarkCommand::Compare {
                    experiment_id,
                    json,
                },
        } => {
            print!(
                "{}",
                render_zram(&benchmark_compare(&cli.config, &experiment_id)?, json)?
            );
            Ok(0)
        }
        Command::Benchmark {
            command: BenchmarkCommand::History { json },
        } => {
            print!("{}", render_zram(&benchmark_history(&cli.config)?, json)?);
            Ok(0)
        }
        Command::Benchmark {
            command:
                BenchmarkCommand::Export {
                    experiment_id,
                    format,
                },
        } => {
            let format = match format {
                BenchmarkExportFormat::Json => "json",
                BenchmarkExportFormat::Csv => "csv",
            };
            print!("{}", benchmark_export(&cli.config, &experiment_id, format)?);
            Ok(0)
        }
    }
}
