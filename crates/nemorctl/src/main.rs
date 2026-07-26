#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use nemorctl::{
    cgroups_status, doctor, render_cgroups_status, render_doctor, render_report, render_status,
    render_workload, report_latest, status, workload_latest, DoctorEnvironment,
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
    }
}
