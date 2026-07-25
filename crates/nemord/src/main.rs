#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::Parser;
use common::{HostMetadata, LinuxPaths, LoadedConfig};
use nemord::run_sampling_loop;
use std::path::PathBuf;
use std::process::ExitCode;
use storage::Storage;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const DEFAULT_CONFIG_PATH: &str = "/etc/nemor/config.toml";

#[derive(Debug, Parser)]
#[command(version, about = "Observe-only Nemor daemon")]
struct Cli {
    #[arg(long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(1);
        }
    };
    let loaded = match LoadedConfig::load(&cli.config) {
        Ok(loaded) => loaded,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(1);
        }
    };
    if let Err(error) = initialize_logging() {
        eprintln!("error: {error:#}");
        return ExitCode::from(1);
    }

    match run(loaded).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(
                event = "daemon_error",
                error = %format!("{error:#}"),
                "daemon stopped with an error"
            );
            ExitCode::from(1)
        }
    }
}

async fn run(loaded: LoadedConfig) -> Result<()> {
    info!(
        event = "configuration_loaded",
        config_path = %loaded.path.display(),
        config_hash = %loaded.sha256,
        mode = %loaded.config.general.mode,
        "validated configuration loaded"
    );

    let mut storage = Storage::open(&loaded.config.general.database_path).with_context(|| {
        format!(
            "cannot initialize database {}",
            loaded.config.general.database_path.display()
        )
    })?;
    info!(
        event = "database_ready",
        database_path = %storage.path().display(),
        schema_version = storage::MIGRATION_VERSION,
        "database opened and migrated"
    );

    let host = HostMetadata::read_once(&LinuxPaths::default())
        .context("cannot collect required host metadata")?;
    let host_id = storage.upsert_host(&host).context("cannot register host")?;
    info!(
        event = "host_registered",
        host_id, "host metadata registered"
    );

    let session_id = storage
        .open_session(host_id, env!("CARGO_PKG_VERSION"), &loaded.sha256)
        .context("cannot open daemon session")?;
    info!(
        event = "session_started",
        session_id,
        mode = "observe",
        daemon_version = env!("CARGO_PKG_VERSION"),
        "observe-only session started"
    );

    let mut collector = collector::SystemCollector::production();
    let signal = run_sampling_loop(
        &mut collector,
        &mut storage,
        session_id,
        &loaded.config,
        wait_for_shutdown_signal(),
    )
    .await
    .context("telemetry sampling loop failed")?;
    info!(
        event = "shutdown_signal_received",
        session_id, signal, "shutdown requested"
    );

    storage
        .close_session(session_id, true)
        .context("cannot close daemon session cleanly")?;
    info!(
        event = "session_closed",
        session_id,
        clean_shutdown = true,
        "session closed cleanly"
    );
    Ok(())
}

fn initialize_logging() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(true)
        .try_init()
        .map_err(|error| anyhow::anyhow!("cannot initialize structured logging: {error}"))
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> Result<&'static str> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate =
        signal(SignalKind::terminate()).context("cannot install SIGTERM handler")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("cannot install SIGINT handler")?;
    tokio::select! {
        _ = terminate.recv() => Ok("SIGTERM"),
        _ = interrupt.recv() => Ok("SIGINT"),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> Result<&'static str> {
    tokio::signal::ctrl_c()
        .await
        .context("cannot install Ctrl-C handler")?;
    Ok("CTRL_C")
}
