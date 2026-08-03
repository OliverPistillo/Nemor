#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use nemor_test_support::BUILD_GIT_HEAD;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use tiering::{
    apply_boot_validation, post_boot_validate, prepare_baseline_rollback, recover_boot_validation,
    root_preflight, select_one_shot, user_preflight, verify_applied, verify_final_restore,
    BootArtifact, BootValidationBackend, TieringBootApplyEvidence, TieringBootValidationManifest,
    TieringBootValidationPreflight, TieringPostBootEvidence,
};

#[derive(Debug, Parser)]
#[command(about = "Validation-only Phase 6 systemd-boot/UKI lifecycle")]
struct Cli {
    #[arg(long, value_enum)]
    command: LifecycleCommand,
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    evidence: Option<PathBuf>,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LifecycleCommand {
    Prepare,
    UserPreflight,
    RootPreflight,
    Apply,
    VerifyApplied,
    SelectOneShot,
    PostBootValidate,
    SelectBaselineRollback,
    VerifyFinalRestore,
    Recover,
    VerifyIdempotence,
}

impl LifecycleCommand {
    fn requires_root(self) -> bool {
        matches!(
            self,
            Self::RootPreflight
                | Self::Apply
                | Self::VerifyApplied
                | Self::SelectOneShot
                | Self::SelectBaselineRollback
                | Self::VerifyFinalRestore
                | Self::Recover
                | Self::VerifyIdempotence
        )
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let manifest: TieringBootValidationManifest =
        serde_json::from_slice(&fs::read(&cli.manifest).context("read manifest")?)
            .context("parse manifest")?;
    manifest.validate().context("validate manifest")?;
    if cli.command.requires_root() && current_uid()? != 0 {
        bail!("authenticated root is required for this separately authorized stage");
    }
    let mut backend = LinuxBootBackend::new(&manifest)?;
    match cli.command {
        LifecycleCommand::Prepare => write_new_json(&cli.output, &manifest),
        LifecycleCommand::UserPreflight => {
            write_new_json(&cli.output, &user_preflight(&manifest, &backend))
        }
        LifecycleCommand::RootPreflight => {
            write_new_json(&cli.output, &root_preflight(&manifest, &backend))
        }
        LifecycleCommand::Apply => {
            let preflight: TieringBootValidationPreflight = read_evidence(&cli)?;
            persist_before_mutation(&cli.output, "apply", &manifest, &preflight)?;
            let evidence = apply_boot_validation(&manifest, &preflight, &mut backend)?;
            replace_json(&cli.output, &evidence)
        }
        LifecycleCommand::VerifyApplied => {
            let evidence: TieringBootApplyEvidence = read_evidence(&cli)?;
            verify_applied(&manifest, &evidence, &backend)?;
            write_new_json(&cli.output, &evidence)
        }
        LifecycleCommand::SelectOneShot => {
            let mut evidence: TieringBootApplyEvidence = read_evidence(&cli)?;
            persist_before_mutation(&cli.output, "select-one-shot", &manifest, &evidence)?;
            select_one_shot(&manifest, &mut evidence, &mut backend)?;
            replace_json(&cli.output, &evidence)
        }
        LifecycleCommand::PostBootValidate => {
            let evidence: TieringPostBootEvidence = read_evidence(&cli)?;
            let checked = post_boot_validate(&manifest, evidence)?;
            write_new_json(&cli.output, &checked)
        }
        LifecycleCommand::SelectBaselineRollback => {
            persist_before_mutation(&cli.output, "select-baseline", &manifest, &manifest)?;
            let evidence = prepare_baseline_rollback(&manifest, &mut backend)?;
            replace_json(&cli.output, &evidence)
        }
        LifecycleCommand::VerifyFinalRestore => {
            persist_before_mutation(&cli.output, "final-restore", &manifest, &manifest)?;
            let evidence = verify_final_restore(&manifest, &mut backend)?;
            replace_json(&cli.output, &evidence)
        }
        LifecycleCommand::Recover | LifecycleCommand::VerifyIdempotence => {
            persist_before_mutation(&cli.output, "recover", &manifest, &manifest)?;
            let evidence = recover_boot_validation(&manifest, &mut backend)?;
            replace_json(&cli.output, &evidence)
        }
    }
}

fn read_evidence<T: serde::de::DeserializeOwned>(cli: &Cli) -> Result<T> {
    let path = cli.evidence.as_ref().context("--evidence is required")?;
    serde_json::from_slice(&fs::read(path)?).context("parse evidence")
}

fn write_new_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create-new {}", path.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    sync_parent(path)
}

fn replace_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let completed = path.with_extension("completed.json");
    write_new_json(&completed, value)
}

fn persist_before_mutation(
    path: &Path,
    operation: &str,
    manifest: &TieringBootValidationManifest,
    detail: &impl Serialize,
) -> Result<()> {
    write_new_json(
        path,
        &serde_json::json!({
            "schema": "tiering-boot-transaction-v1",
            "operation": operation,
            "source_commit": manifest.source_commit,
            "validation_id": manifest.validation_id,
            "mutation_started": false,
            "detail": detail,
        }),
    )
}

fn sync_parent(path: &Path) -> Result<()> {
    fs::File::open(path.parent().context("output parent")?)?.sync_all()?;
    Ok(())
}

fn current_uid() -> Result<u32> {
    let output = Command::new("/usr/bin/id").arg("-u").output()?;
    if !output.status.success() {
        bail!("id -u failed");
    }
    String::from_utf8(output.stdout)?
        .trim()
        .parse()
        .context("parse uid")
}

struct LinuxBootBackend {
    source_matches: bool,
    boot_order: Vec<String>,
    booted_entry: Option<String>,
}

impl LinuxBootBackend {
    fn new(manifest: &TieringBootValidationManifest) -> Result<Self> {
        let bootctl = output("/usr/bin/bootctl", &["status"]);
        let efibootmgr = output("/usr/bin/efibootmgr", &["-v"]);
        Ok(Self {
            source_matches: BUILD_GIT_HEAD == manifest.source_commit,
            boot_order: parse_boot_order(&efibootmgr),
            booted_entry: parse_field(&bootctl, "Current Entry:"),
        })
    }
}

impl BootValidationBackend for LinuxBootBackend {
    fn source_matches(&self, _: &TieringBootValidationManifest) -> bool {
        self.source_matches
    }

    fn storage_matches(&self, manifest: &TieringBootValidationManifest) -> bool {
        let findmnt = output("/usr/bin/findmnt", &["-nro", "SOURCE,FSTYPE", "/"]);
        let fields: Vec<_> = findmnt.split_whitespace().collect();
        if fields.len() != 2 {
            return false;
        }
        let topology = tiering::inspect_storage(Path::new("/"), fields[0], fields[1]);
        topology.profile == Some(manifest.storage_profile)
            && topology.device_identity.as_deref()
                == Some(manifest.physical_device_identity.as_str())
            && topology.filesystem_identity.as_deref()
                == Some(manifest.filesystem_identity.as_str())
    }

    fn bootloader_matches(&self, manifest: &TieringBootValidationManifest) -> bool {
        manifest.bootloader == "systemd-boot/kernel-install-uki"
            && Path::new("/sys/firmware/efi").exists()
            && Path::new("/boot/loader").is_dir()
    }

    fn entries_preserved(&self, manifest: &TieringBootValidationManifest) -> bool {
        manifest.current_entry != manifest.experimental_entry
            && manifest.default_entry != manifest.experimental_entry
            && Path::new("/boot/loader/entries")
                .join(&manifest.rollback_entry)
                .is_file()
    }

    fn boot_order_matches(&self, manifest: &TieringBootValidationManifest) -> bool {
        self.boot_order == manifest.boot_order
    }

    fn artifact_absent_and_safe(&self, artifact: &BootArtifact) -> bool {
        matches!(fs::symlink_metadata(&artifact.path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    }

    fn package_update_absent(&self) -> bool {
        ["/var/lib/pacman/db.lck", "/run/systemd/system-update"]
            .iter()
            .all(|path| !Path::new(path).exists())
    }

    fn secure_boot_compatible(&self) -> bool {
        output("/usr/bin/bootctl", &["status"]).contains("Secure Boot: disabled")
    }

    fn create_new_artifact(&mut self, artifact: &BootArtifact) -> bool {
        create_artifact(artifact).is_ok()
    }

    fn artifact_matches(&self, artifact: &BootArtifact) -> bool {
        artifact_matches(artifact)
    }

    fn sync_artifact_parents(&mut self) -> bool {
        true
    }

    fn set_one_shot(&mut self, entry: &str) -> bool {
        Command::new("/usr/bin/bootctl")
            .args(["set-oneshot", entry])
            .status()
            .is_ok_and(|status| status.success())
    }

    fn booted_entry(&self) -> Option<String> {
        self.booted_entry.clone()
    }

    fn remove_exact_artifact(&mut self, artifact: &BootArtifact) -> bool {
        if !artifact_matches(artifact) {
            return false;
        }
        fs::remove_file(&artifact.path).is_ok() && sync_parent(&artifact.path).is_ok()
    }

    fn temporary_swapfile_absent(&self, manifest: &TieringBootValidationManifest) -> bool {
        !manifest.swapfile_path.exists()
    }

    fn baseline_zswap_restored(&self, manifest: &TieringBootValidationManifest) -> bool {
        fs::read_to_string("/sys/module/zswap/parameters/enabled")
            .ok()
            .is_some_and(|value| (value.trim() == "Y") == manifest.baseline_zswap_enabled)
    }

    fn baseline_zram_restored(&self, manifest: &TieringBootValidationManifest) -> bool {
        fs::read_to_string("/proc/swaps")
            .ok()
            .is_some_and(|value| value.contains("/dev/zram0") == manifest.protected_zram_active)
    }
}

fn create_artifact(artifact: &BootArtifact) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(artifact.mode)
        .open(&artifact.path)?;
    file.write_all(artifact.content.as_bytes())?;
    file.sync_all()?;
    sync_parent(&artifact.path)?;
    if !artifact_matches(artifact) {
        bail!("artifact readback mismatch");
    }
    Ok(())
}

fn artifact_matches(artifact: &BootArtifact) -> bool {
    let Ok(metadata) = fs::symlink_metadata(&artifact.path) else {
        return false;
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != artifact.owner_uid
        || metadata.gid() != artifact.owner_gid
        || metadata.permissions().mode() & 0o7777 != artifact.mode
        || metadata.nlink() != 1
    {
        return false;
    }
    fs::read(&artifact.path)
        .ok()
        .is_some_and(|bytes| hex::encode(Sha256::digest(bytes)) == artifact.sha256)
}

fn output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|result| result.status.success())
        .and_then(|result| String::from_utf8(result.stdout).ok())
        .unwrap_or_default()
}

fn parse_field(text: &str, name: &str) -> Option<String> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix(name).map(str::trim))
        .map(str::to_owned)
}

fn parse_boot_order(text: &str) -> Vec<String> {
    parse_field(text, "BootOrder:")
        .map(|value| value.split(',').map(str::trim).map(str::to_owned).collect())
        .unwrap_or_default()
}
