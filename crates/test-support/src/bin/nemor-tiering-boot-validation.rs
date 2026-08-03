#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use common::Config;
use nemor_test_support::BUILD_GIT_HEAD;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;
use tiering::*;

#[derive(Debug, Parser)]
#[command(about = "Validation-only Phase 6 systemd-boot Type #1 lifecycle v2")]
struct Cli {
    #[command(subcommand)]
    command: LifecycleCommand,
}

#[derive(Debug, Subcommand)]
enum LifecycleCommand {
    /// Read-only host inspection plus create-new user manifest preparation.
    Prepare(PrepareArgs),
    /// Re-inspect the host without mutation as the preparing user.
    UserPreflight(ManifestArgs),
    /// Re-inspect the host without mutation as authenticated sudo root.
    RootPreflight(ManifestArgs),
    /// Initialize the exact durable transaction and apply exact-owned artifacts.
    Apply(ManifestArgs),
    VerifyApplied(TransactionArgs),
    SelectOneShot(TransactionArgs),
    PostBootValidate(TransactionArgs),
    SelectBaselineRollback(TransactionArgs),
    VerifyFinalRestore(TransactionArgs),
    Recover(TransactionArgs),
    VerifyIdempotence(TransactionArgs),
    #[command(hide = true)]
    ExperimentalActivate(TransactionArgs),
    #[command(hide = true)]
    BoundedWorkload(TransactionArgs),
    /// Release identity for manifest preparation.
    BuildGitHead,
}

#[derive(Debug, Args)]
struct PrepareArgs {
    #[arg(long)]
    validation_id: String,
    #[arg(long)]
    prepared_root: PathBuf,
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    validator_binary: PathBuf,
    #[arg(long, default_value_t = 268_435_456)]
    swap_size_bytes: u64,
    #[arg(long, default_value_t = 110)]
    swap_priority: i32,
    #[arg(long, default_value_t = 134_217_728)]
    maximum_write_bytes: u64,
    #[arg(long, default_value_t = 120)]
    timeout_seconds: u64,
}

#[derive(Debug, Args)]
struct ManifestArgs {
    #[arg(long)]
    manifest: PathBuf,
}

#[derive(Debug, Args)]
struct TransactionArgs {
    #[arg(long)]
    validation_id: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        LifecycleCommand::Prepare(args) => prepare(args),
        LifecycleCommand::UserPreflight(args) => {
            let manifest = read_manifest(&args.manifest)?;
            let observation = collect_preflight(&manifest, false)?;
            validate_preflight_v2(&manifest, &observation, false)?;
            print_json(&observation)
        }
        LifecycleCommand::RootPreflight(args) => {
            require_authenticated_root(&read_manifest(&args.manifest)?)?;
            let manifest = read_manifest(&args.manifest)?;
            let observation = collect_preflight(&manifest, true)?;
            validate_preflight_v2(&manifest, &observation, true)?;
            print_json(&observation)
        }
        LifecycleCommand::Apply(args) => {
            let manifest = read_manifest(&args.manifest)?;
            require_authenticated_root(&manifest)?;
            let root = collect_preflight(&manifest, true)?;
            let boot_id = read_trimmed(Path::new("/proc/sys/kernel/random/boot_id"))?;
            let mut backend = LinuxLifecycleBackend::new(&manifest)?;
            let tx = apply_exact_transaction_v2(&manifest, &root, boot_id, &mut backend)?;
            print_json(&tx)
        }
        LifecycleCommand::VerifyApplied(args) => with_transaction(&args, |m, t, b| {
            require_stage(t, TransactionStageV2::Applied)?;
            if m.payload
                .owned_artifacts
                .iter()
                .all(|a| b.artifact_matches(a))
            {
                print_json(t)
            } else {
                bail!("applied artifact readback mismatch")
            }
        }),
        LifecycleCommand::SelectOneShot(args) => with_transaction_mut(&args, |m, t, b| {
            select_exact_one_shot_v2(m, t, b)?;
            print_json(t)
        }),
        LifecycleCommand::PostBootValidate(args) => with_transaction_mut(&args, |m, t, b| {
            let evidence = collect_and_validate_post_boot_v2(m, t, b)?;
            print_json(&evidence)
        }),
        LifecycleCommand::SelectBaselineRollback(args) => with_transaction_mut(&args, |m, t, b| {
            select_baseline_rollback_v2(m, t, b)?;
            print_json(t)
        }),
        LifecycleCommand::VerifyFinalRestore(args) => with_transaction_mut(&args, |m, t, b| {
            verify_then_cleanup_v2(m, t, b)?;
            print_json(t)
        }),
        LifecycleCommand::Recover(args) => recover(args, false),
        LifecycleCommand::VerifyIdempotence(args) => recover(args, true),
        LifecycleCommand::ExperimentalActivate(args) => experimental_activate(args),
        LifecycleCommand::BoundedWorkload(args) => bounded_workload(args),
        LifecycleCommand::BuildGitHead => {
            println!("{BUILD_GIT_HEAD}");
            Ok(())
        }
    }
}

fn prepare(args: PrepareArgs) -> Result<()> {
    if current_uid()? == 0 {
        bail!("prepare must run as an unprivileged user");
    }
    if args.prepared_root.exists() {
        bail!("prepared root already exists");
    }
    let parent = args
        .prepared_root
        .parent()
        .context("prepared-root parent")?;
    require_private_owned_parent(parent, current_uid()?)?;
    let payload = collect_prepared_payload(&args)?;
    let manifest = TieringBootValidationPreparedManifestV2::seal(payload);
    manifest.validate()?;
    fs::create_dir(&args.prepared_root).context("create fresh prepared root")?;
    fs::set_permissions(&args.prepared_root, fs::Permissions::from_mode(0o700))?;
    let path = args.prepared_root.join("prepared-manifest-v2.json");
    write_new_json(&path, &manifest, 0o600)?;
    print_json(
        &serde_json::json!({"manifest":path,"sha256":canonical_json_sha256(&manifest),"mutation":false}),
    )
}

fn collect_prepared_payload(args: &PrepareArgs) -> Result<PreparedManifestPayloadV2> {
    if !(8..=64).contains(&args.validation_id.len()) {
        bail!("invalid validation id");
    }
    let uid = current_uid()?;
    let gid = current_gid()?;
    let source_commit = git_output(&["rev-parse", "HEAD"])?;
    if source_commit != BUILD_GIT_HEAD {
        bail!("binary/source commit mismatch");
    }
    let source_state = git_output(&["status", "--porcelain=v1", "--untracked-files=no"])?;
    if !source_state.is_empty() {
        bail!("tracked source is dirty");
    }
    let source_state_sha256 = sha256(format!("{source_commit}\nclean\n").as_bytes());
    let validator = args
        .validator_binary
        .canonicalize()
        .context("validator binary")?;
    let validator_hash = sha256_file(&validator)?;
    let embedded_commit = command_output(
        validator.to_str().context("validator path is not UTF-8")?,
        &["build-git-head"],
    )?;
    if embedded_commit != source_commit {
        bail!("validator embedded commit does not match exact source")
    }
    let config = args.config.canonicalize().context("config")?;
    let config_sha256 = sha256_file(&config)?;
    if production_state(&config)? != (true, false) {
        bail!("configuration is not observe-only with production activation disabled")
    }
    let topology = collect_topology()?;
    let baseline_swaps = collect_swaps()?;
    let protected_zram = collect_zram(&baseline_swaps)?;
    let baseline_zswap = collect_zswap()?;
    let boot = collect_boot_identity()?;
    let marker = format!("nemor.phase6_validation={}", args.validation_id);
    let unit_name = format!("nemor-phase6-{}.service", args.validation_id);
    let mut experimental_entry = BootEntryIdentityV2 {
        id: format!("nemor-phase6-{}.conf", args.validation_id),
        path: Path::new("/boot/loader/entries")
            .join(format!("nemor-phase6-{}.conf", args.validation_id)),
        sha256: String::new(),
        title: boot.current_entry.title.clone(),
        linux_or_efi: boot.current_entry.linux_or_efi.clone(),
        initrds: boot.current_entry.initrds.clone(),
        options: String::new(),
    };
    let tx_root = Path::new(TRANSACTION_ROOT).join(&args.validation_id);
    let mut experimental_zswap = baseline_zswap.parameters.clone();
    experimental_zswap.insert("enabled".into(), "Y".into());
    experimental_entry.options = build_experimental_options(
        &boot.current_entry.options,
        &marker,
        &unit_name,
        &experimental_zswap,
    );
    let mut payload = PreparedManifestPayloadV2 {
        contract_version: BOOT_VALIDATION_CONTRACT_VERSION_V2.into(),
        rule_version: TIERING_RULE_VERSION.into(),
        validation_id: args.validation_id.clone(),
        prepared_uid: uid,
        prepared_gid: gid,
        source_commit: source_commit.clone(),
        source_state_sha256,
        binaries: BTreeMap::from([(
            "nemor-tiering-boot-validation".into(),
            BinaryIdentityV2 {
                path: validator.clone(),
                sha256: validator_hash,
                embedded_commit,
            },
        )]),
        config_path: config,
        config_sha256,
        material_environment_sha256: material_environment_hash()?,
        topology,
        baseline_swaps,
        protected_zram,
        baseline_zswap,
        experimental_zswap,
        boot,
        experimental_entry,
        validation_marker: marker,
        swapfile: SwapIdentityV2 {
            path: tx_root.join("backing.swap"),
            kind: "file".into(),
            size_bytes: args.swap_size_bytes,
            priority: args.swap_priority,
            uuid: None,
            active: false,
        },
        owned_artifacts: Vec::new(),
        transaction_root: tx_root,
        workload: WorkloadContractV2 {
            bytes: 32 * 1024 * 1024,
            iterations: 2,
            timeout_seconds: args.timeout_seconds,
            maximum_write_bytes: args.maximum_write_bytes,
        },
        recovery_entry: String::new(),
        production_activation: false,
    };
    payload.recovery_entry = payload.boot.current_entry.id.clone();
    let entry_content = render_type1_entry_v2(&payload.experimental_entry).into_bytes();
    payload.experimental_entry.sha256 = sha256(&entry_content);
    let unit_content = render_validation_unit_v2(&payload, &validator).into_bytes();
    payload.owned_artifacts = vec![
        artifact(
            OwnedArtifactKindV2::Type1Entry,
            payload.experimental_entry.path.clone(),
            entry_content,
            0o600,
        ),
        artifact(
            OwnedArtifactKindV2::ValidationUnit,
            Path::new("/etc/systemd/system").join(unit_name),
            unit_content,
            0o644,
        ),
    ];
    Ok(payload)
}

fn artifact(
    kind: OwnedArtifactKindV2,
    path: PathBuf,
    content: Vec<u8>,
    mode: u32,
) -> OwnedArtifactV2 {
    OwnedArtifactV2 {
        kind,
        path,
        sha256: sha256(&content),
        mode,
        owner_uid: 0,
        owner_gid: 0,
        content,
    }
}

fn build_experimental_options(
    baseline: &str,
    marker: &str,
    unit_name: &str,
    zswap: &BTreeMap<String, String>,
) -> String {
    let mut options: Vec<String> = baseline
        .split_whitespace()
        .filter(|item| {
            !item.starts_with("zswap.")
                && !item.starts_with("nemor.phase6_validation=")
                && !item.starts_with("systemd.wants=nemor-phase6-")
        })
        .map(str::to_owned)
        .collect();
    options.push(marker.to_owned());
    options.push(format!("systemd.wants={unit_name}"));
    for name in [
        "enabled",
        "compressor",
        "zpool",
        "max_pool_percent",
        "accept_threshold_percent",
        "shrinker_enabled",
    ] {
        let value = zswap.get(name).expect("validated zswap key");
        let value = match (name, value.as_str()) {
            ("enabled" | "shrinker_enabled", "Y") => "1",
            ("enabled" | "shrinker_enabled", "N") => "0",
            _ => value,
        };
        options.push(format!("zswap.{name}={value}"));
    }
    options.join(" ")
}

fn collect_topology() -> Result<StorageTopologyIdentityV2> {
    let line = command_output("/usr/bin/findmnt", &["-nro", "SOURCE,FSTYPE", "/"])?;
    let mut f = line.split_whitespace();
    let source = f.next().context("root source")?;
    let filesystem = f.next().context("root filesystem")?;
    let old = inspect_storage(Path::new("/"), source, filesystem);
    if old.ambiguous {
        bail!("ambiguous storage topology")
    };
    let physical = old.physical.context("physical device")?;
    let profile = old.profile.context("storage profile")?;
    let mut chain = Vec::new();
    for (index, name) in old.chain.iter().enumerate() {
        let path = PathBuf::from(format!("/dev/{name}"));
        let md = fs::metadata(&path)?;
        let parent = old
            .chain
            .get(index + 1)
            .map(|n| PathBuf::from(format!("/dev/{n}")));
        let kind = if parent.is_some() { "part" } else { "disk" };
        chain.push(BlockLayerIdentityV2 {
            path,
            kind: kind.into(),
            major: major(md.rdev()) as u32,
            minor: minor(md.rdev()) as u32,
            parent,
        });
    }
    let physical_path = PathBuf::from(format!("/dev/{}", physical.name));
    let md = fs::metadata(&physical_path)?;
    let root_md = fs::metadata(source)?;
    let mount_id = fs::read_to_string("/proc/self/mountinfo")?
        .lines()
        .find_map(|l| {
            let mut p = l.split_whitespace();
            let id = p.next()?.parse().ok()?;
            let _ = p.next();
            let _ = p.next();
            let _ = p.next();
            (p.next() == Some("/")).then_some(id)
        })
        .context("root mount id")?;
    let uuid = command_output("/usr/bin/blkid", &["-s", "UUID", "-o", "value", source])
        .or_else(|_| command_output("/usr/bin/btrfs", &["filesystem", "show", "/"]))?;
    Ok(StorageTopologyIdentityV2 {
        storage_profile_version: STORAGE_PROFILE_VERSION.into(),
        profile,
        chain,
        physical: PhysicalDeviceIdentityV2 {
            path: physical_path,
            major: major(md.rdev()) as u32,
            minor: minor(md.rdev()) as u32,
            transport: physical.transport.context("transport")?,
            rotational: physical.rotational.context("rotational")?,
            model: physical.model.context("model")?,
            serial: physical.serial,
            wwn: physical.wwn,
            capacity_bytes: physical.capacity_bytes.context("capacity")?,
            logical_block_size: physical.logical_block_size.context("logical block size")?,
            physical_block_size: physical
                .physical_block_size
                .context("physical block size")?,
        },
        filesystem: FilesystemIdentityV2 {
            filesystem: filesystem.into(),
            uuid_or_fsid: uuid.trim().to_owned(),
            mount_source: PathBuf::from(source),
            mount_point: PathBuf::from("/"),
            mount_id,
            device_major: major(root_md.rdev()) as u32,
            device_minor: minor(root_md.rdev()) as u32,
        },
        composite: false,
        ambiguous: false,
        confidence: "high".into(),
    })
}

fn collect_swaps() -> Result<Vec<SwapIdentityV2>> {
    let text = fs::read_to_string("/proc/swaps")?;
    text.lines()
        .skip(1)
        .map(|line| {
            let f: Vec<_> = line.split_whitespace().collect();
            if f.len() < 5 {
                bail!("malformed /proc/swaps")
            };
            Ok(SwapIdentityV2 {
                path: PathBuf::from(f[0]),
                kind: f[1].into(),
                size_bytes: f[2].parse::<u64>()?.saturating_mul(1024),
                priority: f[4].parse()?,
                uuid: None,
                active: true,
            })
        })
        .collect()
}

fn collect_zram(swaps: &[SwapIdentityV2]) -> Result<ZramIdentityV2> {
    let swap = swaps
        .iter()
        .find(|s| s.path == Path::new("/dev/zram0"))
        .context("protected zram0 swap")?;
    Ok(ZramIdentityV2 {
        device: swap.path.clone(),
        provider: "systemd-zram-generator".into(),
        active: true,
        priority: swap.priority,
        disksize_bytes: read_u64("/sys/block/zram0/disksize")?,
        compressor: read_trimmed(Path::new("/sys/block/zram0/comp_algorithm"))?,
        memory_limit_bytes: read_u64("/sys/block/zram0/mem_limit").unwrap_or(0),
        unit: "dev-zram0.swap".into(),
    })
}

fn collect_zswap() -> Result<ZswapIdentityV2> {
    let mut parameters = BTreeMap::new();
    for name in [
        "enabled",
        "compressor",
        "zpool",
        "max_pool_percent",
        "accept_threshold_percent",
        "shrinker_enabled",
    ] {
        parameters.insert(name.into(), read_zswap_parameter(name)?);
    }
    Ok(ZswapIdentityV2 { parameters })
}

fn read_zswap_parameter(name: &str) -> Result<String> {
    let value = read_trimmed(&Path::new("/sys/module/zswap/parameters").join(name))?;
    if matches!(name, "compressor" | "zpool") {
        let start = value.find('[').context("selected zswap value")? + 1;
        let end = value[start..].find(']').context("selected zswap value")? + start;
        Ok(value[start..end].to_owned())
    } else {
        Ok(value)
    }
}

fn collect_boot_identity() -> Result<BootIdentityV2> {
    let status = command_output("/usr/bin/bootctl", &["status"])?;
    if !status.contains("Secure Boot: disabled") {
        bail!("Secure Boot is not disabled")
    };
    let current_id = parse_field(&status, "Current Boot Loader Entry:")
        .or_else(|| parse_field(&status, "Current Entry:"))
        .context("current entry")?;
    let default_id = parse_field(&status, "Default Boot Loader Entry:")
        .or_else(|| parse_field(&status, "Default Entry:"))
        .context("default entry")?;
    let one_shot = parse_field(&status, "One Shot Boot Loader Entry:")
        .or_else(|| parse_field(&status, "One-shot Boot Loader Entry:"));
    if one_shot.is_some() {
        bail!("existing one-shot state conflicts")
    };
    let current = parse_type1_entry(&current_id)?;
    let default = parse_type1_entry(&default_id)?;
    let mut referenced = Vec::new();
    for path in std::iter::once(&current.linux_or_efi).chain(current.initrds.iter()) {
        let actual = Path::new("/boot").join(path.strip_prefix("/").unwrap_or(path));
        if !actual.is_file() {
            bail!("Type #1 referenced boot file missing: {}", actual.display())
        };
        referenced.push(ReferencedBootFileV2 {
            path: path.clone(),
            sha256: sha256_file(&actual)?,
        });
    }
    let esp = command_output("/usr/bin/findmnt", &["-nro", "SOURCE,FSTYPE", "/boot"])?;
    let mut e = esp.split_whitespace();
    let esp_device = e.next().context("ESP device")?.to_owned();
    let esp_filesystem = e.next().context("ESP filesystem")?.to_owned();
    let esp_uuid = command_output(
        "/usr/bin/blkid",
        &["-s", "UUID", "-o", "value", &esp_device],
    )?;
    let boot_order = parse_field(
        &command_output("/usr/bin/efibootmgr", &["-v"])?,
        "BootOrder:",
    )
    .map(|v| v.split(',').map(str::trim).map(str::to_owned).collect())
    .unwrap_or_default();
    Ok(BootIdentityV2 {
        bootloader: "systemd-boot-type1".into(),
        current_entry: current.clone(),
        default_entry: default,
        boot_order,
        prior_one_shot: None,
        esp_mount: PathBuf::from("/boot"),
        esp_device,
        esp_filesystem,
        esp_uuid: esp_uuid.trim().into(),
        secure_boot: "disabled".into(),
        kernel_release: read_trimmed(Path::new("/proc/sys/kernel/osrelease"))?,
        referenced_files: referenced,
        current_command_line: read_trimmed(Path::new("/proc/cmdline"))?,
    })
}

fn parse_type1_entry(id: &str) -> Result<BootEntryIdentityV2> {
    if !id.ends_with(".conf") || id.contains('/') || id.contains("..") {
        bail!("Type #2 UKI or ambiguous entry is unsupported")
    };
    let path = Path::new("/boot/loader/entries").join(id);
    let text = fs::read_to_string(&path)?;
    let title = entry_value(&text, "title").context("entry title")?;
    if entry_value(&text, "efi").is_some() || entry_value(&text, "uki").is_some() {
        bail!("Type #2 UKI or EFI-only Type #1 entry has no verified clone builder")
    }
    let linux = entry_value(&text, "linux").context("entry linux")?;
    let initrds = text
        .lines()
        .filter_map(|l| entry_line_value(l, "initrd"))
        .map(PathBuf::from)
        .collect();
    let options = entry_value(&text, "options").context("entry options")?;
    Ok(BootEntryIdentityV2 {
        id: id.into(),
        path,
        sha256: sha256(text.as_bytes()),
        title,
        linux_or_efi: PathBuf::from(linux),
        initrds,
        options,
    })
}

fn entry_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| entry_line_value(l, key))
}
fn entry_line_value(line: &str, key: &str) -> Option<String> {
    let line = line.trim();
    let rest = line.strip_prefix(key)?;
    rest.starts_with(char::is_whitespace)
        .then(|| rest.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn material_environment_hash() -> Result<String> {
    let mut values = Vec::new();
    for path in ["/etc/os-release", "/proc/version", "/proc/cmdline"] {
        values.extend(fs::read(path)?);
        values.push(0)
    }
    values.extend(command_output("/usr/bin/systemd-detect-virt", &[])?.bytes());
    Ok(sha256(&values))
}

fn collect_preflight(
    m: &TieringBootValidationPreparedManifestV2,
    root: bool,
) -> Result<PreflightObservationV2> {
    m.validate()?;
    let topology_matches = collect_topology().is_ok_and(|v| v == m.payload.topology);
    let boot = collect_boot_identity();
    let boot_matches = boot.as_ref().is_ok_and(|v| {
        v.current_entry == m.payload.boot.current_entry
            && v.default_entry == m.payload.boot.default_entry
            && v.esp_uuid == m.payload.boot.esp_uuid
    });
    let boot_order_matches = boot
        .as_ref()
        .is_ok_and(|v| v.boot_order == m.payload.boot.boot_order);
    let one_shot_matches = boot
        .as_ref()
        .is_ok_and(|v| v.prior_one_shot == m.payload.boot.prior_one_shot);
    let swaps = collect_swaps().unwrap_or_default();
    let zram_matches = collect_zram(&swaps).is_ok_and(|v| v == m.payload.protected_zram);
    let zswap_matches = collect_zswap().is_ok_and(|v| v == m.payload.baseline_zswap);
    let binaries_match = m.payload.binaries.values().all(|b| {
        sha256_file(&b.path).ok().as_deref() == Some(&b.sha256)
            && b.embedded_commit == BUILD_GIT_HEAD
    });
    let config_matches =
        sha256_file(&m.payload.config_path).ok().as_deref() == Some(&m.payload.config_sha256);
    let parents_safe = m
        .payload
        .owned_artifacts
        .iter()
        .all(|a| path_absent_and_parent_safe(&a.path))
        && path_absent_and_parent_safe(&m.payload.swapfile.path);
    let (esp_free, swap_free) = (
        free_bytes(&m.payload.boot.esp_mount).unwrap_or(0),
        free_bytes(Path::new("/")).unwrap_or(0),
    );
    Ok(PreflightObservationV2 {
        schema: PREFLIGHT_SCHEMA_V2.into(),
        uid: current_uid()?,
        gid: current_gid()?,
        sudo_uid: root.then(|| env_u32("SUDO_UID")).transpose()?,
        sudo_gid: root.then(|| env_u32("SUDO_GID")).transpose()?,
        host_identity_sha256: material_environment_hash()?,
        source_matches: BUILD_GIT_HEAD == m.payload.source_commit
            && git_output(&["rev-parse", "HEAD"]).ok().as_deref() == Some(&m.payload.source_commit)
            && sha256(format!("{}\nclean\n", m.payload.source_commit).as_bytes())
                == m.payload.source_state_sha256
            && git_output(&["status", "--porcelain=v1", "--untracked-files=no"])
                .is_ok_and(|v| v.is_empty()),
        binaries_match,
        config_matches,
        topology_matches,
        boot_matches,
        boot_order_matches,
        one_shot_matches,
        zram_matches,
        zswap_matches,
        parents_safe,
        esp_free_bytes: esp_free,
        swap_free_bytes: swap_free,
        package_update_absent: !["/var/lib/pacman/db.lck", "/run/systemd/system-update"]
            .iter()
            .any(|p| Path::new(p).exists()),
        secure_boot_compatible: boot.as_ref().is_ok_and(|v| v.secure_boot == "disabled"),
        ac_power: ac_power(),
        stale_state_absent: !m.payload.transaction_root.exists()
            && m.payload.owned_artifacts.iter().all(|a| !a.path.exists())
            && !m.payload.swapfile.path.exists(),
        validation_process_absent: no_other_validator_process(),
        unrelated_mutation_absent: command_output(
            "/usr/bin/systemctl",
            &["list-jobs", "--no-legend", "--no-pager"],
        )
        .is_ok_and(|value| value.trim().is_empty()),
        mutation_count: 0,
    })
}

fn require_authenticated_root(m: &TieringBootValidationPreparedManifestV2) -> Result<()> {
    if current_uid()? != 0
        || env_u32("SUDO_UID")? != m.payload.prepared_uid
        || env_u32("SUDO_GID")? != m.payload.prepared_gid
    {
        bail!("exact authenticated SUDO_UID/SUDO_GID required")
    };
    Ok(())
}

struct LinuxLifecycleBackend {
    manifest: TieringBootValidationPreparedManifestV2,
}
impl LinuxLifecycleBackend {
    fn new(m: &TieringBootValidationPreparedManifestV2) -> Result<Self> {
        m.validate()?;
        Ok(Self {
            manifest: m.clone(),
        })
    }
    fn tx_path(&self) -> PathBuf {
        self.manifest
            .payload
            .transaction_root
            .join("transaction-v2.json")
    }
}

impl BootLifecycleBackendV2 for LinuxLifecycleBackend {
    fn persist_transaction(
        &mut self,
        tx: &DurableTransactionV2,
    ) -> std::result::Result<(), String> {
        atomic_replace_json(&self.tx_path(), tx).map_err(|e| e.to_string())
    }
    fn create_transaction_root(
        &mut self,
        m: &TieringBootValidationPreparedManifestV2,
    ) -> std::result::Result<(), String> {
        let p = &m.payload.transaction_root;
        fs::create_dir(p).map_err(|e| e.to_string())?;
        let initialized = fs::set_permissions(p, fs::Permissions::from_mode(0o700))
            .and_then(|()| sync_parent(p).map_err(std::io::Error::other));
        if let Err(error) = initialized {
            let cleanup = fs::remove_dir(p).err();
            return Err(format!(
                "transaction-root initialization failed: {error}; cleanup={cleanup:?}"
            ));
        }
        Ok(())
    }
    fn copy_prepared_manifest(
        &mut self,
        m: &TieringBootValidationPreparedManifestV2,
    ) -> std::result::Result<(), String> {
        write_new_json(
            &m.payload.transaction_root.join("prepared-manifest-v2.json"),
            m,
            0o600,
        )
        .map_err(|e| e.to_string())
    }
    fn persist_evidence(&mut self, name: &str, bytes: &[u8]) -> std::result::Result<(), String> {
        if name.contains('/') || name.contains("..") || !name.ends_with(".json") {
            return Err("unsafe evidence name".into());
        }
        write_new_bytes(
            &self.manifest.payload.transaction_root.join(name),
            bytes,
            0o600,
        )
        .map_err(|e| e.to_string())
    }
    fn create_swapfile(
        &mut self,
        m: &TieringBootValidationPreparedManifestV2,
    ) -> std::result::Result<SwapIdentityV2, String> {
        let mut b = LinuxSwapfileBackend::default();
        SwapfileBackend::create_owned(
            &mut b,
            &m.payload.swapfile.path,
            FilesystemKind::Btrfs,
            m.payload.swapfile.size_bytes,
        )
        .map_err(|e| e.to_string())?;
        let metadata = fs::symlink_metadata(&m.payload.swapfile.path).map_err(|e| e.to_string())?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() != m.payload.swapfile.size_bytes
        {
            return Err("created swapfile structural identity mismatch".into());
        }
        let path = m.payload.swapfile.path.to_str().ok_or("swap path UTF-8")?;
        let kind = command_output("/usr/bin/blkid", &["-s", "TYPE", "-o", "value", path])
            .map_err(|e| e.to_string())?;
        let uuid = command_output("/usr/bin/blkid", &["-s", "UUID", "-o", "value", path])
            .map_err(|e| e.to_string())?;
        if kind != "swap" || uuid.is_empty() {
            return Err("mkswap identity readback mismatch".into());
        }
        Ok(SwapIdentityV2 {
            uuid: Some(uuid),
            ..m.payload.swapfile.clone()
        })
    }
    fn create_artifact(&mut self, a: &OwnedArtifactV2) -> std::result::Result<(), String> {
        write_new_bytes(&a.path, &a.content, a.mode).map_err(|e| e.to_string())
    }
    fn artifact_matches(&self, a: &OwnedArtifactV2) -> bool {
        exact_file_matches(a)
    }
    fn artifact_absent(&self, a: &OwnedArtifactV2) -> bool {
        matches!(fs::symlink_metadata(&a.path), Err(error) if error.kind()==std::io::ErrorKind::NotFound)
    }
    fn sync_parents(
        &mut self,
        m: &TieringBootValidationPreparedManifestV2,
    ) -> std::result::Result<(), String> {
        for p in m
            .payload
            .owned_artifacts
            .iter()
            .filter_map(|a| a.path.parent())
        {
            fs::File::open(p)
                .and_then(|f| f.sync_all())
                .map_err(|e| e.to_string())?
        }
        Ok(())
    }
    fn remove_artifact(&mut self, a: &OwnedArtifactV2) -> std::result::Result<(), String> {
        if matches!(fs::symlink_metadata(&a.path), Err(error) if error.kind()==std::io::ErrorKind::NotFound)
        {
            return Ok(());
        }
        if !exact_file_matches(a) {
            return Err("artifact is absent or no longer exact-owned".into());
        }
        fs::remove_file(&a.path).map_err(|e| e.to_string())?;
        sync_parent(&a.path).map_err(|e| e.to_string())
    }
    fn remove_swapfile(
        &mut self,
        m: &TieringBootValidationPreparedManifestV2,
    ) -> std::result::Result<(), String> {
        let p = &m.payload.swapfile.path;
        if !p.exists() {
            return Ok(());
        }
        let tx: DurableTransactionV2 = read_json(&self.tx_path()).map_err(|e| e.to_string())?;
        let expected = tx
            .payload
            .applied_swap_identity
            .as_ref()
            .and_then(|identity| identity.uuid.as_deref())
            .ok_or_else(|| "durable swap UUID is unavailable".to_owned())?;
        let actual = command_output(
            "/usr/bin/blkid",
            &[
                "-s",
                "UUID",
                "-o",
                "value",
                p.to_str().ok_or("swap path UTF-8")?,
            ],
        )
        .map_err(|e| e.to_string())?;
        if actual != expected {
            return Err("refusing to remove swapfile with mismatched UUID".into());
        }
        let mut b = LinuxSwapfileBackend::default();
        b.resume_owned(p).map_err(|e| e.to_string())?;
        SwapfileBackend::remove_owned(&mut b, p).map_err(|e| e.to_string())
    }
    fn swapfile_absent(&self, m: &TieringBootValidationPreparedManifestV2) -> bool {
        matches!(fs::symlink_metadata(&m.payload.swapfile.path), Err(error) if error.kind()==std::io::ErrorKind::NotFound)
    }
    fn finalize_runtime_cleanup(
        &mut self,
        m: &TieringBootValidationPreparedManifestV2,
    ) -> std::result::Result<(), String> {
        run_exact("/usr/bin/systemctl", &["daemon-reload"])?;
        let unit = format!("nemor-phase6-{}.service", m.payload.validation_id);
        let load = command_output(
            "/usr/bin/systemctl",
            &["show", &unit, "--property=LoadState", "--value"],
        )
        .map_err(|e| e.to_string())?;
        if load != "not-found" {
            return Err("validation unit remains loaded after final cleanup".into());
        }
        Ok(())
    }
    fn set_one_shot(&mut self, entry: &str) -> std::result::Result<(), String> {
        run_exact("/usr/bin/bootctl", &["set-oneshot", entry])
    }
    fn read_one_shot(&self) -> std::result::Result<Option<String>, String> {
        command_output("/usr/bin/bootctl", &["status"])
            .map(|v| {
                parse_field(&v, "One Shot Boot Loader Entry:")
                    .or_else(|| parse_field(&v, "One-shot Boot Loader Entry:"))
            })
            .map_err(|e| e.to_string())
    }
    fn permanent_default(&self) -> std::result::Result<String, String> {
        command_output("/usr/bin/bootctl", &["status"])
            .ok()
            .and_then(|v| {
                parse_field(&v, "Default Boot Loader Entry:")
                    .or_else(|| parse_field(&v, "Default Entry:"))
            })
            .ok_or_else(|| "default unavailable".into())
    }
    fn boot_order(&self) -> std::result::Result<Vec<String>, String> {
        let v = command_output("/usr/bin/efibootmgr", &["-v"]).map_err(|e| e.to_string())?;
        Ok(parse_field(&v, "BootOrder:")
            .map(|s| s.split(',').map(str::trim).map(str::to_owned).collect())
            .unwrap_or_default())
    }
    fn current_boot_is_experimental(&self, m: &TieringBootValidationPreparedManifestV2) -> bool {
        read_trimmed(Path::new("/proc/cmdline"))
            .is_ok_and(|v| v.contains(&m.payload.validation_marker))
    }
    fn collect_post_boot(
        &mut self,
        m: &TieringBootValidationPreparedManifestV2,
    ) -> std::result::Result<ActualPostBootObservationV2, String> {
        collect_post_boot(m).map_err(|e| e.to_string())
    }
    fn collect_baseline(
        &self,
        m: &TieringBootValidationPreparedManifestV2,
    ) -> std::result::Result<BaselineRestoreObservationV2, String> {
        collect_baseline(m).map_err(|e| e.to_string())
    }
    fn seal_archive(&mut self, tx: &DurableTransactionV2) -> std::result::Result<(), String> {
        let root = &self.manifest.payload.transaction_root;
        let status = root.join("STATUS");
        let status_bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema":"tiering-boot-validation-status-v2",
            "validation_id":tx.payload.validation_id,
            "stage":tx.payload.stage,
            "production_activation":false,
            "complete":tx.payload.stage==TransactionStageV2::Restored,
        }))
        .map_err(|e| e.to_string())?;
        if status.exists() {
            if fs::read(&status).map_err(|e| e.to_string())? != status_bytes {
                return Err("existing STATUS is not exact".into());
            }
        } else {
            write_new_bytes(&status, &status_bytes, 0o600).map_err(|e| e.to_string())?;
        }
        let sums_path = root.join("SHA256SUMS");
        if sums_path.exists() {
            return verify_sha256sums(root).map_err(|e| e.to_string());
        }
        let mut files = Vec::new();
        for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let metadata = entry.file_type().map_err(|e| e.to_string())?;
            if metadata.is_file() && entry.file_name() != "SHA256SUMS" {
                files.push(entry.file_name());
            }
        }
        files.sort();
        let mut sums = String::new();
        for name in files {
            let path = root.join(&name);
            let hash = sha256_file(&path).map_err(|e| e.to_string())?;
            let name = name.to_str().ok_or("non-UTF8 evidence name")?;
            sums.push_str(&format!("{hash}  {name}\n"));
        }
        write_new_bytes(&sums_path, sums.as_bytes(), 0o600).map_err(|e| e.to_string())?;
        verify_sha256sums(root).map_err(|e| e.to_string())?;
        fs::File::open(root)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())
    }
}

fn verify_sha256sums(root: &Path) -> Result<()> {
    let text = fs::read_to_string(root.join("SHA256SUMS"))?;
    for line in text.lines() {
        let (hash, name) = line.split_once("  ").context("malformed SHA256SUMS")?;
        if name.contains('/') || name.contains("..") || sha256_file(&root.join(name))? != hash {
            bail!("SHA256SUMS verification failed")
        }
    }
    Ok(())
}

fn with_transaction<F>(a: &TransactionArgs, f: F) -> Result<()>
where
    F: FnOnce(
        &TieringBootValidationPreparedManifestV2,
        &DurableTransactionV2,
        &LinuxLifecycleBackend,
    ) -> Result<()>,
{
    let (m, t) = load_transaction(&a.validation_id)?;
    require_authenticated_root(&m)?;
    let b = LinuxLifecycleBackend::new(&m)?;
    f(&m, &t, &b)
}
fn with_transaction_mut<F>(a: &TransactionArgs, f: F) -> Result<()>
where
    F: FnOnce(
        &TieringBootValidationPreparedManifestV2,
        &mut DurableTransactionV2,
        &mut LinuxLifecycleBackend,
    ) -> Result<()>,
{
    let (m, mut t) = load_transaction(&a.validation_id)?;
    require_authenticated_root(&m)?;
    let mut b = LinuxLifecycleBackend::new(&m)?;
    f(&m, &mut t, &mut b)
}
fn load_transaction(
    id: &str,
) -> Result<(
    TieringBootValidationPreparedManifestV2,
    DurableTransactionV2,
)> {
    require_validation_id(id)?;
    let root = Path::new(TRANSACTION_ROOT).join(id);
    let m: TieringBootValidationPreparedManifestV2 =
        read_json(&root.join("prepared-manifest-v2.json"))?;
    let t: DurableTransactionV2 = read_json(&root.join("transaction-v2.json"))?;
    m.validate()?;
    t.validate()?;
    if m.payload.validation_id != id
        || t.payload.validation_id != id
        || t.payload.manifest_sha256 != canonical_json_sha256(&m)
    {
        bail!("transaction identity mismatch")
    };
    Ok((m, t))
}
fn require_stage(t: &DurableTransactionV2, s: TransactionStageV2) -> Result<()> {
    if t.payload.stage != s {
        bail!("illegal stage")
    };
    Ok(())
}

fn experimental_activate(a: TransactionArgs) -> Result<()> {
    let (m, mut t) = load_transaction(&a.validation_id)?;
    if current_uid()? != 0 {
        bail!("root required")
    };
    let cmd = read_trimmed(Path::new("/proc/cmdline"))?;
    if !cmd
        .split_whitespace()
        .any(|v| v == m.payload.validation_marker)
    {
        bail!("validation marker absent")
    };
    let enabled_path = Path::new("/sys/module/zswap/parameters/enabled");
    fs::write(enabled_path, "N")?;
    for (name, value) in &m.payload.experimental_zswap {
        if name == "enabled" {
            continue;
        }
        let path = Path::new("/sys/module/zswap/parameters").join(name);
        fs::write(&path, value)?;
        if read_zswap_parameter(name)? != *value {
            bail!("zswap readback mismatch")
        }
    }
    fs::write(enabled_path, "Y")?;
    if read_trimmed(enabled_path)? != "Y" {
        bail!("zswap enable readback mismatch")
    }
    run_exact(
        "/usr/bin/swapon",
        &[
            "--priority",
            &m.payload.swapfile.priority.to_string(),
            m.payload.swapfile.path.to_str().context("swap path")?,
        ],
    )
    .map_err(anyhow::Error::msg)?;
    let swaps = collect_swaps()?;
    if !swaps
        .iter()
        .any(|s| s.path == m.payload.swapfile.path && s.priority == m.payload.swapfile.priority)
    {
        bail!("validation swap readback mismatch")
    };
    t.payload.current_boot_id = read_trimmed(Path::new("/proc/sys/kernel/random/boot_id"))?;
    let mut b = LinuxLifecycleBackend::new(&m)?;
    b.persist_transaction(&t).map_err(anyhow::Error::msg)
}

fn collect_post_boot(
    m: &TieringBootValidationPreparedManifestV2,
) -> Result<ActualPostBootObservationV2> {
    let boot_id = read_trimmed(Path::new("/proc/sys/kernel/random/boot_id"))?;
    let status = command_output("/usr/bin/bootctl", &["status"])?;
    let booted_entry = parse_field(&status, "Current Boot Loader Entry:")
        .or_else(|| parse_field(&status, "Current Entry:"))
        .context("booted entry")?;
    let before = block_written_bytes(&m.payload.topology.physical.path);
    let oom_before = vmstat_value("oom_kill");
    let swapin_before = vmstat_value("pswpin");
    let start = Instant::now();
    run_bounded_workload_scope(m)?;
    let elapsed = start.elapsed();
    if elapsed.as_secs() > m.payload.workload.timeout_seconds {
        bail!("workload timeout")
    };
    let after = block_written_bytes(&m.payload.topology.physical.path);
    let writes = before.zip(after).and_then(|(a, b)| b.checked_sub(a));
    let counters = collect_zswap_counters();
    let stored = counters.get("stored_pages").copied().flatten();
    let pool = counters.get("pool_total_size").copied().flatten();
    let (daemon_observe_only, production_activation) = production_state(&m.payload.config_path)?;
    let oom_kill = oom_before
        .zip(vmstat_value("oom_kill"))
        .is_some_and(|(a, b)| b > a);
    Ok(ActualPostBootObservationV2 {
        schema: POST_BOOT_EVIDENCE_SCHEMA_V2.into(),
        boot_id,
        booted_entry,
        command_line: read_trimmed(Path::new("/proc/cmdline"))?,
        kernel_release: read_trimmed(Path::new("/proc/sys/kernel/osrelease"))?,
        zswap: collect_zswap()?,
        swaps: collect_swaps()?,
        protected_zram: collect_zram(&collect_swaps()?)?,
        topology: collect_topology()?,
        unit_active: command_output(
            "/usr/bin/systemctl",
            &[
                "is-active",
                &format!("nemor-phase6-{}.service", m.payload.validation_id),
            ],
        )
        .is_ok_and(|v| v == "active"),
        workload_scope_absent: command_output(
            "/usr/bin/systemctl",
            &[
                "show",
                &format!("nemor-phase6-workload-{}.scope", m.payload.validation_id),
                "--property=LoadState",
                "--value",
            ],
        )
        .is_ok_and(|value| value == "not-found"),
        daemon_observe_only,
        production_activation,
        zswap_counters: counters,
        block_write_bytes: writes,
        latency_ns: Some(elapsed.as_nanos().min(u128::from(u64::MAX)) as u64),
        throughput_bytes_per_second: Some(
            m.payload
                .workload
                .bytes
                .saturating_mul(u64::from(m.payload.workload.iterations))
                / elapsed.as_secs().max(1),
        ),
        compression_ratio_milli: stored.zip(pool).map(|(pages, bytes)| {
            pages
                .saturating_mul(4096)
                .saturating_mul(1000)
                .checked_div(bytes)
                .unwrap_or(0)
        }),
        refault_observed: swapin_before
            .zip(vmstat_value("pswpin"))
            .is_some_and(|(before, after)| after > before),
        oom: oom_kill,
        oom_kill,
        workload_completed: true,
    })
}

fn run_bounded_workload_scope(m: &TieringBootValidationPreparedManifestV2) -> Result<()> {
    let binary = m
        .payload
        .binaries
        .get("nemor-tiering-boot-validation")
        .context("validator identity")?;
    let unit = format!("nemor-phase6-workload-{}.scope", m.payload.validation_id);
    let memory_max = m.payload.workload.bytes.to_string();
    let swap_max = m.payload.workload.bytes.saturating_mul(2).to_string();
    let mut child = Command::new("/usr/bin/systemd-run")
        .args([
            "--scope",
            "--wait",
            "--collect",
            "--quiet",
            "--unit",
            &unit,
            "--property",
            &format!("MemoryMax={memory_max}"),
            "--property",
            &format!("MemorySwapMax={swap_max}"),
            binary.path.to_str().context("validator path")?,
            "bounded-workload",
            "--validation-id",
            &m.payload.validation_id,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline =
        Instant::now() + std::time::Duration::from_secs(m.payload.workload.timeout_seconds);
    loop {
        match child.try_wait()? {
            Some(status) if status.success() => return Ok(()),
            Some(status) => bail!("bounded workload scope exited {status}"),
            None if Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            None => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("bounded workload scope timeout")
            }
        }
    }
}

fn bounded_workload(a: TransactionArgs) -> Result<()> {
    let (m, t) = load_transaction(&a.validation_id)?;
    if current_uid()? != 0 || t.payload.stage != TransactionStageV2::PostBootMeasuring {
        bail!("bounded workload is authorized only by the measuring transaction")
    }
    let command_line = read_trimmed(Path::new("/proc/cmdline"))?;
    if !command_line
        .split_whitespace()
        .any(|item| item == m.payload.validation_marker)
    {
        bail!("validation marker absent")
    }
    let bytes = m.payload.workload.bytes.saturating_mul(2);
    let length: usize = bytes.try_into().context("workload size")?;
    let mut memory = vec![0_u8; length];
    for iteration in 0..m.payload.workload.iterations {
        for (index, byte) in memory.iter_mut().enumerate().step_by(4096) {
            *byte = (index as u8).wrapping_add(iteration as u8);
        }
        std::hint::black_box(&memory);
    }
    Ok(())
}

fn production_state(config_path: &Path) -> Result<(bool, bool)> {
    let config = Config::from_toml(&fs::read_to_string(config_path)?)?;
    let observe_only = config.tiering.dry_run
        && !config.tiering.allow_runtime_reconfigure
        && !config.tiering.allow_persistent_reconfigure
        && !config.tiering.allow_swapfile_create;
    Ok((observe_only, !observe_only))
}

fn collect_baseline(
    m: &TieringBootValidationPreparedManifestV2,
) -> Result<BaselineRestoreObservationV2> {
    let status = command_output("/usr/bin/bootctl", &["status"])?;
    let booted = parse_field(&status, "Current Boot Loader Entry:")
        .or_else(|| parse_field(&status, "Current Entry:"))
        .context("entry")?;
    let default = parse_field(&status, "Default Boot Loader Entry:")
        .or_else(|| parse_field(&status, "Default Entry:"))
        .context("default")?;
    let one = parse_field(&status, "One Shot Boot Loader Entry:")
        .or_else(|| parse_field(&status, "One-shot Boot Loader Entry:"));
    let swaps = collect_swaps()?;
    Ok(BaselineRestoreObservationV2 {
        schema: FINAL_RESTORE_SCHEMA_V2.into(),
        boot_id: read_trimmed(Path::new("/proc/sys/kernel/random/boot_id"))?,
        booted_entry: booted,
        command_line: read_trimmed(Path::new("/proc/cmdline"))?,
        zswap: collect_zswap()?,
        protected_zram: collect_zram(&swaps)?,
        swaps,
        default_entry: default,
        boot_order: LinuxLifecycleBackend::new(m)?
            .boot_order()
            .map_err(anyhow::Error::msg)?,
        one_shot: one,
        production_activation: false,
    })
}

fn recover(a: TransactionArgs, idempotence: bool) -> Result<()> {
    let (m, mut t) = load_transaction(&a.validation_id)?;
    require_authenticated_root(&m)?;
    let mut b = LinuxLifecycleBackend::new(&m)?;
    let experimental = b.current_boot_is_experimental(&m);
    let recovery_stage = t.payload.failed_from_stage.unwrap_or(t.payload.stage);
    if t.payload.stage == TransactionStageV2::Failed {
        t.payload.stage = recovery_stage;
        t.payload.recovery_state = "resuming_failed_stage".into();
        t.payload_sha256 = canonical_json_sha256(&t.payload);
        b.persist_transaction(&t).map_err(anyhow::Error::msg)?;
    }
    match recovery_action_v2(recovery_stage, experimental) {
        "no_op" => {
            if !idempotence {
                print_json(&t)
            } else {
                verify_sha256sums(&m.payload.transaction_root)?;
                print_json(&serde_json::json!({
                    "schema":"tiering-idempotence-verification-v2",
                    "validation_id":m.payload.validation_id,
                    "stage":t.payload.stage,
                    "mutation_count":0,
                    "already_clean":true
                }))
            }
        }
        "select_exact_baseline_oneshot_preserve_artifacts" => {
            select_baseline_rollback_v2(&m, &mut t, &mut b)?;
            print_json(&t)
        }
        "verify_baseline_preserve_artifacts" | "resume_exact_cleanup" => {
            verify_then_cleanup_v2(&m, &mut t, &mut b)?;
            print_json(&t)
        }
        "remove_exact_owned_before_reboot" | "clear_exact_owned_oneshot_then_remove" => {
            if idempotence {
                bail!("idempotence verification cannot mutate")
            };
            if recovery_action_v2(recovery_stage, experimental)
                == "clear_exact_owned_oneshot_then_remove"
            {
                if b.read_one_shot().map_err(anyhow::Error::msg)?.as_deref()
                    != Some(&m.payload.experimental_entry.id)
                {
                    bail!("one-shot state is not exact-owned; preserving all artifacts")
                }
                run_exact("/usr/bin/bootctl", &["set-oneshot", ""]).map_err(anyhow::Error::msg)?;
                if b.read_one_shot().map_err(anyhow::Error::msg)?.is_some() {
                    bail!("owned one-shot state did not clear")
                }
            }
            for art in m.payload.owned_artifacts.iter().rev() {
                if b.artifact_matches(art) {
                    b.remove_artifact(art).map_err(anyhow::Error::msg)?
                }
            }
            b.remove_swapfile(&m).map_err(anyhow::Error::msg)?;
            t.payload.stage = TransactionStageV2::Recovered;
            t.payload.recovery_state = "recovered_before_reboot".into();
            t.payload_sha256 = canonical_json_sha256(&t.payload);
            b.persist_transaction(&t).map_err(anyhow::Error::msg)?;
            print_json(&t)
        }
        other => bail!("recovery requires diagnosis: {other}"),
    }
}

fn read_manifest(path: &Path) -> Result<TieringBootValidationPreparedManifestV2> {
    let m: TieringBootValidationPreparedManifestV2 = read_json(path)?;
    m.validate()?;
    let md = fs::symlink_metadata(path)?;
    if !md.file_type().is_file()
        || md.file_type().is_symlink()
        || md.uid() != current_uid()? && current_uid()? != 0
        || md.mode() & 0o777 != 0o600
    {
        bail!("manifest ownership/mode invalid")
    };
    Ok(m)
}
fn read_json<T: DeserializeOwned>(p: &Path) -> Result<T> {
    serde_json::from_slice(&fs::read(p)?).context("parse sealed JSON")
}
fn print_json(v: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}
fn write_new_json(p: &Path, v: &impl Serialize, mode: u32) -> Result<()> {
    let mut b = serde_json::to_vec_pretty(v)?;
    b.push(b'\n');
    write_new_bytes(p, &b, mode)
}
fn write_new_bytes(p: &Path, b: &[u8], mode: u32) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(p)?;
    f.write_all(b)?;
    f.sync_all()?;
    sync_parent(p)
}
fn atomic_replace_json(p: &Path, v: &impl Serialize) -> Result<()> {
    let tmp = p.with_extension("new");
    if tmp.exists() {
        bail!("stale transaction temp file")
    };
    write_new_json(&tmp, v, 0o600)?;
    fs::rename(&tmp, p)?;
    sync_parent(p)
}
fn sync_parent(p: &Path) -> Result<()> {
    fs::File::open(p.parent().context("parent")?)?.sync_all()?;
    Ok(())
}
fn exact_file_matches(a: &OwnedArtifactV2) -> bool {
    fs::symlink_metadata(&a.path).ok().is_some_and(|m| {
        m.file_type().is_file()
            && !m.file_type().is_symlink()
            && m.uid() == a.owner_uid
            && m.gid() == a.owner_gid
            && m.mode() & 0o7777 == a.mode
            && m.nlink() == 1
    }) && sha256_file(&a.path).ok().as_deref() == Some(&a.sha256)
}
fn sha256(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn major(device: u64) -> u64 {
    ((device >> 8) & 0x0fff) | ((device >> 32) & !0x0fff)
}

fn minor(device: u64) -> u64 {
    (device & 0x00ff) | ((device >> 12) & !0x00ff)
}
fn sha256_file(p: &Path) -> Result<String> {
    Ok(sha256(&fs::read(p)?))
}
fn command_output(program: &str, args: &[&str]) -> Result<String> {
    let o = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if !o.status.success() {
        bail!("{} failed", program)
    };
    Ok(String::from_utf8(o.stdout)?.trim().to_owned())
}
fn run_exact(program: &str, args: &[&str]) -> std::result::Result<(), String> {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .map_err(|e| e.to_string())
        .and_then(|s| {
            if s.success() {
                Ok(())
            } else {
                Err(format!("{program} exited {s}"))
            }
        })
}
fn git_output(args: &[&str]) -> Result<String> {
    command_output("/usr/bin/git", args)
}
fn parse_field(t: &str, n: &str) -> Option<String> {
    t.lines()
        .find_map(|l| l.trim().strip_prefix(n).map(str::trim))
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}
fn read_trimmed(p: &Path) -> Result<String> {
    Ok(fs::read_to_string(p)?.trim().to_owned())
}
fn read_u64(p: &str) -> Result<u64> {
    Ok(read_trimmed(Path::new(p))?.parse()?)
}
fn current_uid() -> Result<u32> {
    Ok(command_output("/usr/bin/id", &["-u"])?.parse()?)
}
fn current_gid() -> Result<u32> {
    Ok(command_output("/usr/bin/id", &["-g"])?.parse()?)
}
fn env_u32(n: &str) -> Result<u32> {
    Ok(std::env::var(n)
        .with_context(|| format!("{n} absent"))?
        .parse()?)
}
fn require_validation_id(id: &str) -> Result<()> {
    if !(8..=64).contains(&id.len())
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        bail!("invalid validation id")
    };
    Ok(())
}
fn require_private_owned_parent(p: &Path, uid: u32) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid() != uid || m.mode() & 0o077 != 0 {
        bail!("prepared parent must be private and user-owned")
    };
    Ok(())
}
fn path_absent_and_parent_safe(p: &Path) -> bool {
    if p.exists()
        || p.components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return false;
    }
    let Some(mut parent) = p.parent() else {
        return false;
    };
    while !parent.exists() {
        let Some(next) = parent.parent() else {
            return false;
        };
        parent = next;
    }
    let mut cursor = Some(parent);
    while let Some(path) = cursor {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return false;
        };
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return false;
        }
        cursor = path.parent().filter(|next| *next != path);
    }
    true
}
fn free_bytes(p: &Path) -> Result<u64> {
    let s = command_output(
        "/usr/bin/df",
        &["-B1", "--output=avail", p.to_str().context("path")?],
    )?;
    Ok(s.lines().last().context("df")?.trim().parse()?)
}
fn ac_power() -> Option<bool> {
    let entries = fs::read_dir("/sys/class/power_supply").ok()?;
    let mut seen = false;
    for e in entries.flatten() {
        if read_trimmed(&e.path().join("type")).ok().as_deref() == Some("Mains") {
            seen = true;
            if read_trimmed(&e.path().join("online")).ok().as_deref() == Some("1") {
                return Some(true);
            }
        }
    }
    seen.then_some(false)
}
fn no_other_validator_process() -> bool {
    let self_pid = std::process::id();
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    !entries
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .filter(|p| *p != self_pid)
        .any(|p| {
            fs::read_to_string(format!("/proc/{p}/cmdline"))
                .ok()
                .is_some_and(|v| v.contains("nemor-tiering-boot-validation"))
        })
}
fn block_written_bytes(device: &Path) -> Option<u64> {
    let name = device.file_name()?.to_str()?;
    let stat = read_trimmed(&Path::new("/sys/class/block").join(name).join("stat")).ok()?;
    stat.split_whitespace()
        .nth(6)?
        .parse::<u64>()
        .ok()
        .map(|v| v * 512)
}
fn vmstat_value(name: &str) -> Option<u64> {
    fs::read_to_string("/proc/vmstat")
        .ok()?
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(' ')?;
            (k == name).then(|| v.trim().parse().ok()).flatten()
        })
}
fn collect_zswap_counters() -> BTreeMap<String, Option<u64>> {
    let mut out = BTreeMap::new();
    for root in ["/sys/kernel/debug/zswap", "/sys/kernel/mm/zswap"] {
        if let Ok(entries) = fs::read_dir(root) {
            for e in entries.flatten() {
                if e.file_type().is_ok_and(|t| t.is_file()) {
                    out.insert(
                        e.file_name().to_string_lossy().into_owned(),
                        read_trimmed(&e.path()).ok().and_then(|v| v.parse().ok()),
                    );
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn prepare_cli_does_not_accept_or_require_a_manifest() {
        let cli = Cli::try_parse_from([
            "validator",
            "prepare",
            "--validation-id",
            "phase6-test-1",
            "--prepared-root",
            "/tmp/prepared",
            "--config",
            "/tmp/config.toml",
            "--validator-binary",
            "/tmp/validator",
        ])
        .unwrap();
        assert!(matches!(cli.command, LifecycleCommand::Prepare(_)));
    }

    #[test]
    fn mutating_cli_has_no_output_evidence_or_artifact_path() {
        assert!(Cli::try_parse_from([
            "validator",
            "select-one-shot",
            "--validation-id",
            "phase6-test-1",
            "--output",
            "/tmp/evil"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "validator",
            "post-boot-validate",
            "--validation-id",
            "phase6-test-1",
            "--evidence",
            "/tmp/success.json"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "validator",
            "recover",
            "--validation-id",
            "phase6-test-1",
            "--artifact",
            "/boot/foreign"
        ])
        .is_err());
    }

    #[test]
    fn experimental_options_remove_conflicts_and_are_exact() {
        let zswap = BTreeMap::from([
            ("enabled".into(), "Y".into()),
            ("compressor".into(), "zstd".into()),
            ("zpool".into(), "zsmalloc".into()),
            ("max_pool_percent".into(), "20".into()),
            ("accept_threshold_percent".into(), "90".into()),
            ("shrinker_enabled".into(), "N".into()),
        ]);
        let options = build_experimental_options(
            "quiet zswap.enabled=0 zswap.zpool=zbud",
            "nemor.phase6_validation=phase6-test-1",
            "nemor-phase6-phase6-test-1.service",
            &zswap,
        );
        assert!(!options.contains("zswap.enabled=0"));
        assert!(!options.contains("zswap.zpool=zbud"));
        assert!(options.contains("zswap.enabled=1"));
        assert!(options.contains("zswap.zpool=zsmalloc"));
        assert!(options.contains("systemd.wants=nemor-phase6-phase6-test-1.service"));
    }

    #[test]
    fn validation_ids_reject_path_grammar() {
        assert!(require_validation_id("phase6-good-1").is_ok());
        assert!(require_validation_id("../phase6").is_err());
        assert!(require_validation_id("UPPERCASE").is_err());
    }

    #[test]
    fn entry_parser_uses_exact_keys_not_substrings() {
        let text = "title Linux\nlinux /vmlinuz\ninitrd /initrd\noptions quiet\n";
        assert_eq!(entry_value(text, "linux").as_deref(), Some("/vmlinuz"));
        assert_eq!(entry_value(text, "options").as_deref(), Some("quiet"));
        assert!(entry_value(text, "efi").is_none());
    }

    #[test]
    fn create_new_json_refuses_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.json");
        write_new_json(&path, &serde_json::json!({"first":true}), 0o600).unwrap();
        assert!(write_new_json(&path, &serde_json::json!({"second":true}), 0o600).is_err());
    }

    #[test]
    fn production_state_requires_all_observe_only_guards() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("default.toml");
        fs::write(&path, include_str!("../../../../config/default.toml")).unwrap();
        assert_eq!(production_state(&path).unwrap(), (true, false));
    }
}
