#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use common::Config;
use nemor_test_support::BUILD_GIT_HEAD;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;
use tiering::boot_validation_v5::*;
use tiering::*;

#[derive(Debug, Parser)]
#[command(about = "Validation-only Phase 6 systemd-boot Type #1 lifecycle v5")]
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
    /// Authorize and seal the same-host zram baseline; no boot/swap mutation.
    MeasureBaseline(ManifestArgs),
    /// Initialize the exact durable transaction and apply exact-owned artifacts.
    Apply(TransactionArgs),
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
            validate_preflight_v5(&manifest, &observation, false)?;
            print_json(&observation)
        }
        LifecycleCommand::RootPreflight(args) => {
            require_authenticated_root(&read_manifest(&args.manifest)?)?;
            let manifest = read_manifest(&args.manifest)?;
            let observation = collect_preflight(&manifest, true)?;
            validate_preflight_v5(&manifest, &observation, true)?;
            print_json(&observation)
        }
        LifecycleCommand::MeasureBaseline(args) => {
            let manifest = read_manifest(&args.manifest)?;
            require_authenticated_root(&manifest)?;
            let root = collect_preflight(&manifest, true)?;
            let boot_id = read_trimmed(Path::new("/proc/sys/kernel/random/boot_id"))?;
            let mut backend = LinuxLifecycleBackend::new(&manifest)?;
            let tx = initialize_and_measure_baseline_v5(&manifest, &root, boot_id, &mut backend)?;
            print_json(&tx)
        }
        LifecycleCommand::Apply(args) => with_transaction_mut(&args, |m, t, b| {
            apply_exact_transaction_v5(m, t, b)?;
            print_json(t)
        }),
        LifecycleCommand::VerifyApplied(args) => with_transaction(&args, |m, t, b| {
            require_stage(t, TransactionStageV5::Applied)?;
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
            select_exact_one_shot_v5(m, t, b)?;
            print_json(t)
        }),
        LifecycleCommand::PostBootValidate(args) => with_transaction_mut(&args, |m, t, b| {
            let evidence = collect_and_validate_post_boot_v5(m, t, b)?;
            print_json(&evidence)
        }),
        LifecycleCommand::SelectBaselineRollback(args) => with_transaction_mut(&args, |m, t, b| {
            select_baseline_rollback_v5(m, t, b)?;
            print_json(t)
        }),
        LifecycleCommand::VerifyFinalRestore(args) => with_transaction_mut(&args, |m, t, b| {
            verify_then_cleanup_v5(m, t, b)?;
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
    let manifest = TieringBootValidationPreparedManifestV5::seal(payload);
    manifest.validate()?;
    fs::create_dir(&args.prepared_root).context("create fresh prepared root")?;
    fs::set_permissions(&args.prepared_root, fs::Permissions::from_mode(0o700))?;
    let path = args.prepared_root.join("prepared-manifest-v5.json");
    write_new_json(&path, &manifest, 0o600)?;
    print_json(
        &serde_json::json!({"manifest":path,"sha256":canonical_json_sha256_v5(&manifest),"mutation":false}),
    )
}

fn collect_prepared_payload(args: &PrepareArgs) -> Result<PreparedManifestPayloadV5> {
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
    let supplied_validator_metadata = fs::symlink_metadata(&args.validator_binary)?;
    if !supplied_validator_metadata.file_type().is_file()
        || supplied_validator_metadata.file_type().is_symlink()
    {
        bail!("validator source must be a regular non-symlink file")
    }
    let validator_metadata = fs::symlink_metadata(&validator)?;
    if validator_metadata.nlink() != 1 || validator_metadata.mode() & 0o022 != 0 {
        bail!("validator source ownership/mode/link identity is unsafe")
    }
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
    let mut experimental_entry = BootEntryIdentityV5 {
        id: format!("nemor-phase6-{}.conf", args.validation_id),
        path: Path::new("/boot/loader/entries")
            .join(format!("nemor-phase6-{}.conf", args.validation_id)),
        sha256: String::new(),
        title: boot.current_entry.title.clone(),
        linux_or_efi: boot.current_entry.linux_or_efi.clone(),
        initrds: boot.current_entry.initrds.clone(),
        options: String::new(),
    };
    let tx_root = Path::new(TRANSACTION_ROOT_V5).join(&args.validation_id);
    let mut experimental_zswap = baseline_zswap.parameters.clone();
    experimental_zswap.insert("enabled".into(), "Y".into());
    experimental_entry.options = build_experimental_options(
        &boot.current_entry.options,
        &marker,
        &unit_name,
        &experimental_zswap,
    );
    let mut payload = PreparedManifestPayloadV5 {
        contract_version: BOOT_VALIDATION_CONTRACT_VERSION_V5.into(),
        rule_version: TIERING_RULE_VERSION.into(),
        validation_id: args.validation_id.clone(),
        prepared_uid: uid,
        prepared_gid: gid,
        source_commit: source_commit.clone(),
        source_state_sha256,
        binaries: BTreeMap::from([(
            "nemor-tiering-boot-validation".into(),
            BinaryIdentityV5 {
                path: validator.clone(),
                sha256: validator_hash.clone(),
                embedded_commit: embedded_commit.clone(),
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
        swapfile: SwapIdentityV5 {
            path: tx_root.join("backing.swap"),
            kind: "file".into(),
            size_bytes: args.swap_size_bytes,
            priority: args.swap_priority,
            uuid: None,
            active: false,
        },
        owned_artifacts: Vec::new(),
        transaction_root: tx_root.clone(),
        workload: WorkloadContractV5 {
            protocol: WORKLOAD_PROTOCOL_V5.into(),
            seed: 0x4e454d4f52,
            bytes: 32 * 1024 * 1024,
            iterations: 2,
            timeout_seconds: args.timeout_seconds,
            maximum_write_bytes: args.maximum_write_bytes,
        },
        staged_helper: StagedBinaryPlanV5 {
            source: BinaryIdentityV5 {
                path: validator.clone(),
                sha256: validator_hash.clone(),
                embedded_commit: embedded_commit.clone(),
            },
            destination: tx_root.join("bin/nemor-tiering-boot-validation"),
            destination_mode: 0o755,
            destination_uid: 0,
            destination_gid: 0,
            require_single_link: true,
            source_uid: validator_metadata.uid(),
            source_gid: validator_metadata.gid(),
            source_mode: validator_metadata.mode() & 0o7777,
            source_link_count: validator_metadata.nlink(),
            source_device: validator_metadata.dev(),
            source_inode: validator_metadata.ino(),
        },
        recovery_entry: String::new(),
        production_activation: false,
    };
    payload.recovery_entry = payload.boot.current_entry.id.clone();
    let entry_content = render_type1_entry_v5(&payload.experimental_entry).into_bytes();
    payload.experimental_entry.sha256 = sha256(&entry_content);
    let unit_content =
        render_validation_unit_v5(&payload, &payload.staged_helper.destination).into_bytes();
    payload.owned_artifacts = vec![
        artifact(
            OwnedArtifactKindV5::Type1Entry,
            payload.experimental_entry.path.clone(),
            entry_content,
            0o600,
        ),
        artifact(
            OwnedArtifactKindV5::ValidationUnit,
            Path::new("/etc/systemd/system").join(unit_name),
            unit_content,
            0o644,
        ),
        OwnedArtifactV5 {
            kind: OwnedArtifactKindV5::HelperBinary,
            path: payload.staged_helper.destination.clone(),
            sha256: payload.staged_helper.source.sha256.clone(),
            mode: 0o755,
            owner_uid: 0,
            owner_gid: 0,
            content: Vec::new(),
        },
    ];
    Ok(payload)
}

fn artifact(
    kind: OwnedArtifactKindV5,
    path: PathBuf,
    content: Vec<u8>,
    mode: u32,
) -> OwnedArtifactV5 {
    OwnedArtifactV5 {
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

fn collect_topology() -> Result<StorageTopologyIdentityV5> {
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
        chain.push(BlockLayerIdentityV5 {
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
    Ok(StorageTopologyIdentityV5 {
        storage_profile_version: STORAGE_PROFILE_VERSION.into(),
        profile,
        chain,
        physical: PhysicalDeviceIdentityV5 {
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
        filesystem: FilesystemIdentityV5 {
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

fn collect_swaps() -> Result<Vec<SwapIdentityV5>> {
    let text = fs::read_to_string("/proc/swaps")?;
    text.lines()
        .skip(1)
        .map(|line| {
            let f: Vec<_> = line.split_whitespace().collect();
            if f.len() < 5 {
                bail!("malformed /proc/swaps")
            };
            Ok(SwapIdentityV5 {
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

fn collect_zram(swaps: &[SwapIdentityV5]) -> Result<ZramIdentityV5> {
    let swap = swaps
        .iter()
        .find(|s| s.path == Path::new("/dev/zram0"))
        .context("protected zram0 swap")?;
    Ok(ZramIdentityV5 {
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

fn collect_zswap() -> Result<ZswapIdentityV5> {
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
    Ok(ZswapIdentityV5 { parameters })
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

fn collect_boot_identity() -> Result<BootIdentityV5> {
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
        referenced.push(ReferencedBootFileV5 {
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
    let mount_identity = command_output("/usr/bin/findmnt", &["-nro", "ID,MAJ:MIN", "/boot"])?;
    let mut mount_fields = mount_identity.split_whitespace();
    let esp_mount_id = mount_fields.next().context("ESP mount id")?.parse()?;
    let (esp_device_major, esp_device_minor) = mount_fields
        .next()
        .context("ESP major:minor")?
        .split_once(':')
        .context("ESP major:minor grammar")?;
    Ok(BootIdentityV5 {
        bootloader: "systemd-boot-type1".into(),
        bootloader_version: command_output("/usr/bin/bootctl", &["--version"])?,
        current_entry: current.clone(),
        default_entry: default,
        boot_order,
        prior_one_shot: None,
        esp_mount: PathBuf::from("/boot"),
        esp_device,
        esp_filesystem,
        esp_uuid: esp_uuid.trim().into(),
        esp_mount_id,
        esp_device_major: esp_device_major.parse()?,
        esp_device_minor: esp_device_minor.parse()?,
        secure_boot: "disabled".into(),
        kernel_release: read_trimmed(Path::new("/proc/sys/kernel/osrelease"))?,
        referenced_files: referenced,
        current_command_line: read_trimmed(Path::new("/proc/cmdline"))?,
    })
}

fn parse_type1_entry(id: &str) -> Result<BootEntryIdentityV5> {
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
    Ok(BootEntryIdentityV5 {
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
    m: &TieringBootValidationPreparedManifestV5,
    root: bool,
) -> Result<PreflightObservationV5> {
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
    let bootloader_type_matches = boot
        .as_ref()
        .is_ok_and(|v| v.bootloader == m.payload.boot.bootloader);
    let bootloader_version_matches = boot
        .as_ref()
        .is_ok_and(|v| v.bootloader_version == m.payload.boot.bootloader_version);
    let current_entry_matches = boot
        .as_ref()
        .is_ok_and(|v| v.current_entry == m.payload.boot.current_entry);
    let default_entry_matches = boot
        .as_ref()
        .is_ok_and(|v| v.default_entry == m.payload.boot.default_entry);
    let mut observation = PreflightObservationV5 {
        schema: PREFLIGHT_SCHEMA_V5.into(),
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
        bootloader_type_matches,
        bootloader_version_matches,
        current_entry_semantics_match: current_entry_matches,
        current_entry_hash_matches: current_entry_matches,
        current_entry_path_matches: current_entry_matches,
        default_entry_semantics_match: default_entry_matches,
        default_entry_hash_matches: default_entry_matches,
        default_entry_path_matches: default_entry_matches,
        referenced_boot_files_match: boot
            .as_ref()
            .is_ok_and(|v| v.referenced_files == m.payload.boot.referenced_files),
        kernel_release_matches: boot
            .as_ref()
            .is_ok_and(|v| v.kernel_release == m.payload.boot.kernel_release),
        command_line_matches: boot
            .as_ref()
            .is_ok_and(|v| v.current_command_line == m.payload.boot.current_command_line),
        esp_device_matches: boot
            .as_ref()
            .is_ok_and(|v| v.esp_device == m.payload.boot.esp_device),
        esp_filesystem_matches: boot
            .as_ref()
            .is_ok_and(|v| v.esp_filesystem == m.payload.boot.esp_filesystem),
        esp_uuid_matches: boot
            .as_ref()
            .is_ok_and(|v| v.esp_uuid == m.payload.boot.esp_uuid),
        esp_mount_matches: boot.as_ref().is_ok_and(|v| {
            v.esp_mount == m.payload.boot.esp_mount
                && v.esp_mount_id == m.payload.boot.esp_mount_id
                && v.esp_device_major == m.payload.boot.esp_device_major
                && v.esp_device_minor == m.payload.boot.esp_device_minor
        }),
        boot_order_matches,
        one_shot_matches,
        zram_matches,
        zswap_matches,
        parents_safe,
        transaction_hierarchy_safe: transaction_hierarchy_safe(&m.payload.transaction_root),
        staged_source_binary_matches: staged_source_matches(&m.payload.staged_helper),
        validation_destinations_absent: m
            .payload
            .owned_artifacts
            .iter()
            .all(|artifact| !artifact.path.exists()),
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
        ready: false,
    };
    observation.ready = derived_preflight_ready_v5(m, &observation);
    Ok(observation)
}

fn require_authenticated_root(m: &TieringBootValidationPreparedManifestV5) -> Result<()> {
    if current_uid()? != 0
        || env_u32("SUDO_UID")? != m.payload.prepared_uid
        || env_u32("SUDO_GID")? != m.payload.prepared_gid
    {
        bail!("exact authenticated SUDO_UID/SUDO_GID required")
    };
    Ok(())
}

struct LinuxLifecycleBackend {
    manifest: TieringBootValidationPreparedManifestV5,
}
impl LinuxLifecycleBackend {
    fn new(m: &TieringBootValidationPreparedManifestV5) -> Result<Self> {
        m.validate()?;
        Ok(Self {
            manifest: m.clone(),
        })
    }
    fn tx_path(&self) -> PathBuf {
        self.manifest
            .payload
            .transaction_root
            .join("transaction-v5.json")
    }
}

impl BootLifecycleBackendV5 for LinuxLifecycleBackend {
    fn persist_transaction(
        &mut self,
        tx: &DurableTransactionV5,
    ) -> std::result::Result<(), String> {
        atomic_replace_json(&self.tx_path(), tx).map_err(|e| e.to_string())
    }
    fn create_transaction_root(
        &mut self,
        m: &TieringBootValidationPreparedManifestV5,
    ) -> std::result::Result<(), String> {
        let components = [
            PathBuf::from("/var/lib/nemor"),
            PathBuf::from("/var/lib/nemor/validation"),
            PathBuf::from(TRANSACTION_ROOT_V5),
            m.payload.transaction_root.clone(),
        ];
        let mut created = Vec::new();
        for path in components {
            if path.exists() {
                let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
                if !metadata.file_type().is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != 0
                    || metadata.gid() != 0
                    || metadata.mode() & 0o7777 != 0o700
                {
                    return Err(format!(
                        "unsafe existing transaction hierarchy: {}",
                        path.display()
                    ));
                }
                continue;
            }
            if let Err(primary) = fs::create_dir(&path)
                .and_then(|()| fs::set_permissions(&path, fs::Permissions::from_mode(0o700)))
                .and_then(|()| sync_parent(&path).map_err(std::io::Error::other))
            {
                let secondary: Vec<_> = created
                    .iter()
                    .rev()
                    .filter_map(|created: &PathBuf| fs::remove_dir(created).err())
                    .map(|error| error.to_string())
                    .collect();
                return Err(format!(
                    "transaction hierarchy component failed: {primary}; secondary={secondary:?}"
                ));
            }
            created.push(path);
        }
        Ok(())
    }
    fn copy_prepared_manifest(
        &mut self,
        m: &TieringBootValidationPreparedManifestV5,
    ) -> std::result::Result<(), String> {
        write_new_json(
            &m.payload.transaction_root.join("prepared-manifest-v5.json"),
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
        m: &TieringBootValidationPreparedManifestV5,
    ) -> std::result::Result<SwapIdentityV5, String> {
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
        Ok(SwapIdentityV5 {
            uuid: Some(uuid),
            ..m.payload.swapfile.clone()
        })
    }
    fn create_artifact(&mut self, a: &OwnedArtifactV5) -> std::result::Result<(), String> {
        write_new_bytes(&a.path, &a.content, a.mode).map_err(|e| e.to_string())
    }
    fn stage_helper(&mut self, plan: &StagedBinaryPlanV5) -> std::result::Result<(), String> {
        if !staged_source_matches(plan) {
            return Err("staged-helper source changed before copy".into());
        }
        let parent = plan.destination.parent().ok_or("staged-helper parent")?;
        fs::create_dir(parent).map_err(|e| e.to_string())?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        fs::File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|e| e.to_string())?;
        let mut source = fs::File::open(&plan.source.path).map_err(|e| e.to_string())?;
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(plan.destination_mode)
            .open(&plan.destination)
            .map_err(|e| e.to_string())?;
        if let Err(primary) = std::io::copy(&mut source, &mut destination)
            .and_then(|_| destination.sync_all())
            .and_then(|_| sync_parent(&plan.destination).map_err(std::io::Error::other))
        {
            let cleanup = fs::remove_file(&plan.destination).err();
            return Err(format!(
                "staged-helper copy failed: {primary}; cleanup={cleanup:?}"
            ));
        }
        if !self.staged_helper_matches(plan) {
            return Err("staged-helper readback mismatch".into());
        }
        Ok(())
    }
    fn staged_helper_matches(&self, plan: &StagedBinaryPlanV5) -> bool {
        let metadata = match fs::symlink_metadata(&plan.destination) {
            Ok(metadata) => metadata,
            Err(_) => return false,
        };
        metadata.file_type().is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == plan.destination_uid
            && metadata.gid() == plan.destination_gid
            && metadata.mode() & 0o7777 == plan.destination_mode
            && metadata.nlink() == 1
            && sha256_file(&plan.destination).ok().as_deref() == Some(&plan.source.sha256)
            && command_output(
                plan.destination.to_str().unwrap_or_default(),
                &["build-git-head"],
            )
            .ok()
            .as_deref()
                == Some(&plan.source.embedded_commit)
    }
    fn artifact_matches(&self, a: &OwnedArtifactV5) -> bool {
        exact_file_matches(a)
    }
    fn artifact_absent(&self, a: &OwnedArtifactV5) -> bool {
        matches!(fs::symlink_metadata(&a.path), Err(error) if error.kind()==std::io::ErrorKind::NotFound)
    }
    fn sync_parents(
        &mut self,
        m: &TieringBootValidationPreparedManifestV5,
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
    fn remove_artifact(&mut self, a: &OwnedArtifactV5) -> std::result::Result<(), String> {
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
        m: &TieringBootValidationPreparedManifestV5,
    ) -> std::result::Result<(), String> {
        let p = &m.payload.swapfile.path;
        if !p.exists() {
            return Ok(());
        }
        let tx: DurableTransactionV5 = read_json(&self.tx_path()).map_err(|e| e.to_string())?;
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
    fn swapfile_absent(&self, m: &TieringBootValidationPreparedManifestV5) -> bool {
        matches!(fs::symlink_metadata(&m.payload.swapfile.path), Err(error) if error.kind()==std::io::ErrorKind::NotFound)
    }
    fn finalize_runtime_cleanup(
        &mut self,
        m: &TieringBootValidationPreparedManifestV5,
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
        let bin = m.payload.transaction_root.join("bin");
        if bin.exists() {
            let metadata = fs::symlink_metadata(&bin).map_err(|e| e.to_string())?;
            if !metadata.file_type().is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.gid() != 0
                || metadata.mode() & 0o7777 != 0o700
                || fs::read_dir(&bin)
                    .map_err(|e| e.to_string())?
                    .next()
                    .is_some()
            {
                return Err("staged-helper directory is not exact-owned and empty".into());
            }
            fs::remove_dir(&bin).map_err(|e| e.to_string())?;
            sync_parent(&bin).map_err(|e| e.to_string())?;
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
    fn current_boot_is_experimental(&self, m: &TieringBootValidationPreparedManifestV5) -> bool {
        read_trimmed(Path::new("/proc/cmdline"))
            .is_ok_and(|v| v.contains(&m.payload.validation_marker))
    }
    fn collect_zram_baseline(
        &mut self,
        m: &TieringBootValidationPreparedManifestV5,
    ) -> std::result::Result<BaselineMeasurementObservationV5, String> {
        let worker = run_bounded_workload_scope(m).map_err(|e| e.to_string())?;
        let swaps = collect_swaps().map_err(|e| e.to_string())?;
        Ok(BaselineMeasurementObservationV5 {
            schema: ZRAM_BASELINE_EVIDENCE_V5.into(),
            validation_id: m.payload.validation_id.clone(),
            boot_id: read_trimmed(Path::new("/proc/sys/kernel/random/boot_id"))
                .map_err(|e| e.to_string())?,
            zram: collect_zram(&swaps).map_err(|e| e.to_string())?,
            zswap: collect_zswap().map_err(|e| e.to_string())?,
            swaps,
            workload_protocol: WORKLOAD_PROTOCOL_V5.into(),
            workload_sha256: canonical_json_sha256_v5(&m.payload.workload),
            bytes_touched: worker.bytes_touched,
            latency_ns: Some(worker.service_latency_ns),
            cgroup_oom_delta: counter_delta_named(
                &worker.memory_events_before,
                &worker.memory_events_after,
                "oom",
            ),
            cgroup_oom_kill_delta: counter_delta_named(
                &worker.memory_events_before,
                &worker.memory_events_after,
                "oom_kill",
            ),
            content_verified: worker.content_verified,
            cleanup_passed: true,
            scope_absent: true,
            production_activation: false,
        })
    }
    fn collect_post_boot(
        &mut self,
        m: &TieringBootValidationPreparedManifestV5,
    ) -> std::result::Result<ActualPostBootObservationV5, String> {
        collect_post_boot(m).map_err(|e| e.to_string())
    }
    fn collect_baseline(
        &self,
        m: &TieringBootValidationPreparedManifestV5,
    ) -> std::result::Result<BaselineRestoreObservationV5, String> {
        collect_baseline(m).map_err(|e| e.to_string())
    }
    fn seal_archive(&mut self, tx: &DurableTransactionV5) -> std::result::Result<(), String> {
        let root = &self.manifest.payload.transaction_root;
        if !matches!(
            tx.payload.stage,
            TransactionStageV5::Restored | TransactionStageV5::Recovered
        ) {
            return Err("archive may be sealed only for an immutable terminal class".into());
        }
        let status = root.join("STATUS");
        let status_bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema":"tiering-boot-validation-status-v5",
            "validation_id":tx.payload.validation_id,
            "stage":tx.payload.stage,
            "production_activation":false,
            "complete":true,
            "terminal_class":if tx.payload.stage==TransactionStageV5::Restored {
                "baseline-restored"
            } else {
                "recovered-before-reboot"
            },
            "primary_error":tx.payload.original_primary_error.as_ref().or(tx.payload.primary_error.as_ref()),
            "secondary_errors":tx.payload.secondary_errors,
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
        let mut required = std::collections::BTreeSet::from([
            "prepared-manifest-v5.json".to_owned(),
            "transaction-v5.json".to_owned(),
            "root-preflight-v5.json".to_owned(),
            "STATUS".to_owned(),
        ]);
        required.extend(tx.payload.evidence_hashes.keys().cloned());
        if tx.payload.stage == TransactionStageV5::Restored {
            required.extend([
                "one-shot-evidence-v5.json".to_owned(),
                "post-boot-evidence-v5.json".to_owned(),
                "baseline-restore-evidence-v5.json".to_owned(),
            ]);
        } else {
            required.insert("recovery-evidence-v5.json".to_owned());
        }
        let mut files = Vec::new();
        for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let metadata = entry.file_type().map_err(|e| e.to_string())?;
            if metadata.is_symlink() {
                return Err("ledger member symlink rejected".into());
            }
            if metadata.is_file() && entry.file_name() != "SHA256SUMS" {
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| "non-UTF8 ledger path")?;
                if !required.contains(&name) {
                    return Err(format!("unexpected ledger member: {name}"));
                }
                let full = root.join(&name);
                let stat = fs::symlink_metadata(&full).map_err(|e| e.to_string())?;
                if stat.uid() != 0
                    || stat.gid() != 0
                    || stat.mode() & 0o7777 != 0o600
                    || stat.nlink() != 1
                {
                    return Err(format!("unsafe ledger metadata: {name}"));
                }
                files.push(name);
            }
        }
        files.sort();
        let found: std::collections::BTreeSet<_> = files.iter().cloned().collect();
        if found != required {
            return Err(format!(
                "incomplete ledger membership: required={required:?} found={found:?}"
            ));
        }
        let mut sums = String::new();
        for name in files {
            let path = root.join(&name);
            let hash = sha256_file(&path).map_err(|e| e.to_string())?;
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
    let mut seen = std::collections::BTreeSet::new();
    for line in text.lines() {
        let (hash, name) = line.split_once("  ").context("malformed SHA256SUMS")?;
        if hash.len() != 64
            || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            || name.is_empty()
            || name.contains('/')
            || name.contains("..")
            || !seen.insert(name)
        {
            bail!("SHA256SUMS grammar or duplicate path failed")
        }
        let path = root.join(name);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || sha256_file(&path)? != hash
        {
            bail!("SHA256SUMS verification failed")
        }
    }
    if seen.is_empty() {
        bail!("empty SHA256SUMS")
    }
    Ok(())
}

fn with_transaction<F>(a: &TransactionArgs, f: F) -> Result<()>
where
    F: FnOnce(
        &TieringBootValidationPreparedManifestV5,
        &DurableTransactionV5,
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
        &TieringBootValidationPreparedManifestV5,
        &mut DurableTransactionV5,
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
    TieringBootValidationPreparedManifestV5,
    DurableTransactionV5,
)> {
    require_validation_id(id)?;
    let root = Path::new(TRANSACTION_ROOT_V5).join(id);
    let m: TieringBootValidationPreparedManifestV5 =
        read_json(&root.join("prepared-manifest-v5.json"))?;
    let transaction_path = root.join("transaction-v5.json");
    reconcile_transaction_new(&transaction_path)?;
    let t: DurableTransactionV5 = read_json(&transaction_path)?;
    m.validate()?;
    t.validate()?;
    if m.payload.validation_id != id
        || t.payload.validation_id != id
        || t.payload.manifest_sha256 != canonical_json_sha256_v5(&m)
    {
        bail!("transaction identity mismatch")
    };
    Ok((m, t))
}

fn reconcile_transaction_new(path: &Path) -> Result<()> {
    let candidate_path = path.with_extension("new");
    if !candidate_path.exists() {
        return Ok(());
    }
    let candidate: DurableTransactionV5 = read_json(&candidate_path)?;
    candidate.validate()?;
    if !path.exists() {
        let manifest_path = path
            .parent()
            .context("transaction parent")?
            .join("prepared-manifest-v5.json");
        let manifest: TieringBootValidationPreparedManifestV5 = read_json(&manifest_path)?;
        manifest.validate()?;
        if candidate.payload.validation_id != manifest.payload.validation_id
            || candidate.payload.manifest_sha256 != canonical_json_sha256_v5(&manifest)
            || candidate.payload.stage != TransactionStageV5::Prepared
            || !candidate.payload.mutation_records.is_empty()
        {
            bail!("orphan transaction .new is not the initial exact candidate")
        }
        fs::rename(&candidate_path, path)?;
        return sync_parent(path);
    }
    let old: DurableTransactionV5 = read_json(path)?;
    old.validate()?;
    let identity_matches = old.payload.validation_id == candidate.payload.validation_id
        && old.payload.manifest_sha256 == candidate.payload.manifest_sha256
        && old.payload.baseline_boot_id == candidate.payload.baseline_boot_id;
    let records_extend = candidate
        .payload
        .mutation_records
        .starts_with(&old.payload.mutation_records);
    let monotonic = candidate.payload.stage == old.payload.stage
        || legal_transition_v5(old.payload.stage, candidate.payload.stage);
    if !identity_matches || !records_extend || !monotonic {
        bail!("stale transaction .new is not a valid monotonic successor")
    }
    fs::rename(&candidate_path, path)?;
    sync_parent(path)
}
fn require_stage(t: &DurableTransactionV5, s: TransactionStageV5) -> Result<()> {
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
    require_stage(&t, TransactionStageV5::OneShotSelected)?;
    let mut backend = LinuxLifecycleBackend::new(&m)?;
    let boot_id = read_trimmed(Path::new("/proc/sys/kernel/random/boot_id"))?;
    if boot_id == t.payload.baseline_boot_id {
        bail!("experimental activation requires a new boot id")
    }
    let cmd = read_trimmed(Path::new("/proc/cmdline"))?;
    if !cmd
        .split_whitespace()
        .any(|v| v == m.payload.validation_marker)
    {
        bail!("validation marker absent")
    };
    // Freeze and re-read the protected fallback immediately before the first
    // zswap write.  A valid entry alone is not sufficient authority.
    let current_swaps = collect_swaps()?;
    let current_zram = collect_zram(&current_swaps)?;
    if current_zram != m.payload.protected_zram
        || !current_zram.active
        || current_zram.priority <= 0
        || m.payload.baseline_swaps.is_empty()
        || current_swaps.iter().any(|swap| {
            m.payload
                .baseline_swaps
                .iter()
                .find(|baseline| baseline.path == swap.path)
                .is_some_and(|baseline| baseline != swap)
                && swap.path != m.payload.swapfile.path
        })
    {
        bail!("protected zram or baseline swap precondition changed")
    }
    let status = command_output("/usr/bin/bootctl", &["status"])?;
    let booted_entry = parse_field(&status, "Current Boot Loader Entry:")
        .or_else(|| parse_field(&status, "Current Entry:"))
        .context("booted entry")?;
    if booted_entry != m.payload.experimental_entry.id
        || !backend.staged_helper_matches(&m.payload.staged_helper)
        || std::env::current_exe()?.canonicalize()? != m.payload.staged_helper.destination
        || backend.permanent_default().map_err(anyhow::Error::msg)?
            != m.payload.boot.default_entry.id
        || backend.boot_order().map_err(anyhow::Error::msg)? != m.payload.boot.boot_order
        || !read_trimmed(Path::new("/proc/self/cgroup"))?
            .contains(&format!("nemor-phase6-{}.service", m.payload.validation_id))
    {
        bail!("experimental boot/helper/unit identity mismatch")
    }
    let applied = t
        .payload
        .applied_swap_identity
        .as_ref()
        .context("applied swap identity")?
        .clone();
    if applied.uuid.is_none()
        || command_output(
            "/usr/bin/blkid",
            &[
                "-s",
                "UUID",
                "-o",
                "value",
                m.payload.swapfile.path.to_str().context("swap path")?,
            ],
        )? != applied.uuid.clone().unwrap_or_default()
        || collect_swaps()?
            .iter()
            .any(|swap| swap.path == m.payload.swapfile.path && swap.active)
    {
        bail!("validation swap identity or inactive baseline mismatch")
    }
    t.payload.current_boot_id = boot_id;
    t.transition(TransactionStageV5::ExperimentalBootDetected)?;
    backend
        .persist_transaction(&t)
        .map_err(anyhow::Error::msg)?;
    t.transition(TransactionStageV5::ActivationPreparing)?;
    backend
        .persist_transaction(&t)
        .map_err(anyhow::Error::msg)?;
    let enabled_path = Path::new("/sys/module/zswap/parameters/enabled");
    t.transition(TransactionStageV5::ZswapDisabling)?;
    t.record_intent("disable_zswap", enabled_path.to_path_buf());
    backend
        .persist_transaction(&t)
        .map_err(anyhow::Error::msg)?;
    if let Err(primary) = fs::write(enabled_path, "N") {
        return activation_failure(&m, &mut t, &mut backend, primary.to_string());
    }
    t.complete_last(sha256(read_trimmed(enabled_path)?.as_bytes()))?;
    backend
        .persist_transaction(&t)
        .map_err(anyhow::Error::msg)?;
    t.transition(TransactionStageV5::ZswapParametersApplying)?;
    backend
        .persist_transaction(&t)
        .map_err(anyhow::Error::msg)?;
    for (name, value) in &m.payload.experimental_zswap {
        if name == "enabled" {
            continue;
        }
        let path = Path::new("/sys/module/zswap/parameters").join(name);
        t.record_intent("write_zswap_parameter", path.clone());
        backend
            .persist_transaction(&t)
            .map_err(anyhow::Error::msg)?;
        if let Err(primary) = fs::write(&path, value) {
            return activation_failure(&m, &mut t, &mut backend, primary.to_string());
        }
        let readback = read_zswap_parameter(name)?;
        if readback != *value {
            return activation_failure(
                &m,
                &mut t,
                &mut backend,
                format!("zswap readback mismatch for {name}"),
            );
        }
        t.complete_last(sha256(readback.as_bytes()))?;
        t.payload.activation_parameter_index += 1;
        backend
            .persist_transaction(&t)
            .map_err(anyhow::Error::msg)?;
    }
    t.transition(TransactionStageV5::ZswapEnabling)?;
    t.record_intent("enable_zswap", enabled_path.to_path_buf());
    backend
        .persist_transaction(&t)
        .map_err(anyhow::Error::msg)?;
    if let Err(primary) = fs::write(enabled_path, "Y") {
        return activation_failure(&m, &mut t, &mut backend, primary.to_string());
    }
    if read_trimmed(enabled_path)? != "Y" {
        return activation_failure(
            &m,
            &mut t,
            &mut backend,
            "zswap enable readback mismatch".into(),
        );
    }
    t.complete_last(sha256(b"Y"))?;
    backend
        .persist_transaction(&t)
        .map_err(anyhow::Error::msg)?;
    t.transition(TransactionStageV5::SwapActivating)?;
    t.record_intent("activate_validation_swap", m.payload.swapfile.path.clone());
    backend
        .persist_transaction(&t)
        .map_err(anyhow::Error::msg)?;
    if let Err(primary) = run_exact(
        "/usr/bin/swapon",
        &[
            "--priority",
            &m.payload.swapfile.priority.to_string(),
            m.payload.swapfile.path.to_str().context("swap path")?,
        ],
    ) {
        return activation_failure(&m, &mut t, &mut backend, primary);
    }
    let swaps = collect_swaps()?;
    if !swaps
        .iter()
        .any(|s| s.path == m.payload.swapfile.path && s.priority == m.payload.swapfile.priority)
    {
        return activation_failure(
            &m,
            &mut t,
            &mut backend,
            "validation swap readback mismatch".into(),
        );
    };
    t.complete_last(canonical_json_sha256_v5(&applied))?;
    let activation_evidence = serde_json::to_vec_pretty(&serde_json::json!({
        "schema":ACTIVATION_EVIDENCE_SCHEMA_V5,
        "validation_id":m.payload.validation_id,
        "boot_id":t.payload.current_boot_id,
        "entry":m.payload.experimental_entry.id,
        "marker":m.payload.validation_marker,
        "staged_helper_sha256":m.payload.staged_helper.source.sha256,
        "swap_uuid":applied.uuid,
        "swap_priority":applied.priority,
        "zswap":collect_zswap()?,
        "mutation_records":t.payload.mutation_records,
        "default_entry":backend.permanent_default().map_err(anyhow::Error::msg)?,
        "boot_order":backend.boot_order().map_err(anyhow::Error::msg)?,
        "production_activation":false
    }))?;
    backend
        .persist_evidence("activation-evidence-v5.json", &activation_evidence)
        .map_err(anyhow::Error::msg)?;
    t.payload.evidence_hashes.insert(
        "activation-evidence-v5.json".into(),
        sha256(&activation_evidence),
    );
    t.payload_sha256 = canonical_json_sha256_v5(&t.payload);
    t.transition(TransactionStageV5::ActivationVerified)?;
    backend.persist_transaction(&t).map_err(anyhow::Error::msg)
}

fn activation_failure(
    m: &TieringBootValidationPreparedManifestV5,
    tx: &mut DurableTransactionV5,
    backend: &mut LinuxLifecycleBackend,
    primary: String,
) -> Result<()> {
    if tx.payload.original_primary_error.is_none() {
        tx.payload.original_primary_error = Some(primary.clone());
    }
    tx.payload.primary_error = Some(primary.clone());
    let mut secondary = Vec::new();
    if collect_swaps().is_ok_and(|swaps| {
        swaps
            .iter()
            .any(|swap| swap.path == m.payload.swapfile.path && swap.active)
    }) {
        tx.record_intent("rollback_swapoff", m.payload.swapfile.path.clone());
        backend
            .persist_transaction(tx)
            .map_err(anyhow::Error::msg)?;
        if let Err(error) = run_exact(
            "/usr/bin/swapoff",
            &[m.payload.swapfile.path.to_str().unwrap_or_default()],
        ) {
            secondary.push(error);
        } else {
            tx.complete_last(sha256(b"inactive"))?;
            backend
                .persist_transaction(tx)
                .map_err(anyhow::Error::msg)?;
        }
    }
    let enabled = Path::new("/sys/module/zswap/parameters/enabled");
    tx.record_intent("rollback_zswap_disable", enabled.to_path_buf());
    backend
        .persist_transaction(tx)
        .map_err(anyhow::Error::msg)?;
    if let Err(error) = fs::write(enabled, "N") {
        secondary.push(error.to_string());
    } else {
        tx.complete_last(sha256(b"N"))?;
        backend
            .persist_transaction(tx)
            .map_err(anyhow::Error::msg)?;
        for (name, value) in &m.payload.baseline_zswap.parameters {
            if name == "enabled" {
                continue;
            }
            let path = Path::new("/sys/module/zswap/parameters").join(name);
            tx.record_intent("rollback_zswap_parameter", path.clone());
            backend
                .persist_transaction(tx)
                .map_err(anyhow::Error::msg)?;
            if let Err(error) = fs::write(&path, value) {
                secondary.push(error.to_string());
            } else if read_zswap_parameter(name).ok().as_deref() == Some(value) {
                tx.complete_last(sha256(value.as_bytes()))?;
                backend
                    .persist_transaction(tx)
                    .map_err(anyhow::Error::msg)?;
            } else {
                secondary.push(format!("baseline zswap readback mismatch: {name}"));
            }
        }
        let baseline_enabled = m
            .payload
            .baseline_zswap
            .parameters
            .get("enabled")
            .cloned()
            .unwrap_or_else(|| "N".into());
        tx.record_intent("rollback_zswap_enabled", enabled.to_path_buf());
        backend
            .persist_transaction(tx)
            .map_err(anyhow::Error::msg)?;
        if let Err(error) = fs::write(enabled, &baseline_enabled) {
            secondary.push(error.to_string());
        } else {
            tx.complete_last(sha256(baseline_enabled.as_bytes()))?;
            backend
                .persist_transaction(tx)
                .map_err(anyhow::Error::msg)?;
        }
    }
    tx.record_intent(
        "select_baseline_after_activation_failure",
        m.payload.boot.current_entry.path.clone(),
    );
    backend
        .persist_transaction(tx)
        .map_err(anyhow::Error::msg)?;
    if let Err(error) = backend.set_one_shot(&m.payload.recovery_entry) {
        secondary.push(error);
    } else if backend.read_one_shot().ok().flatten().as_deref() == Some(&m.payload.recovery_entry) {
        tx.complete_last(canonical_json_sha256_v5(&m.payload.recovery_entry))?;
    } else {
        secondary.push("baseline one-shot readback mismatch".into());
    }
    tx.payload.secondary_errors.extend(secondary);
    tx.transition(TransactionStageV5::ActivationFailed)?;
    backend
        .persist_transaction(tx)
        .map_err(anyhow::Error::msg)?;
    bail!("activation failed and bounded rollback was attempted: {primary}")
}

fn collect_post_boot(
    m: &TieringBootValidationPreparedManifestV5,
) -> Result<ActualPostBootObservationV5> {
    let boot_id = read_trimmed(Path::new("/proc/sys/kernel/random/boot_id"))?;
    let status = command_output("/usr/bin/bootctl", &["status"])?;
    let booted_entry = parse_field(&status, "Current Boot Loader Entry:")
        .or_else(|| parse_field(&status, "Current Entry:"))
        .context("booted entry")?;
    let before = block_written_bytes(&m.payload.topology.physical.path);
    let oom_before = vmstat_value("oom_kill");
    let counters_before = collect_zswap_counters();
    let start = Instant::now();
    let worker = run_bounded_workload_scope(m)?;
    let elapsed = start.elapsed();
    if elapsed.as_secs() > m.payload.workload.timeout_seconds {
        bail!("workload timeout")
    };
    let after = block_written_bytes(&m.payload.topology.physical.path);
    let writes = before.zip(after).and_then(|(a, b)| b.checked_sub(a));
    let counters = collect_zswap_counters();
    let counter_deltas = counter_deltas(&counters_before, &counters);
    let stored = counter_deltas.get("stored_pages").copied().flatten();
    let pool = counter_deltas.get("pool_total_size").copied().flatten();
    let (daemon_observe_only, production_activation) = production_state(&m.payload.config_path)?;
    let cgroup_write_delta = worker
        .cgroup_io_write_bytes_after
        .zip(worker.cgroup_io_write_bytes_before)
        .and_then(|(after, before)| after.checked_sub(before));
    let block_write_attribution = if writes.is_some()
        && writes == cgroup_write_delta
        && writes.is_some_and(|bytes| bytes > 0)
    {
        "bounded-physical-device-attributed"
    } else {
        "physical-device-host-wide-noisy"
    };
    Ok(ActualPostBootObservationV5 {
        schema: POST_BOOT_EVIDENCE_SCHEMA_V5.into(),
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
        zswap_counters_before: counters_before,
        zswap_counter_deltas: counter_deltas,
        cgroup_path: worker.cgroup_path.clone(),
        workload_pid: worker.pid,
        workload_start_ticks: worker.start_ticks,
        workload_ready: worker.ready,
        workload_started: worker.started,
        workload_stopped: worker.stopped,
        progress_steps: worker.progress_steps,
        cgroup_oom_delta: counter_delta_named(
            &worker.memory_events_before,
            &worker.memory_events_after,
            "oom",
        ),
        cgroup_oom_kill_delta: counter_delta_named(
            &worker.memory_events_before,
            &worker.memory_events_after,
            "oom_kill",
        ),
        host_oom_kill_delta: oom_before
            .zip(vmstat_value("oom_kill"))
            .and_then(|(before, after)| after.checked_sub(before)),
        memory_current_bytes: worker.memory_current,
        memory_peak_bytes: worker.memory_peak,
        swap_current_bytes: worker.swap_current,
        scoped_psi_some_micros: worker.psi_some_micros,
        block_write_bytes: writes,
        block_write_attribution: block_write_attribution.into(),
        latency_ns: Some(worker.service_latency_ns),
        bytes_touched: worker.bytes_touched,
        throughput_bytes_per_second: Some(
            worker.bytes_touched.saturating_mul(1_000_000_000) / worker.service_latency_ns.max(1),
        ),
        compression_ratio_milli: stored.zip(pool).map(|(pages, bytes)| {
            pages
                .saturating_mul(4096)
                .saturating_mul(1000)
                .checked_div(bytes)
                .unwrap_or(0)
        }),
        refault_observed: worker.swap_current.is_some_and(|bytes| bytes > 0)
            && worker.refault_content_verified,
        refault_content_verified: worker.refault_content_verified,
        oom: counter_delta_named(
            &worker.memory_events_before,
            &worker.memory_events_after,
            "oom",
        )
        .is_some_and(|delta| delta > 0),
        oom_kill: counter_delta_named(
            &worker.memory_events_before,
            &worker.memory_events_after,
            "oom_kill",
        )
        .is_some_and(|delta| delta > 0),
        workload_completed: true,
        workload_timeout: false,
        runtime_observation: collect_runtime_observe_only(m)?,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerReportV1 {
    protocol: String,
    validation_id: String,
    pid: u32,
    start_ticks: u64,
    cgroup_path: String,
    ready: bool,
    started: bool,
    stopped: bool,
    progress_steps: u64,
    bytes_touched: u64,
    service_latency_ns: u64,
    content_verified: bool,
    refault_content_verified: bool,
    memory_events_before: BTreeMap<String, Option<u64>>,
    memory_events_after: BTreeMap<String, Option<u64>>,
    memory_current: Option<u64>,
    memory_peak: Option<u64>,
    swap_current: Option<u64>,
    psi_some_micros: Option<u64>,
    cgroup_io_write_bytes_before: Option<u64>,
    cgroup_io_write_bytes_after: Option<u64>,
}

fn run_bounded_workload_scope(
    m: &TieringBootValidationPreparedManifestV5,
) -> Result<WorkerReportV1> {
    let binary = &m.payload.staged_helper.destination;
    let unit = format!("nemor-phase6-workload-{}.scope", m.payload.validation_id);
    let memory_max = m.payload.workload.bytes.saturating_mul(2).to_string();
    let swap_max = m.payload.workload.bytes.saturating_mul(3).to_string();
    let mut child = Command::new("/usr/bin/systemd-run")
        .args([
            "--scope",
            "--pipe",
            "--wait",
            "--collect",
            "--quiet",
            "--unit",
            &unit,
            "--property",
            &format!("MemoryMax={memory_max}"),
            "--property",
            &format!("MemorySwapMax={swap_max}"),
            binary.to_str().context("validator path")?,
            "bounded-workload",
            "--validation-id",
            &m.payload.validation_id,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout_pipe = child.stdout.take().context("worker stdout")?;
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut stdout = BufReader::new(stdout_pipe);
        let mut ready = String::new();
        let result = stdout.read_line(&mut ready).map(|_| (ready, stdout));
        let _ = ready_tx.send(result);
    });
    let ready_timeout = std::time::Duration::from_secs(5);
    let (ready, mut stdout) = ready_rx
        .recv_timeout(ready_timeout)
        .map_err(|_| anyhow::anyhow!("bounded worker readiness timeout"))??;
    let ready_json: serde_json::Value = serde_json::from_str(ready.trim())?;
    if ready_json.get("event").and_then(|value| value.as_str()) != Some("ready")
        || ready_json
            .get("validation_id")
            .and_then(|value| value.as_str())
            != Some(&m.payload.validation_id)
    {
        let _ = child.kill();
        bail!("bounded worker ready handshake mismatch")
    }
    writeln!(
        child.stdin.as_mut().context("worker stdin")?,
        "START {}",
        m.payload.validation_id
    )?;
    child.stdin.as_mut().context("worker stdin")?.flush()?;
    let deadline =
        Instant::now() + std::time::Duration::from_secs(m.payload.workload.timeout_seconds);
    loop {
        match child.try_wait()? {
            Some(status) if status.success() => {
                let mut report = String::new();
                stdout.read_line(&mut report)?;
                let report: WorkerReportV1 = serde_json::from_str(report.trim())?;
                if report.protocol != WORKLOAD_PROTOCOL_V5
                    || report.validation_id != m.payload.validation_id
                    || !report.ready
                    || !report.started
                    || !report.stopped
                {
                    bail!("bounded worker terminal handshake mismatch")
                }
                return Ok(report);
            }
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
    if current_uid()? != 0
        || !matches!(
            t.payload.stage,
            TransactionStageV5::BaselineMeasuring | TransactionStageV5::PostBootMeasuring
        )
    {
        bail!("bounded workload is authorized only by the measuring transaction")
    }
    if std::env::current_exe()?.canonicalize()? != m.payload.staged_helper.destination
        || sha256_file(&m.payload.staged_helper.destination)?
            != m.payload.staged_helper.source.sha256
    {
        bail!("bounded worker is not the exact staged helper")
    }
    let command_line = read_trimmed(Path::new("/proc/cmdline"))?;
    if t.payload.stage == TransactionStageV5::PostBootMeasuring
        && !command_line
            .split_whitespace()
            .any(|item| item == m.payload.validation_marker)
    {
        bail!("validation marker absent")
    }
    let pid = std::process::id();
    let start_ticks = process_start_ticks(pid).context("worker start ticks")?;
    let cgroup_path = unified_cgroup_path()?;
    let cgroup_root = Path::new("/sys/fs/cgroup").join(cgroup_path.trim_start_matches('/'));
    let before = read_memory_events(&cgroup_root.join("memory.events"));
    let io_before = read_cgroup_io_write_bytes(
        &cgroup_root.join("io.stat"),
        m.payload.topology.physical.major,
        m.payload.topology.physical.minor,
    );
    println!(
        "{}",
        serde_json::json!({
            "event":"ready",
            "protocol":WORKLOAD_PROTOCOL_V5,
            "validation_id":m.payload.validation_id,
            "pid":pid,
            "start_ticks":start_ticks,
            "cgroup_path":cgroup_path
        })
    );
    std::io::stdout().flush()?;
    let mut start_command = String::new();
    std::io::stdin().lock().read_line(&mut start_command)?;
    if start_command.trim() != format!("START {}", m.payload.validation_id) {
        bail!("bounded worker start handshake mismatch")
    }
    let started = Instant::now();
    let primary_bytes = m.payload.workload.bytes;
    let primary_length: usize = primary_bytes.try_into().context("primary workload size")?;
    let pressure_bytes = primary_bytes.saturating_mul(2);
    let pressure_length: usize = pressure_bytes
        .try_into()
        .context("pressure workload size")?;
    let mut primary = vec![0_u8; primary_length];
    for (index, byte) in primary.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_add(m.payload.workload.seed as u8);
    }
    let expected = sha256(&primary);
    let mut pressure = vec![0_u8; pressure_length];
    let mut progress_steps = 0_u64;
    for iteration in 0..m.payload.workload.iterations {
        for (index, byte) in pressure.iter_mut().enumerate() {
            *byte = (index as u8)
                .wrapping_add(iteration as u8)
                .wrapping_add(m.payload.workload.seed as u8);
        }
        progress_steps += 1;
    }
    std::hint::black_box(&pressure);
    let content_verified = sha256(&primary) == expected;
    let refault_content_verified = primary
        .iter()
        .enumerate()
        .step_by(4096)
        .all(|(index, byte)| *byte == (index as u8).wrapping_add(m.payload.workload.seed as u8));
    std::hint::black_box(&primary);
    let after = read_memory_events(&cgroup_root.join("memory.events"));
    let report = WorkerReportV1 {
        protocol: WORKLOAD_PROTOCOL_V5.into(),
        validation_id: m.payload.validation_id,
        pid,
        start_ticks,
        cgroup_path,
        ready: true,
        started: true,
        stopped: true,
        progress_steps,
        bytes_touched: primary_bytes
            .saturating_add(pressure_bytes.saturating_mul(u64::from(m.payload.workload.iterations)))
            .saturating_add(primary_bytes)
            .saturating_add(primary_bytes),
        service_latency_ns: started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
        content_verified,
        refault_content_verified,
        memory_events_before: before,
        memory_events_after: after,
        memory_current: read_u64_optional(&cgroup_root.join("memory.current")),
        memory_peak: read_u64_optional(&cgroup_root.join("memory.peak")),
        swap_current: read_u64_optional(&cgroup_root.join("memory.swap.current")),
        psi_some_micros: read_psi_total(&cgroup_root.join("memory.pressure")),
        cgroup_io_write_bytes_before: io_before,
        cgroup_io_write_bytes_after: read_cgroup_io_write_bytes(
            &cgroup_root.join("io.stat"),
            m.payload.topology.physical.major,
            m.payload.topology.physical.minor,
        ),
    };
    println!("{}", serde_json::to_string(&report)?);
    std::io::stdout().flush()?;
    Ok(())
}

fn unified_cgroup_path() -> Result<String> {
    fs::read_to_string("/proc/self/cgroup")?
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
        .context("unified cgroup path")
}
fn read_memory_events(path: &Path) -> BTreeMap<String, Option<u64>> {
    let mut values = BTreeMap::new();
    for key in ["oom", "oom_kill"] {
        let value = fs::read_to_string(path).ok().and_then(|text| {
            text.lines().find_map(|line| {
                let (name, value) = line.split_once(' ')?;
                (name == key).then(|| value.parse().ok()).flatten()
            })
        });
        values.insert(key.to_owned(), value);
    }
    values
}
fn read_u64_optional(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}
fn read_psi_total(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.lines().find_map(|line| {
        let fields = line.strip_prefix("some ")?;
        fields
            .split_whitespace()
            .find_map(|field| field.strip_prefix("total=")?.parse().ok())
    })
}
fn read_cgroup_io_write_bytes(path: &Path, major: u32, minor: u32) -> Option<u64> {
    let device = format!("{major}:{minor}");
    fs::read_to_string(path).ok()?.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != device {
            return None;
        }
        fields.find_map(|field| field.strip_prefix("wbytes=")?.parse().ok())
    })
}

fn production_state(config_path: &Path) -> Result<(bool, bool)> {
    let config = Config::from_toml(&fs::read_to_string(config_path)?)?;
    let observe_only = config.tiering.dry_run
        && !config.tiering.allow_runtime_reconfigure
        && !config.tiering.allow_persistent_reconfigure
        && !config.tiering.allow_swapfile_create;
    Ok((observe_only, !observe_only))
}

fn counter_deltas(
    before: &BTreeMap<String, Option<u64>>,
    after: &BTreeMap<String, Option<u64>>,
) -> BTreeMap<String, Option<u64>> {
    before
        .iter()
        .map(|(name, before)| {
            let delta =
                before.and_then(|value| after.get(name).copied().flatten()?.checked_sub(value));
            (name.clone(), delta)
        })
        .collect()
}
fn counter_delta_named(
    before: &BTreeMap<String, Option<u64>>,
    after: &BTreeMap<String, Option<u64>>,
    name: &str,
) -> Option<u64> {
    after
        .get(name)
        .copied()
        .flatten()?
        .checked_sub(before.get(name).copied().flatten()?)
}

fn process_start_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    stat[close + 2..].split_whitespace().nth(19)?.parse().ok()
}

fn collect_runtime_observe_only(
    m: &TieringBootValidationPreparedManifestV5,
) -> Result<RuntimeObserveOnlyEvidenceV5> {
    let (configured_observe_only, production_activation) =
        production_state(&m.payload.config_path)?;
    let nemord_active = command_output("/usr/bin/systemctl", &["is-active", "nemord.service"])
        .is_ok_and(|state| state == "active");
    let nemord_binary = if nemord_active {
        let pid: u32 = command_output(
            "/usr/bin/systemctl",
            &["show", "nemord.service", "--property=MainPID", "--value"],
        )?
        .parse()?;
        let path = fs::read_link(format!("/proc/{pid}/exe"))?;
        Some(RuntimeBinaryIdentityV5 {
            sha256: sha256_file(&path)?,
            path,
            pid,
            start_ticks: process_start_ticks(pid).context("nemord start ticks")?,
        })
    } else {
        None
    };
    let effective_mode = if nemord_active {
        Some(command_output(
            "/usr/bin/systemctl",
            &["show", "nemord.service", "--property=ExecStart", "--value"],
        )?)
    } else {
        Some("absent".into())
    };
    let production_tiering_unit_absent = command_output(
        "/usr/bin/systemctl",
        &[
            "show",
            "nemor-tiering.service",
            "--property=LoadState",
            "--value",
        ],
    )
    .is_ok_and(|state| state == "not-found");
    let validation_unit = format!("nemor-phase6-{}.service", m.payload.validation_id);
    let unexpected_nemor_units = command_output(
        "/usr/bin/systemctl",
        &[
            "list-units",
            "--all",
            "--plain",
            "--no-legend",
            "--type=service",
        ],
    )
    .unwrap_or_default()
    .lines()
    .filter_map(|line| line.split_whitespace().next())
    .filter(|unit| unit.starts_with("nemor"))
    .filter(|unit| *unit != "nemord.service" && *unit != validation_unit)
    .map(str::to_owned)
    .collect();
    let unexpected_nemor_cgroups = fs::read_dir("/sys/fs/cgroup/system.slice")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.contains("nemor"))
        .filter(|name| name != "nemord.service" && name != &validation_unit)
        .collect();
    Ok(RuntimeObserveOnlyEvidenceV5 {
        config_sha256: sha256_file(&m.payload.config_path)?,
        configured_observe_only,
        nemord_active,
        nemord_binary,
        effective_mode,
        production_tiering_unit_absent,
        unexpected_nemor_units,
        unexpected_nemor_cgroups,
        production_activation,
    })
}

fn collect_baseline(
    m: &TieringBootValidationPreparedManifestV5,
) -> Result<BaselineRestoreObservationV5> {
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
    Ok(BaselineRestoreObservationV5 {
        schema: FINAL_RESTORE_SCHEMA_V5.into(),
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
    match recovery_action_v5(recovery_stage, experimental) {
        "no_op" => {
            if !idempotence {
                print_json(&t)
            } else {
                verify_sha256sums(&m.payload.transaction_root)?;
                print_json(&serde_json::json!({
                    "schema":"tiering-idempotence-verification-v5",
                    "validation_id":m.payload.validation_id,
                    "stage":t.payload.stage,
                    "mutation_count":0,
                    "already_clean":true
                }))
            }
        }
        "select_exact_baseline_oneshot_preserve_artifacts" => {
            select_baseline_rollback_v5(&m, &mut t, &mut b)?;
            print_json(&t)
        }
        "verify_baseline_preserve_artifacts" | "resume_exact_cleanup" => {
            verify_then_cleanup_v5(&m, &mut t, &mut b)?;
            print_json(&t)
        }
        "remove_exact_owned_before_reboot" | "clear_exact_owned_oneshot_then_remove" => {
            if idempotence {
                bail!("idempotence verification cannot mutate")
            };
            if recovery_action_v5(recovery_stage, experimental)
                == "clear_exact_owned_oneshot_then_remove"
            {
                if b.read_one_shot().map_err(anyhow::Error::msg)?.as_deref()
                    != Some(&m.payload.experimental_entry.id)
                {
                    bail!("one-shot state is not exact-owned; preserving all artifacts")
                }
                t.record_intent(
                    "recovery_clear_exact_oneshot",
                    m.payload.experimental_entry.path.clone(),
                );
                b.persist_transaction(&t).map_err(anyhow::Error::msg)?;
                run_exact("/usr/bin/bootctl", &["set-oneshot", ""]).map_err(anyhow::Error::msg)?;
                if b.read_one_shot().map_err(anyhow::Error::msg)?.is_some() {
                    bail!("owned one-shot state did not clear")
                }
                t.complete_last(sha256(b"cleared"))?;
                b.persist_transaction(&t).map_err(anyhow::Error::msg)?;
            }
            for art in m.payload.owned_artifacts.iter().rev() {
                if b.artifact_matches(art) {
                    t.record_intent("recovery_remove_exact_artifact", art.path.clone());
                    b.persist_transaction(&t).map_err(anyhow::Error::msg)?;
                    b.remove_artifact(art).map_err(anyhow::Error::msg)?;
                    t.complete_last(sha256(b"absent"))?;
                    b.persist_transaction(&t).map_err(anyhow::Error::msg)?;
                }
            }
            t.record_intent(
                "recovery_remove_exact_swapfile",
                m.payload.swapfile.path.clone(),
            );
            b.persist_transaction(&t).map_err(anyhow::Error::msg)?;
            b.remove_swapfile(&m).map_err(anyhow::Error::msg)?;
            t.complete_last(sha256(b"absent"))?;
            b.finalize_runtime_cleanup(&m).map_err(anyhow::Error::msg)?;
            t.transition(TransactionStageV5::Recovered)?;
            t.payload.recovery_state = "recovered_before_reboot".into();
            t.payload_sha256 = canonical_json_sha256_v5(&t.payload);
            b.persist_transaction(&t).map_err(anyhow::Error::msg)?;
            let recovery = serde_json::to_vec_pretty(&serde_json::json!({
                "schema": RECOVERY_EVIDENCE_SCHEMA_V5,
                "validation_id": t.payload.validation_id,
                "terminal_stage": t.payload.stage,
                "original_primary_error": t.payload.original_primary_error,
                "primary_error": t.payload.primary_error,
                "secondary_errors": t.payload.secondary_errors,
                "mutation_records": t.payload.mutation_records,
                "idempotent": true,
                "production_activation": false
            }))?;
            b.persist_evidence("recovery-evidence-v5.json", &recovery)
                .map_err(anyhow::Error::msg)?;
            t.payload
                .evidence_hashes
                .insert("recovery-evidence-v5.json".into(), sha256(&recovery));
            t.payload_sha256 = canonical_json_sha256_v5(&t.payload);
            b.persist_transaction(&t).map_err(anyhow::Error::msg)?;
            b.seal_archive(&t).map_err(anyhow::Error::msg)?;
            print_json(&t)
        }
        other => bail!("recovery requires diagnosis: {other}"),
    }
}

fn read_manifest(path: &Path) -> Result<TieringBootValidationPreparedManifestV5> {
    let m: TieringBootValidationPreparedManifestV5 = read_json(path)?;
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
fn exact_file_matches(a: &OwnedArtifactV5) -> bool {
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
fn transaction_hierarchy_safe(root: &Path) -> bool {
    if !root.starts_with(TRANSACTION_ROOT_V5) || root.exists() {
        return false;
    }
    let mut cursor = root.parent();
    let mut device = None;
    while let Some(path) = cursor {
        if path.exists() {
            let Ok(metadata) = fs::symlink_metadata(path) else {
                return false;
            };
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || (path.starts_with("/var/lib/nemor") && metadata.mode() & 0o7777 != 0o700)
                || device.is_some_and(|expected| expected != metadata.dev())
            {
                return false;
            }
            device.get_or_insert(metadata.dev());
        }
        if path == Path::new("/var/lib") {
            return true;
        }
        cursor = path.parent();
    }
    false
}
fn staged_source_matches(plan: &StagedBinaryPlanV5) -> bool {
    let Ok(metadata) = fs::symlink_metadata(&plan.source.path) else {
        return false;
    };
    metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == plan.source_uid
        && metadata.gid() == plan.source_gid
        && metadata.mode() & 0o7777 == plan.source_mode
        && metadata.nlink() == plan.source_link_count
        && metadata.dev() == plan.source_device
        && metadata.ino() == plan.source_inode
        && sha256_file(&plan.source.path).ok().as_deref() == Some(&plan.source.sha256)
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

    #[test]
    fn baseline_and_apply_are_separately_authorized_cli_stages() {
        let baseline = Cli::try_parse_from([
            "validator",
            "measure-baseline",
            "--manifest",
            "/tmp/prepared-manifest-v5.json",
        ])
        .unwrap();
        assert!(matches!(
            baseline.command,
            LifecycleCommand::MeasureBaseline(_)
        ));
        let apply = Cli::try_parse_from(["validator", "apply", "--validation-id", "phase6-test-1"])
            .unwrap();
        assert!(matches!(apply.command, LifecycleCommand::Apply(_)));
        assert!(Cli::try_parse_from([
            "validator",
            "apply",
            "--validation-id",
            "phase6-test-1",
            "--manifest",
            "/tmp/hand-authored.json",
        ])
        .is_err());
    }

    #[test]
    fn cgroup_oom_and_oom_kill_are_independent_deltas() {
        let before = BTreeMap::from([("oom".into(), Some(4)), ("oom_kill".into(), Some(1))]);
        let after = BTreeMap::from([("oom".into(), Some(6)), ("oom_kill".into(), Some(1))]);
        assert_eq!(counter_delta_named(&before, &after, "oom"), Some(2));
        assert_eq!(counter_delta_named(&before, &after, "oom_kill"), Some(0));
    }

    #[test]
    fn unavailable_counter_stays_unavailable() {
        let before = BTreeMap::from([("oom".into(), None)]);
        let after = BTreeMap::from([("oom".into(), Some(0))]);
        assert_eq!(counter_delta_named(&before, &after, "oom"), None);
    }

    #[test]
    fn zswap_counter_decrease_is_not_a_wrapped_delta() {
        let before = BTreeMap::from([("stored_pages".into(), Some(9))]);
        let after = BTreeMap::from([("stored_pages".into(), Some(3))]);
        assert_eq!(
            counter_deltas(&before, &after).get("stored_pages"),
            Some(&None)
        );
    }

    #[test]
    fn worker_report_freezes_attributable_protocol_fields() {
        let report = WorkerReportV1 {
            protocol: WORKLOAD_PROTOCOL_V5.into(),
            validation_id: "phase6-test-1".into(),
            pid: 42,
            start_ticks: 99,
            cgroup_path: "/system.slice/test.scope".into(),
            ready: true,
            started: true,
            stopped: true,
            progress_steps: 2,
            bytes_touched: 4096,
            service_latency_ns: 10,
            content_verified: true,
            refault_content_verified: true,
            memory_events_before: BTreeMap::new(),
            memory_events_after: BTreeMap::new(),
            memory_current: None,
            memory_peak: None,
            swap_current: None,
            psi_some_micros: None,
            cgroup_io_write_bytes_before: Some(1),
            cgroup_io_write_bytes_after: Some(2),
        };
        let round_trip: WorkerReportV1 =
            serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
        assert_eq!(round_trip.pid, 42);
        assert_eq!(round_trip.start_ticks, 99);
        assert_eq!(round_trip.bytes_touched, 4096);
        assert!(round_trip.refault_content_verified);
    }

    #[test]
    fn atomic_new_suffix_is_exact_and_not_caller_selected() {
        let path = Path::new("/var/lib/nemor/validation/phase6/id/transaction-v5.json");
        assert_eq!(
            path.with_extension("new"),
            PathBuf::from("/var/lib/nemor/validation/phase6/id/transaction-v5.new")
        );
    }
}
