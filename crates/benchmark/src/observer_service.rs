use crate::harness::{detect_clk_tck, process_cpu_ticks, read_start_ticks};
use crate::performance::{detect_nemord_processes, reject_foreign_nemord, write_inspection_config};
use crate::systemd::{require_successful_job, SystemdJobOutcome};
use crate::{BuildProvenance, EvidenceKind, StructuralSnapshot};
use anyhow::{bail, Context, Result};
use futures_lite::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, Type, Value};

const DESTINATION: &str = "org.freedesktop.systemd1";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
const OBSERVER_PREFIX: &str = "nemor-benchmark-observer-";
const RUNTIME_BASE: &str = "/run";
const PRODUCTION_DATABASE: &str = "/var/lib/nemor/nemor.db";
const SERVICE_RUNTIME_MAX_USEC: u64 = 20_000_000;
const SERVICE_TIMEOUT_USEC: u64 = 5_000_000;
const VALIDATION_WINDOW: Duration = Duration::from_secs(5);
const READY_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_PREPARED_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_PREPARED_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObserverReadbackProperty {
    pub interface: &'static str,
    pub property: &'static str,
    pub signature: &'static str,
}

pub const OBSERVER_READBACK_CONTRACT: [ObserverReadbackProperty; 31] = [
    ObserverReadbackProperty {
        interface: UNIT_INTERFACE,
        property: "Id",
        signature: "s",
    },
    ObserverReadbackProperty {
        interface: UNIT_INTERFACE,
        property: "LoadState",
        signature: "s",
    },
    ObserverReadbackProperty {
        interface: UNIT_INTERFACE,
        property: "ActiveState",
        signature: "s",
    },
    ObserverReadbackProperty {
        interface: UNIT_INTERFACE,
        property: "SubState",
        signature: "s",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "ControlGroup",
        signature: "s",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "MainPID",
        signature: "u",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "ExecMainPID",
        signature: "u",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "ExecMainStatus",
        signature: "i",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "Result",
        signature: "s",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "DynamicUser",
        signature: "b",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "UMask",
        signature: "u",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "RuntimeDirectory",
        signature: "as",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "RuntimeDirectoryMode",
        signature: "u",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "RuntimeDirectoryPreserve",
        signature: "s",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "NoNewPrivileges",
        signature: "b",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "CapabilityBoundingSet",
        signature: "t",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "AmbientCapabilities",
        signature: "t",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "ProtectSystem",
        signature: "s",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "ProtectHome",
        signature: "b",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "PrivateTmp",
        signature: "b",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "PrivateDevices",
        signature: "b",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "ProtectKernelTunables",
        signature: "b",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "ProtectControlGroups",
        signature: "b",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "ProtectKernelModules",
        signature: "b",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "MemoryDenyWriteExecute",
        signature: "b",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "LockPersonality",
        signature: "b",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "RestrictRealtime",
        signature: "b",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "RestrictSUIDSGID",
        signature: "b",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "RestrictAddressFamilies",
        signature: "(bas)",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "SystemCallArchitectures",
        signature: "as",
    },
    ObserverReadbackProperty {
        interface: SERVICE_INTERFACE,
        property: "IPAddressDeny",
        signature: "a(iayu)",
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverServicePlan {
    pub unit_name: String,
    pub description: String,
    pub binary: PathBuf,
    pub service_binary: PathBuf,
    pub config: PathBuf,
    pub service_config: PathBuf,
    pub runtime_directory: String,
    pub database: PathBuf,
    pub runtime_max_usec: u64,
    pub timeout_start_usec: u64,
    pub timeout_stop_usec: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverTransientPropertyAudit {
    pub property: String,
    pub signature: String,
    pub applicability: String,
    pub required: bool,
    pub request_value: String,
}

impl ObserverServicePlan {
    pub fn new(run_id: &str, binary: PathBuf, config: PathBuf) -> Result<Self> {
        let suffix: String = run_id
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(32)
            .collect();
        if suffix.is_empty() {
            bail!("run id cannot produce a safe observer unit name");
        }
        let runtime_directory = format!("{OBSERVER_PREFIX}{suffix}");
        let plan = Self {
            unit_name: format!("{runtime_directory}.service"),
            description: "Nemor benchmark-owned DynamicUser observer validation".into(),
            binary,
            service_binary: Path::new(RUNTIME_BASE)
                .join(&runtime_directory)
                .join("nemord"),
            config,
            service_config: Path::new(RUNTIME_BASE)
                .join(&runtime_directory)
                .join("observer.toml"),
            database: Path::new(RUNTIME_BASE)
                .join(&runtime_directory)
                .join("nemor-observer.sqlite"),
            runtime_directory,
            runtime_max_usec: SERVICE_RUNTIME_MAX_USEC,
            timeout_start_usec: SERVICE_TIMEOUT_USEC,
            timeout_stop_usec: SERVICE_TIMEOUT_USEC,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<()> {
        validate_observer_unit_name(&self.unit_name)?;
        if !self.binary.is_absolute()
            || !self.config.is_absolute()
            || !self.service_binary.is_absolute()
            || !self.service_config.is_absolute()
        {
            bail!("observer binary and config paths must be absolute");
        }
        if self.binary.file_name().and_then(|value| value.to_str()) != Some("nemord") {
            bail!("observer executable must be the exact nemord binary");
        }
        if self.database == Path::new(PRODUCTION_DATABASE)
            || !self
                .database
                .starts_with(Path::new(RUNTIME_BASE).join(&self.runtime_directory))
            || !self
                .service_config
                .starts_with(Path::new(RUNTIME_BASE).join(&self.runtime_directory))
            || !self
                .service_binary
                .starts_with(Path::new(RUNTIME_BASE).join(&self.runtime_directory))
        {
            bail!("observer database is not transaction-isolated");
        }
        if self.runtime_directory.contains('/') || self.runtime_directory.contains("..") {
            bail!("invalid observer RuntimeDirectory basename");
        }
        if self.runtime_max_usec > SERVICE_RUNTIME_MAX_USEC
            || self.timeout_start_usec > SERVICE_TIMEOUT_USEC
            || self.timeout_stop_usec > SERVICE_TIMEOUT_USEC
        {
            bail!("observer lifecycle bounds exceed Checkpoint 3A-P limits");
        }
        Ok(())
    }

    pub fn encoded_property_signatures(&self) -> Result<Vec<(String, String)>> {
        Ok(self
            .encoded_properties()?
            .iter()
            .map(|(name, value)| ((*name).into(), value.value_signature().to_string()))
            .collect())
    }

    pub fn property_audit(&self) -> Result<Vec<ObserverTransientPropertyAudit>> {
        self.encoded_property_signatures()?
            .into_iter()
            .map(|(property, signature)| {
                Ok(ObserverTransientPropertyAudit {
                    applicability: match property.as_str() {
                        "Description" | "CollectMode" => "Unit",
                        _ => "Service",
                    }
                    .into(),
                    required: true,
                    request_value: self.property_value_description(&property)?,
                    property,
                    signature,
                })
            })
            .collect()
    }

    fn property_value_description(&self, property: &str) -> Result<String> {
        Ok(match property {
            "Description" => self.description.clone(),
            "Type" => "simple".into(),
            "ExecStart" => format!(
                "{} --config {}",
                self.service_binary.display(),
                self.service_config.display()
            ),
            "DynamicUser" => "true".into(),
            "UMask" => "0077".into(),
            "CollectMode" => "inactive-or-failed".into(),
            "TimeoutStartUSec" => self.timeout_start_usec.to_string(),
            "TimeoutStopUSec" => self.timeout_stop_usec.to_string(),
            "RuntimeMaxUSec" => self.runtime_max_usec.to_string(),
            "RuntimeDirectory" => self.runtime_directory.clone(),
            "RuntimeDirectoryMode" => "0700".into(),
            "RuntimeDirectoryPreserve" => "no".into(),
            "BindReadOnlyPaths" => format!(
                "{}:{};{}:{}",
                self.binary.display(),
                self.service_binary.display(),
                self.config.display(),
                self.service_config.display()
            ),
            "WorkingDirectory" => Path::new(RUNTIME_BASE)
                .join(&self.runtime_directory)
                .display()
                .to_string(),
            "CapabilityBoundingSet" | "AmbientCapabilities" => "empty".into(),
            "ProtectSystem" => "strict".into(),
            "RestrictAddressFamilies" => "allow AF_UNIX only".into(),
            "IPAddressDeny" => "IPv4+IPv6 any".into(),
            "SystemCallArchitectures" => "native".into(),
            "NoNewPrivileges"
            | "ProtectHome"
            | "PrivateTmp"
            | "PrivateDevices"
            | "ProtectKernelModules"
            | "ProtectKernelTunables"
            | "ProtectControlGroups"
            | "MemoryDenyWriteExecute"
            | "LockPersonality"
            | "RestrictRealtime"
            | "RestrictSUIDSGID" => "true".into(),
            _ => bail!("observer transient property lacks an audit value"),
        })
    }

    fn encoded_properties(&self) -> Result<Vec<(&'static str, Value<'_>)>> {
        self.validate()?;
        let argv = vec![
            self.service_binary.to_string_lossy().into_owned(),
            "--config".into(),
            self.service_config.to_string_lossy().into_owned(),
        ];
        let exec_start = vec![(argv[0].clone(), argv, false)];
        let properties = vec![
            ("Description", Value::from(self.description.as_str())),
            ("Type", Value::from("simple")),
            ("ExecStart", Value::from(exec_start)),
            ("DynamicUser", Value::from(true)),
            ("UMask", Value::from(0o077_u32)),
            ("CollectMode", Value::from("inactive-or-failed")),
            ("TimeoutStartUSec", Value::from(self.timeout_start_usec)),
            ("TimeoutStopUSec", Value::from(self.timeout_stop_usec)),
            ("RuntimeMaxUSec", Value::from(self.runtime_max_usec)),
            (
                "RuntimeDirectory",
                Value::from(vec![self.runtime_directory.as_str()]),
            ),
            ("RuntimeDirectoryMode", Value::from(0o700_u32)),
            ("RuntimeDirectoryPreserve", Value::from("no")),
            (
                "BindReadOnlyPaths",
                Value::from(vec![
                    (
                        self.binary.to_string_lossy().into_owned(),
                        self.service_binary.to_string_lossy().into_owned(),
                        false,
                        0_u64,
                    ),
                    (
                        self.config.to_string_lossy().into_owned(),
                        self.service_config.to_string_lossy().into_owned(),
                        false,
                        0_u64,
                    ),
                ]),
            ),
            (
                "WorkingDirectory",
                Value::from(
                    Path::new(RUNTIME_BASE)
                        .join(&self.runtime_directory)
                        .to_string_lossy()
                        .into_owned(),
                ),
            ),
            ("NoNewPrivileges", Value::from(true)),
            ("CapabilityBoundingSet", Value::from(0_u64)),
            ("AmbientCapabilities", Value::from(0_u64)),
            ("ProtectSystem", Value::from("strict")),
            ("ProtectHome", Value::from(true)),
            ("PrivateTmp", Value::from(true)),
            ("PrivateDevices", Value::from(true)),
            ("ProtectKernelModules", Value::from(true)),
            ("ProtectKernelTunables", Value::from(true)),
            ("ProtectControlGroups", Value::from(true)),
            ("MemoryDenyWriteExecute", Value::from(true)),
            ("LockPersonality", Value::from(true)),
            ("RestrictRealtime", Value::from(true)),
            ("RestrictSUIDSGID", Value::from(true)),
            (
                "RestrictAddressFamilies",
                Value::from((true, vec!["AF_UNIX"])),
            ),
            (
                "IPAddressDeny",
                Value::from(vec![
                    (2_i32, vec![0_u8; 4], 0_u32),
                    (10_i32, vec![0_u8; 16], 0_u32),
                ]),
            ),
            ("SystemCallArchitectures", Value::from(vec!["native"])),
        ];
        let names = properties
            .iter()
            .map(|(name, _)| *name)
            .collect::<BTreeSet<_>>();
        if names.len() != properties.len() {
            bail!("duplicate fixed observer transient property");
        }
        Ok(properties)
    }
}

pub fn observer_property_signatures() -> Result<Vec<(String, String)>> {
    ObserverServicePlan::new(
        "contract",
        PathBuf::from("/tmp/release/nemord"),
        PathBuf::from("/tmp/observer.toml"),
    )?
    .encoded_property_signatures()
}

pub fn observer_aux_signature() -> String {
    type Auxiliary<'a> = Vec<(&'a str, Vec<(&'a str, Value<'a>)>)>;
    <Auxiliary<'_> as Type>::SIGNATURE.to_string()
}

fn validate_observer_unit_name(name: &str) -> Result<()> {
    let suffix = name
        .strip_prefix(OBSERVER_PREFIX)
        .and_then(|value| value.strip_suffix(".service"))
        .context("unit is outside the benchmark observer service prefix")?;
    if suffix.is_empty()
        || suffix.len() > 32
        || !suffix
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        bail!("malformed generated observer service name");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedObserverManifest {
    pub schema_version: u32,
    pub run_id: String,
    pub created_uid: u32,
    pub prepared_directory: PathBuf,
    pub repository: PathBuf,
    pub provenance: BuildProvenance,
    pub runner_path: PathBuf,
    pub runner_sha256: String,
    pub observer_path: PathBuf,
    pub observer_sha256: String,
    pub observer_embedded_commit: String,
    pub config_path: PathBuf,
    pub config_sha256: String,
    pub plan: ObserverServicePlan,
    pub transient_property_audit: Vec<ObserverTransientPropertyAudit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityBoundManifest {
    pub payload: PreparedObserverManifest,
    pub payload_sha256: String,
}

impl IntegrityBoundManifest {
    pub fn new(payload: PreparedObserverManifest) -> Result<Self> {
        let payload_sha256 = hash_json(&payload)?;
        Ok(Self {
            payload,
            payload_sha256,
        })
    }

    pub fn verify(&self, manifest_path: &Path) -> Result<()> {
        if hash_json(&self.payload)? != self.payload_sha256 {
            bail!("observer preparation manifest integrity mismatch");
        }
        verify_prepared_path(manifest_path, self.payload.created_uid)?;
        verify_prepared_path(&self.payload.config_path, self.payload.created_uid)?;
        verify_prepared_directory(&self.payload.prepared_directory, self.payload.created_uid)?;
        if manifest_path.parent() != Some(self.payload.prepared_directory.as_path())
            || self.payload.config_path.parent() != Some(self.payload.prepared_directory.as_path())
        {
            bail!("prepared manifest/config escaped the verified directory");
        }
        if self.payload.transient_property_audit != self.payload.plan.property_audit()? {
            bail!("observer transient property audit differs from encoded request");
        }
        let current = std::env::current_exe()?.canonicalize()?;
        if current != self.payload.runner_path.canonicalize()? {
            bail!("privileged runner path differs from prepared runner");
        }
        if sha256_file(&current)? != self.payload.runner_sha256
            || sha256_file(&self.payload.observer_path)? != self.payload.observer_sha256
            || sha256_file(&self.payload.config_path)? != self.payload.config_sha256
        {
            bail!("prepared binary or config changed before privileged execution");
        }
        let release_parent = current
            .parent()
            .context("runner release directory unavailable")?;
        if release_parent.file_name().and_then(|value| value.to_str()) != Some("release")
            || self.payload.observer_path.parent() != Some(release_parent)
        {
            bail!("prepared executables are not sibling release binaries");
        }
        let observer_bytes = fs::read(&self.payload.observer_path)?;
        if self.payload.observer_embedded_commit != self.payload.provenance.git_head
            || !observer_bytes
                .windows(self.payload.provenance.git_head.len())
                .any(|window| window == self.payload.provenance.git_head.as_bytes())
        {
            bail!("observer binary embedded commit no longer matches manifest");
        }
        self.payload.plan.validate()
    }
}

fn verify_prepared_path(path: &Path, uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("prepared input must be a regular non-symlink file");
    }
    if metadata.uid() != uid || metadata.permissions().mode() & 0o022 != 0 || metadata.nlink() != 1
    {
        bail!("prepared input ownership or mode is unsafe");
    }
    let maximum = if path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name.ends_with(".manifest.json"))
    {
        MAX_PREPARED_MANIFEST_BYTES
    } else {
        MAX_PREPARED_CONFIG_BYTES
    };
    if metadata.len() == 0 || metadata.len() > maximum {
        bail!("prepared input size is outside the bounded contract");
    }
    Ok(())
}

fn verify_prepared_directory(path: &Path, uid: u32) -> Result<()> {
    if !path.is_absolute() {
        bail!("prepared directory must be absolute");
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!("prepared directory ownership, type or mode is unsafe");
    }
    Ok(())
}

pub fn prepare_observer_manifest(
    repository: &Path,
    config_template: &Path,
    observer_binary: &Path,
    destination_dir: &Path,
) -> Result<PathBuf> {
    if nix::unistd::geteuid().is_root() {
        bail!("observer preparation must run as an unprivileged user");
    }
    if std::env::current_dir()?.canonicalize()? != repository.canonicalize()? {
        bail!("observer preparation must run from the explicit repository root");
    }
    let provenance = BuildProvenance::capture()?;
    if !provenance.clean_release_eligible() {
        bail!("observer validation preparation requires clean release provenance");
    }
    if !repository.canonicalize()?.join(".git").exists() {
        bail!("prepared repository root is invalid");
    }
    if !destination_dir.is_absolute() {
        bail!("prepared directory must use an explicit absolute path");
    }
    fs::create_dir(destination_dir)?;
    fs::set_permissions(destination_dir, fs::Permissions::from_mode(0o755))?;
    verify_prepared_directory(destination_dir, nix::unistd::getuid().as_raw())?;
    let run_id = format!("checkpoint3ap{}", now_ns());
    let runner_path = std::env::current_exe()?.canonicalize()?;
    let observer_path = observer_binary.canonicalize()?;
    let observer_metadata = fs::symlink_metadata(observer_binary)?;
    if observer_metadata.file_type().is_symlink()
        || !observer_metadata.is_file()
        || observer_metadata.nlink() != 1
    {
        bail!("observer binary must be a regular non-symlink single-link file");
    }
    let config_path = destination_dir.join(format!("{run_id}.toml"));
    let provisional =
        ObserverServicePlan::new(&run_id, observer_path.clone(), config_path.clone())?;
    write_inspection_config(config_template, &provisional.database, &config_path)?;
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644))?;
    verify_prepared_path(&config_path, nix::unistd::getuid().as_raw())?;
    let loaded = common::LoadedConfig::load(&config_path)?;
    crate::performance::observer_invariant(&loaded.config).validate()?;
    let observer_bytes = fs::read(&observer_path)?;
    if !observer_bytes
        .windows(provenance.git_head.len())
        .any(|window| window == provenance.git_head.as_bytes())
    {
        bail!("observer binary does not embed prepared Git commit");
    }
    let payload = PreparedObserverManifest {
        schema_version: 1,
        run_id: run_id.clone(),
        created_uid: nix::unistd::getuid().as_raw(),
        prepared_directory: destination_dir.to_path_buf(),
        repository: repository.canonicalize()?,
        provenance,
        runner_sha256: sha256_file(&runner_path)?,
        observer_sha256: sha256_file(&observer_path)?,
        observer_embedded_commit: BUILD_GIT_HEAD.into(),
        config_sha256: sha256_file(&config_path)?,
        runner_path,
        observer_path,
        config_path,
        transient_property_audit: provisional.property_audit()?,
        plan: provisional,
    };
    let manifest = IntegrityBoundManifest::new(payload)?;
    let path = destination_dir.join(format!("{run_id}.manifest.json"));
    fs::write(&path, serde_json::to_vec_pretty(&manifest)?)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    verify_prepared_path(&path, nix::unistd::getuid().as_raw())?;
    Ok(path)
}

const BUILD_GIT_HEAD: &str = env!("NEMOR_BUILD_GIT_HEAD");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserverServiceState {
    pub unit_name: String,
    pub object_path: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub main_pid: u32,
    pub exec_main_pid: u32,
    pub exec_main_status: i32,
    pub result: String,
    pub dynamic_user: bool,
    pub umask: u32,
    pub runtime_directories: Vec<String>,
    pub runtime_directory_mode: u32,
    pub runtime_directory_preserve: String,
    pub no_new_privileges: bool,
    pub capability_bounding_set: u64,
    pub ambient_capabilities: u64,
    pub protect_system: String,
    pub protect_home: bool,
    pub private_tmp: bool,
    pub private_devices: bool,
    pub protect_kernel_tunables: bool,
    pub protect_control_groups: bool,
    pub protect_kernel_modules: bool,
    pub memory_deny_write_execute: bool,
    pub lock_personality: bool,
    pub restrict_realtime: bool,
    pub restrict_suid_sgid: bool,
    pub restrict_address_families: (bool, Vec<String>),
    pub system_call_architectures: Vec<String>,
    pub ip_address_deny: Vec<(i32, Vec<u8>, u32)>,
    pub control_group: String,
    pub start_ticks: u64,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub executable_sha256: String,
}

impl ObserverServiceState {
    pub fn verify_declared(&self, plan: &ObserverServicePlan, expected_sha256: &str) -> Result<()> {
        if self.unit_name != plan.unit_name
            || self.load_state != "loaded"
            || self.active_state != "active"
            || self.sub_state != "running"
            || self.main_pid == 0
            || self.exec_main_pid != self.main_pid
            || self.exec_main_status != 0
            || self.result != "success"
            || !self.dynamic_user
            || self.umask != 0o077
            || self.runtime_directories != [plan.runtime_directory.clone()]
            || self.runtime_directory_mode != 0o700
            || self.runtime_directory_preserve != "no"
            || !self.no_new_privileges
            || self.capability_bounding_set != 0
            || self.ambient_capabilities != 0
            || self.protect_system != "strict"
            || !self.protect_home
            || !self.private_tmp
            || !self.private_devices
            || !self.protect_kernel_tunables
            || !self.protect_control_groups
            || !self.protect_kernel_modules
            || !self.memory_deny_write_execute
            || !self.lock_personality
            || !self.restrict_realtime
            || !self.restrict_suid_sgid
            || self.restrict_address_families != (true, vec!["AF_UNIX".into()])
            || self.system_call_architectures != ["native"]
            || self.ip_address_deny != [(2, vec![0; 4], 0), (10, vec![0; 16], 0)]
            || self.effective_uid == 0
            || self.control_group.is_empty()
            || !self.control_group.starts_with('/')
            || self.control_group.contains("..")
            || self.executable_sha256 != expected_sha256
        {
            bail!("transient observer service identity contract failed");
        }
        Ok(())
    }

    pub fn verify(&self, plan: &ObserverServicePlan, expected_sha256: &str) -> Result<()> {
        self.verify_declared(plan, expected_sha256)?;
        if read_start_ticks(self.main_pid) != Some(self.start_ticks) {
            bail!("observer MainPID/start_ticks identity changed");
        }
        let cgroup = fs::read_to_string(format!("/proc/{}/cgroup", self.main_pid))?;
        if !cgroup
            .lines()
            .any(|line| line.strip_prefix("0::") == Some(self.control_group.as_str()))
        {
            bail!("observer MainPID is outside systemd ControlGroup");
        }
        let exe = fs::read_link(format!("/proc/{}/exe", self.main_pid))?;
        if sha256_file(&exe)? != expected_sha256 {
            bail!("observer /proc/exe differs from approved binary identity");
        }
        Ok(())
    }
}

pub trait ObserverServiceBackend {
    fn preflight(&self) -> Result<()>;
    fn unit_exists(&self, unit_name: &str) -> Result<bool>;
    fn start(&mut self, plan: &ObserverServicePlan) -> Result<ObserverServiceState>;
    fn verify_active(
        &self,
        plan: &ObserverServicePlan,
        expected: &ObserverServiceState,
    ) -> Result<()>;
    fn stop(&mut self, plan: &ObserverServicePlan) -> Result<()>;
    fn wait_absent(&self, plan: &ObserverServicePlan) -> Result<()>;
}

pub struct SystemdObserverServiceBackend {
    connection: Connection,
}

impl SystemdObserverServiceBackend {
    pub fn system() -> Result<Self> {
        Ok(Self {
            connection: Connection::system()?,
        })
    }

    fn manager(&self) -> Result<Proxy<'_>> {
        Ok(Proxy::new(
            &self.connection,
            DESTINATION,
            MANAGER_PATH,
            MANAGER_INTERFACE,
        )?)
    }

    fn run_job(
        &self,
        method: &'static str,
        plan: &ObserverServicePlan,
    ) -> Result<SystemdJobOutcome> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        runtime.block_on(async {
            let connection = zbus::Connection::system().await?;
            let manager =
                zbus::Proxy::new(&connection, DESTINATION, MANAGER_PATH, MANAGER_INTERFACE).await?;
            manager.call::<_, _, ()>("Subscribe", &()).await?;
            let mut removed = manager
                .receive_signal_with_args("JobRemoved", &[(2, plan.unit_name.as_str())])
                .await?;
            let job_path: OwnedObjectPath = match method {
                "StartTransientUnit" => {
                    let properties = plan.encoded_properties()?;
                    let auxiliary: Vec<(&str, Vec<(&str, Value<'_>)>)> = Vec::new();
                    manager
                        .call(
                            method,
                            &(plan.unit_name.as_str(), "fail", properties, auxiliary),
                        )
                        .await?
                }
                "StopUnit" => {
                    manager
                        .call(method, &(plan.unit_name.as_str(), "fail"))
                        .await?
                }
                _ => bail!("unsupported observer systemd job"),
            };
            let expected = job_path.to_string();
            let outcome = tokio::time::timeout(Duration::from_secs(5), async {
                while let Some(message) = removed.next().await {
                    let (_id, path, unit, result): (u32, OwnedObjectPath, String, String) =
                        message.body().deserialize()?;
                    if path.as_str() == expected && unit == plan.unit_name {
                        return Ok::<_, anyhow::Error>(SystemdJobOutcome {
                            job_path: expected.clone(),
                            unit_name: unit,
                            successful: result == "done",
                            result,
                        });
                    }
                }
                bail!("systemd disconnected before observer job completion")
            })
            .await
            .context("observer systemd job timed out")??;
            require_successful_job(&outcome)?;
            Ok(outcome)
        })
    }

    fn read_state(&self, plan: &ObserverServicePlan) -> Result<ObserverServiceState> {
        let object: OwnedObjectPath = self.manager()?.call("GetUnit", &plan.unit_name)?;
        let unit = Proxy::new(
            &self.connection,
            DESTINATION,
            object.as_str(),
            UNIT_INTERFACE,
        )?;
        let service = Proxy::new(
            &self.connection,
            DESTINATION,
            object.as_str(),
            SERVICE_INTERFACE,
        )?;
        let main_pid: u32 = service.get_property("MainPID")?;
        let pid_object: OwnedObjectPath = self.manager()?.call("GetUnitByPID", &main_pid)?;
        if pid_object != object {
            bail!("GetUnit and GetUnitByPID disagree for observer MainPID");
        }
        let (uid, gid) = read_effective_ids(main_pid)?;
        let exe = fs::read_link(format!("/proc/{main_pid}/exe"))?;
        let control_group: String = service.get_property("ControlGroup")?;
        let members = fs::read_to_string(
            Path::new("/sys/fs/cgroup")
                .join(control_group.trim_start_matches('/'))
                .join("cgroup.procs"),
        )?
        .lines()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        if members != BTreeSet::from([main_pid]) {
            bail!("observer service ControlGroup contains a foreign or missing PID");
        }
        Ok(ObserverServiceState {
            unit_name: unit.get_property("Id")?,
            object_path: object.to_string(),
            load_state: unit.get_property("LoadState")?,
            active_state: unit.get_property("ActiveState")?,
            sub_state: unit.get_property("SubState")?,
            control_group,
            main_pid,
            exec_main_pid: service.get_property("ExecMainPID")?,
            exec_main_status: service.get_property("ExecMainStatus")?,
            result: service.get_property("Result")?,
            dynamic_user: service.get_property("DynamicUser")?,
            umask: service.get_property("UMask")?,
            runtime_directories: service.get_property("RuntimeDirectory")?,
            runtime_directory_mode: service.get_property("RuntimeDirectoryMode")?,
            runtime_directory_preserve: service.get_property("RuntimeDirectoryPreserve")?,
            no_new_privileges: service.get_property("NoNewPrivileges")?,
            capability_bounding_set: service.get_property("CapabilityBoundingSet")?,
            ambient_capabilities: service.get_property("AmbientCapabilities")?,
            protect_system: service.get_property("ProtectSystem")?,
            protect_home: service.get_property("ProtectHome")?,
            private_tmp: service.get_property("PrivateTmp")?,
            private_devices: service.get_property("PrivateDevices")?,
            protect_kernel_tunables: service.get_property("ProtectKernelTunables")?,
            protect_control_groups: service.get_property("ProtectControlGroups")?,
            protect_kernel_modules: service.get_property("ProtectKernelModules")?,
            memory_deny_write_execute: service.get_property("MemoryDenyWriteExecute")?,
            lock_personality: service.get_property("LockPersonality")?,
            restrict_realtime: service.get_property("RestrictRealtime")?,
            restrict_suid_sgid: service.get_property("RestrictSUIDSGID")?,
            restrict_address_families: service.get_property("RestrictAddressFamilies")?,
            system_call_architectures: service.get_property("SystemCallArchitectures")?,
            ip_address_deny: service.get_property("IPAddressDeny")?,
            start_ticks: read_start_ticks(main_pid).context("observer start_ticks unavailable")?,
            effective_uid: uid,
            effective_gid: gid,
            executable_sha256: sha256_file(&exe)?,
        })
    }
}

impl ObserverServiceBackend for SystemdObserverServiceBackend {
    fn preflight(&self) -> Result<()> {
        let xml: String = Proxy::new(
            &self.connection,
            DESTINATION,
            MANAGER_PATH,
            "org.freedesktop.DBus.Introspectable",
        )?
        .call("Introspect", &())?;
        if !xml.contains("StartTransientUnit") || !xml.contains("Subscribe") {
            bail!("system manager transient service API unavailable");
        }
        let probe: OwnedObjectPath = self.manager()?.call("GetUnit", &"dbus.service")?;
        let service_xml: String = Proxy::new(
            &self.connection,
            DESTINATION,
            probe.as_str(),
            "org.freedesktop.DBus.Introspectable",
        )?
        .call("Introspect", &())?;
        for expected in OBSERVER_READBACK_CONTRACT {
            let marker = format!("<interface name=\"{}\">", expected.interface);
            let body = service_xml
                .split(&marker)
                .nth(1)
                .and_then(|tail| tail.split("</interface>").next())
                .context("observer Unit/Service interface unavailable")?;
            if !body.contains(&format!(
                "<property name=\"{}\" type=\"{}\"",
                expected.property, expected.signature
            )) {
                bail!(
                    "observer readback property contract missing {}.{}",
                    expected.interface,
                    expected.property
                );
            }
        }
        Ok(())
    }

    fn unit_exists(&self, unit_name: &str) -> Result<bool> {
        validate_observer_unit_name(unit_name)?;
        Ok(self
            .manager()?
            .call::<_, _, OwnedObjectPath>("GetUnit", &unit_name)
            .is_ok())
    }

    fn start(&mut self, plan: &ObserverServicePlan) -> Result<ObserverServiceState> {
        if self.unit_exists(&plan.unit_name)? {
            bail!("exact observer service name already exists");
        }
        self.run_job("StartTransientUnit", plan)?;
        self.read_state(plan)
    }

    fn stop(&mut self, plan: &ObserverServicePlan) -> Result<()> {
        if self.unit_exists(&plan.unit_name)? {
            self.run_job("StopUnit", plan)?;
        }
        Ok(())
    }

    fn verify_active(
        &self,
        plan: &ObserverServicePlan,
        expected: &ObserverServiceState,
    ) -> Result<()> {
        let current = self.read_state(plan)?;
        if current.main_pid != expected.main_pid
            || current.start_ticks != expected.start_ticks
            || current.control_group != expected.control_group
        {
            bail!("observer service identity changed while validation was active");
        }
        Ok(())
    }

    fn wait_absent(&self, plan: &ObserverServicePlan) -> Result<()> {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if !self.unit_exists(&plan.unit_name)?
                && !Path::new(RUNTIME_BASE)
                    .join(&plan.runtime_directory)
                    .exists()
            {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        bail!("observer unit or RuntimeDirectory remained after cleanup")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverValidationReport {
    pub run_id: String,
    pub evidence_kind: EvidenceKind,
    pub performance_claim_eligible: bool,
    pub provenance: BuildProvenance,
    pub plan: ObserverServicePlan,
    pub transient_property_audit: Vec<ObserverTransientPropertyAudit>,
    pub state: Option<ObserverServiceState>,
    pub observer_setup_wall_seconds: Option<f64>,
    pub observer_setup_cpu_seconds: Option<f64>,
    pub readiness: String,
    pub readiness_duration_seconds: Option<f64>,
    pub foreign_nemord_clear: bool,
    pub structural_restore_passed: bool,
    pub process_absent: bool,
    pub unit_absent: bool,
    pub cgroup_absent: bool,
    pub runtime_state_cleaned: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct ObserverHostSnapshot {
    structural: StructuralSnapshot,
    production_database: Option<(u64, i64, i64)>,
    production_config_sha256: Option<String>,
    cgroup_tree: BTreeSet<String>,
}

impl ObserverHostSnapshot {
    fn capture() -> Self {
        let production_database = fs::metadata(PRODUCTION_DATABASE)
            .ok()
            .map(|metadata| (metadata.len(), metadata.mtime(), metadata.mtime_nsec()));
        let production_config_sha256 = sha256_file(Path::new("/etc/nemor/config.toml")).ok();
        let cgroup_tree = bounded_directory_tree(Path::new("/sys/fs/cgroup"), 4);
        Self {
            structural: StructuralSnapshot::capture(),
            production_database,
            production_config_sha256,
            cgroup_tree,
        }
    }

    fn matches(&self, other: &Self) -> bool {
        self.structural.matches(&other.structural)
            && self.production_database == other.production_database
            && self.production_config_sha256 == other.production_config_sha256
            && self.cgroup_tree == other.cgroup_tree
    }
}

fn bounded_directory_tree(root: &Path, remaining_depth: usize) -> BTreeSet<String> {
    fn visit(root: &Path, path: &Path, depth: usize, output: &mut BTreeSet<String>) {
        if depth == 0 {
            return;
        }
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if !kind.is_dir() {
                continue;
            }
            let child = entry.path();
            if let Ok(relative) = child.strip_prefix(root) {
                output.insert(relative.to_string_lossy().into_owned());
            }
            visit(root, &child, depth - 1, output);
        }
    }
    let mut output = BTreeSet::new();
    visit(root, root, remaining_depth, &mut output);
    output
}

impl ObserverValidationReport {
    pub fn passed(&self) -> bool {
        self.errors.is_empty()
            && self.readiness == "telemetry_sample_persisted"
            && self.process_absent
            && self.unit_absent
            && self.cgroup_absent
            && self.runtime_state_cleaned
            && self.structural_restore_passed
    }
}

pub fn validate_observer_service_with_backend<B: ObserverServiceBackend>(
    manifest: &IntegrityBoundManifest,
    backend: &mut B,
) -> Result<ObserverValidationReport> {
    backend.preflight()?;
    let plan = &manifest.payload.plan;
    let foreign = detect_nemord_processes(&manifest.payload.observer_path, None);
    reject_foreign_nemord(&foreign, None)?;
    let before = ObserverHostSnapshot::capture();
    let setup_wall = Instant::now();
    let mut report = ObserverValidationReport {
        run_id: manifest.payload.run_id.clone(),
        evidence_kind: EvidenceKind::HarnessValidation,
        performance_claim_eligible: false,
        provenance: manifest.payload.provenance.clone(),
        plan: plan.clone(),
        transient_property_audit: plan.property_audit()?,
        state: None,
        observer_setup_wall_seconds: None,
        observer_setup_cpu_seconds: None,
        readiness: "not_started".into(),
        readiness_duration_seconds: None,
        foreign_nemord_clear: true,
        structural_restore_passed: false,
        process_absent: false,
        unit_absent: false,
        cgroup_absent: false,
        runtime_state_cleaned: false,
        errors: Vec::new(),
    };
    let start_result = backend.start(plan);
    match start_result {
        Ok(state) => {
            let identity_result = state.verify(plan, &manifest.payload.observer_sha256);
            report.state = Some(state);
            if let Err(error) = identity_result {
                report.errors.push(error.to_string());
            } else if let Err(error) = wait_ready(
                &plan.database,
                backend,
                plan,
                report.state.as_ref().unwrap(),
            ) {
                report.errors.push(error.to_string());
            } else {
                report.readiness_duration_seconds = Some(setup_wall.elapsed().as_secs_f64());
                report.observer_setup_wall_seconds = Some(setup_wall.elapsed().as_secs_f64());
                report.observer_setup_cpu_seconds =
                    process_cpu_ticks(report.state.as_ref().unwrap().main_pid)
                        .zip(detect_clk_tck())
                        .map(|(ticks, ticks_per_second)| ticks as f64 / ticks_per_second as f64);
                report.readiness = "telemetry_sample_persisted".into();
                if let Err(error) =
                    observe_alive_window(backend, plan, report.state.as_ref().unwrap())
                {
                    report.errors.push(error.to_string());
                }
            }
        }
        Err(error) => report.errors.push(error.to_string()),
    }
    if let Err(error) = backend.stop(plan) {
        report.errors.push(error.to_string());
    }
    if let Err(error) = backend.wait_absent(plan) {
        report.errors.push(error.to_string());
    }
    report.process_absent = report
        .state
        .as_ref()
        .is_none_or(|state| read_start_ticks(state.main_pid) != Some(state.start_ticks));
    report.unit_absent = !backend.unit_exists(&plan.unit_name).unwrap_or(true);
    report.cgroup_absent = report.state.as_ref().is_none_or(|state| {
        !Path::new("/sys/fs/cgroup")
            .join(state.control_group.trim_start_matches('/'))
            .exists()
    });
    report.runtime_state_cleaned = !Path::new(RUNTIME_BASE)
        .join(&plan.runtime_directory)
        .exists();
    report.structural_restore_passed = before.matches(&ObserverHostSnapshot::capture());
    Ok(report)
}

pub fn execute_observer_validation(
    manifest_path: &Path,
    report_path: &Path,
) -> Result<ObserverValidationReport> {
    if !nix::unistd::geteuid().is_root() {
        bail!("observer service validation requires privileged execution");
    }
    let manifest: IntegrityBoundManifest = serde_json::from_slice(&fs::read(manifest_path)?)?;
    manifest.verify(manifest_path)?;
    fs::write(
        report_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "run_id": manifest.payload.run_id,
            "evidence_kind": "harness_validation",
            "performance_claim_eligible": false,
            "audit_complete": true,
            "mutation_started": false,
            "unit_name": manifest.payload.plan.unit_name,
            "transient_property_audit": manifest.payload.transient_property_audit,
            "manifest_payload_sha256": manifest.payload_sha256,
        }))?,
    )?;
    fs::set_permissions(report_path, fs::Permissions::from_mode(0o600))?;
    let (staged_manifest, staged_config) = stage_root_owned_config(&manifest)?;
    let mut backend = SystemdObserverServiceBackend::system()?;
    let result = validate_observer_service_with_backend(&staged_manifest, &mut backend);
    let cleanup_result = remove_staged_config(&staged_config);
    let report = result?;
    cleanup_result?;
    fs::write(report_path, serde_json::to_vec_pretty(&report)?)?;
    fs::set_permissions(report_path, fs::Permissions::from_mode(0o600))?;
    if !report.passed() {
        bail!(
            "observer service validation failed closed; report preserved at {}",
            report_path.display()
        );
    }
    Ok(report)
}

fn stage_root_owned_config(
    manifest: &IntegrityBoundManifest,
) -> Result<(IntegrityBoundManifest, PathBuf)> {
    let suffix = manifest
        .payload
        .run_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(32)
        .collect::<String>();
    let staged = Path::new("/run").join(format!("nemor-benchmark-observer-config-{suffix}.toml"));
    let bytes = fs::read(&manifest.payload.config_path)?;
    if hex::encode(Sha256::digest(&bytes)) != manifest.payload.config_sha256 {
        bail!("observer config changed before root-owned staging");
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&staged)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    if sha256_file(&staged)? != manifest.payload.config_sha256 {
        let _ = fs::remove_file(&staged);
        bail!("root-owned staged observer config hash mismatch");
    }
    let mut payload = manifest.payload.clone();
    payload.config_path = staged.clone();
    payload.plan.config = staged.clone();
    payload.transient_property_audit = payload.plan.property_audit()?;
    Ok((IntegrityBoundManifest::new(payload)?, staged))
}

fn remove_staged_config(path: &Path) -> Result<()> {
    if path.parent() != Some(Path::new("/run"))
        || !path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.starts_with("nemor-benchmark-observer-config-"))
    {
        bail!("refusing unsafe staged config cleanup target");
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.uid() != 0 {
        bail!("refusing ambiguous staged config cleanup");
    }
    fs::remove_file(path)?;
    Ok(())
}

fn wait_ready<B: ObserverServiceBackend>(
    database: &Path,
    backend: &B,
    plan: &ObserverServicePlan,
    state: &ObserverServiceState,
) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < READY_TIMEOUT {
        if storage::latest_telemetry_report(database).is_ok_and(|report| report.system_samples > 0)
        {
            return Ok(());
        }
        backend.verify_active(plan, state)?;
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("observer did not persist a telemetry sample before readiness timeout")
}

fn observe_alive_window<B: ObserverServiceBackend>(
    backend: &B,
    plan: &ObserverServicePlan,
    state: &ObserverServiceState,
) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < VALIDATION_WINDOW {
        backend.verify_active(plan, state)?;
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn read_effective_ids(pid: u32) -> Result<(u32, u32)> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let uid = parse_effective_id(&status, "Uid:")?;
    let gid = parse_effective_id(&status, "Gid:")?;
    Ok((uid, gid))
}

fn parse_effective_id(status: &str, prefix: &str) -> Result<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .and_then(|value| value.split_whitespace().nth(1))
        .context("effective process identity unavailable")?
        .parse()
        .context("invalid effective process identity")
}

fn sha256_file(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

fn hash_json(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    fn plan() -> ObserverServicePlan {
        ObserverServicePlan::new(
            "attempt1",
            PathBuf::from("/tmp/target/release/nemord"),
            PathBuf::from("/tmp/checkpoint3ap/config.toml"),
        )
        .unwrap()
    }

    fn state(plan: &ObserverServicePlan) -> ObserverServiceState {
        ObserverServiceState {
            unit_name: plan.unit_name.clone(),
            object_path: "/org/freedesktop/systemd1/unit/test".into(),
            load_state: "loaded".into(),
            active_state: "active".into(),
            sub_state: "running".into(),
            main_pid: 42,
            exec_main_pid: 42,
            exec_main_status: 0,
            result: "success".into(),
            dynamic_user: true,
            umask: 0o077,
            runtime_directories: vec![plan.runtime_directory.clone()],
            runtime_directory_mode: 0o700,
            runtime_directory_preserve: "no".into(),
            no_new_privileges: true,
            capability_bounding_set: 0,
            ambient_capabilities: 0,
            protect_system: "strict".into(),
            protect_home: true,
            private_tmp: true,
            private_devices: true,
            protect_kernel_tunables: true,
            protect_control_groups: true,
            protect_kernel_modules: true,
            memory_deny_write_execute: true,
            lock_personality: true,
            restrict_realtime: true,
            restrict_suid_sgid: true,
            restrict_address_families: (true, vec!["AF_UNIX".into()]),
            system_call_architectures: vec!["native".into()],
            ip_address_deny: vec![(2, vec![0; 4], 0), (10, vec![0; 16], 0)],
            control_group: "/system.slice/test.service".into(),
            start_ticks: 10,
            effective_uid: 61_234,
            effective_gid: 61_234,
            executable_sha256: "binary".into(),
        }
    }

    #[test]
    fn transient_observer_request_is_fixed_typed_service_contract() {
        let plan = plan();
        assert!(plan.unit_name.ends_with(".service"));
        let properties = plan.encoded_property_signatures().unwrap();
        let lookup = |name: &str| {
            properties
                .iter()
                .find(|(property, _)| property == name)
                .map(|(_, signature)| signature.as_str())
        };
        assert_eq!(lookup("ExecStart"), Some("a(sasb)"));
        assert_eq!(lookup("DynamicUser"), Some("b"));
        assert_eq!(lookup("UMask"), Some("u"));
        assert_eq!(lookup("RuntimeDirectory"), Some("as"));
        assert_eq!(lookup("RuntimeDirectoryMode"), Some("u"));
        assert_eq!(lookup("RuntimeDirectoryPreserve"), Some("s"));
        assert_eq!(lookup("BindReadOnlyPaths"), Some("a(ssbt)"));
        assert_eq!(lookup("RestrictAddressFamilies"), Some("(bas)"));
        assert_eq!(lookup("IPAddressDeny"), Some("a(iayu)"));
        assert_eq!(lookup("CapabilityBoundingSet"), Some("t"));
        assert_eq!(lookup("AmbientCapabilities"), Some("t"));
        assert_eq!(observer_aux_signature(), "a(sa(sv))");
        let audit = plan.property_audit().unwrap();
        assert_eq!(audit.len(), properties.len());
        assert!(audit.iter().all(|entry| entry.required));
        assert_eq!(
            audit
                .iter()
                .map(|entry| entry.property.as_str())
                .collect::<Vec<_>>(),
            [
                "Description",
                "Type",
                "ExecStart",
                "DynamicUser",
                "UMask",
                "CollectMode",
                "TimeoutStartUSec",
                "TimeoutStopUSec",
                "RuntimeMaxUSec",
                "RuntimeDirectory",
                "RuntimeDirectoryMode",
                "RuntimeDirectoryPreserve",
                "BindReadOnlyPaths",
                "WorkingDirectory",
                "NoNewPrivileges",
                "CapabilityBoundingSet",
                "AmbientCapabilities",
                "ProtectSystem",
                "ProtectHome",
                "PrivateTmp",
                "PrivateDevices",
                "ProtectKernelModules",
                "ProtectKernelTunables",
                "ProtectControlGroups",
                "MemoryDenyWriteExecute",
                "LockPersonality",
                "RestrictRealtime",
                "RestrictSUIDSGID",
                "RestrictAddressFamilies",
                "IPAddressDeny",
                "SystemCallArchitectures",
            ]
        );
    }

    #[test]
    fn observer_request_uses_mode_fail_and_subscribe_before_start() {
        let source = include_str!("observer_service.rs");
        let subscribe = source.find("\"Subscribe\"").unwrap();
        let receive = source.find("receive_signal_with_args").unwrap();
        let start = source.find("\"StartTransientUnit\" =>").unwrap();
        assert!(subscribe < receive && receive < start);
        assert!(source.contains("plan.unit_name.as_str(), \"fail\""));
    }

    #[test]
    fn exec_start_is_absolute_exact_argv_and_rejects_arbitrary_binary() {
        let valid = plan();
        valid.validate().unwrap();
        let mut wrong = valid.clone();
        wrong.binary = PathBuf::from("/bin/sh");
        assert!(wrong.validate().is_err());
        let mut relative = valid;
        relative.binary = PathBuf::from("nemord");
        assert!(relative.validate().is_err());
    }

    #[test]
    fn runtime_database_is_isolated_and_production_path_rejected() {
        let valid = plan();
        assert!(valid.database.starts_with("/run"));
        assert!(valid
            .database
            .to_string_lossy()
            .contains("nemor-benchmark-observer-"));
        let mut production = valid;
        production.database = PathBuf::from(PRODUCTION_DATABASE);
        assert!(production.validate().is_err());
    }

    #[test]
    fn dynamic_user_requires_non_root_but_not_stable_numeric_uid() {
        let plan = plan();
        let first = state(&plan);
        first.verify_declared(&plan, "binary").unwrap();
        let mut another = first.clone();
        another.effective_uid = 62_000;
        another.effective_gid = 62_000;
        another.verify_declared(&plan, "binary").unwrap();
        let mut root = first;
        root.effective_uid = 0;
        assert!(root.verify_declared(&plan, "binary").is_err());
    }

    #[test]
    fn main_pid_dynamic_user_binary_and_cgroup_fail_closed() {
        let plan = plan();
        for mutate in 0..5 {
            let mut observed = state(&plan);
            match mutate {
                0 => observed.main_pid = 0,
                1 => observed.exec_main_pid += 1,
                2 => observed.dynamic_user = false,
                3 => observed.executable_sha256 = "stale".into(),
                4 => observed.control_group = "../foreign".into(),
                _ => unreachable!(),
            }
            assert!(observed.verify_declared(&plan, "binary").is_err());
        }
    }

    #[test]
    fn unit_and_service_property_routing_is_explicit() {
        let source = include_str!("observer_service.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(source.contains("UNIT_INTERFACE"));
        assert!(source.contains("SERVICE_INTERFACE"));
        assert!(source.contains("service.get_property(\"ControlGroup\")"));
        assert!(source.contains("service.get_property(\"MainPID\")"));
        assert!(!source.contains("unit.get_property(\"MainPID\")"));
    }

    #[test]
    fn asynchronous_stop_and_absence_are_required() {
        let source = include_str!("observer_service.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(source.contains("self.run_job(\"StopUnit\", plan)?"));
        assert!(source.contains("observer unit or RuntimeDirectory remained after cleanup"));
        assert!(source.contains("require_successful_job(&outcome)?"));
    }

    #[test]
    fn readiness_uses_real_persisted_telemetry_not_sleep_only() {
        let source = include_str!("observer_service.rs");
        assert!(source.contains("storage::latest_telemetry_report"));
        assert!(source.contains("report.system_samples > 0"));
        assert_eq!(VALIDATION_WINDOW, Duration::from_secs(5));
    }

    #[test]
    fn validation_is_harness_evidence_never_performance_claim() {
        let source = include_str!("observer_service.rs");
        assert!(source.contains("evidence_kind: EvidenceKind::HarnessValidation"));
        assert!(source.contains("performance_claim_eligible: false"));
    }

    #[test]
    fn production_service_and_foreign_processes_are_never_mutated() {
        let source = include_str!("observer_service.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!source.contains("nemord.service\", \""));
        assert!(!source.contains("systemctl"));
        assert!(!source.contains("systemd-run"));
        assert!(!source.contains("Command::new"));
        assert!(source.contains("reject_foreign_nemord"));
    }

    #[test]
    fn persistent_state_is_not_requested_and_runtime_cleanup_is_verified() {
        let properties = plan().encoded_property_signatures().unwrap();
        assert!(properties
            .iter()
            .any(|(name, _)| name == "RuntimeDirectory"));
        assert!(!properties.iter().any(|(name, _)| name == "StateDirectory"));
        assert!(include_str!("observer_service.rs").contains("runtime_state_cleaned"));
    }

    #[test]
    fn hardening_has_no_observer_performance_tuning() {
        let properties = plan().encoded_property_signatures().unwrap();
        for forbidden in [
            "CPUQuota",
            "CPUWeight",
            "MemoryMax",
            "MemoryHigh",
            "IOWeight",
        ] {
            assert!(!properties.iter().any(|(name, _)| name == forbidden));
        }
        for required in [
            "NoNewPrivileges",
            "ProtectSystem",
            "ProtectHome",
            "PrivateTmp",
            "PrivateDevices",
            "ProtectKernelTunables",
            "ProtectControlGroups",
        ] {
            assert!(properties.iter().any(|(name, _)| name == required));
        }
    }

    #[test]
    fn manifest_rejects_integrity_and_toctou_changes() {
        let source = include_str!("observer_service.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(source.contains("payload_sha256"));
        assert!(source.contains("sha256_file(&self.payload.observer_path)?"));
        assert!(source.contains("sha256_file(&self.payload.config_path)?"));
        assert!(source.contains("current != self.payload.runner_path.canonicalize()?"));
        assert!(!source.contains("git config"));
    }

    #[test]
    fn prepared_inputs_reject_symlink_wrong_owner_and_writable_modes() {
        let source = include_str!("observer_service.rs");
        assert!(source.contains("file_type().is_symlink()"));
        assert!(source.contains("metadata.uid() != uid"));
        assert!(source.contains("permissions().mode() & 0o022"));
        assert!(source.contains("metadata.nlink() != 1"));
        assert!(source.contains("MAX_PREPARED_CONFIG_BYTES"));

        let root = tempfile::tempdir().unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let directory = root.path().join("prepared");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        verify_prepared_directory(&directory, uid).unwrap();

        let regular = directory.join("config.toml");
        fs::write(&regular, b"bounded").unwrap();
        fs::set_permissions(&regular, fs::Permissions::from_mode(0o644)).unwrap();
        verify_prepared_path(&regular, uid).unwrap();

        fs::set_permissions(&regular, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(verify_prepared_path(&regular, uid).is_err());
        fs::set_permissions(&regular, fs::Permissions::from_mode(0o644)).unwrap();

        let second_link = directory.join("hardlink.toml");
        fs::hard_link(&regular, second_link).unwrap();
        assert!(verify_prepared_path(&regular, uid).is_err());
    }

    struct FailingBackend {
        start_error: Option<&'static str>,
        state: ObserverServiceState,
        stop_error: Option<&'static str>,
        absent_error: Option<&'static str>,
        stop_called: Rc<Cell<bool>>,
        exists: bool,
    }

    impl ObserverServiceBackend for FailingBackend {
        fn preflight(&self) -> Result<()> {
            Ok(())
        }

        fn unit_exists(&self, _unit_name: &str) -> Result<bool> {
            Ok(self.exists)
        }

        fn start(&mut self, _plan: &ObserverServicePlan) -> Result<ObserverServiceState> {
            self.start_error
                .map_or_else(|| Ok(self.state.clone()), |message| bail!("{message}"))
        }

        fn verify_active(
            &self,
            _plan: &ObserverServicePlan,
            _expected: &ObserverServiceState,
        ) -> Result<()> {
            Ok(())
        }

        fn stop(&mut self, _plan: &ObserverServicePlan) -> Result<()> {
            self.stop_called.set(true);
            self.stop_error.map_or(Ok(()), |message| bail!("{message}"))
        }

        fn wait_absent(&self, _plan: &ObserverServicePlan) -> Result<()> {
            self.absent_error
                .map_or(Ok(()), |message| bail!("{message}"))
        }
    }

    fn fake_manifest(plan: ObserverServicePlan) -> IntegrityBoundManifest {
        IntegrityBoundManifest::new(PreparedObserverManifest {
            schema_version: 1,
            run_id: "attempt1".into(),
            created_uid: 1000,
            prepared_directory: PathBuf::from("/tmp/prepared"),
            repository: PathBuf::from("/repo"),
            provenance: BuildProvenance {
                git_head: "a".repeat(40),
                git_dirty: true,
                source_state_id: "state".into(),
                binary_sha256: "runner".into(),
                build_profile: "release".into(),
                benchmark_schema_version: crate::BENCHMARK_SCHEMA_VERSION,
                development_build: false,
            },
            runner_path: PathBuf::from("/tmp/release/nemor-benchmark"),
            runner_sha256: "runner".into(),
            observer_path: plan.binary.clone(),
            observer_sha256: "binary".into(),
            observer_embedded_commit: "a".repeat(40),
            config_path: plan.config.clone(),
            config_sha256: "config".into(),
            transient_property_audit: plan.property_audit().unwrap(),
            plan,
        })
        .unwrap()
    }

    #[test]
    fn simulated_start_and_post_start_failures_always_enter_cleanup() {
        for failure in [
            "dynamic user property rejected",
            "exec start rejected",
            "start job timeout",
            "start job failed",
        ] {
            let plan = plan();
            let called = Rc::new(Cell::new(false));
            let mut backend = FailingBackend {
                start_error: Some(failure),
                state: state(&plan),
                stop_error: None,
                absent_error: None,
                stop_called: Rc::clone(&called),
                exists: false,
            };
            let report =
                validate_observer_service_with_backend(&fake_manifest(plan), &mut backend).unwrap();
            assert!(called.get());
            assert!(report.errors.iter().any(|error| error.contains(failure)));
            assert!(!report.passed());
        }
    }

    #[test]
    fn simulated_identity_failures_are_retained_and_cleaned() {
        for kind in 0..7 {
            let plan = plan();
            let mut invalid = state(&plan);
            match kind {
                0 => invalid.main_pid = 0,
                1 => invalid.exec_main_pid += 1,
                2 => invalid.effective_uid = 0,
                3 => invalid.dynamic_user = false,
                4 => invalid.executable_sha256 = "mismatch".into(),
                5 => invalid.control_group = String::new(),
                6 => invalid.active_state = "failed".into(),
                _ => unreachable!(),
            }
            let called = Rc::new(Cell::new(false));
            let mut backend = FailingBackend {
                start_error: None,
                state: invalid,
                stop_error: None,
                absent_error: None,
                stop_called: Rc::clone(&called),
                exists: false,
            };
            let report =
                validate_observer_service_with_backend(&fake_manifest(plan), &mut backend).unwrap();
            assert!(called.get());
            assert!(!report.errors.is_empty());
            assert!(!report.passed());
        }
    }

    #[test]
    fn simulated_stop_and_absence_failures_fail_closed() {
        for (stop_error, absent_error) in [
            (Some("StopUnit failure"), None),
            (None, Some("unit remains")),
            (Some("stop job timeout"), Some("runtime directory remains")),
        ] {
            let plan = plan();
            let called = Rc::new(Cell::new(false));
            let mut invalid = state(&plan);
            invalid.main_pid = 0;
            let mut backend = FailingBackend {
                start_error: None,
                state: invalid,
                stop_error,
                absent_error,
                stop_called: Rc::clone(&called),
                exists: true,
            };
            let report =
                validate_observer_service_with_backend(&fake_manifest(plan), &mut backend).unwrap();
            assert!(called.get());
            assert!(!report.passed());
        }
    }

    #[test]
    fn matched_timeline_places_setup_before_equal_common_hold() {
        let profile = crate::performance::PerformanceProfile::checkpoint3a(
            crate::performance::CHECKPOINT3A_DEFAULT_PAYLOAD_BYTES,
        )
        .unwrap();
        assert_eq!(profile.pre_measurement_hold_ms, 5_000);
        assert_eq!(profile.observer_warmup_ms, profile.pre_measurement_hold_ms);
        let source = include_str!("harness.rs");
        assert!(
            source.find("start_observer(launch").unwrap()
                < source
                    .find("thread::sleep(Duration::from_millis(hold_ms))")
                    .unwrap()
        );
        assert!(
            source
                .find("thread::sleep(Duration::from_millis(hold_ms))")
                .unwrap()
                < source.find("control_dir.join(\"allocate\")").unwrap()
        );
    }
}
