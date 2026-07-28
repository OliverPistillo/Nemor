use crate::harness::{detect_clk_tck, process_cpu_ticks, read_start_ticks};
use crate::performance::{detect_nemord_processes, reject_foreign_nemord, write_inspection_config};
use crate::systemd::{require_successful_job, SystemdJobOutcome};
use crate::{BuildProvenance, EvidenceKind, StructuralSnapshot};
use anyhow::{bail, Context, Result};
use futures_lite::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
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
pub const PERFORMANCE_SERVICE_RUNTIME_MAX_USEC: u64 = 60_000_000;
const SERVICE_TIMEOUT_USEC: u64 = 5_000_000;
const VALIDATION_WINDOW: Duration = Duration::from_secs(5);
const READY_TIMEOUT: Duration = Duration::from_secs(8);
const EXEC_IDENTITY_SETTLING_TIMEOUT: Duration = Duration::from_secs(2);
const EXEC_IDENTITY_SETTLING_POLL: Duration = Duration::from_millis(20);
const MAX_PREPARED_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_PREPARED_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_SOURCE_OBSERVER_BYTES: u64 = 128 * 1024 * 1024;
const STAGED_BINARY_PREFIX: &str = "nemor-benchmark-observer-bin-";
const STAGED_CONFIG_PREFIX: &str = "nemor-benchmark-observer-config-";
pub const OBSERVER_PROPERTY_CONTRACT_VERSION: u32 = 2;
const PREPARED_MANIFEST_SCHEMA_VERSION: u32 = 3;

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
        signature: "s",
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

const OBSERVER_TRANSIENT_PROPERTIES: [&str; 31] = [
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
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PropertyContractFailureKind {
    PropertyMissing,
    InterfaceMismatch,
    SignatureMismatch,
    ValueContractMismatch,
    UnsupportedRequiredProperty,
}

fn introspected_signature<'a>(xml: &'a str, interface: &str, property: &str) -> Option<&'a str> {
    let marker = format!("<interface name=\"{interface}\">");
    let body = xml.split(&marker).nth(1)?.split("</interface>").next()?;
    let marker = format!("<property name=\"{property}\" type=\"");
    body.split(&marker).nth(1)?.split('"').next()
}

fn verify_readback_contract(xml: &str) -> Result<()> {
    let mut expected_properties = OBSERVER_READBACK_CONTRACT.to_vec();
    for property in OBSERVER_TRANSIENT_PROPERTIES {
        let (interface, signature) = readback_contract(property)?;
        let expected = ObserverReadbackProperty {
            interface,
            property,
            signature,
        };
        if !expected_properties.contains(&expected) {
            expected_properties.push(expected);
        }
    }
    for expected in expected_properties {
        if let Some(observed) = introspected_signature(xml, expected.interface, expected.property) {
            if observed != expected.signature {
                bail!(
                    "property_contract_failure=SIGNATURE_MISMATCH interface={} property={} expected={} observed={}",
                    expected.interface,
                    expected.property,
                    expected.signature,
                    observed
                );
            }
            continue;
        }
        let other_interface = [UNIT_INTERFACE, SERVICE_INTERFACE]
            .into_iter()
            .find(|interface| {
                *interface != expected.interface
                    && introspected_signature(xml, interface, expected.property).is_some()
            });
        if let Some(observed_interface) = other_interface {
            bail!(
                "property_contract_failure=INTERFACE_MISMATCH interface={} property={} observed_interface={}",
                expected.interface,
                expected.property,
                observed_interface
            );
        }
        bail!(
            "property_contract_failure=PROPERTY_MISSING interface={} property={}",
            expected.interface,
            expected.property
        );
    }
    Ok(())
}

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
    pub readback_interface: String,
    pub readback_signature: String,
    pub expected_readback_value: String,
}

fn readback_contract(property: &str) -> Result<(&'static str, &'static str)> {
    Ok(match property {
        "Description" | "CollectMode" => (UNIT_INTERFACE, "s"),
        "Type" => (SERVICE_INTERFACE, "s"),
        "ExecStart" => (SERVICE_INTERFACE, "a(sasbttttuii)"),
        "DynamicUser"
        | "NoNewPrivileges"
        | "PrivateTmp"
        | "PrivateDevices"
        | "ProtectKernelModules"
        | "ProtectKernelTunables"
        | "ProtectControlGroups"
        | "MemoryDenyWriteExecute"
        | "LockPersonality"
        | "RestrictRealtime"
        | "RestrictSUIDSGID" => (SERVICE_INTERFACE, "b"),
        "UMask" | "RuntimeDirectoryMode" => (SERVICE_INTERFACE, "u"),
        "TimeoutStartUSec"
        | "TimeoutStopUSec"
        | "RuntimeMaxUSec"
        | "CapabilityBoundingSet"
        | "AmbientCapabilities" => (SERVICE_INTERFACE, "t"),
        "RuntimeDirectory" | "SystemCallArchitectures" => (SERVICE_INTERFACE, "as"),
        "RuntimeDirectoryPreserve" | "WorkingDirectory" | "ProtectSystem" | "ProtectHome" => {
            (SERVICE_INTERFACE, "s")
        }
        "BindReadOnlyPaths" => (SERVICE_INTERFACE, "a(ssbt)"),
        "RestrictAddressFamilies" => (SERVICE_INTERFACE, "(bas)"),
        "IPAddressDeny" => (SERVICE_INTERFACE, "a(iayu)"),
        _ => bail!("observer transient property lacks a readback contract"),
    })
}

impl ObserverServicePlan {
    pub fn new(run_id: &str, binary: PathBuf, config: PathBuf) -> Result<Self> {
        Self::new_with_runtime(run_id, binary, config, SERVICE_RUNTIME_MAX_USEC)
    }

    pub fn new_with_runtime(
        run_id: &str,
        binary: PathBuf,
        config: PathBuf,
        runtime_max_usec: u64,
    ) -> Result<Self> {
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
            runtime_max_usec,
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
        if self.binary.parent() != Some(Path::new(RUNTIME_BASE))
            || !self
                .binary
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| {
                    name.strip_prefix(STAGED_BINARY_PREFIX)
                        .is_some_and(is_safe_transaction_suffix)
                })
        {
            bail!("observer bind source must be the fixed staged executable role");
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
        if self.runtime_max_usec == 0
            || self.runtime_max_usec > PERFORMANCE_SERVICE_RUNTIME_MAX_USEC
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
                    readback_interface: readback_contract(&property)?.0.into(),
                    readback_signature: readback_contract(&property)?.1.into(),
                    expected_readback_value: self.property_value_description(&property)?,
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
            "ProtectHome" => "yes".into(),
            "RestrictAddressFamilies" => "allow AF_UNIX only".into(),
            "IPAddressDeny" => "IPv4+IPv6 any".into(),
            "SystemCallArchitectures" => "native".into(),
            "NoNewPrivileges"
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
            ("ProtectHome", Value::from("yes")),
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
        PathBuf::from("/run/nemor-benchmark-observer-bin-contract"),
        PathBuf::from("/run/nemor-benchmark-observer-config-contract.toml"),
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
    if !is_safe_transaction_suffix(suffix) {
        bail!("malformed generated observer service name");
    }
    Ok(())
}

fn is_safe_transaction_suffix(suffix: &str) -> bool {
    !suffix.is_empty()
        && suffix.len() <= 32
        && suffix
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
}

fn transaction_suffix(run_id: &str) -> Result<String> {
    let suffix = run_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(32)
        .collect::<String>();
    if !is_safe_transaction_suffix(&suffix) {
        bail!("run id cannot produce a safe staging suffix");
    }
    Ok(suffix)
}

fn staged_observer_path(run_id: &str) -> Result<PathBuf> {
    Ok(Path::new(RUNTIME_BASE).join(format!(
        "{STAGED_BINARY_PREFIX}{}",
        transaction_suffix(run_id)?
    )))
}

fn staged_config_path(run_id: &str) -> Result<PathBuf> {
    Ok(Path::new(RUNTIME_BASE).join(format!(
        "{STAGED_CONFIG_PREFIX}{}.toml",
        transaction_suffix(run_id)?
    )))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedObserverManifest {
    pub schema_version: u32,
    #[serde(default)]
    pub property_contract_version: u32,
    pub run_id: String,
    pub created_uid: u32,
    pub prepared_directory: PathBuf,
    pub repository: PathBuf,
    pub provenance: BuildProvenance,
    pub runner_path: PathBuf,
    pub runner_sha256: String,
    pub source_observer_path: PathBuf,
    pub source_observer_sha256: String,
    pub source_observer_nlink: u64,
    pub observer_embedded_commit: String,
    pub staged_observer_role: String,
    pub expected_staged_observer_path: PathBuf,
    pub expected_staged_observer_sha256: String,
    pub expected_staged_observer_mode: u32,
    pub expected_staged_observer_ownership: String,
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
        if self.payload.schema_version != PREPARED_MANIFEST_SCHEMA_VERSION {
            bail!("unsupported observer preparation manifest schema");
        }
        if self.payload.property_contract_version != OBSERVER_PROPERTY_CONTRACT_VERSION {
            bail!("unsupported observer transient property contract");
        }
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
            let expected = self.payload.plan.property_audit()?;
            for required in expected {
                let Some(observed) = self
                    .payload
                    .transient_property_audit
                    .iter()
                    .find(|entry| entry.property == required.property)
                else {
                    bail!(
                        "property_contract_failure=UNSUPPORTED_REQUIRED_PROPERTY property={}",
                        required.property
                    );
                };
                if observed.signature != required.signature
                    || observed.readback_signature != required.readback_signature
                {
                    bail!(
                        "property_contract_failure=SIGNATURE_MISMATCH property={} expected_request={} observed_request={} expected_readback={} observed_readback={}",
                        required.property,
                        required.signature,
                        observed.signature,
                        required.readback_signature,
                        observed.readback_signature
                    );
                }
                if observed.request_value != required.request_value
                    || observed.expected_readback_value != required.expected_readback_value
                {
                    bail!(
                        "property_contract_failure=VALUE_CONTRACT_MISMATCH property={}",
                        required.property
                    );
                }
                if observed.readback_interface != required.readback_interface {
                    bail!(
                        "property_contract_failure=INTERFACE_MISMATCH property={} expected={} observed={}",
                        required.property,
                        required.readback_interface,
                        observed.readback_interface
                    );
                }
            }
            bail!("observer transient property audit contains unsupported entries");
        }
        let current = std::env::current_exe()?.canonicalize()?;
        if current != self.payload.runner_path.canonicalize()? {
            bail!("privileged runner path differs from prepared runner");
        }
        let source = read_verified_source_observer(
            &self.payload.source_observer_path,
            self.payload.created_uid,
            Some(&self.payload.source_observer_sha256),
        )?;
        if sha256_file(&current)? != self.payload.runner_sha256
            || source.sha256 != self.payload.source_observer_sha256
            || source.metadata.nlink() != self.payload.source_observer_nlink
            || sha256_file(&self.payload.config_path)? != self.payload.config_sha256
        {
            bail!("prepared binary or config changed before privileged execution");
        }
        let release_parent = current
            .parent()
            .context("runner release directory unavailable")?;
        if release_parent.file_name().and_then(|value| value.to_str()) != Some("release")
            || self.payload.source_observer_path.parent() != Some(release_parent)
        {
            bail!("prepared executables are not sibling release binaries");
        }
        if self.payload.observer_embedded_commit != self.payload.provenance.git_head
            || !source
                .bytes
                .windows(self.payload.provenance.git_head.len())
                .any(|window| window == self.payload.provenance.git_head.as_bytes())
        {
            bail!("observer binary embedded commit no longer matches manifest");
        }
        if self.payload.staged_observer_role != "root_staged_transaction_executable"
            || self.payload.expected_staged_observer_path != self.payload.plan.binary
            || self.payload.expected_staged_observer_sha256 != self.payload.source_observer_sha256
            || self.payload.expected_staged_observer_mode != 0o755
            || self.payload.expected_staged_observer_ownership != "root:root"
        {
            bail!("staged observer executable contract differs from manifest plan");
        }
        self.payload.plan.validate()
    }
}

struct VerifiedSourceObserver {
    bytes: Vec<u8>,
    metadata: fs::Metadata,
    sha256: String,
}

fn read_verified_source_observer(
    path: &Path,
    expected_uid: u32,
    expected_sha256: Option<&str>,
) -> Result<VerifiedSourceObserver> {
    if !path.is_absolute() {
        bail!("source observer path must be absolute");
    }
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() {
        bail!("source observer must be a regular non-symlink file");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .context("open source observer with no-follow semantics")?;
    let opened = file.metadata()?;
    validate_source_observer_metadata(&opened, expected_uid)?;
    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        bail!("source observer changed between lstat and no-follow open");
    }
    let capacity = usize::try_from(opened.len()).context("source observer size overflow")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if opened.dev() != after.dev()
        || opened.ino() != after.ino()
        || opened.len() != after.len()
        || opened.mtime() != after.mtime()
        || opened.mtime_nsec() != after.mtime_nsec()
        || opened.ctime() != after.ctime()
        || opened.ctime_nsec() != after.ctime_nsec()
        || bytes.len() as u64 != opened.len()
    {
        bail!("source observer changed while reading verified file descriptor");
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    if expected_sha256.is_some_and(|expected| expected != sha256) {
        bail!("source observer content hash differs from prepared manifest");
    }
    Ok(VerifiedSourceObserver {
        bytes,
        metadata: opened,
        sha256,
    })
}

fn validate_source_observer_metadata(metadata: &fs::Metadata, expected_uid: u32) -> Result<()> {
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_SOURCE_OBSERVER_BYTES
    {
        bail!("source observer ownership, mode, type or size is unsafe");
    }
    Ok(())
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
    let observer_lstat = fs::symlink_metadata(observer_binary)?;
    if observer_lstat.file_type().is_symlink() {
        bail!("source observer path must not be a symlink");
    }
    let observer_path = observer_binary.canonicalize()?;
    let release_parent = runner_path
        .parent()
        .context("runner release directory unavailable")?;
    if release_parent.file_name().and_then(|value| value.to_str()) != Some("release")
        || observer_path.parent() != Some(release_parent)
        || observer_path.file_name().and_then(|value| value.to_str()) != Some("nemord")
    {
        bail!("source observer must be the exact sibling release nemord");
    }
    let source_observer =
        read_verified_source_observer(&observer_path, nix::unistd::getuid().as_raw(), None)?;
    let config_path = destination_dir.join(format!("{run_id}.toml"));
    let staged_observer_path = staged_observer_path(&run_id)?;
    let staged_config_path = staged_config_path(&run_id)?;
    let provisional =
        ObserverServicePlan::new(&run_id, staged_observer_path.clone(), staged_config_path)?;
    write_inspection_config(config_template, &provisional.database, &config_path)?;
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644))?;
    verify_prepared_path(&config_path, nix::unistd::getuid().as_raw())?;
    let loaded = common::LoadedConfig::load(&config_path)?;
    crate::performance::observer_invariant(&loaded.config).validate()?;
    if !source_observer
        .bytes
        .windows(provenance.git_head.len())
        .any(|window| window == provenance.git_head.as_bytes())
    {
        bail!("observer binary does not embed prepared Git commit");
    }
    let payload = PreparedObserverManifest {
        schema_version: PREPARED_MANIFEST_SCHEMA_VERSION,
        property_contract_version: OBSERVER_PROPERTY_CONTRACT_VERSION,
        run_id: run_id.clone(),
        created_uid: nix::unistd::getuid().as_raw(),
        prepared_directory: destination_dir.to_path_buf(),
        repository: repository.canonicalize()?,
        provenance,
        runner_sha256: sha256_file(&runner_path)?,
        source_observer_sha256: source_observer.sha256.clone(),
        source_observer_nlink: source_observer.metadata.nlink(),
        observer_embedded_commit: BUILD_GIT_HEAD.into(),
        staged_observer_role: "root_staged_transaction_executable".into(),
        expected_staged_observer_path: staged_observer_path,
        expected_staged_observer_sha256: source_observer.sha256,
        expected_staged_observer_mode: 0o755,
        expected_staged_observer_ownership: "root:root".into(),
        config_sha256: sha256_file(&config_path)?,
        runner_path,
        source_observer_path: observer_path,
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
    pub protect_home: String,
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
    #[serde(default)]
    pub executable_path: PathBuf,
    pub executable_sha256: String,
}

fn canonicalize_ip_address_deny(entries: &[(i32, Vec<u8>, u32)]) -> Vec<(i32, Vec<u8>, u32)> {
    let mut canonical = entries.to_vec();
    canonical.sort();
    canonical
}

fn describe_ip_address_deny(entries: &[(i32, Vec<u8>, u32)]) -> String {
    let canonical = canonicalize_ip_address_deny(entries);
    let mut description = format!("count={}", canonical.len());
    for (family, address, prefix) in canonical.iter().take(4) {
        description.push_str(&format!(
            " family={family} address_len={} prefix={prefix}",
            address.len()
        ));
    }
    if canonical.len() > 4 {
        description.push_str(" truncated=true");
    }
    description
}

impl ObserverServiceState {
    fn verify_startup_contract(
        &self,
        plan: &ObserverServicePlan,
        initial_pid: u32,
        initial_start_ticks: u64,
        initial_object_path: &str,
        initial_control_group: &str,
    ) -> Result<()> {
        if self.unit_name != plan.unit_name
            || self.load_state != "loaded"
            || self.active_state != "active"
            || self.sub_state != "running"
            || self.main_pid == 0
            || self.main_pid != initial_pid
            || self.start_ticks != initial_start_ticks
            || self.object_path != initial_object_path
            || self.control_group != initial_control_group
            || self.exec_main_pid != self.main_pid
            || self.exec_main_status != 0
            || self.result != "success"
            || !self.dynamic_user
            || self.control_group.is_empty()
            || !self.control_group.starts_with('/')
            || self.control_group.contains("..")
        {
            bail!("observer service changed or failed during identity settling");
        }
        Ok(())
    }

    pub fn verify_declared(&self, plan: &ObserverServicePlan, expected_sha256: &str) -> Result<()> {
        macro_rules! require_declared {
            ($condition:expr, $category:literal, $field:literal, $expected:expr, $observed:expr) => {
                if !$condition {
                    bail!(
                        "DECLARED_CONTRACT_MISMATCH category={} field={} expected={:?} observed={:?}",
                        $category,
                        $field,
                        $expected,
                        $observed
                    );
                }
            };
        }

        require_declared!(
            self.unit_name == plan.unit_name,
            "PROCESS_IDENTITY_MISMATCH",
            "unit_name",
            plan.unit_name,
            self.unit_name
        );
        require_declared!(
            self.load_state == "loaded",
            "SERVICE_RUNTIME_CONTRACT_MISMATCH",
            "LoadState",
            "loaded",
            self.load_state
        );
        require_declared!(
            self.active_state == "active",
            "SERVICE_RUNTIME_CONTRACT_MISMATCH",
            "ActiveState",
            "active",
            self.active_state
        );
        require_declared!(
            self.sub_state == "running",
            "SERVICE_RUNTIME_CONTRACT_MISMATCH",
            "SubState",
            "running",
            self.sub_state
        );
        require_declared!(
            self.main_pid > 0,
            "PROCESS_IDENTITY_MISMATCH",
            "MainPID",
            ">0",
            self.main_pid
        );
        require_declared!(
            self.exec_main_pid == self.main_pid,
            "PROCESS_IDENTITY_MISMATCH",
            "ExecMainPID",
            self.main_pid,
            self.exec_main_pid
        );
        require_declared!(
            self.exec_main_status == 0,
            "SERVICE_RUNTIME_CONTRACT_MISMATCH",
            "ExecMainStatus",
            0,
            self.exec_main_status
        );
        require_declared!(
            self.result == "success",
            "SERVICE_RUNTIME_CONTRACT_MISMATCH",
            "Result",
            "success",
            self.result
        );
        require_declared!(
            self.dynamic_user,
            "SERVICE_HARDENING_MISMATCH",
            "DynamicUser",
            true,
            self.dynamic_user
        );
        require_declared!(
            self.umask == 0o077,
            "SERVICE_HARDENING_MISMATCH",
            "UMask",
            0o077,
            self.umask
        );
        require_declared!(
            self.runtime_directories == [plan.runtime_directory.clone()],
            "SERVICE_RUNTIME_CONTRACT_MISMATCH",
            "RuntimeDirectory",
            vec![plan.runtime_directory.clone()],
            self.runtime_directories
        );
        require_declared!(
            self.runtime_directory_mode == 0o700,
            "SERVICE_RUNTIME_CONTRACT_MISMATCH",
            "RuntimeDirectoryMode",
            0o700,
            self.runtime_directory_mode
        );
        require_declared!(
            self.runtime_directory_preserve == "no",
            "SERVICE_RUNTIME_CONTRACT_MISMATCH",
            "RuntimeDirectoryPreserve",
            "no",
            self.runtime_directory_preserve
        );
        require_declared!(
            self.no_new_privileges,
            "SERVICE_HARDENING_MISMATCH",
            "NoNewPrivileges",
            true,
            self.no_new_privileges
        );
        require_declared!(
            self.capability_bounding_set == 0,
            "SERVICE_HARDENING_MISMATCH",
            "CapabilityBoundingSet",
            0,
            self.capability_bounding_set
        );
        require_declared!(
            self.ambient_capabilities == 0,
            "SERVICE_HARDENING_MISMATCH",
            "AmbientCapabilities",
            0,
            self.ambient_capabilities
        );
        require_declared!(
            self.protect_system == "strict",
            "SERVICE_HARDENING_MISMATCH",
            "ProtectSystem",
            "strict",
            self.protect_system
        );
        require_declared!(
            self.protect_home == "yes",
            "SERVICE_HARDENING_MISMATCH",
            "ProtectHome",
            "yes",
            self.protect_home
        );
        require_declared!(
            self.private_tmp,
            "SERVICE_HARDENING_MISMATCH",
            "PrivateTmp",
            true,
            self.private_tmp
        );
        require_declared!(
            self.private_devices,
            "SERVICE_HARDENING_MISMATCH",
            "PrivateDevices",
            true,
            self.private_devices
        );
        require_declared!(
            self.protect_kernel_tunables,
            "SERVICE_HARDENING_MISMATCH",
            "ProtectKernelTunables",
            true,
            self.protect_kernel_tunables
        );
        require_declared!(
            self.protect_control_groups,
            "SERVICE_HARDENING_MISMATCH",
            "ProtectControlGroups",
            true,
            self.protect_control_groups
        );
        require_declared!(
            self.protect_kernel_modules,
            "SERVICE_HARDENING_MISMATCH",
            "ProtectKernelModules",
            true,
            self.protect_kernel_modules
        );
        require_declared!(
            self.memory_deny_write_execute,
            "SERVICE_HARDENING_MISMATCH",
            "MemoryDenyWriteExecute",
            true,
            self.memory_deny_write_execute
        );
        require_declared!(
            self.lock_personality,
            "SERVICE_HARDENING_MISMATCH",
            "LockPersonality",
            true,
            self.lock_personality
        );
        require_declared!(
            self.restrict_realtime,
            "SERVICE_HARDENING_MISMATCH",
            "RestrictRealtime",
            true,
            self.restrict_realtime
        );
        require_declared!(
            self.restrict_suid_sgid,
            "SERVICE_HARDENING_MISMATCH",
            "RestrictSUIDSGID",
            true,
            self.restrict_suid_sgid
        );
        require_declared!(
            self.restrict_address_families == (true, vec!["AF_UNIX".into()]),
            "SERVICE_HARDENING_MISMATCH",
            "RestrictAddressFamilies",
            (true, vec!["AF_UNIX"]),
            self.restrict_address_families
        );
        require_declared!(
            self.system_call_architectures == ["native"],
            "SERVICE_HARDENING_MISMATCH",
            "SystemCallArchitectures",
            ["native"],
            self.system_call_architectures
        );
        let expected_ip_address_deny = vec![(2, vec![0; 4], 0), (10, vec![0; 16], 0)];
        let observed_ip_address_deny = canonicalize_ip_address_deny(&self.ip_address_deny);
        require_declared!(
            observed_ip_address_deny == canonicalize_ip_address_deny(&expected_ip_address_deny),
            "SERVICE_HARDENING_MISMATCH",
            "IPAddressDeny",
            describe_ip_address_deny(&expected_ip_address_deny),
            describe_ip_address_deny(&self.ip_address_deny)
        );
        require_declared!(
            self.effective_uid != 0,
            "PROCESS_IDENTITY_MISMATCH",
            "effective_uid",
            "non-root",
            self.effective_uid
        );
        require_declared!(
            self.effective_gid != 0,
            "PROCESS_IDENTITY_MISMATCH",
            "effective_gid",
            "non-root",
            self.effective_gid
        );
        require_declared!(
            !self.control_group.is_empty()
                && self.control_group.starts_with('/')
                && !self.control_group.contains(".."),
            "PROCESS_IDENTITY_MISMATCH",
            "ControlGroup",
            "absolute owned cgroup",
            self.control_group
        );
        require_declared!(
            self.executable_sha256 == expected_sha256,
            "PROCESS_IDENTITY_MISMATCH",
            "executable_sha256",
            expected_sha256,
            self.executable_sha256
        );
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
        let proc_exe = PathBuf::from(format!("/proc/{}/exe", self.main_pid));
        let exe = fs::read_link(&proc_exe)?;
        if exe != plan.service_binary {
            bail!("observer /proc/exe path differs from staged service mapping");
        }
        if sha256_file(&proc_exe)? != expected_sha256 {
            bail!("observer /proc/exe differs from approved binary identity");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecIdentitySettlingEvidence {
    pub status: String,
    pub initial_uid: u32,
    pub initial_gid: u32,
    pub final_uid: u32,
    pub final_gid: u32,
    pub polls: u32,
    pub duration_seconds: f64,
    pub pre_exec_root_observed: bool,
    pub initial_executable_path: PathBuf,
    pub initial_executable_sha256: String,
    pub final_executable_sha256: String,
    pub expected_executable_sha256: String,
    pub transition_observed: bool,
}

#[derive(Debug, Clone)]
pub struct ObserverServiceStart {
    pub state: ObserverServiceState,
    pub settling: ExecIdentitySettlingEvidence,
}

/// Runtime handle used by Checkpoint 3A. This deliberately shares the same
/// systemd backend, identity settling, declared-contract verification, and
/// readiness boundary as the privileged 3A-P validator.
pub struct PerformanceObserverHandle {
    pub backend: SystemdObserverServiceBackend,
    pub plan: ObserverServicePlan,
    pub state: ObserverServiceState,
    pub settling: ExecIdentitySettlingEvidence,
    pub staged: StagedObserverInputs,
    pub source_sha256: String,
    pub config_sha256: String,
    pub setup_wall_seconds: f64,
}

pub fn start_performance_observer(
    plan: &ObserverServicePlan,
    source_observer: &Path,
    expected_source_sha256: &str,
    prepared_config: &Path,
    expected_config_sha256: &str,
) -> Result<PerformanceObserverHandle> {
    if !nix::unistd::geteuid().is_root() {
        bail!("performance observer service requires privileged execution");
    }
    let source_uid = fs::symlink_metadata(source_observer)?.uid();
    let source =
        read_verified_source_observer(source_observer, source_uid, Some(expected_source_sha256))?;
    plan.validate()?;
    if plan.runtime_max_usec <= SERVICE_RUNTIME_MAX_USEC
        || plan.runtime_max_usec > PERFORMANCE_SERVICE_RUNTIME_MAX_USEC
    {
        bail!("performance observer RuntimeMax is outside the performance contract");
    }
    let config_bytes = read_verified_prepared_bytes(
        prepared_config,
        fs::symlink_metadata(prepared_config)?.uid(),
        MAX_PREPARED_CONFIG_BYTES,
        expected_config_sha256,
    )?;
    let staged_binary_path = plan.binary.clone();
    let staged_config_path = plan.config.clone();
    let staged = {
        stage_verified_bytes(
            &staged_binary_path,
            &source.bytes,
            0o755,
            0,
            expected_source_sha256,
        )?;
        if let Err(error) = stage_verified_bytes(
            &staged_config_path,
            &config_bytes,
            0o644,
            0,
            expected_config_sha256,
        ) {
            let _ = remove_staged_input(
                &staged_binary_path,
                STAGED_BINARY_PREFIX,
                0,
                0o755,
                expected_source_sha256,
            );
            return Err(error);
        }
        StagedObserverInputs {
            binary: staged_binary_path,
            config: staged_config_path,
        }
    };
    let mut backend = SystemdObserverServiceBackend::system()?;
    backend.preflight()?;
    let setup = Instant::now();
    let started = match backend.start(plan, expected_source_sha256) {
        Ok(started) => started,
        Err(error) => {
            let _ = backend.stop(plan);
            if backend.wait_absent(plan).is_ok() {
                let (binary, config) =
                    staged.cleanup_paths(expected_source_sha256, expected_config_sha256);
                binary.context("performance observer binary cleanup after start failure")?;
                config.context("performance observer config cleanup after start failure")?;
            } else {
                bail!("observer start failed and owned service absence could not be proven: {error:#}");
            }
            return Err(error);
        }
    };
    if let Err(error) = started.state.verify_declared(plan, expected_source_sha256) {
        let _ = backend.stop(plan);
        let _ = backend.wait_absent(plan);
        let _ = staged.cleanup_paths(expected_source_sha256, expected_config_sha256);
        return Err(error);
    }
    if let Err(error) = wait_ready(&plan.database, &backend, plan, &started.state) {
        let _ = backend.stop(plan);
        let _ = backend.wait_absent(plan);
        let _ = staged.cleanup_paths(expected_source_sha256, expected_config_sha256);
        return Err(error);
    }
    Ok(PerformanceObserverHandle {
        backend,
        plan: plan.clone(),
        state: started.state,
        settling: started.settling,
        staged,
        source_sha256: expected_source_sha256.into(),
        config_sha256: expected_config_sha256.into(),
        setup_wall_seconds: setup.elapsed().as_secs_f64(),
    })
}

impl PerformanceObserverHandle {
    pub fn verify_active(&self) -> Result<()> {
        self.backend.verify_active(&self.plan, &self.state)
    }

    pub fn stop_and_cleanup(mut self) -> Result<()> {
        let stop_result = self.backend.stop(&self.plan);
        let absence_result = self.backend.wait_absent(&self.plan);
        stop_result.context("observer StopUnit cleanup")?;
        absence_result.context("observer service absence cleanup")?;
        let (binary, config) = self
            .staged
            .cleanup_paths(&self.source_sha256, &self.config_sha256);
        binary?;
        config?;
        Ok(())
    }
}

pub fn performance_observer_unit_exists(unit_name: &str) -> Result<bool> {
    let backend = SystemdObserverServiceBackend::system()?;
    backend.unit_exists(unit_name)
}

pub trait ObserverServiceBackend {
    fn preflight(&self) -> Result<()>;
    fn unit_exists(&self, unit_name: &str) -> Result<bool>;
    fn start(
        &mut self,
        plan: &ObserverServicePlan,
        expected_sha256: &str,
    ) -> Result<ObserverServiceStart>;
    fn last_start_state(&self) -> Option<ObserverServiceState> {
        None
    }
    fn last_settling_evidence(&self) -> Option<ExecIdentitySettlingEvidence> {
        None
    }
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
    last_start_state: Option<ObserverServiceState>,
    last_settling_evidence: Option<ExecIdentitySettlingEvidence>,
}

impl SystemdObserverServiceBackend {
    pub fn system() -> Result<Self> {
        Ok(Self {
            connection: Connection::system()?,
            last_start_state: None,
            last_settling_evidence: None,
        })
    }

    pub fn systemd_version(&self) -> Result<String> {
        self.manager()?
            .get_property("Version")
            .context("system manager Version property unavailable")
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

    fn read_state(
        &self,
        plan: &ObserverServicePlan,
        hash_unexpected_executable: bool,
    ) -> Result<ObserverServiceState> {
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
        if main_pid == 0 {
            bail!("observer MainPID unavailable");
        }
        let pid_object: OwnedObjectPath = self.manager()?.call("GetUnitByPID", &main_pid)?;
        if pid_object != object {
            bail!("GetUnit and GetUnitByPID disagree for observer MainPID");
        }
        let (uid, gid) = read_effective_ids(main_pid)?;
        let proc_exe = PathBuf::from(format!("/proc/{main_pid}/exe"));
        let executable_path = fs::read_link(&proc_exe)?;
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
            executable_sha256: if hash_unexpected_executable
                || executable_path == plan.service_binary
            {
                sha256_file(&proc_exe)?
            } else {
                String::new()
            },
            executable_path,
        })
    }
}

fn settle_observer_identity<F>(
    plan: &ObserverServicePlan,
    expected_sha256: &str,
    timeout: Duration,
    poll_interval: Duration,
    mut read_state: F,
) -> Result<ObserverServiceStart>
where
    F: FnMut(bool) -> Result<ObserverServiceState>,
{
    let started = Instant::now();
    let initial = read_state(true)?;
    let initial_pid = initial.main_pid;
    let initial_start_ticks = initial.start_ticks;
    let initial_object_path = initial.object_path.clone();
    let initial_control_group = initial.control_group.clone();
    let initial_uid = initial.effective_uid;
    let initial_gid = initial.effective_gid;
    initial.verify_startup_contract(
        plan,
        initial_pid,
        initial_start_ticks,
        &initial_object_path,
        &initial_control_group,
    )?;
    let mut polls = 1_u32;
    let mut pre_exec_root_observed = initial.effective_uid == 0 && initial.effective_gid == 0;
    let initial_executable_path = initial.executable_path.clone();
    let initial_executable_sha256 = initial.executable_sha256.clone();
    let mut current = initial;

    loop {
        current.verify_startup_contract(
            plan,
            initial_pid,
            initial_start_ticks,
            &initial_object_path,
            &initial_control_group,
        )?;
        let expected_executable = current.executable_path == plan.service_binary
            && current.executable_sha256 == expected_sha256;
        let non_root = current.effective_uid != 0 && current.effective_gid != 0;

        if expected_executable && non_root {
            return Ok(ObserverServiceStart {
                settling: ExecIdentitySettlingEvidence {
                    status: "EXEC_IDENTITY_SETTLED".into(),
                    initial_uid,
                    initial_gid,
                    final_uid: current.effective_uid,
                    final_gid: current.effective_gid,
                    polls,
                    duration_seconds: started.elapsed().as_secs_f64(),
                    pre_exec_root_observed,
                    initial_executable_path,
                    initial_executable_sha256,
                    final_executable_sha256: current.executable_sha256.clone(),
                    expected_executable_sha256: expected_sha256.into(),
                    transition_observed: polls > 1,
                },
                state: current,
            });
        }
        if expected_executable && !non_root {
            bail!("observer expected executable appeared with root identity");
        }
        if started.elapsed() >= timeout {
            bail!("observer EXEC_IDENTITY_SETTLING timed out");
        }

        if !poll_interval.is_zero() {
            std::thread::sleep(poll_interval);
        }
        current = read_state(false)?;
        polls = polls
            .checked_add(1)
            .context("observer settling poll count overflow")?;
        pre_exec_root_observed |= current.effective_uid == 0 && current.effective_gid == 0;
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
        verify_readback_contract(&service_xml)
    }

    fn unit_exists(&self, unit_name: &str) -> Result<bool> {
        validate_observer_unit_name(unit_name)?;
        Ok(self
            .manager()?
            .call::<_, _, OwnedObjectPath>("GetUnit", &unit_name)
            .is_ok())
    }

    fn start(
        &mut self,
        plan: &ObserverServicePlan,
        expected_sha256: &str,
    ) -> Result<ObserverServiceStart> {
        self.last_start_state = None;
        self.last_settling_evidence = None;
        if self.unit_exists(&plan.unit_name)? {
            bail!("exact observer service name already exists");
        }
        self.run_job("StartTransientUnit", plan)?;
        let settling_started = Instant::now();
        let mut observations = Vec::new();
        let mut transitioned_hashes: BTreeMap<PathBuf, String> = BTreeMap::new();
        let result = settle_observer_identity(
            plan,
            expected_sha256,
            EXEC_IDENTITY_SETTLING_TIMEOUT,
            EXEC_IDENTITY_SETTLING_POLL,
            |hash_unexpected| {
                let mut state = self.read_state(plan, hash_unexpected)?;
                let transitioned =
                    observations
                        .first()
                        .is_some_and(|initial: &ObserverServiceState| {
                            state.executable_path != initial.executable_path
                        });
                if transitioned && state.executable_sha256.is_empty() {
                    state.executable_sha256 = if let Some(cached) =
                        transitioned_hashes.get(&state.executable_path)
                    {
                        cached.clone()
                    } else {
                        let hash =
                            sha256_file(&PathBuf::from(format!("/proc/{}/exe", state.main_pid)))?;
                        transitioned_hashes.insert(state.executable_path.clone(), hash.clone());
                        hash
                    };
                }
                observations.push(state.clone());
                Ok(state)
            },
        );
        if let Some(final_state) = observations.last() {
            self.last_start_state = Some(final_state.clone());
        }
        match result {
            Ok(started) => {
                self.last_settling_evidence = Some(started.settling.clone());
                Ok(started)
            }
            Err(error) => {
                if let (Some(initial), Some(final_state)) =
                    (observations.first(), observations.last())
                {
                    self.last_settling_evidence = Some(ExecIdentitySettlingEvidence {
                        status: "EXEC_IDENTITY_SETTLING_FAILED".into(),
                        initial_uid: initial.effective_uid,
                        initial_gid: initial.effective_gid,
                        final_uid: final_state.effective_uid,
                        final_gid: final_state.effective_gid,
                        polls: u32::try_from(observations.len()).unwrap_or(u32::MAX),
                        duration_seconds: settling_started.elapsed().as_secs_f64(),
                        pre_exec_root_observed: observations
                            .iter()
                            .any(|state| state.effective_uid == 0 && state.effective_gid == 0),
                        initial_executable_path: initial.executable_path.clone(),
                        initial_executable_sha256: initial.executable_sha256.clone(),
                        final_executable_sha256: final_state.executable_sha256.clone(),
                        expected_executable_sha256: expected_sha256.into(),
                        transition_observed: observations.len() > 1,
                    });
                }
                Err(error)
            }
        }
    }

    fn last_start_state(&self) -> Option<ObserverServiceState> {
        self.last_start_state.clone()
    }

    fn last_settling_evidence(&self) -> Option<ExecIdentitySettlingEvidence> {
        self.last_settling_evidence.clone()
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
        let current = self.read_state(plan, false)?;
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
    pub exec_identity_settling: Option<ExecIdentitySettlingEvidence>,
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
    pub source_observer_artifact_verified: bool,
    pub source_observer_hash_verified: bool,
    pub staged_observer_binary_created: bool,
    pub staged_observer_binary_hash_verified: bool,
    pub staged_observer_binary_single_link: bool,
    pub staged_observer_binary_cleanup: bool,
    pub staged_config_cleanup: bool,
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
            && self.source_observer_artifact_verified
            && self.source_observer_hash_verified
            && self.staged_observer_binary_created
            && self.staged_observer_binary_hash_verified
            && self.staged_observer_binary_single_link
            && self.staged_observer_binary_cleanup
            && self.staged_config_cleanup
            && self.structural_restore_passed
    }
}

pub fn validate_observer_service_with_backend<B: ObserverServiceBackend>(
    manifest: &IntegrityBoundManifest,
    backend: &mut B,
) -> Result<ObserverValidationReport> {
    backend.preflight()?;
    let plan = &manifest.payload.plan;
    let foreign = detect_nemord_processes(&manifest.payload.source_observer_path, None);
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
        exec_identity_settling: None,
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
        source_observer_artifact_verified: true,
        source_observer_hash_verified: true,
        staged_observer_binary_created: true,
        staged_observer_binary_hash_verified: true,
        staged_observer_binary_single_link: true,
        staged_observer_binary_cleanup: false,
        staged_config_cleanup: false,
        errors: Vec::new(),
    };
    let start_result = backend.start(plan, &manifest.payload.expected_staged_observer_sha256);
    match start_result {
        Ok(started) => {
            let state = started.state;
            report.exec_identity_settling = Some(started.settling);
            let identity_result =
                state.verify(plan, &manifest.payload.expected_staged_observer_sha256);
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
        Err(error) => {
            report.state = backend.last_start_state();
            report.exec_identity_settling = backend.last_settling_evidence();
            report.errors.push(error.to_string());
        }
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
    create_durable_audit_report(
        report_path,
        &serde_json::to_vec_pretty(&serde_json::json!({
            "run_id": manifest.payload.run_id,
            "evidence_kind": "harness_validation",
            "performance_claim_eligible": false,
            "audit_complete": true,
            "mutation_started": false,
            "unit_name": manifest.payload.plan.unit_name,
            "source_observer_path": manifest.payload.source_observer_path,
            "source_observer_sha256": manifest.payload.source_observer_sha256,
            "source_observer_nlink": manifest.payload.source_observer_nlink,
            "staged_observer_path": manifest.payload.expected_staged_observer_path,
            "transient_property_audit": manifest.payload.transient_property_audit,
            "manifest_payload_sha256": manifest.payload_sha256,
        }))?,
    )?;
    let staged = stage_root_owned_inputs(&manifest)?;
    let result = (|| {
        let mut backend = SystemdObserverServiceBackend::system()?;
        validate_observer_service_with_backend(&manifest, &mut backend)
    })();
    let (config_cleanup, binary_cleanup) = staged.cleanup(&manifest);
    let mut report = result?;
    match config_cleanup {
        Ok(()) => report.staged_config_cleanup = true,
        Err(error) => report
            .errors
            .push(format!("staged config cleanup failed: {error}")),
    }
    match binary_cleanup {
        Ok(()) => report.staged_observer_binary_cleanup = true,
        Err(error) => report
            .errors
            .push(format!("staged observer cleanup failed: {error}")),
    }
    replace_durable_audit_report(report_path, &serde_json::to_vec_pretty(&report)?)?;
    if !report.passed() {
        bail!(
            "observer service validation failed closed; report preserved at {}",
            report_path.display()
        );
    }
    Ok(report)
}

fn create_durable_audit_report(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut report = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .mode(0o600)
        .open(path)?;
    report.set_permissions(fs::Permissions::from_mode(0o600))?;
    report.write_all(bytes)?;
    report.sync_all()?;
    verify_staged_metadata(&report.metadata()?, 0, 0o600, bytes.len() as u64)
        .context("durable observer audit report metadata")?;
    Ok(())
}

fn replace_durable_audit_report(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut report = OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    let before = report.metadata()?;
    if before.uid() != 0 || before.permissions().mode() & 0o777 != 0o600 || before.nlink() != 1 {
        bail!("refusing unsafe observer audit report replacement");
    }
    report.set_len(0)?;
    report.write_all(bytes)?;
    report.sync_all()?;
    verify_staged_metadata(&report.metadata()?, 0, 0o600, bytes.len() as u64)
        .context("final observer report metadata")?;
    Ok(())
}

pub struct StagedObserverInputs {
    binary: PathBuf,
    config: PathBuf,
}

impl StagedObserverInputs {
    fn cleanup(self, manifest: &IntegrityBoundManifest) -> (Result<()>, Result<()>) {
        let config = remove_staged_input(
            &self.config,
            STAGED_CONFIG_PREFIX,
            0,
            0o644,
            &manifest.payload.config_sha256,
        );
        let binary = remove_staged_input(
            &self.binary,
            STAGED_BINARY_PREFIX,
            0,
            0o755,
            &manifest.payload.expected_staged_observer_sha256,
        );
        (config, binary)
    }
}

impl StagedObserverInputs {
    pub fn cleanup_paths(
        self,
        binary_sha256: &str,
        config_sha256: &str,
    ) -> (Result<()>, Result<()>) {
        let config =
            remove_staged_input(&self.config, STAGED_CONFIG_PREFIX, 0, 0o644, config_sha256);
        let binary =
            remove_staged_input(&self.binary, STAGED_BINARY_PREFIX, 0, 0o755, binary_sha256);
        (config, binary)
    }
}

pub fn stage_root_owned_inputs(manifest: &IntegrityBoundManifest) -> Result<StagedObserverInputs> {
    let source = read_verified_source_observer(
        &manifest.payload.source_observer_path,
        manifest.payload.created_uid,
        Some(&manifest.payload.source_observer_sha256),
    )?;
    if source.metadata.nlink() != manifest.payload.source_observer_nlink {
        bail!("source observer link count changed after preparation");
    }
    let config_bytes = read_verified_prepared_bytes(
        &manifest.payload.config_path,
        manifest.payload.created_uid,
        MAX_PREPARED_CONFIG_BYTES,
        &manifest.payload.config_sha256,
    )?;
    let binary = staged_observer_path(&manifest.payload.run_id)?;
    let config = staged_config_path(&manifest.payload.run_id)?;
    if binary != manifest.payload.expected_staged_observer_path
        || binary != manifest.payload.plan.binary
        || config != manifest.payload.plan.config
    {
        bail!("derived privileged staging paths differ from audited manifest");
    }
    stage_verified_bytes(
        &binary,
        &source.bytes,
        0o755,
        0,
        &manifest.payload.expected_staged_observer_sha256,
    )
    .context("stage root-owned observer executable")?;
    if let Err(error) = stage_verified_bytes(
        &config,
        &config_bytes,
        0o644,
        0,
        &manifest.payload.config_sha256,
    ) {
        let cleanup = remove_staged_input(
            &binary,
            STAGED_BINARY_PREFIX,
            0,
            0o755,
            &manifest.payload.expected_staged_observer_sha256,
        );
        return match cleanup {
            Ok(()) => Err(error).context("stage root-owned observer config"),
            Err(cleanup_error) => Err(error).context(format!(
                "stage root-owned observer config; binary cleanup also failed: {cleanup_error}"
            )),
        };
    }
    Ok(StagedObserverInputs { binary, config })
}

fn read_verified_prepared_bytes(
    path: &Path,
    expected_uid: u32,
    maximum: u64,
    expected_sha256: &str,
) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() {
        bail!("prepared source must be a regular non-symlink file");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    let opened = file.metadata()?;
    if opened.uid() != expected_uid
        || opened.permissions().mode() & 0o022 != 0
        || opened.nlink() != 1
        || opened.len() == 0
        || opened.len() > maximum
        || before.dev() != opened.dev()
        || before.ino() != opened.ino()
    {
        bail!("prepared source metadata differs from safe staging contract");
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len())?);
    file.read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if opened.dev() != after.dev()
        || opened.ino() != after.ino()
        || opened.len() != after.len()
        || opened.mtime() != after.mtime()
        || opened.mtime_nsec() != after.mtime_nsec()
        || bytes.len() as u64 != opened.len()
        || hex::encode(Sha256::digest(&bytes)) != expected_sha256
    {
        bail!("prepared source changed while staging or hash mismatched");
    }
    Ok(bytes)
}

fn stage_verified_bytes(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    expected_uid: u32,
    expected_sha256: &str,
) -> Result<()> {
    stage_verified_bytes_with_fault(
        path,
        bytes,
        mode,
        expected_uid,
        expected_sha256,
        StageFault::None,
    )
}

#[derive(Clone, Copy)]
enum StageFault {
    None,
    #[cfg(test)]
    PartialWrite,
    #[cfg(test)]
    SyncFailure,
}

fn stage_verified_bytes_with_fault(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    expected_uid: u32,
    expected_sha256: &str,
    fault: StageFault,
) -> Result<()> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .mode(mode)
        .open(path)?;
    let staged_result = (|| {
        #[cfg(test)]
        if matches!(fault, StageFault::PartialWrite) {
            output.write_all(&bytes[..bytes.len() / 2])?;
            bail!("simulated partial staged write");
        }
        output.write_all(bytes)?;
        output.set_permissions(fs::Permissions::from_mode(mode))?;
        #[cfg(test)]
        if matches!(fault, StageFault::SyncFailure) {
            bail!("simulated staged sync failure");
        }
        let _ = fault;
        output.sync_all()?;
        let metadata = output.metadata()?;
        verify_staged_metadata(&metadata, expected_uid, mode, bytes.len() as u64)?;
        drop(output);
        if sha256_file(path)? != expected_sha256 {
            bail!("staged transaction input hash mismatch");
        }
        Ok(())
    })();
    if staged_result.is_err() {
        let _ = fs::remove_file(path);
    }
    staged_result
}

fn verify_staged_metadata(
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_mode: u32,
    expected_size: u64,
) -> Result<()> {
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o777 != expected_mode
        || metadata.nlink() != 1
        || metadata.len() != expected_size
    {
        bail!("staged transaction input metadata mismatch");
    }
    Ok(())
}

fn remove_staged_input(
    path: &Path,
    prefix: &str,
    expected_uid: u32,
    expected_mode: u32,
    expected_sha256: &str,
) -> Result<()> {
    if path.parent() != Some(Path::new(RUNTIME_BASE))
        || !path
            .file_name()
            .and_then(|value| value.to_str())
            .and_then(|name| name.strip_prefix(prefix))
            .is_some_and(|suffix| {
                let suffix = suffix.strip_suffix(".toml").unwrap_or(suffix);
                is_safe_transaction_suffix(suffix)
            })
    {
        bail!("refusing unsafe staged input cleanup target");
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o777 != expected_mode
        || metadata.nlink() != 1
        || sha256_file(path)? != expected_sha256
    {
        bail!("refusing ambiguous staged input cleanup");
    }
    fs::remove_file(path)?;
    if path.exists() {
        bail!("staged transaction input remained after cleanup");
    }
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
            PathBuf::from("/run/nemor-benchmark-observer-bin-attempt1"),
            PathBuf::from("/run/nemor-benchmark-observer-config-attempt1.toml"),
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
            protect_home: "yes".into(),
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
            executable_path: plan.service_binary.clone(),
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
        assert_eq!(lookup("ProtectHome"), Some("s"));
        assert_eq!(observer_aux_signature(), "a(sa(sv))");
        let audit = plan.property_audit().unwrap();
        assert_eq!(audit.len(), properties.len());
        assert!(audit.iter().all(|entry| entry.required));
        let protect_home = audit
            .iter()
            .find(|entry| entry.property == "ProtectHome")
            .unwrap();
        assert_eq!(protect_home.signature, "s");
        assert_eq!(protect_home.request_value, "yes");
        assert_eq!(protect_home.readback_interface, SERVICE_INTERFACE);
        assert_eq!(protect_home.readback_signature, "s");
        assert_eq!(protect_home.expected_readback_value, "yes");
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
    fn host_contract_parser_distinguishes_missing_interface_and_signature() {
        let valid = format!(
            r#"<interface name="{SERVICE_INTERFACE}"><property name="ProtectHome" type="s" access="read"/></interface>"#
        );
        assert_eq!(
            introspected_signature(&valid, SERVICE_INTERFACE, "ProtectHome"),
            Some("s")
        );
        let wrong_signature = valid.replace("type=\"s\"", "type=\"b\"");
        let single = [ObserverReadbackProperty {
            interface: SERVICE_INTERFACE,
            property: "ProtectHome",
            signature: "s",
        }];
        let check = |xml: &str| -> Result<()> {
            for expected in single {
                match introspected_signature(xml, expected.interface, expected.property) {
                    Some(observed) if observed == expected.signature => {}
                    Some(observed) => bail!(
                        "property_contract_failure=SIGNATURE_MISMATCH expected={} observed={}",
                        expected.signature,
                        observed
                    ),
                    None if introspected_signature(xml, UNIT_INTERFACE, expected.property)
                        .is_some() =>
                    {
                        bail!("property_contract_failure=INTERFACE_MISMATCH")
                    }
                    None => bail!("property_contract_failure=PROPERTY_MISSING"),
                }
            }
            Ok(())
        };
        assert!(check(&wrong_signature)
            .unwrap_err()
            .to_string()
            .contains("SIGNATURE_MISMATCH"));
        assert!(check(&valid.replace(SERVICE_INTERFACE, UNIT_INTERFACE))
            .unwrap_err()
            .to_string()
            .contains("INTERFACE_MISMATCH"));
        assert!(check("<node/>")
            .unwrap_err()
            .to_string()
            .contains("PROPERTY_MISSING"));
    }

    #[test]
    fn old_property_contract_manifest_is_rejected() {
        let mut manifest = fake_manifest(plan());
        manifest.payload.schema_version = 2;
        manifest.payload.property_contract_version = 1;
        manifest.payload_sha256 = hash_json(&manifest.payload).unwrap();
        assert!(manifest
            .verify(Path::new("/tmp/prepared/manifest.json"))
            .unwrap_err()
            .to_string()
            .contains("unsupported observer preparation manifest schema"));
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
    fn ip_address_deny_readback_is_order_independent_but_exact() {
        let plan = plan();
        let mut reversed = state(&plan);
        reversed.ip_address_deny = vec![(10, vec![0; 16], 0), (2, vec![0; 4], 0)];
        reversed.verify_declared(&plan, "binary").unwrap();

        for observed in [
            vec![(10, vec![0; 16], 0)],
            vec![(2, vec![0; 4], 0)],
            vec![(2, vec![0; 4], 0), (10, vec![0; 16], 0), (2, vec![0; 4], 1)],
            vec![(2, vec![0; 4], 1), (10, vec![0; 16], 0)],
            vec![(2, vec![1, 0, 0, 0], 0), (10, vec![0; 16], 0)],
        ] {
            let mut invalid = state(&plan);
            invalid.ip_address_deny = observed;
            let error = invalid.verify_declared(&plan, "binary").unwrap_err();
            assert!(error.to_string().contains("IPAddressDeny"));
            assert!(error
                .to_string()
                .contains("category=SERVICE_HARDENING_MISMATCH"));
        }
    }

    #[test]
    fn semantic_normalization_does_not_change_exec_start_order() {
        let plan = plan();
        let audit = plan.property_audit().unwrap();
        let exec_start = audit
            .iter()
            .find(|entry| entry.property == "ExecStart")
            .unwrap();
        assert_eq!(
            exec_start.request_value,
            format!(
                "{} --config {}",
                plan.service_binary.display(),
                plan.service_config.display()
            )
        );
        assert_eq!(
            canonicalize_ip_address_deny(&[(2, vec![0; 4], 0), (10, vec![0; 16], 0),]),
            canonicalize_ip_address_deny(&[(10, vec![0; 16], 0), (2, vec![0; 4], 0),])
        );
    }

    #[test]
    fn declared_contract_diagnostics_identify_non_ip_fields() {
        let plan = plan();
        let mut invalid = state(&plan);
        invalid.protect_home = "no".into();
        let error = invalid.verify_declared(&plan, "binary").unwrap_err();
        assert!(error.to_string().contains("field=ProtectHome"));
        assert!(error
            .to_string()
            .contains("category=SERVICE_HARDENING_MISMATCH"));
    }

    #[test]
    fn type_simple_pre_exec_identity_settles_before_readiness() {
        let plan = plan();
        let mut pre_exec = state(&plan);
        pre_exec.effective_uid = 0;
        pre_exec.effective_gid = 0;
        pre_exec.executable_path = PathBuf::from("/usr/lib/systemd/systemd-executor");
        pre_exec.executable_sha256 = "executor".into();
        let settled = state(&plan);
        let mut samples = vec![pre_exec, settled].into_iter();

        let started = settle_observer_identity(
            &plan,
            "binary",
            Duration::from_secs(1),
            Duration::ZERO,
            |_| samples.next().context("missing scripted settling sample"),
        )
        .unwrap();

        assert_eq!(started.state.effective_uid, 61_234);
        assert_eq!(started.settling.status, "EXEC_IDENTITY_SETTLED");
        assert_eq!(started.settling.polls, 2);
        assert!(started.settling.pre_exec_root_observed);
        assert!(started.settling.transition_observed);
        assert_eq!(
            started.settling.initial_executable_path,
            Path::new("/usr/lib/systemd/systemd-executor")
        );
        assert_eq!(started.settling.final_executable_sha256, "binary");
    }

    #[test]
    fn identity_settling_times_out_on_persistent_root_executor() {
        let plan = plan();
        let mut pre_exec = state(&plan);
        pre_exec.effective_uid = 0;
        pre_exec.effective_gid = 0;
        pre_exec.executable_path = PathBuf::from("/usr/lib/systemd/systemd-executor");
        pre_exec.executable_sha256 = "executor".into();
        let error =
            settle_observer_identity(&plan, "binary", Duration::ZERO, Duration::ZERO, |_| {
                Ok(pre_exec.clone())
            })
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }

    #[test]
    fn identity_settling_rejects_bad_transitions_and_never_accepts_executor_hash() {
        let plan = plan();
        let mut initial = state(&plan);
        initial.effective_uid = 0;
        initial.effective_gid = 0;
        initial.executable_path = PathBuf::from("/usr/lib/systemd/systemd-executor");
        initial.executable_sha256 = "executor".into();

        for mutation in 0..6 {
            let mut bad = initial.clone();
            match mutation {
                0 => bad.main_pid += 1,
                1 => bad.start_ticks += 1,
                2 => bad.unit_name = "foreign.service".into(),
                3 => bad.control_group = "/system.slice/foreign.service".into(),
                4 => bad.active_state = "failed".into(),
                5 => bad.main_pid = 0,
                _ => unreachable!(),
            }
            let mut samples = vec![initial.clone(), bad].into_iter();
            assert!(settle_observer_identity(
                &plan,
                "binary",
                Duration::from_secs(1),
                Duration::ZERO,
                |_| samples.next().context("missing scripted settling sample"),
            )
            .is_err());
        }

        let mut executor_as_non_root = initial.clone();
        executor_as_non_root.effective_uid = 61_234;
        executor_as_non_root.effective_gid = 61_234;
        assert!(settle_observer_identity(
            &plan,
            "executor",
            Duration::ZERO,
            Duration::ZERO,
            |_| Ok(executor_as_non_root.clone()),
        )
        .is_err());

        let mut expected_as_root = initial;
        expected_as_root.executable_path = plan.service_binary.clone();
        expected_as_root.executable_sha256 = "binary".into();
        assert!(settle_observer_identity(
            &plan,
            "binary",
            Duration::from_secs(1),
            Duration::ZERO,
            |_| Ok(expected_as_root.clone()),
        )
        .unwrap_err()
        .to_string()
        .contains("root identity"));
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
        assert!(source.contains("read_verified_source_observer("));
        assert!(source.contains("O_NOFOLLOW"));
        assert!(source.contains("source observer content hash differs from prepared manifest"));
        assert!(source.contains("sha256_file(&self.payload.config_path)?"));
        assert!(source.contains("current != self.payload.runner_path.canonicalize()?"));
        assert!(!source.contains("git config"));
    }

    #[test]
    fn source_observer_accepts_one_or_multiple_links_but_rejects_unsafe_metadata() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let source = root.path().join("nemord");
        fs::write(&source, b"approved observer bytes").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();

        let one = read_verified_source_observer(&source, uid, None).unwrap();
        assert_eq!(one.metadata.nlink(), 1);
        let alias = root.path().join("cargo-deps-artifact");
        fs::hard_link(&source, &alias).unwrap();
        let two = read_verified_source_observer(&source, uid, Some(&one.sha256)).unwrap();
        assert_eq!(two.metadata.nlink(), 2);

        fs::set_permissions(&source, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(read_verified_source_observer(&source, uid, None).is_err());
        fs::set_permissions(&source, fs::Permissions::from_mode(0o757)).unwrap();
        assert!(read_verified_source_observer(&source, uid, None).is_err());
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(read_verified_source_observer(&source, uid.saturating_add(1), None).is_err());

        let directory = root.path().join("directory");
        fs::create_dir(&directory).unwrap();
        assert!(read_verified_source_observer(&directory, uid, None).is_err());
        let link = root.path().join("symlink");
        symlink(&source, &link).unwrap();
        assert!(read_verified_source_observer(&link, uid, None).is_err());
    }

    #[test]
    fn source_observer_is_bounded_and_hash_authoritative_across_hardlink_aliases() {
        let root = tempfile::tempdir().unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let source = root.path().join("nemord");
        fs::write(&source, b"first").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        let approved = read_verified_source_observer(&source, uid, None).unwrap();
        assert!(read_verified_source_observer(&source, uid, Some("wrong")).is_err());

        let alias = root.path().join("alternate-hard-link");
        fs::hard_link(&source, &alias).unwrap();
        fs::write(&alias, b"changed through alias").unwrap();
        assert!(read_verified_source_observer(&source, uid, Some(&approved.sha256)).is_err());

        let oversized = root.path().join("oversized");
        let file = fs::File::create(&oversized).unwrap();
        file.set_len(MAX_SOURCE_OBSERVER_BYTES + 1).unwrap();
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(read_verified_source_observer(&oversized, uid, None).is_err());
    }

    #[test]
    fn privileged_staging_creates_single_link_hash_identical_executable() {
        let root = tempfile::tempdir().unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let staged = root.path().join("staged-nemord");
        let bytes = b"byte-identical approved observer";
        let hash = hex::encode(Sha256::digest(bytes));
        stage_verified_bytes(&staged, bytes, 0o755, uid, &hash).unwrap();
        let metadata = fs::symlink_metadata(&staged).unwrap();
        verify_staged_metadata(&metadata, uid, 0o755, bytes.len() as u64).unwrap();
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(sha256_file(&staged).unwrap(), hash);
    }

    #[test]
    fn privileged_staging_rejects_collision_symlink_and_hash_mismatch() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let bytes = b"approved";
        let hash = hex::encode(Sha256::digest(bytes));
        let existing = root.path().join("existing");
        fs::write(&existing, b"foreign").unwrap();
        assert!(stage_verified_bytes(&existing, bytes, 0o755, uid, &hash).is_err());
        assert_eq!(fs::read(&existing).unwrap(), b"foreign");

        let target = root.path().join("target");
        fs::write(&target, b"foreign").unwrap();
        let link = root.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(stage_verified_bytes(&link, bytes, 0o755, uid, &hash).is_err());
        assert!(link.is_symlink());

        let mismatch = root.path().join("mismatch");
        assert!(stage_verified_bytes(&mismatch, bytes, 0o755, uid, "wrong").is_err());
        assert!(!mismatch.exists());
    }

    #[test]
    fn privileged_staging_partial_write_and_sync_failures_remove_partial_file() {
        let root = tempfile::tempdir().unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let bytes = b"approved observer bytes";
        let hash = hex::encode(Sha256::digest(bytes));
        for (name, fault) in [
            ("partial", StageFault::PartialWrite),
            ("sync", StageFault::SyncFailure),
        ] {
            let staged = root.path().join(name);
            assert!(
                stage_verified_bytes_with_fault(&staged, bytes, 0o755, uid, &hash, fault).is_err()
            );
            assert!(!staged.exists());
        }
    }

    #[test]
    fn source_path_inode_replacement_requires_the_prepared_content_hash() {
        let root = tempfile::tempdir().unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let source = root.path().join("nemord");
        fs::write(&source, b"approved").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        let approved = read_verified_source_observer(&source, uid, None).unwrap();
        let replacement = root.path().join("replacement");
        fs::write(&replacement, b"different").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755)).unwrap();
        fs::rename(&replacement, &source).unwrap();
        assert!(read_verified_source_observer(&source, uid, Some(&approved.sha256)).is_err());
    }

    #[test]
    fn staged_metadata_rejects_mode_owner_and_multiple_links() {
        let root = tempfile::tempdir().unwrap();
        let uid = nix::unistd::getuid().as_raw();
        let staged = root.path().join("staged");
        fs::write(&staged, b"binary").unwrap();
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755)).unwrap();
        let metadata = fs::metadata(&staged).unwrap();
        assert!(verify_staged_metadata(&metadata, uid, 0o700, 6).is_err());
        assert!(verify_staged_metadata(&metadata, uid.saturating_add(1), 0o755, 6).is_err());
        let alias = root.path().join("alias");
        fs::hard_link(&staged, alias).unwrap();
        assert!(verify_staged_metadata(&fs::metadata(&staged).unwrap(), uid, 0o755, 6).is_err());
    }

    #[test]
    fn source_hardlinks_never_flow_into_transient_exec_start() {
        let source = PathBuf::from("/home/user/repository/target/release/nemord");
        let plan = plan();
        assert_ne!(plan.binary, source);
        assert_eq!(plan.binary, staged_observer_path("attempt1").unwrap());
        let audit = plan.property_audit().unwrap();
        let binds = audit
            .iter()
            .find(|entry| entry.property == "BindReadOnlyPaths")
            .unwrap();
        assert!(binds.request_value.contains(STAGED_BINARY_PREFIX));
        assert!(!binds.request_value.contains("/home/"));
        let exec = audit
            .iter()
            .find(|entry| entry.property == "ExecStart")
            .unwrap();
        assert!(exec.request_value.starts_with("/run/"));
        assert!(!exec.request_value.contains("target/release"));
    }

    #[test]
    fn staging_verification_precedes_systemd_connection_and_start() {
        let source = include_str!("observer_service.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let execute = source
            .split("pub fn execute_observer_validation")
            .nth(1)
            .unwrap();
        let stage = execute.find("stage_root_owned_inputs(&manifest)").unwrap();
        let system = execute
            .find("SystemdObserverServiceBackend::system()")
            .unwrap();
        let start = execute
            .find("validate_observer_service_with_backend")
            .unwrap();
        assert!(stage < system && system < start);
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

        fn start(
            &mut self,
            _plan: &ObserverServicePlan,
            expected_sha256: &str,
        ) -> Result<ObserverServiceStart> {
            self.start_error.map_or_else(
                || {
                    Ok(ObserverServiceStart {
                        state: self.state.clone(),
                        settling: ExecIdentitySettlingEvidence {
                            status: "EXEC_IDENTITY_SETTLED".into(),
                            initial_uid: self.state.effective_uid,
                            initial_gid: self.state.effective_gid,
                            final_uid: self.state.effective_uid,
                            final_gid: self.state.effective_gid,
                            polls: 1,
                            duration_seconds: 0.0,
                            pre_exec_root_observed: false,
                            initial_executable_path: self.state.executable_path.clone(),
                            initial_executable_sha256: self.state.executable_sha256.clone(),
                            final_executable_sha256: self.state.executable_sha256.clone(),
                            expected_executable_sha256: expected_sha256.into(),
                            transition_observed: false,
                        },
                    })
                },
                |message| bail!("{message}"),
            )
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
            schema_version: PREPARED_MANIFEST_SCHEMA_VERSION,
            property_contract_version: OBSERVER_PROPERTY_CONTRACT_VERSION,
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
            source_observer_path: PathBuf::from("/tmp/target/release/nemord"),
            source_observer_sha256: "binary".into(),
            source_observer_nlink: 2,
            observer_embedded_commit: "a".repeat(40),
            staged_observer_role: "root_staged_transaction_executable".into(),
            expected_staged_observer_path: plan.binary.clone(),
            expected_staged_observer_sha256: "binary".into(),
            expected_staged_observer_mode: 0o755,
            expected_staged_observer_ownership: "root:root".into(),
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
