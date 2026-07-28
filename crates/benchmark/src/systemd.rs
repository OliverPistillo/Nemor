use crate::harness::OwnedProcessIdentity;
use anyhow::{bail, Context, Result};
use futures_lite::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, Type, Value};

const DESTINATION: &str = "org.freedesktop.systemd1";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SCOPE_INTERFACE: &str = "org.freedesktop.systemd1.Scope";
const INTROSPECT_INTERFACE: &str = "org.freedesktop.DBus.Introspectable";
pub const UNIT_PREFIX: &str = "nemor-benchmark-";
const JOB_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadbackPropertySpec {
    pub interface: &'static str,
    pub property: &'static str,
    pub signature: &'static str,
    pub required: bool,
}

pub const READBACK_PROPERTY_CONTRACT: [ReadbackPropertySpec; 12] = [
    ReadbackPropertySpec {
        interface: UNIT_INTERFACE,
        property: "Id",
        signature: "s",
        required: true,
    },
    ReadbackPropertySpec {
        interface: UNIT_INTERFACE,
        property: "LoadState",
        signature: "s",
        required: true,
    },
    ReadbackPropertySpec {
        interface: UNIT_INTERFACE,
        property: "ActiveState",
        signature: "s",
        required: true,
    },
    ReadbackPropertySpec {
        interface: UNIT_INTERFACE,
        property: "SubState",
        signature: "s",
        required: true,
    },
    ReadbackPropertySpec {
        interface: SCOPE_INTERFACE,
        property: "ControlGroup",
        signature: "s",
        required: true,
    },
    ReadbackPropertySpec {
        interface: SCOPE_INTERFACE,
        property: "MemoryMax",
        signature: "t",
        required: true,
    },
    ReadbackPropertySpec {
        interface: SCOPE_INTERFACE,
        property: "MemoryAccounting",
        signature: "b",
        required: true,
    },
    ReadbackPropertySpec {
        interface: SCOPE_INTERFACE,
        property: "IOAccounting",
        signature: "b",
        required: true,
    },
    ReadbackPropertySpec {
        interface: SCOPE_INTERFACE,
        property: "RuntimeMaxUSec",
        signature: "t",
        required: true,
    },
    ReadbackPropertySpec {
        interface: SCOPE_INTERFACE,
        property: "MemoryCurrent",
        signature: "t",
        required: false,
    },
    ReadbackPropertySpec {
        interface: SCOPE_INTERFACE,
        property: "MemoryPeak",
        signature: "t",
        required: false,
    },
    ReadbackPropertySpec {
        interface: SCOPE_INTERFACE,
        property: "CPUUsageNSec",
        signature: "t",
        required: false,
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemdOperationFailure {
    pub stage: String,
    pub dbus_error_name: Option<String>,
    pub error_category: String,
    pub bounded_message: String,
    pub method: String,
    pub interface: Option<String>,
    pub property: Option<String>,
    pub job_path: Option<String>,
    pub job_result: Option<String>,
    pub unit_object_path: Option<String>,
    pub worker_unit_object_path: Option<String>,
    pub unit_absent_after_method_failure: Option<bool>,
    pub mutation_may_have_started: bool,
    pub cleanup_required: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemdStartEvidence {
    pub requested_unit: String,
    pub method_returned_job: bool,
    pub job_path: Option<String>,
    pub job_result: Option<String>,
    pub mutation_may_have_started: bool,
    pub cleanup_required: bool,
    pub unit_object_path: Option<String>,
    pub worker_unit_object_path: Option<String>,
    pub unit_id: Option<String>,
    pub load_state: Option<String>,
    pub active_state: Option<String>,
    pub sub_state: Option<String>,
    pub control_group: Option<String>,
}

impl SystemdStartEvidence {
    pub fn job_done(&self) -> bool {
        self.method_returned_job && self.job_result.as_deref() == Some("done")
    }
}

impl std::fmt::Display for SystemdOperationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: {}",
            self.error_category, self.bounded_message
        )
    }
}

impl std::error::Error for SystemdOperationFailure {}

fn bounded_message(message: impl AsRef<str>) -> String {
    message.as_ref().chars().take(512).collect()
}

fn dbus_error_parts(error: &zbus::Error) -> (Option<String>, String) {
    match error {
        zbus::Error::MethodError(name, detail, _) => (
            Some(name.as_str().to_owned()),
            bounded_message(detail.as_deref().unwrap_or("no details")),
        ),
        _ => (None, bounded_message(error.to_string())),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemdJobOutcome {
    pub job_path: String,
    pub unit_name: String,
    pub result: String,
    pub successful: bool,
}

pub fn require_successful_job(outcome: &SystemdJobOutcome) -> Result<()> {
    if outcome.result != "done" || !outcome.successful {
        bail!(
            "systemd job did not complete successfully: {}",
            outcome.result
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemdCapability {
    pub pid1_systemd: bool,
    pub system_bus_reachable: bool,
    pub manager_available: bool,
    pub start_transient_unit_available: bool,
    pub transient_memory_max_supported: bool,
    pub transient_runtime_max_supported: bool,
    pub transient_property_api_version_supported: bool,
    pub transient_request_encoding_verified: bool,
    pub unit_readback_contract_verified: bool,
    pub scope_readback_contract_verified: bool,
    pub systemd_version: Option<String>,
    pub unified_cgroup_v2: bool,
    pub memory_controller_supported: bool,
    pub supported: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransientScopePlan {
    pub unit_name: String,
    pub description: String,
    pub identity: OwnedProcessIdentity,
    pub memory_max: u64,
    pub runtime_max_usec: u64,
    pub memory_accounting: bool,
    pub cpu_accounting: bool,
    pub io_accounting: bool,
    pub collect_mode: String,
}

impl TransientScopePlan {
    pub fn new(run_id: &str, identity: OwnedProcessIdentity) -> Result<Self> {
        Self::with_limits(
            run_id,
            identity,
            128 * 1024 * 1024,
            15_000_000,
            "Nemor Phase 10 owned cgroup harness validation",
        )
    }

    pub fn with_limits(
        run_id: &str,
        identity: OwnedProcessIdentity,
        memory_max: u64,
        runtime_max_usec: u64,
        description: &str,
    ) -> Result<Self> {
        let suffix: String = run_id
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(32)
            .collect();
        if suffix.is_empty() {
            bail!("run id cannot produce a safe systemd unit name");
        }
        let unit_name = format!("{UNIT_PREFIX}{suffix}.scope");
        validate_unit_name(&unit_name)?;
        Ok(Self {
            unit_name,
            description: description.into(),
            identity,
            memory_max,
            runtime_max_usec,
            memory_accounting: true,
            cpu_accounting: true,
            io_accounting: true,
            collect_mode: "inactive-or-failed".into(),
        })
    }

    pub fn validate(&self) -> Result<()> {
        validate_unit_name(&self.unit_name)?;
        if self.memory_max == 0
            || self.memory_max > 512 * 1024 * 1024
            || self.runtime_max_usec < 15_000_000
            || self.runtime_max_usec > 120_000_000
            || !self.memory_accounting
            || !self.cpu_accounting
            || !self.io_accounting
            || self.collect_mode != "inactive-or-failed"
        {
            bail!("invalid Checkpoint 2 transient scope plan");
        }
        Ok(())
    }

    pub fn encoded_property_signatures(&self) -> Result<Vec<(String, String)>> {
        let properties = self.encoded_properties()?;
        Ok(properties
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.value_signature().to_string()))
            .collect())
    }

    fn encoded_properties(&self) -> Result<Vec<(&'static str, Value<'_>)>> {
        self.validate()?;
        let properties = vec![
            ("Description", Value::from(self.description.as_str())),
            ("PIDs", Value::from(vec![self.identity.pid])),
            ("MemoryAccounting", Value::from(self.memory_accounting)),
            ("CPUAccounting", Value::from(self.cpu_accounting)),
            ("IOAccounting", Value::from(self.io_accounting)),
            ("MemoryMax", Value::from(self.memory_max)),
            ("RuntimeMaxUSec", Value::from(self.runtime_max_usec)),
            ("CollectMode", Value::from(self.collect_mode.as_str())),
        ];
        let names = properties
            .iter()
            .map(|(name, _)| *name)
            .collect::<BTreeSet<_>>();
        if names.len() != properties.len() {
            bail!("duplicate fixed transient property");
        }
        Ok(properties)
    }
}

pub fn transient_aux_signature() -> String {
    type Auxiliary<'a> = Vec<(&'a str, Vec<(&'a str, Value<'a>)>)>;
    <Auxiliary<'_> as Type>::SIGNATURE.to_string()
}

fn fixed_encoding_is_valid() -> bool {
    let plan = TransientScopePlan::new(
        "capabilityencoding",
        OwnedProcessIdentity {
            run_id: "capabilityencoding".into(),
            pid: std::process::id(),
            start_ticks: 0,
        },
    );
    plan.and_then(|plan| plan.encoded_property_signatures())
        .is_ok_and(|properties| {
            properties
                == [
                    ("Description", "s"),
                    ("PIDs", "au"),
                    ("MemoryAccounting", "b"),
                    ("CPUAccounting", "b"),
                    ("IOAccounting", "b"),
                    ("MemoryMax", "t"),
                    ("RuntimeMaxUSec", "t"),
                    ("CollectMode", "s"),
                ]
                .into_iter()
                .map(|(name, signature)| (name.into(), signature.into()))
                .collect::<Vec<_>>()
                && transient_aux_signature() == "a(sa(sv))"
        })
}

pub fn interface_contract_matches(xml: &str, interface: &str) -> bool {
    let marker = format!("<interface name=\"{interface}\">");
    let Some(start) = xml.find(&marker) else {
        return false;
    };
    let body = &xml[start..];
    let Some(end) = body.find("</interface>") else {
        return false;
    };
    let body = &body[..end];
    READBACK_PROPERTY_CONTRACT
        .iter()
        .filter(|spec| spec.interface == interface && spec.required)
        .all(|spec| {
            body.contains(&format!(
                "<property name=\"{}\" type=\"{}\"",
                spec.property, spec.signature
            ))
        })
}

pub fn validate_unit_name(name: &str) -> Result<()> {
    let suffix = name
        .strip_prefix(UNIT_PREFIX)
        .and_then(|value| value.strip_suffix(".scope"))
        .context("unit is outside the Nemor benchmark scope prefix")?;
    if suffix.is_empty()
        || suffix.len() > 32
        || !suffix
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        bail!("malformed generated transient scope name");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeState {
    pub unit_name: String,
    pub object_path: String,
    pub control_group: String,
    pub memory_max: u64,
    pub memory_accounting: bool,
    pub cpu_accounting: bool,
    pub io_accounting: bool,
    pub runtime_max_usec: u64,
    pub active_state: String,
    pub sub_state: String,
    pub members: BTreeSet<u32>,
}

impl ScopeState {
    pub fn kernel_path(&self) -> Result<PathBuf> {
        if !self.control_group.starts_with('/')
            || self.control_group.contains("..")
            || self.control_group.contains('\0')
        {
            bail!("systemd returned an invalid ControlGroup");
        }
        Ok(Path::new("/sys/fs/cgroup").join(self.control_group.trim_start_matches('/')))
    }

    pub fn verify(&self, plan: &TransientScopePlan) -> Result<()> {
        if self.unit_name != plan.unit_name {
            bail!("systemd unit identity mismatch");
        }
        if self.control_group.is_empty() {
            bail!("systemd ControlGroup is unavailable");
        }
        if self.memory_max != plan.memory_max
            || !self.memory_accounting
            || !self.cpu_accounting
            || !self.io_accounting
            || self.runtime_max_usec != plan.runtime_max_usec
        {
            bail!("systemd scope resource property mismatch");
        }
        if self.active_state != "active" || self.sub_state != "running" {
            bail!("systemd transient scope is not active/running");
        }
        if self.members != BTreeSet::from([plan.identity.pid]) {
            bail!("systemd scope membership is not exclusive");
        }
        plan.identity.verify()?;
        let process_cgroup = fs::read_to_string(format!("/proc/{}/cgroup", plan.identity.pid))?;
        if !process_cgroup
            .lines()
            .any(|line| line.strip_prefix("0::") == Some(self.control_group.as_str()))
        {
            bail!("owned worker is not in systemd ControlGroup");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOwnership {
    ExactOwned,
    Absent,
    Ambiguous,
}

pub trait TransientScopeBackend {
    fn capability(&self) -> Result<SystemdCapability>;
    fn unit_exists(&self, unit_name: &str) -> Result<bool>;
    fn list_owned_units(&self) -> Result<Vec<String>>;
    fn start_owned_scope(&mut self, plan: &TransientScopePlan) -> Result<ScopeState>;
    fn start_evidence(&self) -> Option<SystemdStartEvidence>;
    fn read_scope_state(&self, unit_name: &str) -> Result<Option<ScopeState>>;
    fn stop_owned_scope(&mut self, plan: &TransientScopePlan) -> Result<()>;
    fn wait_inactive_or_removed(&self, unit_name: &str, timeout: std::time::Duration)
        -> Result<()>;
    fn recover_owned_scope(
        &mut self,
        plan: &TransientScopePlan,
        ownership: RecoveryOwnership,
    ) -> Result<()>;
}

pub struct SystemdDbusBackend {
    connection: Connection,
    last_start_evidence: Option<SystemdStartEvidence>,
}

impl SystemdDbusBackend {
    pub fn system() -> Result<Self> {
        Ok(Self {
            connection: Connection::system().context("connect system D-Bus")?,
            last_start_evidence: None,
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

    fn unit_path(&self, unit_name: &str) -> Result<OwnedObjectPath> {
        validate_unit_name(unit_name)?;
        Ok(self.manager()?.call("GetUnit", &(unit_name))?)
    }

    fn unit_path_by_pid(&self, pid: u32) -> Result<OwnedObjectPath> {
        Ok(self.manager()?.call("GetUnitByPID", &(pid))?)
    }

    fn readback_contract(&self) -> Result<(bool, bool)> {
        let object: OwnedObjectPath = self.manager()?.call("GetUnit", &("init.scope"))?;
        let introspect = Proxy::new(
            &self.connection,
            DESTINATION,
            object.as_str(),
            INTROSPECT_INTERFACE,
        )?;
        let xml: String = introspect.call("Introspect", &())?;
        Ok((
            interface_contract_matches(&xml, UNIT_INTERFACE),
            interface_contract_matches(&xml, SCOPE_INTERFACE),
        ))
    }

    fn read_state_at(&self, unit_name: &str, object_path: &str) -> Result<ScopeState> {
        let unit = Proxy::new(&self.connection, DESTINATION, object_path, UNIT_INTERFACE)?;
        let scope = Proxy::new(&self.connection, DESTINATION, object_path, SCOPE_INTERFACE)?;
        let memory_max = scope.get_property("MemoryMax").context("Scope.MemoryMax")?;
        let memory_accounting = scope
            .get_property("MemoryAccounting")
            .context("Scope.MemoryAccounting")?;
        let io_accounting = scope
            .get_property("IOAccounting")
            .context("Scope.IOAccounting")?;
        let runtime_max_usec = scope
            .get_property("RuntimeMaxUSec")
            .context("Scope.RuntimeMaxUSec")?;
        let control_group: String = scope
            .get_property("ControlGroup")
            .context("Scope.ControlGroup")?;
        let kernel_path = Path::new("/sys/fs/cgroup").join(control_group.trim_start_matches('/'));
        let members = read_members(&kernel_path.join("cgroup.procs"))?;
        Ok(ScopeState {
            unit_name: unit_name.into(),
            object_path: object_path.into(),
            control_group,
            memory_max,
            memory_accounting,
            // systemd >=258 deprecated/removed the CPUAccounting D-Bus
            // property because CPU accounting is always available on unified
            // cgroup v2. Verify the effective kernel interface instead.
            cpu_accounting: kernel_path.join("cpu.stat").is_file(),
            io_accounting,
            runtime_max_usec,
            active_state: unit.get_property("ActiveState")?,
            sub_state: unit.get_property("SubState")?,
            members,
        })
    }

    fn run_job(
        &self,
        method: &'static str,
        plan: &TransientScopePlan,
    ) -> Result<SystemdJobOutcome> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        runtime.block_on(async {
            let connection = zbus::Connection::system()
                .await
                .context("connect system D-Bus for job tracking")?;
            let manager =
                zbus::Proxy::new(&connection, DESTINATION, MANAGER_PATH, MANAGER_INTERFACE).await?;
            // systemd emits Manager job signals only to clients that called
            // Subscribe().  Do this before installing the match and before the
            // method so an immediately completed job cannot race observation.
            manager
                .call::<_, _, ()>("Subscribe", &())
                .await
                .context("subscribe to systemd manager job signals")?;
            let mut removed = manager
                .receive_signal_with_args("JobRemoved", &[(2, plan.unit_name.as_str())])
                .await?;
            let job_path: OwnedObjectPath = if method == "StartTransientUnit" {
                let properties = plan.encoded_properties()?;
                let auxiliary: Vec<(&str, Vec<(&str, Value<'_>)>)> = Vec::new();
                let reply: zbus::Result<OwnedObjectPath> = manager
                    .call(
                        "StartTransientUnit",
                        &(plan.unit_name.as_str(), "fail", properties, auxiliary),
                    )
                    .await;
                match reply {
                    Ok(path) => path,
                    Err(error) => {
                        let (name, message) = dbus_error_parts(&error);
                        let absent = self.unit_exists(&plan.unit_name).ok().map(|exists| !exists);
                        return Err(SystemdOperationFailure {
                            stage: "start_transient_unit_method".into(),
                            dbus_error_name: name,
                            error_category: "start_transient_method_failed".into(),
                            bounded_message: message,
                            method: "StartTransientUnit".into(),
                            interface: Some(MANAGER_INTERFACE.into()),
                            property: None,
                            job_path: None,
                            job_result: None,
                            unit_object_path: None,
                            worker_unit_object_path: None,
                            unit_absent_after_method_failure: absent,
                            mutation_may_have_started: absent != Some(true),
                            cleanup_required: absent != Some(true),
                        }
                        .into());
                    }
                }
            } else if method == "StopUnit" {
                manager
                    .call("StopUnit", &(plan.unit_name.as_str(), "fail"))
                    .await?
            } else {
                bail!("unsupported fixed systemd job method");
            };
            let expected_path = job_path.to_string();
            let outcome = tokio::time::timeout(JOB_TIMEOUT, async {
                while let Some(message) = removed.next().await {
                    let (_id, removed_path, unit_name, result): (
                        u32,
                        OwnedObjectPath,
                        String,
                        String,
                    ) = message.body().deserialize()?;
                    if removed_path.as_str() == expected_path && unit_name == plan.unit_name {
                        return Ok::<_, anyhow::Error>(SystemdJobOutcome {
                            job_path: expected_path.clone(),
                            unit_name,
                            successful: result == "done",
                            result,
                        });
                    }
                }
                Err(anyhow::Error::new(SystemdOperationFailure {
                    stage: format!("{}_job", method.to_ascii_lowercase()),
                    dbus_error_name: None,
                    error_category: "systemd_connection_lost".into(),
                    bounded_message: "system D-Bus disconnected while job was pending".into(),
                    method: method.into(),
                    interface: Some(MANAGER_INTERFACE.into()),
                    property: None,
                    job_path: Some(expected_path.clone()),
                    job_result: None,
                    unit_object_path: None,
                    worker_unit_object_path: None,
                    unit_absent_after_method_failure: None,
                    mutation_may_have_started: true,
                    cleanup_required: true,
                }))
            })
            .await
            .map_err(|_| {
                anyhow::Error::new(SystemdOperationFailure {
                    stage: format!("{}_job", method.to_ascii_lowercase()),
                    dbus_error_name: None,
                    error_category: if method == "StartTransientUnit" {
                        "start_job_timeout"
                    } else {
                        "stop_job_timeout"
                    }
                    .into(),
                    bounded_message: "systemd job completion signal timed out".into(),
                    method: method.into(),
                    interface: Some(MANAGER_INTERFACE.into()),
                    property: None,
                    job_path: Some(expected_path.clone()),
                    job_result: None,
                    unit_object_path: None,
                    worker_unit_object_path: None,
                    unit_absent_after_method_failure: None,
                    mutation_may_have_started: true,
                    cleanup_required: true,
                })
            })??;
            if let Err(error) = require_successful_job(&outcome) {
                return Err(SystemdOperationFailure {
                    stage: format!("{}_job", method.to_ascii_lowercase()),
                    dbus_error_name: None,
                    error_category: match (method, outcome.result.as_str()) {
                        ("StartTransientUnit", "canceled") => "start_job_cancelled",
                        ("StartTransientUnit", _) => "start_job_failed",
                        ("StopUnit", "canceled") => "stop_job_cancelled",
                        ("StopUnit", _) => "stop_job_failed",
                        _ => "systemd_job_failed",
                    }
                    .into(),
                    bounded_message: bounded_message(error.to_string()),
                    method: method.into(),
                    interface: Some(MANAGER_INTERFACE.into()),
                    property: None,
                    job_path: Some(outcome.job_path.clone()),
                    job_result: Some(outcome.result.clone()),
                    unit_object_path: None,
                    worker_unit_object_path: None,
                    unit_absent_after_method_failure: None,
                    mutation_may_have_started: true,
                    cleanup_required: true,
                }
                .into());
            }
            Ok(outcome)
        })
    }
}

impl TransientScopeBackend for SystemdDbusBackend {
    fn capability(&self) -> Result<SystemdCapability> {
        let manager = self.manager()?;
        let version: String = manager.get_property("Version")?;
        let introspection: String = Proxy::new(
            &self.connection,
            DESTINATION,
            MANAGER_PATH,
            "org.freedesktop.DBus.Introspectable",
        )?
        .call("Introspect", &())?;
        let pid1_systemd =
            fs::read_to_string("/proc/1/comm").is_ok_and(|value| value.trim() == "systemd");
        let unified = Path::new("/sys/fs/cgroup/cgroup.controllers").is_file();
        let memory = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
            .is_ok_and(|value| value.split_whitespace().any(|item| item == "memory"));
        let start = introspection.contains("StartTransientUnit");
        let version_number = version
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse::<u32>()
            .ok();
        let memory_max_supported = version_number.is_some_and(|value| value >= 227);
        let runtime_max_supported = version_number.is_some_and(|value| value >= 229);
        let request_encoding_verified = fixed_encoding_is_valid();
        let (unit_readback_verified, scope_readback_verified) =
            self.readback_contract().unwrap_or((false, false));
        let supported = pid1_systemd
            && unified
            && memory
            && start
            && memory_max_supported
            && runtime_max_supported
            && request_encoding_verified
            && unit_readback_verified
            && scope_readback_verified;
        Ok(SystemdCapability {
            pid1_systemd,
            system_bus_reachable: true,
            manager_available: true,
            start_transient_unit_available: start,
            transient_memory_max_supported: memory_max_supported,
            transient_runtime_max_supported: runtime_max_supported,
            transient_property_api_version_supported: memory_max_supported && runtime_max_supported,
            transient_request_encoding_verified: request_encoding_verified,
            unit_readback_contract_verified: unit_readback_verified,
            scope_readback_contract_verified: scope_readback_verified,
            systemd_version: Some(version),
            unified_cgroup_v2: unified,
            memory_controller_supported: memory,
            supported,
            reason: if supported {
                "systemd_transient_scope_supported".into()
            } else {
                "required_systemd_or_cgroup_capability_missing".into()
            },
        })
    }

    fn unit_exists(&self, unit_name: &str) -> Result<bool> {
        match self.unit_path(unit_name) {
            Ok(_) => Ok(true),
            Err(error)
                if error.to_string().contains("NoSuchUnit")
                    || error.to_string().contains("not loaded") =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn list_owned_units(&self) -> Result<Vec<String>> {
        type UnitRow = (
            String,
            String,
            String,
            String,
            String,
            String,
            OwnedObjectPath,
            u32,
            String,
            OwnedObjectPath,
        );
        let rows: Vec<UnitRow> = self.manager()?.call("ListUnits", &())?;
        Ok(rows
            .into_iter()
            .map(|row| row.0)
            .filter(|name| name.starts_with(UNIT_PREFIX) && name.ends_with(".scope"))
            .collect())
    }

    fn start_owned_scope(&mut self, plan: &TransientScopePlan) -> Result<ScopeState> {
        plan.validate()?;
        self.last_start_evidence = Some(SystemdStartEvidence {
            requested_unit: plan.unit_name.clone(),
            ..Default::default()
        });
        if self.unit_exists(&plan.unit_name)? {
            bail!("transient unit name collision");
        }
        let completed_job = match self.run_job("StartTransientUnit", plan) {
            Ok(job) => job,
            Err(error) => {
                if let Some(failure) = error.downcast_ref::<SystemdOperationFailure>() {
                    if let Some(evidence) = self.last_start_evidence.as_mut() {
                        evidence.method_returned_job = failure.job_path.is_some();
                        evidence.job_path = failure.job_path.clone();
                        evidence.job_result = failure.job_result.clone();
                        evidence.mutation_may_have_started = failure.mutation_may_have_started;
                        evidence.cleanup_required = failure.cleanup_required;
                    }
                }
                return Err(error);
            }
        };
        if let Some(evidence) = self.last_start_evidence.as_mut() {
            evidence.method_returned_job = true;
            evidence.job_path = Some(completed_job.job_path);
            evidence.job_result = Some(completed_job.result);
            evidence.mutation_may_have_started = true;
            evidence.cleanup_required = true;
        }
        // Unit and worker reconciliation happens only after JobRemoved(done).
        let started = std::time::Instant::now();
        let mut last_failure = SystemdOperationFailure {
            stage: "get_unit".into(),
            dbus_error_name: None,
            error_category: "unit_lookup_failed".into(),
            bounded_message: "unit reconciliation did not start".into(),
            method: "GetUnit".into(),
            interface: Some(MANAGER_INTERFACE.into()),
            property: None,
            job_path: self
                .last_start_evidence
                .as_ref()
                .and_then(|evidence| evidence.job_path.clone()),
            job_result: Some("done".into()),
            unit_object_path: None,
            worker_unit_object_path: None,
            unit_absent_after_method_failure: None,
            mutation_may_have_started: true,
            cleanup_required: true,
        };
        while started.elapsed() < std::time::Duration::from_secs(2) {
            if let Err(error) = plan.identity.verify() {
                last_failure.stage = "unit_identity".into();
                last_failure.method = "proc_pid_stat".into();
                last_failure.error_category = "worker_identity_stale".into();
                last_failure.bounded_message = bounded_message(error.to_string());
                break;
            }
            let object = match self.unit_path(&plan.unit_name) {
                Ok(object) => object,
                Err(error) => {
                    let (name, message) = error
                        .downcast_ref::<zbus::Error>()
                        .map(dbus_error_parts)
                        .unwrap_or((None, bounded_message(error.to_string())));
                    last_failure.stage = "get_unit".into();
                    last_failure.method = "GetUnit".into();
                    last_failure.dbus_error_name = name;
                    last_failure.error_category = "unit_lookup_failed".into();
                    last_failure.bounded_message = message;
                    std::thread::sleep(std::time::Duration::from_millis(25));
                    continue;
                }
            };
            if let Some(evidence) = self.last_start_evidence.as_mut() {
                evidence.unit_object_path = Some(object.to_string());
            }
            let worker_object = match self.unit_path_by_pid(plan.identity.pid) {
                Ok(object) => object,
                Err(error) => {
                    let (name, message) = error
                        .downcast_ref::<zbus::Error>()
                        .map(dbus_error_parts)
                        .unwrap_or((None, bounded_message(error.to_string())));
                    last_failure.stage = "get_unit_by_pid".into();
                    last_failure.method = "GetUnitByPID".into();
                    last_failure.dbus_error_name = name;
                    last_failure.error_category = "worker_unit_lookup_failed".into();
                    last_failure.bounded_message = message;
                    last_failure.unit_object_path = Some(object.to_string());
                    std::thread::sleep(std::time::Duration::from_millis(25));
                    continue;
                }
            };
            if let Some(evidence) = self.last_start_evidence.as_mut() {
                evidence.worker_unit_object_path = Some(worker_object.to_string());
            }
            if object != worker_object {
                last_failure.stage = "unit_identity".into();
                last_failure.method = "GetUnit/GetUnitByPID".into();
                last_failure.error_category = "unit_identity_mismatch".into();
                last_failure.bounded_message =
                    "GetUnit and GetUnitByPID returned different objects".into();
                last_failure.unit_object_path = Some(object.to_string());
                last_failure.worker_unit_object_path = Some(worker_object.to_string());
                break;
            }
            let unit = Proxy::new(
                &self.connection,
                DESTINATION,
                object.as_str(),
                UNIT_INTERFACE,
            )?;
            let id: String = match unit.get_property("Id") {
                Ok(id) => id,
                Err(error) => {
                    let (name, message) = dbus_error_parts(&error);
                    last_failure.stage = "unit_identity".into();
                    last_failure.method = "Properties.Get(Unit.Id)".into();
                    last_failure.dbus_error_name = name;
                    last_failure.error_category = "unit_id_read_failed".into();
                    last_failure.bounded_message = message;
                    continue;
                }
            };
            if id != plan.unit_name {
                last_failure.stage = "unit_identity".into();
                last_failure.method = "Properties.Get(Unit.Id)".into();
                last_failure.error_category = "unit_identity_mismatch".into();
                last_failure.bounded_message = "systemd Unit.Id mismatch".into();
                break;
            }
            if let Some(evidence) = self.last_start_evidence.as_mut() {
                evidence.unit_id = Some(id);
            }
            let load_state: String = match unit.get_property("LoadState") {
                Ok(value) => value,
                Err(error) => {
                    let (name, message) = dbus_error_parts(&error);
                    last_failure.stage = "unit_identity".into();
                    last_failure.method = "Properties.Get".into();
                    last_failure.interface = Some(UNIT_INTERFACE.into());
                    last_failure.property = Some("LoadState".into());
                    last_failure.dbus_error_name = name;
                    last_failure.error_category = "unit_property_read_failed".into();
                    last_failure.bounded_message = message;
                    break;
                }
            };
            let active_state: String = match unit.get_property("ActiveState") {
                Ok(value) => value,
                Err(error) => {
                    let (name, message) = dbus_error_parts(&error);
                    last_failure.stage = "active_state".into();
                    last_failure.method = "Properties.Get".into();
                    last_failure.interface = Some(UNIT_INTERFACE.into());
                    last_failure.property = Some("ActiveState".into());
                    last_failure.dbus_error_name = name;
                    last_failure.error_category = "unit_property_read_failed".into();
                    last_failure.bounded_message = message;
                    break;
                }
            };
            let sub_state: String = match unit.get_property("SubState") {
                Ok(value) => value,
                Err(error) => {
                    let (name, message) = dbus_error_parts(&error);
                    last_failure.stage = "active_state".into();
                    last_failure.method = "Properties.Get".into();
                    last_failure.interface = Some(UNIT_INTERFACE.into());
                    last_failure.property = Some("SubState".into());
                    last_failure.dbus_error_name = name;
                    last_failure.error_category = "unit_property_read_failed".into();
                    last_failure.bounded_message = message;
                    break;
                }
            };
            if load_state != "loaded" || active_state != "active" || sub_state != "running" {
                last_failure.stage = "active_state".into();
                last_failure.method = "Unit lifecycle verification".into();
                last_failure.interface = Some(UNIT_INTERFACE.into());
                last_failure.property = None;
                last_failure.error_category = "unit_state_invalid".into();
                last_failure.bounded_message = format!("{load_state}/{active_state}/{sub_state}");
                break;
            }
            if let Some(evidence) = self.last_start_evidence.as_mut() {
                evidence.load_state = Some(load_state);
                evidence.active_state = Some(active_state);
                evidence.sub_state = Some(sub_state);
            }
            match self.read_state_at(&plan.unit_name, object.as_str()) {
                Ok(state) => {
                    if let Some(evidence) = self.last_start_evidence.as_mut() {
                        evidence.active_state = Some(state.active_state.clone());
                        evidence.sub_state = Some(state.sub_state.clone());
                        evidence.control_group = Some(state.control_group.clone());
                        evidence.cleanup_required = true;
                    }
                    return Ok(state);
                }
                Err(error) => {
                    let rendered = error.to_string();
                    let (name, message) = error
                        .downcast_ref::<zbus::Error>()
                        .map(dbus_error_parts)
                        .unwrap_or((None, bounded_message(&rendered)));
                    let property = [
                        "MemoryMax",
                        "MemoryAccounting",
                        "IOAccounting",
                        "RuntimeMaxUSec",
                        "ControlGroup",
                    ]
                    .into_iter()
                    .find(|property| rendered.contains(property));
                    last_failure.stage = if property == Some("ControlGroup") {
                        "control_group"
                    } else {
                        "resource_property"
                    }
                    .into();
                    last_failure.method = if property.is_some() {
                        "Properties.Get"
                    } else {
                        "read_cgroup_members"
                    }
                    .into();
                    last_failure.interface = Some(SCOPE_INTERFACE.into());
                    last_failure.property = property.map(str::to_owned);
                    last_failure.dbus_error_name = name;
                    last_failure.error_category = if property == Some("ControlGroup") {
                        "control_group_read_failed"
                    } else {
                        "scope_property_read_failed"
                    }
                    .into();
                    last_failure.bounded_message = message;
                    last_failure.unit_object_path = Some(object.to_string());
                    last_failure.worker_unit_object_path = Some(worker_object.to_string());
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        Err(last_failure.into())
    }

    fn start_evidence(&self) -> Option<SystemdStartEvidence> {
        self.last_start_evidence.clone()
    }

    fn read_scope_state(&self, unit_name: &str) -> Result<Option<ScopeState>> {
        let object = match self.unit_path(unit_name) {
            Ok(path) => path,
            Err(error)
                if error.to_string().contains("NoSuchUnit")
                    || error.to_string().contains("not loaded") =>
            {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        Ok(Some(self.read_state_at(unit_name, object.as_str())?))
    }

    fn stop_owned_scope(&mut self, plan: &TransientScopePlan) -> Result<()> {
        plan.validate()?;
        let _completed_job = self.run_job("StopUnit", plan)?;
        Ok(())
    }

    fn wait_inactive_or_removed(
        &self,
        unit_name: &str,
        timeout: std::time::Duration,
    ) -> Result<()> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            match self.read_scope_state(unit_name)? {
                None => return Ok(()),
                Some(state)
                    if state.active_state == "inactive" || state.active_state == "failed" =>
                {
                    return Ok(())
                }
                Some(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
        bail!("timed out waiting for transient scope cleanup")
    }

    fn recover_owned_scope(
        &mut self,
        plan: &TransientScopePlan,
        ownership: RecoveryOwnership,
    ) -> Result<()> {
        match ownership {
            RecoveryOwnership::Absent => Ok(()),
            RecoveryOwnership::ExactOwned => {
                self.stop_owned_scope(plan)?;
                self.wait_inactive_or_removed(&plan.unit_name, std::time::Duration::from_secs(3))
            }
            RecoveryOwnership::Ambiguous => bail!("ambiguous transient scope is never stopped"),
        }
    }
}

fn read_members(path: &Path) -> Result<BTreeSet<u32>> {
    Ok(fs::read_to_string(path)?
        .lines()
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?)
}

#[cfg(test)]
#[derive(Debug, Default)]
pub struct SimulatedSystemdBackend {
    pub available: bool,
    pub collision: bool,
    pub disconnect: bool,
    pub disconnect_while_start_pending: bool,
    pub scope: Option<ScopeState>,
    pub starts: usize,
    pub stops: usize,
    pub start_job_result: Option<String>,
    pub stop_job_result: Option<String>,
    pub start_job_timeout: bool,
    pub stop_job_timeout: bool,
    pub unit_disappears_after_start: bool,
    pub post_start_read_failure: bool,
    pub unit_queries: usize,
    pub property_reads: usize,
    pub worker_unit_mismatch: bool,
    pub last_start_evidence: Option<SystemdStartEvidence>,
}

#[cfg(test)]
impl TransientScopeBackend for SimulatedSystemdBackend {
    fn capability(&self) -> Result<SystemdCapability> {
        Ok(SystemdCapability {
            pid1_systemd: self.available,
            system_bus_reachable: self.available,
            manager_available: self.available,
            start_transient_unit_available: self.available,
            transient_memory_max_supported: self.available,
            transient_runtime_max_supported: self.available,
            transient_property_api_version_supported: self.available,
            transient_request_encoding_verified: self.available,
            unit_readback_contract_verified: self.available,
            scope_readback_contract_verified: self.available,
            systemd_version: self.available.then(|| "test".into()),
            unified_cgroup_v2: self.available,
            memory_controller_supported: self.available,
            supported: self.available,
            reason: if self.available {
                "systemd_transient_scope_supported".into()
            } else {
                "systemd_unavailable".into()
            },
        })
    }

    fn unit_exists(&self, _: &str) -> Result<bool> {
        Ok(self.collision || self.scope.is_some())
    }

    fn list_owned_units(&self) -> Result<Vec<String>> {
        Ok(self
            .scope
            .as_ref()
            .map(|scope| vec![scope.unit_name.clone()])
            .unwrap_or_default())
    }

    fn start_owned_scope(&mut self, plan: &TransientScopePlan) -> Result<ScopeState> {
        self.last_start_evidence = Some(SystemdStartEvidence {
            requested_unit: plan.unit_name.clone(),
            ..Default::default()
        });
        if self.disconnect {
            bail!("system D-Bus disconnected");
        }
        if self.unit_exists(&plan.unit_name)? {
            bail!("transient unit name collision");
        }
        self.starts += 1;
        if let Some(evidence) = self.last_start_evidence.as_mut() {
            evidence.method_returned_job = true;
            evidence.job_path = Some("/test/job/start".into());
            evidence.mutation_may_have_started = true;
            evidence.cleanup_required = true;
        }
        if self.disconnect_while_start_pending {
            bail!("system D-Bus disconnected while start job was pending");
        }
        if self.start_job_timeout {
            bail!("systemd start job completion timeout");
        }
        let result = self.start_job_result.as_deref().unwrap_or("done");
        require_successful_job(&SystemdJobOutcome {
            job_path: "/test/job/start".into(),
            unit_name: plan.unit_name.clone(),
            result: result.into(),
            successful: result == "done",
        })?;
        if let Some(evidence) = self.last_start_evidence.as_mut() {
            evidence.job_result = Some(result.into());
        }
        self.unit_queries += 1;
        if self.unit_disappears_after_start {
            bail!("transient unit disappeared after successful start job");
        }
        self.property_reads += 1;
        if self.worker_unit_mismatch {
            if let Some(evidence) = self.last_start_evidence.as_mut() {
                evidence.unit_object_path = Some("/test/unit".into());
                evidence.worker_unit_object_path = Some("/test/foreign".into());
            }
            bail!("GetUnit and GetUnitByPID returned different objects");
        }
        let state = ScopeState {
            unit_name: plan.unit_name.clone(),
            object_path: "/test/unit".into(),
            control_group: "/test/nemor.scope".into(),
            memory_max: plan.memory_max,
            memory_accounting: true,
            cpu_accounting: true,
            io_accounting: true,
            runtime_max_usec: plan.runtime_max_usec,
            active_state: "active".into(),
            sub_state: "running".into(),
            members: BTreeSet::from([plan.identity.pid]),
        };
        self.scope = Some(state.clone());
        if self.post_start_read_failure {
            if let Some(evidence) = self.last_start_evidence.as_mut() {
                evidence.unit_object_path = Some(state.object_path.clone());
                evidence.worker_unit_object_path = Some(state.object_path.clone());
                evidence.unit_id = Some(state.unit_name.clone());
            }
            bail!("simulated post-start property read failure");
        }
        if let Some(evidence) = self.last_start_evidence.as_mut() {
            evidence.unit_object_path = Some(state.object_path.clone());
            evidence.worker_unit_object_path = Some(state.object_path.clone());
            evidence.unit_id = Some(state.unit_name.clone());
            evidence.load_state = Some("loaded".into());
            evidence.active_state = Some(state.active_state.clone());
            evidence.sub_state = Some(state.sub_state.clone());
            evidence.control_group = Some(state.control_group.clone());
        }
        Ok(state)
    }

    fn start_evidence(&self) -> Option<SystemdStartEvidence> {
        self.last_start_evidence.clone()
    }

    fn read_scope_state(&self, _: &str) -> Result<Option<ScopeState>> {
        if self.disconnect {
            bail!("system D-Bus disconnected");
        }
        Ok(self.scope.clone())
    }

    fn stop_owned_scope(&mut self, plan: &TransientScopePlan) -> Result<()> {
        if self.disconnect {
            bail!("system D-Bus disconnected");
        }
        if self
            .scope
            .as_ref()
            .is_some_and(|scope| scope.unit_name != plan.unit_name)
        {
            bail!("foreign unit is never stopped");
        }
        if self.stop_job_timeout {
            bail!("systemd stop job completion timeout");
        }
        let result = self.stop_job_result.as_deref().unwrap_or("done");
        require_successful_job(&SystemdJobOutcome {
            job_path: "/test/job/stop".into(),
            unit_name: plan.unit_name.clone(),
            result: result.into(),
            successful: result == "done",
        })?;
        self.stops += usize::from(self.scope.is_some());
        self.scope = None;
        Ok(())
    }

    fn wait_inactive_or_removed(&self, _: &str, _: std::time::Duration) -> Result<()> {
        if self.scope.is_none() {
            Ok(())
        } else {
            bail!("scope remains active")
        }
    }

    fn recover_owned_scope(
        &mut self,
        plan: &TransientScopePlan,
        ownership: RecoveryOwnership,
    ) -> Result<()> {
        match ownership {
            RecoveryOwnership::Absent => Ok(()),
            RecoveryOwnership::ExactOwned => self.stop_owned_scope(plan),
            RecoveryOwnership::Ambiguous => bail!("ambiguous transient scope is never stopped"),
        }
    }
}
