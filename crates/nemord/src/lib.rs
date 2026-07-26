#![forbid(unsafe_code)]

use actuator::{CgroupBackend, LinuxCgroupBackend};
use anyhow::{Context, Result};
use classifier::{
    ClassificationOutcome, Classifier, ProcessClassification, WorkloadExplanation,
    WorkloadTransition, RULE_VERSION,
};
use collector::{CollectorError, ProcessCollection, SystemCollector, SystemSample};
use common::Config;
use policy_engine::{
    CounterSample, PolicyDecision, PolicyEngine, PolicyInput, RateFeatures, RateTracker,
};
use std::collections::HashSet;
use std::future::Future;
use std::time::Duration;
use storage::{RetentionResult, Storage};
use tokio::time::{self, Instant, MissedTickBehavior};
use tracing::{debug, error, info, warn};

pub trait TelemetryCollector {
    fn system_sample(&mut self, timestamp_ns: i64) -> Result<SystemSample, CollectorError>;
    fn process_samples(
        &mut self,
        timestamp_ns: i64,
        read_smaps: bool,
        smaps_budget: usize,
    ) -> Result<ProcessCollection, CollectorError>;
}

impl TelemetryCollector for SystemCollector {
    fn system_sample(&mut self, timestamp_ns: i64) -> Result<SystemSample, CollectorError> {
        self.sample_system(timestamp_ns)
    }

    fn process_samples(
        &mut self,
        timestamp_ns: i64,
        read_smaps: bool,
        smaps_budget: usize,
    ) -> Result<ProcessCollection, CollectorError> {
        self.sample_processes(timestamp_ns, read_smaps, smaps_budget)
    }
}

pub trait TelemetryStorage {
    fn store_system(&mut self, session_id: i64, sample: &SystemSample) -> Result<()>;
    fn store_processes(
        &mut self,
        session_id: i64,
        samples: &[collector::ProcessSample],
    ) -> Result<usize>;
    fn store_classified(
        &mut self,
        session_id: i64,
        samples: &[ProcessClassification],
        transition: Option<&WorkloadTransition>,
    ) -> Result<usize>;
    fn retain(&mut self, cutoff_timestamp_ns: i64) -> Result<RetentionResult>;
    fn store_policy(
        &mut self,
        _session_id: i64,
        _decision: &PolicyDecision,
        _heartbeat_seconds: u64,
    ) -> Result<bool> {
        Ok(false)
    }
    fn policy_history_counts(&self, _timestamp_ns: i64) -> Result<(usize, usize)> {
        Ok((0, 0))
    }
}

impl TelemetryStorage for Storage {
    fn store_system(&mut self, session_id: i64, sample: &SystemSample) -> Result<()> {
        self.insert_system_sample(session_id, sample)
    }

    fn store_processes(
        &mut self,
        session_id: i64,
        samples: &[collector::ProcessSample],
    ) -> Result<usize> {
        self.insert_process_samples(session_id, samples)
    }

    fn store_classified(
        &mut self,
        session_id: i64,
        samples: &[ProcessClassification],
        transition: Option<&WorkloadTransition>,
    ) -> Result<usize> {
        self.insert_classification_batch(session_id, samples, transition)
    }

    fn retain(&mut self, cutoff_timestamp_ns: i64) -> Result<RetentionResult> {
        self.enforce_retention(cutoff_timestamp_ns)
    }

    fn store_policy(
        &mut self,
        session_id: i64,
        decision: &PolicyDecision,
        heartbeat_seconds: u64,
    ) -> Result<bool> {
        self.insert_policy_decision(session_id, decision, heartbeat_seconds)
    }

    fn policy_history_counts(&self, timestamp_ns: i64) -> Result<(usize, usize)> {
        Storage::policy_history_counts(self, timestamp_ns)
    }
}

pub async fn run_sampling_loop<C, S, F>(
    collector: &mut C,
    storage: &mut S,
    session_id: i64,
    config: &Config,
    shutdown: F,
) -> Result<&'static str>
where
    C: TelemetryCollector,
    S: TelemetryStorage,
    F: Future<Output = Result<&'static str>>,
{
    let mut system_interval =
        time::interval(Duration::from_millis(config.general.sample_interval_ms));
    let mut process_interval = time::interval(Duration::from_millis(
        config.telemetry.process_sample_interval_ms,
    ));
    let mut retention_interval = time::interval(Duration::from_millis(
        config.telemetry.retention_interval_ms,
    ));
    system_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    process_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    retention_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut next_smaps = Instant::now();
    let mut next_classification = Instant::now();
    let mut next_policy = Instant::now();
    let mut classifier = Classifier::new(config.classification.clone(), config.pressure.clone());
    let mut policy_engine = PolicyEngine::new(config.pressure.clone(), 0);
    let mut rate_tracker = RateTracker::default();
    let mut latest_rates = RateFeatures::default();
    let cgroup_capabilities = LinuxCgroupBackend::default().capabilities().ok();
    let mut latest_system = None;
    let mut logged_capabilities = HashSet::new();
    tokio::pin!(shutdown);

    info!(
        event = "telemetry_loop_started",
        session_id,
        system_interval_ms = config.general.sample_interval_ms,
        process_interval_ms = config.telemetry.process_sample_interval_ms,
        "telemetry sampling loop started"
    );

    loop {
        tokio::select! {
            biased;
            signal = &mut shutdown => {
                let signal = signal.context("shutdown signal future failed")?;
                info!(
                    event = "telemetry_loop_stopped",
                    session_id,
                    signal,
                    "telemetry sampling loop stopped"
                );
                return Ok(signal);
            }
            _ = system_interval.tick() => {
                let timestamp_ns = collector::unix_timestamp_ns()
                    .context("cannot create system sample timestamp")?;
                match collector.system_sample(timestamp_ns) {
                    Ok(sample) => {
                        log_capabilities_once(&sample, &mut logged_capabilities);
                        storage.store_system(session_id, &sample).map_err(|source| {
                            error!(
                                event = "storage_batch_error",
                                session_id,
                                batch = "system",
                                error = %format!("{source:#}"),
                                "system telemetry storage failed"
                            );
                            source
                        }).context("fatal system telemetry storage error")?;
                        latest_rates = rate_tracker.update(CounterSample {
                            timestamp_ns: sample.timestamp_ns,
                            swap_in: sample.swap_in_pages,
                            swap_out: sample.swap_out_pages,
                            major_faults: sample.major_faults,
                            pgscan: sample.pgscan,
                            pgsteal: sample.pgsteal,
                        });
                        latest_system = Some(sample);
                    }
                    Err(source) => {
                        warn!(
                            event = "partial_sample",
                            session_id,
                            component = "system",
                            error = %source,
                            "required system metric was temporarily unreadable"
                        );
                    }
                }
            }
            _ = process_interval.tick() => {
                let timestamp_ns = collector::unix_timestamp_ns()
                    .context("cannot create process sample timestamp")?;
                let now = Instant::now();
                let read_smaps = now >= next_smaps;
                if read_smaps {
                    next_smaps = now + Duration::from_millis(
                        config.telemetry.smaps_rollup_interval_ms
                    );
                }
                match collector.process_samples(
                    timestamp_ns,
                    read_smaps,
                    config.telemetry.smaps_rollup_budget,
                ) {
                    Ok(processes) => {
                        if processes.stats != collector::ProcessCollectionStats::default() {
                            debug!(
                                event = "partial_sample",
                                session_id,
                                component = "process",
                                disappeared = processes.stats.disappeared,
                                permission_denied = processes.stats.permission_denied,
                                invalid = processes.stats.invalid,
                                "some processes could not be sampled"
                            );
                        }
                        let classified = classifier.classify_processes(&processes.samples);
                        let classification_due = now >= next_classification;
                        let classification = classification_due.then(|| {
                            next_classification = now + Duration::from_millis(
                                config.classification.interval_ms
                            );
                            if timestamp_ns < 0 {
                                error!(
                                    event = "classifier_error",
                                    session_id,
                                    timestamp_ns,
                                    "classifier rejected an invalid persistent timestamp"
                                );
                                Some((
                                    ClassificationOutcome::Unknown(WorkloadExplanation {
                                        rule_version: RULE_VERSION.to_owned(),
                                        selected_class: "unknown".to_owned(),
                                        confidence: 0.0,
                                        evidence: Vec::new(),
                                        rejected_candidates: Vec::new(),
                                        protection_reasons: vec![
                                            "structural_classifier_error".to_owned()
                                        ],
                                    }),
                                    None,
                                ))
                            } else {
                                Some(classifier.evaluate(
                                    timestamp_ns,
                                    latest_system.as_ref(),
                                    &classified,
                                ))
                            }
                        }).flatten();
                        if let Some((outcome, transition)) = &classification {
                            let unknown_processes = classified
                                .iter()
                                .filter(|process| {
                                    process.category == classifier::ProcessCategory::Unknown
                                })
                                .count();
                            let game_processes =
                                classified.iter().filter(|process| process.is_game).count();
                            if !classified.is_empty()
                                && classified.iter().all(|process| {
                                    process.foreground == classifier::ForegroundState::Unknown
                                })
                            {
                                debug!(
                                    event = "foreground_detector_unavailable",
                                    session_id,
                                    processes = classified.len(),
                                    "no foreground detector had sufficient evidence"
                                );
                            }
                            if game_processes > 0 {
                                info!(
                                    event = "gaming_signal_detected",
                                    session_id,
                                    game_processes,
                                    "independent gaming evidence was detected"
                                );
                            }
                            if unknown_processes > 0 {
                                debug!(
                                    event = "process_classification_uncertain",
                                    session_id,
                                    unknown_processes,
                                    "some process identities remained conservatively unknown"
                                );
                            }
                            match outcome {
                                ClassificationOutcome::Classified(decision) => debug!(
                                    event = "workload_classification",
                                    session_id,
                                    workload = %decision.class,
                                    confidence = decision.confidence,
                                    rule_version = %decision.explanation.rule_version,
                                    "deterministic workload classification evaluated"
                                ),
                                ClassificationOutcome::Unknown(explanation) => debug!(
                                    event = "classifier_fallback",
                                    session_id,
                                    confidence = explanation.confidence,
                                    rule_version = %explanation.rule_version,
                                    "workload evidence remained below the safe confidence floor"
                                ),
                            }
                            if let Some(transition) = transition {
                                info!(
                                    event = "workload_classification_changed",
                                    session_id,
                                    previous_class = ?transition.previous_class,
                                    new_class = %transition.new_class,
                                    confidence = transition.confidence,
                                    rule_version = %transition.explanation.rule_version,
                                    "stabilized workload class changed"
                                );
                            }
                            if config.policy.enabled && now >= next_policy {
                                next_policy = now + Duration::from_millis(
                                    config.policy.evaluation_interval_ms
                                );
                                if let Some(system) = &latest_system {
                                    let workload = outcome.class();
                                    let confidence = match outcome {
                                        ClassificationOutcome::Classified(decision) => {
                                            Some(decision.confidence)
                                        }
                                        ClassificationOutcome::Unknown(_) => None,
                                    };
                                    let foreground = if classified.iter().any(|process| {
                                        process.foreground
                                            == classifier::ForegroundState::Foreground
                                    }) {
                                        classifier::ForegroundState::Foreground
                                    } else if !classified.is_empty()
                                        && classified.iter().all(|process| {
                                            process.foreground
                                                == classifier::ForegroundState::Background
                                        })
                                    {
                                        classifier::ForegroundState::Background
                                    } else {
                                        classifier::ForegroundState::Unknown
                                    };
                                    let swap_total = system.swap.entries.iter().try_fold(
                                        0_u64,
                                        |total, entry| total.checked_add(entry.size_bytes),
                                    );
                                    let swap_used = system.swap.entries.iter().try_fold(
                                        0_u64,
                                        |total, entry| total.checked_add(entry.used_bytes),
                                    );
                                    let (recent_decisions, recent_safety_events) = storage
                                        .policy_history_counts(timestamp_ns)
                                        .context("cannot read bounded policy history")?;
                                    let input = PolicyInput {
                                        timestamp_ns,
                                        ram_total_bytes: system.mem_total_bytes,
                                        mem_available_bytes: system.mem_available_bytes,
                                        available_percent: system.mem_available_bytes as f64
                                            * 100.0
                                            / system.mem_total_bytes as f64,
                                        swap_total_bytes: swap_total,
                                        swap_used_bytes: swap_used,
                                        swap_in_per_second: latest_rates.swap_in_per_second,
                                        swap_out_per_second: latest_rates.swap_out_per_second,
                                        major_faults_per_second:
                                            latest_rates.major_faults_per_second,
                                        pgscan_per_second: latest_rates.pgscan_per_second,
                                        pgsteal_per_second: latest_rates.pgsteal_per_second,
                                        psi_memory_some_avg10: system
                                            .psi_memory
                                            .as_ref()
                                            .and_then(|psi| psi.some)
                                            .map(|line| line.avg10),
                                        psi_memory_full_avg10: system
                                            .psi_memory
                                            .as_ref()
                                            .and_then(|psi| psi.full)
                                            .map(|line| line.avg10),
                                        workload_class: workload,
                                        workload_confidence: confidence,
                                        gaming: classified.iter().any(|process| process.is_game),
                                        critical_processes: classified
                                            .iter()
                                            .filter(|process| process.is_critical)
                                            .count(),
                                        protected_processes: classified
                                            .iter()
                                            .filter(|process| process.protected)
                                            .count(),
                                        unknown_processes,
                                        foreground,
                                        cgroup_capabilities: cgroup_capabilities.clone(),
                                        actuator_available: cgroup_capabilities
                                            .as_ref()
                                            .is_some_and(
                                                actuator::CgroupCapabilities::mutation_ready,
                                            ),
                                        recent_safety_events,
                                        recent_decisions,
                                    };
                                    match policy_engine.evaluate(input, true) {
                                        Ok(decision) => {
                                            if decision.state_changed {
                                                info!(
                                                    event = "pressure_state_changed",
                                                    session_id,
                                                    state = ?decision.current_state,
                                                    rule_version = %decision.rule_version,
                                                    "deterministic pressure state changed"
                                                );
                                            } else if decision.candidate_state.is_some() {
                                                debug!(
                                                    event = "policy_hysteresis_holding",
                                                    session_id,
                                                    candidate = ?decision.candidate_state,
                                                    "policy transition is waiting for its hold time"
                                                );
                                            }
                                            let inserted = storage.store_policy(
                                                session_id,
                                                &decision,
                                                config.policy.decision_heartbeat_seconds,
                                            ).context("cannot persist policy decision")?;
                                            if inserted {
                                                info!(
                                                    event = "policy_decision_persisted",
                                                    session_id,
                                                    state = ?decision.current_state,
                                                    dry_run = decision.dry_run,
                                                    "policy audit persisted"
                                                );
                                            }
                                            debug!(
                                                event = "policy_dry_run_plan",
                                                session_id,
                                                planned = decision.planned_actions.len(),
                                                rejected = decision.rejected_actions.len(),
                                                "policy plan stopped before actuator apply"
                                            );
                                        }
                                        Err(error) => warn!(
                                            event = "invalid_policy_telemetry",
                                            session_id,
                                            error = %error,
                                            "policy input rejected; state retained and no action applied"
                                        ),
                                    }
                                }
                            }
                        }
                        if classified.is_empty() {
                            storage.store_classified(
                                session_id,
                                &[],
                                classification
                                    .as_ref()
                                    .and_then(|(_, transition)| transition.as_ref()),
                            ).map_err(|source| {
                                error!(
                                    event = "storage_batch_error",
                                    session_id,
                                    batch = "classification",
                                    error = %format!("{source:#}"),
                                    "classified telemetry storage failed"
                                );
                                source
                            }).context("fatal classification storage error")?;
                        } else {
                            let chunk_count = classified.len().div_ceil(
                                config.telemetry.sqlite_batch_size
                            );
                            for (index, batch) in classified
                                .chunks(config.telemetry.sqlite_batch_size)
                                .enumerate()
                            {
                                let transition = (index + 1 == chunk_count)
                                    .then_some(classification.as_ref())
                                    .flatten()
                                    .and_then(|(_, transition)| transition.as_ref());
                                storage.store_classified(session_id, batch, transition)
                                    .map_err(|source| {
                                        error!(
                                            event = "storage_batch_error",
                                            session_id,
                                            batch = "classification",
                                            error = %format!("{source:#}"),
                                            "classified telemetry storage failed"
                                        );
                                        source
                                    })
                                    .context("fatal classification storage error")?;
                            }
                        }
                    }
                    Err(source) => warn!(
                        event = "partial_sample",
                        session_id,
                        component = "process",
                        error = %source,
                        "process enumeration was temporarily unavailable"
                    ),
                }
            }
            _ = retention_interval.tick() => {
                let now_ns = collector::unix_timestamp_ns()
                    .context("cannot create retention timestamp")?;
                let retention_ns = i64::try_from(
                    u128::from(config.telemetry.retention_days)
                        * 24 * 60 * 60 * 1_000_000_000
                ).context("retention duration overflows nanoseconds")?;
                let cutoff = now_ns.checked_sub(retention_ns)
                    .context("retention cutoff underflows timestamp")?;
                let removed = storage.retain(cutoff).map_err(|source| {
                    error!(
                        event = "storage_batch_error",
                        session_id,
                        batch = "retention",
                        error = %format!("{source:#}"),
                        "telemetry retention failed"
                    );
                    source
                }).context("fatal telemetry retention error")?;
                info!(
                    event = "retention_execution",
                    session_id,
                    cutoff_timestamp_ns = cutoff,
                    system_samples_deleted = removed.system_samples,
                    process_samples_deleted = removed.process_samples,
                    "telemetry retention completed"
                );
            }
        }
    }
}

fn log_capabilities_once(sample: &SystemSample, logged: &mut HashSet<String>) {
    for capability in ["psi_memory", "psi_cpu", "psi_io", "zram", "zswap"] {
        let unavailable = sample
            .capabilities_unavailable
            .iter()
            .any(|value| value == capability);
        let key = format!(
            "{capability}:{}",
            if unavailable {
                "unavailable"
            } else {
                "available"
            }
        );
        if logged.insert(key) {
            if unavailable {
                warn!(
                    event = "capability_unavailable",
                    capability, "collector capability is unavailable"
                );
            } else {
                info!(
                    event = "collector_capability_detected",
                    capability, "collector capability detected"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use collector::swap::{SwapConfiguration, SwapState};
    use collector::zram::ZramState;
    use collector::zswap::ZswapState;
    use std::io;
    use tokio::sync::oneshot;

    fn config() -> Config {
        Config::from_toml(include_str!("../../../config/default.toml")).expect("config")
    }

    fn sample(timestamp_ns: i64) -> SystemSample {
        SystemSample {
            timestamp_ns,
            mem_total_bytes: 100,
            mem_available_bytes: 50,
            anon_bytes: None,
            file_cache_bytes: None,
            slab_bytes: None,
            swap_used_bytes: None,
            swap_in_pages: None,
            swap_out_pages: None,
            major_faults: None,
            minor_faults: None,
            pgscan: None,
            pgsteal: None,
            workingset_refault: None,
            psi_memory: None,
            psi_cpu: None,
            psi_io: None,
            swap: SwapState {
                entries: Vec::new(),
                configuration: SwapConfiguration::None,
            },
            zram: ZramState {
                available: false,
                devices: Vec::new(),
            },
            zswap: ZswapState {
                available: false,
                enabled: None,
                stored_pages: None,
                pool_bytes: None,
            },
            capabilities_unavailable: vec![
                "psi_memory".to_owned(),
                "psi_cpu".to_owned(),
                "psi_io".to_owned(),
                "zram".to_owned(),
                "zswap".to_owned(),
            ],
        }
    }

    #[derive(Default)]
    struct MockCollector {
        system_calls: usize,
        process_calls: usize,
        fail_first_system: bool,
    }

    impl TelemetryCollector for MockCollector {
        fn system_sample(&mut self, timestamp_ns: i64) -> Result<SystemSample, CollectorError> {
            self.system_calls += 1;
            if self.fail_first_system && self.system_calls == 1 {
                return Err(CollectorError::RequiredRead {
                    metric: "fixture",
                    path: "/fixture".to_owned(),
                    source: io::Error::new(io::ErrorKind::NotFound, "fixture"),
                });
            }
            Ok(sample(timestamp_ns))
        }

        fn process_samples(
            &mut self,
            _timestamp_ns: i64,
            _read_smaps: bool,
            _smaps_budget: usize,
        ) -> Result<ProcessCollection, CollectorError> {
            self.process_calls += 1;
            Ok(ProcessCollection::default())
        }
    }

    #[derive(Default)]
    struct MockStorage {
        system_writes: usize,
        process_batches: usize,
        workload_transitions: usize,
        retention_runs: usize,
        fail_system: bool,
    }

    impl TelemetryStorage for MockStorage {
        fn store_system(&mut self, _session_id: i64, _sample: &SystemSample) -> Result<()> {
            if self.fail_system {
                anyhow::bail!("simulated database failure");
            }
            self.system_writes += 1;
            Ok(())
        }

        fn store_processes(
            &mut self,
            _session_id: i64,
            _samples: &[collector::ProcessSample],
        ) -> Result<usize> {
            self.process_batches += 1;
            Ok(0)
        }

        fn store_classified(
            &mut self,
            _session_id: i64,
            _samples: &[ProcessClassification],
            transition: Option<&WorkloadTransition>,
        ) -> Result<usize> {
            self.process_batches += 1;
            self.workload_transitions += usize::from(transition.is_some());
            Ok(0)
        }

        fn retain(&mut self, _cutoff_timestamp_ns: i64) -> Result<RetentionResult> {
            self.retention_runs += 1;
            Ok(RetentionResult {
                system_samples: 0,
                process_samples: 0,
            })
        }
    }

    async fn shutdown_future(receiver: oneshot::Receiver<()>) -> Result<&'static str> {
        receiver.await.context("test shutdown sender dropped")?;
        Ok("TEST")
    }

    #[tokio::test(start_paused = true)]
    async fn schedules_processes_less_frequently_and_shuts_down() {
        let mut config = config();
        config.general.sample_interval_ms = 100;
        config.telemetry.process_sample_interval_ms = 1_000;
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            for _ in 0..9 {
                time::advance(Duration::from_millis(100)).await;
                tokio::task::yield_now().await;
            }
            sender.send(()).expect("send shutdown");
        });
        let mut collector = MockCollector::default();
        let mut storage = MockStorage::default();
        let signal = run_sampling_loop(
            &mut collector,
            &mut storage,
            1,
            &config,
            shutdown_future(receiver),
        )
        .await
        .expect("loop");
        assert_eq!(signal, "TEST");
        assert!(collector.system_calls > collector.process_calls);
        assert_eq!(collector.process_calls, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn partial_collector_error_does_not_stop_next_sample() {
        let mut config = config();
        config.general.sample_interval_ms = 100;
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
            sender.send(()).expect("send shutdown");
        });
        let mut collector = MockCollector {
            fail_first_system: true,
            ..MockCollector::default()
        };
        let mut storage = MockStorage::default();
        run_sampling_loop(
            &mut collector,
            &mut storage,
            1,
            &config,
            shutdown_future(receiver),
        )
        .await
        .expect("loop");
        assert!(collector.system_calls >= 2);
        assert!(storage.system_writes >= 1);
    }

    #[tokio::test(start_paused = true)]
    async fn database_error_is_fatal_and_controlled() {
        let config = config();
        let mut collector = MockCollector::default();
        let mut storage = MockStorage {
            fail_system: true,
            ..MockStorage::default()
        };
        let error = run_sampling_loop(
            &mut collector,
            &mut storage,
            1,
            &config,
            std::future::pending(),
        )
        .await
        .expect_err("database failure");
        assert!(error.to_string().contains("fatal system telemetry storage"));
    }

    #[tokio::test(start_paused = true)]
    async fn no_busy_loop_without_clock_progress() {
        let config = config();
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            sender.send(()).expect("send shutdown");
        });
        let mut collector = MockCollector::default();
        let mut storage = MockStorage::default();
        run_sampling_loop(
            &mut collector,
            &mut storage,
            1,
            &config,
            shutdown_future(receiver),
        )
        .await
        .expect("loop");
        assert!(collector.system_calls <= 1);
        assert!(collector.process_calls <= 1);
        assert!(storage.retention_runs <= 1);
    }

    #[tokio::test(start_paused = true)]
    async fn workload_classification_uses_its_interval_and_stabilizes_once() {
        let mut config = config();
        config.general.sample_interval_ms = 100;
        config.telemetry.process_sample_interval_ms = 1_000;
        config.classification.interval_ms = 1_000;
        config.classification.confirmation_samples = 2;
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            time::advance(Duration::from_millis(1_100)).await;
            tokio::task::yield_now().await;
            sender.send(()).expect("send shutdown");
        });
        let mut collector = MockCollector::default();
        let mut storage = MockStorage::default();
        run_sampling_loop(
            &mut collector,
            &mut storage,
            1,
            &config,
            shutdown_future(receiver),
        )
        .await
        .expect("loop");
        assert_eq!(storage.workload_transitions, 1);
        assert!(storage.process_batches >= 2);
    }
}
