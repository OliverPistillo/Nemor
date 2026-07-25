use crate::model::{
    ClassificationOutcome, Evidence, ForegroundState, ProcessCategory, ProcessClassification,
    RejectedCandidate, WorkloadClass, WorkloadDecision, WorkloadExplanation, RULE_VERSION,
};
use collector::SystemSample;
use common::{ClassificationConfig, PressureConfig};

pub(crate) fn classify(
    system: Option<&SystemSample>,
    processes: &[ProcessClassification],
    config: &ClassificationConfig,
    pressure: &PressureConfig,
) -> ClassificationOutcome {
    let mut candidates = Vec::new();
    let memory_percent = system.and_then(|sample| {
        (sample.mem_total_bytes > 0)
            .then(|| sample.mem_available_bytes as f64 / sample.mem_total_bytes as f64 * 100.0)
    });
    let psi_some = system
        .and_then(|sample| sample.psi_memory.as_ref())
        .and_then(|psi| psi.some)
        .map(|line| line.avg10);
    let psi_full = system
        .and_then(|sample| sample.psi_memory.as_ref())
        .and_then(|psi| psi.full)
        .map(|line| line.avg10);

    let available_at_or_below = |threshold: u8| {
        system.is_some_and(|sample| {
            u128::from(sample.mem_available_bytes) * 100
                <= u128::from(sample.mem_total_bytes) * u128::from(threshold)
        })
    };
    if available_at_or_below(pressure.critical_available_percent)
        || psi_full.is_some_and(|value| value >= pressure.psi_full_avg10_threshold)
    {
        candidates.push(candidate(
            WorkloadClass::CriticalPressure,
            1.0,
            "critical_memory_pressure",
            memory_percent
                .map(|value| format!("{value:.2}% available"))
                .unwrap_or_else(|| format!("PSI full {:.2}", psi_full.unwrap_or_default())),
            Some(format!(
                "<= {}% or PSI full >= {:.2}",
                pressure.critical_available_percent, pressure.psi_full_avg10_threshold
            )),
        ));
    }
    if available_at_or_below(pressure.pressure_available_percent)
        || psi_some.is_some_and(|value| value >= pressure.psi_some_avg10_threshold)
    {
        candidates.push(candidate(
            WorkloadClass::MemoryPressure,
            0.92,
            "sustained_memory_pressure",
            memory_percent
                .map(|value| format!("{value:.2}% available"))
                .unwrap_or_else(|| format!("PSI some {:.2}", psi_some.unwrap_or_default())),
            Some(format!(
                "<= {}% or PSI some >= {:.2}",
                pressure.pressure_available_percent, pressure.psi_some_avg10_threshold
            )),
        ));
    }

    let games = processes
        .iter()
        .filter(|process| process.category == ProcessCategory::Game)
        .collect::<Vec<_>>();
    let game_confidence = games
        .iter()
        .map(|process| process.confidence)
        .fold(0.0_f64, f64::max);
    let non_game_rss = processes
        .iter()
        .filter(|process| process.category != ProcessCategory::Game)
        .filter_map(|process| process.sample.rss_bytes)
        .sum::<u64>();
    let non_game_percent = system
        .filter(|sample| sample.mem_total_bytes > 0)
        .map(|sample| non_game_rss as f64 / sample.mem_total_bytes as f64 * 100.0)
        .unwrap_or(0.0);
    if !games.is_empty() {
        if non_game_percent >= config.gaming_background_memory_percent {
            candidates.push(candidate(
                WorkloadClass::GamingBackgroundHeavy,
                game_confidence.max(0.80),
                "game_with_heavy_background",
                format!("{non_game_percent:.2}% non-game RSS"),
                Some(format!(
                    ">= {:.2}%",
                    config.gaming_background_memory_percent
                )),
            ));
        }
        candidates.push(candidate(
            WorkloadClass::Gaming,
            game_confidence,
            "protected_game_process",
            format!("{} game process(es)", games.len()),
            Some("at least one independently confirmed game".to_owned()),
        ));
    }

    let virtualization = processes
        .iter()
        .filter(|process| process.category == ProcessCategory::Virtualization)
        .collect::<Vec<_>>();
    let virtualization_rss = virtualization
        .iter()
        .filter_map(|process| process.sample.rss_bytes)
        .sum::<u64>();
    let virtualization_percent = system
        .filter(|sample| sample.mem_total_bytes > 0)
        .map(|sample| virtualization_rss as f64 / sample.mem_total_bytes as f64 * 100.0)
        .unwrap_or(0.0);
    if !virtualization.is_empty() && virtualization_percent >= config.virtualization_memory_percent
    {
        candidates.push(candidate(
            WorkloadClass::Virtualization,
            0.88,
            "virtual_machine_memory_share",
            format!("{virtualization_percent:.2}% VM RSS"),
            Some(format!(">= {:.2}%", config.virtualization_memory_percent)),
        ));
    }

    let browsers = processes
        .iter()
        .filter(|process| process.category == ProcessCategory::Browser)
        .collect::<Vec<_>>();
    let browser_rss = browsers
        .iter()
        .filter_map(|process| process.sample.rss_bytes)
        .sum::<u64>();
    let browser_percent = system
        .filter(|sample| sample.mem_total_bytes > 0)
        .map(|sample| browser_rss as f64 / sample.mem_total_bytes as f64 * 100.0)
        .unwrap_or(0.0);
    if browsers.len() >= config.browser_heavy_process_count
        && browser_percent >= config.browser_heavy_memory_percent
    {
        candidates.push(candidate(
            WorkloadClass::BrowserHeavy,
            0.85,
            "browser_processes_and_memory",
            format!("{} processes, {browser_percent:.2}% RSS", browsers.len()),
            Some(format!(
                ">= {} processes and >= {:.2}% RSS",
                config.browser_heavy_process_count, config.browser_heavy_memory_percent
            )),
        ));
    }

    let development = processes
        .iter()
        .filter(|process| process.category == ProcessCategory::Development)
        .count();
    if development >= 2 {
        candidates.push(candidate(
            WorkloadClass::Development,
            0.82,
            "development_toolset",
            format!("{development} development processes"),
            Some(">= 2 independent development tools".to_owned()),
        ));
    }
    let desktop_evidence = processes.iter().any(|process| {
        matches!(
            process.category,
            ProcessCategory::Desktop | ProcessCategory::Browser | ProcessCategory::Development
        ) || (process.foreground == ForegroundState::Foreground
            && !matches!(
                process.category,
                ProcessCategory::System | ProcessCategory::Critical | ProcessCategory::Unknown
            ))
    });
    if desktop_evidence {
        candidates.push(candidate(
            WorkloadClass::Desktop,
            0.75,
            "interactive_desktop_process",
            "interactive desktop evidence".to_owned(),
            None,
        ));
    }
    let idle = processes.is_empty()
        || (!processes.is_empty()
            && processes.iter().all(|process| {
                matches!(
                    process.category,
                    ProcessCategory::System
                        | ProcessCategory::Critical
                        | ProcessCategory::Background
                ) && process.sample.cpu_percent.unwrap_or(0.0) <= 0.5
            }));
    if idle {
        candidates.push(candidate(
            WorkloadClass::Idle,
            0.80,
            "demonstrated_inactivity",
            "no active user workload".to_owned(),
            Some("only idle system/background activity".to_owned()),
        ));
    }

    let precedence = [
        WorkloadClass::CriticalPressure,
        WorkloadClass::MemoryPressure,
        WorkloadClass::GamingBackgroundHeavy,
        WorkloadClass::Gaming,
        WorkloadClass::Virtualization,
        WorkloadClass::BrowserHeavy,
        WorkloadClass::Development,
        WorkloadClass::Desktop,
        WorkloadClass::Idle,
    ];
    let selected = precedence.iter().find_map(|class| {
        candidates
            .iter()
            .find(|candidate| {
                candidate.class == *class && candidate.confidence >= config.minimum_confidence
            })
            .cloned()
    });
    let protection_reasons = processes
        .iter()
        .flat_map(|process| process.reasons.iter())
        .filter(|reason| reason.contains("protected"))
        .cloned()
        .collect::<Vec<_>>();
    let rejected_candidates = candidates
        .iter()
        .filter(|candidate| {
            selected
                .as_ref()
                .is_none_or(|selected| selected.class != candidate.class)
        })
        .map(|candidate| RejectedCandidate {
            candidate: candidate.class,
            confidence: candidate.confidence,
            reason: if candidate.confidence < config.minimum_confidence {
                "below minimum confidence".to_owned()
            } else {
                "lower deterministic precedence".to_owned()
            },
        })
        .collect();

    match selected {
        Some(selected) => {
            let explanation = WorkloadExplanation {
                rule_version: RULE_VERSION.to_owned(),
                selected_class: selected.class.to_string(),
                confidence: selected.confidence,
                evidence: vec![selected.evidence],
                rejected_candidates,
                protection_reasons,
            };
            ClassificationOutcome::Classified(WorkloadDecision {
                class: selected.class,
                confidence: selected.confidence,
                explanation,
            })
        }
        None => ClassificationOutcome::Unknown(WorkloadExplanation {
            rule_version: RULE_VERSION.to_owned(),
            selected_class: "unknown".to_owned(),
            confidence: 0.0,
            evidence: Vec::new(),
            rejected_candidates,
            protection_reasons,
        }),
    }
}

#[derive(Clone)]
struct Candidate {
    class: WorkloadClass,
    confidence: f64,
    evidence: Evidence,
}

fn candidate(
    class: WorkloadClass,
    confidence: f64,
    code: &str,
    observed: String,
    threshold: Option<String>,
) -> Candidate {
    Candidate {
        class,
        confidence,
        evidence: Evidence {
            code: code.to_owned(),
            description: format!("deterministic evidence for {class}"),
            observed,
            threshold,
            contribution: confidence,
        },
    }
}
