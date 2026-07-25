use collector::ProcessSample;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const RULE_VERSION: &str = "heuristic-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessCategory {
    Unknown,
    System,
    Critical,
    Desktop,
    Browser,
    Development,
    Game,
    Virtualization,
    Background,
}

impl fmt::Display for ProcessCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}",
            serde_json::to_value(self)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".to_owned())
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForegroundState {
    Foreground,
    Background,
    Unknown,
}

impl fmt::Display for ForegroundState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Foreground => formatter.write_str("foreground"),
            Self::Background => formatter.write_str("background"),
            Self::Unknown => formatter.write_str("unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadClass {
    Idle,
    Desktop,
    BrowserHeavy,
    Development,
    Gaming,
    GamingBackgroundHeavy,
    Virtualization,
    MemoryPressure,
    CriticalPressure,
}

impl fmt::Display for WorkloadClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Idle => "idle",
            Self::Desktop => "desktop",
            Self::BrowserHeavy => "browser_heavy",
            Self::Development => "development",
            Self::Gaming => "gaming",
            Self::GamingBackgroundHeavy => "gaming_background_heavy",
            Self::Virtualization => "virtualization",
            Self::MemoryPressure => "memory_pressure",
            Self::CriticalPressure => "critical_pressure",
        };
        formatter.write_str(text)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub code: String,
    pub description: String,
    pub observed: String,
    pub threshold: Option<String>,
    pub contribution: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RejectedCandidate {
    pub candidate: WorkloadClass,
    pub confidence: f64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkloadExplanation {
    pub rule_version: String,
    pub selected_class: String,
    pub confidence: f64,
    pub evidence: Vec<Evidence>,
    pub rejected_candidates: Vec<RejectedCandidate>,
    pub protection_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessClassification {
    pub sample: ProcessSample,
    pub executable: String,
    pub command_signature: String,
    pub application_name: Option<String>,
    pub category: ProcessCategory,
    pub is_game: bool,
    pub is_critical: bool,
    pub protected: bool,
    pub protected_game: bool,
    pub cold_candidate: bool,
    pub foreground: ForegroundState,
    pub foreground_confidence: f64,
    pub confidence: f64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WorkloadDecision {
    pub class: WorkloadClass,
    pub confidence: f64,
    pub explanation: WorkloadExplanation,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClassificationOutcome {
    Classified(WorkloadDecision),
    Unknown(WorkloadExplanation),
}

impl ClassificationOutcome {
    #[must_use]
    pub fn class(&self) -> Option<WorkloadClass> {
        match self {
            Self::Classified(decision) => Some(decision.class),
            Self::Unknown(_) => None,
        }
    }

    #[must_use]
    pub fn explanation(&self) -> &WorkloadExplanation {
        match self {
            Self::Classified(decision) => &decision.explanation,
            Self::Unknown(explanation) => explanation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkloadTransition {
    pub timestamp_ns: i64,
    pub previous_class: Option<WorkloadClass>,
    pub new_class: WorkloadClass,
    pub confidence: f64,
    pub explanation: WorkloadExplanation,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClassificationBatch {
    pub processes: Vec<ProcessClassification>,
    pub outcome: ClassificationOutcome,
    pub transition: Option<WorkloadTransition>,
}
