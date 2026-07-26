use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PressureState {
    Normal,
    Watch,
    Pressure,
    Critical,
    Emergency,
    Stabilizing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentState {
    pub current: PressureState,
    pub previous: Option<PressureState>,
    pub entered_at_ns: i64,
    pub candidate: Option<PressureState>,
    pub candidate_since_ns: Option<i64>,
    pub last_transition_ns: Option<i64>,
    pub transition_reason: String,
}

impl PersistentState {
    #[must_use]
    pub fn conservative(timestamp_ns: i64) -> Self {
        Self {
            current: PressureState::Watch,
            previous: None,
            entered_at_ns: timestamp_ns,
            candidate: None,
            candidate_since_ns: None,
            last_transition_ns: None,
            transition_reason: "restart_without_continuity".to_owned(),
        }
    }
}
