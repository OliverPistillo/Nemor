use crate::PolicyDecision;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyEvent {
    pub timestamp_ns: i64,
    pub action_family: Option<String>,
    pub event_type: String,
}

#[derive(Debug, Clone, Default)]
pub struct DecisionHistory {
    pub recent: Vec<PolicyDecision>,
    pub safety_events: Vec<SafetyEvent>,
}

impl DecisionHistory {
    pub fn limited(mut self, limit: usize) -> Self {
        let limit = limit.min(100);
        self.recent.truncate(limit);
        self.safety_events.truncate(limit);
        self
    }
}
