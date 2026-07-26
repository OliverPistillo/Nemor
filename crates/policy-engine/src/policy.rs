use crate::planner::plan_actions;
use crate::transition;
use crate::{
    CandidateRejection, PersistentState, PlannedAction, PolicyError, PolicyEvidence, PolicyInput,
    RejectedAction,
};
use common::PressureConfig;
use serde::{Deserialize, Serialize};

pub const POLICY_NAME: &str = "nemor-policy-v1";
pub const RULE_VERSION: &str = "pressure-rules-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub timestamp_ns: i64,
    pub current_state: crate::PressureState,
    pub previous_state: Option<crate::PressureState>,
    pub state_changed: bool,
    pub state_since_ns: i64,
    pub candidate_state: Option<crate::PressureState>,
    pub policy_name: String,
    pub rule_version: String,
    pub input_features: PolicyInput,
    pub evidence: Vec<PolicyEvidence>,
    pub rejected_candidates: Vec<CandidateRejection>,
    pub planned_actions: Vec<PlannedAction>,
    pub rejected_actions: Vec<RejectedAction>,
    pub expected_gain_bytes: Option<u64>,
    pub expected_cost_score: Option<f64>,
    pub dry_run: bool,
    pub transition_reason: String,
}

pub struct PolicyEngine {
    config: PressureConfig,
    state: PersistentState,
}

impl PolicyEngine {
    #[must_use]
    pub fn new(config: PressureConfig, timestamp_ns: i64) -> Self {
        Self {
            config,
            state: PersistentState::conservative(timestamp_ns),
        }
    }

    #[must_use]
    pub fn from_state(config: PressureConfig, state: PersistentState) -> Self {
        Self { config, state }
    }

    pub fn evaluate(
        &mut self,
        input: PolicyInput,
        observe: bool,
    ) -> Result<PolicyDecision, PolicyError> {
        input.validate()?;
        if input.timestamp_ns < self.state.entered_at_ns {
            return Err(PolicyError::TimeRegression);
        }
        let transition = transition::transition(&self.state, &input, &self.config);
        self.state = transition.state;
        let actions = plan_actions(self.state.current, &input, observe);
        Ok(PolicyDecision {
            timestamp_ns: input.timestamp_ns,
            current_state: self.state.current,
            previous_state: self.state.previous,
            state_changed: transition.changed,
            state_since_ns: self.state.entered_at_ns,
            candidate_state: self.state.candidate,
            policy_name: POLICY_NAME.to_owned(),
            rule_version: RULE_VERSION.to_owned(),
            input_features: input,
            evidence: transition.evidence,
            rejected_candidates: transition.rejected,
            planned_actions: actions.planned,
            rejected_actions: actions.rejected,
            expected_gain_bytes: None,
            expected_cost_score: None,
            dry_run: observe,
            transition_reason: self.state.transition_reason.clone(),
        })
    }

    #[must_use]
    pub fn state(&self) -> &PersistentState {
        &self.state
    }
}
