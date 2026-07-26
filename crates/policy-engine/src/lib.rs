#![forbid(unsafe_code)]

pub mod action;
pub mod error;
pub mod explanation;
pub mod features;
pub mod history;
pub mod planner;
pub mod policy;
pub mod state;
pub mod transition;

pub use action::{ActionKind, PlannedAction, RejectedAction, ZramProfileIntent};
pub use error::PolicyError;
pub use explanation::{CandidateRejection, PolicyEvidence};
pub use features::{CounterSample, PolicyInput, RateFeatures, RateTracker};
pub use history::{DecisionHistory, SafetyEvent};
pub use policy::{PolicyDecision, PolicyEngine, POLICY_NAME, RULE_VERSION};
pub use state::{PersistentState, PressureState};

#[cfg(test)]
mod tests;
