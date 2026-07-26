use crate::state::PressureState;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyEvidence {
    pub signal: String,
    pub value: Option<f64>,
    pub threshold: Option<f64>,
    pub relation: String,
    pub available: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateRejection {
    pub candidate: PressureState,
    pub reason: String,
}
