use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZramProfileIntent {
    Safe,
    Gaming,
    Capacity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    NoAction,
    PrepareForegroundProtection,
    ProtectForeground,
    ApplyBackgroundSoftLimit,
    RollbackCgroupMeasures,
    SelectZramProfile { profile: ZramProfileIntent },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedAction {
    pub kind: ActionKind,
    pub reason: String,
    pub mutating: bool,
    pub actuator_plan: Option<actuator::CgroupPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedAction {
    pub requested: String,
    pub reason_code: String,
    pub explanation: String,
}
