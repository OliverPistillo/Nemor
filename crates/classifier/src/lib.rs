#![forbid(unsafe_code)]

mod model;
mod process;
mod stabilize;
mod workload;

pub use model::{
    ClassificationBatch, ClassificationOutcome, Evidence, ForegroundState, ProcessCategory,
    ProcessClassification, RejectedCandidate, WorkloadClass, WorkloadDecision, WorkloadExplanation,
    WorkloadTransition, RULE_VERSION,
};
pub use stabilize::WorkloadStabilizer;

use collector::{ProcessSample, SystemSample};
use common::{ClassificationConfig, PressureConfig};

#[derive(Debug)]
pub struct Classifier {
    classification: ClassificationConfig,
    pressure: PressureConfig,
    stabilizer: WorkloadStabilizer,
}

impl Classifier {
    #[must_use]
    pub fn new(classification: ClassificationConfig, pressure: PressureConfig) -> Self {
        let confirmation_samples = classification.confirmation_samples;
        Self {
            classification,
            pressure,
            stabilizer: WorkloadStabilizer::new(confirmation_samples),
        }
    }

    #[must_use]
    pub fn classify(
        &mut self,
        timestamp_ns: i64,
        system: Option<&SystemSample>,
        samples: &[ProcessSample],
    ) -> ClassificationBatch {
        let processes = self.classify_processes(samples);
        self.classify_preprocessed(timestamp_ns, system, processes)
    }

    #[must_use]
    pub fn classify_processes(&self, samples: &[ProcessSample]) -> Vec<ProcessClassification> {
        process::classify_all(samples, &self.classification)
    }

    #[must_use]
    pub fn classify_preprocessed(
        &mut self,
        timestamp_ns: i64,
        system: Option<&SystemSample>,
        processes: Vec<ProcessClassification>,
    ) -> ClassificationBatch {
        let (outcome, transition) = self.evaluate(timestamp_ns, system, &processes);
        ClassificationBatch {
            processes,
            outcome,
            transition,
        }
    }

    #[must_use]
    pub fn evaluate(
        &mut self,
        timestamp_ns: i64,
        system: Option<&SystemSample>,
        processes: &[ProcessClassification],
    ) -> (ClassificationOutcome, Option<WorkloadTransition>) {
        let outcome = workload::classify(system, processes, &self.classification, &self.pressure);
        let transition = self.stabilizer.observe(timestamp_ns, &outcome);
        (outcome, transition)
    }

    #[must_use]
    pub fn current(&self) -> Option<WorkloadClass> {
        self.stabilizer.current()
    }
}

#[cfg(test)]
mod tests;
