use crate::{ClassificationOutcome, WorkloadClass, WorkloadTransition};

#[derive(Debug)]
pub struct WorkloadStabilizer {
    confirmation_samples: u32,
    current: Option<WorkloadClass>,
    pending: Option<(WorkloadClass, u32)>,
}

impl WorkloadStabilizer {
    #[must_use]
    pub fn new(confirmation_samples: u32) -> Self {
        Self {
            confirmation_samples,
            current: None,
            pending: None,
        }
    }

    #[must_use]
    pub fn current(&self) -> Option<WorkloadClass> {
        self.current
    }

    pub fn observe(
        &mut self,
        timestamp_ns: i64,
        outcome: &ClassificationOutcome,
    ) -> Option<WorkloadTransition> {
        let ClassificationOutcome::Classified(decision) = outcome else {
            self.pending = None;
            return None;
        };
        if self.current == Some(decision.class) {
            self.pending = None;
            return None;
        }
        let immediate = decision.class == WorkloadClass::CriticalPressure;
        let count = if self
            .pending
            .is_some_and(|(class, _)| class == decision.class)
        {
            self.pending.map_or(1, |(_, count)| count.saturating_add(1))
        } else {
            1
        };
        self.pending = Some((decision.class, count));
        if !immediate && count < self.confirmation_samples {
            return None;
        }
        let previous_class = self.current.replace(decision.class);
        self.pending = None;
        Some(WorkloadTransition {
            timestamp_ns,
            previous_class,
            new_class: decision.class,
            confidence: decision.confidence,
            explanation: decision.explanation.clone(),
        })
    }
}
