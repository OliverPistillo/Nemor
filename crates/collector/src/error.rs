use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CollectorError {
    #[error("required metric `{metric}` is unreadable at {path}: {source}")]
    RequiredRead {
        metric: &'static str,
        path: String,
        source: io::Error,
    },
    #[error("invalid {metric} fixture/input: {message}")]
    Invalid {
        metric: &'static str,
        message: String,
    },
    #[error("timestamp cannot be represented as signed Unix epoch nanoseconds")]
    Timestamp,
}

impl CollectorError {
    pub(crate) fn invalid(metric: &'static str, message: impl Into<String>) -> Self {
        Self::Invalid {
            metric,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessReadFailure {
    Disappeared,
    PermissionDenied,
    Invalid,
}

pub(crate) fn classify_process_io(error: &io::Error) -> ProcessReadFailure {
    match error.kind() {
        io::ErrorKind::NotFound => ProcessReadFailure::Disappeared,
        io::ErrorKind::PermissionDenied => ProcessReadFailure::PermissionDenied,
        _ => ProcessReadFailure::Invalid,
    }
}
