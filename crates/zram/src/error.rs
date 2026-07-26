use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZramError {
    #[error("cannot read zram interface {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid zram field `{field}`: {message}")]
    Parse {
        field: &'static str,
        message: String,
    },
    #[error("zram operation blocked: {0}")]
    Blocked(String),
    #[error("zram backend operation `{operation}` failed: {message}")]
    Backend {
        operation: &'static str,
        message: String,
    },
    #[error("zram verification failed: {0}")]
    Verification(String),
}
