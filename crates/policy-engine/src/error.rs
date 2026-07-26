use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum PolicyError {
    #[error("invalid policy input field `{field}`: {message}")]
    InvalidInput {
        field: &'static str,
        message: &'static str,
    },
    #[error("logical timestamp moved backwards")]
    TimeRegression,
    #[error("serialization failed: {0}")]
    Serialization(String),
}
