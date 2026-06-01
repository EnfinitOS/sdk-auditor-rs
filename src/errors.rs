//! Typed error envelope. Mirrors the TS/Py shape: audit failures stay
//! inside the report; operational errors raise this type.

use crate::types::AuditReasonCode;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditorErrorCode {
    InvalidInput,
    KeysUnavailable,
    KeysMalformed,
    PlatformResponse,
    Internal,
}

impl AuditorErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditorErrorCode::InvalidInput => "INVALID_INPUT",
            AuditorErrorCode::KeysUnavailable => "KEYS_UNAVAILABLE",
            AuditorErrorCode::KeysMalformed => "KEYS_MALFORMED",
            AuditorErrorCode::PlatformResponse => "PLATFORM_RESPONSE",
            AuditorErrorCode::Internal => "INTERNAL",
        }
    }
}

/// Raised only for operational failures the SDK could not reduce to a
/// structured AuditReport step.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct AuditorError {
    pub code: AuditorErrorCode,
    pub message: String,
    pub reason: Option<AuditReasonCode>,
    pub detail: Option<serde_json::Value>,
}

impl AuditorError {
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self {
            code: AuditorErrorCode::InvalidInput,
            message: message.into(),
            reason: None,
            detail: None,
        }
    }

    pub fn with_reason(mut self, reason: AuditReasonCode) -> Self {
        self.reason = Some(reason);
        self
    }

    pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = Some(detail);
        self
    }

    pub fn keys_malformed(message: impl Into<String>) -> Self {
        Self {
            code: AuditorErrorCode::KeysMalformed,
            message: message.into(),
            reason: None,
            detail: None,
        }
    }

    pub fn keys_unavailable(message: impl Into<String>) -> Self {
        Self {
            code: AuditorErrorCode::KeysUnavailable,
            message: message.into(),
            reason: None,
            detail: None,
        }
    }

    pub fn platform_response(message: impl Into<String>) -> Self {
        Self {
            code: AuditorErrorCode::PlatformResponse,
            message: message.into(),
            reason: None,
            detail: None,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            code: AuditorErrorCode::Internal,
            message: message.into(),
            reason: None,
            detail: None,
        }
    }
}

impl From<serde_json::Error> for AuditorError {
    fn from(e: serde_json::Error) -> Self {
        AuditorError::invalid_input(format!("JSON parse error: {e}"))
    }
}
