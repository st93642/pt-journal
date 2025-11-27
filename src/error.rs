//! Unified error handling for the PT Journal application.
//!
//! This module provides a comprehensive error type that encompasses all
//! error conditions that can occur throughout the application. It follows
//! best practices for error handling in Rust:
//!
//! - Uses `thiserror` for ergonomic error definitions
//! - Provides context preservation through error chaining
//! - Includes detailed error messages for debugging
//! - Supports conversion from specific error types
//!
//! ## Error Categories
//!
//! - **Configuration**: Config file parsing, validation, and loading errors
//! - **State Management**: Model access, validation, and mutation errors
//! - **UI Handling**: User interface event processing errors
//! - **Chat/LLM**: AI chatbot communication and processing errors
//! - **I/O**: File system, network, and system interaction errors
//! - **Tool Integration**: Security tool execution and management errors
//! - **Validation**: Data validation and business rule errors
//!
//! ## Usage
//!
//! ```rust
//! use pt_journal::error::{Result, PtError};
//!
//! fn some_operation() -> Result<()> {
//!     // Operation that might fail
//!     Ok(())
//! }
//!
//! // Error conversion is automatic via ? operator
//! fn calling_function() -> Result<()> {
//!     some_operation()?;
//!     Ok(())
//! }
//! ```

use thiserror::Error;

/// Result type alias for operations that can return PtError
pub type Result<T> = std::result::Result<T, PtError>;

/// Comprehensive error type for the PT Journal application
#[derive(Debug, Error)]
pub enum PtError {
    // Configuration errors
    #[error("Configuration error: {message}")]
    Config {
        message: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Configuration file not found: {path}")]
    ConfigFileNotFound { path: String },

    #[error("Invalid configuration format: {message}")]
    ConfigFormat { message: String },

    // State management errors
    #[error("Invalid phase index: {phase_idx}")]
    InvalidPhaseIndex { phase_idx: usize },

    #[error("Invalid step index: phase={phase_idx}, step={step_idx}")]
    InvalidStepIndex { phase_idx: usize, step_idx: usize },

    #[error("Invalid question index: phase={phase_idx}, step={step_idx}, question={question_idx}")]
    InvalidQuestionIndex {
        phase_idx: usize,
        step_idx: usize,
        question_idx: usize,
    },

    #[error("State mutation error: {message}")]
    StateMutation { message: String },

    // UI handling errors
    #[error("UI handler error: {message}")]
    UiHandler { message: String },

    #[error("Invalid UI state: {message}")]
    InvalidUiState { message: String },

    // Chat/LLM errors
    #[error("Chat service error: {message}")]
    Chat {
        message: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Chat model not found: {model_id}")]
    ChatModelNotFound { model_id: String },

    #[error("Chat service unavailable: {message}")]
    ChatServiceUnavailable { message: String },

    // I/O errors
    #[error("I/O error: {message}")]
    Io {
        message: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("File not found: {path}")]
    FileNotFound { path: String },

    // Tool integration errors
    #[error("Tool integration error: {message}")]
    Tool { message: String },

    #[error("Tool not found: {tool_id}")]
    ToolNotFound { tool_id: String },

    #[error("Tool execution failed: {tool_id} - {message}")]
    ToolExecution { tool_id: String, message: String },

    // Validation errors
    #[error("Validation error: {message}")]
    Validation { message: String },

    #[error("Missing required field: {field}")]
    MissingRequiredField { field: String },

    #[error("Invalid field value: {field} - {message}")]
    InvalidFieldValue { field: String, message: String },

    #[error("Duplicate entry: {entry}")]
    DuplicateEntry { entry: String },

    // Generic errors
    #[error("Internal error: {message}")]
    Internal { message: String },

    #[error("Operation not supported: {operation}")]
    NotSupported { operation: String },

    #[error("Timeout error: {operation}")]
    Timeout { operation: String },
}

impl PtError {
    /// Create a new configuration error
    pub fn config<S: Into<String>>(message: S) -> Self {
        PtError::Config {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new configuration error with source
    pub fn config_with_source<S: Into<String>, E: std::error::Error + Send + Sync + 'static>(
        message: S,
        source: E,
    ) -> Self {
        PtError::Config {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a new I/O error
    pub fn io<S: Into<String>>(message: S) -> Self {
        PtError::Io {
            message: message.into(),
            source: None,
        }
    }

    /// Create a new I/O error with source
    pub fn io_with_source<S: Into<String>, E: std::error::Error + Send + Sync + 'static>(
        message: S,
        source: E,
    ) -> Self {
        PtError::Io {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a new validation error
    pub fn validation<S: Into<String>>(message: S) -> Self {
        PtError::Validation {
            message: message.into(),
        }
    }

    /// Create a new internal error
    pub fn internal<S: Into<String>>(message: S) -> Self {
        PtError::Internal {
            message: message.into(),
        }
    }

    /// Check if this error represents a "not found" condition
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            PtError::ConfigFileNotFound { .. }
                | PtError::FileNotFound { .. }
                | PtError::ToolNotFound { .. }
                | PtError::ChatModelNotFound { .. }
        )
    }

    /// Check if this error represents a validation failure
    pub fn is_validation_error(&self) -> bool {
        matches!(
            self,
            PtError::Validation { .. }
                | PtError::MissingRequiredField { .. }
                | PtError::InvalidFieldValue { .. }
                | PtError::DuplicateEntry { .. }
                | PtError::InvalidPhaseIndex { .. }
                | PtError::InvalidStepIndex { .. }
                | PtError::InvalidQuestionIndex { .. }
        )
    }

    /// Check if this error represents a configuration issue
    pub fn is_config_error(&self) -> bool {
        matches!(
            self,
            PtError::Config { .. }
                | PtError::ConfigFileNotFound { .. }
                | PtError::ConfigFormat { .. }
        )
    }
}

// Conversion implementations for existing error types

impl From<crate::config::validation::ValidationError> for PtError {
    fn from(err: crate::config::validation::ValidationError) -> Self {
        match err {
            crate::config::validation::ValidationError::FileNotFound(path) => {
                PtError::FileNotFound { path }
            }
            crate::config::validation::ValidationError::InvalidJson(msg) => {
                PtError::ConfigFormat { message: msg }
            }
            crate::config::validation::ValidationError::InvalidToml(msg) => {
                PtError::ConfigFormat { message: msg }
            }
            crate::config::validation::ValidationError::SchemaValidationFailed(msg) => {
                PtError::Validation { message: msg }
            }
            crate::config::validation::ValidationError::MissingRequiredField(field) => {
                PtError::MissingRequiredField { field }
            }
            crate::config::validation::ValidationError::InvalidFieldValue(msg) => {
                PtError::Validation { message: msg }
            }
            crate::config::validation::ValidationError::DuplicateEntry(entry) => {
                PtError::DuplicateEntry { entry }
            }
            crate::config::validation::ValidationError::CrossReferenceError(msg) => {
                PtError::Validation { message: msg }
            }
        }
    }
}

// Standard library conversions

impl From<std::io::Error> for PtError {
    fn from(err: std::io::Error) -> Self {
        PtError::io_with_source("I/O operation failed", err)
    }
}

impl From<serde_json::Error> for PtError {
    fn from(err: serde_json::Error) -> Self {
        PtError::config_with_source("JSON parsing failed", err)
    }
}

impl From<toml::de::Error> for PtError {
    fn from(err: toml::de::Error) -> Self {
        PtError::config_with_source("TOML parsing failed", err)
    }
}

impl From<reqwest::Error> for PtError {
    fn from(err: reqwest::Error) -> Self {
        PtError::io_with_source("HTTP request failed", err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = PtError::config("Test config error");
        assert!(err.is_config_error());
        assert!(!err.is_validation_error());
        assert!(!err.is_not_found());

        let err = PtError::validation("Test validation error");
        assert!(!err.is_config_error());
        assert!(err.is_validation_error());
        assert!(!err.is_not_found());

        let err = PtError::FileNotFound {
            path: "/test".to_string(),
        };
        assert!(!err.is_config_error());
        assert!(!err.is_validation_error());
        assert!(err.is_not_found());
    }

    #[test]
    fn test_error_display() {
        let err = PtError::InvalidPhaseIndex { phase_idx: 5 };
        assert_eq!(format!("{}", err), "Invalid phase index: 5");

        let err = PtError::FileNotFound {
            path: "/missing/file".to_string(),
        };
        assert_eq!(format!("{}", err), "File not found: /missing/file");
    }

    #[test]
    fn test_error_conversions() {
        // Test ValidationError conversion
        let validation_err =
            crate::config::validation::ValidationError::FileNotFound("test.toml".to_string());
        let pt_err: PtError = validation_err.into();
        assert!(matches!(pt_err, PtError::FileNotFound { .. }));
    }
}
