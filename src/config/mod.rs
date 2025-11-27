//! Configuration management module
//!
//! This module handles all configuration loading, validation, and management
//! for the PT Journal application.

pub mod config;
pub mod validation;
pub mod validator;

// Re-export main types for convenience
pub use config::{AppConfig, ChatbotConfig, ModelParameters, ModelProfile, ModelProviderKind, OllamaProviderConfig};