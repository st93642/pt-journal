//! Configuration management module
//!
//! This module handles all configuration loading, validation, and management
//! for the PT Journal application.

pub mod loader;
pub mod validation;
pub mod validator;

// Re-export main types for convenience
pub use loader::{
    AppConfig, AzureOpenAIProviderConfig, ChatbotConfig, ModelParameters, ModelProfile,
    ModelProviderKind, OllamaProviderConfig, OpenAIProviderConfig,
};
