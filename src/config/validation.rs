//! Configuration validation module
//!
//! This module provides comprehensive validation for all configuration files
//! used by PT Journal, including TOML configs and JSON manifests.

use crate::config::config::{AppConfig, ChatbotConfig};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Represents validation errors that can occur during config validation
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    /// File not found or cannot be read
    FileNotFound(String),
    /// Invalid JSON format
    InvalidJson(String),
    /// Invalid TOML format
    InvalidToml(String),
    /// Schema validation failed
    SchemaValidationFailed(String),
    /// Required field missing
    MissingRequiredField(String),
    /// Invalid field value
    InvalidFieldValue(String),
    /// Duplicate entries found
    DuplicateEntry(String),
    /// Cross-reference validation failed
    CrossReferenceError(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::FileNotFound(path) => write!(f, "File not found: {}", path),
            ValidationError::InvalidJson(msg) => write!(f, "Invalid JSON: {}", msg),
            ValidationError::InvalidToml(msg) => write!(f, "Invalid TOML: {}", msg),
            ValidationError::SchemaValidationFailed(msg) => write!(f, "Schema validation failed: {}", msg),
            ValidationError::MissingRequiredField(field) => write!(f, "Missing required field: {}", field),
            ValidationError::InvalidFieldValue(msg) => write!(f, "Invalid field value: {}", msg),
            ValidationError::DuplicateEntry(entry) => write!(f, "Duplicate entry: {}", entry),
            ValidationError::CrossReferenceError(msg) => write!(f, "Cross-reference error: {}", msg),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Result type for validation operations
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Validates the tool instructions manifest JSON file
pub fn validate_tool_manifest(manifest_path: &Path) -> ValidationResult<()> {
    // Read and parse the manifest
    let content = fs::read_to_string(manifest_path)
        .map_err(|_| ValidationError::FileNotFound(manifest_path.display().to_string()))?;

    let json_value: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| ValidationError::InvalidJson(format!("Failed to parse manifest: {}", e)))?;

    let entries = json_value.as_array()
        .ok_or_else(|| ValidationError::InvalidJson("Manifest must be a JSON array".to_string()))?;

    if entries.is_empty() {
        return Err(ValidationError::InvalidFieldValue("Manifest cannot be empty".to_string()));
    }

    // Validate each entry
    let mut seen_ids = HashSet::new();
    let mut seen_categories = HashSet::new();

    for (index, entry) in entries.iter().enumerate() {
        let entry_obj = entry.as_object()
            .ok_or_else(|| ValidationError::InvalidJson(format!("Entry {} must be a JSON object", index)))?;

        // Validate required fields
        let id = entry_obj.get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ValidationError::MissingRequiredField(format!("Entry {}: id field is missing or not a string", index)))?;

        if id.trim().is_empty() {
            return Err(ValidationError::MissingRequiredField(format!("Entry {}: id cannot be empty", index)));
        }

        let label = entry_obj.get("label")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ValidationError::MissingRequiredField(format!("Entry {} (id: {}): label field is missing or not a string", index, id)))?;

        if label.trim().is_empty() {
            return Err(ValidationError::MissingRequiredField(format!("Entry {} (id: {}): label cannot be empty", index, id)));
        }

        let category = entry_obj.get("category")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ValidationError::MissingRequiredField(format!("Entry {} (id: {}): category field is missing or not a string", index, id)))?;

        if category.trim().is_empty() {
            return Err(ValidationError::MissingRequiredField(format!("Entry {} (id: {}): category cannot be empty", index, id)));
        }

        // Check for duplicate IDs
        if !seen_ids.insert(id.to_string()) {
            return Err(ValidationError::DuplicateEntry(format!("Duplicate tool ID: {}", id)));
        }

        seen_categories.insert(category.to_string());
    }

    // Validate that we have a reasonable number of categories
    if seen_categories.len() < 3 {
        return Err(ValidationError::InvalidFieldValue("Manifest should have at least 3 different categories".to_string()));
    }

    Ok(())
}

/// Validates the main application configuration
pub fn validate_app_config(config_path: &Path) -> ValidationResult<()> {
    // If config file doesn't exist, skip validation (defaults will be used)
    if !config_path.exists() {
        println!("ℹ️  Config file not found, using defaults (validation skipped)");
        return Ok(());
    }

    // Read and parse the config
    let content = fs::read_to_string(config_path)
        .map_err(|_| ValidationError::FileNotFound(config_path.display().to_string()))?;

    let config: AppConfig = toml::from_str(&content)
        .map_err(|e| ValidationError::InvalidToml(format!("Failed to parse config: {}", e)))?;

    // Validate chatbot configuration
    validate_chatbot_config(&config.chatbot)?;

    Ok(())
}

/// Validates an AppConfig instance (useful for validating loaded configs)
pub fn validate_app_config_instance(config: &AppConfig) -> ValidationResult<()> {
    validate_chatbot_config(&config.chatbot)
}

/// Validates chatbot-specific configuration
fn validate_chatbot_config(chatbot: &ChatbotConfig) -> ValidationResult<()> {
    // Validate default model ID
    if chatbot.default_model_id.trim().is_empty() {
        return Err(ValidationError::MissingRequiredField("chatbot.default_model_id cannot be empty".to_string()));
    }

    // Validate that default model exists in the models list
    let default_model_exists = chatbot.models.iter().any(|m| m.id == chatbot.default_model_id);
    if !default_model_exists {
        return Err(ValidationError::CrossReferenceError(format!(
            "Default model '{}' not found in models list", chatbot.default_model_id
        )));
    }

    // Validate models list
    if chatbot.models.is_empty() {
        return Err(ValidationError::InvalidFieldValue("At least one model must be configured".to_string()));
    }

    let mut seen_ids = HashSet::new();
    for model in &chatbot.models {
        // Validate model ID
        if model.id.trim().is_empty() {
            return Err(ValidationError::MissingRequiredField("Model ID cannot be empty".to_string()));
        }

        // Check for duplicate model IDs
        if !seen_ids.insert(model.id.clone()) {
            return Err(ValidationError::DuplicateEntry(format!("Duplicate model ID: {}", model.id)));
        }

        // Validate display name
        if model.display_name.trim().is_empty() {
            return Err(ValidationError::MissingRequiredField(format!("Model '{}' display_name cannot be empty", model.id)));
        }

        // Validate prompt template
        if model.prompt_template.trim().is_empty() {
            return Err(ValidationError::MissingRequiredField(format!("Model '{}' prompt_template cannot be empty", model.id)));
        }

        // Validate parameters
        if let Some(temp) = model.parameters.temperature {
            if !(0.0..=2.0).contains(&temp) {
                return Err(ValidationError::InvalidFieldValue(format!(
                    "Model '{}' temperature must be between 0.0 and 2.0, got {}", model.id, temp
                )));
            }
        }

        if let Some(top_p) = model.parameters.top_p {
            if !(0.0..=1.0).contains(&top_p) {
                return Err(ValidationError::InvalidFieldValue(format!(
                    "Model '{}' top_p must be between 0.0 and 1.0, got {}", model.id, top_p
                )));
            }
        }

        if let Some(top_k) = model.parameters.top_k {
            if top_k < 0 {
                return Err(ValidationError::InvalidFieldValue(format!(
                    "Model '{}' top_k must be non-negative, got {}", model.id, top_k
                )));
            }
        }

        if let Some(num_predict) = model.parameters.num_predict {
            if num_predict <= 0 {
                return Err(ValidationError::InvalidFieldValue(format!(
                    "Model '{}' num_predict must be positive, got {}", model.id, num_predict
                )));
            }
        }
    }

    // Validate Ollama configuration
    if chatbot.ollama.endpoint.trim().is_empty() {
        return Err(ValidationError::MissingRequiredField("ollama.endpoint cannot be empty".to_string()));
    }

    // Validate endpoint URL format
    if !chatbot.ollama.endpoint.starts_with("http://") && !chatbot.ollama.endpoint.starts_with("https://") {
        return Err(ValidationError::InvalidFieldValue(format!(
            "Ollama endpoint must be a valid HTTP/HTTPS URL, got: {}", chatbot.ollama.endpoint
        )));
    }

    if chatbot.ollama.timeout_seconds == 0 {
        return Err(ValidationError::InvalidFieldValue("Ollama timeout_seconds must be greater than 0".to_string()));
    }

    Ok(())
}

/// Validates cross-references between manifest and instruction files
pub fn validate_manifest_instructions_cross_refs(manifest_path: &Path, instructions_dir: &Path) -> ValidationResult<()> {
    // First validate the manifest itself
    validate_tool_manifest(manifest_path)?;

    // Read the manifest
    let content = fs::read_to_string(manifest_path)
        .map_err(|_| ValidationError::FileNotFound(manifest_path.display().to_string()))?;

    let json_value: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| ValidationError::InvalidJson(format!("Failed to parse manifest: {}", e)))?;

    let entries = json_value.as_array()
        .ok_or_else(|| ValidationError::InvalidJson("Manifest must be a JSON array".to_string()))?;

    // Collect tool IDs from manifest
    let mut tool_ids = Vec::new();
    for entry in entries {
        if let Some(entry_obj) = entry.as_object() {
            if let Some(id) = entry_obj.get("id").and_then(|v| v.as_str()) {
                tool_ids.push(id.to_string());
            }
        }
    }

    // Check that instruction files exist for each manifest entry
    for tool_id in &tool_ids {
        let instruction_path = instructions_dir.join(format!("{}.md", tool_id));
        if !instruction_path.exists() {
            return Err(ValidationError::CrossReferenceError(format!(
                "Instruction file missing for tool '{}': expected at {}", tool_id, instruction_path.display()
            )));
        }
    }

    // Check for orphaned instruction files (files without manifest entries)
    if let Ok(dir_entries) = fs::read_dir(instructions_dir) {
        for entry in dir_entries.flatten() {
            if let Some(file_name) = entry.file_name().to_str() {
                if file_name.ends_with(".md") {
                    if let Some(tool_id) = file_name.strip_suffix(".md") {
                        if !tool_ids.iter().any(|id| id == tool_id) {
                            return Err(ValidationError::CrossReferenceError(format!(
                                "Orphaned instruction file: {} (no corresponding manifest entry)", file_name
                            )));
                        }
                    }
                }
            }
        }
    }

    Ok(())
}