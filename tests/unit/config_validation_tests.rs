//! Tests for configuration validation

use std::fs;
use tempfile::TempDir;
use pt_journal::config::validation::{validate_app_config, validate_tool_manifest, validate_manifest_instructions_cross_refs, ValidationError};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_tool_manifest_valid() {
        let temp_dir = TempDir::new().unwrap();
        let manifest_path = temp_dir.path().join("manifest.json");

        let valid_manifest = r#"[
  {
    "id": "nmap",
    "label": "Nmap - Port Scanner",
    "category": "Scanning & Enumeration"
  },
  {
    "id": "metasploit",
    "label": "Metasploit Framework",
    "category": "Exploitation"
  },
  {
    "id": "wireshark",
    "label": "Wireshark",
    "category": "Network Analysis"
  }
]"#;

        fs::write(&manifest_path, valid_manifest).unwrap();

        let result = validate_tool_manifest(&manifest_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_tool_manifest_empty() {
        let temp_dir = TempDir::new().unwrap();
        let manifest_path = temp_dir.path().join("manifest.json");

        fs::write(&manifest_path, "[]").unwrap();

        let result = validate_tool_manifest(&manifest_path);
        assert!(matches!(result, Err(ValidationError::InvalidFieldValue(_))));
    }

    #[test]
    fn test_validate_tool_manifest_missing_id() {
        let temp_dir = TempDir::new().unwrap();
        let manifest_path = temp_dir.path().join("manifest.json");

        let invalid_manifest = r#"[
  {
    "label": "Test Tool",
    "category": "Testing"
  }
]"#;

        fs::write(&manifest_path, invalid_manifest).unwrap();

        let result = validate_tool_manifest(&manifest_path);
        assert!(matches!(result, Err(ValidationError::MissingRequiredField(_))));
    }

    #[test]
    fn test_validate_tool_manifest_duplicate_id() {
        let temp_dir = TempDir::new().unwrap();
        let manifest_path = temp_dir.path().join("manifest.json");

        let duplicate_manifest = r#"[
  {
    "id": "duplicate",
    "label": "First Tool",
    "category": "Testing"
  },
  {
    "id": "duplicate",
    "label": "Second Tool",
    "category": "Testing"
  }
]"#;

        fs::write(&manifest_path, duplicate_manifest).unwrap();

        let result = validate_tool_manifest(&manifest_path);
        assert!(matches!(result, Err(ValidationError::DuplicateEntry(_))));
    }

    #[test]
    fn test_validate_tool_manifest_invalid_json() {
        let temp_dir = TempDir::new().unwrap();
        let manifest_path = temp_dir.path().join("manifest.json");

        fs::write(&manifest_path, "{ invalid json }").unwrap();

        let result = validate_tool_manifest(&manifest_path);
        assert!(matches!(result, Err(ValidationError::InvalidJson(_))));
    }

    #[test]
    fn test_validate_tool_manifest_file_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let manifest_path = temp_dir.path().join("nonexistent.json");

        let result = validate_tool_manifest(&manifest_path);
        assert!(matches!(result, Err(ValidationError::FileNotFound(_))));
    }

    #[test]
    fn test_validate_app_config_valid() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        let valid_config = r#"
[chatbot]
default_model_id = "llama3.2:latest"

[[chatbot.models]]
id = "llama3.2:latest"
display_name = "Llama 3.2"
provider = "ollama"
prompt_template = "{{context}}"

[chatbot.ollama]
endpoint = "http://localhost:11434"
timeout_seconds = 180
"#;

        fs::write(&config_path, valid_config).unwrap();

        let result = validate_app_config(&config_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_app_config_missing_default_model() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        let invalid_config = r#"
[chatbot]
default_model_id = ""

[[chatbot.models]]
id = "llama3.2:latest"
display_name = "Llama 3.2"
provider = "ollama"
prompt_template = "{{context}}"

[chatbot.ollama]
endpoint = "http://localhost:11434"
timeout_seconds = 180
"#;

        fs::write(&config_path, invalid_config).unwrap();

        let result = validate_app_config(&config_path);
        assert!(matches!(result, Err(ValidationError::MissingRequiredField(_))));
    }

    #[test]
    fn test_validate_app_config_invalid_model_reference() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        let invalid_config = r#"
[chatbot]
default_model_id = "nonexistent-model"

[[chatbot.models]]
id = "llama3.2:latest"
display_name = "Llama 3.2"
provider = "ollama"
prompt_template = "{{context}}"

[chatbot.ollama]
endpoint = "http://localhost:11434"
timeout_seconds = 180
"#;

        fs::write(&config_path, invalid_config).unwrap();

        let result = validate_app_config(&config_path);
        assert!(matches!(result, Err(ValidationError::CrossReferenceError(_))));
    }

    #[test]
    fn test_validate_app_config_invalid_temperature() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        let invalid_config = r#"
[chatbot]
default_model_id = "llama3.2:latest"

[[chatbot.models]]
id = "llama3.2:latest"
display_name = "Llama 3.2"
provider = "ollama"
prompt_template = "{{context}}"

[chatbot.models.parameters]
temperature = 3.0

[chatbot.ollama]
endpoint = "http://localhost:11434"
timeout_seconds = 180
"#;

        fs::write(&config_path, invalid_config).unwrap();

        let result = validate_app_config(&config_path);
        assert!(matches!(result, Err(ValidationError::InvalidFieldValue(_))));
    }

    #[test]
    fn test_validate_app_config_invalid_endpoint() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        let invalid_config = r#"
[chatbot]
default_model_id = "llama3.2:latest"

[[chatbot.models]]
id = "llama3.2:latest"
display_name = "Llama 3.2"
provider = "ollama"
prompt_template = "{{context}}"

[chatbot.ollama]
endpoint = "invalid-endpoint"
timeout_seconds = 180
"#;

        fs::write(&config_path, invalid_config).unwrap();

        let result = validate_app_config(&config_path);
        assert!(matches!(result, Err(ValidationError::InvalidFieldValue(_))));
    }

    #[test]
    fn test_validate_manifest_instructions_cross_refs_valid() {
        let temp_dir = TempDir::new().unwrap();
        let manifest_path = temp_dir.path().join("manifest.json");
        let instructions_dir = temp_dir.path().join("categories");

        fs::create_dir(&instructions_dir).unwrap();

        let valid_manifest = r#"[
  {
    "id": "test-tool",
    "label": "Test Tool",
    "category": "Testing"
  },
  {
    "id": "another-tool",
    "label": "Another Tool",
    "category": "Analysis"
  },
  {
    "id": "third-tool",
    "label": "Third Tool",
    "category": "Scanning"
  }
]"#;

        fs::write(&manifest_path, valid_manifest).unwrap();
        fs::write(instructions_dir.join("test-tool.md"), "# Test Tool").unwrap();
        fs::write(instructions_dir.join("another-tool.md"), "# Another Tool").unwrap();
        fs::write(instructions_dir.join("third-tool.md"), "# Third Tool").unwrap();

        let result = validate_manifest_instructions_cross_refs(&manifest_path, &instructions_dir);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_manifest_instructions_cross_refs_missing_instruction() {
        let temp_dir = TempDir::new().unwrap();
        let manifest_path = temp_dir.path().join("manifest.json");
        let instructions_dir = temp_dir.path().join("categories");

        fs::create_dir(&instructions_dir).unwrap();

        let manifest = r#"[
  {
    "id": "test-tool",
    "label": "Test Tool",
    "category": "Testing"
  },
  {
    "id": "another-tool",
    "label": "Another Tool",
    "category": "Analysis"
  },
  {
    "id": "third-tool",
    "label": "Third Tool",
    "category": "Scanning"
  }
]"#;

        fs::write(&manifest_path, manifest).unwrap();
        // Don't create the instruction file

        let result = validate_manifest_instructions_cross_refs(&manifest_path, &instructions_dir);
        assert!(matches!(result, Err(ValidationError::CrossReferenceError(_))));
    }

    #[test]
    fn test_validate_manifest_instructions_cross_refs_orphaned_instruction() {
        let temp_dir = TempDir::new().unwrap();
        let manifest_path = temp_dir.path().join("manifest.json");
        let instructions_dir = temp_dir.path().join("categories");

        fs::create_dir(&instructions_dir).unwrap();

        let manifest = r#"[
  {
    "id": "test-tool",
    "label": "Test Tool",
    "category": "Testing"
  },
  {
    "id": "another-tool",
    "label": "Another Tool",
    "category": "Analysis"
  },
  {
    "id": "third-tool",
    "label": "Third Tool",
    "category": "Scanning"
  }
]"#;

        fs::write(&manifest_path, manifest).unwrap();
        fs::write(instructions_dir.join("test-tool.md"), "# Test Tool").unwrap();
        fs::write(instructions_dir.join("orphaned.md"), "# Orphaned").unwrap();

        let result = validate_manifest_instructions_cross_refs(&manifest_path, &instructions_dir);
        assert!(matches!(result, Err(ValidationError::CrossReferenceError(_))));
    }
}