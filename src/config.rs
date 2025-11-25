/*****************************************************************************/
/*                                                                           */
/*  config.rs                                            TTTTTTTT SSSSSSS II */
/*                                                          TT    SS      II */
/*  By: st93642@students.tsi.lv                             TT    SSSSSSS II */
/*                                                          TT         SS II */
/*  Created: Nov 25 2025 14:30 st93642                      TT    SSSSSSS II */
/*  Updated: Nov 25 2025 20:40 st93642                                       */
/*                                                                           */
/*   Transport and Telecommunication Institute - Riga, Latvia                */
/*                       https://tsi.lv                                      */
/*****************************************************************************/

use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatbotConfig {
    pub endpoint: String,
    pub model: String,
    pub timeout_seconds: u64,
}

impl Default for ChatbotConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:11434".to_string(),
            model: "llama3.2:latest".to_string(),
            timeout_seconds: 180, // Increased to 3 minutes for complex queries
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub chatbot: ChatbotConfig,
}

impl AppConfig {
    /// Load configuration from file and environment variables
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let config_path = Self::config_file_path();
        let mut config = if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            toml::from_str(&content)?
        } else {
            AppConfig::default()
        };

        // Override with environment variables if set
        if let Ok(endpoint) = env::var("PT_JOURNAL_OLLAMA_ENDPOINT") {
            config.chatbot.endpoint = endpoint;
        }
        if let Ok(model) = env::var("PT_JOURNAL_OLLAMA_MODEL") {
            config.chatbot.model = model;
        }
        if let Ok(timeout_str) = env::var("PT_JOURNAL_OLLAMA_TIMEOUT_SECONDS") {
            if let Ok(timeout) = timeout_str.parse::<u64>() {
                config.chatbot.timeout_seconds = timeout;
            }
        }

        Ok(config)
    }

    /// Save configuration to file
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_path = Self::config_file_path();
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        fs::write(config_path, content)?;
        Ok(())
    }

    /// Load configuration from a specific path
    pub fn load_from_path(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if path.exists() {
            let content = fs::read_to_string(path)?;
            toml::from_str(&content).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        } else {
            Ok(AppConfig::default())
        }
    }

    /// Save configuration to a specific path
    pub fn save_to_path(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content =
            toml::to_string_pretty(self).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Get the configuration file path
    fn config_file_path() -> PathBuf {
        // Use XDG_CONFIG_HOME if available, otherwise ~/.config
        let config_dir = env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs::home_dir()
                    .expect("Could not determine home directory")
                    .join(".config")
            });
        config_dir.join("pt-journal").join("config.toml")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.chatbot.endpoint, "http://localhost:11434");
        assert_eq!(config.chatbot.model, "llama3.2:latest");
        assert_eq!(config.chatbot.timeout_seconds, 180);
    }

    #[test]
    fn test_config_file_path() {
        let path = AppConfig::config_file_path();
        assert!(path.to_string_lossy().contains("pt-journal"));
        assert!(path.to_string_lossy().contains("config.toml"));
    }

    #[test]
    fn test_load_nonexistent_config() {
        // Temporarily change XDG_CONFIG_HOME to a temp directory
        let temp_dir = TempDir::new().unwrap();
        let original_xdg = env::var("XDG_CONFIG_HOME");
        let original_endpoint = env::var("PT_JOURNAL_OLLAMA_ENDPOINT");
        let original_model = env::var("PT_JOURNAL_OLLAMA_MODEL");
        
        env::set_var("XDG_CONFIG_HOME", temp_dir.path());
        // Clear any existing environment variables
        env::remove_var("PT_JOURNAL_OLLAMA_ENDPOINT");
        env::remove_var("PT_JOURNAL_OLLAMA_MODEL");

        // Ensure environment variables are cleared right before loading
        assert!(env::var("PT_JOURNAL_OLLAMA_ENDPOINT").is_err());
        assert!(env::var("PT_JOURNAL_OLLAMA_MODEL").is_err());

        let config = AppConfig::load().unwrap();
        assert_eq!(config.chatbot.endpoint, "http://localhost:11434");
        assert_eq!(config.chatbot.model, "llama3.2:latest");

        // Restore original values
        if let Ok(original) = original_xdg {
            env::set_var("XDG_CONFIG_HOME", original);
        } else {
            env::remove_var("XDG_CONFIG_HOME");
        }
        if let Ok(original) = original_endpoint {
            env::set_var("PT_JOURNAL_OLLAMA_ENDPOINT", original);
        }
        if let Ok(original) = original_model {
            env::set_var("PT_JOURNAL_OLLAMA_MODEL", original);
        }
    }

    #[test]
    fn test_save_and_load_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        let mut config = AppConfig::default();
        config.chatbot.endpoint = "http://custom:8080".to_string();
        config.chatbot.model = "llama2".to_string();
        config.chatbot.timeout_seconds = 120;

        config.save_to_path(&config_path).unwrap();
        let loaded = AppConfig::load_from_path(&config_path).unwrap();

        assert_eq!(loaded.chatbot.endpoint, "http://custom:8080");
        assert_eq!(loaded.chatbot.model, "llama2");
        assert_eq!(loaded.chatbot.timeout_seconds, 120);
    }

    #[test]
    fn test_environment_override() {
        let temp_dir = TempDir::new().unwrap();
        let original_xdg = env::var("XDG_CONFIG_HOME");
        env::set_var("XDG_CONFIG_HOME", temp_dir.path());

        // Set environment variables
        env::set_var("PT_JOURNAL_OLLAMA_ENDPOINT", "http://env:9090");
        env::set_var("PT_JOURNAL_OLLAMA_MODEL", "env-model");
        env::set_var("PT_JOURNAL_OLLAMA_TIMEOUT_SECONDS", "90");

        let config = AppConfig::load().unwrap();
        assert_eq!(config.chatbot.endpoint, "http://env:9090");
        assert_eq!(config.chatbot.model, "env-model");
        assert_eq!(config.chatbot.timeout_seconds, 90);

        // Clean up
        env::remove_var("PT_JOURNAL_OLLAMA_ENDPOINT");
        env::remove_var("PT_JOURNAL_OLLAMA_MODEL");
        env::remove_var("PT_JOURNAL_OLLAMA_TIMEOUT_SECONDS");
        if let Ok(original) = original_xdg {
            env::set_var("XDG_CONFIG_HOME", original);
        } else {
            env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn test_config_file_override_env() {
        let temp_dir = TempDir::new().unwrap();
        let original_xdg = env::var("XDG_CONFIG_HOME");
        env::set_var("XDG_CONFIG_HOME", temp_dir.path());

        // Save config with file values
        let mut config = AppConfig::default();
        config.chatbot.endpoint = "http://file:7070".to_string();
        config.chatbot.model = "file-model".to_string();
        config.chatbot.timeout_seconds = 45;
        config.save().unwrap();

        // Set environment variables that should override
        env::set_var("PT_JOURNAL_OLLAMA_ENDPOINT", "http://env:9090");
        env::set_var("PT_JOURNAL_OLLAMA_MODEL", "env-model");
        env::set_var("PT_JOURNAL_OLLAMA_TIMEOUT_SECONDS", "120");

        let loaded = AppConfig::load().unwrap();
        assert_eq!(loaded.chatbot.endpoint, "http://env:9090");
        assert_eq!(loaded.chatbot.model, "env-model");
        assert_eq!(loaded.chatbot.timeout_seconds, 120);

        // Clean up
        env::remove_var("PT_JOURNAL_OLLAMA_ENDPOINT");
        env::remove_var("PT_JOURNAL_OLLAMA_MODEL");
        env::remove_var("PT_JOURNAL_OLLAMA_TIMEOUT_SECONDS");
        if let Ok(original) = original_xdg {
            env::set_var("XDG_CONFIG_HOME", original);
        } else {
            env::remove_var("XDG_CONFIG_HOME");
        }
    }
}
