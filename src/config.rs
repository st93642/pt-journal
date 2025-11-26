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
use std::path::{Path, PathBuf};

const DEFAULT_PROMPT_TEMPLATE: &str = "{{context}}";
const DEFAULT_MODEL_ID: &str = "llama3.2:latest";
const DEFAULT_OLLAMA_ENDPOINT: &str = "http://localhost:11434";
const DEFAULT_OLLAMA_TIMEOUT: u64 = 180;
const DEFAULT_LLAMA_CPP_CONTEXT: u32 = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatbotConfig {
    #[serde(default = "default_chatbot_model_id")]
    pub default_model_id: String,

    #[serde(default = "default_model_profiles")]
    pub models: Vec<ModelProfile>,

    #[serde(default)]
    pub ollama: OllamaProviderConfig,

    #[serde(default)]
    pub llama_cpp: LlamaCppProviderConfig,

    #[serde(skip_serializing, default, alias = "endpoint")]
    legacy_endpoint: Option<String>,

    #[serde(skip_serializing, default, alias = "model")]
    legacy_model: Option<String>,

    #[serde(skip_serializing, default, alias = "timeout_seconds")]
    legacy_timeout_seconds: Option<u64>,
}

impl Default for ChatbotConfig {
    fn default() -> Self {
        Self {
            default_model_id: default_chatbot_model_id(),
            models: default_model_profiles(),
            ollama: OllamaProviderConfig::default(),
            llama_cpp: LlamaCppProviderConfig::default(),
            legacy_endpoint: None,
            legacy_model: None,
            legacy_timeout_seconds: None,
        }
    }
}

impl ChatbotConfig {
    pub fn ensure_valid(&mut self) {
        self.normalize();
    }

    pub fn active_model(&self) -> &ModelProfile {
        self
            .models
            .iter()
            .find(|profile| profile.id == self.default_model_id)
            .or_else(|| self.models.first())
            .expect("Chatbot configuration must include at least one model")
    }

    fn normalize(&mut self) {
        if let Some(endpoint) = self.legacy_endpoint.take() {
            self.ollama.endpoint = endpoint;
        }
        if let Some(timeout) = self.legacy_timeout_seconds.take() {
            self.ollama.timeout_seconds = timeout;
        }

        let mut migrated_model_id = None;
        if let Some(model) = self.legacy_model.take() {
            if !model.trim().is_empty() {
                self.default_model_id = model.clone();
                migrated_model_id = Some(model);
            }
        }

        if self.models.is_empty() {
            self.models = default_model_profiles();
        }

        if let Some(legacy_id) = migrated_model_id {
            self.ensure_model_present(&legacy_id);
        }

        let default_id = self.default_model_id.clone();
        self.ensure_model_present(default_id.as_str());

        if self.default_model_id.trim().is_empty()
            || !self
                .models
                .iter()
                .any(|profile| profile.id == self.default_model_id)
        {
            self.default_model_id = self
                .models
                .first()
                .map(|profile| profile.id.clone())
                .unwrap_or_else(default_chatbot_model_id);
        }
    }

    fn ensure_model_present(&mut self, model_id: &str) {
        if model_id.trim().is_empty() {
            return;
        }

        let exists = self.models.iter().any(|profile| profile.id == model_id);
        if !exists {
            self.models
                .push(ModelProfile::for_ollama(model_id, model_id));
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelProfile {
    pub id: String,
    pub display_name: String,
    pub provider: ModelProviderKind,
    #[serde(default = "default_prompt_template")]
    pub prompt_template: String,
    #[serde(default)]
    pub resource_paths: Vec<String>,
}

impl ModelProfile {
    pub fn for_ollama(id: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            display_name: display_name.into(),
            provider: ModelProviderKind::Ollama,
            prompt_template: default_prompt_template(),
            resource_paths: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ModelProviderKind {
    Ollama,
    LlamaCpp,
}

impl std::fmt::Display for ModelProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelProviderKind::Ollama => write!(f, "ollama"),
            ModelProviderKind::LlamaCpp => write!(f, "llama-cpp"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaProviderConfig {
    #[serde(default = "default_ollama_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_ollama_timeout")]
    pub timeout_seconds: u64,
}

impl Default for OllamaProviderConfig {
    fn default() -> Self {
        Self {
            endpoint: default_ollama_endpoint(),
            timeout_seconds: default_ollama_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlamaCppProviderConfig {
    #[serde(default)]
    pub server_url: Option<String>,
    #[serde(default)]
    pub gguf_path: Option<String>,
    #[serde(default = "default_llama_cpp_context_tokens")]
    pub context_tokens: u32,
}

impl Default for LlamaCppProviderConfig {
    fn default() -> Self {
        Self {
            server_url: None,
            gguf_path: None,
            context_tokens: default_llama_cpp_context_tokens(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub chatbot: ChatbotConfig,
}

impl AppConfig {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let config_path = Self::config_file_path();
        let mut config = if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            toml::from_str(&content)?
        } else {
            AppConfig::default()
        };

        config.chatbot.ensure_valid();
        config.apply_env_overrides();
        config.chatbot.ensure_valid();

        Ok(config)
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_path = Self::config_file_path();
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        fs::write(config_path, content)?;
        Ok(())
    }

    pub fn load_from_path(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = if path.exists() {
            let content = fs::read_to_string(path)?;
            toml::from_str(&content)?
        } else {
            AppConfig::default()
        };
        config.chatbot.ensure_valid();
        Ok(config)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(model_id) = env::var("PT_JOURNAL_CHATBOT_MODEL_ID") {
            self.chatbot.default_model_id = model_id;
        } else if let Ok(model_id) = env::var("PT_JOURNAL_OLLAMA_MODEL") {
            self.chatbot.default_model_id = model_id;
        }

        if let Ok(endpoint) = env::var("PT_JOURNAL_OLLAMA_ENDPOINT") {
            self.chatbot.ollama.endpoint = endpoint;
        }

        if let Ok(timeout_str) = env::var("PT_JOURNAL_OLLAMA_TIMEOUT_SECONDS") {
            if let Ok(timeout) = timeout_str.parse::<u64>() {
                self.chatbot.ollama.timeout_seconds = timeout;
            }
        }

        if let Ok(path) = env::var("PT_JOURNAL_LLAMA_CPP_GGUF_PATH") {
            self.chatbot.llama_cpp.gguf_path = Some(path);
        }

        if let Ok(context_size) = env::var("PT_JOURNAL_LLAMA_CPP_CONTEXT_SIZE") {
            if let Ok(tokens) = context_size.parse::<u32>() {
                self.chatbot.llama_cpp.context_tokens = tokens;
            }
        }

        if let Ok(url) = env::var("PT_JOURNAL_LLAMA_CPP_SERVER_URL") {
            self.chatbot.llama_cpp.server_url = Some(url);
        }
    }

    fn config_file_path() -> PathBuf {
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

fn default_prompt_template() -> String {
    DEFAULT_PROMPT_TEMPLATE.to_string()
}

fn default_chatbot_model_id() -> String {
    DEFAULT_MODEL_ID.to_string()
}

fn default_model_profiles() -> Vec<ModelProfile> {
    vec![
        ModelProfile::for_ollama("llama3.2:latest", "Meta Llama 3.2"),
        ModelProfile::for_ollama("mistral:7b", "Mistral 7B Instruct"),
        ModelProfile::for_ollama("phi3:mini-4k-instruct", "Phi-3 Mini 4K"),
        ModelProfile::for_ollama("neural-chat:latest", "Intel Neural Chat"),
        ModelProfile::for_ollama("starcoder:latest", "StarCoder"),
    ]
}

fn default_ollama_endpoint() -> String {
    DEFAULT_OLLAMA_ENDPOINT.to_string()
}

fn default_ollama_timeout() -> u64 {
    DEFAULT_OLLAMA_TIMEOUT
}

fn default_llama_cpp_context_tokens() -> u32 {
    DEFAULT_LLAMA_CPP_CONTEXT
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::TempDir;

    fn clear_chatbot_env() {
        env::remove_var("PT_JOURNAL_CHATBOT_MODEL_ID");
        env::remove_var("PT_JOURNAL_OLLAMA_MODEL");
        env::remove_var("PT_JOURNAL_OLLAMA_ENDPOINT");
        env::remove_var("PT_JOURNAL_OLLAMA_TIMEOUT_SECONDS");
        env::remove_var("PT_JOURNAL_LLAMA_CPP_GGUF_PATH");
        env::remove_var("PT_JOURNAL_LLAMA_CPP_CONTEXT_SIZE");
        env::remove_var("PT_JOURNAL_LLAMA_CPP_SERVER_URL");
    }

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.chatbot.default_model_id, "llama3.2:latest");
        assert!(config
            .chatbot
            .models
            .iter()
            .any(|profile| profile.id == config.chatbot.default_model_id));
        assert_eq!(config.chatbot.ollama.endpoint, "http://localhost:11434");
        assert_eq!(config.chatbot.ollama.timeout_seconds, 180);
        assert!(config.chatbot.models.len() >= 5);
    }

    #[test]
    fn test_config_file_path() {
        let path = AppConfig::config_file_path();
        assert!(path.to_string_lossy().contains("pt-journal"));
        assert!(path.to_string_lossy().contains("config.toml"));
    }

    #[test]
    fn test_load_nonexistent_config() {
        let temp_dir = TempDir::new().unwrap();
        let original_xdg = env::var("XDG_CONFIG_HOME");
        env::set_var("XDG_CONFIG_HOME", temp_dir.path());
        clear_chatbot_env();

        let config = AppConfig::load().unwrap();
        assert_eq!(config.chatbot.default_model_id, "llama3.2:latest");
        assert_eq!(config.chatbot.ollama.endpoint, "http://localhost:11434");

        if let Ok(original) = original_xdg {
            env::set_var("XDG_CONFIG_HOME", original);
        } else {
            env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn test_save_and_load_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        let mut config = AppConfig::default();
        config.chatbot.default_model_id = "mistral:7b".to_string();
        config.chatbot.ollama.endpoint = "http://custom:8080".to_string();
        config.chatbot.llama_cpp.gguf_path = Some("/models/custom.gguf".to_string());

        config.save_to_path(&config_path).unwrap();
        let loaded = AppConfig::load_from_path(&config_path).unwrap();

        assert_eq!(loaded.chatbot.default_model_id, "mistral:7b");
        assert_eq!(loaded.chatbot.ollama.endpoint, "http://custom:8080");
        assert_eq!(
            loaded.chatbot.llama_cpp.gguf_path.as_deref(),
            Some("/models/custom.gguf")
        );
    }

    #[test]
    fn test_environment_override() {
        let temp_dir = TempDir::new().unwrap();
        let original_xdg = env::var("XDG_CONFIG_HOME");
        env::set_var("XDG_CONFIG_HOME", temp_dir.path());

        clear_chatbot_env();
        env::set_var("PT_JOURNAL_CHATBOT_MODEL_ID", "phi3:mini-4k-instruct");
        env::set_var("PT_JOURNAL_OLLAMA_MODEL", "mistral:7b");
        env::set_var("PT_JOURNAL_OLLAMA_ENDPOINT", "http://env:9090");
        env::set_var("PT_JOURNAL_OLLAMA_TIMEOUT_SECONDS", "90");
        env::set_var("PT_JOURNAL_LLAMA_CPP_GGUF_PATH", "/models/phi3.gguf");
        env::set_var("PT_JOURNAL_LLAMA_CPP_CONTEXT_SIZE", "8192");

        let config = AppConfig::load().unwrap();
        assert_eq!(config.chatbot.default_model_id, "phi3:mini-4k-instruct");
        assert_eq!(config.chatbot.ollama.endpoint, "http://env:9090");
        assert_eq!(config.chatbot.ollama.timeout_seconds, 90);
        assert_eq!(
            config.chatbot.llama_cpp.gguf_path.as_deref(),
            Some("/models/phi3.gguf")
        );
        assert_eq!(config.chatbot.llama_cpp.context_tokens, 8192);

        clear_chatbot_env();
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

        let mut config = AppConfig::default();
        config.chatbot.default_model_id = "neural-chat:latest".to_string();
        config.chatbot.ollama.endpoint = "http://file:7070".to_string();
        config.chatbot.ollama.timeout_seconds = 45;
        config.save().unwrap();

        clear_chatbot_env();
        env::set_var("PT_JOURNAL_CHATBOT_MODEL_ID", "starcoder2:latest");
        env::set_var("PT_JOURNAL_OLLAMA_ENDPOINT", "http://env:6060");
        env::set_var("PT_JOURNAL_OLLAMA_TIMEOUT_SECONDS", "120");

        let loaded = AppConfig::load().unwrap();
        assert_eq!(loaded.chatbot.default_model_id, "starcoder2:latest");
        assert_eq!(loaded.chatbot.ollama.endpoint, "http://env:6060");
        assert_eq!(loaded.chatbot.ollama.timeout_seconds, 120);

        clear_chatbot_env();
        if let Ok(original) = original_xdg {
            env::set_var("XDG_CONFIG_HOME", original);
        } else {
            env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn test_legacy_config_migration() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("legacy.toml");
        let legacy = r#"
[chatbot]
endpoint = "http://legacy:11434"
model = "neural-chat:latest"
timeout_seconds = 42
"#;
        fs::write(&config_path, legacy).unwrap();

        let config = AppConfig::load_from_path(&config_path).unwrap();
        assert_eq!(config.chatbot.ollama.endpoint, "http://legacy:11434");
        assert_eq!(config.chatbot.default_model_id, "neural-chat:latest");
        assert_eq!(config.chatbot.ollama.timeout_seconds, 42);
        assert!(config
            .chatbot
            .models
            .iter()
            .any(|profile| profile.id == "neural-chat:latest"));
    }

    #[test]
    fn test_default_model_validation() {
        let mut chatbot = ChatbotConfig {
            default_model_id: String::new(),
            models: Vec::new(),
            ollama: OllamaProviderConfig::default(),
            llama_cpp: LlamaCppProviderConfig::default(),
            legacy_endpoint: None,
            legacy_model: None,
            legacy_timeout_seconds: None,
        };
        chatbot.ensure_valid();
        assert!(!chatbot.models.is_empty());
        assert!(!chatbot.default_model_id.is_empty());
    }
}
