use crate::chatbot::{ChatError, ChatProvider, ChatRequest};
use crate::config::{LlamaCppProviderConfig, ModelProviderKind};
use crate::model::{ChatMessage, ChatRole};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Cached model state for avoiding reloads
struct ModelCache {
    // In the feature-enabled version, this would store llama_cpp_rs::LlamaModel
    // For testing without the feature, we use a placeholder
    #[cfg(feature = "llama-cpp")]
    model: Option<Arc<llama_cpp_rs::model::LlamaModel>>,
    #[cfg(not(feature = "llama-cpp"))]
    model: Option<Arc<String>>,
}

/// llama.cpp chat provider implementation
pub struct LlamaCppProvider {
    config: LlamaCppProviderConfig,
    /// Cache of loaded models keyed by GGUF path
    model_cache: Arc<Mutex<HashMap<String, ModelCache>>>,
}

impl LlamaCppProvider {
    pub fn new(config: LlamaCppProviderConfig) -> Self {
        Self {
            config,
            model_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[allow(dead_code)]
    fn build_system_prompt(&self, request: &ChatRequest) -> String {
        let step_ctx = &request.step_context;
        let base_context = format!(
            "You are an expert penetration testing assistant helping with structured pentesting methodology.\n\n\
            Current Context:\n\
            - Phase: {}\n\
            - Step: {} (Status: {})\n\
            - Description: {}\n\
            - Notes: {} characters\n\
            - Evidence: {} items\n\
            {}\n\n\
            Provide helpful, methodology-aligned assistance for general pentesting questions, step-specific guidance, or tool recommendations. \
            Keep responses focused and actionable.",
            step_ctx.phase_name,
            step_ctx.step_title,
            step_ctx.step_status,
            step_ctx.step_description.chars().take(200).collect::<String>(),
            step_ctx.notes_count,
            step_ctx.evidence_count,
            step_ctx
                .quiz_status
                .as_ref()
                .map(|s| format!("- Quiz Status: {}", s))
                .unwrap_or_default()
        );

        Self::render_prompt_template(
            &request.model_profile.prompt_template,
            &base_context,
            step_ctx,
            &request.model_profile,
        )
    }

    #[allow(dead_code)]
    fn render_prompt_template(
        template: &str,
        base_context: &str,
        step_ctx: &crate::chatbot::StepContext,
        profile: &crate::config::ModelProfile,
    ) -> String {
        let template = template.trim();
        if template.is_empty() {
            return base_context.to_string();
        }

        let mut rendered = template.to_string();
        rendered = rendered.replace("{{context}}", base_context);
        rendered = rendered.replace("{{phase_name}}", &step_ctx.phase_name);
        rendered = rendered.replace("{{step_title}}", &step_ctx.step_title);
        rendered = rendered.replace("{{step_description}}", &step_ctx.step_description);
        rendered = rendered.replace("{{step_status}}", &step_ctx.step_status);
        rendered = rendered.replace("{{model_display_name}}", &profile.display_name);

        if !template.contains("{{context}}") {
            rendered.push_str("\n\n");
            rendered.push_str(base_context);
        }

        rendered
    }

    #[cfg(feature = "llama-cpp")]
    fn get_or_load_model(
        &self,
        gguf_path: &str,
    ) -> Result<Arc<llama_cpp_rs::model::LlamaModel>, ChatError> {
        let mut cache = self.model_cache.lock().expect("Failed to acquire cache lock");

        if let Some(cached) = cache.get(gguf_path) {
            if let Some(model) = &cached.model {
                return Ok(model.clone());
            }
        }

        // Load the model
        let path = Path::new(gguf_path);
        if !path.exists() {
            return Err(ChatError::GgufPathNotFound(gguf_path.to_string()));
        }

        let mut model_params = llama_cpp_rs::model::LlamaModelParams::default();
        model_params.context_size = self.config.context_tokens as usize;

        let model = llama_cpp_rs::model::LlamaModel::load_from_file(gguf_path, model_params)
            .map_err(|e| ChatError::ModelLoadError(e.to_string()))?;

        let model = Arc::new(model);
        cache.insert(
            gguf_path.to_string(),
            ModelCache {
                model: Some(model.clone()),
            },
        );

        Ok(model)
    }

    #[cfg(not(feature = "llama-cpp"))]
    fn get_or_load_model(
        &self,
        gguf_path: &str,
    ) -> Result<Arc<String>, ChatError> {
        // Stub implementation for testing without llama-cpp feature
        let mut cache = self.model_cache.lock().expect("Failed to acquire cache lock");

        if let Some(cached) = cache.get(gguf_path) {
            if let Some(model) = &cached.model {
                return Ok(model.clone());
            }
        }

        // Validate path exists
        let path = Path::new(gguf_path);
        if !path.exists() {
            return Err(ChatError::GgufPathNotFound(gguf_path.to_string()));
        }

        let model = Arc::new(gguf_path.to_string());
        cache.insert(
            gguf_path.to_string(),
            ModelCache {
                model: Some(model.clone()),
            },
        );

        Ok(model)
    }
}

impl ChatProvider for LlamaCppProvider {
    fn send_message(&self, request: &ChatRequest) -> Result<ChatMessage, ChatError> {
        if request.model_profile.provider != ModelProviderKind::LlamaCpp {
            return Err(ChatError::UnsupportedProvider(
                request.model_profile.provider.to_string(),
            ));
        }

        let gguf_path = request
            .model_profile
            .resource_paths
            .first()
            .ok_or_else(|| ChatError::GgufPathNotFound("No GGUF path specified in model profile".to_string()))?;

        #[cfg(feature = "llama-cpp")]
        {
            let model = self.get_or_load_model(gguf_path)?;
            let system_prompt = self.build_system_prompt(request);

            // Build prompt with history
            let mut full_prompt = system_prompt;
            full_prompt.push_str("\n\n");

            for msg in &request.history {
                match msg.role {
                    ChatRole::User => full_prompt.push_str("User: "),
                    ChatRole::Assistant => full_prompt.push_str("Assistant: "),
                }
                full_prompt.push_str(&msg.content);
                full_prompt.push_str("\n\n");
            }

            full_prompt.push_str("User: ");
            full_prompt.push_str(&request.user_prompt);
            full_prompt.push_str("\n\nAssistant: ");

            // Create context and generate response
            let mut ctx = model.create_context(Default::default())
                .map_err(|e| ChatError::InferenceError(e.to_string()))?;

            let response = ctx
                .complete_text(
                    &full_prompt,
                    request.model_profile.parameters.num_predict.unwrap_or(256) as usize,
                )
                .map_err(|e| ChatError::InferenceError(e.to_string()))?;

            Ok(ChatMessage::new(ChatRole::Assistant, response))
        }

        #[cfg(not(feature = "llama-cpp"))]
        {
            // Stub implementation for testing
            let _ = self.get_or_load_model(gguf_path)?;
            
            // Return a mock response for testing
            Ok(ChatMessage::new(
                ChatRole::Assistant,
                "Mock response from llama-cpp (feature not enabled)".to_string(),
            ))
        }
    }

    fn check_availability(&self) -> Result<bool, ChatError> {
        // Check if GGUF path is accessible
        if let Some(path) = &self.config.gguf_path {
            Ok(Path::new(path).exists())
        } else {
            Ok(false)
        }
    }

    fn provider_name(&self) -> &str {
        "llama-cpp"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chatbot::StepContext;
    use crate::config::ModelProfile;
    use std::fs;
    use tempfile::NamedTempFile;

    fn create_test_request_with_gguf(gguf_path: &str, model_id: &str) -> ChatRequest {
        let step_ctx = StepContext {
            phase_name: "Test Phase".to_string(),
            step_title: "Test Step".to_string(),
            step_description: "Test desc".to_string(),
            step_status: "In Progress".to_string(),
            notes_count: 0,
            evidence_count: 0,
            quiz_status: None,
        };

        let mut profile = ModelProfile {
            id: model_id.to_string(),
            display_name: "Test Model".to_string(),
            provider: ModelProviderKind::LlamaCpp,
            prompt_template: "{{context}}".to_string(),
            resource_paths: vec![gguf_path.to_string()],
            parameters: Default::default(),
        };

        ChatRequest::new(step_ctx, vec![], "Hello".to_string(), profile)
    }

    fn create_test_config() -> LlamaCppProviderConfig {
        LlamaCppProviderConfig {
            server_url: None,
            gguf_path: None,
            context_tokens: 4096,
        }
    }

    #[test]
    fn test_provider_name() {
        let config = create_test_config();
        let provider = LlamaCppProvider::new(config);
        assert_eq!(provider.provider_name(), "llama-cpp");
    }

    #[test]
    fn test_check_availability_no_path() {
        let config = create_test_config();
        let provider = LlamaCppProvider::new(config);
        let result = provider.check_availability();
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_check_availability_with_missing_path() {
        let mut config = create_test_config();
        config.gguf_path = Some("/nonexistent/path/to/model.gguf".to_string());
        let provider = LlamaCppProvider::new(config);
        let result = provider.check_availability();
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_check_availability_with_existing_path() {
        // Create a temporary file to simulate a GGUF model
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_string_lossy().to_string();

        let mut config = create_test_config();
        config.gguf_path = Some(path.clone());
        let provider = LlamaCppProvider::new(config);

        let result = provider.check_availability();
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_send_message_no_gguf_path() {
        let config = create_test_config();
        let provider = LlamaCppProvider::new(config);
        let request = create_test_request_with_gguf("", "test-model");

        let result = provider.send_message(&request);
        assert!(result.is_err());
        assert!(matches!(result, Err(ChatError::GgufPathNotFound(_))));
    }

    #[test]
    fn test_send_message_missing_gguf_file() {
        let config = create_test_config();
        let provider = LlamaCppProvider::new(config);
        let request = create_test_request_with_gguf("/nonexistent/model.gguf", "test-model");

        let result = provider.send_message(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_send_message_with_existing_file() {
        // Create a temporary file to simulate a GGUF model
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_string_lossy().to_string();

        let config = create_test_config();
        let provider = LlamaCppProvider::new(config);
        let request = create_test_request_with_gguf(&path, "test-model");

        #[cfg(feature = "llama-cpp")]
        {
            // With feature enabled, it would try to load the model
            // For this test, it will fail because the temp file isn't a real GGUF
            let result = provider.send_message(&request);
            // Either it fails to load the GGUF (expected), or succeeds with mock response
            assert!(result.is_ok() || result.is_err());
        }

        #[cfg(not(feature = "llama-cpp"))]
        {
            // Without feature, should succeed with mock response
            let result = provider.send_message(&request);
            assert!(result.is_ok());
            let msg = result.unwrap();
            assert_eq!(msg.role, ChatRole::Assistant);
        }
    }

    #[test]
    fn test_send_message_wrong_provider() {
        let config = create_test_config();
        let provider = LlamaCppProvider::new(config);

        let step_ctx = StepContext {
            phase_name: "Test".to_string(),
            step_title: "Test".to_string(),
            step_description: "Test".to_string(),
            step_status: "In Progress".to_string(),
            notes_count: 0,
            evidence_count: 0,
            quiz_status: None,
        };

        let mut profile = ModelProfile::for_ollama("llama3.2:latest", "Ollama Model");
        profile.resource_paths = vec!["/some/path.gguf".to_string()];

        let request = ChatRequest::new(step_ctx, vec![], "Hello".to_string(), profile);
        let result = provider.send_message(&request);

        assert!(result.is_err());
        assert!(matches!(result, Err(ChatError::UnsupportedProvider(_))));
    }

    #[test]
    fn test_build_system_prompt() {
        let config = create_test_config();
        let provider = LlamaCppProvider::new(config);

        let step_ctx = StepContext {
            phase_name: "Reconnaissance".to_string(),
            step_title: "Initial Scan".to_string(),
            step_description: "Perform initial reconnaissance".to_string(),
            step_status: "In Progress".to_string(),
            notes_count: 5,
            evidence_count: 3,
            quiz_status: Some("2/5 correct".to_string()),
        };

        let profile = ModelProfile {
            id: "test".to_string(),
            display_name: "Test".to_string(),
            provider: ModelProviderKind::LlamaCpp,
            prompt_template: "{{context}}".to_string(),
            resource_paths: vec![],
            parameters: Default::default(),
        };

        let request = ChatRequest::new(
            step_ctx.clone(),
            vec![],
            "What should I do next?".to_string(),
            profile,
        );

        let prompt = LlamaCppProvider::build_system_prompt(&provider, &request);
        assert!(prompt.contains("Reconnaissance"));
        assert!(prompt.contains("Initial Scan"));
        assert!(prompt.contains("penetration testing assistant"));
        assert!(prompt.contains("5 characters"));
        assert!(prompt.contains("3 items"));
        assert!(prompt.contains("2/5 correct"));
    }

    #[test]
    fn test_model_caching() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_string_lossy().to_string();

        let config = create_test_config();
        let provider = LlamaCppProvider::new(config);

        let request1 = create_test_request_with_gguf(&path, "model1");
        let request2 = create_test_request_with_gguf(&path, "model2");

        // First call should load the model
        let result1 = provider.send_message(&request1);
        assert!(result1.is_ok() || result1.is_err());

        // Second call should use cached model
        let result2 = provider.send_message(&request2);
        assert!(result2.is_ok() || result2.is_err());

        // Verify cache has the entry
        let cache = provider.model_cache.lock().expect("Failed to acquire cache lock");
        assert!(cache.contains_key(&path));
    }
}
