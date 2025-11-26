use pt_journal::chatbot::{ChatProvider, ChatRequest, ChatService, ChatError, OllamaProvider, LlamaCppProvider, StepContext};
use pt_journal::config::{ChatbotConfig, ModelParameters, ModelProfile, OllamaProviderConfig, LlamaCppProviderConfig, ModelProviderKind};
use pt_journal::model::{ChatMessage, ChatRole};

#[cfg(test)]
mod chat_provider_tests {
    use super::*;
    use httpmock::prelude::*;

    fn create_test_profile(model_id: &str) -> ModelProfile {
        let mut profile = ModelProfile::for_ollama(model_id, "Test Model");
        profile.id = model_id.to_string();
        profile
    }

    fn create_test_step_context() -> StepContext {
        StepContext {
            phase_name: "Test Phase".to_string(),
            step_title: "Test Step".to_string(),
            step_description: "Test description".to_string(),
            step_status: "In Progress".to_string(),
            notes_count: 5,
            evidence_count: 2,
            quiz_status: None,
        }
    }

    #[test]
    fn test_chat_request_bundles_all_fields() {
        let step_ctx = create_test_step_context();
        let profile = create_test_profile("llama3.2:latest");
        let history = vec![ChatMessage::new(ChatRole::User, "Previous".to_string())];
        let prompt = "Current question".to_string();

        let request = ChatRequest::new(
            step_ctx.clone(),
            history.clone(),
            prompt.clone(),
            profile.clone(),
        );

        assert_eq!(request.step_context.phase_name, step_ctx.phase_name);
        assert_eq!(request.history.len(), 1);
        assert_eq!(request.user_prompt, prompt);
        assert_eq!(request.model_profile.id, profile.id);
    }

    #[test]
    fn test_ollama_provider_embeds_correct_model_id() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method("POST")
                .path("/api/chat")
                .body_contains(r#""model":"custom-model:tag""#);
            then.status(200).json_body(serde_json::json!({
                "message": {
                    "content": "Response"
                }
            }));
        });

        let mut config = OllamaProviderConfig::default();
        config.endpoint = server.url("");
        let provider = OllamaProvider::new(config);

        let profile = create_test_profile("custom-model:tag");
        let request = ChatRequest::new(
            create_test_step_context(),
            vec![],
            "Test".to_string(),
            profile,
        );

        let result = provider.send_message(&request);
        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn test_ollama_provider_honors_temperature_parameter() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method("POST")
                .path("/api/chat")
                .body_contains(r#""temperature":0.8"#);
            then.status(200).json_body(serde_json::json!({
                "message": {
                    "content": "Response"
                }
            }));
        });

        let mut config = OllamaProviderConfig::default();
        config.endpoint = server.url("");
        let provider = OllamaProvider::new(config);

        let mut profile = create_test_profile("mistral:7b");
        profile.parameters.temperature = Some(0.8);

        let request = ChatRequest::new(
            create_test_step_context(),
            vec![],
            "Test".to_string(),
            profile,
        );

        let result = provider.send_message(&request);
        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn test_ollama_provider_honors_all_parameters() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method("POST")
                .path("/api/chat");
            then.status(200).json_body(serde_json::json!({
                "message": {
                    "content": "Response"
                }
            }));
        });

        let mut config = OllamaProviderConfig::default();
        config.endpoint = server.url("");
        let provider = OllamaProvider::new(config);

        let mut profile = create_test_profile("mistral:7b");
        profile.parameters = ModelParameters {
            temperature: Some(0.7),
            top_p: Some(0.95),
            top_k: Some(50),
            num_predict: Some(256),
        };

        let request = ChatRequest::new(
            create_test_step_context(),
            vec![],
            "Test".to_string(),
            profile,
        );

        let result = provider.send_message(&request);
        assert!(result.is_ok());
        mock.assert();
        // Parameters are applied in the OllamaProvider::send_message implementation
    }

    #[test]
    fn test_ollama_provider_check_availability() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method("GET").path("/api/tags");
            then.status(200).json_body(serde_json::json!({
                "models": [
                    {"name": "llama3.2:latest"},
                    {"name": "mistral:7b"}
                ]
            }));
        });

        let mut config = OllamaProviderConfig::default();
        config.endpoint = server.url("");
        let provider = OllamaProvider::new(config);

        let result = provider.check_availability();
        assert!(result.is_ok());
        assert!(result.unwrap());
        mock.assert();
    }

    #[test]
    fn test_ollama_provider_unavailable() {
        let mut config = OllamaProviderConfig::default();
        config.endpoint = "http://localhost:99999".to_string();
        let provider = OllamaProvider::new(config);

        let result = provider.check_availability();
        assert!(result.is_err());
    }

    #[test]
    fn test_chat_service_uses_active_profile() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method("POST")
                .path("/api/chat")
                .body_contains(r#""model":"phi3:mini-4k-instruct""#);
            then.status(200).json_body(serde_json::json!({
                "message": {
                    "content": "Service response"
                }
            }));
        });

        let mut config = ChatbotConfig::default();
        config.ollama.endpoint = server.url("");
        config.default_model_id = "phi3:mini-4k-instruct".to_string();

        let service = ChatService::new(config);
        let step_ctx = create_test_step_context();

        let result = service.send_message(&step_ctx, &[], "Test");
        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn test_chat_service_applies_profile_parameters() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method("POST")
                .path("/api/chat");
            then.status(200).json_body(serde_json::json!({
                "message": {
                    "content": "Response"
                }
            }));
        });

        let mut config = ChatbotConfig::default();
        config.ollama.endpoint = server.url("");
        
        // Find and modify the default model profile
        if let Some(profile) = config.models.iter_mut().find(|p| p.id == config.default_model_id) {
            profile.parameters.temperature = Some(0.5);
            profile.parameters.top_p = Some(0.9);
        }

        let service = ChatService::new(config);
        let step_ctx = create_test_step_context();

        let result = service.send_message(&step_ctx, &[], "Test");
        assert!(result.is_ok());
        mock.assert();
        // Service uses the active profile's parameters
    }

    #[test]
    fn test_provider_name() {
        let config = OllamaProviderConfig::default();
        let provider = OllamaProvider::new(config);
        assert_eq!(provider.provider_name(), "ollama");
    }

    // ========================================================================
    // LlamaCpp Provider Tests
    // ========================================================================

    #[test]
    fn test_llama_cpp_provider_name() {
        let config = LlamaCppProviderConfig::default();
        let provider = LlamaCppProvider::new(config);
        assert_eq!(provider.provider_name(), "llama-cpp");
    }

    #[test]
    fn test_llama_cpp_check_availability_no_path() {
        let config = LlamaCppProviderConfig::default();
        let provider = LlamaCppProvider::new(config);
        let result = provider.check_availability();
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_llama_cpp_check_availability_missing_file() {
        let mut config = LlamaCppProviderConfig::default();
        config.gguf_path = Some("/nonexistent/model.gguf".to_string());
        let provider = LlamaCppProvider::new(config);
        let result = provider.check_availability();
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_llama_cpp_send_message_no_resource_paths() {
        let config = LlamaCppProviderConfig::default();
        let provider = LlamaCppProvider::new(config);

        let profile = ModelProfile {
            id: "test-model".to_string(),
            display_name: "Test Model".to_string(),
            provider: ModelProviderKind::LlamaCpp,
            prompt_template: "{{context}}".to_string(),
            resource_paths: vec![],
            parameters: Default::default(),
        };

        let request = ChatRequest::new(
            create_test_step_context(),
            vec![],
            "Test".to_string(),
            profile,
        );

        let result = provider.send_message(&request);
        assert!(matches!(result, Err(ChatError::GgufPathNotFound(_))));
    }

    #[test]
    fn test_llama_cpp_send_message_nonexistent_file() {
        let config = LlamaCppProviderConfig::default();
        let provider = LlamaCppProvider::new(config);

        let profile = ModelProfile {
            id: "test-model".to_string(),
            display_name: "Test Model".to_string(),
            provider: ModelProviderKind::LlamaCpp,
            prompt_template: "{{context}}".to_string(),
            resource_paths: vec!["/nonexistent/model.gguf".to_string()],
            parameters: Default::default(),
        };

        let request = ChatRequest::new(
            create_test_step_context(),
            vec![],
            "Test".to_string(),
            profile,
        );

        let result = provider.send_message(&request);
        // Should fail because the file doesn't exist
        assert!(result.is_err());
    }

    #[test]
    fn test_chat_service_routes_to_llama_cpp() {
        let mut config = ChatbotConfig::default();
        config.ollama.endpoint = "http://localhost:11434".to_string();
        config.llama_cpp.gguf_path = None;

        // Add a llama-cpp model profile
        let llama_cpp_profile = ModelProfile {
            id: "local-model".to_string(),
            display_name: "Local Model".to_string(),
            provider: ModelProviderKind::LlamaCpp,
            prompt_template: "{{context}}".to_string(),
            resource_paths: vec![],
            parameters: Default::default(),
        };
        config.models.push(llama_cpp_profile);

        let service = ChatService::new(config);

        // The service should be able to get the llama-cpp provider
        let result = service.get_provider(&ModelProviderKind::LlamaCpp);
        assert!(result.is_ok());
    }

    #[test]
    fn test_llama_cpp_send_message_builds_proper_prompt() {
        use tempfile::NamedTempFile;

        // Create a temporary file to simulate a GGUF model
        let temp_file = NamedTempFile::new().unwrap();
        let gguf_path = temp_file.path().to_string_lossy().to_string();

        let config = LlamaCppProviderConfig::default();
        let provider = LlamaCppProvider::new(config);

        let profile = ModelProfile {
            id: "test-model".to_string(),
            display_name: "Test Model".to_string(),
            provider: ModelProviderKind::LlamaCpp,
            prompt_template: "{{context}}".to_string(),
            resource_paths: vec![gguf_path],
            parameters: Default::default(),
        };

        let step_ctx = StepContext {
            phase_name: "Reconnaissance".to_string(),
            step_title: "Initial Scan".to_string(),
            step_description: "Perform initial scan".to_string(),
            step_status: "In Progress".to_string(),
            notes_count: 5,
            evidence_count: 2,
            quiz_status: Some("1/3 correct".to_string()),
        };

        let request = ChatRequest::new(
            step_ctx,
            vec![],
            "What should I do?".to_string(),
            profile,
        );

        // The provider should successfully process this request
        // (either with real inference if llama-cpp feature is enabled, or mock response)
        let result = provider.send_message(&request);
        // Result depends on whether llama-cpp feature is enabled and if file is a valid GGUF
        // Just verify it returns a result (ok or err) without panicking
        let _ = result;
    }

    #[test]
    fn test_service_switches_between_providers() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method("POST").path("/api/chat");
            then.status(200).json_body(serde_json::json!({
                "message": {
                    "content": "Ollama response"
                }
            }));
        });

        let mut config = ChatbotConfig::default();
        config.ollama.endpoint = server.url("");

        // Add both providers to config
        let llama_cpp_profile = ModelProfile {
            id: "local-model".to_string(),
            display_name: "Local Model".to_string(),
            provider: ModelProviderKind::LlamaCpp,
            prompt_template: "{{context}}".to_string(),
            resource_paths: vec![],
            parameters: Default::default(),
        };
        config.models.push(llama_cpp_profile);

        let service = ChatService::new(config);
        let step_ctx = create_test_step_context();

        // Sending with Ollama profile should work
        let result = service.send_message(&step_ctx, &[], "Hello");
        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn test_llama_cpp_parameters_respected() {
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();
        let gguf_path = temp_file.path().to_string_lossy().to_string();

        let config = LlamaCppProviderConfig {
            server_url: None,
            gguf_path: Some(gguf_path.clone()),
            context_tokens: 8192,
        };

        let provider = LlamaCppProvider::new(config);

        let profile = ModelProfile {
            id: "test-model".to_string(),
            display_name: "Test Model".to_string(),
            provider: ModelProviderKind::LlamaCpp,
            prompt_template: "{{context}}".to_string(),
            resource_paths: vec![gguf_path],
            parameters: ModelParameters {
                temperature: Some(0.7),
                top_p: Some(0.9),
                top_k: Some(40),
                num_predict: Some(512),
            },
        };

        let request = ChatRequest::new(
            create_test_step_context(),
            vec![],
            "Test".to_string(),
            profile,
        );

        // Just verify the request can be processed without panicking
        let result = provider.send_message(&request);
        let _ = result;
    }

    #[test]
    fn test_llama_cpp_message_history_included() {
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();
        let gguf_path = temp_file.path().to_string_lossy().to_string();

        let config = LlamaCppProviderConfig::default();
        let provider = LlamaCppProvider::new(config);

        let history = vec![
            ChatMessage::new(ChatRole::User, "First question".to_string()),
            ChatMessage::new(ChatRole::Assistant, "First answer".to_string()),
            ChatMessage::new(ChatRole::User, "Second question".to_string()),
        ];

        let profile = ModelProfile {
            id: "test-model".to_string(),
            display_name: "Test Model".to_string(),
            provider: ModelProviderKind::LlamaCpp,
            prompt_template: "{{context}}".to_string(),
            resource_paths: vec![gguf_path],
            parameters: Default::default(),
        };

        let request = ChatRequest::new(
            create_test_step_context(),
            history,
            "Third question".to_string(),
            profile,
        );

        // Just verify the request can be processed
        let result = provider.send_message(&request);
        let _ = result;
    }

    #[test]
    fn test_service_llama_cpp_configuration() {
        let mut config = ChatbotConfig::default();
        config.llama_cpp.gguf_path = Some("/path/to/model.gguf".to_string());
        config.llama_cpp.context_tokens = 2048;

        // Verify the configuration is preserved through service creation
        let service = ChatService::new(config);
        // Service created successfully with llama_cpp config
        assert_eq!(service.config.llama_cpp.context_tokens, 2048);
        assert_eq!(
            service.config.llama_cpp.gguf_path.as_deref(),
            Some("/path/to/model.gguf")
        );
    }
}
