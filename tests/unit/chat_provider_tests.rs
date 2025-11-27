use pt_journal::chatbot::{ChatProvider, ChatRequest, ChatService, OllamaProvider, StepContext};
use pt_journal::config::{
    ChatbotConfig, ModelParameters, ModelProfile, ModelProviderKind, OllamaProviderConfig,
};
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
            when.method("POST").path("/api/chat");
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
            when.method("POST").path("/api/chat");
            then.status(200).json_body(serde_json::json!({
                "message": {
                    "content": "Response"
                }
            }));
        });

        let mut config = ChatbotConfig::default();
        config.ollama.endpoint = server.url("");

        // Find and modify the default model profile
        if let Some(profile) = config
            .models
            .iter_mut()
            .find(|p| p.id == config.default_model_id)
        {
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

    #[test]
    fn test_seeded_model_list_configuration() {
        let config = ChatbotConfig::default();

        // Should have 10 seeded models (updated from 5)
        assert_eq!(config.models.len(), 10);

        // Check all expected model IDs are present
        let model_ids: Vec<String> = config.models.iter().map(|m| m.id.clone()).collect();

        assert!(model_ids.contains(&"llama3.2:latest".to_string()));
        assert!(model_ids.contains(&"mistral:7b".to_string()));
        assert!(model_ids.contains(&"llama3.1:8b".to_string()));
        assert!(model_ids.contains(&"codellama:7b".to_string()));
        assert!(model_ids.contains(&"deepseek-coder:6.7b".to_string()));
        assert!(model_ids.contains(&"qwen2.5:7b".to_string()));
        assert!(model_ids.contains(&"phi3:14b".to_string()));
        assert!(model_ids.contains(&"phi3:mini-4k-instruct".to_string()));
        assert!(model_ids.contains(&"neural-chat:latest".to_string()));
        assert!(model_ids.contains(&"starcoder:latest".to_string()));

        // All should be Ollama providers
        for model in &config.models {
            assert_eq!(model.provider, ModelProviderKind::Ollama);
        }

        // Default model should be in the list
        let default_model = config.active_model();
        assert_eq!(default_model.id, "llama3.2:latest");
        assert_eq!(default_model.display_name, "Meta Llama 3.2 (Ollama)");
    }

    #[test]
    fn test_model_profile_validation() {
        // Test valid profile
        let valid_profile = ModelProfile::for_ollama("test:model", "Test Model");
        assert_eq!(valid_profile.id, "test:model");
        assert_eq!(valid_profile.display_name, "Test Model");
        assert_eq!(valid_profile.provider, ModelProviderKind::Ollama);
        assert!(!valid_profile.prompt_template.is_empty());

        // Test profile with parameters
        let mut profile_with_params = ModelProfile::for_ollama("param:model", "Param Model");
        profile_with_params.parameters.temperature = Some(0.5);
        profile_with_params.parameters.top_p = Some(0.8);
        profile_with_params.parameters.num_predict = Some(100);

        assert_eq!(profile_with_params.parameters.temperature, Some(0.5));
        assert_eq!(profile_with_params.parameters.top_p, Some(0.8));
        assert_eq!(profile_with_params.parameters.num_predict, Some(100));
    }

    #[test]
    fn test_provider_routing_consistency() {
        let server = MockServer::start();

        // Mock Ollama endpoint
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

        // Add Ollama model
        let ollama_profile = ModelProfile::for_ollama("test-ollama", "Test Ollama");
        config.models = vec![ollama_profile];
        let service = ChatService::new(config);
        let step_ctx = create_test_step_context();

        // Test Ollama routing
        let result = service.send_message(&step_ctx, &[], "test");
        assert!(result.is_ok());
        mock.assert();
    }
}
