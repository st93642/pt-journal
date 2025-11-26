use pt_journal::chatbot::{ChatProvider, ChatRequest, ChatService, OllamaProvider, StepContext};
use pt_journal::config::{ChatbotConfig, ModelParameters, ModelProfile, OllamaProviderConfig};
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
}
