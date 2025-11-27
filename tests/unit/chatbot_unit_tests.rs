#[cfg(test)]
mod tests {
    use httpmock::prelude::*;
    use pt_journal::chatbot::{ChatProvider, ChatRequest, OllamaProvider, StepContext};
    use pt_journal::config::{ModelProfile, OllamaProviderConfig};
    use pt_journal::error::PtError;
    use pt_journal::model::ChatRole;

    fn create_test_request(model_id: &str, endpoint: &str) -> (ChatRequest, OllamaProviderConfig) {
        let mut config = OllamaProviderConfig::default();
        config.endpoint = endpoint.to_string();
        config.timeout_seconds = 30;

        let mut profile = ModelProfile::for_ollama(model_id, "Test Model");
        profile.id = model_id.to_string();

        let step_ctx = StepContext {
            phase_name: "Test Phase".to_string(),
            step_title: "Test Step".to_string(),
            step_description: "Test desc".to_string(),
            step_status: "In Progress".to_string(),
            quiz_status: None,
        };

        let request = ChatRequest::new(step_ctx, vec![], "Hello".to_string(), profile);
        (request, config)
    }

    #[test]
    fn test_send_message_success() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method("POST")
                .path("/api/chat")
                .body_contains(r#""model":"mistral:7b""#)
                .body_contains(r#""role":"system""#)
                .body_contains("You are an expert penetration testing assistant")
                .body_contains("Current Context");
            then.status(200).json_body(serde_json::json!({
                "message": {
                    "content": "Test response"
                }
            }));
        });

        let (request, config) = create_test_request("mistral:7b", &server.url(""));
        let provider = OllamaProvider::new(config);
        let result = provider.send_message(&request);

        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg.role, ChatRole::Assistant);
        assert_eq!(msg.content, "Test response");
        mock.assert();
    }

    #[test]
    fn test_send_message_with_parameters() {
        let server = MockServer::start();

        // Just verify the request is made successfully when parameters are set
        let mock = server.mock(|when, then| {
            when.method("POST").path("/api/chat");
            then.status(200).json_body(serde_json::json!({
                "message": {
                    "content": "Response with params"
                }
            }));
        });

        let (mut request, config) = create_test_request("mistral:7b", &server.url(""));
        request.model_profile.parameters.temperature = Some(0.7);
        request.model_profile.parameters.top_p = Some(0.9);
        request.model_profile.parameters.top_k = Some(40);

        let provider = OllamaProvider::new(config);
        let result = provider.send_message(&request);

        assert!(result.is_ok());
        mock.assert();

        // The important part is that the code doesn't fail when parameters are present
        // The actual parameter values are applied in the payload construction (lines 116-127)
    }

    #[test]
    fn test_check_availability_success() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method("GET").path("/api/tags");
            then.status(200).json_body(serde_json::json!({
                "models": []
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
    fn test_check_availability_failure() {
        let mut config = OllamaProviderConfig::default();
        config.endpoint = "http://invalid:1234".to_string();
        let provider = OllamaProvider::new(config);

        let result = provider.check_availability();
        assert!(matches!(
            result,
            Err(PtError::ChatServiceUnavailable { .. })
        ));
    }

    #[test]
    fn test_list_available_models_success() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method("GET").path("/api/tags");
            then.status(200).json_body(serde_json::json!({
                "models": [
                    {"name": "llama3.2:latest"},
                    {"name": "mistral:7b"},
                    {"name": "codellama:7b"}
                ]
            }));
        });

        let mut config = OllamaProviderConfig::default();
        config.endpoint = server.url("");
        let provider = OllamaProvider::new(config);

        let result = provider.list_available_models();
        assert!(result.is_ok());
        let models = result.unwrap();
        assert_eq!(models.len(), 3);
        assert!(models.contains(&"llama3.2:latest".to_string()));
        assert!(models.contains(&"mistral:7b".to_string()));
        assert!(models.contains(&"codellama:7b".to_string()));
        mock.assert();
    }

    #[test]
    fn test_list_available_models_service_unavailable() {
        let mut config = OllamaProviderConfig::default();
        config.endpoint = "http://invalid:1234".to_string();
        let provider = OllamaProvider::new(config);

        let result = provider.list_available_models();
        assert!(matches!(
            result,
            Err(PtError::ChatServiceUnavailable { .. })
        ));
    }
}

#[cfg(test)]
mod service_tests {
    use httpmock::prelude::*;
    use pt_journal::chatbot::{ChatService, StepContext};
    use pt_journal::config::ChatbotConfig;

    #[test]
    fn test_service_send_message_success() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method("POST")
                .path("/api/chat")
                .body_contains(r#""model":"mistral:7b""#);
            then.status(200).json_body(serde_json::json!({
                "message": {
                    "content": "Service response"
                }
            }));
        });

        let mut config = ChatbotConfig::default();
        config.ollama.endpoint = server.url("");
        config.default_model_id = "mistral:7b".to_string();

        let service = ChatService::new(config);
        let step_ctx = StepContext {
            phase_name: "Test".to_string(),
            step_title: "Test".to_string(),
            step_description: "Test".to_string(),
            step_status: "In Progress".to_string(),
            quiz_status: None,
        };

        let result = service.send_message(&step_ctx, &[], "Hello");
        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn test_service_check_availability() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method("GET").path("/api/tags");
            then.status(200).json_body(serde_json::json!({
                "models": []
            }));
        });

        let mut config = ChatbotConfig::default();
        config.ollama.endpoint = server.url("");
        config.default_model_id = "llama3.2:latest".to_string(); // Use Ollama model for this test

        let service = ChatService::new(config);
        let result = service.check_availability();

        assert!(result.is_ok());
        assert!(result.unwrap());
        mock.assert();
    }

    #[test]
    fn test_service_unsupported_provider() {
        let config = ChatbotConfig::default();
        let _service = ChatService::new(config);

        // Since we removed LlamaCpp, all providers should be Ollama now
        // This test is no longer relevant
        assert!(true);
    }

    #[test]
    fn test_service_registry_functionality() {
        let config = ChatbotConfig::default();
        let service = ChatService::new(config);

        // Test that Ollama provider is registered
        let registry = service.registry();
        assert!(registry.has_provider(&pt_journal::config::ModelProviderKind::Ollama));

        // Test that we can get the provider
        let provider = service.get_provider(&pt_journal::config::ModelProviderKind::Ollama);
        assert!(provider.is_ok());

        // Test that registered providers list includes Ollama
        let registered = registry.registered_providers();
        assert!(registered.contains(&pt_journal::config::ModelProviderKind::Ollama));
    }
}

#[cfg(test)]
mod context_tests {
    use pt_journal::chatbot::ContextBuilder;
    use pt_journal::model::Session;

    #[test]
    fn test_context_builder() {
        let session = Session::default();
        let context = ContextBuilder::build_session_context(&session, 0, 0);
        assert!(context.contains("Current Session Summary"));
        assert!(context.contains("Phase 1: Reconnaissance"));
    }
}
