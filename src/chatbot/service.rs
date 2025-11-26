use crate::chatbot::{ChatError, ChatProvider, ChatRequest, OllamaProvider, StepContext};
use crate::config::{ChatbotConfig, ModelProviderKind};
use crate::model::ChatMessage;
use std::sync::Arc;

/// Chat service that routes requests to appropriate providers
pub struct ChatService {
    pub config: ChatbotConfig,
    ollama_provider: Arc<OllamaProvider>,
}

impl ChatService {
    pub fn new(mut config: ChatbotConfig) -> Self {
        config.ensure_valid();
        let ollama_provider = Arc::new(OllamaProvider::new(config.ollama.clone()));
        Self {
            config,
            ollama_provider,
        }
    }

    /// Send a chat message using the appropriate provider based on the profile
    pub fn send_message(
        &self,
        step_ctx: &StepContext,
        history: &[ChatMessage],
        user_input: &str,
    ) -> Result<ChatMessage, ChatError> {
        let profile = self.config.active_model();
        let request = ChatRequest::new(
            step_ctx.clone(),
            history.to_vec(),
            user_input.to_string(),
            profile.clone(),
        );
        self.send_request(&request)
    }

    /// Send a chat request using the appropriate provider
    pub fn send_request(&self, request: &ChatRequest) -> Result<ChatMessage, ChatError> {
        let provider = self.get_provider(&request.model_profile.provider)?;
        provider.send_message(request)
    }

    /// Check if the provider for the active model is available
    pub fn check_availability(&self) -> Result<bool, ChatError> {
        let profile = self.config.active_model();
        let provider = self.get_provider(&profile.provider)?;
        provider.check_availability()
    }

    /// Get list of available models from Ollama
    pub fn list_available_models(&self) -> Result<Vec<String>, ChatError> {
        // Since we only support Ollama now, we can access it directly
        self.ollama_provider.list_available_models()
    }

    pub fn get_provider(
        &self,
        provider_kind: &ModelProviderKind,
    ) -> Result<Arc<dyn ChatProvider>, ChatError> {
        match provider_kind {
            ModelProviderKind::Ollama => Ok(self.ollama_provider.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ChatbotConfig;
    use httpmock::prelude::*;

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
            notes_count: 0,
            evidence_count: 0,
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
}
