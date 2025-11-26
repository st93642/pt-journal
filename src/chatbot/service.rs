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
