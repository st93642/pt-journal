use crate::chatbot::{ChatProvider, ChatRequest, OllamaProvider, ProviderRegistry, StepContext};
use crate::config::{ChatbotConfig, ModelProviderKind};
use crate::model::ChatMessage;
use crate::error::Result as PtResult;
use std::sync::Arc;

/// Chat service that routes requests to appropriate providers
pub struct ChatService {
    pub config: ChatbotConfig,
    registry: ProviderRegistry,
}

impl ChatService {
    pub fn new(mut config: ChatbotConfig) -> Self {
        config.ensure_valid();

        let registry = ProviderRegistry::new();

        // Register default providers
        Self::register_default_providers(&registry, &config);

        Self {
            config,
            registry,
        }
    }

    /// Register the default providers with the registry.
    fn register_default_providers(registry: &ProviderRegistry, config: &ChatbotConfig) {
        // Register Ollama provider
        let ollama_provider = Arc::new(OllamaProvider::new(config.ollama.clone()));
        if let Err(e) = registry.register(ollama_provider) {
            eprintln!("Warning: Failed to register Ollama provider: {}", e);
        }
    }

    /// Send a chat message using the appropriate provider based on the profile
    pub fn send_message(
        &self,
        step_ctx: &StepContext,
        history: &[ChatMessage],
        user_input: &str,
    ) -> PtResult<ChatMessage> {
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
    pub fn send_request(&self, request: &ChatRequest) -> PtResult<ChatMessage> {
        let provider = self.get_provider(&request.model_profile.provider)?;
        provider.send_message(request)
    }

    /// Check if the provider for the active model is available
    pub fn check_availability(&self) -> PtResult<bool> {
        let profile = self.config.active_model();
        let provider = self.get_provider(&profile.provider)?;
        provider.check_availability()
    }

    /// Get list of available models from Ollama
    pub fn list_available_models(&self) -> PtResult<Vec<String>> {
        // Since we only support Ollama now, we can access it directly
        // In the future, this could be made more generic
        self.get_provider(&ModelProviderKind::Ollama)?
            .list_available_models()
    }

    /// Get a provider for the specified provider kind using the registry.
    pub fn get_provider(
        &self,
        provider_kind: &ModelProviderKind,
    ) -> PtResult<Arc<dyn ChatProvider>> {
        self.registry.get_provider(provider_kind)
    }

    /// Get access to the provider registry for advanced operations.
    ///
    /// This allows external code to register additional providers or
    /// inspect the current provider registrations.
    pub fn registry(&self) -> &ProviderRegistry {
        &self.registry
    }
}
