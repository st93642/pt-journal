use crate::chatbot::{ChatProvider, ChatRequest, OllamaProvider, OpenAIProvider, AzureOpenAIProvider, ProviderRegistry, StepContext};
use crate::config::{ChatbotConfig, ModelProviderKind};
use crate::error::Result as PtResult;
use crate::model::ChatMessage;
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

        Self { config, registry }
    }

    /// Register the default providers with the registry.
    fn register_default_providers(registry: &ProviderRegistry, config: &ChatbotConfig) {
        // Register Ollama provider
        let ollama_provider = Arc::new(OllamaProvider::new(config.ollama.clone()));
        if let Err(_e) = registry.register(ollama_provider) {}

        // Register OpenAI provider if API key is configured
        if config.openai.api_key.is_some() {
            let openai_provider = Arc::new(OpenAIProvider::new(config.openai.clone()));
            if let Err(_e) = registry.register(openai_provider) {}
        }

        // Register Azure OpenAI provider if API key and endpoint are configured
        if config.azure_openai.api_key.is_some() && config.azure_openai.endpoint.is_some() {
            let azure_openai_provider = Arc::new(AzureOpenAIProvider::new(config.azure_openai.clone()));
            if let Err(_e) = registry.register(azure_openai_provider) {}
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

    /// Get list of available models from all configured providers
    pub fn list_available_models(&self) -> PtResult<Vec<String>> {
        let mut all_models = Vec::new();
        
        // Try to get models from each registered provider
        for provider_kind in self.registry.registered_providers() {
            if let Ok(provider) = self.get_provider(&provider_kind) {
                if let Ok(models) = provider.list_available_models() {
                    all_models.extend(models);
                }
                // If a provider can't list models, we just skip it
                // This is expected for some providers that don't support model enumeration
            }
        }
        
        Ok(all_models)
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
