use crate::chatbot::ChatRequest;
use crate::model::ChatMessage;
use crate::error::Result as PtResult;

/// Trait for different chat backend providers
pub trait ChatProvider: Send + Sync {
    /// Send a chat request and get a response
    fn send_message(&self, request: &ChatRequest) -> PtResult<ChatMessage>;

    /// Check if the provider service is available
    fn check_availability(&self) -> PtResult<bool>;

    /// Get the provider name for identification
    fn provider_name(&self) -> &str;

    /// Get list of available models from this provider
    fn list_available_models(&self) -> PtResult<Vec<String>> {
        // Default implementation returns empty list
        // Providers that support model listing should override this
        Ok(Vec::new())
    }
}
