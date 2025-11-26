use crate::chatbot::{ChatError, ChatRequest};
use crate::model::ChatMessage;

/// Trait for different chat backend providers
pub trait ChatProvider: Send + Sync {
    /// Send a chat request and get a response
    fn send_message(&self, request: &ChatRequest) -> Result<ChatMessage, ChatError>;

    /// Check if the provider service is available
    fn check_availability(&self) -> Result<bool, ChatError>;

    /// Get the provider name for identification
    fn provider_name(&self) -> &str;
}
