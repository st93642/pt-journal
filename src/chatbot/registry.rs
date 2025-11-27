//! Provider registry for dynamic chat provider management.
//!
//! This module implements a registry pattern for chat providers, allowing
//! dynamic registration and lookup of providers without modifying the core
//! ChatService logic. This enables easy addition of new providers and
//! better separation of concerns.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::chatbot::registry::ProviderRegistry;
//! use crate::chatbot::{ChatProvider, OllamaProvider};
//! use std::sync::Arc;
//!
//! let mut registry = ProviderRegistry::new();
//! let ollama_provider = Arc::new(OllamaProvider::new(config.ollama.clone()));
//!
//! registry.register(ollama_provider);
//!
//! // Later, lookup by provider kind
//! let provider = registry.get_provider(&ModelProviderKind::Ollama);
//! ```

use crate::chatbot::{ChatError, ChatProvider};
use crate::config::ModelProviderKind;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Registry for managing chat providers dynamically.
///
/// The registry allows providers to be registered at runtime and looked up
/// by their provider kind. This enables the ChatService to support new
/// providers without code changes.
#[derive(Clone)]
pub struct ProviderRegistry {
    providers: Arc<RwLock<HashMap<ModelProviderKind, Arc<dyn ChatProvider>>>>,
}

impl ProviderRegistry {
    /// Create a new empty provider registry.
    pub fn new() -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a provider for a specific provider kind.
    ///
    /// If a provider is already registered for this kind, it will be replaced.
    ///
    /// # Arguments
    /// * `provider` - The provider implementation to register
    ///
    /// # Returns
    /// The provider kind that was registered
    ///
    /// # Note
    /// The provider kind is determined by calling `provider.provider_name()`
    /// and converting it to a `ModelProviderKind`. This assumes the provider
    /// name matches the enum variant name.
    pub fn register<P>(&self, provider: Arc<P>) -> Result<ModelProviderKind, ChatError>
    where
        P: ChatProvider + 'static,
    {
        let provider_name = provider.provider_name();
        let kind = Self::provider_name_to_kind(provider_name)?;

        let mut providers = self.providers.write().map_err(|_| {
            ChatError::InvalidResponse("Failed to acquire registry write lock".to_string())
        })?;

        providers.insert(kind.clone(), provider);
        Ok(kind)
    }

    /// Get a provider for the specified provider kind.
    ///
    /// # Arguments
    /// * `kind` - The provider kind to look up
    ///
    /// # Returns
    /// The registered provider, or an error if not found
    pub fn get_provider(&self, kind: &ModelProviderKind) -> Result<Arc<dyn ChatProvider>, ChatError> {
        let providers = self.providers.read().map_err(|_| {
            ChatError::InvalidResponse("Failed to acquire registry read lock".to_string())
        })?;

        providers.get(kind).cloned().ok_or_else(|| {
            ChatError::UnsupportedProvider(format!("Provider '{}' is not registered", kind))
        })
    }

    /// Check if a provider is registered for the given kind.
    ///
    /// # Arguments
    /// * `kind` - The provider kind to check
    ///
    /// # Returns
    /// true if a provider is registered, false otherwise
    pub fn has_provider(&self, kind: &ModelProviderKind) -> bool {
        self.providers.read().map(|providers| providers.contains_key(kind)).unwrap_or(false)
    }

    /// Get a list of all registered provider kinds.
    ///
    /// # Arguments
    /// * `kind` - The provider kind to check
    ///
    /// # Returns
    /// A vector of all provider kinds that have registered providers
    pub fn registered_providers(&self) -> Vec<ModelProviderKind> {
        self.providers.read().map(|providers| providers.keys().cloned().collect()).unwrap_or_default()
    }

    /// Unregister a provider for the given kind.
    ///
    /// # Arguments
    /// * `kind` - The provider kind to unregister
    ///
    /// # Returns
    /// true if a provider was removed, false if none was registered
    pub fn unregister(&self, kind: &ModelProviderKind) -> Result<bool, ChatError> {
        let mut providers = self.providers.write().map_err(|_| {
            ChatError::InvalidResponse("Failed to acquire registry write lock".to_string())
        })?;

        Ok(providers.remove(kind).is_some())
    }

    /// Clear all registered providers.
    pub fn clear(&self) -> Result<(), ChatError> {
        let mut providers = self.providers.write().map_err(|_| {
            ChatError::InvalidResponse("Failed to acquire registry write lock".to_string())
        })?;

        providers.clear();
        Ok(())
    }

    /// Convert a provider name string to a ModelProviderKind.
    ///
    /// # Arguments
    /// * `name` - The provider name (e.g., "ollama")
    ///
    /// # Returns
    /// The corresponding ModelProviderKind, or an error if unknown
    fn provider_name_to_kind(name: &str) -> Result<ModelProviderKind, ChatError> {
        match name.to_lowercase().as_str() {
            "ollama" => Ok(ModelProviderKind::Ollama),
            _ => Err(ChatError::UnsupportedProvider(format!(
                "Unknown provider name: '{}'. Supported providers: ollama",
                name
            ))),
        }
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chatbot::OllamaProvider;
    use crate::config::OllamaProviderConfig;

    // Mock provider for testing
    struct MockProvider {
        name: String,
    }

    impl MockProvider {
        fn new(name: impl Into<String>) -> Self {
            Self { name: name.into() }
        }
    }

    impl ChatProvider for MockProvider {
        fn send_message(&self, _request: &crate::chatbot::ChatRequest) -> Result<crate::model::ChatMessage, ChatError> {
            unimplemented!()
        }

        fn check_availability(&self) -> Result<bool, ChatError> {
            Ok(true)
        }

        fn provider_name(&self) -> &str {
            &self.name
        }
    }

    #[test]
    fn test_registry_creation() {
        let registry = ProviderRegistry::new();
        assert!(!registry.has_provider(&ModelProviderKind::Ollama));
        assert!(registry.registered_providers().is_empty());
    }

    #[test]
    fn test_register_and_get_provider() {
        let registry = ProviderRegistry::new();
        let mock_provider = Arc::new(MockProvider::new("ollama"));

        // Register the provider
        let kind = registry.register(mock_provider.clone()).unwrap();
        assert_eq!(kind, ModelProviderKind::Ollama);

        // Check that it's registered
        assert!(registry.has_provider(&ModelProviderKind::Ollama));
        assert_eq!(registry.registered_providers(), vec![ModelProviderKind::Ollama]);

        // Get the provider back
        let retrieved = registry.get_provider(&ModelProviderKind::Ollama).unwrap();
        assert_eq!(retrieved.provider_name(), "ollama");
    }

    #[test]
    fn test_get_unregistered_provider() {
        let registry = ProviderRegistry::new();
        let result = registry.get_provider(&ModelProviderKind::Ollama);
        assert!(result.is_err());
        // Check that it's an UnsupportedProvider error
        match result {
            Err(ChatError::UnsupportedProvider(_)) => (),
            _ => panic!("Expected UnsupportedProvider error"),
        }
    }

    #[test]
    fn test_unregister_provider() {
        let registry = ProviderRegistry::new();
        let mock_provider = Arc::new(MockProvider::new("ollama"));

        // Register and verify
        registry.register(mock_provider).unwrap();
        assert!(registry.has_provider(&ModelProviderKind::Ollama));

        // Unregister
        let removed = registry.unregister(&ModelProviderKind::Ollama).unwrap();
        assert!(removed);
        assert!(!registry.has_provider(&ModelProviderKind::Ollama));

        // Try to unregister again
        let removed_again = registry.unregister(&ModelProviderKind::Ollama).unwrap();
        assert!(!removed_again);
    }

    #[test]
    fn test_clear_registry() {
        let registry = ProviderRegistry::new();
        let mock_provider = Arc::new(MockProvider::new("ollama"));

        registry.register(mock_provider).unwrap();
        assert!(!registry.registered_providers().is_empty());

        registry.clear().unwrap();
        assert!(registry.registered_providers().is_empty());
    }

    #[test]
    fn test_provider_name_to_kind() {
        assert_eq!(ProviderRegistry::provider_name_to_kind("ollama").unwrap(), ModelProviderKind::Ollama);
        assert_eq!(ProviderRegistry::provider_name_to_kind("OLLAMA").unwrap(), ModelProviderKind::Ollama);
        assert!(ProviderRegistry::provider_name_to_kind("unknown").is_err());
    }

    #[test]
    fn test_register_unknown_provider() {
        let registry = ProviderRegistry::new();
        let unknown_provider = Arc::new(MockProvider::new("unknown"));

        let result = registry.register(unknown_provider);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChatError::UnsupportedProvider(_)));
    }
}