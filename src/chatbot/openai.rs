use crate::chatbot::provider::ChatProvider;
use crate::chatbot::ChatRequest;
use crate::config::config::{OpenAIProviderConfig, ModelParameters};
use crate::error::{PtError, Result as PtResult};
use crate::model::{ChatMessage, ChatRole};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// OpenAI provider implementation.
pub struct OpenAIProvider {
    config: OpenAIProviderConfig,
    client: Client,
}

impl OpenAIProvider {
    pub fn new(config: OpenAIProviderConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    fn get_api_key(&self) -> PtResult<String> {
        self.config.api_key.clone().ok_or_else(|| {
            PtError::Config {
                message: "OpenAI API key is required but not configured".to_string(),
                source: None,
            }
        })
    }

    fn convert_to_openai_messages(messages: &[ChatMessage]) -> Vec<OpenAIMessage> {
        messages
            .iter()
            .map(|msg| OpenAIMessage {
                role: match msg.role {
                    ChatRole::User => "user".to_string(),
                    ChatRole::Assistant => "assistant".to_string(),
                    ChatRole::System => "system".to_string(),
                },
                content: msg.content.clone(),
            })
            .collect()
    }

    fn convert_parameters(params: &ModelParameters) -> OpenAIParameters {
        OpenAIParameters {
            temperature: params.temperature,
            top_p: params.top_p,
            max_tokens: params.num_predict.map(|n| n as u32),
            // Note: OpenAI doesn't support top_k directly
        }
    }
}

impl ChatProvider for OpenAIProvider {
    fn send_message(&self, request: &ChatRequest) -> PtResult<ChatMessage> {
        let api_key = self.get_api_key()?;
        
        let openai_request = OpenAIRequest {
            model: request.model_profile.id.clone(),
            messages: Self::convert_to_openai_messages(&request.history),
            max_tokens: None, // Will be set from parameters
            temperature: None, // Will be set from parameters
            top_p: None, // Will be set from parameters
            stream: false,
        };

        let mut openai_request = openai_request;
        let params = Self::convert_parameters(&request.model_profile.parameters);
        
        if let Some(temp) = params.temperature {
            openai_request.temperature = Some(temp);
        }
        if let Some(top_p) = params.top_p {
            openai_request.top_p = Some(top_p);
        }
        if let Some(max_tokens) = params.max_tokens {
            openai_request.max_tokens = Some(max_tokens);
        }

        // Add the current user message if not already in history
        if request.history.last().map_or(true, |msg| msg.role != ChatRole::User || msg.content != request.user_prompt) {
            openai_request.messages.push(OpenAIMessage {
                role: "user".to_string(),
                content: request.user_prompt.clone(),
            });
        }

        let response = self
            .client
            .post(&format!("{}/chat/completions", self.config.endpoint))
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&openai_request)
            .send()
            .map_err(|e| PtError::network(
                format!("Failed to send request to OpenAI: {}", e),
            ))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .unwrap_or_else(|_| "Failed to read error response".to_string());
            return Err(PtError::provider(
                "OpenAI".to_string(),
                format!("HTTP {}: {}", status, error_text),
            ));
        }

        let openai_response: OpenAIResponse = response.json().map_err(|e| PtError::network(
            format!("Failed to parse OpenAI response: {}", e),
        ))?;

        if let Some(choice) = openai_response.choices.first() {
            Ok(ChatMessage::new(ChatRole::Assistant, choice.message.content.clone()))
        } else {
            Err(PtError::provider(
                "OpenAI".to_string(),
                "No response choices returned".to_string(),
            ))
        }
    }

    fn check_availability(&self) -> PtResult<bool> {
        // Check if we have an API key
        if self.config.api_key.is_none() {
            return Ok(false);
        }

        // Try to list models as a simple availability check
        let api_key = self.get_api_key()?;
        
        let response = self
            .client
            .get(&format!("{}/models", self.config.endpoint))
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .map_err(|_| PtError::network(
                "Failed to connect to OpenAI".to_string(),
            ))?;

        Ok(response.status().is_success())
    }

    fn provider_name(&self) -> &str {
        "openai"
    }

    fn list_available_models(&self) -> PtResult<Vec<String>> {
        let api_key = self.get_api_key()?;
        
        let response = self
            .client
            .get(&format!("{}/models", self.config.endpoint))
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .map_err(|e| PtError::network(
                format!("Failed to list OpenAI models: {}", e),
            ))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .unwrap_or_else(|_| "Failed to read error response".to_string());
            return Err(PtError::provider(
                "OpenAI".to_string(),
                format!("HTTP {}: {}", status, error_text),
            ));
        }

        let models_response: OpenAIModelsResponse = response.json().map_err(|e| PtError::network(
            format!("Failed to parse OpenAI models response: {}", e),
        ))?;

        Ok(models_response
            .data
            .into_iter()
            .filter(|model| model.id.starts_with("gpt-"))
            .map(|model| model.id)
            .collect())
    }
}

#[derive(Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
    max_tokens: Option<u32>,
    temperature: Option<f32>,
    top_p: Option<f32>,
    stream: bool,
}

#[derive(Serialize, Deserialize)]
struct OpenAIMessage {
    role: String,
    content: String,
}

#[derive(Deserialize, Serialize)]
struct OpenAIResponse {
    choices: Vec<OpenAIChoice>,
}

#[derive(Deserialize, Serialize)]
struct OpenAIChoice {
    message: OpenAIMessage,
}

#[derive(Deserialize, Serialize)]
struct OpenAIModelsResponse {
    data: Vec<OpenAIModel>,
}

#[derive(Deserialize, Serialize)]
struct OpenAIModel {
    id: String,
}

struct OpenAIParameters {
    temperature: Option<f32>,
    top_p: Option<f32>,
    max_tokens: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ModelProfile, ModelProviderKind};
    use httpmock::prelude::*;

    #[test]
    fn test_openai_provider_creation() {
        let config = OpenAIProviderConfig {
            api_key: Some("test-key".to_string()),
            endpoint: "https://api.openai.com/v1".to_string(),
            timeout_seconds: 30,
        };

        let provider = OpenAIProvider::new(config);
        assert_eq!(provider.provider_name(), "openai");
    }

    #[test]
    fn test_openai_provider_no_api_key() {
        let config = OpenAIProviderConfig {
            api_key: None,
            endpoint: "https://api.openai.com/v1".to_string(),
            timeout_seconds: 30,
        };

        let provider = OpenAIProvider::new(config);
        let request = ChatRequest::new(
            crate::chatbot::StepContext::default(),
            vec![],
            "test".to_string(),
            ModelProfile::for_openai("gpt-4", "GPT-4"),
        );

        let result = provider.send_message(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PtError::Config { .. }));
    }

    #[test]
    fn test_openai_provider_availability_no_key() {
        let config = OpenAIProviderConfig {
            api_key: None,
            endpoint: "https://api.openai.com/v1".to_string(),
            timeout_seconds: 30,
        };

        let provider = OpenAIProvider::new(config);
        let result = provider.check_availability();
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_openai_provider_send_message_success() {
        let server = MockServer::start();
        
        let mock_response = OpenAIResponse {
            choices: vec![OpenAIChoice {
                message: OpenAIMessage {
                    role: "assistant".to_string(),
                    content: "Hello from OpenAI!".to_string(),
                },
            }],
        };

        server.mock(|when, then| {
            when.method(POST)
                .path("/chat/completions")
                .header("Authorization", "Bearer test-key")
                .header("Content-Type", "application/json");
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body_obj(&mock_response);
        });

        let config = OpenAIProviderConfig {
            api_key: Some("test-key".to_string()),
            endpoint: server.url(""),
            timeout_seconds: 30,
        };

        let provider = OpenAIProvider::new(config);
        let request = ChatRequest::new(
            crate::chatbot::StepContext::default(),
            vec![],
            "Hello".to_string(),
            ModelProfile::for_openai("gpt-4", "GPT-4"),
        );

        let result = provider.send_message(&request);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().content, "Hello from OpenAI!");
    }

    #[test]
    fn test_openai_provider_list_models() {
        let server = MockServer::start();
        
        let mock_response = OpenAIModelsResponse {
            data: vec![
                OpenAIModel {
                    id: "gpt-4".to_string(),
                },
                OpenAIModel {
                    id: "gpt-3.5-turbo".to_string(),
                },
                OpenAIModel {
                    id: "text-davinci-003".to_string(), // Should be filtered out
                },
            ],
        };

        server.mock(|when, then| {
            when.method(GET)
                .path("/models")
                .header("Authorization", "Bearer test-key");
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body_obj(&mock_response);
        });

        let config = OpenAIProviderConfig {
            api_key: Some("test-key".to_string()),
            endpoint: server.url(""),
            timeout_seconds: 30,
        };

        let provider = OpenAIProvider::new(config);
        let result = provider.list_available_models();
        assert!(result.is_ok());
        let models = result.unwrap();
        assert_eq!(models.len(), 2);
        assert!(models.contains(&"gpt-4".to_string()));
        assert!(models.contains(&"gpt-3.5-turbo".to_string()));
        assert!(!models.contains(&"text-davinci-003".to_string()));
    }

    #[test]
    fn test_convert_to_openai_messages() {
        let messages = vec![
            ChatMessage::new(ChatRole::User, "Hello".to_string()),
            ChatMessage::new(ChatRole::Assistant, "Hi there!".to_string()),
            ChatMessage::new(ChatRole::System, "You are helpful.".to_string()),
        ];

        let openai_messages = OpenAIProvider::convert_to_openai_messages(&messages);
        assert_eq!(openai_messages.len(), 3);
        assert_eq!(openai_messages[0].role, "user");
        assert_eq!(openai_messages[0].content, "Hello");
        assert_eq!(openai_messages[1].role, "assistant");
        assert_eq!(openai_messages[1].content, "Hi there!");
        assert_eq!(openai_messages[2].role, "system");
        assert_eq!(openai_messages[2].content, "You are helpful.");
    }
}