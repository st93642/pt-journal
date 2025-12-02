use crate::chatbot::provider::ChatProvider;
use crate::chatbot::ChatRequest;
use crate::config::config::{AzureOpenAIProviderConfig, ModelParameters};
use crate::error::{PtError, Result as PtResult};
use crate::model::{ChatMessage, ChatRole};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Azure OpenAI provider implementation.
pub struct AzureOpenAIProvider {
    config: AzureOpenAIProviderConfig,
    client: Client,
}

impl AzureOpenAIProvider {
    pub fn new(config: AzureOpenAIProviderConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    fn get_api_key(&self) -> PtResult<String> {
        self.config.api_key.clone().ok_or_else(|| {
            PtError::Config {
                message: "Azure OpenAI API key is required but not configured".to_string(),
                source: None,
            }
        })
    }

    fn get_endpoint(&self) -> PtResult<String> {
        self.config.endpoint.clone().ok_or_else(|| {
            PtError::Config {
                message: "Azure OpenAI endpoint is required but not configured".to_string(),
                source: None,
            }
        })
    }

    fn get_deployment_name(&self, model_id: &str) -> PtResult<String> {
        // Use global deployment name if configured
        if let Some(deployment) = &self.config.deployment_name {
            return Ok(deployment.clone());
        }
        // Otherwise use the model_id as deployment name
        Ok(model_id.to_string())
    }

    fn get_api_version(&self) -> String {
        self.config
            .api_version
            .clone()
            .unwrap_or_else(|| "2024-02-15-preview".to_string())
    }

    fn convert_to_openai_messages(messages: &[ChatMessage]) -> Vec<OpenAIMessage> {
        messages
            .iter()
            .map(|msg| OpenAIMessage {
                role: match msg.role {
                    ChatRole::User => "user".to_string(),
                    ChatRole::Assistant => "assistant".to_string(),
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
            // Note: Azure OpenAI doesn't support top_k directly
        }
    }
}

impl ChatProvider for AzureOpenAIProvider {
    fn send_message(&self, request: &ChatRequest) -> PtResult<ChatMessage> {
        let api_key = self.get_api_key()?;
        let endpoint = self.get_endpoint()?;
        let deployment_name = self.get_deployment_name(&request.model_profile.id)?;
        let api_version = self.get_api_version();
        
        let openai_request = OpenAIRequest {
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

        let url = format!(
            "{}/openai/deployments/{}/chat/completions?api-version={}",
            endpoint, deployment_name, api_version
        );

        let response = self
            .client
            .post(&url)
            .header("api-key", api_key)
            .header("Content-Type", "application/json")
            .json(&openai_request)
            .send()
            .map_err(|e| PtError::network(
                format!("Failed to send request to Azure OpenAI: {}", e),
            ))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .unwrap_or_else(|_| "Failed to read error response".to_string());
            return Err(PtError::provider(
                "Azure OpenAI".to_string(),
                format!("HTTP {}: {}", status, error_text),
            ));
        }

        let openai_response: OpenAIResponse = response.json().map_err(|e| PtError::network(
            format!("Failed to parse Azure OpenAI response: {}", e),
        ))?;

        if let Some(choice) = openai_response.choices.first() {
            Ok(ChatMessage::new(ChatRole::Assistant, choice.message.content.clone()))
        } else {
            Err(PtError::provider(
                "Azure OpenAI".to_string(),
                "No response choices returned".to_string(),
            ))
        }
    }

    fn check_availability(&self) -> PtResult<bool> {
        // Check if we have required configuration
        if self.config.api_key.is_none() || self.config.endpoint.is_none() {
            return Ok(false);
        }

        // Try to list deployments as a simple availability check
        let api_key = self.get_api_key()?;
        let endpoint = self.get_endpoint()?;
        let api_version = self.get_api_version();
        
        let url = format!("{}/openai/deployments?api-version={}", endpoint, api_version);
        
        let response = self
            .client
            .get(&url)
            .header("api-key", api_key)
            .send()
            .map_err(|_| PtError::Network {
                message: "Failed to connect to Azure OpenAI".to_string(),
            })?;

        Ok(response.status().is_success())
    }

    fn provider_name(&self) -> &str {
        "azure-openai"
    }

    fn list_available_models(&self) -> PtResult<Vec<String>> {
        let api_key = self.get_api_key()?;
        let endpoint = self.get_endpoint()?;
        let api_version = self.get_api_version();
        
        let url = format!("{}/openai/deployments?api-version={}", endpoint, api_version);
        
        let response = self
            .client
            .get(&url)
            .header("api-key", api_key)
            .send()
            .map_err(|e| PtError::network(
                format!("Failed to list Azure OpenAI deployments: {}", e),
            ))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .unwrap_or_else(|_| "Failed to read error response".to_string());
            return Err(PtError::provider(
                "Azure OpenAI".to_string(),
                format!("HTTP {}: {}", status, error_text),
            ));
        }

        let deployments_response: AzureOpenAIDeploymentsResponse = response.json().map_err(|e| PtError::network(
            format!("Failed to parse Azure OpenAI deployments response: {}", e),
        ))?;

        Ok(deployments_response
            .data
            .into_iter()
            .filter(|deployment| {
                // Filter for chat models (GPT models)
                deployment.model.r#type == "text-generation" || 
                deployment.model.r#type == "chat-completion" ||
                deployment.model.id.contains("gpt")
            })
            .map(|deployment| deployment.id)
            .collect())
    }
}

#[derive(Serialize)]
struct OpenAIRequest {
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

#[derive(Deserialize)]
struct OpenAIResponse {
    choices: Vec<OpenAIChoice>,
}

#[derive(Deserialize)]
struct OpenAIChoice {
    message: OpenAIMessage,
}

#[derive(Deserialize)]
struct AzureOpenAIDeploymentsResponse {
    data: Vec<AzureOpenAIDeployment>,
}

#[derive(Deserialize)]
struct AzureOpenAIDeployment {
    id: String,
    model: AzureOpenAIModel,
}

#[derive(Deserialize)]
struct AzureOpenAIModel {
    id: String,
    #[serde(rename = "type")]
    r#type: String,
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
    fn test_azure_openai_provider_creation() {
        let config = AzureOpenAIProviderConfig {
            api_key: Some("test-key".to_string()),
            endpoint: Some("https://test.openai.azure.com".to_string()),
            deployment_name: Some("gpt-4".to_string()),
            api_version: Some("2024-02-15-preview".to_string()),
            timeout_seconds: 30,
        };

        let provider = AzureOpenAIProvider::new(config);
        assert_eq!(provider.provider_name(), "azure-openai");
    }

    #[test]
    fn test_azure_openai_provider_no_api_key() {
        let config = AzureOpenAIProviderConfig {
            api_key: None,
            endpoint: Some("https://test.openai.azure.com".to_string()),
            deployment_name: Some("gpt-4".to_string()),
            api_version: Some("2024-02-15-preview".to_string()),
            timeout_seconds: 30,
        };

        let provider = AzureOpenAIProvider::new(config);
        let request = ChatRequest::new(
            crate::chatbot::StepContext::default(),
            vec![],
            "test".to_string(),
            ModelProfile::for_azure_openai("gpt-4", "GPT-4"),
        );

        let result = provider.send_message(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PtError::Configuration { .. }));
    }

    #[test]
    fn test_azure_openai_provider_no_endpoint() {
        let config = AzureOpenAIProviderConfig {
            api_key: Some("test-key".to_string()),
            endpoint: None,
            deployment_name: Some("gpt-4".to_string()),
            api_version: Some("2024-02-15-preview".to_string()),
            timeout_seconds: 30,
        };

        let provider = AzureOpenAIProvider::new(config);
        let request = ChatRequest::new(
            crate::chatbot::StepContext::default(),
            vec![],
            "test".to_string(),
            ModelProfile::for_azure_openai("gpt-4", "GPT-4"),
        );

        let result = provider.send_message(&request);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PtError::Configuration { .. }));
    }

    #[test]
    fn test_azure_openai_provider_availability_no_config() {
        let config = AzureOpenAIProviderConfig {
            api_key: None,
            endpoint: None,
            deployment_name: None,
            api_version: None,
            timeout_seconds: 30,
        };

        let provider = AzureOpenAIProvider::new(config);
        let result = provider.check_availability();
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_azure_openai_provider_send_message_success() {
        let server = MockServer::start();
        
        let mock_response = OpenAIResponse {
            choices: vec![OpenAIChoice {
                message: OpenAIMessage {
                    role: "assistant".to_string(),
                    content: "Hello from Azure OpenAI!".to_string(),
                },
            }],
        };

        server.mock(|when, then| {
            when.method(POST)
                .path("/openai/deployments/gpt-4/chat/completions")
                .header("api-key", "test-key")
                .header("Content-Type", "application/json")
                .query_param("api-version", "2024-02-15-preview");
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body_obj(&mock_response);
        });

        let config = AzureOpenAIProviderConfig {
            api_key: Some("test-key".to_string()),
            endpoint: Some(server.url()),
            deployment_name: Some("gpt-4".to_string()),
            api_version: Some("2024-02-15-preview".to_string()),
            timeout_seconds: 30,
        };

        let provider = AzureOpenAIProvider::new(config);
        let request = ChatRequest::new(
            crate::chatbot::StepContext::default(),
            vec![],
            "Hello".to_string(),
            ModelProfile::for_azure_openai("gpt-4", "GPT-4"),
        );

        let result = provider.send_message(&request);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().content(), "Hello from Azure OpenAI!");
    }

    #[test]
    fn test_azure_openai_provider_list_deployments() {
        let server = MockServer::start();
        
        let mock_response = AzureOpenAIDeploymentsResponse {
            data: vec![
                AzureOpenAIDeployment {
                    id: "gpt-4".to_string(),
                    model: AzureOpenAIModel {
                        id: "gpt-4".to_string(),
                        r#type: "text-generation".to_string(),
                    },
                },
                AzureOpenAIDeployment {
                    id: "gpt-35-turbo".to_string(),
                    model: AzureOpenAIModel {
                        id: "gpt-35-turbo".to_string(),
                        r#type: "chat-completion".to_string(),
                    },
                },
                AzureOpenAIDeployment {
                    id: "text-embedding-ada-002".to_string(),
                    model: AzureOpenAIModel {
                        id: "text-embedding-ada-002".to_string(),
                        r#type: "text-embedding".to_string(), // Should be filtered out
                    },
                },
            ],
        };

        server.mock(|when, then| {
            when.method(GET)
                .path("/openai/deployments")
                .header("api-key", "test-key")
                .query_param("api-version", "2024-02-15-preview");
            then.status(200)
                .header("Content-Type", "application/json")
                .json_body_obj(&mock_response);
        });

        let config = AzureOpenAIProviderConfig {
            api_key: Some("test-key".to_string()),
            endpoint: Some(server.url()),
            deployment_name: None,
            api_version: Some("2024-02-15-preview".to_string()),
            timeout_seconds: 30,
        };

        let provider = AzureOpenAIProvider::new(config);
        let result = provider.list_available_models();
        assert!(result.is_ok());
        let models = result.unwrap();
        assert_eq!(models.len(), 2);
        assert!(models.contains(&"gpt-4".to_string()));
        assert!(models.contains(&"gpt-35-turbo".to_string()));
        assert!(!models.contains(&"text-embedding-ada-002".to_string()));
    }

    #[test]
    fn test_convert_to_openai_messages() {
        let messages = vec![
            ChatMessage::new(ChatRole::User, "Hello".to_string()),
            ChatMessage::new(ChatRole::Assistant, "Hi there!".to_string()),
            ChatMessage::new(ChatRole::System, "You are helpful.".to_string()),
        ];

        let openai_messages = AzureOpenAIProvider::convert_to_openai_messages(&messages);
        assert_eq!(openai_messages.len(), 3);
        assert_eq!(openai_messages[0].role, "user");
        assert_eq!(openai_messages[0].content, "Hello");
        assert_eq!(openai_messages[1].role, "assistant");
        assert_eq!(openai_messages[1].content, "Hi there!");
        assert_eq!(openai_messages[2].role, "system");
        assert_eq!(openai_messages[2].content, "You are helpful.");
    }

    #[test]
    fn test_get_deployment_name_from_config() {
        let config = AzureOpenAIProviderConfig {
            api_key: Some("test-key".to_string()),
            endpoint: Some("https://test.openai.azure.com".to_string()),
            deployment_name: Some("my-gpt4-deployment".to_string()),
            api_version: Some("2024-02-15-preview".to_string()),
            timeout_seconds: 30,
        };

        let provider = AzureOpenAIProvider::new(config);
        let result = provider.get_deployment_name("gpt-4");
        assert_eq!(result.unwrap(), "my-gpt4-deployment");
    }

    #[test]
    fn test_get_deployment_name_from_model_id() {
        let config = AzureOpenAIProviderConfig {
            api_key: Some("test-key".to_string()),
            endpoint: Some("https://test.openai.azure.com".to_string()),
            deployment_name: None, // No global deployment name
            api_version: Some("2024-02-15-preview".to_string()),
            timeout_seconds: 30,
        };

        let provider = AzureOpenAIProvider::new(config);
        let result = provider.get_deployment_name("gpt-4");
        assert_eq!(result.unwrap(), "gpt-4");
    }
}