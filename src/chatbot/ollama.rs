use crate::chatbot::{ChatProvider, ChatRequest};
use crate::config::{ModelProviderKind, OllamaProviderConfig};
use crate::error::{PtError, Result as PtResult};
use crate::model::{ChatMessage, ChatRole};
use reqwest::blocking::Client;
use std::time::Duration;

/// Ollama chat provider implementation
pub struct OllamaProvider {
    config: OllamaProviderConfig,
    client: Client,
}

impl OllamaProvider {
    pub fn new(config: OllamaProviderConfig) -> Self {
        let timeout = config.timeout_seconds;
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout))
            .build()
            .expect("Failed to build HTTP client");
        Self { config, client }
    }

    fn build_system_prompt(&self, request: &ChatRequest) -> String {
        let step_ctx = &request.step_context;
        let base_context = format!(
            "You are an expert penetration testing assistant helping with structured pentesting methodology.\n\n\
            Current Context:\n\
            - Phase: {}\n\
            - Step: {} (Status: {})\n\
            - Description: {}\n\
            {}\n\n\
            Provide helpful, methodology-aligned assistance for general pentesting questions, step-specific guidance, or tool recommendations. \
            Keep responses focused and actionable.",
            step_ctx.phase_name,
            step_ctx.step_title,
            step_ctx.step_status,
            step_ctx.step_description.chars().take(200).collect::<String>(),
            step_ctx
                .quiz_status
                .as_ref()
                .map(|s| format!("- Quiz Status: {}", s))
                .unwrap_or_default()
        );

        Self::render_prompt_template(
            &request.model_profile.prompt_template,
            &base_context,
            step_ctx,
            &request.model_profile,
        )
    }

    fn render_prompt_template(
        template: &str,
        base_context: &str,
        step_ctx: &crate::chatbot::StepContext,
        profile: &crate::config::ModelProfile,
    ) -> String {
        let template = template.trim();
        if template.is_empty() {
            return base_context.to_string();
        }

        let mut rendered = template.to_string();
        rendered = rendered.replace("{{context}}", base_context);
        rendered = rendered.replace("{{phase_name}}", &step_ctx.phase_name);
        rendered = rendered.replace("{{step_title}}", &step_ctx.step_title);
        rendered = rendered.replace("{{step_description}}", &step_ctx.step_description);
        rendered = rendered.replace("{{step_status}}", &step_ctx.step_status);
        rendered = rendered.replace("{{model_display_name}}", &profile.display_name);

        if !template.contains("{{context}}") {
            rendered.push_str("\n\n");
            rendered.push_str(base_context);
        }

        rendered
    }
}

impl ChatProvider for OllamaProvider {
    fn send_message(&self, request: &ChatRequest) -> PtResult<ChatMessage> {
        if request.model_profile.provider != ModelProviderKind::Ollama {
            return Err(PtError::NotSupported {
                operation: request.model_profile.provider.to_string(),
            });
        }

        let system_prompt = self.build_system_prompt(request);

        let mut messages = vec![serde_json::json!({
            "role": "system",
            "content": system_prompt
        })];

        for msg in &request.history {
            messages.push(serde_json::json!({
                "role": match msg.role {
                    ChatRole::User => "user",
                    ChatRole::Assistant => "assistant",
                },
                "content": &msg.content
            }));
        }

        messages.push(serde_json::json!({
            "role": "user",
            "content": &request.user_prompt
        }));

        let mut payload = serde_json::json!({
            "model": &request.model_profile.id,
            "messages": messages,
            "stream": false
        });

        // Apply model parameters if set
        let params = &request.model_profile.parameters;
        if let Some(temperature) = params.temperature {
            payload["temperature"] = serde_json::json!(temperature);
        }
        if let Some(top_p) = params.top_p {
            payload["top_p"] = serde_json::json!(top_p);
        }
        if let Some(top_k) = params.top_k {
            payload["top_k"] = serde_json::json!(top_k);
        }
        if let Some(num_predict) = params.num_predict {
            payload["num_predict"] = serde_json::json!(num_predict);
        }

        let url = format!("{}/api/chat", self.config.endpoint.trim_end_matches('/'));

        let response = self.client.post(&url).json(&payload).send().map_err(|e| {
            if e.is_timeout() {
                PtError::Timeout {
                    operation: "Ollama chat request".to_string(),
                }
            } else if e.is_connect() {
                PtError::ChatServiceUnavailable {
                    message: "Ollama service is not running or unreachable".to_string(),
                }
            } else {
                PtError::io_with_source("HTTP request failed", e)
            }
        })?;

        if !response.status().is_success() {
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Err(PtError::ChatModelNotFound {
                    model_id: request.model_profile.id.clone(),
                });
            } else {
                return Err(PtError::ChatServiceUnavailable {
                    message: "Ollama service returned error status".to_string(),
                });
            }
        }

        let resp_json: serde_json::Value = response
            .json()
            .map_err(|e| PtError::io_with_source("Failed to parse Ollama response", e))?;

        let content = resp_json["message"]["content"]
            .as_str()
            .ok_or_else(|| PtError::Chat {
                message: "Missing content in response".to_string(),
                source: None,
            })?;

        Ok(ChatMessage::new(ChatRole::Assistant, content.to_string()))
    }

    fn check_availability(&self) -> PtResult<bool> {
        let url = format!("{}/api/tags", self.config.endpoint.trim_end_matches('/'));

        let response = self.client.get(&url).send().map_err(|e| {
            if e.is_connect() {
                PtError::ChatServiceUnavailable {
                    message: "Ollama service is not running or unreachable".to_string(),
                }
            } else {
                PtError::io_with_source("HTTP request failed", e)
            }
        })?;

        Ok(response.status().is_success())
    }

    fn provider_name(&self) -> &str {
        "ollama"
    }

    /// Get list of available models from Ollama
    fn list_available_models(&self) -> PtResult<Vec<String>> {
        let url = format!("{}/api/tags", self.config.endpoint.trim_end_matches('/'));

        let response = self.client.get(&url).send().map_err(|e| {
            if e.is_connect() {
                PtError::ChatServiceUnavailable {
                    message: "Ollama service is not running or unreachable".to_string(),
                }
            } else {
                PtError::io_with_source("HTTP request failed", e)
            }
        })?;

        if !response.status().is_success() {
            return Err(PtError::ChatServiceUnavailable {
                message: "Ollama service returned error status".to_string(),
            });
        }

        let resp_json: serde_json::Value = response
            .json()
            .map_err(|e| PtError::io_with_source("Failed to parse Ollama response", e))?;

        let models = resp_json["models"]
            .as_array()
            .ok_or_else(|| PtError::Chat {
                message: "Missing models array in response".to_string(),
                source: None,
            })?;

        let model_names = models
            .iter()
            .filter_map(|model| model["name"].as_str())
            .map(|name| name.to_string())
            .collect();

        Ok(model_names)
    }
}
