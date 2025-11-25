use crate::config::ChatbotConfig;
use crate::model::{ChatMessage, ChatRole, Session, StepStatus};
use reqwest::blocking::Client;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChatError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Ollama service is not running or unreachable. Please ensure Ollama is installed and running. Visit https://ollama.ai for setup instructions.")]
    ServiceUnavailable,
    #[error("Invalid response from Ollama: {0}")]
    InvalidResponse(String),
    #[error("Connection timeout - Ollama took too long to respond")]
    Timeout,
}

pub struct StepContext {
    pub phase_name: String,
    pub step_title: String,
    pub step_description: String,
    pub step_status: String,
    pub notes_count: usize,
    pub evidence_count: usize,
    pub quiz_status: Option<String>,
}

pub struct ContextBuilder;

impl ContextBuilder {
    pub fn build_session_context(
        session: &Session,
        current_phase_idx: usize,
        current_step_idx: usize,
    ) -> String {
        let mut context = String::new();
        context.push_str("Current Session Summary:\n");

        for (idx, phase) in session.phases.iter().enumerate() {
            let status = if idx < current_phase_idx {
                "Completed"
            } else if idx == current_phase_idx {
                "In Progress"
            } else {
                "Pending"
            };
            context.push_str(&format!(
                "- Phase {}: {} ({})\n",
                idx + 1,
                phase.name,
                status
            ));

            if idx == current_phase_idx {
                for (sidx, step) in phase.steps.iter().enumerate() {
                    let step_status = match step.status {
                        StepStatus::Done => "Done",
                        StepStatus::InProgress => "In Progress",
                        StepStatus::Todo => "Todo",
                        StepStatus::Skipped => "Skipped",
                    };
                    let marker = if sidx == current_step_idx {
                        " <-- CURRENT"
                    } else {
                        ""
                    };
                    let notes = step.get_notes();
                    let evidence = step.get_evidence();
                    context.push_str(&format!(
                        "  - Step {}: {} ({}){}\n",
                        sidx + 1,
                        step.title,
                        step_status,
                        marker
                    ));

                    if !notes.is_empty() {
                        context.push_str(&format!("    Notes: {} characters\n", notes.len()));
                    }
                    if !evidence.is_empty() {
                        context.push_str(&format!("    Evidence: {} items\n", evidence.len()));
                    }
                    if step.is_quiz() {
                        if let Some(quiz) = step.get_quiz_step() {
                            let stats = quiz.statistics();
                            context.push_str(&format!(
                                "    Quiz: {}/{} correct\n",
                                stats.correct, stats.total_questions
                            ));
                        }
                    }
                }
            }
        }
        context
    }
}

pub struct LocalChatBot {
    config: ChatbotConfig,
    client: Client,
}

impl LocalChatBot {
    pub fn new(config: ChatbotConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .expect("Failed to build HTTP client");
        Self { config, client }
    }

    pub fn send_message(
        &self,
        step_ctx: &StepContext,
        history: &[ChatMessage],
        user_input: &str,
    ) -> Result<ChatMessage, ChatError> {
        let system_prompt = self.build_system_prompt(step_ctx);

        let mut messages = vec![serde_json::json!({
            "role": "system",
            "content": system_prompt
        })];

        for msg in history {
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
            "content": user_input
        }));

        let payload = serde_json::json!({
            "model": &self.config.model,
            "messages": messages,
            "stream": false
        });

        let url = format!("{}/api/chat", self.config.endpoint.trim_end_matches('/'));

        let response = self.client.post(&url).json(&payload).send().map_err(|e| {
            if e.is_timeout() {
                ChatError::Timeout
            } else if e.is_connect() {
                ChatError::ServiceUnavailable
            } else {
                ChatError::Http(e)
            }
        })?;

        if !response.status().is_success() {
            return Err(ChatError::ServiceUnavailable);
        }

        let resp_json: serde_json::Value = response.json().map_err(ChatError::Http)?;

        let content = resp_json["message"]["content"]
            .as_str()
            .ok_or_else(|| ChatError::InvalidResponse("Missing content in response".to_string()))?;

        Ok(ChatMessage::new(ChatRole::Assistant, content.to_string()))
    }

    fn build_system_prompt(&self, step_ctx: &StepContext) -> String {
        format!(
            "You are an expert penetration testing assistant helping with structured pentesting methodology.\n\n\
            Current Context:\n\
            - Phase: {}\n\
            - Step: {} (Status: {})\n\
            - Description: {}\n\
            - Notes: {} characters\n\
            - Evidence: {} items\n\
            {}\n\n\
            Provide helpful, methodology-aligned assistance for general pentesting questions, step-specific guidance, or tool recommendations. \
            Keep responses focused and actionable.",
            step_ctx.phase_name,
            step_ctx.step_title,
            step_ctx.step_status,
            step_ctx.step_description.chars().take(200).collect::<String>(),
            step_ctx.notes_count,
            step_ctx.evidence_count,
            step_ctx.quiz_status.as_ref().map(|s| format!("- Quiz Status: {}", s)).unwrap_or_default()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Session;
    use httpmock::prelude::*;

    #[test]
    fn test_context_builder() {
        let session = Session::default();
        let context = ContextBuilder::build_session_context(&session, 0, 0);
        assert!(context.contains("Current Session Summary"));
        assert!(context.contains("Phase 1: Reconnaissance"));
    }

    #[test]
    fn test_send_message_success() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method("POST")
                .path("/api/chat")
                .body_contains(r#""model":"mistral""#)
                .body_contains(r#""role":"system""#)
                .body_contains("You are an expert penetration testing assistant")
                .body_contains("Current Context");
            then.status(200).json_body(serde_json::json!({
                "message": {
                    "content": "Test response"
                }
            }));
        });

        let config = ChatbotConfig {
            endpoint: server.url(""),
            model: "mistral".to_string(),
            timeout_seconds: 30,
        };
        let bot = LocalChatBot::new(config);
        let step_ctx = StepContext {
            phase_name: "Test Phase".to_string(),
            step_title: "Test Step".to_string(),
            step_description: "Test desc".to_string(),
            step_status: "In Progress".to_string(),
            notes_count: 0,
            evidence_count: 0,
            quiz_status: None,
        };
        let history = vec![];
        let result = bot.send_message(&step_ctx, &history, "Hello");
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg.role, ChatRole::Assistant);
        assert_eq!(msg.content, "Test response");
        mock.assert();
    }

    #[test]
    fn test_send_message_service_unavailable() {
        let config = ChatbotConfig {
            endpoint: "http://invalid:1234".to_string(),
            model: "mistral".to_string(),
            timeout_seconds: 30,
        };
        let bot = LocalChatBot::new(config);
        let step_ctx = StepContext {
            phase_name: "Test".to_string(),
            step_title: "Test".to_string(),
            step_description: "Test".to_string(),
            step_status: "Test".to_string(),
            notes_count: 0,
            evidence_count: 0,
            quiz_status: None,
        };
        let result = bot.send_message(&step_ctx, &[], "Hello");
        assert!(matches!(result, Err(ChatError::ServiceUnavailable)));
    }
}
