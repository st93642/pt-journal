mod provider;
mod request;
mod service;
mod ollama;

pub use provider::ChatProvider;
pub use request::{ChatRequest, StepContext};
pub use service::ChatService;
pub use ollama::OllamaProvider;

// Re-export for backward compatibility
pub use service::ChatService as LocalChatBot;

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
    #[error("The configured chatbot provider '{0}' is not supported yet")]
    UnsupportedProvider(String),
}

pub struct ContextBuilder;

impl ContextBuilder {
    pub fn build_session_context(
        session: &crate::model::Session,
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
                        crate::model::StepStatus::Done => "Done",
                        crate::model::StepStatus::InProgress => "In Progress",
                        crate::model::StepStatus::Todo => "Todo",
                        crate::model::StepStatus::Skipped => "Skipped",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Session;

    #[test]
    fn test_context_builder() {
        let session = Session::default();
        let context = ContextBuilder::build_session_context(&session, 0, 0);
        assert!(context.contains("Current Session Summary"));
        assert!(context.contains("Phase 1: Reconnaissance"));
    }
}
