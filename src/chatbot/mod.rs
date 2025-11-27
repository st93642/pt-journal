mod ollama;
mod provider;
mod registry;
mod request;
mod service;

pub use ollama::OllamaProvider;
pub use provider::ChatProvider;
pub use registry::ProviderRegistry;
pub use request::{ChatRequest, StepContext};
pub use service::ChatService;

// Re-export for backward compatibility
pub use service::ChatService as LocalChatBot;

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
                    let notes = step.notes.clone();
                    let evidence = step.evidence.clone();
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
                        if let Some(quiz) = step.quiz_data.as_ref() {
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
