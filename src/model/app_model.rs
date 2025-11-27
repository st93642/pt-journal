use chrono::{DateTime, Utc};
use std::path::PathBuf;

use super::chat::ChatMessage;
use super::quiz::QuizStep;
use super::session::Session;
use super::step::{Evidence, Phase, Step, StepStatus};

/// Core application model holding all state.
///
/// This struct encapsulates the application's data model with proper
/// abstraction barriers. Direct field access is discouraged - use
/// the provided getter/setter methods and StateManager operations instead.
#[derive(Clone, Debug)]
pub struct AppModel {
    /// Current tutorial session with phases and steps
    session: Session,
    /// Index of currently selected phase
    selected_phase: usize,
    /// Index of currently selected step within the phase
    selected_step: Option<usize>,
    /// Current working directory path for the session
    current_path: Option<PathBuf>,
    /// Application configuration
    config: crate::config::AppConfig,
    /// ID of the currently active chat model
    active_chat_model_id: String,
}

impl Default for AppModel {
    fn default() -> Self {
        let config = crate::config::AppConfig::load().unwrap_or_default();
        let active_chat_model_id = config.chatbot.default_model_id.clone();
        Self {
            session: Session::default(),
            selected_phase: 0,
            selected_step: Some(0),
            current_path: None,
            config,
            active_chat_model_id,
        }
    }
}

impl AppModel {
    pub fn get_active_chat_model_id(&self) -> String {
        self.active_chat_model_id.clone()
    }

    pub fn set_active_chat_model_id(&mut self, model_id: String) {
        self.active_chat_model_id = model_id;
    }

    /// Get the current session
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Get mutable reference to session (use with caution)
    pub fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    /// Get the currently selected phase index
    pub fn selected_phase(&self) -> usize {
        self.selected_phase
    }

    /// Set the currently selected phase index
    pub fn set_selected_phase(&mut self, phase_idx: usize) {
        self.selected_phase = phase_idx;
    }

    /// Get the currently selected step index
    pub fn selected_step(&self) -> Option<usize> {
        self.selected_step
    }

    /// Set the currently selected step index
    pub fn set_selected_step(&mut self, step_idx: Option<usize>) {
        self.selected_step = step_idx;
    }

    /// Get the current path
    pub fn current_path(&self) -> Option<&PathBuf> {
        self.current_path.as_ref()
    }

    /// Set the current path
    pub fn set_current_path(&mut self, path: Option<PathBuf>) {
        self.current_path = path;
    }

    /// Get the configuration
    pub fn config(&self) -> &crate::config::AppConfig {
        &self.config
    }

    /// Get mutable reference to config (use with caution)
    pub fn config_mut(&mut self) -> &mut crate::config::AppConfig {
        &mut self.config
    }

    /// Get a read-only view of a phase by index
    pub fn phase(&self, idx: usize) -> Option<&Phase> {
        self.session.phases.get(idx)
    }

    /// Get the number of phases
    pub fn phase_count(&self) -> usize {
        self.session.phases.len()
    }

    /// Get a read-only view of the currently selected phase
    pub fn current_phase(&self) -> Option<&Phase> {
        self.phase(self.selected_phase)
    }

    /// Get a read-only view of a step within the currently selected phase
    pub fn current_step(&self) -> Option<&Step> {
        self.current_phase().and_then(|phase| {
            self.selected_step
                .and_then(|step_idx| phase.steps.get(step_idx))
        })
    }

    /// Get a read-only view of a step by phase and step indices
    pub fn step(&self, phase_idx: usize, step_idx: usize) -> Option<&Step> {
        self.phase(phase_idx)
            .and_then(|phase| phase.steps.get(step_idx))
    }

    /// Get the number of steps in the currently selected phase
    pub fn current_phase_step_count(&self) -> usize {
        self.current_phase()
            .map(|phase| phase.steps.len())
            .unwrap_or(0)
    }

    /// Get summaries of steps for a given phase (for UI display)
    pub fn get_step_summaries_for_phase(&self, phase_idx: usize) -> Vec<StepSummary> {
        self.phase(phase_idx)
            .map(|phase| {
                phase
                    .steps
                    .iter()
                    .enumerate()
                    .map(|(idx, step)| StepSummary {
                        index: idx,
                        title: step.title.clone(),
                        status: step.status.clone(),
                        completed_at: step.completed_at,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get a snapshot of the currently active step
    pub fn get_active_step_snapshot(&self) -> Option<ActiveStepSnapshot> {
        self.current_step().map(|step| ActiveStepSnapshot {
            title: step.title.clone(),
            description: step.get_description(),
            description_notes: step.get_description_notes(),
            status: step.status.clone(),
            completed_at: step.completed_at,
            is_quiz: step.is_quiz(),
            quiz_data: step.get_quiz_step().cloned(),
            chat_history: step.get_chat_history(),
            evidence: step.get_evidence(),
        })
    }
}

/// Summary of a step for UI display
#[derive(Debug, Clone)]
pub struct StepSummary {
    pub index: usize,
    pub title: String,
    pub status: StepStatus,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Snapshot of the currently active step for UI rendering
#[derive(Debug, Clone)]
pub struct ActiveStepSnapshot {
    pub title: String,
    pub description: String,
    pub description_notes: String,
    pub status: StepStatus,
    pub completed_at: Option<DateTime<Utc>>,
    pub is_quiz: bool,
    pub quiz_data: Option<QuizStep>,
    pub chat_history: Vec<ChatMessage>,
    pub evidence: Vec<Evidence>,
}
