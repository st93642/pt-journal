use crate::error::PtError;
use crate::error::Result as PtResult;
use chrono::{DateTime, Utc};
use std::path::PathBuf;

use super::chat::ChatMessage;
use super::quiz::QuizStep;
use super::session::Session;
use super::step::{Phase, Step, StepStatus};

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

    pub fn get_active_step_snapshot(&self) -> Option<ActiveStepSnapshot> {
        self.current_step().map(|step| ActiveStepSnapshot {
            title: step.title.clone(),
            description: step.description.clone(),
            status: step.status.clone(),
            completed_at: step.completed_at,
            is_quiz: step.is_quiz(),
            quiz_data: step.quiz_data.clone(),
            chat_history: step.chat_history.clone(),
            related_tools: step.related_tools.clone(),
        })
    }

    // ========== Direct State Mutation Methods ==========

    /// Select a phase and update UI state
    pub fn select_phase(&mut self, phase_idx: usize) -> PtResult<()> {
        // Validate phase exists
        if phase_idx >= self.session.phases.len() {
            return Err(PtError::InvalidPhaseIndex { phase_idx });
        }

        self.selected_phase = phase_idx;
        self.selected_step = None;
        Ok(())
    }

    /// Select a step within current phase
    pub fn select_step(&mut self, step_idx: usize) -> PtResult<()> {
        // Validate step exists
        if step_idx >= self.session.phases[self.selected_phase].steps.len() {
            return Err(PtError::InvalidStepIndex {
                phase_idx: self.selected_phase,
                step_idx,
            });
        }

        self.selected_step = Some(step_idx);
        Ok(())
    }

    /// Update step status
    pub fn update_step_status(
        &mut self,
        phase_idx: usize,
        step_idx: usize,
        status: StepStatus,
    ) -> PtResult<()> {
        let step = self
            .session
            .phases
            .get_mut(phase_idx)
            .and_then(|phase| phase.steps.get_mut(step_idx))
            .ok_or_else(|| PtError::InvalidStepIndex {
                phase_idx,
                step_idx,
            })?;

        step.status = status.clone();
        if matches!(status, StepStatus::Done) {
            step.completed_at = Some(chrono::Utc::now());
        } else {
            step.completed_at = None;
        }

        Ok(())
    }

    /// Add chat message to a step
    pub fn add_chat_message(
        &mut self,
        phase_idx: usize,
        step_idx: usize,
        message: ChatMessage,
    ) -> PtResult<()> {
        let step = self
            .session
            .phases
            .get_mut(phase_idx)
            .and_then(|phase| phase.steps.get_mut(step_idx))
            .ok_or_else(|| PtError::InvalidStepIndex {
                phase_idx,
                step_idx,
            })?;

        step.add_chat_message(message);
        Ok(())
    }

    /// Set the active chat model and update config
    pub fn set_chat_model(&mut self, model_id: String) -> PtResult<()> {
        self.active_chat_model_id = model_id.clone();
        self.config.chatbot.default_model_id = model_id.clone();
        Ok(())
    }

    /// Get chat history for a step
    pub fn get_chat_history(&self, phase_idx: usize, step_idx: usize) -> Vec<ChatMessage> {
        self.session
            .phases
            .get(phase_idx)
            .and_then(|phase| phase.steps.get(step_idx))
            .map(|step| step.chat_history.clone())
            .unwrap_or_default()
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
    pub status: StepStatus,
    pub completed_at: Option<DateTime<Utc>>,
    pub is_quiz: bool,
    pub quiz_data: Option<QuizStep>,
    pub chat_history: Vec<ChatMessage>,
    pub related_tools: Vec<String>,
}
