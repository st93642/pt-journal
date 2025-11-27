//! Common state update implementations.
//!
//! This module provides concrete implementations of the StateUpdater trait
//! for common state management operations. These can be used to refactor
//! complex RefCell patterns in the StateManager into cleaner, testable updates.

use crate::model::{StepStatus, ChatMessage, Evidence};
use crate::state::updater::{StateUpdater, UpdateContext, ModelAccessor, EventDispatcher};
use crate::error::Result as PtResult;
use uuid::Uuid;

/// State update for selecting a phase.
pub struct SelectPhase {
    pub phase_idx: usize,
}

impl StateUpdater for SelectPhase {
    type Result = ();

    fn update(&self, context: &UpdateContext) -> PtResult<()> {
        // Validate phase exists
        context.model.with_phase(self.phase_idx, |_| ())?;

        // Update model
        {
            let mut model = context.model.borrow_mut();
            model.set_selected_phase(self.phase_idx);
            model.set_selected_step(None);
        }

        // Dispatch events
        context.dispatcher.dispatch_phase_selected(self.phase_idx);
        context.dispatcher.borrow().emit(crate::dispatcher::AppEvent::RefreshStepList(self.phase_idx));

        Ok(())
    }
}

/// State update for selecting a step.
pub struct SelectStep {
    pub step_idx: usize,
}

impl StateUpdater for SelectStep {
    type Result = ();

    fn update(&self, context: &UpdateContext) -> PtResult<()> {
        let phase_idx = {
            let model = context.model.borrow();
            model.selected_phase()
        };

        // Validate step exists
        context.model.with_step(phase_idx, self.step_idx, |_| ())?;

        // Update model
        {
            let mut model = context.model.borrow_mut();
            model.set_selected_step(Some(self.step_idx));
        }

        // Dispatch events
        context.dispatcher.dispatch_step_selected(self.step_idx);
        context.dispatcher.borrow().emit(crate::dispatcher::AppEvent::RefreshDetailView(phase_idx, self.step_idx));

        Ok(())
    }
}

/// State update for changing step status.
pub struct UpdateStepStatus {
    pub phase_idx: usize,
    pub step_idx: usize,
    pub status: StepStatus,
}

impl StateUpdater for UpdateStepStatus {
    type Result = ();

    fn update(&self, context: &UpdateContext) -> PtResult<()> {
        context.model.with_step_mut(self.phase_idx, self.step_idx, |step| {
            step.status = self.status.clone();
            if matches!(self.status, StepStatus::Done) {
                step.completed_at = Some(chrono::Utc::now());
            } else {
                step.completed_at = None;
            }
        })?;

        context.dispatcher.dispatch_step_status_changed(self.phase_idx, self.step_idx, self.status.clone());

        Ok(())
    }
}

/// State update for updating step notes.
pub struct UpdateStepNotes {
    pub phase_idx: usize,
    pub step_idx: usize,
    pub notes: String,
}

impl StateUpdater for UpdateStepNotes {
    type Result = ();

    fn update(&self, context: &UpdateContext) -> PtResult<()> {
        context.model.with_step_mut(self.phase_idx, self.step_idx, |step| {
            step.set_notes(self.notes.clone());
        })?;

        context.dispatcher.dispatch_step_notes_updated(self.phase_idx, self.step_idx, self.notes.clone());

        Ok(())
    }
}

/// State update for updating step description notes.
pub struct UpdateStepDescriptionNotes {
    pub phase_idx: usize,
    pub step_idx: usize,
    pub notes: String,
}

impl StateUpdater for UpdateStepDescriptionNotes {
    type Result = ();

    fn update(&self, context: &UpdateContext) -> PtResult<()> {
        context.model.with_step_mut(self.phase_idx, self.step_idx, |step| {
            step.set_description_notes(self.notes.clone());
        })?;

        context.dispatcher.borrow().emit(crate::dispatcher::AppEvent::StepDescriptionNotesUpdated(
            self.phase_idx, self.step_idx, self.notes.clone(),
        ));

        Ok(())
    }
}

/// State update for updating phase notes.
pub struct UpdatePhaseNotes {
    pub phase_idx: usize,
    pub notes: String,
}

impl StateUpdater for UpdatePhaseNotes {
    type Result = ();

    fn update(&self, context: &UpdateContext) -> PtResult<()> {
        context.model.with_phase_mut(self.phase_idx, |phase| {
            phase.notes = self.notes.clone();
        })?;

        context.dispatcher.borrow().emit(crate::dispatcher::AppEvent::PhaseNotesUpdated(self.phase_idx, self.notes.clone()));

        Ok(())
    }
}

/// State update for updating global notes.
pub struct UpdateGlobalNotes {
    pub notes: String,
}

impl StateUpdater for UpdateGlobalNotes {
    type Result = ();

    fn update(&self, context: &UpdateContext) -> PtResult<()> {
        {
            let mut model = context.model.borrow_mut();
            model.session_mut().notes_global = self.notes.clone();
        }

        context.dispatcher.borrow().emit(crate::dispatcher::AppEvent::GlobalNotesUpdated(self.notes.clone()));

        Ok(())
    }
}

/// State update for adding a chat message.
pub struct AddChatMessage {
    pub phase_idx: usize,
    pub step_idx: usize,
    pub message: ChatMessage,
}

impl StateUpdater for AddChatMessage {
    type Result = ();

    fn update(&self, context: &UpdateContext) -> PtResult<()> {
        context.model.with_step_mut(self.phase_idx, self.step_idx, |step| {
            step.add_chat_message(self.message.clone());
        })?;

        context.dispatcher.borrow().emit(crate::dispatcher::AppEvent::ChatMessageAdded(
            self.phase_idx, self.step_idx, self.message.clone(),
        ));

        Ok(())
    }
}

/// State update for adding evidence.
pub struct AddEvidence {
    pub phase_idx: usize,
    pub step_idx: usize,
    pub evidence: Evidence,
}

impl StateUpdater for AddEvidence {
    type Result = ();

    fn update(&self, context: &UpdateContext) -> PtResult<()> {
        context.model.with_step_mut(self.phase_idx, self.step_idx, |step| {
            step.add_evidence(self.evidence.clone());
        })?;

        context.dispatcher.borrow().emit(crate::dispatcher::AppEvent::EvidenceAdded(
            self.phase_idx, self.step_idx, self.evidence.clone(),
        ));

        Ok(())
    }
}

/// State update for removing evidence.
pub struct RemoveEvidence {
    pub phase_idx: usize,
    pub step_idx: usize,
    pub evidence_id: Uuid,
}

impl StateUpdater for RemoveEvidence {
    type Result = ();

    fn update(&self, context: &UpdateContext) -> PtResult<()> {
        context.model.with_step_mut(self.phase_idx, self.step_idx, |step| {
            step.remove_evidence(self.evidence_id);
        })?;

        context.dispatcher.borrow().emit(crate::dispatcher::AppEvent::EvidenceRemoved(
            self.phase_idx, self.step_idx, self.evidence_id,
        ));

        Ok(())
    }
}

/// State update for setting chat model.
pub struct SetChatModel {
    pub model_id: String,
}

impl StateUpdater for SetChatModel {
    type Result = ();

    fn update(&self, context: &UpdateContext) -> PtResult<()> {
        {
            let mut model = context.model.borrow_mut();
            model.set_active_chat_model_id(self.model_id.clone());
            model.config_mut().chatbot.default_model_id = self.model_id.clone();
        }

        context.dispatcher.borrow().emit(crate::dispatcher::AppEvent::ChatModelChanged(self.model_id.clone()));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AppModel, ChatRole};
    use std::rc::Rc;
    use std::cell::RefCell;

    fn create_test_context() -> UpdateContext {
        let model = Rc::new(RefCell::new(AppModel::default()));
        let dispatcher = crate::dispatcher::create_event_bus();
        UpdateContext::new(model, dispatcher)
    }

    #[test]
    fn test_select_phase_valid() {
        let context = create_test_context();
        let update = SelectPhase { phase_idx: 0 };
        let result = update.update(&context);
        assert!(result.is_ok());

        let selected = context.model.borrow().selected_phase();
        assert_eq!(selected, 0);
    }

    #[test]
    fn test_select_phase_invalid() {
        let context = create_test_context();
        let update = SelectPhase { phase_idx: 99 };
        let result = update.update(&context);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_step_status() {
        let context = create_test_context();
        let update = UpdateStepStatus {
            phase_idx: 0,
            step_idx: 0,
            status: StepStatus::Done,
        };
        let result = update.update(&context);
        assert!(result.is_ok());

        let mut step_status = None;
        context.model.with_step(0, 0, |step| {
            step_status = Some(step.status.clone());
        }).unwrap();
        assert!(matches!(step_status.unwrap(), StepStatus::Done));
    }

    #[test]
    fn test_update_step_notes() {
        let context = create_test_context();
        let update = UpdateStepNotes {
            phase_idx: 0,
            step_idx: 0,
            notes: "Test notes".to_string(),
        };
        let result = update.update(&context);
        assert!(result.is_ok());

        let mut notes = None;
        context.model.with_step(0, 0, |step| {
            notes = Some(step.get_notes().to_string());
        }).unwrap();
        assert_eq!(notes.unwrap(), "Test notes");
    }

    #[test]
    fn test_add_chat_message() {
        let context = create_test_context();
        let message = ChatMessage::new(ChatRole::User, "Hello".to_string());
        let update = AddChatMessage {
            phase_idx: 0,
            step_idx: 0,
            message: message.clone(),
        };
        let result = update.update(&context);
        assert!(result.is_ok());

        let mut history_len = 0;
        let mut first_content = None;
        context.model.with_step(0, 0, |step| {
            let history = step.get_chat_history();
            history_len = history.len();
            if !history.is_empty() {
                first_content = Some(history[0].content.clone());
            }
        }).unwrap();
        assert_eq!(history_len, 1);
        assert_eq!(first_content.unwrap(), "Hello");
    }

    #[test]
    fn test_set_chat_model() {
        let context = create_test_context();
        let update = SetChatModel {
            model_id: "mistral:7b".to_string(),
        };
        let result = update.update(&context);
        assert!(result.is_ok());

        let model_id = context.model.borrow().get_active_chat_model_id();
        assert_eq!(model_id, "mistral:7b");
    }
}