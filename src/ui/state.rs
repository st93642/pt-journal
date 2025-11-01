/// UI state management module
use std::rc::Rc;
use std::cell::RefCell;
use uuid::Uuid;
use crate::model::{AppModel, StepStatus, Evidence};
use crate::dispatcher::{SharedDispatcher, AppMessage};

/// Shared app model reference for GTK
pub type SharedModel = Rc<RefCell<AppModel>>;

/// State manager for coordinating model updates and dispatcher events
pub struct StateManager {
    model: SharedModel,
    dispatcher: SharedDispatcher,
}

impl StateManager {
    pub fn new(model: SharedModel, dispatcher: SharedDispatcher) -> Self {
        Self { model, dispatcher }
    }
    
    /// Select a phase and update UI
    pub fn select_phase(&self, phase_idx: usize) {
        {
            let mut model = self.model.borrow_mut();
            model.selected_phase = phase_idx;
            model.selected_step = None;
        }
        self.dispatcher.borrow().dispatch(&AppMessage::PhaseSelected(phase_idx));
        self.dispatcher.borrow().dispatch(&AppMessage::RefreshStepList(phase_idx));
    }
    
    /// Select a step within current phase
    pub fn select_step(&self, step_idx: usize) {
        let phase_idx = self.model.borrow().selected_phase;
        {
            let mut model = self.model.borrow_mut();
            model.selected_step = Some(step_idx);
        }
        self.dispatcher.borrow().dispatch(&AppMessage::StepSelected(step_idx));
        self.dispatcher.borrow().dispatch(&AppMessage::RefreshDetailView(phase_idx, step_idx));
        self.dispatcher.borrow().dispatch(&AppMessage::RefreshCanvas(phase_idx, step_idx));
    }
    
    /// Update step status
    pub fn update_step_status(&self, phase_idx: usize, step_idx: usize, status: StepStatus) {
        {
            let mut model = self.model.borrow_mut();
            if let Some(step) = model.session.phases.get_mut(phase_idx)
                .and_then(|p| p.steps.get_mut(step_idx)) {
                step.status = status.clone();
                if matches!(status, StepStatus::Done) {
                    step.completed_at = Some(chrono::Utc::now());
                } else {
                    step.completed_at = None;
                }
            }
        }
        self.dispatcher.borrow().dispatch(&AppMessage::StepStatusChanged(phase_idx, step_idx, status));
    }
    
    /// Update step notes
    pub fn update_step_notes(&self, phase_idx: usize, step_idx: usize, notes: String) {
        {
            let mut model = self.model.borrow_mut();
            if let Some(step) = model.session.phases.get_mut(phase_idx)
                .and_then(|p| p.steps.get_mut(step_idx)) {
                step.set_notes(notes.clone());
            }
        }
        self.dispatcher.borrow().dispatch(&AppMessage::StepNotesUpdated(phase_idx, step_idx, notes));
    }
    
    /// Update step description notes
    pub fn update_step_description_notes(&self, phase_idx: usize, step_idx: usize, notes: String) {
        {
            let mut model = self.model.borrow_mut();
            if let Some(step) = model.session.phases.get_mut(phase_idx)
                .and_then(|p| p.steps.get_mut(step_idx)) {
                step.set_description_notes(notes.clone());
            }
        }
        self.dispatcher.borrow().dispatch(&AppMessage::StepDescriptionNotesUpdated(phase_idx, step_idx, notes));
    }
    
    /// Update phase notes
    pub fn update_phase_notes(&self, phase_idx: usize, notes: String) {
        {
            let mut model = self.model.borrow_mut();
            if let Some(phase) = model.session.phases.get_mut(phase_idx) {
                phase.notes = notes.clone();
            }
        }
        self.dispatcher.borrow().dispatch(&AppMessage::PhaseNotesUpdated(phase_idx, notes));
    }
    
    /// Update global notes
    pub fn update_global_notes(&self, notes: String) {
        {
            let mut model = self.model.borrow_mut();
            model.session.notes_global = notes.clone();
        }
        self.dispatcher.borrow().dispatch(&AppMessage::GlobalNotesUpdated(notes));
    }
    
    /// Add evidence to a step
    pub fn add_evidence(&self, phase_idx: usize, step_idx: usize, evidence: Evidence) {
        {
            let mut model = self.model.borrow_mut();
            if let Some(step) = model.session.phases.get_mut(phase_idx)
                .and_then(|p| p.steps.get_mut(step_idx)) {
                step.add_evidence(evidence.clone());
            }
        }
        self.dispatcher.borrow().dispatch(&AppMessage::EvidenceAdded(phase_idx, step_idx, evidence));
    }
    
    /// Remove evidence from a step
    pub fn remove_evidence(&self, phase_idx: usize, step_idx: usize, evidence_id: Uuid) {
        {
            let mut model = self.model.borrow_mut();
            if let Some(step) = model.session.phases.get_mut(phase_idx)
                .and_then(|p| p.steps.get_mut(step_idx)) {
                step.remove_evidence(evidence_id);
            }
        }
        self.dispatcher.borrow().dispatch(&AppMessage::EvidenceRemoved(phase_idx, step_idx, evidence_id));
    }
    
    /// Move evidence on canvas
    pub fn move_evidence(&self, phase_idx: usize, step_idx: usize, evidence_id: Uuid, x: f64, y: f64) {
        {
            let mut model = self.model.borrow_mut();
            if let Some(step) = model.session.phases.get_mut(phase_idx)
                .and_then(|p| p.steps.get_mut(step_idx)) {
                step.update_evidence_position(evidence_id, x, y);
            }
        }
        self.dispatcher.borrow().dispatch(&AppMessage::EvidenceMoved(phase_idx, step_idx, evidence_id, x, y));
    }
    
    /// Get current phase index
    pub fn current_phase(&self) -> usize {
        self.model.borrow().selected_phase
    }
    
    /// Get current step index
    pub fn current_step(&self) -> Option<usize> {
        self.model.borrow().selected_step
    }
    
    /// Get immutable reference to model for reading
    pub fn model(&self) -> SharedModel {
        self.model.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatcher::create_dispatcher;
    use crate::model::AppModel;
    use std::sync::{Arc, Mutex};
    
    fn create_test_state() -> StateManager {
        let model = Rc::new(RefCell::new(AppModel::default()));
        let dispatcher = create_dispatcher();
        StateManager::new(model, dispatcher)
    }
    
    #[test]
    fn test_select_phase() {
        let state = create_test_state();
        let message_received = Arc::new(Mutex::new(false));
        let msg_clone = message_received.clone();
        
        state.dispatcher.borrow_mut().register("test", Box::new(move |msg| {
            if matches!(msg, AppMessage::PhaseSelected(1)) {
                *msg_clone.lock().unwrap() = true;
            }
        }));
        
        state.select_phase(1);
        assert_eq!(state.current_phase(), 1);
        assert!(state.current_step().is_none());
        assert!(*message_received.lock().unwrap());
    }
    
    #[test]
    fn test_select_step() {
        let state = create_test_state();
        let message_received = Arc::new(Mutex::new(false));
        let msg_clone = message_received.clone();
        
        state.dispatcher.borrow_mut().register("test", Box::new(move |msg| {
            if matches!(msg, AppMessage::StepSelected(2)) {
                *msg_clone.lock().unwrap() = true;
            }
        }));
        
        state.select_step(2);
        assert_eq!(state.current_step(), Some(2));
        assert!(*message_received.lock().unwrap());
    }
    
    #[test]
    fn test_update_step_status() {
        let state = create_test_state();
        let messages = Arc::new(Mutex::new(Vec::new()));
        let msg_clone = messages.clone();
        
        state.dispatcher.borrow_mut().register("test", Box::new(move |msg| {
            msg_clone.lock().unwrap().push(format!("{:?}", msg));
        }));
        
        state.update_step_status(0, 0, StepStatus::Done);
        
        let status = {
            let model = state.model.borrow();
            model.session.phases[0].steps[0].status.clone()
        };
        assert!(matches!(status, StepStatus::Done));
        
        let msgs = messages.lock().unwrap();
        assert!(msgs.iter().any(|m| m.contains("StepStatusChanged")));
    }
    
    #[test]
    fn test_update_step_notes() {
        let state = create_test_state();
        state.update_step_notes(0, 0, "Test notes".to_string());
        
        let notes = {
            let model = state.model.borrow();
            model.session.phases[0].steps[0].notes.clone()
        };
        assert_eq!(notes, "Test notes");
    }
    
    #[test]
    fn test_update_description_notes() {
        let state = create_test_state();
        state.update_step_description_notes(0, 0, "Description notes".to_string());
        
        let notes = {
            let model = state.model.borrow();
            model.session.phases[0].steps[0].description_notes.clone()
        };
        assert_eq!(notes, "Description notes");
    }
    
    #[test]
    fn test_evidence_operations() {
        let state = create_test_state();
        let evidence = Evidence {
            id: uuid::Uuid::new_v4(),
            path: "/test/path.png".to_string(),
            created_at: chrono::Utc::now(),
            kind: "screenshot".to_string(),
            x: 100.0,
            y: 200.0,
        };
        
        let evidence_id = evidence.id;
        state.add_evidence(0, 0, evidence);
        
        let count = {
            let model = state.model.borrow();
            model.session.phases[0].steps[0].evidence.len()
        };
        assert_eq!(count, 1);
        
        state.move_evidence(0, 0, evidence_id, 150.0, 250.0);
        
        let (x, y) = {
            let model = state.model.borrow();
            let ev = &model.session.phases[0].steps[0].evidence[0];
            (ev.x, ev.y)
        };
        assert_eq!(x, 150.0);
        assert_eq!(y, 250.0);
        
        state.remove_evidence(0, 0, evidence_id);
        
        let count = {
            let model = state.model.borrow();
            model.session.phases[0].steps[0].evidence.len()
        };
        assert_eq!(count, 0);
    }
}
