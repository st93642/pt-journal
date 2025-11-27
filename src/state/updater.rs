//! State update abstraction for consistent state management patterns.
//!
//! This module provides a standardized interface for updating application state
//! in a thread-safe manner with proper error handling and event dispatching.
//!
//! ## State Update Pattern
//!
//! State updates follow a consistent pattern:
//! 1. Validate input parameters
//! 2. Borrow the model mutably
//! 3. Apply the state change
//! 4. Dispatch appropriate events
//! 5. Return success/failure with context
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::state::updater::{StateUpdater, UpdateContext, UpdateResult};
//!
//! struct MyStateUpdate {
//!     phase_idx: usize,
//!     step_idx: usize,
//!     new_status: StepStatus,
//! }
//!
//! impl StateUpdater for MyStateUpdate {
//!     fn update(&self, context: &UpdateContext) -> UpdateResult<()> {
//!         // Validate and update state
//!         Ok(())
//!     }
//! }
//! ```

use crate::dispatcher::{AppEvent, SharedEventBus};
use crate::error::{PtError, Result as PtResult};
use crate::model::StepStatus;
use crate::ui::state::SharedModel;

/// Context provided to state updaters containing dependencies.
#[derive(Clone)]
pub struct UpdateContext {
    /// Shared model reference for state mutations
    pub model: SharedModel,
    /// Event bus for sending events
    pub dispatcher: SharedEventBus,
}

impl UpdateContext {
    /// Create a new update context.
    pub fn new(model: SharedModel, dispatcher: SharedEventBus) -> Self {
        Self { model, dispatcher }
    }
}

/// Result type for state update operations.
pub type UpdateResult<T> = PtResult<T>;

/// Trait for state update operations.
///
/// Implementors of this trait encapsulate a specific state change
/// with validation, mutation, and event dispatching logic.
pub trait StateUpdater {
    /// The return type of the update operation.
    type Result;

    /// Perform the state update with the given context.
    ///
    /// # Arguments
    /// * `context` - The update context containing model and dispatcher
    ///
    /// # Returns
    /// Result of the update operation
    fn update(&self, context: &UpdateContext) -> PtResult<Self::Result>;
}

/// Helper trait for accessing model data with validation.
pub trait ModelAccessor {
    /// Access a phase immutably with validation, passing the result to a closure.
    fn with_phase<F, T>(&self, phase_idx: usize, f: F) -> PtResult<T>
    where
        F: FnOnce(&crate::model::Phase) -> T;

    /// Access a phase mutably with validation, passing the result to a closure.
    fn with_phase_mut<F, T>(&self, phase_idx: usize, f: F) -> PtResult<T>
    where
        F: FnOnce(&mut crate::model::Phase) -> T;

    /// Access a step immutably with validation, passing the result to a closure.
    fn with_step<F, T>(&self, phase_idx: usize, step_idx: usize, f: F) -> PtResult<T>
    where
        F: FnOnce(&crate::model::Step) -> T;

    /// Access a step mutably with validation, passing the result to a closure.
    fn with_step_mut<F, T>(&self, phase_idx: usize, step_idx: usize, f: F) -> PtResult<T>
    where
        F: FnOnce(&mut crate::model::Step) -> T;
}

impl ModelAccessor for SharedModel {
    fn with_phase<F, T>(&self, phase_idx: usize, f: F) -> PtResult<T>
    where
        F: FnOnce(&crate::model::Phase) -> T,
    {
        let model = self.borrow();
        if let Some(phase) = model.session().phases.get(phase_idx) {
            Ok(f(phase))
        } else {
            Err(PtError::InvalidPhaseIndex { phase_idx })
        }
    }

    fn with_phase_mut<F, T>(&self, phase_idx: usize, f: F) -> PtResult<T>
    where
        F: FnOnce(&mut crate::model::Phase) -> T,
    {
        let mut model = self.borrow_mut();
        if let Some(phase) = model.session_mut().phases.get_mut(phase_idx) {
            Ok(f(phase))
        } else {
            Err(PtError::InvalidPhaseIndex { phase_idx })
        }
    }

    fn with_step<F, T>(&self, phase_idx: usize, step_idx: usize, f: F) -> PtResult<T>
    where
        F: FnOnce(&crate::model::Step) -> T,
    {
        let model = self.borrow();
        if let Some(phase) = model.session().phases.get(phase_idx) {
            if let Some(step) = phase.steps.get(step_idx) {
                Ok(f(step))
            } else {
                Err(PtError::InvalidStepIndex { phase_idx, step_idx })
            }
        } else {
            Err(PtError::InvalidPhaseIndex { phase_idx })
        }
    }

    fn with_step_mut<F, T>(&self, phase_idx: usize, step_idx: usize, f: F) -> PtResult<T>
    where
        F: FnOnce(&mut crate::model::Step) -> T,
    {
        let mut model = self.borrow_mut();
        if let Some(phase) = model.session_mut().phases.get_mut(phase_idx) {
            if let Some(step) = phase.steps.get_mut(step_idx) {
                Ok(f(step))
            } else {
                Err(PtError::InvalidStepIndex { phase_idx, step_idx })
            }
        } else {
            Err(PtError::InvalidPhaseIndex { phase_idx })
        }
    }
}

/// Helper trait for dispatching common events.
pub trait EventDispatcher {
    /// Dispatch a phase selection event.
    fn dispatch_phase_selected(&self, phase_idx: usize);

    /// Dispatch a step selection event.
    fn dispatch_step_selected(&self, step_idx: usize);

    /// Dispatch a step status change event.
    fn dispatch_step_status_changed(&self, phase_idx: usize, step_idx: usize, status: StepStatus);

    /// Dispatch a step notes update event.
    fn dispatch_step_notes_updated(&self, phase_idx: usize, step_idx: usize, notes: String);

    /// Dispatch an error event.
    fn dispatch_error(&self, error: String);
}

impl EventDispatcher for SharedEventBus {
    fn dispatch_phase_selected(&self, phase_idx: usize) {
        self.borrow().emit(AppEvent::PhaseSelected(phase_idx));
    }

    fn dispatch_step_selected(&self, step_idx: usize) {
        self.borrow().emit(AppEvent::StepSelected(step_idx));
    }

    fn dispatch_step_status_changed(&self, phase_idx: usize, step_idx: usize, status: StepStatus) {
        self.borrow().emit(AppEvent::StepStatusChanged(phase_idx, step_idx, status));
    }

    fn dispatch_step_notes_updated(&self, phase_idx: usize, step_idx: usize, notes: String) {
        self.borrow().emit(AppEvent::StepNotesUpdated(phase_idx, step_idx, notes));
    }

    fn dispatch_error(&self, error: String) {
        self.borrow().emit(AppEvent::Error(error));
    }
}

/// Convenience macro for executing state updates.
///
/// This macro handles the common pattern of creating an update,
/// executing it, and handling errors.
///
/// # Example
///
/// ```rust,ignore
/// execute_update!(context, UpdateStepStatus::new(0, 0, StepStatus::Done))
/// ```
#[macro_export]
macro_rules! execute_update {
    ($context:expr, $update:expr) => {
        $update.update($context)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AppModel;
    use std::rc::Rc;
    use std::cell::RefCell;

    fn create_test_context() -> UpdateContext {
        let model = Rc::new(RefCell::new(AppModel::default()));
        let dispatcher = crate::dispatcher::create_event_bus();
        UpdateContext::new(model, dispatcher)
    }

    #[test]
    fn test_update_context_creation() {
        let _context = create_test_context();
        // Context should be created successfully
        assert!(true); // If we get here, creation worked
    }

    #[test]
    fn test_model_accessor_valid_phase() {
        let context = create_test_context();
        let result = context.model.with_phase(0, |_| ());
        assert!(result.is_ok());
    }

    #[test]
    fn test_model_accessor_invalid_phase() {
        let context = create_test_context();
        let result = context.model.with_phase(99, |_| ());
        assert!(matches!(result, Err(PtError::InvalidPhaseIndex { phase_idx: 99 })));
    }

    #[test]
    fn test_model_accessor_valid_step() {
        let context = create_test_context();
        let result = context.model.with_step(0, 0, |_| ());
        assert!(result.is_ok());
    }

    #[test]
    fn test_model_accessor_invalid_step() {
        let context = create_test_context();
        let result = context.model.with_step(0, 99, |_| ());
        assert!(matches!(result, Err(PtError::InvalidStepIndex { phase_idx: 0, step_idx: 99 })));
    }

    #[test]
    fn test_update_error_display() {
        let err = PtError::InvalidPhaseIndex { phase_idx: 5 };
        assert_eq!(format!("{}", err), "Invalid phase index: 5");

        let err = PtError::InvalidStepIndex { phase_idx: 1, step_idx: 2 };
        assert_eq!(format!("{}", err), "Invalid step index: phase=1, step=2");
    }
}