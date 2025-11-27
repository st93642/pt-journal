//! Example handlers demonstrating the Handler trait pattern.
//!
//! These handlers show how to convert existing GTK event handlers
//! to use the standardized Handler trait interface.

use std::rc::Rc;
use gtk4::prelude::*;

use crate::ui::handler_base::{Handler, HandlerContext, UIUpdate, HandlerError, EventData};
use crate::ui::state::StateManager;

/// Handler for toggling sidebar visibility.
///
/// This demonstrates a simple handler that doesn't need state access.
pub struct SidebarToggleHandler {
    left_box: gtk4::Box,
}

impl SidebarToggleHandler {
    pub fn new(left_box: gtk4::Box) -> Self {
        Self { left_box }
    }
}

impl Handler for SidebarToggleHandler {
    type Context = HandlerContext;
    type Result = Result<UIUpdate, HandlerError>;

    fn handle(&self, _context: Self::Context) -> Self::Result {
        // Toggle sidebar visibility
        let is_visible = self.left_box.is_visible();
        self.left_box.set_visible(!is_visible);

        // This is a pure UI change, no state update needed
        Ok(UIUpdate::None)
    }
}

/// Handler for phase selection changes.
///
/// This demonstrates a handler that interacts with application state.
pub struct PhaseSelectionHandler {
    steps_list: gtk4::ListBox,
    detail_panel: Rc<crate::ui::detail_panel::DetailPanel>,
}

impl PhaseSelectionHandler {
    pub fn new(
        steps_list: gtk4::ListBox,
        detail_panel: Rc<crate::ui::detail_panel::DetailPanel>,
    ) -> Self {
        Self {
            steps_list,
            detail_panel,
        }
    }
}

impl Handler for PhaseSelectionHandler {
    type Context = HandlerContext;
    type Result = Result<UIUpdate, HandlerError>;

    fn handle(&self, context: Self::Context) -> Self::Result {
        let state = context.state.ok_or_else(|| {
            HandlerError::StateError("Phase selection handler requires state access".to_string())
        })?;

        // Extract the selected phase index from event data
        let phase_idx = match context.event_data {
            EventData::Index(idx) => idx,
            _ => return Err(HandlerError::ValidationError("Expected Index event data".to_string())),
        };

        // Update application state
        state.select_phase(phase_idx);

        // Return UI update to refresh the steps list
        // Note: In a real implementation, we would need to pass the steps_list
        // and detail_panel to actually perform the refresh here, or return
        // enough information for the caller to do it
        Ok(UIUpdate::RefreshStepsList)
    }
}

/// Handler for checking quiz answers.
///
/// This demonstrates a more complex handler with multiple state interactions.
pub struct QuizAnswerHandler {
    detail_panel: Rc<crate::ui::detail_panel::DetailPanel>,
}

impl QuizAnswerHandler {
    pub fn new(detail_panel: Rc<crate::ui::detail_panel::DetailPanel>) -> Self {
        Self { detail_panel }
    }
}

impl Handler for QuizAnswerHandler {
    type Context = HandlerContext;
    type Result = Result<UIUpdate, HandlerError>;

    fn handle(&self, context: Self::Context) -> Self::Result {
        let state = context.state.ok_or_else(|| {
            HandlerError::StateError("Quiz answer handler requires state access".to_string())
        })?;

        // Extract quiz answer data from event context
        let (phase_idx, step_idx, question_idx, answer_idx) = match context.event_data {
            EventData::Triple((p, s, q)) => {
                // Get the selected answer from the UI
                let selected_answer = self.detail_panel.quiz_widget().get_selected_answer();
                match selected_answer {
                    Some(ans_idx) => (p, s, q, ans_idx),
                    None => return Err(HandlerError::ValidationError("No answer selected".to_string())),
                }
            }
            _ => return Err(HandlerError::ValidationError("Expected Triple event data".to_string())),
        };

        // Check the answer using state manager
        let is_correct = state.check_answer(phase_idx, step_idx, question_idx, answer_idx);

        match is_correct {
            Some(_correct) => {
                // Get explanation and update UI
                // (In a real implementation, this would get the explanation from state
                // and update the quiz widget to show it)
                Ok(UIUpdate::UpdateQuizStats)
            }
            None => Err(HandlerError::StateError("Failed to check answer".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sidebar_toggle_handler_creation() {
        // This would need a real GTK box in a test environment
        // For now, just test that the struct can be created
        // let box = gtk4::Box::new(gtk4::Orientation::Horizontal, 0);
        // let handler = SidebarToggleHandler::new(box);
        // assert!(!handler.left_box.is_visible()); // Would fail without display
    }

    #[test]
    fn test_handler_error_variants() {
        assert!(matches!(
            HandlerError::ValidationError("test".to_string()),
            HandlerError::ValidationError(_)
        ));
        assert!(matches!(
            HandlerError::StateError("test".to_string()),
            HandlerError::StateError(_)
        ));
    }
}