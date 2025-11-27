//! Notes controller for handling description text editing.
//!
//! This controller manages the notes/description text view,
//! updating the model when the user edits step descriptions.

use gtk4::prelude::*;
use std::rc::Rc;

use crate::ui::detail_panel::DetailPanel;
use crate::ui::state::StateManager;

/// Notes controller that encapsulates notes-related UI logic.
pub struct NotesController {
    detail_panel: Rc<DetailPanel>,
    state: Rc<StateManager>,
}

impl NotesController {
    /// Create a new notes controller.
    pub fn new(detail_panel: Rc<DetailPanel>, state: Rc<StateManager>) -> Self {
        Self {
            detail_panel,
            state,
        }
    }

    /// Bind all notes-related event handlers.
    pub fn bind(&self) {
        self.bind_description_text_view();
    }

    /// Bind the description text view change handler.
    fn bind_description_text_view(&self) {
        let desc_view = self.detail_panel.desc_view().clone();
        let state = self.state.clone();

        // Description notes handler
        desc_view.buffer().connect_changed(move |buffer| {
            let text = buffer
                .text(&buffer.start_iter(), &buffer.end_iter(), false)
                .to_string();
            let (phase_idx, step_idx) = {
                let model_rc = state.model();
                let model = model_rc.borrow();
                (model.selected_phase(), model.selected_step())
            };
            if let Some(step_idx) = step_idx {
                // Use state manager to update (dispatches events)
                state.update_step_description_notes(phase_idx, step_idx, text);
            }
        });
    }
}
