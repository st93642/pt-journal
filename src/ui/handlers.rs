//! Simple closure-based UI event hooks.
//!
//! This module wires GTK signals directly to closures or controller logic.
//! The previous trait-based handler abstraction has been replaced with
//! lightweight callback structs that keep the event flow explicit and easy
//! to follow.

use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{ApplicationWindow, Button, ListBox};
use std::rc::Rc;

use crate::ui::controllers::{chat, navigation, notes, quiz, tool};
use crate::ui::detail_panel::DetailPanel;
use crate::ui::state::StateManager;

/// Simple struct that stores closure callbacks for common UI events.
#[derive(Clone)]
pub struct UIHandlers {
    pub on_step_selected: Rc<dyn Fn(usize)>,
    pub on_note_changed: Rc<dyn Fn(usize, usize, String)>,
    pub on_panel_updated: Rc<dyn Fn(String)>,
    pub on_sidebar_toggle: Rc<dyn Fn()>,
}

impl Default for UIHandlers {
    fn default() -> Self {
        Self {
            on_step_selected: Rc::new(|_| {}),
            on_note_changed: Rc::new(|_, _, _| {}),
            on_panel_updated: Rc::new(|_| {}),
            on_sidebar_toggle: Rc::new(|| {}),
        }
    }
}

impl UIHandlers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn step_selected(&self, idx: usize) {
        (self.on_step_selected)(idx);
    }

    pub fn note_changed(&self, phase_idx: usize, step_idx: usize, notes: String) {
        (self.on_note_changed)(phase_idx, step_idx, notes);
    }

    pub fn panel_updated(&self, panel_id: String) {
        (self.on_panel_updated)(panel_id);
    }

    pub fn sidebar_toggled(&self) {
        (self.on_sidebar_toggle)();
    }

    pub fn with_step_selected<F>(mut self, handler: F) -> Self
    where
        F: Fn(usize) + 'static,
    {
        self.on_step_selected = Rc::new(handler);
        self
    }

    pub fn with_note_changed<F>(mut self, handler: F) -> Self
    where
        F: Fn(usize, usize, String) + 'static,
    {
        self.on_note_changed = Rc::new(handler);
        self
    }

    pub fn with_panel_updated<F>(mut self, handler: F) -> Self
    where
        F: Fn(String) + 'static,
    {
        self.on_panel_updated = Rc::new(handler);
        self
    }

    pub fn with_sidebar_toggle<F>(mut self, handler: F) -> Self
    where
        F: Fn() + 'static,
    {
        self.on_sidebar_toggle = Rc::new(handler);
        self
    }
}

/// Wire up quiz widget buttons (Check Answer, View Explanation, Previous/Next)
pub fn setup_quiz_handlers(detail_panel: Rc<DetailPanel>, state: Rc<StateManager>) {
    let controller = quiz::QuizController::new(detail_panel, state);
    controller.bind();
}

/// Wire up tool execution panel (info dialog only)
pub fn setup_tool_execution_handlers(
    detail_panel: Rc<DetailPanel>,
    state: Rc<StateManager>,
    window: &ApplicationWindow,
) {
    let controller = tool::ToolController::new(detail_panel, state, window);
    controller.bind(window);
}

/// Wire up phase combo box selection handler
pub fn setup_phase_handler(
    phase_combo: &gtk4::DropDown,
    steps_list: &ListBox,
    state: Rc<StateManager>,
    detail_panel: Rc<DetailPanel>,
) -> Rc<glib::SignalHandlerId> {
    let controller = navigation::NavigationController::new(state);
    controller.bind_phase_handler(phase_combo, steps_list, &detail_panel)
}

/// Wire up step selection and checkbox handlers
pub fn setup_step_handlers(
    steps_list: &ListBox,
    state: Rc<StateManager>,
    detail_panel: Rc<DetailPanel>,
) {
    let controller = navigation::NavigationController::new(state);
    controller.bind_step_handlers(steps_list, &detail_panel);
}

/// Wire up description text view
pub fn setup_notes_handlers(detail_panel: Rc<DetailPanel>, state: Rc<StateManager>) {
    let controller = notes::NotesController::new(detail_panel, state);
    controller.bind();
}

/// Wire up sidebar toggle button and return the underlying closure handle
pub fn setup_sidebar_handler(btn_sidebar: &Button, left_box: &gtk4::Box) -> UIHandlers {
    let handlers = UIHandlers::default().with_sidebar_toggle({
        let sidebar = left_box.clone();
        move || {
            let is_visible = sidebar.is_visible();
            sidebar.set_visible(!is_visible);
        }
    });

    let toggle_handler = handlers.on_sidebar_toggle.clone();
    btn_sidebar.connect_clicked(move |_| {
        (toggle_handler)();
    });

    handlers
}

/// Wire up chat panel handlers
pub fn setup_chat_handlers(detail_panel: Rc<DetailPanel>, state: Rc<StateManager>) {
    let controller = chat::ChatController::new(detail_panel, state);
    controller.bind();
}

/// Re-export navigation helper functions for backward compatibility
pub use crate::ui::controllers::navigation::{
    clear_detail_panel, load_step_into_panel, rebuild_phase_combo, rebuild_steps_list,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    #[test]
    fn sidebar_toggle_closure_executes() {
        let toggles = Rc::new(Cell::new(0));
        let handlers = UIHandlers::default().with_sidebar_toggle({
            let toggles = toggles.clone();
            move || {
                toggles.set(toggles.get() + 1);
            }
        });

        handlers.sidebar_toggled();
        handlers.sidebar_toggled();

        assert_eq!(toggles.get(), 2);
    }

    #[test]
    fn step_selected_closure_receives_index() {
        let last_index = Rc::new(Cell::new(0usize));
        let handlers = UIHandlers::default().with_step_selected({
            let last_index = last_index.clone();
            move |idx| last_index.set(idx)
        });

        handlers.step_selected(5);

        assert_eq!(last_index.get(), 5);
    }

    #[test]
    fn note_changed_closure_receives_payload() {
        let captured = Rc::new(RefCell::new(None));
        let handlers = UIHandlers::default().with_note_changed({
            let captured = captured.clone();
            move |phase, step, note| {
                *captured.borrow_mut() = Some((phase, step, note));
            }
        });

        handlers.note_changed(1, 2, "hello".to_string());

        let value = captured.borrow();
        let (phase, step, note) = value.as_ref().expect("note should be captured");
        assert_eq!((*phase, *step, note.as_str()), (1, 2, "hello"));
    }
}
