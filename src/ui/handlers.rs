//! UI event handlers and business logic coordination.
//!
//! This module contains signal handlers for GTK widgets that coordinate between
//! the UI layer and application state. Handlers are designed to be non-blocking
//! and thread-safe, using GTK's main loop for UI updates.
//!
//! ## Threading Constraints
//!
//! - All handlers run on the GTK main thread
//! - State mutations use `Rc<RefCell<>>` for thread safety
//! - Long operations dispatch to background threads
//! - UI updates deferred with `glib::idle_add_local_once`
//!
//! ## Error Handling
//!
//! - Invalid user input shows error dialogs
//! - State inconsistencies log warnings but don't crash
//! - Tool execution errors display in terminal widgets
//! - Network failures show user-friendly messages
//!
//! ## Handler Categories
//!
//! - **Navigation**: Phase/step selection, sidebar interactions
//! - **Content**: Quiz answers, chat messages, note editing
//! - **Tools**: Execution panel, terminal output, configuration
//! - **Files**: Save/load dialogs, evidence management

use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{ApplicationWindow, Button, ListBox};
use std::rc::Rc;

use crate::ui::controllers::{chat, navigation, notes, quiz, tool};
use crate::ui::example_handlers::SidebarToggleHandler;
use crate::ui::handler_base::{create_context, execute_handler};
use crate::ui::detail_panel::DetailPanel;
use crate::ui::state::StateManager;

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

/// Wire up sidebar toggle button
pub fn setup_sidebar_handler(btn_sidebar: &Button, left_box: &gtk4::Box) {
    let handler = SidebarToggleHandler::new(left_box.clone());

    btn_sidebar.connect_clicked(move |_| {
        let context = create_context(
            None, // Sidebar toggle doesn't need state access
            crate::ui::handler_base::EventData::None,
        );

        if let Err(e) = execute_handler(&handler, context) {
            eprintln!("Sidebar toggle handler error: {}", e);
        }
    });
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
