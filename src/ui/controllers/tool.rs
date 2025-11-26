//! Tool controller for handling tool execution panel interactions.
//!
//! This controller manages the tool execution panel, including
//! showing instructions and handling tool-related UI events.

use gtk4::{ApplicationWindow, Window};
use gtk4::prelude::*;
use std::rc::Rc;

use crate::ui::detail_panel::DetailPanel;
use crate::ui::state::StateManager;

/// Tool controller that encapsulates tool-related UI logic.
pub struct ToolController {
    detail_panel: Rc<DetailPanel>,
    _state: Rc<StateManager>,
}

impl ToolController {
    /// Create a new tool controller.
    pub fn new(detail_panel: Rc<DetailPanel>, state: Rc<StateManager>, _window: &ApplicationWindow) -> Self {
        Self {
            detail_panel,
            _state: state,
        }
    }

    /// Bind all tool-related event handlers.
    pub fn bind(&self, window: &ApplicationWindow) {
        self.bind_info_button(window);
    }

    /// Bind the info button handler for showing tool instructions.
    fn bind_info_button(&self, window: &ApplicationWindow) {
        let window = window.clone();
        let tool_panel = self.detail_panel.tool_panel();

        // Get the button reference before moving into closure
        let info_button = tool_panel.info_button.clone();
        let tool_panel_clone = tool_panel.clone();

        info_button
            .connect_clicked(move |_| {
                tool_panel_clone.show_instructions_dialog(&window.clone().upcast::<Window>());
            });
    }
}