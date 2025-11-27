//! Controller for the tool execution panel.
//!
//! This module contains the business logic for coordinating between
//! the instruction provider, terminal interface, and view. It handles
//! selector changes, instruction resolution, and user interactions.

use super::interfaces::{InstructionProvider, TerminalInterface, ToolPanelView};
use std::sync::OnceLock;

/// Controller that coordinates between the instruction provider,
/// terminal interface, and view components.
pub struct ToolPanelController<P: InstructionProvider, T: TerminalInterface, V: ToolPanelView> {
    provider: P,
    _terminal: std::rc::Rc<std::cell::RefCell<T>>,
    view: std::rc::Rc<std::cell::RefCell<V>>,
    initializing: std::cell::Cell<bool>,
    updating: std::cell::Cell<bool>,
}

impl<P: InstructionProvider, T: TerminalInterface, V: ToolPanelView> ToolPanelController<P, T, V> {
    /// Creates a new controller with the given components.
    pub fn new(provider: P, terminal: T, view: V) -> Self {
        Self {
            provider,
            _terminal: std::rc::Rc::new(std::cell::RefCell::new(terminal)),
            view: std::rc::Rc::new(std::cell::RefCell::new(view)),
            initializing: std::cell::Cell::new(false),
            updating: std::cell::Cell::new(false),
        }
    }

    /// Initializes the view with categories and tools.
    pub fn initialize(&self) {
        self.initializing.set(true);

        let categories: Vec<String> = self
            .provider
            .category_groups()
            .iter()
            .map(|group| group.name.clone())
            .collect();

        self.view
            .borrow_mut()
            .set_categories(&categories, self.provider.default_category_index());

        // Initialize tools for the default category
        self.update_tools_for_category(None);

        self.initializing.set(false);
    }

    /// Handles category selection changes.
    pub fn on_category_changed(&self, category_name: Option<&str>) {
        if self.initializing.get() || self.updating.get() {
            return;
        }
        self.update_tools_for_category(category_name);
    }

    /// Handles tool selection changes.
    pub fn on_tool_changed(&self) {
        if self.initializing.get() || self.updating.get() {
            // No longer updating inline instructions display
        }
    }

    /// Shows the instructions dialog for the currently selected tool.
    pub fn show_instructions_dialog(&self) {
        let tool_id = self.view.borrow().selected_tool();
        let state = self.resolve_instruction_state(tool_id.as_deref());
        let title = state.dialog_title();
        let widget = state.inline_widget();
        self.view.borrow().show_instructions_dialog(&title, widget);
    }

    /// Writes text to the terminal.
    pub fn write_to_terminal(&self, text: &str) {
        self._terminal.borrow_mut().write(text);
    }

    /// Clears the terminal.
    pub fn clear_terminal(&self) {
        self._terminal.borrow_mut().clear();
    }

    /// Executes a command in the terminal.
    pub fn execute_in_terminal(&self, command: &str) {
        self._terminal.borrow_mut().execute(command);
    }

    /// Returns the currently selected tool ID.
    pub fn selected_tool(&self) -> Option<String> {
        self.view.borrow().selected_tool()
    }

    /// Resolves instruction state for the given tool ID (exposed for panel use).
    pub fn resolve_instruction_state(
        &self,
        tool_id: Option<&str>,
    ) -> super::renderer::InstructionState<'_> {
        if let Some(tool_id) = tool_id {
            if let Some(instructions) = self.provider.get_instructions(Some(tool_id)) {
                return super::renderer::InstructionState::Available(instructions);
            }
        } else {
            // Fallback to first manifest entry when no tool is selected
            if let Some(first_group) = self.provider.category_groups().first() {
                if let Some(first_tool) = first_group.tools.first() {
                    if let Some(instructions) = self.provider.get_instructions(Some(&first_tool.id))
                    {
                        return super::renderer::InstructionState::Available(instructions);
                    }
                }
            }
        }

        super::renderer::InstructionState::Missing {
            tool_id: tool_id.map(|s| s.to_string()),
        }
    }

    /// Updates the tools for the given category (or default category if None).
    fn update_tools_for_category(&self, category_name: Option<&str>) {
        self.updating.set(true);

        let category_name = category_name.unwrap_or_else(|| {
            let categories = self.provider.category_groups();
            categories
                .get(self.provider.default_category_index())
                .map(|g| g.name.as_str())
                .unwrap_or("")
        });

        let tools_data = self.provider.tools_for_category(category_name);
        let tools: Vec<(&str, &str)> = tools_data
            .iter()
            .map(|tool| (tool.id.as_str(), tool.label.as_str()))
            .collect();

        let default_tool_id = Some(self.provider.default_tool_id());
        self.view.borrow_mut().set_tools(&tools, default_tool_id);

        self.updating.set(false);
    }
}

/// Default instruction provider that uses the tool_instructions module.
pub struct DefaultInstructionProvider;

impl InstructionProvider for DefaultInstructionProvider {
    fn category_groups(&self) -> &[crate::ui::tool_instructions::CategoryGroup] {
        // Return a static reference to avoid lifetime issues
        static CACHED_GROUPS: OnceLock<Vec<crate::ui::tool_instructions::CategoryGroup>> =
            OnceLock::new();

        CACHED_GROUPS.get_or_init(crate::ui::tool_instructions::grouped_manifest)
    }

    fn default_category_index(&self) -> usize {
        use super::picker::ToolPickerModel;
        ToolPickerModel::from_manifest().default_category_index()
    }

    fn default_tool_id(&self) -> &str {
        use super::picker::ToolPickerModel;
        // Return a static string to avoid lifetime issues
        static CACHED_TOOL_ID: OnceLock<String> = OnceLock::new();

        CACHED_TOOL_ID.get_or_init(|| {
            ToolPickerModel::from_manifest()
                .default_tool_id()
                .to_string()
        })
    }

    fn tools_for_category(
        &self,
        category: &str,
    ) -> Vec<crate::ui::tool_instructions::ToolManifestEntry> {
        use super::picker::ToolPickerModel;
        let model = ToolPickerModel::from_manifest();
        model.tools_for_category(category).to_vec()
    }

    fn get_instructions(
        &self,
        tool_id: Option<&str>,
    ) -> Option<&crate::ui::tool_instructions::ToolInstructions> {
        tool_id.and_then(crate::ui::tool_instructions::get_instructions)
    }
}
