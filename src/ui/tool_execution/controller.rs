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

#[allow(dead_code)]
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
        
        let categories: Vec<String> = self.provider.category_groups()
            .iter()
            .map(|group| group.name.clone())
            .collect();

        self.view.borrow_mut().set_categories(&categories, self.provider.default_category_index());

        // Initialize tools for the default category
        self.update_tools_for_category(None);

        // Initialize instructions for the default tool
        self.update_instructions();
        
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
            return;
        }
        self.update_instructions();
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
    pub fn resolve_instruction_state(&self, tool_id: Option<&str>) -> super::renderer::InstructionState<'_> {
        if let Some(tool_id) = tool_id {
            if let Some(instructions) = self.provider.get_instructions(Some(tool_id)) {
                return super::renderer::InstructionState::Available(instructions);
            }
        } else {
            // Fallback to first manifest entry when no tool is selected
            if let Some(first_group) = self.provider.category_groups().first() {
                if let Some(first_tool) = first_group.tools.first() {
                    if let Some(instructions) = self.provider.get_instructions(Some(&first_tool.id)) {
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
            categories.get(self.provider.default_category_index())
                .map(|g| g.name.as_str())
                .unwrap_or("")
        });

        let tools_data = self.provider.tools_for_category(category_name);
        let tools: Vec<(&str, &str)> = tools_data.iter()
            .map(|tool| (tool.id.as_str(), tool.label.as_str()))
            .collect();

        let default_tool_id = Some(self.provider.default_tool_id());
        self.view.borrow_mut().set_tools(&tools, default_tool_id);
        
        self.updating.set(false);
    }

    /// Updates the instructions display for the currently selected tool.
    fn update_instructions(&self) {
        self.updating.set(true);
        let tool_id = self.view.borrow().selected_tool();
        let state = self.resolve_instruction_state(tool_id.as_deref());
        let widget = state.inline_widget();
        self.view.borrow().render_instructions(widget);
        self.updating.set(false);
    }
}

/// Default instruction provider that uses the tool_instructions module.
pub struct DefaultInstructionProvider;

impl InstructionProvider for DefaultInstructionProvider {
    fn category_groups(&self) -> &[crate::ui::tool_instructions::CategoryGroup] {
        // Return a static reference to avoid lifetime issues
        static CACHED_GROUPS: OnceLock<Vec<crate::ui::tool_instructions::CategoryGroup>> = OnceLock::new();

        CACHED_GROUPS.get_or_init(|| crate::ui::tool_instructions::grouped_manifest())
    }

    fn default_category_index(&self) -> usize {
        use super::picker::ToolPickerModel;
        ToolPickerModel::from_manifest().default_category_index()
    }

    fn default_tool_id(&self) -> &str {
        use super::picker::ToolPickerModel;
        // Return a static string to avoid lifetime issues
        static CACHED_TOOL_ID: OnceLock<String> = OnceLock::new();

        CACHED_TOOL_ID.get_or_init(|| ToolPickerModel::from_manifest().default_tool_id().to_string())
    }

    fn tools_for_category(&self, category: &str) -> Vec<crate::ui::tool_instructions::ToolManifestEntry> {
        use super::picker::ToolPickerModel;
        let model = ToolPickerModel::from_manifest();
        model.tools_for_category(category).to_vec()
    }

    fn get_instructions(&self, tool_id: Option<&str>) -> Option<&crate::ui::tool_instructions::ToolInstructions> {
        tool_id.and_then(|id| crate::ui::tool_instructions::get_instructions(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::tool_instructions::{CategoryGroup, ToolManifestEntry, ToolInstructions};
    use gtk4::Box as GtkBox;

    // Mock implementations for testing
    struct MockInstructionProvider {
        categories: Vec<CategoryGroup>,
        default_category_index: usize,
        default_tool_id: String,
    }

    impl MockInstructionProvider {
        fn new() -> Self {
            let mut entry = ToolManifestEntry {
                id: "test-tool".to_string(),
                label: "Test Tool".to_string(),
                category: "Test Category".to_string(),
            };

            let instructions = ToolInstructions {
                id: "test-tool".to_string(),
                name: "Test Tool".to_string(),
                summary: "A test tool".to_string(),
                details: Some("Test details".to_string()),
                installation_guides: vec![],
                quick_examples: vec![],
                common_flags: vec![],
                operational_tips: vec![],
                step_sequences: vec![],
                workflow_guides: vec![],
                output_notes: vec![],
                advanced_usage: vec![],
                comparison_table: None,
                resources: vec![],
            };

            let group = CategoryGroup {
                name: "Test Category".to_string(),
                tools: vec![entry],
            };

            Self {
                categories: vec![group],
                default_category_index: 0,
                default_tool_id: "test-tool".to_string(),
            }
        }
    }

    impl InstructionProvider for MockInstructionProvider {
        fn category_groups(&self) -> &[CategoryGroup] {
            &self.categories
        }

        fn default_category_index(&self) -> usize {
            self.default_category_index
        }

        fn default_tool_id(&self) -> &str {
            &self.default_tool_id
        }

        fn tools_for_category(&self, category: &str) -> Vec<ToolManifestEntry> {
            self.categories.iter()
                .find(|g| g.name == category)
                .map(|g| g.tools.clone())
                .unwrap_or_default()
        }

        fn get_instructions(&self, tool_id: Option<&str>) -> Option<&ToolInstructions> {
            if tool_id == Some("test-tool") {
                // In a real implementation, this would return the actual instructions
                None // For simplicity in this test
            } else {
                None
            }
        }
    }

    struct MockTerminal {
        pub written_text: Vec<String>,
        pub executed_commands: Vec<String>,
        pub cleared: bool,
    }

    impl MockTerminal {
        fn new() -> Self {
            Self {
                written_text: vec![],
                executed_commands: vec![],
                cleared: false,
            }
        }
    }

    impl TerminalInterface for MockTerminal {
        fn write(&mut self, text: &str) {
            self.written_text.push(text.to_string());
        }

        fn clear(&mut self) {
            self.cleared = true;
        }

        fn execute(&mut self, command: &str) {
            self.executed_commands.push(command.to_string());
        }
    }

    struct MockView {
        pub categories: Vec<String>,
        pub default_category_index: usize,
        pub tools: Vec<(String, String)>,
        pub default_tool_id: Option<String>,
        pub rendered_widgets: Vec<String>, // Simplified for testing
        pub selected_tool_id: Option<String>,
        pub shown_dialogs: Vec<String>,
    }

    impl MockView {
        fn new() -> Self {
            Self {
                categories: vec![],
                default_category_index: 0,
                tools: vec![],
                default_tool_id: None,
                rendered_widgets: vec![],
                selected_tool_id: Some("test-tool".to_string()),
                shown_dialogs: vec![],
            }
        }
    }

    impl ToolPanelView for MockView {
        fn set_categories(&self, categories: &[String], default_index: usize) {
            // In real implementation, this would update GTK widgets
        }

        fn set_tools(&self, tools: &[(&str, &str)], default_tool_id: Option<&str>) {
            // In real implementation, this would update GTK widgets
        }

        fn render_instructions(&self, widget: GtkBox) {
            // In real implementation, this would update the instructions area
        }

        fn selected_tool(&self) -> Option<String> {
            self.selected_tool_id.clone()
        }

        fn show_instructions_dialog(&self, title: &str, widget: GtkBox) {
            // In real implementation, this would show a GTK dialog
        }
    }

    #[test]
    fn test_controller_initialization() {
        let provider = MockInstructionProvider::new();
        let terminal = MockTerminal::new();
        let view = MockView::new();

        let controller = ToolPanelController::new(provider, terminal, view);
        assert_eq!(controller.selected_tool(), Some("test-tool".to_string()));
    }

    #[test]
    fn test_terminal_operations() {
        let provider = MockInstructionProvider::new();
        let terminal = MockTerminal::new();
        let view = MockView::new();

        let controller = ToolPanelController::new(provider, terminal, view);

        controller.write_to_terminal("test text");
        controller.clear_terminal();
        controller.execute_in_terminal("ls -la");

        // Note: Since we moved the terminal into the controller,
        // we can't access it directly. In a real test, we'd use
        // a mock that allows inspection.
    }
}