//! Traits and interfaces for the tool execution panel.
//!
//! This module defines the contracts that decouple the GTK view from
//! business logic, enabling better testability and extensibility.

use crate::ui::tool_instructions::{CategoryGroup, ToolInstructions};
use gtk4::Box as GtkBox;

/// Provides instruction data for tools, decoupling the panel from
/// the tool_instructions module and enabling mocking in tests.
pub trait InstructionProvider {
    /// Returns all available category groups.
    fn category_groups(&self) -> &[CategoryGroup];

    /// Returns the index of the default category to select.
    fn default_category_index(&self) -> usize;

    /// Returns the ID of the default tool to select.
    fn default_tool_id(&self) -> &str;

    /// Returns tools available in the specified category.
    fn tools_for_category(
        &self,
        category: &str,
    ) -> Vec<crate::ui::tool_instructions::ToolManifestEntry>;

    /// Resolves instruction content for the given tool ID.
    /// Returns None if no instructions are available.
    fn get_instructions(&self, tool_id: Option<&str>) -> Option<&ToolInstructions>;
}

/// Abstracts terminal operations, allowing the panel to work with
/// different terminal implementations or mocks.
pub trait TerminalInterface {
    /// Writes text to the terminal.
    fn write(&mut self, text: &str);

    /// Clears the terminal contents.
    fn clear(&mut self);

    /// Executes a command in the terminal (appends newline).
    fn execute(&mut self, command: &str);
}

/// Abstracts the view operations needed by the controller,
/// allowing the controller to work with different view implementations.
pub trait ToolPanelView {
    /// Updates the category selector with available categories.
    fn set_categories(&self, categories: &[String], default_index: usize);

    /// Updates the tool selector for the current category.
    fn set_tools(&self, tools: &[(&str, &str)], default_tool_id: Option<&str>);

    /// Renders the instruction content in the view.
    fn render_instructions(&self, widget: GtkBox);

    /// Returns the currently selected tool ID.
    fn selected_tool(&self) -> Option<String>;

    /// Shows the instructions dialog.
    fn show_instructions_dialog(&self, title: &str, widget: GtkBox);

    /// Returns the tool ID at the given index.
    fn tool_id_at_index(&self, index: usize) -> Option<String>;
}
