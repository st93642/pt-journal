/// Mock terminal implementation for testing.
pub struct MockTerminal {
    pub written_text: Vec<String>,
    pub executed_commands: Vec<String>,
    pub cleared: bool,
}

impl MockTerminal {
    pub fn new() -> Self {
        Self {
            written_text: vec![],
            executed_commands: vec![],
            cleared: false,
        }
    }
}

impl Default for MockTerminal {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::ui::tool_execution::interfaces::TerminalInterface for MockTerminal {
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

/// Mock view implementation for testing.
pub struct MockView {
    pub categories: Vec<String>,
    pub default_category_index: usize,
    pub tools: Vec<(String, String)>,
    pub default_tool_id: Option<String>,
    pub rendered_widgets: Vec<String>, // Simplified for testing
    pub selected_tool_id: Option<String>,
    pub shown_dialogs: Vec<String>,
}

impl MockView {
    pub fn new() -> Self {
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

impl Default for MockView {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::ui::tool_execution::interfaces::ToolPanelView for MockView {
    fn set_categories(&self, _categories: &[String], _default_index: usize) {
        // In real implementation, this would update GTK widgets
    }

    fn set_tools(&self, _tools: &[(&str, &str)], _default_tool_id: Option<&str>) {
        // In real implementation, this would update GTK widgets
    }

    fn render_instructions(&self, _widget: gtk4::Box) {
        // In real implementation, this would update the instructions area
    }

    fn selected_tool(&self) -> Option<String> {
        self.selected_tool_id.clone()
    }

    fn show_instructions_dialog(&self, _title: &str, _widget: gtk4::Box) {
        // In real implementation, this would show a GTK dialog
    }

    fn tool_id_at_index(&self, _index: usize) -> Option<String> {
        // Mock implementation - just return a dummy ID
        Some("mock-tool-id".to_string())
    }
}

/// Mock instruction provider for testing.
pub struct MockInstructionProvider {
    pub categories: Vec<crate::ui::tool_instructions::CategoryGroup>,
    pub default_category_index: usize,
    pub default_tool_id: String,
}

impl MockInstructionProvider {
    pub fn new() -> Self {
        let entry = crate::ui::tool_instructions::ToolManifestEntry {
            id: "test-tool".to_string(),
            label: "Test Tool".to_string(),
            category: "Test Category".to_string(),
        };

        let _instructions = crate::ui::tool_instructions::ToolInstructions {
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

        let group = crate::ui::tool_instructions::CategoryGroup {
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

impl Default for MockInstructionProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::ui::tool_execution::interfaces::InstructionProvider for MockInstructionProvider {
    fn category_groups(&self) -> &[crate::ui::tool_instructions::CategoryGroup] {
        &self.categories
    }

    fn default_category_index(&self) -> usize {
        self.default_category_index
    }

    fn default_tool_id(&self) -> &str {
        &self.default_tool_id
    }

    fn tools_for_category(
        &self,
        category: &str,
    ) -> Vec<crate::ui::tool_instructions::ToolManifestEntry> {
        self.categories
            .iter()
            .find(|g| g.name == category)
            .map(|g| g.tools.clone())
            .unwrap_or_default()
    }

    fn get_instructions(
        &self,
        tool_id: Option<&str>,
    ) -> Option<&crate::ui::tool_instructions::ToolInstructions> {
        if tool_id == Some("test-tool") {
            // In a real implementation, this would return the actual instructions
            None // For simplicity in this test
        } else {
            None
        }
    }
}
