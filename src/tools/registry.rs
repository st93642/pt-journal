/// Tool registry for managing tool instruction metadata
///
/// This registry tracks tool instruction information but does not
/// provide actual tool execution capabilities.
use std::collections::HashSet;

/// Registry for managing tool instruction metadata
pub struct ToolRegistry {
    available_tools: HashSet<String>,
}

impl ToolRegistry {
    /// Create new empty registry
    pub fn new() -> Self {
        Self {
            available_tools: HashSet::new(),
        }
    }

    /// Mark a tool as having instructions available
    pub fn register_instructions(&mut self, tool_name: &str) {
        self.available_tools.insert(tool_name.to_string());
    }

    /// Check if a tool has instructions available
    pub fn has_instructions(&self, tool_name: &str) -> bool {
        self.available_tools.contains(tool_name)
    }

    /// List all tools with available instructions
    pub fn list_tools(&self) -> Vec<String> {
        self.available_tools.iter().cloned().collect()
    }

    /// Get count of tools with instructions
    pub fn count(&self) -> usize {
        self.available_tools.len()
    }

    /// Clear all registered tools
    pub fn clear(&mut self) {
        self.available_tools.clear();
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}
