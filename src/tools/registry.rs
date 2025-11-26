/// Tool registry for managing available security tools
use super::traits::*;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Registry for managing security tool instances
pub struct ToolRegistry {
    tools: Arc<Mutex<HashMap<String, Box<dyn SecurityTool + Send + Sync>>>>,
}

impl ToolRegistry {
    /// Create new empty registry
    pub fn new() -> Self {
        Self {
            tools: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a tool in the registry
    pub fn register(&mut self, tool: Box<dyn SecurityTool + Send + Sync>) -> Result<()> {
        let name = tool.name().to_string();
        let mut tools = self.tools.lock().unwrap();

        if tools.contains_key(&name) {
            anyhow::bail!("Tool '{}' is already registered", name);
        }

        tools.insert(name, tool);
        Ok(())
    }

    /// Get a tool by name (returns true if exists)
    /// TODO: Refactor to use `Arc<SecurityTool>` for proper tool retrieval
    pub fn get(&self, name: &str) -> Option<()> {
        let tools = self.tools.lock().unwrap();
        if tools.contains_key(name) {
            Some(())
        } else {
            None
        }
    }

    /// List all registered tool names
    pub fn list_tools(&self) -> Vec<String> {
        let tools = self.tools.lock().unwrap();
        tools.keys().cloned().collect()
    }

    /// Check if a tool is registered
    pub fn has_tool(&self, name: &str) -> bool {
        let tools = self.tools.lock().unwrap();
        tools.contains_key(name)
    }

    /// Discover available tools in PATH
    pub fn discover_tools(&mut self) -> Result<Vec<String>> {
        let mut discovered = Vec::new();

        // Common security tools to look for
        let common_tools = vec![
            "nmap",
            "gobuster",
            "nikto",
            "sqlmap",
            "ffuf",
            "nuclei",
            "feroxbuster",
            "dirsearch",
        ];

        for tool_name in common_tools {
            if self.is_in_path(tool_name) {
                discovered.push(tool_name.to_string());
            }
        }

        Ok(discovered)
    }

    /// Check if a command is available in PATH
    fn is_in_path(&self, command: &str) -> bool {
        std::process::Command::new("which")
            .arg(command)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Remove a tool from the registry
    pub fn unregister(&mut self, name: &str) -> Result<()> {
        let mut tools = self.tools.lock().unwrap();

        if tools.remove(name).is_none() {
            anyhow::bail!("Tool '{}' not found in registry", name);
        }

        Ok(())
    }

    /// Clear all registered tools
    pub fn clear(&mut self) {
        let mut tools = self.tools.lock().unwrap();
        tools.clear();
    }

    /// Get count of registered tools
    pub fn count(&self) -> usize {
        let tools = self.tools.lock().unwrap();
        tools.len()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}
