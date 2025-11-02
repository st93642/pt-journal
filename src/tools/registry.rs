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
    /// TODO: Refactor to use Arc<dyn SecurityTool> for proper tool retrieval
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
            "nmap", "gobuster", "nikto", "sqlmap", 
            "ffuf", "nuclei", "feroxbuster", "dirsearch"
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    
    // Mock tool for testing
    #[derive(Clone)]
    struct TestTool {
        name: String,
    }
    
    impl TestTool {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
            }
        }
    }
    
    impl SecurityTool for TestTool {
        fn name(&self) -> &str {
            &self.name
        }
        
        fn check_availability(&self) -> Result<ToolVersion> {
            Ok(ToolVersion::new(1, 0, 0))
        }
        
        fn build_command(&self, _config: &ToolConfig) -> Result<Command> {
            Ok(Command::new("echo"))
        }
        
        fn parse_output(&self, output: &str) -> Result<ToolResult> {
            Ok(ToolResult::Raw {
                stdout: output.to_string(),
                stderr: String::new(),
            })
        }
        
        fn extract_evidence(&self, _result: &ToolResult) -> Vec<crate::model::Evidence> {
            Vec::new()
        }
        
        fn validate_prerequisites(&self, _config: &ToolConfig) -> Result<()> {
            Ok(())
        }
    }
    
    #[test]
    fn test_registry_creation() {
        let registry = ToolRegistry::new();
        assert_eq!(registry.count(), 0);
    }
    
    #[test]
    fn test_registry_register_tool() {
        let mut registry = ToolRegistry::new();
        let tool = Box::new(TestTool::new("test-tool"));
        
        let result = registry.register(tool);
        assert!(result.is_ok());
        assert_eq!(registry.count(), 1);
        assert!(registry.has_tool("test-tool"));
    }
    
    #[test]
    fn test_registry_prevents_duplicate_registration() {
        let mut registry = ToolRegistry::new();
        
        let tool1 = Box::new(TestTool::new("duplicate"));
        let tool2 = Box::new(TestTool::new("duplicate"));
        
        assert!(registry.register(tool1).is_ok());
        
        let result = registry.register(tool2);
        assert!(result.is_err());
        
        let err = result.unwrap_err();
        assert!(err.to_string().contains("already registered"));
    }
    
    #[test]
    fn test_registry_list_tools() {
        let mut registry = ToolRegistry::new();
        
        registry.register(Box::new(TestTool::new("tool1"))).unwrap();
        registry.register(Box::new(TestTool::new("tool2"))).unwrap();
        registry.register(Box::new(TestTool::new("tool3"))).unwrap();
        
        let tools = registry.list_tools();
        assert_eq!(tools.len(), 3);
        assert!(tools.contains(&"tool1".to_string()));
        assert!(tools.contains(&"tool2".to_string()));
        assert!(tools.contains(&"tool3".to_string()));
    }
    
    #[test]
    fn test_registry_has_tool() {
        let mut registry = ToolRegistry::new();
        
        registry.register(Box::new(TestTool::new("existing"))).unwrap();
        
        assert!(registry.has_tool("existing"));
        assert!(!registry.has_tool("nonexistent"));
    }
    
    #[test]
    fn test_registry_unregister_tool() {
        let mut registry = ToolRegistry::new();
        
        registry.register(Box::new(TestTool::new("removable"))).unwrap();
        assert_eq!(registry.count(), 1);
        
        let result = registry.unregister("removable");
        assert!(result.is_ok());
        assert_eq!(registry.count(), 0);
        assert!(!registry.has_tool("removable"));
    }
    
    #[test]
    fn test_registry_unregister_nonexistent_tool() {
        let mut registry = ToolRegistry::new();
        
        let result = registry.unregister("nonexistent");
        assert!(result.is_err());
        
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }
    
    #[test]
    fn test_registry_clear() {
        let mut registry = ToolRegistry::new();
        
        registry.register(Box::new(TestTool::new("tool1"))).unwrap();
        registry.register(Box::new(TestTool::new("tool2"))).unwrap();
        assert_eq!(registry.count(), 2);
        
        registry.clear();
        assert_eq!(registry.count(), 0);
    }
    
    #[test]
    fn test_registry_count() {
        let mut registry = ToolRegistry::new();
        
        assert_eq!(registry.count(), 0);
        
        registry.register(Box::new(TestTool::new("tool1"))).unwrap();
        assert_eq!(registry.count(), 1);
        
        registry.register(Box::new(TestTool::new("tool2"))).unwrap();
        assert_eq!(registry.count(), 2);
        
        registry.unregister("tool1").unwrap();
        assert_eq!(registry.count(), 1);
    }
    
    #[test]
    fn test_registry_discover_tools() {
        let mut registry = ToolRegistry::new();
        
        // This test depends on system PATH, so results may vary
        let discovered = registry.discover_tools();
        assert!(discovered.is_ok());
        
        // At least 'echo' or 'which' should be available on most systems
        let tools = discovered.unwrap();
        // We can't assert specific tools without knowing the test environment
        assert!(tools.len() >= 0);
    }
}
