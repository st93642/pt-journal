#[cfg(test)]
mod registry_tests {
    use pt_journal::tools::registry::ToolRegistry;
    use pt_journal::tools::integrations::TemplateTool;

    #[test]
    fn test_registry_creation() {
        let registry = ToolRegistry::new();
        assert_eq!(registry.count(), 0);
        assert!(registry.list_tools().is_empty());
    }

    #[test]
    fn test_register_template_tool() {
        let mut registry = ToolRegistry::new();
        let tool = Box::new(TemplateTool::new());

        // Template tool should register successfully
        assert!(registry.register(tool).is_ok());
        assert_eq!(registry.count(), 1);
        assert!(registry.has_tool("template"));
        assert_eq!(registry.list_tools(), vec!["template"]);
    }

    #[test]
    fn test_register_duplicate_tool() {
        let mut registry = ToolRegistry::new();
        let tool1 = Box::new(TemplateTool::new());
        let tool2 = Box::new(TemplateTool::new());

        assert!(registry.register(tool1).is_ok());
        assert!(registry.register(tool2).is_err()); // Should fail for duplicate
    }

    #[test]
    fn test_get_missing_tool() {
        let registry = ToolRegistry::new();

        // Should return error for missing tool
        match registry.get_tool("nonexistent") {
            Ok(_) => panic!("Expected error for missing tool"),
            Err(e) => {
                let err_msg = format!("{}", e);
                assert!(err_msg.contains("not found in registry"));
            }
        }
    }

    #[test]
    fn test_get_registered_tool() {
        let mut registry = ToolRegistry::new();
        let tool = Box::new(TemplateTool::new());
        registry.register(tool).unwrap();

        // Should return error because retrieval is not implemented yet
        match registry.get_tool("template") {
            Ok(_) => panic!("Expected error for stub implementation"),
            Err(e) => {
                let err_msg = format!("{}", e);
                assert!(err_msg.contains("retrieval not implemented yet"));
            }
        }
    }

    #[test]
    fn test_unregister_tool() {
        let mut registry = ToolRegistry::new();
        let tool = Box::new(TemplateTool::new());
        registry.register(tool).unwrap();

        assert!(registry.unregister("template").is_ok());
        assert_eq!(registry.count(), 0);
        assert!(!registry.has_tool("template"));
    }

    #[test]
    fn test_unregister_missing_tool() {
        let mut registry = ToolRegistry::new();

        match registry.unregister("nonexistent") {
            Ok(_) => panic!("Expected error for unregistering missing tool"),
            Err(e) => {
                let err_msg = format!("{}", e);
                assert!(err_msg.contains("not found in registry"));
            }
        }
    }

    #[test]
    fn test_clear_registry() {
        let mut registry = ToolRegistry::new();
        let tool = Box::new(TemplateTool::new());
        registry.register(tool).unwrap();

        registry.clear();
        assert_eq!(registry.count(), 0);
        assert!(registry.list_tools().is_empty());
    }

    #[test]
    fn test_discover_tools() {
        let mut registry = ToolRegistry::new();

        // This will discover tools available in PATH
        let result = registry.discover_tools();
        assert!(result.is_ok());

        let discovered = result.unwrap();
        // Should find some common tools if they're installed
        // We don't assert specific tools since they may not be installed
        assert!(discovered.iter().all(|tool| !tool.is_empty()));
    }
}