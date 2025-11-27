#[cfg(test)]
mod registry_tests {
    use pt_journal::tools::registry::ToolRegistry;

    #[test]
    fn test_registry_creation() {
        let registry = ToolRegistry::new();
        assert_eq!(registry.count(), 0);
        assert!(registry.list_tools().is_empty());
    }

    #[test]
    fn test_register_instructions() {
        let mut registry = ToolRegistry::new();
        registry.register_instructions("nmap");

        assert_eq!(registry.count(), 1);
        assert!(registry.has_instructions("nmap"));
        assert_eq!(registry.list_tools(), vec!["nmap"]);
    }

    #[test]
    fn test_register_duplicate_instructions() {
        let mut registry = ToolRegistry::new();
        registry.register_instructions("nmap");
        registry.register_instructions("nmap"); // Should be idempotent

        assert_eq!(registry.count(), 1);
        assert!(registry.has_instructions("nmap"));
    }

    #[test]
    fn test_has_instructions_missing_tool() {
        let registry = ToolRegistry::new();
        assert!(!registry.has_instructions("nonexistent"));
    }

    #[test]
    fn test_clear_registry() {
        let mut registry = ToolRegistry::new();
        registry.register_instructions("nmap");
        registry.register_instructions("gobuster");

        registry.clear();
        assert_eq!(registry.count(), 0);
        assert!(registry.list_tools().is_empty());
    }

    #[test]
    fn test_multiple_tools() {
        let mut registry = ToolRegistry::new();
        registry.register_instructions("nmap");
        registry.register_instructions("gobuster");
        registry.register_instructions("nikto");

        assert_eq!(registry.count(), 3);
        assert!(registry.has_instructions("nmap"));
        assert!(registry.has_instructions("gobuster"));
        assert!(registry.has_instructions("nikto"));

        let tools = registry.list_tools();
        assert_eq!(tools.len(), 3);
        assert!(tools.contains(&"nmap".to_string()));
        assert!(tools.contains(&"gobuster".to_string()));
        assert!(tools.contains(&"nikto".to_string()));
    }
}