#[cfg(test)]
mod related_tools_tests {
    use pt_journal::model::Step;

    #[test]
    fn test_step_can_store_related_tools() {
        let step = Step::new_tutorial_with_tools(
            uuid::Uuid::new_v4(),
            "Test Step".to_string(),
            "Test content".to_string(),
            vec!["test-tag".to_string()],
            vec!["nmap".to_string(), "nikto".to_string()],
        );

        assert_eq!(step.related_tools.len(), 2);
        assert!(step.related_tools.contains(&"nmap".to_string()));
        assert!(step.related_tools.contains(&"nikto".to_string()));
    }

    #[test]
    fn test_step_without_related_tools() {
        let step = Step::new_tutorial(
            uuid::Uuid::new_v4(),
            "Test Step".to_string(),
            "Test content".to_string(),
            vec!["test-tag".to_string()],
        );

        assert_eq!(step.related_tools.len(), 0);
    }

    #[test]
    fn test_step_with_empty_related_tools() {
        let step = Step::new_tutorial_with_tools(
            uuid::Uuid::new_v4(),
            "Test Step".to_string(),
            "Test content".to_string(),
            vec!["test-tag".to_string()],
            vec![],
        );

        assert_eq!(step.related_tools.len(), 0);
    }
}
