#[cfg(test)]
mod renderer_tests {
    use pt_journal::ui::tool_execution::{resolve_instruction_state, InstructionState};
    use pt_journal::ui::tool_instructions;

    #[test]
    fn missing_tool_resolves_to_missing_state() {
        let state = resolve_instruction_state(Some("nonexistent_tool_12345"));
        assert!(
            matches!(state, InstructionState::Missing { .. }),
            "missing tool should use fallback state"
        );
    }

    #[test]
    fn none_tool_falls_back_to_manifest_first_entry() {
        let state = resolve_instruction_state(None);
        match state {
            InstructionState::Available(doc) => {
                assert!(tool_instructions::has_tool(&doc.id));
            }
            InstructionState::Missing { tool_id } => {
                // Manifest may be empty when instruction data fails to load
                if let Some(id) = tool_id {
                    assert!(!id.is_empty());
                }
            }
        }
    }

    #[test]
    fn dialog_title_for_missing_tool_has_fallback_text() {
        let state = InstructionState::Missing {
            tool_id: Some("custom-tool".to_string()),
        };
        assert_eq!(state.dialog_title(), "custom-tool - Full Instructions");

        let unnamed = InstructionState::Missing { tool_id: None };
        assert_eq!(unnamed.dialog_title(), "Tool Instructions");
    }
}

#[cfg(test)]
mod picker_tests {
    use pt_journal::ui::tool_execution::ToolPickerModel;
    use pt_journal::ui::tool_instructions;

    #[test]
    fn test_model_construction_preserves_category_order() {
        let model = ToolPickerModel::from_manifest();

        let manifest = tool_instructions::manifest();
        let mut expected_categories = Vec::new();
        for entry in manifest {
            if !expected_categories.contains(&entry.category) {
                expected_categories.push(entry.category.clone());
            }
        }

        let actual_categories: Vec<String> =
            model.groups().iter().map(|g| g.name.clone()).collect();
        assert_eq!(
            actual_categories, expected_categories,
            "Categories should preserve manifest ordering"
        );
    }

    #[test]
    fn test_tools_for_category_handles_nonexistent_category() {
        let model = ToolPickerModel::from_manifest();
        let tools = model.tools_for_category("NonexistentCategory123");
        assert!(
            tools.is_empty(),
            "Unknown categories should return no tools"
        );
    }

    #[test]
    fn test_default_selection_prefers_nmap_when_available() {
        let model = ToolPickerModel::from_manifest();
        let manifest = tool_instructions::manifest();
        let has_nmap = manifest.iter().any(|entry| entry.id == "nmap");

        if has_nmap {
            assert_eq!(model.default_tool_id(), "nmap");
            if let Some(default_category) = model.default_category() {
                let nmap_entry = manifest.iter().find(|entry| entry.id == "nmap").unwrap();
                assert_eq!(default_category, nmap_entry.category);
            }
        }
    }

    #[test]
    fn test_default_category_index_matches_category_name() {
        let model = ToolPickerModel::from_manifest();
        if model.is_empty() {
            return;
        }
        let default_category = model.default_category().expect("default category");
        assert_eq!(
            default_category,
            model.groups()[model.default_category_index()].name
        );
    }
}

#[cfg(test)]
mod controller_tests {
    use pt_journal::test_support::ui::{MockInstructionProvider, MockTerminal, MockView};
    use pt_journal::ui::tool_execution::ToolPanelController;

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
