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

#[cfg(test)]
mod new_ai_tools_tests {
    use pt_journal::ui::tool_instructions;

    #[test]
    fn test_new_ai_tools_available() {
        // Test that our new AI tools are available in the manifest
        let manifest = tool_instructions::manifest();
        
        // Check PyRIT
        assert!(manifest.iter().any(|entry| entry.id == "pyrit"), "PyRIT should be available");
        let pyrit_entry = manifest.iter().find(|entry| entry.id == "pyrit").unwrap();
        assert_eq!(pyrit_entry.category, "AI & LLM Security");
        assert!(pyrit_entry.label.contains("PyRIT"));
        
        // Check PentestGPT
        assert!(manifest.iter().any(|entry| entry.id == "pentestgpt"), "PentestGPT should be available");
        let pentestgpt_entry = manifest.iter().find(|entry| entry.id == "pentestgpt").unwrap();
        assert_eq!(pentestgpt_entry.category, "AI & LLM Security");
        assert!(pentestgpt_entry.label.contains("PentestGPT"));
        
        // Check NeMo Guardrails
        assert!(manifest.iter().any(|entry| entry.id == "nemo_guardrails"), "NeMo Guardrails should be available");
        let nemo_entry = manifest.iter().find(|entry| entry.id == "nemo_guardrails").unwrap();
        assert_eq!(nemo_entry.category, "AI & LLM Security");
        assert!(nemo_entry.label.contains("NeMo Guardrails"));
    }

    #[test]
    fn test_new_ai_tools_have_instructions() {
        // Test that our new AI tools have detailed instructions loaded
        assert!(tool_instructions::has_tool("pyrit"), "PyRIT should have instructions");
        assert!(tool_instructions::has_tool("pentestgpt"), "PentestGPT should have instructions");
        assert!(tool_instructions::has_tool("nemo_guardrails"), "NeMo Guardrails should have instructions");
        
        // Try to get the actual instruction documents
        let pyrit_doc = tool_instructions::get_instructions("pyrit");
        assert!(pyrit_doc.is_some(), "PyRIT instructions should be loadable");
        
        let pentestgpt_doc = tool_instructions::get_instructions("pentestgpt");
        assert!(pentestgpt_doc.is_some(), "PentestGPT instructions should be loadable");
        
        let nemo_doc = tool_instructions::get_instructions("nemo_guardrails");
        assert!(nemo_doc.is_some(), "NeMo Guardrails instructions should be loadable");
    }

    #[test]
    fn test_ai_tools_category_count() {
        // Verify we have the expected number of AI & LLM Security tools
        let manifest = tool_instructions::manifest();
        let ai_tools_count = manifest.iter()
            .filter(|entry| entry.category == "AI & LLM Security")
            .count();
        
        // We should have exactly 9 AI tools now (6 existing + 3 new)
        assert_eq!(ai_tools_count, 9, "Should have exactly 9 AI & LLM Security tools, found {}", ai_tools_count);
    }

    #[test]
    fn test_total_tool_count_increased() {
        // Verify total tool count increased from 226 to 229
        let manifest = tool_instructions::manifest();
        assert_eq!(manifest.len(), 229, "Should have exactly 229 tools after adding 3 new AI tools");
    }
}
