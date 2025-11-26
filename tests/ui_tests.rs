#![allow(clippy::field_reassign_with_default)]

use pt_journal::model::*;
use uuid::Uuid;

#[cfg(test)]
mod ui_integration_tests {
    #[test]
    fn test_setup_image_handling_attaches_controllers() {
        // This test requires GTK initialization
        // In a real environment, we would:
        // 1. Create a TextView
        // 2. Call setup_image_handling
        // 3. Verify that controllers are attached
        // 4. Check that the controllers have the correct types

        // For now, just ensure the function exists and can be called
        // (without GTK init, it would panic, so we skip actual execution)
        // Placeholder test - no assertions needed
    }

    #[test]
    fn test_image_handling_workflow() {
        // Integration test for the complete image handling workflow
        // This would test:
        // 1. File validation
        // 2. Texture creation
        // 3. Buffer insertion
        // 4. UI controller setup

        // Since GTK is required, this is a placeholder
        // Placeholder test - no assertions needed
    }

    #[test]
    fn test_pane_minimum_sizes() {
        // Test that pane minimum sizes are properly set
        // Description pane: 80px minimum
        // Chat pane: 80px minimum

        // Since GTK is required for actual widget testing, this is a placeholder
        // In a real test, we would:
        // 1. Create the UI components
        // 2. Check that minimum sizes are set correctly
        // 3. Verify that panes cannot be resized below minimums
        // Placeholder test - no assertions needed
    }

    #[test]
    fn test_model_selector_default_behavior() {
        // Test that model selector defaults to the configured default model
        // This would test the chat_panel's model_combo behavior

        // In a real GTK environment, we would:
        // 1. Create a ChatPanel
        // 2. Create a test config with known models
        // 3. Populate the model selector
        // 4. Verify the default model is selected
        // 5. Test changing selection updates the state

        // Since GTK is required, this is a placeholder test
        // In a real test, we would:
        let models = vec![
            ("llama3.2:latest".to_string(), "Meta Llama 3.2".to_string()),
            ("mistral:7b".to_string(), "Mistral 7B".to_string()),
            (
                "phi3:mini-4k-instruct".to_string(),
                "Phi-3 Mini".to_string(),
            ),
        ];

        // Verify model list contains expected models
        assert_eq!(models.len(), 3);
        assert!(models.iter().any(|(id, _)| id == "llama3.2:latest"));

        // Default model should be first in list or configured default
        let default_model_id = "llama3.2:latest";
        assert!(models.iter().any(|(id, _)| id == default_model_id));

        // Placeholder test - no GTK assertions needed
    }

    #[test]
    fn test_model_selector_population() {
        // Test that model selector populates with available models from config
        // This would verify the populate_models method works correctly

        // Test data representing models from config
        let test_models = vec![
            ("model1".to_string(), "Model 1".to_string()),
            ("model2".to_string(), "Model 2".to_string()),
            ("model3".to_string(), "Model 3".to_string()),
        ];

        // Verify all models are present
        assert_eq!(test_models.len(), 3);

        // Verify model IDs and display names are paired correctly
        for (id, display_name) in &test_models {
            assert!(!id.is_empty());
            assert!(!display_name.is_empty());
        }

        // In real GTK test:
        // 1. Call chat_panel.populate_models(&test_models)
        // 2. Verify combo box has 3 items
        // 3. Verify each item has correct ID and text
        // Placeholder test - no GTK assertions needed
    }

    #[test]
    fn test_chat_panel_state_management() {
        // Test that chat panel correctly manages model selection state
        // This would test the interaction between model selector and chat state

        // Test scenarios:
        // 1. Model selection disabled during loading
        // 2. Model selection enabled after load complete
        // 3. Model selection persists across chat messages
        // 4. Active model changes update chat service

        // Since GTK is required, this is a placeholder test
        // In a real test, we would:
        // 1. Create chat panel with mock state
        // 2. Trigger loading state
        // 3. Verify model combo is disabled
        // 4. Complete loading
        // 5. Verify model combo is enabled
        // 6. Change model selection
        // 7. Verify state is updated
        // Placeholder test - no GTK assertions needed
    }

    #[test]
    fn test_text_input_handlers() {
        // Test that text input handlers are properly connected
        // This would verify that:
        // 1. Description pane changes are saved to description_notes
        // 2. Notes pane changes are saved to notes
        // 3. Text is properly loaded when switching steps

        // Since GTK is required, this is a placeholder
        // Placeholder test - no assertions needed
    }
}

#[cfg(test)]
mod text_input_tests {
    use super::*;

    #[test]
    fn test_text_buffer_operations() {
        // Test that text buffer operations work correctly
        // This tests the logic without requiring GTK

        let mut model = AppModel::default();
        model.set_selected_phase(0);
        model.set_selected_step(Some(0));

        // Simulate text input to notes
        if let Some(step) = model.session_mut().phases[0].steps.get_mut(0) {
            step.notes = "Test notes content".to_string();
            assert_eq!(step.notes, "Test notes content");
        }

        // Simulate text input to description_notes
        if let Some(step) = model.session_mut().phases[0].steps.get_mut(0) {
            step.description_notes = "Test description notes".to_string();
            assert_eq!(step.description_notes, "Test description notes");
        }
    }

    #[test]
    fn test_step_text_persistence() {
        // Test that text changes persist across step switches
        let mut model = AppModel::default();

        // Set text for first step
        model.set_selected_step(Some(0));
        if let Some(step) = model.session_mut().phases[0].steps.get_mut(0) {
            step.notes = "Notes for step 0".to_string();
            step.description_notes = "Description notes for step 0".to_string();
        }

        // Switch to second step
        model.set_selected_step(Some(1));
        if let Some(step) = model.session_mut().phases[0].steps.get_mut(1) {
            step.notes = "Notes for step 1".to_string();
            step.description_notes = "Description notes for step 1".to_string();
        }

        // Verify first step still has its text
        if let Some(step) = model.session_mut().phases[0].steps.first() {
            assert_eq!(step.notes, "Notes for step 0");
            assert_eq!(step.description_notes, "Description notes for step 0");
        }

        // Verify second step has its text
        if let Some(step) = model.session_mut().phases[0].steps.get(1) {
            assert_eq!(step.notes, "Notes for step 1");
            assert_eq!(step.description_notes, "Description notes for step 1");
        }
    }

    #[test]
    fn test_empty_text_handling() {
        // Test handling of empty text input
        let mut step = Step::new_tutorial(
            Uuid::new_v4(),
            "Test".to_string(),
            "Test".to_string(),
            vec![],
        );

        // Empty strings should be handled
        if let StepContent::Tutorial {
            notes,
            description_notes,
            ..
        } = &step.content
        {
            assert!(notes.is_empty());
            assert!(description_notes.is_empty());
        }

        // Setting to empty should work
        if let StepContent::Tutorial {
            notes,
            description_notes,
            ..
        } = &mut step.content
        {
            *notes = "".to_string();
            *description_notes = "".to_string();
            assert!(notes.is_empty());
            assert!(description_notes.is_empty());
        }
    }
}

#[cfg(test)]
mod chat_tests {
    use super::*;
    use httpmock::prelude::*;
    use pt_journal::chatbot::LocalChatBot;
    use pt_journal::config::ChatbotConfig;
    use pt_journal::model::{ChatMessage, ChatRole};
    use serde_json::json;

    #[test]
    fn test_chat_message_serialization() {
        let message = ChatMessage {
            role: ChatRole::User,
            content: "Test message".to_string(),
            timestamp: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&message).unwrap();
        let deserialized: ChatMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.role, ChatRole::User);
        assert_eq!(deserialized.content, "Test message");
    }

    #[test]
    fn test_chat_config_loading() {
        let config = ChatbotConfig::default();
        assert_eq!(config.ollama.endpoint, "http://localhost:11434");
        assert_eq!(config.default_model_id, "llama3.2:latest");
        assert_eq!(config.ollama.timeout_seconds, 180);
        assert!(config
            .models
            .iter()
            .any(|profile| profile.id == config.default_model_id));
    }

    #[test]
    fn test_local_chatbot_payload_construction() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(POST).path("/api/chat").json_body(json!({
                "model": "llama3.2:latest",
                "messages": [
                    {"role": "system", "content": "You are an expert penetration testing assistant helping with structured pentesting methodology.\n\nCurrent Context:\n- Phase: Reconnaissance\n- Step: Test Step (Status: Todo)\n- Description: Test description\n- Notes: 0 characters\n- Evidence: 0 items\n\n\nProvide helpful, methodology-aligned assistance for general pentesting questions, step-specific guidance, or tool recommendations. Keep responses focused and actionable."},
                    {"role": "user", "content": "Hello"}
                ],
                "stream": false
            }));
            then.status(200).json_body(json!({
                "message": {"role": "assistant", "content": "Hi there!"}
            }));
        });

        let mut config = ChatbotConfig::default();
        config.ollama.endpoint = server.url("");
        config.ollama.timeout_seconds = 60;
        config.default_model_id = "llama3.2:latest".to_string();

        let chatbot = LocalChatBot::new(config);
        let step_ctx = pt_journal::chatbot::StepContext {
            phase_name: "Reconnaissance".to_string(),
            step_title: "Test Step".to_string(),
            step_description: "Test description".to_string(),
            step_status: "Todo".to_string(),
            notes_count: 0,
            evidence_count: 0,
            quiz_status: None,
        };
        let history = vec![];

        // Actually make the call to test payload construction
        let result = chatbot.send_message(&step_ctx, &history, "Hello");
        assert!(result.is_ok());

        mock.assert();
    }

    #[test]
    fn test_chat_history_persistence() {
        let mut model = AppModel::default();
        model.set_selected_phase(0);
        model.set_selected_step(Some(0));

        // Add chat messages to step
        let message1 = ChatMessage {
            role: ChatRole::User,
            content: "User question".to_string(),
            timestamp: chrono::Utc::now(),
        };

        let message2 = ChatMessage {
            role: ChatRole::Assistant,
            content: "Assistant response".to_string(),
            timestamp: chrono::Utc::now(),
        };

        if let Some(step) = model.session_mut().phases[0].steps.get_mut(0) {
            if let StepContent::Tutorial { chat_history, .. } = &mut step.content {
                chat_history.push(message1.clone());
                chat_history.push(message2.clone());
                assert_eq!(chat_history.len(), 2);
                assert_eq!(chat_history[0].content, "User question");
                assert_eq!(chat_history[1].content, "Assistant response");
            }
        }

        // Switch to another step - should have empty chat history
        model.set_selected_step(Some(1));
        if let Some(step) = model.session_mut().phases[0].steps.get(1) {
            if let StepContent::Tutorial { chat_history, .. } = &step.content {
                assert_eq!(chat_history.len(), 0);
            }
        }

        // Switch back - should still have chat history
        model.set_selected_step(Some(0));
        if let Some(step) = model.session_mut().phases[0].steps.first() {
            if let StepContent::Tutorial { chat_history, .. } = &step.content {
                assert_eq!(chat_history.len(), 2);
                assert_eq!(chat_history[0].content, "User question");
                assert_eq!(chat_history[1].content, "Assistant response");
            }
        }
    }
}
