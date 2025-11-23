// Integration tests for the PT Journal application
use pt_journal::dispatcher::*;
use pt_journal::model::*;
use pt_journal::store;
use pt_journal::ui::state::*;
use std::cell::RefCell;
use std::rc::Rc;
use tempfile::TempDir;

// GTK imports for UI integration tests
use gtk4::prelude::*;

mod test_runner;

// Model Tests
fn test_default_app_model() {
    let model = AppModel::default();
    assert_eq!(model.selected_phase, 0);
    assert_eq!(model.selected_step, Some(0));
    assert_eq!(model.current_path, None);
    assert_eq!(model.session.phases.len(), 9); // Updated: 5 pentesting + Bug Bounty + CompTIA + CEH
}

fn test_session_creation() {
    let session = Session::default();
    assert!(!session.name.is_empty());
    assert_eq!(session.phases.len(), 9); // Updated: 5 pentesting + Bug Bounty + CompTIA + CEH
    assert!(session.notes_global.is_empty());
}

fn test_phase_structure() {
    let session = Session::default();
    assert_eq!(session.phases[0].name, "Reconnaissance");
    assert_eq!(session.phases[0].steps.len(), 16);
    assert_eq!(session.phases[1].name, "Vulnerability Analysis");
    assert_eq!(session.phases[1].steps.len(), 5);
    assert_eq!(session.phases[2].name, "Exploitation");
    assert_eq!(session.phases[2].steps.len(), 4);
    assert_eq!(session.phases[3].name, "Post-Exploitation");
    assert_eq!(session.phases[3].steps.len(), 4);
    assert_eq!(session.phases[4].name, "Reporting");
    assert_eq!(session.phases[4].steps.len(), 4);
}

// Store Tests
fn test_save_and_load_session() {
    let temp_dir = TempDir::new().unwrap();
    let session_path = temp_dir.path().join("test_session");

    let mut session = Session::default();
    session.name = "Test Session".to_string();
    session.notes_global = "Test notes".to_string();

    if let Some(step) = session.phases[0].steps.get_mut(0) {
        step.status = StepStatus::Done;
        step.notes = "Test step notes".to_string();
    }

    store::save_session(&session_path, &session).unwrap();
    let session_file = session_path.join("session.json");
    let loaded_session = store::load_session(&session_file).unwrap();

    assert_eq!(loaded_session.name, session.name);
    assert_eq!(loaded_session.notes_global, session.notes_global);
    assert_eq!(loaded_session.phases.len(), session.phases.len());
}

fn test_session_data_integrity() {
    let temp_dir = TempDir::new().unwrap();
    let session_path = temp_dir.path().join("integrity_test");

    let mut session = Session::default();
    session.notes_global = "Global test notes".to_string();

    // Only modify tutorial steps in first 5 phases (pentesting phases)
    // Skip bug bounty (phase 5) and CompTIA (phase 6) as they may have quiz steps
    for (_phase_idx, phase) in session.phases.iter_mut().enumerate().take(5) {
        for step in &mut phase.steps {
            // Only set notes on tutorial steps, not quiz steps
            if !step.is_quiz() {
                step.set_notes(format!("Notes for {}", step.title)); // Use set_notes() method
                if step.title.contains("enumeration") || step.title.contains("Subdomain") {
                    step.status = StepStatus::Done;
                }
            }
        }
    }

    store::save_session(&session_path, &session).unwrap();
    let session_file = session_path.join("session.json");
    let loaded_session = store::load_session(&session_file).unwrap();

    assert_eq!(loaded_session.notes_global, session.notes_global);
    assert_eq!(loaded_session.phases.len(), session.phases.len());

    // Check only the first 5 tutorial phases for data integrity
    for (phase_idx, (original_phase, loaded_phase)) in session
        .phases
        .iter()
        .zip(&loaded_session.phases)
        .enumerate()
        .take(5)
    {
        assert_eq!(
            loaded_phase.name, original_phase.name,
            "Phase {} name mismatch",
            phase_idx
        );
        assert_eq!(
            loaded_phase.steps.len(),
            original_phase.steps.len(),
            "Phase {} step count mismatch",
            phase_idx
        );

        for (step_idx, (original_step, loaded_step)) in original_phase
            .steps
            .iter()
            .zip(&loaded_phase.steps)
            .enumerate()
        {
            assert_eq!(
                loaded_step.title, original_step.title,
                "Phase {} Step {} title mismatch",
                phase_idx, step_idx
            );
            assert_eq!(
                loaded_step.status, original_step.status,
                "Phase {} Step {} status mismatch",
                phase_idx, step_idx
            );

            // Only check notes/description on tutorial steps using getter methods
            if !original_step.is_quiz() {
                assert_eq!(
                    loaded_step.get_notes(),
                    original_step.get_notes(),
                    "Phase {} Step {} '{}' notes mismatch",
                    phase_idx,
                    step_idx,
                    original_step.title
                );
                assert_eq!(
                    loaded_step.get_description(),
                    original_step.get_description(),
                    "Phase {} Step {} description mismatch",
                    phase_idx,
                    step_idx
                );
            }
        }
    }
}

// Dispatcher Tests
fn test_dispatcher_message_routing() {
    let dispatcher = create_dispatcher();
    let messages = Rc::new(RefCell::new(Vec::new()));
    let msg_clone = messages.clone();

    {
        let mut disp = dispatcher.borrow_mut();
        disp.register(
            "test",
            Box::new(move |msg| {
                msg_clone.borrow_mut().push(format!("{:?}", msg));
            }),
        );
    }

    dispatcher.borrow().dispatch(&AppMessage::PhaseSelected(1));
    dispatcher.borrow().dispatch(&AppMessage::StepSelected(2));

    assert_eq!(messages.borrow().len(), 2);
}

// State Manager Tests
fn test_state_manager_phase_selection() {
    let model = Rc::new(RefCell::new(AppModel::default()));
    let dispatcher = create_dispatcher();
    let state = StateManager::new(model.clone(), dispatcher);

    state.select_phase(2);
    assert_eq!(model.borrow().selected_phase, 2);
    assert!(model.borrow().selected_step.is_none());
}

fn test_state_manager_step_updates() {
    let model = Rc::new(RefCell::new(AppModel::default()));
    let dispatcher = create_dispatcher();
    let state = StateManager::new(model.clone(), dispatcher);

    state.update_step_notes(0, 0, "Updated notes".to_string());
    // Use getter method instead of accessing legacy field
    assert_eq!(
        model.borrow().session.phases[0].steps[0].get_notes(),
        "Updated notes"
    );

    state.update_step_status(0, 0, StepStatus::Done);
    assert!(matches!(
        model.borrow().session.phases[0].steps[0].status,
        StepStatus::Done
    ));
}

// Integration workflow tests
fn test_full_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let session_path = temp_dir.path().join("workflow");

    let mut session = Session::default();
    session.name = "Workflow Test".to_string();

    for step in &mut session.phases[0].steps[0..3] {
        step.status = StepStatus::Done;
        step.set_notes(format!("Completed: {}", step.title)); // Use set_notes() method
    }

    store::save_session(&session_path, &session).unwrap();
    let session_file = session_path.join("session.json");
    let loaded = store::load_session(&session_file).unwrap();

    assert_eq!(loaded.name, "Workflow Test");
    for i in 0..3 {
        assert!(matches!(loaded.phases[0].steps[i].status, StepStatus::Done));
        // Verify notes were saved and loaded correctly
        assert_eq!(
            loaded.phases[0].steps[i].get_notes(),
            format!("Completed: {}", loaded.phases[0].steps[i].title)
        );
    }
}

// UI Integration Tests (require GTK)
fn test_tool_execution_panel_creation() {
    gtk4::init().expect("Failed to initialize GTK");

    let panel = pt_journal::ui::tool_execution::ToolExecutionPanel::new();
    assert_eq!(panel.get_selected_tool(), Some("nmap".to_string()));
    assert!(panel.instructions_scroll.child().is_some());
}

fn test_tool_selection() {
    gtk4::init().expect("Failed to initialize GTK");

    let panel = pt_journal::ui::tool_execution::ToolExecutionPanel::new();

    // Default should be nmap
    assert_eq!(panel.get_selected_tool(), Some("nmap".to_string()));

    // Switch to gobuster - iterate until the desired tool is selected
    let model = panel.tool_selector.model().unwrap();
    let count = model.iter_n_children(None);
    let mut found = false;
    for idx in 0..count {
        panel.tool_selector.set_active(Some(idx as u32));
        if panel.get_selected_tool() == Some("gobuster".to_string()) {
            found = true;
            break;
        }
    }
    assert!(found, "gobuster tool should exist");
    assert_eq!(panel.get_selected_tool(), Some("gobuster".to_string()));
}

fn main() {
    let tests: Vec<(&str, fn())> = vec![
        ("test_default_app_model", test_default_app_model),
        ("test_session_creation", test_session_creation),
        ("test_phase_structure", test_phase_structure),
        ("test_save_and_load_session", test_save_and_load_session),
        ("test_session_data_integrity", test_session_data_integrity),
        (
            "test_dispatcher_message_routing",
            test_dispatcher_message_routing,
        ),
        (
            "test_state_manager_phase_selection",
            test_state_manager_phase_selection,
        ),
        (
            "test_state_manager_step_updates",
            test_state_manager_step_updates,
        ),
        ("test_full_workflow", test_full_workflow),
        (
            "test_tool_execution_panel_creation",
            test_tool_execution_panel_creation,
        ),
        ("test_tool_selection", test_tool_selection),
    ];

    let mut runner = test_runner::TestRunner::new(tests.len());

    for (name, test_fn) in tests {
        runner.run_test(name, test_fn);
    }

    runner.finish();

    if runner.has_failures() {
        std::process::exit(1);
    }
}
