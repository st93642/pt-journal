#![allow(clippy::field_reassign_with_default)]
#![allow(deprecated)]

//! Integration tests for PT Journal
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

    // Test first phase (Reconnaissance)
    let phase = &session.phases[0];
    assert_eq!(phase.name, "Reconnaissance");
    assert!(!phase.steps.is_empty());
}

// Storage Tests
fn test_save_and_load_session() {
    let temp_dir = tempdir().unwrap();
    let session_path = temp_dir.path().join("test_session");

    let mut session = Session::default();
    session.name = "Test Session".to_string();
    session.notes_global = "Test notes".to_string();

    // Modify first step to verify persistence
    if let Some(phase) = session.phases.get_mut(0) {
        if let Some(step) = phase.steps.get_mut(0) {
            step.status = StepStatus::Done;
            step.set_notes("Test notes content".to_string());
        }
    }

    store::save_session(&session_path, &session).unwrap();
    let loaded = store::load_session(&session_path).unwrap();

    assert_eq!(loaded.name, session.name);
    assert_eq!(loaded.notes_global, session.notes_global);
    assert_eq!(loaded.phases.len(), session.phases.len());
}

fn test_session_data_integrity() {
    let temp_dir = TempDir::new().unwrap();
    let session_path = temp_dir.path().join("test_session");

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
    assert!(session_file.exists());

    let json_content = std::fs::read_to_string(&session_file).unwrap();
    assert!(json_content.contains("Global test notes"));
    assert!(json_content.contains("Notes for"));

    let loaded_session = store::load_session(&session_path).unwrap();
    assert_eq!(loaded_session.notes_global, "Global test notes");

    // Verify that modified tutorial steps have notes
    for phase in loaded_session.phases.iter().take(5) {
        for step in &phase.steps {
            if !step.is_quiz() && (step.title.contains("enumeration") || step.title.contains("Subdomain")) {
                assert!(!step.get_notes().is_empty());
                assert_matches!(step.status, StepStatus::Done);
            }
        }
    }
}

// Dispatcher Tests
fn test_dispatcher_message_routing() {
    let dispatcher = Rc::new(RefCell::new(Dispatcher::new()));
    let message_received = Rc::new(RefCell::new(false));

    let flag = message_received.clone();
    dispatcher.borrow_mut().register("test_event", move |_msg| {
        *flag.borrow_mut() = true;
    });

    dispatcher.borrow().dispatch("test_event", "test message");
    assert!(*message_received.borrow());
}

fn test_dispatcher_multiple_handlers() {
    let dispatcher = Rc::new(RefCell::new(Dispatcher::new()));
    let counter = Rc::new(RefCell::new(0));

    let c1 = counter.clone();
    dispatcher.borrow_mut().register("count", move |_msg| {
        *c1.borrow_mut() += 1;
    });

    let c2 = counter.clone();
    dispatcher.borrow_mut().register("count", move |_msg| {
        *c2.borrow_mut() += 10;
    });

    dispatcher.borrow().dispatch("count", "increment");
    assert_eq!(*counter.borrow(), 11);
}

// State Manager Tests
fn test_state_manager_creation() {
    let state = StateManager::new(AppModel::default());
    let model = state.model();
    let borrowed = model.borrow();
    assert_eq!(borrowed.selected_phase, 0);
}

fn test_state_manager_step_navigation() {
    let state = StateManager::new(AppModel::default());

    state.select_phase_and_step(0, 0);
    {
        let model = state.model();
        let borrowed = model.borrow();
        assert_eq!(borrowed.selected_phase, 0);
        assert_eq!(borrowed.selected_step, Some(0));
    }

    state.select_phase_and_step(1, 2);
    {
        let model = state.model();
        let borrowed = model.borrow();
        assert_eq!(borrowed.selected_phase, 1);
        assert_eq!(borrowed.selected_step, Some(2));
    }
}

fn test_state_manager_step_notes_update() {
    let state = StateManager::new(AppModel::default());
    let test_notes = "Updated notes content";

    state.update_step_notes(0, 0, test_notes.to_string());

    let model = state.model();
    let borrowed = model.borrow();
    let phase = &borrowed.session.phases[0];
    let step = &phase.steps[0];
    assert_eq!(step.get_notes(), test_notes);
}

fn test_state_manager_step_status_update() {
    let state = StateManager::new(AppModel::default());

    state.update_step_status(0, 0, StepStatus::Done);

    let model = state.model();
    let borrowed = model.borrow();
    let phase = &borrowed.session.phases[0];
    let step = &phase.steps[0];
    assert_matches!(step.status, StepStatus::Done);
}

// UI Integration Tests (GTK)
fn test_session_workflow() {
    gtk4::init().expect("Failed to initialize GTK");

    let temp_dir = tempdir().unwrap();
    let session_path = temp_dir.path().join("workflow_session");

    let mut session = Session::default();
    session.name = "Workflow Test".to_string();

    // Simulate a complete workflow
    for phase in session.phases.iter_mut().take(3) {
        for step in phase.steps.iter_mut().take(2) {
            if step.is_tutorial() {
                step.set_notes("Completed this step".to_string());
                step.status = StepStatus::Done;
            }
        }
    }

    store::save_session(&session_path, &session).unwrap();
    let loaded = store::load_session(&session_path).unwrap();

    assert_eq!(loaded.name, "Workflow Test");
    let mut completed_count = 0;
    for phase in loaded.phases.iter().take(3) {
        for step in phase.steps.iter().take(2) {
            if step.status == StepStatus::Done {
                completed_count += 1;
            }
        }
    }
    assert!(completed_count > 0);
}

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
            "test_dispatcher_multiple_handlers",
            test_dispatcher_multiple_handlers,
        ),
        ("test_state_manager_creation", test_state_manager_creation),
        (
            "test_state_manager_step_navigation",
            test_state_manager_step_navigation,
        ),
        (
            "test_state_manager_step_notes_update",
            test_state_manager_step_notes_update,
        ),
        (
            "test_state_manager_step_status_update",
            test_state_manager_step_status_update,
        ),
        ("test_session_workflow", test_session_workflow),
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
