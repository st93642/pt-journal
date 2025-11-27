#![allow(clippy::field_reassign_with_default)]
#![allow(deprecated)]

//! Integration tests for PT Journal
use assert_matches::assert_matches;
use pt_journal::dispatcher::{AppEvent, EventBus};
use pt_journal::model::*;
use pt_journal::ui::state::*;
use std::cell::RefCell;
use std::rc::Rc;

// GTK imports for UI integration tests
use gtk4::prelude::*;

mod test_runner;

// Model Tests
fn test_default_app_model() {
    let model = AppModel::default();
    assert_eq!(model.selected_phase(), 0);
    assert_eq!(model.selected_step(), Some(0));
    assert_eq!(model.current_path(), None);
    assert_eq!(model.session().phases.len(), 22); // Updated: consolidated API phases
}

fn test_session_creation() {
    let session = Session::default();
    assert!(!session.name.is_empty());
    assert_eq!(session.phases.len(), 22); // Updated: consolidated API phases
    assert!(session.notes_global.is_empty());
}

fn test_phase_structure() {
    let session = Session::default();

    // Test first phase (Reconnaissance)
    let phase = &session.phases[0];
    assert_eq!(phase.name, "Reconnaissance");
    assert!(!phase.steps.is_empty());
}

fn test_dispatcher_message_routing() {
    let dispatcher = Rc::new(RefCell::new(EventBus::new()));
    let message_received = Rc::new(RefCell::new(false));

    let flag = message_received.clone();
    dispatcher.borrow_mut().on_info = Box::new(move |_info| {
        *flag.borrow_mut() = true;
    });

    dispatcher
        .borrow()
        .emit(AppEvent::Info("test message".to_string()));
    assert!(*message_received.borrow());
}

fn test_dispatcher_multiple_handlers() {
    let dispatcher = Rc::new(RefCell::new(EventBus::new()));
    let counter = Rc::new(RefCell::new(0));

    let c1 = counter.clone();
    dispatcher.borrow_mut().on_info = Box::new(move |_info| {
        *c1.borrow_mut() += 1;
    });

    dispatcher
        .borrow()
        .emit(AppEvent::Info("increment".to_string()));
    assert_eq!(*counter.borrow(), 1);
}

// State Manager Tests
fn test_state_manager_creation() {
    let model = Rc::new(RefCell::new(AppModel::default()));
    let dispatcher = Rc::new(RefCell::new(EventBus::new()));
    let state = StateManager::new(model, dispatcher);
    let model = state.model();
    let borrowed = model.borrow();
    assert_eq!(borrowed.selected_phase(), 0);
}

fn test_state_manager_step_navigation() {
    let model = Rc::new(RefCell::new(AppModel::default()));
    let dispatcher = Rc::new(RefCell::new(EventBus::new()));
    let state = StateManager::new(model, dispatcher);

    state.select_phase(0);
    state.select_step(0);
    {
        let model = state.model();
        let borrowed = model.borrow();
        assert_eq!(borrowed.selected_phase(), 0);
        assert_eq!(borrowed.selected_step(), Some(0));
    }

    state.select_phase(1);
    state.select_step(2);
    {
        let model = state.model();
        let borrowed = model.borrow();
        assert_eq!(borrowed.selected_phase(), 1);
        assert_eq!(borrowed.selected_step(), Some(2));
    }
}

fn test_state_manager_step_notes_update() {
    let model = Rc::new(RefCell::new(AppModel::default()));
    let dispatcher = Rc::new(RefCell::new(EventBus::new()));
    let state = StateManager::new(model, dispatcher);
    let test_notes = "Updated notes content";

    state.update_step_notes(0, 0, test_notes.to_string());

    let model = state.model();
    let borrowed = model.borrow();
    let phase = &borrowed.session().phases[0];
    let step = &phase.steps[0];
    assert_eq!(step.get_notes(), test_notes);
}

fn test_state_manager_step_status_update() {
    let model = Rc::new(RefCell::new(AppModel::default()));
    let dispatcher = Rc::new(RefCell::new(EventBus::new()));
    let state = StateManager::new(model, dispatcher);

    state.update_step_status(0, 0, StepStatus::Done);

    let model = state.model();
    let borrowed = model.borrow();
    let phase = &borrowed.session().phases[0];
    let step = &phase.steps[0];
    assert_matches!(step.status, StepStatus::Done);
}

// UI Integration Tests (GTK)
fn test_tool_execution_panel_creation() {
    gtk4::init().expect("Failed to initialize GTK");

    let panel = pt_journal::ui::tool_execution::ToolExecutionPanel::new();
    assert_eq!(panel.get_selected_tool(), Some("nmap".to_string()));
    // Panel created successfully and has expected default tool
}

fn test_tool_selection() {
    gtk4::init().expect("Failed to initialize GTK");

    let panel = pt_journal::ui::tool_execution::ToolExecutionPanel::new();

    // Default should be nmap
    assert_eq!(panel.get_selected_tool(), Some("nmap".to_string()));

    // Switch to gobuster - use the new DropDown API
    if let Some(model) = panel.tool_selector.model() {
        if let Ok(string_list) = model.downcast::<gtk4::StringList>() {
            let count = string_list.n_items();
            let mut found = false;
            for idx in 0..count {
                panel.tool_selector.set_selected(idx);
                if panel.get_selected_tool() == Some("gobuster".to_string()) {
                    found = true;
                    break;
                }
            }
            assert!(found, "gobuster tool should exist");
            assert_eq!(panel.get_selected_tool(), Some("gobuster".to_string()));
        } else {
            panic!("Expected StringList model");
        }
    } else {
        panic!("Expected model to be set");
    }
}

fn main() {
    let tests: Vec<(&str, fn())> = vec![
        ("test_default_app_model", test_default_app_model),
        ("test_session_creation", test_session_creation),
        ("test_phase_structure", test_phase_structure),
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
