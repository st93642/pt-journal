//! Base abstraction for UI event handlers.
//!
//! This module provides a standardized interface for handling UI events
//! and coordinating between user interactions and application state.
//!
//! ## Handler Pattern
//!
//! Handlers follow a functional pattern where they:
//! 1. Receive context about the event (user input, widget state, etc.)
//! 2. Interact with application state through the StateManager
//! 3. Return UI updates that describe how the interface should change
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::ui::handler_base::{Handler, HandlerContext, UIUpdate};
//!
//! struct MyHandler {
//!     state: Rc<StateManager>,
//! }
//!
//! impl Handler for MyHandler {
//!     type Context = MyEventData;
//!     type Result = Result<UIUpdate, HandlerError>;
//!
//!     fn handle(&self, context: Self::Context) -> Self::Result {
//!         // Process the event and return UI updates
//!         Ok(UIUpdate::None)
//!     }
//! }
//! ```

use std::rc::Rc;
use gtk4::glib;

use crate::ui::state::StateManager;
use crate::error::Result as PtResult;

/// Context passed to handlers containing event information and dependencies.
#[derive(Clone)]
pub struct HandlerContext {
    /// Optional reference to the state manager for state mutations
    pub state: Option<Rc<StateManager>>,
    /// Event-specific data (can be extended by specific handlers)
    pub event_data: EventData,
}

/// Event data that can be passed to handlers.
/// This is extensible for different types of events.
#[derive(Debug, Clone)]
pub enum EventData {
    /// No event data
    None,
    /// String data (e.g., text input, selected item)
    String(String),
    /// Index data (e.g., selected phase/step/question index)
    Index(usize),
    /// Boolean data (e.g., checkbox state)
    Bool(bool),
    /// Tuple data for complex events
    Tuple((usize, usize)), // e.g., (phase_idx, step_idx)
    /// Triple data for complex events
    Triple((usize, usize, usize)), // e.g., (phase_idx, step_idx, question_idx)
}

/// Result of UI updates that handlers can request.
#[derive(Debug, Clone)]
pub enum UIUpdate {
    /// No UI update needed
    None,
    /// Update the detail panel with new content
    UpdateDetailPanel,
    /// Refresh the steps list
    RefreshStepsList,
    /// Refresh the phase combo box
    RefreshPhaseCombo,
    /// Show an error dialog with the given message
    ShowError(String),
    /// Show a success message
    ShowSuccess(String),
    /// Update quiz statistics display
    UpdateQuizStats,
    /// Refresh the current quiz question
    RefreshQuizQuestion,
    /// Custom update with specific data
    Custom(String),
}

/// Trait for UI event handlers.
///
/// Handlers encapsulate the logic for processing user interactions
/// and coordinating between the UI layer and application state.
pub trait Handler {
    /// The type of context this handler expects
    type Context;
    /// The type of result this handler returns
    type Result;

    /// Handle an event with the given context.
    ///
    /// # Arguments
    /// * `context` - The context containing event data and dependencies
    ///
    /// # Returns
    /// Result of handling the event, typically containing UI updates
    fn handle(&self, context: Self::Context) -> Self::Result;
}

/// Macro to generate boilerplate for GTK signal handlers.
///
/// This macro creates a closure that captures the necessary state
/// and converts GTK events into Handler trait calls.
///
/// # Example
///
/// ```rust,ignore
/// make_handler!(my_button, connect_clicked, MyHandler, |btn| {
///     HandlerContext::new(state.clone(), EventData::None)
/// })
/// ```
#[macro_export]
macro_rules! make_handler {
    ($widget:expr, $signal:ident, $handler:expr, $context_fn:expr) => {
        $widget.$signal(move |args| {
            let context = $context_fn(args);
            if let Err(e) = crate::ui::handler_base::execute_handler(&$handler, context) {
                eprintln!("Handler error: {}", e);
            }
        });
    };
}

/// Helper function to create a handler context.
pub fn create_context(state: Option<Rc<StateManager>>, event_data: EventData) -> HandlerContext {
    HandlerContext { state, event_data }
}

/// Helper function to execute a handler and process the result.
///
/// This function handles common post-handler logic like dispatching
/// UI updates to the GTK main loop.
pub fn execute_handler<H, C, R>(
    handler: &H,
    context: C,
) -> PtResult<()>
where
    H: Handler<Context = C, Result = PtResult<R>>,
    R: Into<UIUpdate>,
{
    let result = handler.handle(context)?;
    let update: UIUpdate = result.into();

    match update {
        UIUpdate::None => {
            // No action needed
        }
        UIUpdate::UpdateDetailPanel => {
            // Schedule detail panel update on main thread
            glib::idle_add_local_once(|| {
                // TODO: Implement detail panel update logic
            });
        }
        UIUpdate::RefreshStepsList => {
            // Schedule steps list refresh on main thread
            glib::idle_add_local_once(|| {
                // TODO: Implement steps list refresh logic
            });
        }
        UIUpdate::RefreshPhaseCombo => {
            // Schedule phase combo refresh on main thread
            glib::idle_add_local_once(move || {
                // TODO: Implement phase combo refresh logic
            });
        }
        UIUpdate::ShowError(message) => {
            // Schedule error dialog on main thread
            let message_clone = message.clone();
            glib::idle_add_local_once(move || {
                // TODO: Implement error dialog logic
                eprintln!("Error: {}", message_clone);
            });
        }
        UIUpdate::ShowSuccess(message) => {
            // Schedule success message on main thread
            let message_clone = message.clone();
            glib::idle_add_local_once(move || {
                // TODO: Implement success message logic
                println!("Success: {}", message_clone);
            });
        }
        UIUpdate::UpdateQuizStats | UIUpdate::RefreshQuizQuestion => {
            // Schedule quiz UI updates on main thread
            glib::idle_add_local_once(|| {
                // TODO: Implement quiz UI update logic
            });
        }
        UIUpdate::Custom(data) => {
            // Custom update handling
            let data_clone = data.clone();
            glib::idle_add_local_once(move || {
                // TODO: Implement custom update logic
                println!("Custom update: {}", data_clone);
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_context() {
        // This would need a mock StateManager
        // For now, just test the event data structure
        let _event_data = EventData::String("test".to_string());
        // let context = create_context(state, event_data);
        // assert!(matches!(context.event_data, EventData::String(s) if s == "test"));
    }

    #[test]
    fn test_ui_update_variants() {
        match UIUpdate::None {
            UIUpdate::None => (),
            _ => panic!("Expected None"),
        }
        match UIUpdate::UpdateDetailPanel {
            UIUpdate::UpdateDetailPanel => (),
            _ => panic!("Expected UpdateDetailPanel"),
        }
        match UIUpdate::ShowError("test".to_string()) {
            UIUpdate::ShowError(_) => (),
            _ => panic!("Expected ShowError"),
        }
    }
}