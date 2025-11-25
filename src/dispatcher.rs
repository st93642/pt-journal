/*****************************************************************************/
/*                                                                           */
/*  dispatcher.rs                                        TTTTTTTT SSSSSSS II */
/*                                                          TT    SS      II */
/*  By: st93642@students.tsi.lv                             TT    SSSSSSS II */
/*                                                          TT         SS II */
/*  Created: Nov 21 2025 23:42 st93642                      TT    SSSSSSS II */
/*  Updated: Nov 25 2025 17:42 st93642                                       */
/*                                                                           */
/*   Transport and Telecommunication Institute - Riga, Latvia                */
/*                       https://tsi.lv                                      */
/*****************************************************************************/

use std::cell::RefCell;
use std::collections::HashMap;
/// Event-driven message dispatcher for decoupled module communication
use std::rc::Rc;

/// Messages that can be dispatched throughout the application
#[derive(Debug, Clone)]
pub enum AppMessage {
    // Phase/Step Selection
    PhaseSelected(usize),
    StepSelected(usize),

    // Session Operations
    SessionLoaded(std::path::PathBuf),
    SessionSaved(std::path::PathBuf),
    SessionCreated,

    // Step Status Changes
    StepCompleted(usize, usize), // (phase_idx, step_idx)
    StepStatusChanged(usize, usize, crate::model::StepStatus),

    // Text Updates
    StepNotesUpdated(usize, usize, String),
    StepDescriptionNotesUpdated(usize, usize, String),
    PhaseNotesUpdated(usize, String),
    GlobalNotesUpdated(String),

    // Chat Operations
    ChatMessageAdded(usize, usize, crate::model::ChatMessage),
    ChatRequestStarted(usize, usize),
    ChatRequestCompleted(usize, usize),
    ChatRequestFailed(usize, usize, String),

    // Evidence Operations
    EvidenceAdded(usize, usize, crate::model::Evidence),
    EvidenceRemoved(usize, usize, uuid::Uuid),

    // UI Updates
    RefreshStepList(usize),
    RefreshDetailView(usize, usize),

    // Quiz Operations
    QuizAnswerChecked(usize, usize, usize, bool), // (phase_idx, step_idx, question_idx, is_correct)
    QuizExplanationViewed(usize, usize, usize),   // (phase_idx, step_idx, question_idx)
    QuizQuestionChanged(usize, usize, usize),     // (phase_idx, step_idx, question_idx)
    QuizStatisticsUpdated(usize, usize),          // (phase_idx, step_idx)

    // Error/Info
    Error(String),
    Info(String),
}

/// Handler function type for messages
pub type MessageHandler = Box<dyn Fn(&AppMessage)>;

/// Central message dispatcher for event-driven communication
pub struct Dispatcher {
    handlers: HashMap<String, Vec<MessageHandler>>,
}

impl Dispatcher {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for a specific message pattern
    /// Key should describe the handler's purpose (e.g., "ui:phase_list")
    pub fn register(&mut self, key: &str, handler: MessageHandler) {
        self.handlers
            .entry(key.to_string())
            .or_default()
            .push(handler);
    }

    /// Dispatch a message to all registered handlers
    pub fn dispatch(&self, message: &AppMessage) {
        for handlers in self.handlers.values() {
            for handler in handlers {
                handler(message);
            }
        }
    }

    /// Remove all handlers for a specific key
    pub fn unregister(&mut self, key: &str) {
        self.handlers.remove(key);
    }

    /// Clear all handlers
    pub fn clear(&mut self) {
        self.handlers.clear();
    }
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared dispatcher instance wrapped in Rc<RefCell<>> for GTK usage
pub type SharedDispatcher = Rc<RefCell<Dispatcher>>;

/// Create a new shared dispatcher instance
pub fn create_dispatcher() -> SharedDispatcher {
    Rc::new(RefCell::new(Dispatcher::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_dispatcher_creation() {
        let dispatcher = Dispatcher::new();
        assert_eq!(dispatcher.handlers.len(), 0);
    }

    #[test]
    fn test_register_handler() {
        let mut dispatcher = Dispatcher::new();
        let called = Arc::new(Mutex::new(false));
        let called_clone = called.clone();

        dispatcher.register(
            "test",
            Box::new(move |_| {
                *called_clone.lock().unwrap() = true;
            }),
        );

        assert_eq!(dispatcher.handlers.len(), 1);
        dispatcher.dispatch(&AppMessage::Info("test".to_string()));
        assert!(*called.lock().unwrap());
    }

    #[test]
    fn test_multiple_handlers() {
        let mut dispatcher = Dispatcher::new();
        let count = Arc::new(Mutex::new(0));
        let count_clone1 = count.clone();
        let count_clone2 = count.clone();

        dispatcher.register(
            "handler1",
            Box::new(move |_| {
                *count_clone1.lock().unwrap() += 1;
            }),
        );

        dispatcher.register(
            "handler2",
            Box::new(move |_| {
                *count_clone2.lock().unwrap() += 10;
            }),
        );

        dispatcher.dispatch(&AppMessage::Info("test".to_string()));
        assert_eq!(*count.lock().unwrap(), 11);
    }

    #[test]
    fn test_unregister_handler() {
        let mut dispatcher = Dispatcher::new();
        let called = Arc::new(Mutex::new(false));
        let called_clone = called.clone();

        dispatcher.register(
            "test",
            Box::new(move |_| {
                *called_clone.lock().unwrap() = true;
            }),
        );

        dispatcher.unregister("test");
        dispatcher.dispatch(&AppMessage::Info("test".to_string()));
        assert!(!*called.lock().unwrap());
    }

    #[test]
    fn test_message_variants() {
        let mut dispatcher = Dispatcher::new();
        let messages = Arc::new(Mutex::new(Vec::new()));
        let messages_clone = messages.clone();

        dispatcher.register(
            "collector",
            Box::new(move |msg| {
                messages_clone.lock().unwrap().push(format!("{:?}", msg));
            }),
        );

        dispatcher.dispatch(&AppMessage::PhaseSelected(0));
        dispatcher.dispatch(&AppMessage::StepSelected(1));
        dispatcher.dispatch(&AppMessage::SessionCreated);
        dispatcher.dispatch(&AppMessage::Error("test error".to_string()));

        let collected = messages.lock().unwrap();
        assert_eq!(collected.len(), 4);
        assert!(collected[0].contains("PhaseSelected"));
        assert!(collected[1].contains("StepSelected"));
        assert!(collected[2].contains("SessionCreated"));
        assert!(collected[3].contains("Error"));
    }

    #[test]
    fn test_clear_handlers() {
        let mut dispatcher = Dispatcher::new();
        dispatcher.register("test1", Box::new(|_| {}));
        dispatcher.register("test2", Box::new(|_| {}));

        assert_eq!(dispatcher.handlers.len(), 2);
        dispatcher.clear();
        assert_eq!(dispatcher.handlers.len(), 0);
    }

    #[test]
    fn test_shared_dispatcher() {
        let dispatcher = create_dispatcher();
        let called = Arc::new(Mutex::new(false));
        let called_clone = called.clone();

        dispatcher.borrow_mut().register(
            "test",
            Box::new(move |_| {
                *called_clone.lock().unwrap() = true;
            }),
        );

        dispatcher
            .borrow()
            .dispatch(&AppMessage::Info("test".to_string()));
        assert!(*called.lock().unwrap());
    }
}
