/*****************************************************************************/
/*                                                                           */
/*  dispatcher.rs                                        TTTTTTTT SSSSSSS II */
/*                                                          TT    SS      II */
/*  By: st93642@students.tsi.lv                             TT    SSSSSSS II */
/*                                                          TT         SS II */
/*  Created: Nov 21 2025 23:42 st93642                      TT    SSSSSSS II */
/*  Updated: Nov 27 2025 00:06 st93642                                       */
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
    ChatModelChanged(String), // model_id

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

/// Enum representing the kind (discriminant) of AppMessage variants
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AppMessageKind {
    PhaseSelected,
    StepSelected,
    SessionLoaded,
    SessionSaved,
    SessionCreated,
    StepCompleted,
    StepStatusChanged,
    StepNotesUpdated,
    StepDescriptionNotesUpdated,
    PhaseNotesUpdated,
    GlobalNotesUpdated,
    ChatMessageAdded,
    ChatRequestStarted,
    ChatRequestCompleted,
    ChatRequestFailed,
    ChatModelChanged,
    EvidenceAdded,
    EvidenceRemoved,
    RefreshStepList,
    RefreshDetailView,
    QuizAnswerChecked,
    QuizExplanationViewed,
    QuizQuestionChanged,
    QuizStatisticsUpdated,
    Error,
    Info,
}

impl From<&AppMessage> for AppMessageKind {
    fn from(msg: &AppMessage) -> Self {
        match msg {
            AppMessage::PhaseSelected(_) => AppMessageKind::PhaseSelected,
            AppMessage::StepSelected(_) => AppMessageKind::StepSelected,
            AppMessage::SessionLoaded(_) => AppMessageKind::SessionLoaded,
            AppMessage::SessionSaved(_) => AppMessageKind::SessionSaved,
            AppMessage::SessionCreated => AppMessageKind::SessionCreated,
            AppMessage::StepCompleted(_, _) => AppMessageKind::StepCompleted,
            AppMessage::StepStatusChanged(_, _, _) => AppMessageKind::StepStatusChanged,
            AppMessage::StepNotesUpdated(_, _, _) => AppMessageKind::StepNotesUpdated,
            AppMessage::StepDescriptionNotesUpdated(_, _, _) => {
                AppMessageKind::StepDescriptionNotesUpdated
            }
            AppMessage::PhaseNotesUpdated(_, _) => AppMessageKind::PhaseNotesUpdated,
            AppMessage::GlobalNotesUpdated(_) => AppMessageKind::GlobalNotesUpdated,
            AppMessage::ChatMessageAdded(_, _, _) => AppMessageKind::ChatMessageAdded,
            AppMessage::ChatRequestStarted(_, _) => AppMessageKind::ChatRequestStarted,
            AppMessage::ChatRequestCompleted(_, _) => AppMessageKind::ChatRequestCompleted,
            AppMessage::ChatRequestFailed(_, _, _) => AppMessageKind::ChatRequestFailed,
            AppMessage::ChatModelChanged(_) => AppMessageKind::ChatModelChanged,
            AppMessage::EvidenceAdded(_, _, _) => AppMessageKind::EvidenceAdded,
            AppMessage::EvidenceRemoved(_, _, _) => AppMessageKind::EvidenceRemoved,
            AppMessage::RefreshStepList(_) => AppMessageKind::RefreshStepList,
            AppMessage::RefreshDetailView(_, _) => AppMessageKind::RefreshDetailView,
            AppMessage::QuizAnswerChecked(_, _, _, _) => AppMessageKind::QuizAnswerChecked,
            AppMessage::QuizExplanationViewed(_, _, _) => AppMessageKind::QuizExplanationViewed,
            AppMessage::QuizQuestionChanged(_, _, _) => AppMessageKind::QuizQuestionChanged,
            AppMessage::QuizStatisticsUpdated(_, _) => AppMessageKind::QuizStatisticsUpdated,
            AppMessage::Error(_) => AppMessageKind::Error,
            AppMessage::Info(_) => AppMessageKind::Info,
        }
    }
}

/// Handler function type for messages
pub type MessageHandler = Box<dyn Fn(&AppMessage)>;

/// Central message dispatcher for event-driven communication
///
/// The dispatcher supports targeted message routing where handlers can subscribe
/// to specific message kinds or listen to all messages (wildcard).
///
/// # Examples
///
/// ```rust
/// use pt_journal::dispatcher::{Dispatcher, AppMessageKind};
///
/// let mut dispatcher = Dispatcher::new();
/// let handler = |msg: &pt_journal::dispatcher::AppMessage| {
///     println!("Received message: {:?}", msg);
/// };
///
/// // Register for specific message kinds
/// dispatcher.register(Some(AppMessageKind::ChatMessageAdded), "my_chat_handler", Box::new(handler));
///
/// // Register for all messages (wildcard)
/// dispatcher.register(None, "my_wildcard_handler", Box::new(handler));
/// ```
pub struct Dispatcher {
    /// Handlers organized by message kind (None = wildcard for all messages)
    handlers: HashMap<Option<AppMessageKind>, HashMap<String, Vec<MessageHandler>>>,
}

impl Dispatcher {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for a specific message kind or all messages (wildcard)
    ///
    /// # Arguments
    /// * `kind` - The message kind to listen for, or None to listen to all messages
    /// * `key` - A unique identifier for this handler (used for unregistering)
    /// * `handler` - The function to call when a matching message is dispatched
    ///
    /// # Examples
    /// ```rust
    /// use pt_journal::dispatcher::{Dispatcher, AppMessageKind};
    ///
    /// let mut dispatcher = Dispatcher::new();
    /// let handler = |msg: &pt_journal::dispatcher::AppMessage| {
    ///     println!("Received message: {:?}", msg);
    /// };
    ///
    /// // Listen only to chat messages
    /// dispatcher.register(Some(AppMessageKind::ChatMessageAdded), "my_chat_handler", Box::new(handler));
    ///
    /// // Listen to all messages (wildcard)
    /// dispatcher.register(None, "my_wildcard_handler", Box::new(handler));
    /// ```
    pub fn register(&mut self, kind: Option<AppMessageKind>, key: &str, handler: MessageHandler) {
        self.handlers
            .entry(kind)
            .or_default()
            .entry(key.to_string())
            .or_default()
            .push(handler);
    }

    /// Dispatch a message to all registered handlers that match the message kind
    /// or are registered as wildcards (listening to all messages)
    pub fn dispatch(&self, message: &AppMessage) {
        let kind = AppMessageKind::from(message);

        // Call handlers for the specific message kind
        if let Some(kind_handlers) = self.handlers.get(&Some(kind.clone())) {
            for handlers in kind_handlers.values() {
                for handler in handlers {
                    handler(message);
                }
            }
        }

        // Call wildcard handlers (registered with None)
        if let Some(wildcard_handlers) = self.handlers.get(&None) {
            for handlers in wildcard_handlers.values() {
                for handler in handlers {
                    handler(message);
                }
            }
        }
    }

    /// Remove all handlers for a specific key across all message kinds
    pub fn unregister(&mut self, key: &str) {
        for kind_handlers in self.handlers.values_mut() {
            kind_handlers.remove(key);
        }
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
            None, // wildcard
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
            None, // wildcard
            "handler1",
            Box::new(move |_| {
                *count_clone1.lock().unwrap() += 1;
            }),
        );

        dispatcher.register(
            None, // wildcard
            "handler2",
            Box::new(move |_| {
                *count_clone2.lock().unwrap() += 10;
            }),
        );

        dispatcher.dispatch(&AppMessage::Info("test".to_string()));
        assert_eq!(*count.lock().unwrap(), 11);
    }

    #[test]
    fn test_message_variants() {
        let mut dispatcher = Dispatcher::new();
        let messages = Arc::new(Mutex::new(Vec::new()));
        let messages_clone = messages.clone();

        dispatcher.register(
            None, // wildcard
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
        dispatcher.register(None, "test1", Box::new(|_| {}));
        dispatcher.register(None, "test2", Box::new(|_| {}));

        assert_eq!(dispatcher.handlers.len(), 1); // Both under None key
        dispatcher.clear();
        assert_eq!(dispatcher.handlers.len(), 0);
    }

    #[test]
    fn test_shared_dispatcher() {
        let dispatcher = create_dispatcher();
        let called = Arc::new(Mutex::new(false));
        let called_clone = called.clone();

        dispatcher.borrow_mut().register(
            None, // wildcard
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

    #[test]
    fn test_specific_kind_routing() {
        let mut dispatcher = Dispatcher::new();
        let chat_calls = Arc::new(Mutex::new(0));
        let info_calls = Arc::new(Mutex::new(0));

        let chat_clone = chat_calls.clone();
        let info_clone = info_calls.clone();

        // Register handler for only ChatMessageAdded
        dispatcher.register(
            Some(AppMessageKind::ChatMessageAdded),
            "chat_handler",
            Box::new(move |_| {
                *chat_clone.lock().unwrap() += 1;
            }),
        );

        // Register handler for only Info messages
        dispatcher.register(
            Some(AppMessageKind::Info),
            "info_handler",
            Box::new(move |_| {
                *info_clone.lock().unwrap() += 1;
            }),
        );

        // Dispatch ChatMessageAdded - should only call chat handler
        dispatcher.dispatch(&AppMessage::ChatMessageAdded(
            0,
            0,
            crate::model::ChatMessage::new(crate::model::ChatRole::User, "test".to_string()),
        ));
        assert_eq!(*chat_calls.lock().unwrap(), 1);
        assert_eq!(*info_calls.lock().unwrap(), 0);

        // Dispatch Info - should only call info handler
        dispatcher.dispatch(&AppMessage::Info("test info".to_string()));
        assert_eq!(*chat_calls.lock().unwrap(), 1);
        assert_eq!(*info_calls.lock().unwrap(), 1);

        // Dispatch unrelated message - should call neither
        dispatcher.dispatch(&AppMessage::PhaseSelected(1));
        assert_eq!(*chat_calls.lock().unwrap(), 1);
        assert_eq!(*info_calls.lock().unwrap(), 1);
    }

    #[test]
    fn test_wildcard_handlers_receive_all_messages() {
        let mut dispatcher = Dispatcher::new();
        let call_count = Arc::new(Mutex::new(0));
        let count_clone = call_count.clone();

        // Register wildcard handler
        dispatcher.register(
            None, // wildcard
            "wildcard_handler",
            Box::new(move |_| {
                *count_clone.lock().unwrap() += 1;
            }),
        );

        // Dispatch different message types
        dispatcher.dispatch(&AppMessage::ChatMessageAdded(
            0,
            0,
            crate::model::ChatMessage::new(crate::model::ChatRole::User, "test".to_string()),
        ));
        dispatcher.dispatch(&AppMessage::Info("test info".to_string()));
        dispatcher.dispatch(&AppMessage::PhaseSelected(1));
        dispatcher.dispatch(&AppMessage::Error("test error".to_string()));

        assert_eq!(*call_count.lock().unwrap(), 4);
    }

    #[test]
    fn test_mixed_specific_and_wildcard_handlers() {
        let mut dispatcher = Dispatcher::new();
        let specific_calls = Arc::new(Mutex::new(0));
        let wildcard_calls = Arc::new(Mutex::new(0));

        let specific_clone = specific_calls.clone();
        let wildcard_clone = wildcard_calls.clone();

        // Register specific handler for Info messages
        dispatcher.register(
            Some(AppMessageKind::Info),
            "info_specific",
            Box::new(move |_| {
                *specific_clone.lock().unwrap() += 1;
            }),
        );

        // Register wildcard handler
        dispatcher.register(
            None,
            "wildcard",
            Box::new(move |_| {
                *wildcard_clone.lock().unwrap() += 1;
            }),
        );

        // Dispatch Info - should call both handlers
        dispatcher.dispatch(&AppMessage::Info("test".to_string()));
        assert_eq!(*specific_calls.lock().unwrap(), 1);
        assert_eq!(*wildcard_calls.lock().unwrap(), 1);

        // Dispatch ChatMessageAdded - should only call wildcard
        dispatcher.dispatch(&AppMessage::ChatMessageAdded(
            0,
            0,
            crate::model::ChatMessage::new(crate::model::ChatRole::User, "test".to_string()),
        ));
        assert_eq!(*specific_calls.lock().unwrap(), 1);
        assert_eq!(*wildcard_calls.lock().unwrap(), 2);
    }

    #[test]
    fn test_unregister_removes_from_all_kinds() {
        let mut dispatcher = Dispatcher::new();
        let calls = Arc::new(Mutex::new(0));

        // Register same key for different kinds
        let calls1 = calls.clone();
        dispatcher.register(
            Some(AppMessageKind::Info),
            "test_key",
            Box::new(move |_| {
                *calls1.lock().unwrap() += 1;
            }),
        );

        let calls2 = calls.clone();
        dispatcher.register(
            Some(AppMessageKind::Error),
            "test_key",
            Box::new(move |_| {
                *calls2.lock().unwrap() += 1;
            }),
        );

        // Unregister by key should remove all
        dispatcher.unregister("test_key");

        dispatcher.dispatch(&AppMessage::Info("test".to_string()));
        dispatcher.dispatch(&AppMessage::Error("test".to_string()));

        // Should not have been called
        assert_eq!(*calls.lock().unwrap(), 0);
    }
}
