/*****************************************************************************/
/*                                                                           */
/*  dispatcher.rs                                        TTTTTTTT SSSSSSS II */
/*                                                          TT    SS      II */
/*  By: st93642@students.tsi.lv                             TT    SSSSSSS II */
/*                                                          TT         SS II */
/*  Created: Nov 21 2025 23:42 st93642                      TT    SSSSSSS II */
/*  Updated: Nov 27 2025 18:18 st93642                                       */
/*                                                                           */
/*   Transport and Telecommunication Institute - Riga, Latvia                */
/*                       https://tsi.lv                                      */
/*****************************************************************************/

use std::cell::RefCell;
use std::rc::Rc;

/// Events that can be emitted throughout the application
///
/// This enum consolidates the previous AppMessage and AppMessageKind enums
/// into a single, clear event system.
#[derive(Debug, Clone)]
pub enum AppEvent {
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

/// Direct event bus with simplified callback architecture
///
/// Replaces the complex HashMap-based dispatcher with direct function calls.
/// Each event type has its own callback field for clear, traceable event flow.
pub struct EventBus {
    // Phase/Step Selection
    pub on_phase_selected: Box<dyn Fn(usize)>,
    pub on_step_selected: Box<dyn Fn(usize)>,

    // Session Operations
    pub on_session_loaded: Box<dyn Fn(std::path::PathBuf)>,
    pub on_session_saved: Box<dyn Fn(std::path::PathBuf)>,
    pub on_session_created: Box<dyn Fn()>,

    // Step Status Changes
    pub on_step_completed: Box<dyn Fn(usize, usize)>,
    pub on_step_status_changed: Box<dyn Fn(usize, usize, crate::model::StepStatus)>,

    // Text Updates
    pub on_step_notes_updated: Box<dyn Fn(usize, usize, String)>,
    pub on_step_description_notes_updated: Box<dyn Fn(usize, usize, String)>,
    pub on_phase_notes_updated: Box<dyn Fn(usize, String)>,
    pub on_global_notes_updated: Box<dyn Fn(String)>,

    // Chat Operations
    pub on_chat_message_added: Box<dyn Fn(usize, usize, crate::model::ChatMessage)>,
    pub on_chat_request_started: Box<dyn Fn(usize, usize)>,
    pub on_chat_request_completed: Box<dyn Fn(usize, usize)>,
    pub on_chat_request_failed: Box<dyn Fn(usize, usize, String)>,
    pub on_chat_model_changed: Box<dyn Fn(String)>,

    // Evidence Operations
    pub on_evidence_added: Box<dyn Fn(usize, usize, crate::model::Evidence)>,
    pub on_evidence_removed: Box<dyn Fn(usize, usize, uuid::Uuid)>,

    // UI Updates
    pub on_refresh_step_list: Box<dyn Fn(usize)>,
    pub on_refresh_detail_view: Box<dyn Fn(usize, usize)>,

    // Quiz Operations
    pub on_quiz_answer_checked: Box<dyn Fn(usize, usize, usize, bool)>,
    pub on_quiz_explanation_viewed: Box<dyn Fn(usize, usize, usize)>,
    pub on_quiz_question_changed: Box<dyn Fn(usize, usize, usize)>,
    pub on_quiz_statistics_updated: Box<dyn Fn(usize, usize)>,

    // Error/Info
    pub on_error: Box<dyn Fn(String)>,
    pub on_info: Box<dyn Fn(String)>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self {
            on_phase_selected: Box::new(|_| {}),
            on_step_selected: Box::new(|_| {}),
            on_session_loaded: Box::new(|_| {}),
            on_session_saved: Box::new(|_| {}),
            on_session_created: Box::new(|| {}),
            on_step_completed: Box::new(|_, _| {}),
            on_step_status_changed: Box::new(|_, _, _| {}),
            on_step_notes_updated: Box::new(|_, _, _| {}),
            on_step_description_notes_updated: Box::new(|_, _, _| {}),
            on_phase_notes_updated: Box::new(|_, _| {}),
            on_global_notes_updated: Box::new(|_| {}),
            on_chat_message_added: Box::new(|_, _, _| {}),
            on_chat_request_started: Box::new(|_, _| {}),
            on_chat_request_completed: Box::new(|_, _| {}),
            on_chat_request_failed: Box::new(|_, _, _| {}),
            on_chat_model_changed: Box::new(|_| {}),
            on_evidence_added: Box::new(|_, _, _| {}),
            on_evidence_removed: Box::new(|_, _, _| {}),
            on_refresh_step_list: Box::new(|_| {}),
            on_refresh_detail_view: Box::new(|_, _| {}),
            on_quiz_answer_checked: Box::new(|_, _, _, _| {}),
            on_quiz_explanation_viewed: Box::new(|_, _, _| {}),
            on_quiz_question_changed: Box::new(|_, _, _| {}),
            on_quiz_statistics_updated: Box::new(|_, _| {}),
            on_error: Box::new(|_| {}),
            on_info: Box::new(|_| {}),
        }
    }
}

impl EventBus {
    /// Create a new EventBus with default no-op handlers
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit an event to the appropriate handler
    ///
    /// This replaces the complex dispatcher routing with a simple match statement
    /// that calls the appropriate callback directly.
    pub fn emit(&self, event: AppEvent) {
        match event {
            AppEvent::PhaseSelected(idx) => (self.on_phase_selected)(idx),
            AppEvent::StepSelected(idx) => (self.on_step_selected)(idx),
            AppEvent::SessionLoaded(path) => (self.on_session_loaded)(path),
            AppEvent::SessionSaved(path) => (self.on_session_saved)(path),
            AppEvent::SessionCreated => (self.on_session_created)(),
            AppEvent::StepCompleted(phase_idx, step_idx) => {
                (self.on_step_completed)(phase_idx, step_idx)
            }
            AppEvent::StepStatusChanged(phase_idx, step_idx, status) => {
                (self.on_step_status_changed)(phase_idx, step_idx, status)
            }
            AppEvent::StepNotesUpdated(phase_idx, step_idx, notes) => {
                (self.on_step_notes_updated)(phase_idx, step_idx, notes)
            }
            AppEvent::StepDescriptionNotesUpdated(phase_idx, step_idx, notes) => {
                (self.on_step_description_notes_updated)(phase_idx, step_idx, notes)
            }
            AppEvent::PhaseNotesUpdated(phase_idx, notes) => {
                (self.on_phase_notes_updated)(phase_idx, notes)
            }
            AppEvent::GlobalNotesUpdated(notes) => (self.on_global_notes_updated)(notes),
            AppEvent::ChatMessageAdded(phase_idx, step_idx, message) => {
                (self.on_chat_message_added)(phase_idx, step_idx, message)
            }
            AppEvent::ChatRequestStarted(phase_idx, step_idx) => {
                (self.on_chat_request_started)(phase_idx, step_idx)
            }
            AppEvent::ChatRequestCompleted(phase_idx, step_idx) => {
                (self.on_chat_request_completed)(phase_idx, step_idx)
            }
            AppEvent::ChatRequestFailed(phase_idx, step_idx, error) => {
                (self.on_chat_request_failed)(phase_idx, step_idx, error)
            }
            AppEvent::ChatModelChanged(model_id) => (self.on_chat_model_changed)(model_id),
            AppEvent::EvidenceAdded(phase_idx, step_idx, evidence) => {
                (self.on_evidence_added)(phase_idx, step_idx, evidence)
            }
            AppEvent::EvidenceRemoved(phase_idx, step_idx, evidence_id) => {
                (self.on_evidence_removed)(phase_idx, step_idx, evidence_id)
            }
            AppEvent::RefreshStepList(phase_idx) => (self.on_refresh_step_list)(phase_idx),
            AppEvent::RefreshDetailView(phase_idx, step_idx) => {
                (self.on_refresh_detail_view)(phase_idx, step_idx)
            }
            AppEvent::QuizAnswerChecked(phase_idx, step_idx, question_idx, is_correct) => {
                (self.on_quiz_answer_checked)(phase_idx, step_idx, question_idx, is_correct)
            }
            AppEvent::QuizExplanationViewed(phase_idx, step_idx, question_idx) => {
                (self.on_quiz_explanation_viewed)(phase_idx, step_idx, question_idx)
            }
            AppEvent::QuizQuestionChanged(phase_idx, step_idx, question_idx) => {
                (self.on_quiz_question_changed)(phase_idx, step_idx, question_idx)
            }
            AppEvent::QuizStatisticsUpdated(phase_idx, step_idx) => {
                (self.on_quiz_statistics_updated)(phase_idx, step_idx)
            }
            AppEvent::Error(error) => (self.on_error)(error),
            AppEvent::Info(info) => (self.on_info)(info),
        }
    }

    /// Builder-style method to set the phase selected handler
    pub fn with_phase_selected<F>(mut self, handler: F) -> Self
    where
        F: Fn(usize) + 'static,
    {
        self.on_phase_selected = Box::new(handler);
        self
    }

    /// Builder-style method to set the step selected handler
    pub fn with_step_selected<F>(mut self, handler: F) -> Self
    where
        F: Fn(usize) + 'static,
    {
        self.on_step_selected = Box::new(handler);
        self
    }

    /// Builder-style method to set the step notes updated handler
    pub fn with_step_notes_updated<F>(mut self, handler: F) -> Self
    where
        F: Fn(usize, usize, String) + 'static,
    {
        self.on_step_notes_updated = Box::new(handler);
        self
    }

    /// Builder-style method to set the error handler
    pub fn with_error<F>(mut self, handler: F) -> Self
    where
        F: Fn(String) + 'static,
    {
        self.on_error = Box::new(handler);
        self
    }

    /// Builder-style method to set the info handler
    pub fn with_info<F>(mut self, handler: F) -> Self
    where
        F: Fn(String) + 'static,
    {
        self.on_info = Box::new(handler);
        self
    }

    /// Builder-style method to set the chat message added handler
    pub fn with_chat_message_added<F>(mut self, handler: F) -> Self
    where
        F: Fn(usize, usize, crate::model::ChatMessage) + 'static,
    {
        self.on_chat_message_added = Box::new(handler);
        self
    }

    /// Builder-style method to set the refresh step list handler
    pub fn with_refresh_step_list<F>(mut self, handler: F) -> Self
    where
        F: Fn(usize) + 'static,
    {
        self.on_refresh_step_list = Box::new(handler);
        self
    }

    /// Builder-style method to set the refresh detail view handler
    pub fn with_refresh_detail_view<F>(mut self, handler: F) -> Self
    where
        F: Fn(usize, usize) + 'static,
    {
        self.on_refresh_detail_view = Box::new(handler);
        self
    }
}

/// Shared event bus instance wrapped in Rc<RefCell<>> for GTK usage
pub type SharedEventBus = Rc<RefCell<EventBus>>;

/// Create a new shared event bus instance
pub fn create_event_bus() -> SharedEventBus {
    Rc::new(RefCell::new(EventBus::new()))
}

// Legacy type aliases for backward compatibility during migration
pub type AppMessage = AppEvent;
pub type SharedDispatcher = SharedEventBus;

/// Create a new shared dispatcher instance (legacy compatibility)
pub fn create_dispatcher() -> SharedDispatcher {
    create_event_bus()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_event_bus_creation() {
        let _bus = EventBus::new();
        // Should create without panicking
        assert!(true);
    }

    #[test]
    fn test_phase_selected_event() {
        let received = Arc::new(Mutex::new(None));
        let received_clone = received.clone();

        let bus = EventBus::new().with_phase_selected(move |idx| {
            *received_clone.lock().unwrap() = Some(idx);
        });

        bus.emit(AppEvent::PhaseSelected(5));
        assert_eq!(*received.lock().unwrap(), Some(5));
    }

    #[test]
    fn test_step_selected_event() {
        let received = Arc::new(Mutex::new(None));
        let received_clone = received.clone();

        let bus = EventBus::new().with_step_selected(move |idx| {
            *received_clone.lock().unwrap() = Some(idx);
        });

        bus.emit(AppEvent::StepSelected(3));
        assert_eq!(*received.lock().unwrap(), Some(3));
    }

    #[test]
    fn test_step_notes_updated_event() {
        let received = Arc::new(Mutex::new(None));
        let received_clone = received.clone();

        let bus = EventBus::new().with_step_notes_updated(move |phase_idx, step_idx, notes| {
            *received_clone.lock().unwrap() = Some((phase_idx, step_idx, notes));
        });

        bus.emit(AppEvent::StepNotesUpdated(1, 2, "test notes".to_string()));
        let received_val = received.lock().unwrap();
        assert_eq!(
            received_val.as_ref().unwrap(),
            &(1, 2, "test notes".to_string())
        );
    }

    #[test]
    fn test_error_event() {
        let received = Arc::new(Mutex::new(None));
        let received_clone = received.clone();

        let bus = EventBus::new().with_error(move |error| {
            *received_clone.lock().unwrap() = Some(error);
        });

        bus.emit(AppEvent::Error("test error".to_string()));
        assert_eq!(*received.lock().unwrap(), Some("test error".to_string()));
    }

    #[test]
    fn test_info_event() {
        let received = Arc::new(Mutex::new(None));
        let received_clone = received.clone();

        let bus = EventBus::new().with_info(move |info| {
            *received_clone.lock().unwrap() = Some(info);
        });

        bus.emit(AppEvent::Info("test info".to_string()));
        assert_eq!(*received.lock().unwrap(), Some("test info".to_string()));
    }

    #[test]
    fn test_chat_message_added_event() {
        use crate::model::{ChatMessage, ChatRole};

        let received = Arc::new(Mutex::new(None));
        let received_clone = received.clone();

        let bus = EventBus::new().with_chat_message_added(move |phase_idx, step_idx, message| {
            *received_clone.lock().unwrap() = Some((phase_idx, step_idx, message));
        });

        let message = ChatMessage::new(ChatRole::User, "test message".to_string());
        bus.emit(AppEvent::ChatMessageAdded(0, 1, message.clone()));

        let received_val = received.lock().unwrap();
        let (phase_idx, step_idx, received_message) = received_val.as_ref().unwrap();
        assert_eq!(*phase_idx, 0);
        assert_eq!(*step_idx, 1);
        assert_eq!(received_message.content, "test message");
    }

    #[test]
    fn test_multiple_handlers() {
        let phase_received = Arc::new(Mutex::new(None));
        let step_received = Arc::new(Mutex::new(None));

        let phase_clone = phase_received.clone();
        let step_clone = step_received.clone();

        let bus = EventBus::new()
            .with_phase_selected(move |idx| {
                *phase_clone.lock().unwrap() = Some(idx);
            })
            .with_step_selected(move |idx| {
                *step_clone.lock().unwrap() = Some(idx);
            });

        bus.emit(AppEvent::PhaseSelected(7));
        bus.emit(AppEvent::StepSelected(8));

        assert_eq!(*phase_received.lock().unwrap(), Some(7));
        assert_eq!(*step_received.lock().unwrap(), Some(8));
    }

    #[test]
    fn test_shared_event_bus() {
        let bus = create_event_bus();
        let received = Arc::new(Mutex::new(None));
        let received_clone = received.clone();

        bus.borrow_mut().on_phase_selected = Box::new(move |idx| {
            *received_clone.lock().unwrap() = Some(idx);
        });

        bus.borrow().emit(AppEvent::PhaseSelected(9));
        assert_eq!(*received.lock().unwrap(), Some(9));
    }

    #[test]
    fn test_legacy_compatibility() {
        // Test that legacy type aliases work
        let _dispatcher: SharedDispatcher = create_dispatcher();
        let _message: AppMessage = AppEvent::Info("test".to_string());

        // Should compile and work
        assert!(true);
    }

    #[test]
    fn test_all_event_types() {
        // Test that all event types can be emitted without panicking
        use crate::model::{ChatMessage, ChatRole, Evidence, StepStatus};
        use std::path::PathBuf;
        use uuid::Uuid;

        let bus = EventBus::new();

        // Test each event variant to ensure they all work
        bus.emit(AppEvent::PhaseSelected(0));
        bus.emit(AppEvent::StepSelected(0));
        bus.emit(AppEvent::SessionLoaded(PathBuf::from("/test")));
        bus.emit(AppEvent::SessionSaved(PathBuf::from("/test")));
        bus.emit(AppEvent::SessionCreated);
        bus.emit(AppEvent::StepCompleted(0, 0));
        bus.emit(AppEvent::StepStatusChanged(0, 0, StepStatus::Done));
        bus.emit(AppEvent::StepNotesUpdated(0, 0, "test".to_string()));
        bus.emit(AppEvent::StepDescriptionNotesUpdated(
            0,
            0,
            "test".to_string(),
        ));
        bus.emit(AppEvent::PhaseNotesUpdated(0, "test".to_string()));
        bus.emit(AppEvent::GlobalNotesUpdated("test".to_string()));

        let message = ChatMessage::new(ChatRole::User, "test".to_string());
        bus.emit(AppEvent::ChatMessageAdded(0, 0, message));
        bus.emit(AppEvent::ChatRequestStarted(0, 0));
        bus.emit(AppEvent::ChatRequestCompleted(0, 0));
        bus.emit(AppEvent::ChatRequestFailed(0, 0, "error".to_string()));
        bus.emit(AppEvent::ChatModelChanged("test".to_string()));

        let evidence = Evidence {
            id: Uuid::new_v4(),
            path: "/test".to_string(),
            created_at: chrono::Utc::now(),
            kind: "test".to_string(),
            x: 0.0,
            y: 0.0,
        };
        bus.emit(AppEvent::EvidenceAdded(0, 0, evidence));
        bus.emit(AppEvent::EvidenceRemoved(0, 0, Uuid::new_v4()));

        bus.emit(AppEvent::RefreshStepList(0));
        bus.emit(AppEvent::RefreshDetailView(0, 0));
        bus.emit(AppEvent::QuizAnswerChecked(0, 0, 0, true));
        bus.emit(AppEvent::QuizExplanationViewed(0, 0, 0));
        bus.emit(AppEvent::QuizQuestionChanged(0, 0, 0));
        bus.emit(AppEvent::QuizStatisticsUpdated(0, 0));
        bus.emit(AppEvent::Error("error".to_string()));
        bus.emit(AppEvent::Info("info".to_string()));

        // If we get here, all events worked
        assert!(true);
    }
}
