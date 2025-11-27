use crate::dispatcher::{AppMessage, SharedDispatcher};
use crate::model::{AppModel, ChatMessage, Evidence, StepStatus};
use log;
use std::cell::RefCell;
/// UI state management module
use std::rc::Rc;
use uuid::Uuid;

/// Shared app model reference for GTK
pub type SharedModel = Rc<RefCell<AppModel>>;

/// State manager for coordinating model updates and dispatcher events
pub struct StateManager {
    model: SharedModel,
    dispatcher: SharedDispatcher,
}

impl StateManager {
    pub fn new(model: SharedModel, dispatcher: SharedDispatcher) -> Self {
        Self { model, dispatcher }
    }

    /// Select a phase and update UI
    pub fn select_phase(&self, phase_idx: usize) {
        {
            let mut model = self.model.borrow_mut();
            model.set_selected_phase(phase_idx);
            model.set_selected_step(None);
        }
        self.dispatcher
            .borrow()
            .dispatch(&AppMessage::PhaseSelected(phase_idx));
        self.dispatcher
            .borrow()
            .dispatch(&AppMessage::RefreshStepList(phase_idx));
    }

    /// Select a step within current phase
    pub fn select_step(&self, step_idx: usize) {
        let phase_idx = self.model.borrow().selected_phase();
        {
            let mut model = self.model.borrow_mut();
            model.set_selected_step(Some(step_idx));
        }
        self.dispatcher
            .borrow()
            .dispatch(&AppMessage::StepSelected(step_idx));
        self.dispatcher
            .borrow()
            .dispatch(&AppMessage::RefreshDetailView(phase_idx, step_idx));
    }

    /// Helper to access a step mutably with validation and logging
    ///
    /// Returns Some(T) if the step exists, None if invalid indexes.
    /// Logs a warning on invalid indexes.
    fn with_step_mut<F, T>(&self, phase_idx: usize, step_idx: usize, f: F) -> Option<T>
    where
        F: FnOnce(&mut crate::model::Step) -> T,
    {
        let mut model = self.model.borrow_mut();
        if let Some(step) = model
            .session_mut()
            .phases
            .get_mut(phase_idx)
            .and_then(|p| p.steps.get_mut(step_idx))
        {
            Some(f(step))
        } else {
            log::warn!(
                "Invalid phase/step index: phase={}, step={}",
                phase_idx,
                step_idx
            );
            None
        }
    }

    /// Helper to access a step immutably with validation and logging
    ///
    /// Returns Some(T) if the step exists, None if invalid indexes.
    /// Logs a warning on invalid indexes.
    fn with_step<F, T>(&self, phase_idx: usize, step_idx: usize, f: F) -> Option<T>
    where
        F: FnOnce(&crate::model::Step) -> T,
    {
        let model = self.model.borrow();
        if let Some(step) = model
            .session()
            .phases
            .get(phase_idx)
            .and_then(|p| p.steps.get(step_idx))
        {
            Some(f(step))
        } else {
            log::warn!(
                "Invalid phase/step index: phase={}, step={}",
                phase_idx,
                step_idx
            );
            None
        }
    }

    /// Helper to access a phase mutably with validation and logging
    ///
    /// Returns Some(T) if the phase exists, None if invalid index.
    /// Logs a warning on invalid index.
    fn with_phase_mut<F, T>(&self, phase_idx: usize, f: F) -> Option<T>
    where
        F: FnOnce(&mut crate::model::Phase) -> T,
    {
        let mut model = self.model.borrow_mut();
        if let Some(phase) = model.session_mut().phases.get_mut(phase_idx) {
            Some(f(phase))
        } else {
            log::warn!("Invalid phase index: phase={}", phase_idx);
            None
        }
    }

    /// Update step status
    pub fn update_step_status(&self, phase_idx: usize, step_idx: usize, status: StepStatus) {
        if self
            .with_step_mut(phase_idx, step_idx, |step| {
                step.status = status.clone();
                if matches!(status, StepStatus::Done) {
                    step.completed_at = Some(chrono::Utc::now());
                } else {
                    step.completed_at = None;
                }
            })
            .is_some()
        {
            self.dispatcher
                .borrow()
                .dispatch(&AppMessage::StepStatusChanged(phase_idx, step_idx, status));
        }
    }

    /// Update step notes
    pub fn update_step_notes(&self, phase_idx: usize, step_idx: usize, notes: String) {
        if self
            .with_step_mut(phase_idx, step_idx, |step| step.set_notes(notes.clone()))
            .is_some()
        {
            self.dispatcher
                .borrow()
                .dispatch(&AppMessage::StepNotesUpdated(phase_idx, step_idx, notes));
        }
    }

    /// Update step description notes
    pub fn update_step_description_notes(&self, phase_idx: usize, step_idx: usize, notes: String) {
        if self
            .with_step_mut(phase_idx, step_idx, |step| {
                step.set_description_notes(notes.clone())
            })
            .is_some()
        {
            self.dispatcher
                .borrow()
                .dispatch(&AppMessage::StepDescriptionNotesUpdated(
                    phase_idx, step_idx, notes,
                ));
        }
    }

    /// Update phase notes
    pub fn update_phase_notes(&self, phase_idx: usize, notes: String) {
        if self
            .with_phase_mut(phase_idx, |phase| phase.notes = notes.clone())
            .is_some()
        {
            self.dispatcher
                .borrow()
                .dispatch(&AppMessage::PhaseNotesUpdated(phase_idx, notes));
        }
    }

    /// Update global notes
    pub fn update_global_notes(&self, notes: String) {
        {
            let mut model = self.model.borrow_mut();
            model.session_mut().notes_global = notes.clone();
        }
        self.dispatcher
            .borrow()
            .dispatch(&AppMessage::GlobalNotesUpdated(notes));
    }

    /// Add chat message to a step
    pub fn add_chat_message(&self, phase_idx: usize, step_idx: usize, message: ChatMessage) {
        if self
            .with_step_mut(phase_idx, step_idx, |step| {
                step.add_chat_message(message.clone())
            })
            .is_some()
        {
            self.dispatcher
                .borrow()
                .dispatch(&AppMessage::ChatMessageAdded(phase_idx, step_idx, message));
        }
    }

    /// Start a chat request
    pub fn start_chat_request(&self, phase_idx: usize, step_idx: usize) {
        self.dispatcher
            .borrow()
            .dispatch(&AppMessage::ChatRequestStarted(phase_idx, step_idx));
    }

    /// Complete a chat request
    pub fn complete_chat_request(&self, phase_idx: usize, step_idx: usize) {
        self.dispatcher
            .borrow()
            .dispatch(&AppMessage::ChatRequestCompleted(phase_idx, step_idx));
    }

    /// Fail a chat request
    pub fn fail_chat_request(&self, phase_idx: usize, step_idx: usize, error: String) {
        self.dispatcher
            .borrow()
            .dispatch(&AppMessage::ChatRequestFailed(phase_idx, step_idx, error));
    }

    /// Get chat history for a step
    pub fn get_chat_history(&self, phase_idx: usize, step_idx: usize) -> Vec<ChatMessage> {
        self.with_step(phase_idx, step_idx, |step| step.get_chat_history().clone())
            .unwrap_or_default()
    }

    /// Dispatch an error message
    pub fn dispatch_error(&self, error: String) {
        self.dispatcher.borrow().dispatch(&AppMessage::Error(error));
    }

    /// Add evidence to a step
    pub fn add_evidence(&self, phase_idx: usize, step_idx: usize, evidence: Evidence) {
        if self
            .with_step_mut(phase_idx, step_idx, |step| {
                step.add_evidence(evidence.clone())
            })
            .is_some()
        {
            self.dispatcher
                .borrow()
                .dispatch(&AppMessage::EvidenceAdded(phase_idx, step_idx, evidence));
        }
    }

    /// Remove evidence from a step
    pub fn remove_evidence(&self, phase_idx: usize, step_idx: usize, evidence_id: Uuid) {
        if self
            .with_step_mut(phase_idx, step_idx, |step| {
                step.remove_evidence(evidence_id)
            })
            .is_some()
        {
            self.dispatcher
                .borrow()
                .dispatch(&AppMessage::EvidenceRemoved(
                    phase_idx,
                    step_idx,
                    evidence_id,
                ));
        }
    }

    /// Get current phase index
    pub fn current_phase(&self) -> usize {
        self.model.borrow().selected_phase()
    }

    /// Get current step index
    pub fn current_step(&self) -> Option<usize> {
        self.model.borrow().selected_step()
    }

    /// Get immutable reference to model for reading
    pub fn model(&self) -> SharedModel {
        self.model.clone()
    }

    /// Get step summaries for a phase (for UI list display)
    pub fn get_step_summaries_for_phase(&self, phase_idx: usize) -> Vec<crate::model::StepSummary> {
        self.model.borrow().get_step_summaries_for_phase(phase_idx)
    }

    /// Toggle completion status of a step
    pub fn toggle_step_completion(&self, phase_idx: usize, step_idx: usize) {
        let current_status = self.with_step(phase_idx, step_idx, |step| step.status.clone());
        if let Some(status) = current_status {
            let new_status = match status {
                StepStatus::Done => StepStatus::InProgress,
                _ => StepStatus::Done,
            };
            self.update_step_status(phase_idx, step_idx, new_status);
        }
    }

    /// Get a snapshot of the currently active step
    pub fn get_active_step_snapshot(&self) -> Option<crate::model::ActiveStepSnapshot> {
        self.model.borrow().get_active_step_snapshot()
    }

    // ========== Quiz-specific State Management ==========

    /// Check an answer for a quiz question
    pub fn check_answer(
        &self,
        phase_idx: usize,
        step_idx: usize,
        question_idx: usize,
        answer_idx: usize,
    ) -> Option<bool> {
        let is_correct = self
            .with_step_mut(phase_idx, step_idx, |step| {
                if let Some(quiz_step) = step.quiz_mut_safe() {
                    if let Some(question) = quiz_step.questions.get(question_idx) {
                        // Check if the selected answer is correct
                        let correct = question
                            .answers
                            .get(answer_idx)
                            .map(|a| a.is_correct)
                            .unwrap_or(false);

                        // Update progress
                        if let Some(progress) = quiz_step.progress.get_mut(question_idx) {
                            let first_attempt = progress.attempts == 0;
                            progress.answered = true;
                            progress.selected_answer_index = Some(answer_idx);
                            progress.is_correct = Some(correct);
                            progress.attempts += 1;
                            progress.last_attempted = Some(chrono::Utc::now());

                            if first_attempt
                                && correct
                                && !progress.explanation_viewed_before_answer
                            {
                                progress.first_attempt_correct = true;
                            }
                        }

                        Some(correct)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .flatten();

        if let Some(correct) = is_correct {
            self.dispatcher
                .borrow()
                .dispatch(&AppMessage::QuizAnswerChecked(
                    phase_idx,
                    step_idx,
                    question_idx,
                    correct,
                ));
            self.dispatcher
                .borrow()
                .dispatch(&AppMessage::QuizStatisticsUpdated(phase_idx, step_idx));
        }

        is_correct
    }

    /// Mark that a user viewed the explanation before answering
    pub fn view_explanation(&self, phase_idx: usize, step_idx: usize, question_idx: usize) {
        if self
            .with_step_mut(phase_idx, step_idx, |step| {
                if let Some(quiz_step) = step.quiz_mut_safe() {
                    if let Some(progress) = quiz_step.progress.get_mut(question_idx) {
                        if !progress.answered {
                            progress.explanation_viewed_before_answer = true;
                        }
                    }
                }
            })
            .is_some()
        {
            self.dispatcher
                .borrow()
                .dispatch(&AppMessage::QuizExplanationViewed(
                    phase_idx,
                    step_idx,
                    question_idx,
                ));
        }
    }

    /// Change current question in quiz
    pub fn change_quiz_question(&self, phase_idx: usize, step_idx: usize, question_idx: usize) {
        self.dispatcher
            .borrow()
            .dispatch(&AppMessage::QuizQuestionChanged(
                phase_idx,
                step_idx,
                question_idx,
            ));
    }

    /// Set the active chat model and persist to config
    pub fn set_chat_model(&self, model_id: String) {
        {
            let mut model = self.model.borrow_mut();
            model.set_active_chat_model_id(model_id.clone());
            model.config_mut().chatbot.default_model_id = model_id.clone();
        }
        self.dispatcher
            .borrow()
            .dispatch(&AppMessage::ChatModelChanged(model_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatcher::create_dispatcher;
    use crate::model::{AppModel, ChatRole, QuizAnswer, QuizQuestion, QuizStep, Step};
    use std::sync::{Arc, Mutex};

    fn create_test_state() -> StateManager {
        let model = Rc::new(RefCell::new(AppModel::default()));
        let dispatcher = create_dispatcher();
        StateManager::new(model, dispatcher)
    }

    fn create_quiz_step_fixture() -> QuizStep {
        let question_one = QuizQuestion {
            id: uuid::Uuid::new_v4(),
            question_text: "Which option is correct?".to_string(),
            answers: vec![
                QuizAnswer {
                    text: "Wrong".to_string(),
                    is_correct: false,
                },
                QuizAnswer {
                    text: "Correct".to_string(),
                    is_correct: true,
                },
            ],
            explanation: "Second option is correct.".to_string(),
            domain: "Test Domain".to_string(),
            subdomain: "1.1".to_string(),
        };

        let question_two = QuizQuestion {
            id: uuid::Uuid::new_v4(),
            question_text: "Pick the true statement.".to_string(),
            answers: vec![
                QuizAnswer {
                    text: "True".to_string(),
                    is_correct: true,
                },
                QuizAnswer {
                    text: "False".to_string(),
                    is_correct: false,
                },
            ],
            explanation: "First answer is true.".to_string(),
            domain: "Test Domain".to_string(),
            subdomain: "1.2".to_string(),
        };

        QuizStep::new(
            uuid::Uuid::new_v4(),
            "Test Quiz".to_string(),
            "Test Domain".to_string(),
            vec![question_one, question_two],
        )
    }

    fn create_test_state_with_quiz() -> StateManager {
        let model = Rc::new(RefCell::new(AppModel::default()));
        let dispatcher = create_dispatcher();

        // Replace first step of first phase with a quiz step
        {
            let mut model_mut = model.borrow_mut();
            if let Some(phase) = model_mut.session_mut().phases.get_mut(0) {
                if phase.steps.is_empty() {
                    phase.steps.push(Step::new_quiz(
                        uuid::Uuid::new_v4(),
                        "Quiz Step".to_string(),
                        vec!["quiz".to_string()],
                        create_quiz_step_fixture(),
                    ));
                } else {
                    phase.steps[0] = Step::new_quiz(
                        uuid::Uuid::new_v4(),
                        "Quiz Step".to_string(),
                        vec!["quiz".to_string()],
                        create_quiz_step_fixture(),
                    );
                }
            }
        }

        StateManager::new(model, dispatcher)
    }

    #[test]
    fn test_select_phase() {
        let state = create_test_state();
        let message_received = Arc::new(Mutex::new(false));
        let msg_clone = message_received.clone();

        state.dispatcher.borrow_mut().register(
            None,
            "test",
            Box::new(move |msg| {
                if matches!(msg, AppMessage::PhaseSelected(1)) {
                    *msg_clone.lock().unwrap() = true;
                }
            }),
        );

        state.select_phase(1);
        assert_eq!(state.current_phase(), 1);
        assert!(state.current_step().is_none());
        assert!(*message_received.lock().unwrap());
    }

    #[test]
    fn test_select_step() {
        let state = create_test_state();
        let message_received = Arc::new(Mutex::new(false));
        let msg_clone = message_received.clone();

        state.dispatcher.borrow_mut().register(
            None,
            "test",
            Box::new(move |msg| {
                if matches!(msg, AppMessage::StepSelected(2)) {
                    *msg_clone.lock().unwrap() = true;
                }
            }),
        );

        state.select_step(2);
        assert_eq!(state.current_step(), Some(2));
        assert!(*message_received.lock().unwrap());
    }

    #[test]
    fn test_update_step_status() {
        let state = create_test_state();
        let messages = Arc::new(Mutex::new(Vec::new()));
        let msg_clone = messages.clone();

        state.dispatcher.borrow_mut().register(
            None,
            "test",
            Box::new(move |msg| {
                msg_clone.lock().unwrap().push(format!("{:?}", msg));
            }),
        );

        state.update_step_status(0, 0, StepStatus::Done);

        let status = {
            let model = state.model.borrow();
            model.session().phases[0].steps[0].status.clone()
        };
        assert!(matches!(status, StepStatus::Done));

        let msgs = messages.lock().unwrap();
        assert!(msgs.iter().any(|m| m.contains("StepStatusChanged")));
    }

    #[test]
    fn test_update_step_notes() {
        let state = create_test_state();
        state.update_step_notes(0, 0, "Test notes".to_string());

        let notes = {
            let model = state.model.borrow();
            model.session().phases[0].steps[0].get_notes()
        };
        assert_eq!(notes, "Test notes");
    }

    #[test_log::test]
    fn test_update_step_notes_invalid_index() {
        let state = create_test_state();
        state.update_step_notes(99, 99, "notes".to_string());
        // Log should contain warning
    }

    #[test]
    fn test_update_description_notes() {
        let state = create_test_state();
        state.update_step_description_notes(0, 0, "Description notes".to_string());

        let notes = {
            let model = state.model.borrow();
            model.session().phases[0].steps[0].get_description_notes()
        };
        assert_eq!(notes, "Description notes");
    }

    #[test]
    fn test_evidence_operations() {
        let state = create_test_state();
        let evidence = Evidence {
            id: uuid::Uuid::new_v4(),
            path: "/test/path.png".to_string(),
            created_at: chrono::Utc::now(),
            kind: "screenshot".to_string(),
            x: 100.0,
            y: 200.0,
        };

        let evidence_id = evidence.id;
        state.add_evidence(0, 0, evidence);

        let count = {
            let model = state.model.borrow();
            model.session().phases[0].steps[0].get_evidence().len()
        };
        assert_eq!(count, 1);

        state.remove_evidence(0, 0, evidence_id);

        let count = {
            let model = state.model.borrow();
            model.session().phases[0].steps[0].get_evidence().len()
        };
        assert_eq!(count, 0);
    }

    #[test]
    fn test_chat_operations() {
        let state = create_test_state();
        let messages = Arc::new(Mutex::new(Vec::new()));
        let msg_clone = messages.clone();

        state.dispatcher.borrow_mut().register(
            None,
            "test",
            Box::new(move |msg| {
                msg_clone.lock().unwrap().push(format!("{:?}", msg));
            }),
        );

        // Test adding chat message
        let message = ChatMessage::new(ChatRole::User, "Hello".to_string());
        state.add_chat_message(0, 0, message.clone());

        let history = state.get_chat_history(0, 0);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].content, "Hello");

        // Test chat request events
        state.start_chat_request(0, 0);
        state.complete_chat_request(0, 0);
        state.fail_chat_request(0, 0, "Test error".to_string());

        let msgs = messages.lock().unwrap();
        assert!(msgs.iter().any(|m| m.contains("ChatMessageAdded")));
        assert!(msgs.iter().any(|m| m.contains("ChatRequestStarted")));
        assert!(msgs.iter().any(|m| m.contains("ChatRequestCompleted")));
        assert!(msgs.iter().any(|m| m.contains("ChatRequestFailed")));
    }

    #[test]
    fn test_set_chat_model() {
        let state = create_test_state();
        let messages = Arc::new(Mutex::new(Vec::new()));
        let msg_clone = messages.clone();

        state.dispatcher.borrow_mut().register(
            None,
            "test",
            Box::new(move |msg| {
                msg_clone.lock().unwrap().push(format!("{:?}", msg));
            }),
        );

        state.set_chat_model("mistral:7b".to_string());

        let model_id = {
            let model = state.model.borrow();
            model.get_active_chat_model_id()
        };
        assert_eq!(model_id, "mistral:7b");

        let msgs = messages.lock().unwrap();
        assert!(msgs.iter().any(|m| m.contains("ChatModelChanged")));
    }

    #[test]
    fn test_check_answer_correct_first_attempt() {
        let state = create_test_state_with_quiz();
        let messages = Arc::new(Mutex::new(Vec::new()));
        let msg_clone = messages.clone();

        state.dispatcher.borrow_mut().register(
            None,
            "test",
            Box::new(move |msg| {
                msg_clone.lock().unwrap().push(format!("{:?}", msg));
            }),
        );

        // Check correct answer (index 1 for first question)
        let result = state.check_answer(0, 0, 0, 1);
        assert_eq!(result, Some(true));

        // Verify progress was updated
        let model = state.model.borrow();
        let step = &model.session().phases[0].steps[0];
        if let Some(quiz_data) = step.get_quiz_step() {
            let progress = &quiz_data.progress[0];
            assert!(progress.answered);
            assert_eq!(progress.selected_answer_index, Some(1));
            assert_eq!(progress.is_correct, Some(true));
            assert_eq!(progress.attempts, 1);
            assert!(progress.first_attempt_correct);
        } else {
            panic!("Expected quiz step");
        }

        // Verify dispatcher messages
        let msgs = messages.lock().unwrap();
        assert!(msgs.iter().any(|m| m.contains("QuizAnswerChecked")));
        assert!(msgs.iter().any(|m| m.contains("QuizStatisticsUpdated")));
    }

    #[test]
    fn test_check_answer_incorrect() {
        let state = create_test_state_with_quiz();

        // Check incorrect answer (index 0 for first question)
        let result = state.check_answer(0, 0, 0, 0);
        assert_eq!(result, Some(false));

        // Verify progress
        let model = state.model.borrow();
        let step = &model.session().phases[0].steps[0];
        if let Some(quiz_data) = step.get_quiz_step() {
            let progress = &quiz_data.progress[0];
            assert!(progress.answered);
            assert_eq!(progress.is_correct, Some(false));
            assert!(!progress.first_attempt_correct);
        } else {
            panic!("Expected quiz step");
        }
    }

    #[test]
    fn test_check_answer_multiple_attempts() {
        let state = create_test_state_with_quiz();

        // First attempt - wrong
        state.check_answer(0, 0, 0, 0);

        // Second attempt - correct
        let result = state.check_answer(0, 0, 0, 1);
        assert_eq!(result, Some(true));

        // Verify attempts count and first_attempt_correct flag
        let model = state.model.borrow();
        let step = &model.session().phases[0].steps[0];
        if let Some(quiz_data) = step.get_quiz_step() {
            let progress = &quiz_data.progress[0];
            assert_eq!(progress.attempts, 2);
            assert_eq!(progress.is_correct, Some(true)); // Last attempt was correct
            assert!(!progress.first_attempt_correct); // But not on first attempt
        } else {
            panic!("Expected quiz step");
        }
    }

    #[test]
    fn test_check_answer_invalid_question_index() {
        let state = create_test_state_with_quiz();

        // Try to check answer for nonexistent question
        let result = state.check_answer(0, 0, 99, 0);
        assert_eq!(result, None);
    }

    #[test]
    fn test_check_answer_on_tutorial_step_returns_none() {
        let state = create_test_state();

        // Try to check answer on a tutorial step
        let result = state.check_answer(0, 0, 0, 0);
        assert_eq!(result, None);
    }

    #[test]
    fn test_view_explanation_before_answering() {
        let state = create_test_state_with_quiz();
        let messages = Arc::new(Mutex::new(Vec::new()));
        let msg_clone = messages.clone();

        state.dispatcher.borrow_mut().register(
            None,
            "test",
            Box::new(move |msg| {
                msg_clone.lock().unwrap().push(format!("{:?}", msg));
            }),
        );

        // View explanation before answering
        state.view_explanation(0, 0, 0);

        // Verify flag was set
        {
            let model = state.model.borrow();
            let step = &model.session().phases[0].steps[0];
            if let Some(quiz_data) = step.get_quiz_step() {
                let progress = &quiz_data.progress[0];
                assert!(progress.explanation_viewed_before_answer);
            } else {
                panic!("Expected quiz step");
            }
        }

        // Verify dispatcher message
        {
            let msgs = messages.lock().unwrap();
            assert!(msgs.iter().any(|m| m.contains("QuizExplanationViewed")));
        }

        // Now answer correctly
        state.check_answer(0, 0, 0, 1);

        // Verify that first_attempt_correct remains false and awards_points returns false
        {
            let model = state.model.borrow();
            let step = &model.session().phases[0].steps[0];
            if let Some(quiz_data) = step.get_quiz_step() {
                let progress = &quiz_data.progress[0];
                assert!(!progress.first_attempt_correct);
                assert!(!progress.awards_points()); // Should not award points
            } else {
                panic!("Expected quiz step");
            }
        }
    }

    #[test]
    fn test_view_explanation_after_answering_does_not_set_flag() {
        let state = create_test_state_with_quiz();

        // Answer first
        state.check_answer(0, 0, 0, 1);

        // Then view explanation
        state.view_explanation(0, 0, 0);

        // Verify flag was NOT set (because already answered)
        let model = state.model.borrow();
        let step = &model.session().phases[0].steps[0];
        if let Some(quiz_data) = step.get_quiz_step() {
            let progress = &quiz_data.progress[0];
            assert!(!progress.explanation_viewed_before_answer);
        } else {
            panic!("Expected quiz step");
        }
    }

    #[test]
    fn test_view_explanation_invalid_question_index() {
        let state = create_test_state_with_quiz();

        // Should not panic on invalid index
        state.view_explanation(0, 0, 99);
    }

    #[test]
    fn test_change_quiz_question() {
        let state = create_test_state_with_quiz();
        let messages = Arc::new(Mutex::new(Vec::new()));
        let msg_clone = messages.clone();

        state.dispatcher.borrow_mut().register(
            None,
            "test",
            Box::new(move |msg| {
                msg_clone.lock().unwrap().push(format!("{:?}", msg));
            }),
        );

        // Change to second question
        state.change_quiz_question(0, 0, 1);

        // Verify dispatcher message
        let msgs = messages.lock().unwrap();
        assert!(msgs.iter().any(|m| m.contains("QuizQuestionChanged")));
    }

    #[test]
    fn test_change_quiz_question_invalid_index() {
        let state = create_test_state_with_quiz();

        // Should not panic on invalid index, just dispatches message
        state.change_quiz_question(0, 0, 99);
    }
}
