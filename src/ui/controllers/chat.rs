//! Chat controller for handling chatbot interactions.
//!
//! This controller manages the chat panel, including model selection,
//! sending messages, and handling responses from the chatbot service.

use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{gdk, EventControllerKey};
use std::rc::Rc;
use std::sync::mpsc;

use crate::chatbot::{ChatService, StepContext};
use crate::model::ChatMessage;
use crate::ui::detail_panel::DetailPanel;
use crate::ui::state::StateManager;

/// Chat controller that encapsulates chat-related UI logic.
pub struct ChatController {
    detail_panel: Rc<DetailPanel>,
    state: Rc<StateManager>,
}

impl ChatController {
    /// Create a new chat controller.
    pub fn new(detail_panel: Rc<DetailPanel>, state: Rc<StateManager>) -> Self {
        Self {
            detail_panel,
            state,
        }
    }

    /// Bind all chat-related event handlers.
    pub fn bind(&self) {
        // Initially populate model combo with empty list (will be updated asynchronously)
        self.detail_panel.chat_panel().populate_models(&[]);

        // Asynchronously update model combo with available Ollama models
        self.bind_async_model_population();

        // Model combo change handler
        self.bind_model_selection();

        // Send button handler
        self.bind_send_button();

        // Enter key handler for input
        self.bind_enter_key();
    }

    /// Bind asynchronous model population.
    fn bind_async_model_population(&self) {
        let chat_panel = Rc::new(self.detail_panel.chat_panel().clone());
        let state = self.state.clone();

        glib::idle_add_local_once(move || {
            let config = {
                let model_rc = state.model();
                let model = model_rc.borrow();
                model.config().chatbot.clone()
            };

            let service = ChatService::new(config);
            match service.list_available_models() {
                Ok(available_models) => {
                    // Get all configured models from config as fallback
                    let configured_models = {
                        let model_rc = state.model();
                        let model = model_rc.borrow();
                        model.config().chatbot.models.clone()
                    };

                    // Create display names for models
                    let mut models: Vec<(String, String)> = Vec::new();

                    // First, add models that are available from providers
                    for model_id in available_models {
                        let display_name = configured_models
                            .iter()
                            .find(|m| m.id == model_id)
                            .map(|m| m.display_name.clone())
                            .unwrap_or_else(|| model_id.clone());
                        models.push((model_id, display_name));
                    }

                    // Then, add configured models that weren't found in available models
                    // (useful for remote providers that can't enumerate models)
                    for configured_model in configured_models {
                        if !models.iter().any(|(id, _)| id == &configured_model.id) {
                            models.push((
                                configured_model.id.clone(),
                                configured_model.display_name.clone(),
                            ));
                        }
                    }

                    if !models.is_empty() {
                        // Update UI with available models
                        chat_panel.populate_models(&models);

                        // Try to set the active model again (it might be available now)
                        let active_model_id = {
                            let model_rc = state.model();
                            let model = model_rc.borrow();
                            model.get_active_chat_model_id()
                        };
                        if !chat_panel.set_active_model(&active_model_id) {
                            // Active model not available, set to first available model
                            if let Some(first_model) = models.first() {
                                let model_rc = state.model();
                                let mut model_mut = model_rc.borrow_mut();
                                model_mut.set_active_chat_model_id(first_model.0.clone());
                            }
                        }
                    } else {
                        // No models available - show error
                        chat_panel.show_error(
                            "No models available. Please configure at least one model provider.",
                        );
                    }
                }
                Err(e) => {
                    // Failed to get available models - show error with provider-specific message
                    let error_msg = if e.to_string().contains("OpenAI") {
                        format!(
                            "OpenAI provider error: {}. Please check your API key configuration.",
                            e
                        )
                    } else if e.to_string().contains("Azure OpenAI") {
                        format!("Azure OpenAI provider error: {}. Please check your API key, endpoint, and deployment configuration.", e)
                    } else {
                        format!("Failed to connect to model providers: {}", e)
                    };
                    chat_panel.show_error(&error_msg);
                }
            }
        });
    }

    /// Bind model selection change handler.
    fn bind_model_selection(&self) {
        let model_combo = self.detail_panel.chat_panel().model_combo.clone();
        let state = self.state.clone();
        let chat_panel = self.detail_panel.chat_panel().clone();

        model_combo.connect_selected_item_notify(move |_| {
            if let Some(model_id) = chat_panel.get_active_model_id() {
                state.set_chat_model(model_id);
            }
        });
    }

    /// Bind the send button handler.
    fn bind_send_button(&self) {
        let send_button = self.detail_panel.chat_panel().send_button.clone();
        let chat_panel = Rc::new(self.detail_panel.chat_panel().clone());
        let state = self.state.clone();

        send_button.connect_clicked(move |_| {
            let input_text = chat_panel.take_input();
            if !input_text.is_empty() {
                Self::handle_send_message(chat_panel.clone(), state.clone(), input_text);
            }
        });
    }

    /// Bind the Enter key handler for the input text view.
    fn bind_enter_key(&self) {
        let input_textview = self.detail_panel.chat_panel().input_textview.clone();
        let send_button = self.detail_panel.chat_panel().send_button.clone();

        let key_controller = EventControllerKey::new();
        let send_button_clone = send_button.clone();
        key_controller.connect_key_pressed(move |_, keyval, _, _| {
            if keyval == gdk::Key::Return || keyval == gdk::Key::KP_Enter {
                // Check if Shift is not pressed (to allow multi-line input with Shift+Enter)
                if !gdk::ModifierType::SHIFT_MASK.contains(gdk::ModifierType::SHIFT_MASK) {
                    send_button_clone.emit_clicked();
                    glib::Propagation::Stop
                } else {
                    glib::Propagation::Proceed
                }
            } else {
                glib::Propagation::Proceed
            }
        });
        input_textview.add_controller(key_controller);
    }

    /// Handle sending a chat message.
    fn handle_send_message(
        chat_panel: Rc<crate::ui::chat_panel::ChatPanel>,
        state: Rc<StateManager>,
        input_text: String,
    ) {
        let (phase_idx, step_idx, config, step_ctx, history) = Self::build_step_context(&state);

        // Add user message immediately
        let user_message = ChatMessage::new(crate::model::ChatRole::User, input_text.clone());
        state.add_chat_message(phase_idx, step_idx, user_message.clone());

        // Start request
        state.start_chat_request(phase_idx, step_idx);

        // Show loading
        chat_panel.show_loading();

        // Include user message in history for context
        let mut history_with_user = history;
        history_with_user.push(user_message);

        // Use channel to communicate result from thread to main thread
        let (tx, rx) = mpsc::channel();

        // Spawn thread for chatbot
        Self::spawn_request_thread(config, step_ctx, history_with_user, input_text, tx);

        // Poll the receiver in idle callback
        Self::bind_response_polling(chat_panel.clone(), state.clone(), phase_idx, step_idx, rx);
    }

    /// Build the step context for the current step.
    fn build_step_context(
        state: &Rc<StateManager>,
    ) -> (
        usize,
        usize,
        crate::config::ChatbotConfig,
        StepContext,
        Vec<ChatMessage>,
    ) {
        let phase_idx = state.current_phase();
        let step_idx = state.current_step().unwrap_or(0);
        let config = state.model().borrow().config().chatbot.clone();

        if let Some(snapshot) = state.get_active_step_snapshot() {
            let quiz_status = snapshot.quiz_data.as_ref().map(|q| {
                format!(
                    "{}/{} correct",
                    q.statistics().correct,
                    q.statistics().total_questions
                )
            });

            let step_ctx = StepContext {
                phase_name: state
                    .model()
                    .borrow()
                    .current_phase()
                    .map(|p| p.name.clone())
                    .unwrap_or_default(),
                step_title: snapshot.title,
                step_description: snapshot.description,
                step_status: match snapshot.status {
                    crate::model::StepStatus::Done => "Done".to_string(),
                    crate::model::StepStatus::InProgress => "In Progress".to_string(),
                    crate::model::StepStatus::Todo => "Todo".to_string(),
                    crate::model::StepStatus::Skipped => "Skipped".to_string(),
                },
                quiz_status,
            };
            let history = snapshot.chat_history;
            (phase_idx, step_idx, config, step_ctx, history)
        } else {
            // Fallback if no active step
            let step_ctx = StepContext {
                phase_name: String::new(),
                step_title: String::new(),
                step_description: String::new(),
                step_status: "Unknown".to_string(),
                quiz_status: None,
            };
            (phase_idx, step_idx, config, step_ctx, Vec::new())
        }
    }

    /// Spawn a background thread to handle the chatbot request.
    fn spawn_request_thread(
        config: crate::config::ChatbotConfig,
        step_ctx: StepContext,
        history: Vec<ChatMessage>,
        input_text: String,
        tx: mpsc::Sender<Result<ChatMessage, String>>,
    ) {
        std::thread::spawn(move || {
            let chat_service = ChatService::new(config);
            let result = chat_service.send_message(&step_ctx, &history, &input_text);
            let result_string = result.map_err(|e| e.to_string());
            let _ = tx.send(result_string);
        });
    }

    /// Bind the response polling mechanism.
    fn bind_response_polling(
        chat_panel: Rc<crate::ui::chat_panel::ChatPanel>,
        state: Rc<StateManager>,
        phase_idx: usize,
        step_idx: usize,
        rx: mpsc::Receiver<Result<ChatMessage, String>>,
    ) {
        glib::idle_add_local(move || {
            match rx.try_recv() {
                Ok(result) => {
                    match result {
                        Ok(response) => {
                            state.add_chat_message(phase_idx, step_idx, response);
                            state.complete_chat_request(phase_idx, step_idx);
                            chat_panel.hide_loading();
                        }
                        Err(e) => {
                            let error_msg = format!("Chatbot error: {}", e);
                            chat_panel.show_error(&error_msg);
                            state.fail_chat_request(phase_idx, step_idx, error_msg.clone());
                            state.dispatch_error(error_msg);
                            chat_panel.hide_loading();
                        }
                    }
                    glib::ControlFlow::Break
                }
                Err(mpsc::TryRecvError::Empty) => {
                    // Not ready yet, continue polling
                    glib::ControlFlow::Continue
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    // Thread panicked or something, show error
                    let error_msg = "Chatbot thread disconnected".to_string();
                    chat_panel.show_error(&error_msg);
                    state.fail_chat_request(phase_idx, step_idx, error_msg.clone());
                    state.dispatch_error(error_msg);
                    chat_panel.hide_loading();
                    glib::ControlFlow::Break
                }
            }
        });
    }
}
