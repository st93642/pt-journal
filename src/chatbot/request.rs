use crate::config::ModelProfile;
use crate::model::ChatMessage;

/// Context about the current step for chat requests
#[derive(Debug, Clone)]
pub struct StepContext {
    pub phase_name: String,
    pub step_title: String,
    pub step_description: String,
    pub step_status: String,
    pub quiz_status: Option<String>,
}

impl Default for StepContext {
    fn default() -> Self {
        Self {
            phase_name: "Test Phase".to_string(),
            step_title: "Test Step".to_string(),
            step_description: "Test Description".to_string(),
            step_status: "Todo".to_string(),
            quiz_status: None,
        }
    }
}

/// Bundle of all information needed for a chat request
#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub step_context: StepContext,
    pub history: Vec<ChatMessage>,
    pub user_prompt: String,
    pub model_profile: ModelProfile,
}

impl ChatRequest {
    pub fn new(
        step_context: StepContext,
        history: Vec<ChatMessage>,
        user_prompt: String,
        model_profile: ModelProfile,
    ) -> Self {
        Self {
            step_context,
            history,
            user_prompt,
            model_profile,
        }
    }
}
