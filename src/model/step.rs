use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::chat::ChatMessage;
use super::quiz::QuizStep;

/// Status of a step in the tutorial/quiz process
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepStatus {
    Todo,
    InProgress,
    Done,
    Skipped,
}

/// A step in a tutorial or quiz phase with direct field access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub id: Uuid,
    pub title: String,
    pub tags: Vec<String>,
    pub status: StepStatus,
    pub completed_at: Option<DateTime<Utc>>,

    // Tutorial fields
    pub description: String,
    #[serde(default)]
    pub chat_history: Vec<ChatMessage>,
    #[serde(default)]
    pub related_tools: Vec<String>,

    // Quiz field (optional, present only for quiz steps)
    pub quiz_data: Option<QuizStep>,
}

impl Step {
    /// Create a new tutorial-based step
    pub fn new_tutorial(id: Uuid, title: String, description: String, tags: Vec<String>) -> Self {
        Self {
            id,
            title,
            tags,
            status: StepStatus::Todo,
            completed_at: None,
            description,
            chat_history: Vec::new(),
            related_tools: Vec::new(),
            quiz_data: None,
        }
    }

    /// Create a new tutorial-based step with related tools
    pub fn new_tutorial_with_tools(
        id: Uuid,
        title: String,
        description: String,
        tags: Vec<String>,
        related_tools: Vec<String>,
    ) -> Self {
        Self {
            id,
            title,
            tags,
            status: StepStatus::Todo,
            completed_at: None,
            description,
            chat_history: Vec::new(),
            related_tools,
            quiz_data: None,
        }
    }

    /// Create a new quiz-based step
    pub fn new_quiz(id: Uuid, title: String, tags: Vec<String>, quiz_data: QuizStep) -> Self {
        Self {
            id,
            title,
            tags,
            status: StepStatus::Todo,
            completed_at: None,
            description: String::new(),
            chat_history: Vec::new(),
            related_tools: Vec::new(),
            quiz_data: Some(quiz_data),
        }
    }

    /// Check if this is a tutorial step
    pub fn is_tutorial(&self) -> bool {
        self.quiz_data.is_none()
    }

    /// Check if this is a quiz step
    pub fn is_quiz(&self) -> bool {
        self.quiz_data.is_some()
    }

    /// Get mutable reference to quiz content (panics if tutorial step)
    pub fn quiz_mut(&mut self) -> &mut QuizStep {
        self.quiz_data
            .as_mut()
            .expect("Attempted to access quiz content on tutorial step")
    }

    /// Get mutable reference to quiz content safely (returns None if tutorial step)
    pub fn quiz_mut_safe(&mut self) -> Option<&mut QuizStep> {
        self.quiz_data.as_mut()
    }

    /// Add a chat message to history
    pub fn add_chat_message(&mut self, message: ChatMessage) {
        self.chat_history.push(message);
    }

    /// Clear chat history
    pub fn clear_chat_history(&mut self) {
        self.chat_history.clear();
    }
}

/// A phase containing multiple steps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase {
    pub id: Uuid,
    pub name: String,
    pub steps: Vec<Step>,
}
