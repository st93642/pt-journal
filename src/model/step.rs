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

/// Evidence attached to a tutorial step
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Evidence {
    pub id: Uuid,
    pub path: String,
    pub created_at: DateTime<Utc>,
    pub kind: String,
    pub x: f64,
    pub y: f64,
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
    pub description_notes: String,
    pub notes: String,
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub chat_history: Vec<ChatMessage>,

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
            description_notes: String::new(),
            notes: String::new(),
            evidence: Vec::new(),
            chat_history: Vec::new(),
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
            description_notes: String::new(),
            notes: String::new(),
            evidence: Vec::new(),
            chat_history: Vec::new(),
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

    /// Get description (for backward compatibility)
    pub fn get_description(&self) -> String {
        self.description.clone()
    }

    /// Get description notes (for backward compatibility)
    pub fn get_description_notes(&self) -> String {
        self.description_notes.clone()
    }

    /// Get notes (for backward compatibility)
    pub fn get_notes(&self) -> String {
        self.notes.clone()
    }

    /// Get evidence (for backward compatibility)
    pub fn get_evidence(&self) -> Vec<Evidence> {
        self.evidence.clone()
    }

    /// Set description notes (for backward compatibility)
    pub fn set_description_notes(&mut self, text: String) {
        self.description_notes = text;
    }

    /// Set notes (for backward compatibility)
    pub fn set_notes(&mut self, text: String) {
        self.notes = text;
    }

    /// Add evidence (for backward compatibility)
    pub fn add_evidence(&mut self, evidence: Evidence) {
        self.evidence.push(evidence);
    }

    /// Get quiz step data (for backward compatibility)
    pub fn get_quiz_step(&self) -> Option<&QuizStep> {
        self.quiz_data.as_ref()
    }

    /// Remove evidence by ID
    pub fn remove_evidence(&mut self, evidence_id: Uuid) {
        self.evidence.retain(|e| e.id != evidence_id);
    }

    /// Update evidence position
    pub fn update_evidence_position(&mut self, evidence_id: Uuid, x: f64, y: f64) -> bool {
        if let Some(ev) = self.evidence.iter_mut().find(|e| e.id == evidence_id) {
            ev.x = x;
            ev.y = y;
            return true;
        }
        false
    }

    /// Get chat history (for backward compatibility)
    pub fn get_chat_history(&self) -> Vec<ChatMessage> {
        self.chat_history.clone()
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
    pub notes: String,
}
