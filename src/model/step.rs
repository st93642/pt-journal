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

/// Legacy tutorial data for backward compatibility during serde migration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LegacyTutorialData {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub description_notes: String,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

/// Content type for a step - either tutorial-based or quiz-based
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepContent {
    /// Traditional tutorial step with description, notes, evidence, and chat history
    Tutorial {
        description: String,
        description_notes: String,
        notes: String,
        evidence: Vec<Evidence>,
        #[serde(default)]
        chat_history: Vec<ChatMessage>,
    },
    /// Quiz-based learning step with questions and progress tracking
    Quiz { quiz_data: QuizStep },
}

impl Default for StepContent {
    fn default() -> Self {
        StepContent::Tutorial {
            description: String::new(),
            description_notes: String::new(),
            notes: String::new(),
            evidence: Vec::new(),
            chat_history: Vec::new(),
        }
    }
}

/// A step in a tutorial or quiz phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub id: Uuid,
    pub title: String,
    pub tags: Vec<String>,
    pub status: StepStatus,
    pub completed_at: Option<DateTime<Utc>>,

    /// The content of this step - either tutorial or quiz
    #[serde(default)]
    pub content: StepContent,

    // Legacy fields for backward compatibility with existing sessions
    // These are automatically migrated to StepContent::Tutorial on load
    #[serde(default, skip_serializing)]
    pub legacy: LegacyTutorialData,
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
            content: StepContent::Tutorial {
                description: description.clone(),
                description_notes: String::new(),
                notes: String::new(),
                evidence: Vec::new(),
                chat_history: Vec::new(),
            },
            // Legacy fields
            legacy: LegacyTutorialData {
                description,
                notes: String::new(),
                description_notes: String::new(),
                evidence: Vec::new(),
            },
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
            content: StepContent::Quiz { quiz_data },
            // Legacy fields
            legacy: LegacyTutorialData::default(),
        }
    }

    /// Migrate legacy step data to new content format
    pub fn migrate_from_legacy(&mut self) {
        // If content is default and we have legacy data, migrate it
        if matches!(self.content, StepContent::Tutorial { ref description, .. } if description.is_empty())
            && !self.legacy.description.is_empty()
        {
            self.content = StepContent::Tutorial {
                description: std::mem::take(&mut self.legacy.description),
                description_notes: std::mem::take(&mut self.legacy.description_notes),
                notes: std::mem::take(&mut self.legacy.notes),
                evidence: std::mem::take(&mut self.legacy.evidence),
                chat_history: Vec::new(), // New field, defaults to empty
            };
        }
    }

    /// Check if this is a tutorial step
    pub fn is_tutorial(&self) -> bool {
        matches!(self.content, StepContent::Tutorial { .. })
    }

    /// Check if this is a quiz step
    pub fn is_quiz(&self) -> bool {
        matches!(self.content, StepContent::Quiz { .. })
    }

    /// Get mutable reference to quiz content (panics if tutorial step)
    pub fn quiz_mut(&mut self) -> &mut QuizStep {
        match &mut self.content {
            StepContent::Quiz { quiz_data } => quiz_data,
            StepContent::Tutorial { .. } => {
                panic!("Attempted to access quiz content on tutorial step")
            }
        }
    }

    /// Get mutable reference to quiz content safely (returns None if tutorial step)
    pub fn quiz_mut_safe(&mut self) -> Option<&mut QuizStep> {
        match &mut self.content {
            StepContent::Quiz { quiz_data } => Some(quiz_data),
            StepContent::Tutorial { .. } => None,
        }
    }

    // Helper methods for backward compatibility with UI code

    /// Get description (for tutorial steps)
    pub fn get_description(&self) -> String {
        match &self.content {
            StepContent::Tutorial { description, .. } => description.clone(),
            StepContent::Quiz { .. } => String::new(),
        }
    }

    /// Get description notes (for tutorial steps)
    pub fn get_description_notes(&self) -> String {
        match &self.content {
            StepContent::Tutorial {
                description_notes, ..
            } => description_notes.clone(),
            StepContent::Quiz { .. } => String::new(),
        }
    }

    /// Get notes (for tutorial steps)
    pub fn get_notes(&self) -> String {
        match &self.content {
            StepContent::Tutorial { notes, .. } => notes.clone(),
            StepContent::Quiz { .. } => String::new(),
        }
    }

    /// Get evidence (for tutorial steps)
    pub fn get_evidence(&self) -> Vec<Evidence> {
        match &self.content {
            StepContent::Tutorial { evidence, .. } => evidence.clone(),
            StepContent::Quiz { .. } => Vec::new(),
        }
    }

    /// Set description notes (for tutorial steps)
    pub fn set_description_notes(&mut self, text: String) {
        if let StepContent::Tutorial {
            description_notes, ..
        } = &mut self.content
        {
            *description_notes = text;
        }
    }

    /// Set notes (for tutorial steps)
    pub fn set_notes(&mut self, text: String) {
        if let StepContent::Tutorial { notes, .. } = &mut self.content {
            *notes = text;
        }
    }

    /// Add evidence (for tutorial steps)
    pub fn add_evidence(&mut self, evidence: Evidence) {
        if let StepContent::Tutorial { evidence: ev, .. } = &mut self.content {
            ev.push(evidence);
        }
    }

    /// Get quiz step data (for quiz steps)
    pub fn get_quiz_step(&self) -> Option<&QuizStep> {
        match &self.content {
            StepContent::Quiz { quiz_data } => Some(quiz_data),
            StepContent::Tutorial { .. } => None,
        }
    }

    /// Remove evidence by ID (for tutorial steps)
    pub fn remove_evidence(&mut self, evidence_id: Uuid) {
        if let StepContent::Tutorial { evidence, .. } = &mut self.content {
            evidence.retain(|e| e.id != evidence_id);
        }
    }

    /// Update evidence position (for tutorial steps)
    pub fn update_evidence_position(&mut self, evidence_id: Uuid, x: f64, y: f64) -> bool {
        if let StepContent::Tutorial { evidence, .. } = &mut self.content {
            if let Some(ev) = evidence.iter_mut().find(|e| e.id == evidence_id) {
                ev.x = x;
                ev.y = y;
                return true;
            }
        }
        false
    }

    /// Get chat history (for tutorial steps)
    pub fn get_chat_history(&self) -> Vec<ChatMessage> {
        match &self.content {
            StepContent::Tutorial { chat_history, .. } => chat_history.clone(),
            StepContent::Quiz { .. } => Vec::new(),
        }
    }

    /// Add a chat message to history (for tutorial steps)
    pub fn add_chat_message(&mut self, message: ChatMessage) {
        if let StepContent::Tutorial { chat_history, .. } = &mut self.content {
            chat_history.push(message);
        }
    }

    /// Clear chat history (for tutorial steps)
    pub fn clear_chat_history(&mut self) {
        if let StepContent::Tutorial { chat_history, .. } = &mut self.content {
            chat_history.clear();
        }
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

