use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Role of a chat message participant
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChatRole {
    System,
    User,
    Assistant,
}

/// A single chat message with role and content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
    pub timestamp: DateTime<Utc>,
}

impl ChatMessage {
    pub fn new(role: ChatRole, content: String) -> Self {
        Self {
            role,
            content,
            timestamp: Utc::now(),
        }
    }
}
