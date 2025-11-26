use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::step::Phase;

/// Core session model holding phases and global notes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub phases: Vec<Phase>,
    pub notes_global: String,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            id: Uuid::new_v4(),
            name: "New Engagement".to_string(),
            created_at: Utc::now(),
            phases: crate::tutorials::load_tutorial_phases(),
            notes_global: String::new(),
        }
    }
}

