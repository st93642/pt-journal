use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

use crate::tutorials;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepStatus {
    Todo,
    InProgress,
    Done,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Evidence {
    pub id: Uuid,
    pub path: String,
    pub created_at: DateTime<Utc>,
    pub kind: String,
    pub x: f64,
    pub y: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub tags: Vec<String>,
    pub status: StepStatus,
    pub completed_at: Option<DateTime<Utc>>,
    pub notes: String,
    pub description_notes: String,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase {
    pub id: Uuid,
    pub name: String,
    pub steps: Vec<Step>,
    pub notes: String,
}

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
            phases: tutorials::load_tutorial_phases(),
            notes_global: String::new(),
        }
    }
}

#[derive(Debug)]
pub struct AppModel {
    pub session: Session,
    pub selected_phase: usize,
    pub selected_step: Option<usize>,
    pub current_path: Option<PathBuf>,
}

impl Default for AppModel {
    fn default() -> Self {
        Self {
            session: Session::default(),
            selected_phase: 0,
            selected_step: Some(0),
            current_path: None,
        }
    }
}

// UI messages were removed in favor of a direct GTK setup.

// UI wiring is provided by the Relm4 component in `ui.rs`.

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use assert_matches::assert_matches;

    #[test]
    fn test_step_status_variants() {
        // Test that all status variants work
        let todo_step = Step {
            id: Uuid::new_v4(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            tags: vec![],
            status: StepStatus::Todo,
            completed_at: None,
            notes: String::new(),
            description_notes: String::new(),
            evidence: vec![],
        };

        let in_progress_step = Step {
            status: StepStatus::InProgress,
            ..todo_step.clone()
        };

        let done_step = Step {
            status: StepStatus::Done,
            completed_at: Some(Utc::now()),
            ..todo_step.clone()
        };

        let skipped_step = Step {
            status: StepStatus::Skipped,
            ..todo_step.clone()
        };

        assert_matches!(todo_step.status, StepStatus::Todo);
        assert_matches!(in_progress_step.status, StepStatus::InProgress);
        assert_matches!(done_step.status, StepStatus::Done);
        assert_matches!(skipped_step.status, StepStatus::Skipped);
    }

    #[test]
    fn test_evidence_structure() {
        let evidence = Evidence {
            id: Uuid::new_v4(),
            path: "/path/to/file.png".to_string(),
            created_at: Utc::now(),
            kind: "screenshot".to_string(),
            x: 100.0,
            y: 200.0,
        };

        assert!(!evidence.path.is_empty());
        assert!(!evidence.kind.is_empty());
        assert!(evidence.created_at <= Utc::now());
        assert!(evidence.id != Uuid::nil());
    }

    #[test]
    fn test_phase_with_steps() {
        let steps = vec![
            Step {
                id: Uuid::new_v4(),
                title: "Step 1".to_string(),
                description: "Description 1".to_string(),
                tags: vec!["tag1".to_string()],
                status: StepStatus::Todo,
                completed_at: None,
                notes: String::new(),
                description_notes: String::new(),
                evidence: vec![],
            },
            Step {
                id: Uuid::new_v4(),
                title: "Step 2".to_string(),
                description: "Description 2".to_string(),
                tags: vec!["tag2".to_string()],
                status: StepStatus::Done,
                completed_at: Some(Utc::now()),
                notes: "Completed".to_string(),
                description_notes: String::new(),
                evidence: vec![],
            },
        ];

        let phase = Phase {
            id: Uuid::new_v4(),
            name: "Test Phase".to_string(),
            steps,
            notes: "Phase notes".to_string(),
        };

        assert_eq!(phase.steps.len(), 2);
        assert_eq!(phase.name, "Test Phase");
        assert_eq!(phase.notes, "Phase notes");
        assert_matches!(phase.steps[0].status, StepStatus::Todo);
        assert_matches!(phase.steps[1].status, StepStatus::Done);
    }

    #[test]
    fn test_session_with_phases() {
        let phase1 = Phase {
            id: Uuid::new_v4(),
            name: "Phase 1".to_string(),
            steps: vec![],
            notes: String::new(),
        };

        let phase2 = Phase {
            id: Uuid::new_v4(),
            name: "Phase 2".to_string(),
            steps: vec![],
            notes: String::new(),
        };

        let session = Session {
            id: Uuid::new_v4(),
            name: "Test Session".to_string(),
            created_at: Utc::now(),
            phases: vec![phase1, phase2],
            notes_global: "Global notes".to_string(),
        };

        assert_eq!(session.phases.len(), 2);
        assert_eq!(session.name, "Test Session");
        assert_eq!(session.notes_global, "Global notes");
        assert!(session.created_at <= Utc::now());
    }

    #[test]
    fn test_step_tags() {
        let step = Step {
            id: Uuid::new_v4(),
            title: "Tagged Step".to_string(),
            description: "Test".to_string(),
            tags: vec!["recon".to_string(), "passive".to_string(), "dns".to_string()],
            status: StepStatus::Todo,
            completed_at: None,
            notes: String::new(),
            description_notes: String::new(),
            evidence: vec![],
        };

        assert_eq!(step.tags.len(), 3);
        assert!(step.tags.contains(&"recon".to_string()));
        assert!(step.tags.contains(&"passive".to_string()));
        assert!(step.tags.contains(&"dns".to_string()));
    }

    #[test]
    fn test_unique_ids() {
        let mut ids = HashSet::new();

        // Create multiple steps and ensure IDs are unique
        for _ in 0..100 {
            let step = Step {
                id: Uuid::new_v4(),
                title: "Test".to_string(),
                description: "Test".to_string(),
                tags: vec![],
                status: StepStatus::Todo,
                completed_at: None,
                notes: String::new(),
                description_notes: String::new(),
                evidence: vec![],
            };
            assert!(ids.insert(step.id), "Duplicate ID generated: {}", step.id);
        }
    }

    #[test]
    fn test_step_description_notes() {
        let mut step = Step {
            id: Uuid::new_v4(),
            title: "Test Step".to_string(),
            description: "Test description".to_string(),
            tags: vec![],
            status: StepStatus::Todo,
            completed_at: None,
            notes: String::new(),
            description_notes: String::new(),
            evidence: vec![],
        };

        // Test description_notes updates
        step.description_notes = "User notes in description area".to_string();
        assert_eq!(step.description_notes, "User notes in description area");

        step.description_notes = "Updated description notes with more content".to_string();
        assert_eq!(step.description_notes, "Updated description notes with more content");

        // Test clearing description_notes
        step.description_notes.clear();
        assert!(step.description_notes.is_empty());
    }

    #[test]
    fn test_evidence_attachment() {
        let mut step = Step {
            id: Uuid::new_v4(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            tags: vec![],
            status: StepStatus::Todo,
            completed_at: None,
            notes: String::new(),
            description_notes: String::new(),
            evidence: vec![],
        };

        let evidence1 = Evidence {
            id: Uuid::new_v4(),
            path: "/path/to/screenshot1.png".to_string(),
            created_at: Utc::now(),
            kind: "screenshot".to_string(),
            x: 10.0,
            y: 20.0,
        };

        let evidence2 = Evidence {
            id: Uuid::new_v4(),
            path: "/path/to/log.txt".to_string(),
            created_at: Utc::now(),
            kind: "log".to_string(),
            x: 50.0,
            y: 60.0,
        };

        step.evidence.push(evidence1);
        step.evidence.push(evidence2);

        assert_eq!(step.evidence.len(), 2);
        assert_eq!(step.evidence[0].kind, "screenshot");
        assert_eq!(step.evidence[1].kind, "log");
    }
}


