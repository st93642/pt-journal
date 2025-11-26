/*****************************************************************************/
/*                                                                           */
/*  model.rs                                             TTTTTTTT SSSSSSS II */
/*                                                          TT    SS      II */
/*  By: st93642@students.tsi.lv                             TT    SSSSSSS II */
/*                                                          TT         SS II */
/*  Created: Nov 21 2025 23:42 st93642                      TT    SSSSSSS II */
/*  Updated: Nov 25 2025 16:34 st93642                                       */
/*                                                                           */
/*   Transport and Telecommunication Institute - Riga, Latvia                */
/*                       https://tsi.lv                                      */
/*****************************************************************************/

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

use crate::tutorials;

// ============================================================================
// Chatbot Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChatRole {
    User,
    Assistant,
}

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

// ============================================================================
// Tutorial/Penetration Testing Models
// ============================================================================

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

// ============================================================================
// Quiz System Models (CompTIA Security+ and future quiz-based learning)
// ============================================================================

/// Multiple choice answer option
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuizAnswer {
    pub text: String,
    pub is_correct: bool,
}

/// Single quiz question
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuizQuestion {
    pub id: Uuid,
    pub question_text: String,
    pub answers: Vec<QuizAnswer>, // Typically 4 options (A, B, C, D)
    pub explanation: String,
    pub domain: String,    // e.g., "1.0 General Security Concepts"
    pub subdomain: String, // e.g., "1.1 Compare and contrast various security controls"
}

/// User's progress on a single question
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionProgress {
    pub question_id: Uuid,
    pub answered: bool,
    pub selected_answer_index: Option<usize>,
    pub is_correct: Option<bool>,
    pub explanation_viewed_before_answer: bool,
    pub first_attempt_correct: bool, // For scoring - true only if correct on first try
    pub attempts: u32,
    pub last_attempted: Option<DateTime<Utc>>,
}

impl QuestionProgress {
    pub fn new(question_id: Uuid) -> Self {
        Self {
            question_id,
            answered: false,
            selected_answer_index: None,
            is_correct: None,
            explanation_viewed_before_answer: false,
            first_attempt_correct: false,
            attempts: 0,
            last_attempted: None,
        }
    }

    /// Determines if this question should award points (correct on first attempt without viewing explanation)
    pub fn awards_points(&self) -> bool {
        self.first_attempt_correct && !self.explanation_viewed_before_answer
    }
}

/// Quiz step containing multiple questions from a specific domain/subdomain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuizStep {
    pub id: Uuid,
    pub title: String, // e.g., "Domain 1.1 - Security Controls"
    pub domain: String,
    pub questions: Vec<QuizQuestion>,
    pub progress: Vec<QuestionProgress>,
}

impl QuizStep {
    pub fn new(id: Uuid, title: String, domain: String, questions: Vec<QuizQuestion>) -> Self {
        let progress = questions
            .iter()
            .map(|q| QuestionProgress::new(q.id))
            .collect();

        Self {
            id,
            title,
            domain,
            questions,
            progress,
        }
    }

    /// Get statistics for this quiz step
    pub fn statistics(&self) -> QuizStatistics {
        let total_questions = self.questions.len();
        let answered = self.progress.iter().filter(|p| p.answered).count();
        let correct = self
            .progress
            .iter()
            .filter(|p| p.is_correct == Some(true))
            .count();
        let incorrect = self
            .progress
            .iter()
            .filter(|p| p.is_correct == Some(false))
            .count();
        let first_attempt_correct = self.progress.iter().filter(|p| p.awards_points()).count();

        let score_percentage = if total_questions > 0 {
            (first_attempt_correct as f32 / total_questions as f32) * 100.0
        } else {
            0.0
        };

        QuizStatistics {
            total_questions,
            answered,
            correct,
            incorrect,
            first_attempt_correct,
            score_percentage,
        }
    }
}

/// Statistics for quiz performance
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct QuizStatistics {
    pub total_questions: usize,
    pub answered: usize,
    pub correct: usize,
    pub incorrect: usize,
    pub first_attempt_correct: usize, // Questions answered correctly on first try without viewing explanation
    pub score_percentage: f32,
}

// ============================================================================
// Unified Step Model (Tutorial or Quiz)
// ============================================================================

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
    pub description: String,
    #[serde(default, skip_serializing)]
    pub notes: String,
    #[serde(default, skip_serializing)]
    pub description_notes: String,
    #[serde(default, skip_serializing)]
    pub evidence: Vec<Evidence>,
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
                description,
                description_notes: String::new(),
                notes: String::new(),
                evidence: Vec::new(),
                chat_history: Vec::new(),
            },
            // Legacy fields
            description: String::new(),
            notes: String::new(),
            description_notes: String::new(),
            evidence: Vec::new(),
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
            description: String::new(),
            notes: String::new(),
            description_notes: String::new(),
            evidence: Vec::new(),
        }
    }

    /// Migrate legacy step data to new content format
    pub fn migrate_from_legacy(&mut self) {
        // If content is default and we have legacy data, migrate it
        if matches!(self.content, StepContent::Tutorial { ref description, .. } if description.is_empty())
            && !self.description.is_empty()
        {
            self.content = StepContent::Tutorial {
                description: std::mem::take(&mut self.description),
                description_notes: std::mem::take(&mut self.description_notes),
                notes: std::mem::take(&mut self.notes),
                evidence: std::mem::take(&mut self.evidence),
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

    /// Get mutable reference to tutorial content (panics if quiz step)
    pub fn tutorial_mut(&mut self) -> &mut StepContent {
        match &mut self.content {
            StepContent::Tutorial { .. } => &mut self.content,
            StepContent::Quiz { .. } => panic!("Attempted to access tutorial content on quiz step"),
        }
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
    pub config: crate::config::AppConfig,
    pub active_chat_model_id: String,
}

impl Default for AppModel {
    fn default() -> Self {
        let config = crate::config::AppConfig::load().unwrap_or_default();
        let active_chat_model_id = config.chatbot.default_model_id.clone();
        Self {
            session: Session::default(),
            selected_phase: 0,
            selected_step: Some(0),
            current_path: None,
            config,
            active_chat_model_id,
        }
    }
}

impl AppModel {
    pub fn get_active_chat_model_id(&self) -> String {
        self.active_chat_model_id.clone()
    }

    pub fn set_active_chat_model_id(&mut self, model_id: String) {
        self.active_chat_model_id = model_id;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use std::collections::HashSet;

    fn legacy_step_with_data() -> Step {
        Step {
            id: Uuid::new_v4(),
            title: "Legacy Step".to_string(),
            tags: vec!["legacy".to_string()],
            status: StepStatus::Todo,
            completed_at: None,
            content: StepContent::default(),
            description: "Legacy description".to_string(),
            notes: "Legacy notes".to_string(),
            description_notes: "Legacy description notes".to_string(),
            evidence: vec![Evidence {
                id: Uuid::new_v4(),
                path: "/tmp/evidence.png".to_string(),
                created_at: Utc::now(),
                kind: "screenshot".to_string(),
                x: 5.0,
                y: 10.0,
            }],
        }
    }

    fn quiz_step_fixture() -> QuizStep {
        let question_one = QuizQuestion {
            id: Uuid::new_v4(),
            question_text: "Which option is correct first?".to_string(),
            answers: vec![
                QuizAnswer {
                    text: "Incorrect".to_string(),
                    is_correct: false,
                },
                QuizAnswer {
                    text: "Correct".to_string(),
                    is_correct: true,
                },
            ],
            explanation: "Second option is correct.".to_string(),
            domain: "Fixture Domain".to_string(),
            subdomain: "1.1".to_string(),
        };

        let question_two = QuizQuestion {
            id: Uuid::new_v4(),
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
                QuizAnswer {
                    text: "Also false".to_string(),
                    is_correct: false,
                },
            ],
            explanation: "First answer is correct.".to_string(),
            domain: "Fixture Domain".to_string(),
            subdomain: "1.2".to_string(),
        };

        QuizStep::new(
            Uuid::new_v4(),
            "Quiz Fixture".to_string(),
            "Fixture Domain".to_string(),
            vec![question_one, question_two],
        )
    }

    #[test]
    fn test_step_status_variants() {
        // Test that all status variants work
        let todo_step = Step::new_tutorial(
            Uuid::new_v4(),
            "Test".to_string(),
            "Test description".to_string(),
            vec![],
        );

        let mut in_progress_step = todo_step.clone();
        in_progress_step.status = StepStatus::InProgress;

        let mut done_step = todo_step.clone();
        done_step.status = StepStatus::Done;
        done_step.completed_at = Some(Utc::now());

        let mut skipped_step = todo_step.clone();
        skipped_step.status = StepStatus::Skipped;

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
        let step1 = Step::new_tutorial(
            Uuid::new_v4(),
            "Step 1".to_string(),
            "Description 1".to_string(),
            vec!["tag1".to_string()],
        );

        let mut step2 = Step::new_tutorial(
            Uuid::new_v4(),
            "Step 2".to_string(),
            "Description 2".to_string(),
            vec!["tag2".to_string()],
        );
        step2.status = StepStatus::Done;
        step2.completed_at = Some(Utc::now());
        if let StepContent::Tutorial { notes, .. } = &mut step2.content {
            *notes = "Completed".to_string();
        }

        let steps = vec![step1, step2];

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
        let step = Step::new_tutorial(
            Uuid::new_v4(),
            "Tagged Step".to_string(),
            "Test".to_string(),
            vec![
                "recon".to_string(),
                "passive".to_string(),
                "dns".to_string(),
            ],
        );

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
            let step = Step::new_tutorial(
                Uuid::new_v4(),
                "Test".to_string(),
                "Test".to_string(),
                vec![],
            );
            assert!(ids.insert(step.id), "Duplicate ID generated: {}", step.id);
        }
    }

    #[test]
    fn test_step_description_notes() {
        let mut step = Step::new_tutorial(
            Uuid::new_v4(),
            "Test Step".to_string(),
            "Test description".to_string(),
            vec![],
        );

        // Test description_notes updates
        if let StepContent::Tutorial {
            description_notes, ..
        } = &mut step.content
        {
            *description_notes = "User notes in description area".to_string();
            assert_eq!(*description_notes, "User notes in description area");

            *description_notes = "Updated description notes with more content".to_string();
            assert_eq!(
                *description_notes,
                "Updated description notes with more content"
            );

            // Test clearing description_notes
            description_notes.clear();
            assert!(description_notes.is_empty());
        }
    }

    #[test]
    fn test_evidence_attachment() {
        let mut step = Step::new_tutorial(
            Uuid::new_v4(),
            "Test".to_string(),
            "Test".to_string(),
            vec![],
        );

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

        if let StepContent::Tutorial { evidence, .. } = &mut step.content {
            evidence.push(evidence1);
            evidence.push(evidence2);

            assert_eq!(evidence.len(), 2);
            assert_eq!(evidence[0].kind, "screenshot");
            assert_eq!(evidence[1].kind, "log");
        }
    }

    #[test]
    fn test_migrate_from_legacy() {
        let mut step = legacy_step_with_data();

        assert_eq!(step.description, "Legacy description");
        assert_eq!(step.notes, "Legacy notes");
        assert_eq!(step.description_notes, "Legacy description notes");
        assert_eq!(step.evidence.len(), 1);

        step.migrate_from_legacy();

        assert_eq!(step.get_description(), "Legacy description");
        assert_eq!(step.get_notes(), "Legacy notes");
        assert_eq!(step.get_description_notes(), "Legacy description notes");
        assert_eq!(step.get_evidence().len(), 1);

        // Legacy fields should now be empty
        assert!(step.description.is_empty());
        assert!(step.notes.is_empty());
        assert!(step.description_notes.is_empty());
        assert!(step.evidence.is_empty());
    }

    #[test]
    fn test_migrate_from_legacy_does_not_override_existing_content() {
        let mut step = Step::new_tutorial(
            Uuid::new_v4(),
            "Test".to_string(),
            "New description".to_string(),
            vec![],
        );
        step.description = "Legacy description".to_string();

        step.migrate_from_legacy();

        // Should not override existing content
        assert_eq!(step.get_description(), "New description");
    }

    #[test]
    fn test_remove_evidence() {
        let mut step = Step::new_tutorial(
            Uuid::new_v4(),
            "Test".to_string(),
            "Test".to_string(),
            vec![],
        );

        let ev1_id = Uuid::new_v4();
        let ev2_id = Uuid::new_v4();

        step.add_evidence(Evidence {
            id: ev1_id,
            path: "/tmp/ev1.png".to_string(),
            created_at: Utc::now(),
            kind: "screenshot".to_string(),
            x: 0.0,
            y: 0.0,
        });

        step.add_evidence(Evidence {
            id: ev2_id,
            path: "/tmp/ev2.png".to_string(),
            created_at: Utc::now(),
            kind: "screenshot".to_string(),
            x: 10.0,
            y: 10.0,
        });

        assert_eq!(step.get_evidence().len(), 2);

        step.remove_evidence(ev1_id);
        assert_eq!(step.get_evidence().len(), 1);
        assert_eq!(step.get_evidence()[0].id, ev2_id);

        step.remove_evidence(ev2_id);
        assert_eq!(step.get_evidence().len(), 0);
    }

    #[test]
    fn test_remove_evidence_nonexistent() {
        let mut step = Step::new_tutorial(
            Uuid::new_v4(),
            "Test".to_string(),
            "Test".to_string(),
            vec![],
        );

        let ev_id = Uuid::new_v4();
        step.add_evidence(Evidence {
            id: ev_id,
            path: "/tmp/ev.png".to_string(),
            created_at: Utc::now(),
            kind: "screenshot".to_string(),
            x: 0.0,
            y: 0.0,
        });

        let nonexistent_id = Uuid::new_v4();
        step.remove_evidence(nonexistent_id);
        assert_eq!(step.get_evidence().len(), 1);
    }

    #[test]
    fn test_update_evidence_position() {
        let mut step = Step::new_tutorial(
            Uuid::new_v4(),
            "Test".to_string(),
            "Test".to_string(),
            vec![],
        );

        let ev_id = Uuid::new_v4();
        step.add_evidence(Evidence {
            id: ev_id,
            path: "/tmp/ev.png".to_string(),
            created_at: Utc::now(),
            kind: "screenshot".to_string(),
            x: 5.0,
            y: 10.0,
        });

        let updated = step.update_evidence_position(ev_id, 50.0, 100.0);
        assert!(updated);

        let evidence = step.get_evidence();
        assert_eq!(evidence[0].x, 50.0);
        assert_eq!(evidence[0].y, 100.0);
    }

    #[test]
    fn test_update_evidence_position_nonexistent() {
        let mut step = Step::new_tutorial(
            Uuid::new_v4(),
            "Test".to_string(),
            "Test".to_string(),
            vec![],
        );

        let nonexistent_id = Uuid::new_v4();
        let updated = step.update_evidence_position(nonexistent_id, 50.0, 100.0);
        assert!(!updated);
    }

    #[test]
    fn test_add_chat_message() {
        let mut step = Step::new_tutorial(
            Uuid::new_v4(),
            "Test".to_string(),
            "Test".to_string(),
            vec![],
        );

        assert_eq!(step.get_chat_history().len(), 0);

        let msg1 = ChatMessage::new(ChatRole::User, "First message".to_string());
        step.add_chat_message(msg1);
        assert_eq!(step.get_chat_history().len(), 1);

        let msg2 = ChatMessage::new(ChatRole::Assistant, "Response".to_string());
        step.add_chat_message(msg2);
        assert_eq!(step.get_chat_history().len(), 2);

        let history = step.get_chat_history();
        assert_eq!(history[0].content, "First message");
        assert!(matches!(history[0].role, ChatRole::User));
        assert_eq!(history[1].content, "Response");
        assert!(matches!(history[1].role, ChatRole::Assistant));
    }

    #[test]
    fn test_clear_chat_history() {
        let mut step = Step::new_tutorial(
            Uuid::new_v4(),
            "Test".to_string(),
            "Test".to_string(),
            vec![],
        );

        step.add_chat_message(ChatMessage::new(ChatRole::User, "Message 1".to_string()));
        step.add_chat_message(ChatMessage::new(ChatRole::User, "Message 2".to_string()));
        assert_eq!(step.get_chat_history().len(), 2);

        step.clear_chat_history();
        assert_eq!(step.get_chat_history().len(), 0);
    }

    #[test]
    fn test_quiz_step_statistics_all_unanswered() {
        let quiz_step = quiz_step_fixture();
        let stats = quiz_step.statistics();

        assert_eq!(stats.total_questions, 2);
        assert_eq!(stats.answered, 0);
        assert_eq!(stats.correct, 0);
        assert_eq!(stats.incorrect, 0);
        assert_eq!(stats.first_attempt_correct, 0);
        assert_eq!(stats.score_percentage, 0.0);
    }

    #[test]
    fn test_quiz_step_statistics_some_answered() {
        let mut quiz_step = quiz_step_fixture();

        // Answer first question correctly on first try
        if let Some(progress) = quiz_step.progress.get_mut(0) {
            progress.answered = true;
            progress.is_correct = Some(true);
            progress.attempts = 1;
            progress.first_attempt_correct = true;
            progress.explanation_viewed_before_answer = false;
        }

        // Answer second question incorrectly
        if let Some(progress) = quiz_step.progress.get_mut(1) {
            progress.answered = true;
            progress.is_correct = Some(false);
            progress.attempts = 1;
        }

        let stats = quiz_step.statistics();
        assert_eq!(stats.total_questions, 2);
        assert_eq!(stats.answered, 2);
        assert_eq!(stats.correct, 1);
        assert_eq!(stats.incorrect, 1);
        assert_eq!(stats.first_attempt_correct, 1);
        assert_eq!(stats.score_percentage, 50.0);
    }

    #[test]
    fn test_quiz_step_statistics_multiple_attempts() {
        let mut quiz_step = quiz_step_fixture();

        // Answer first question correctly after multiple attempts
        if let Some(progress) = quiz_step.progress.get_mut(0) {
            progress.answered = true;
            progress.is_correct = Some(true);
            progress.attempts = 3;
            progress.first_attempt_correct = false; // Wasn't correct on first try
        }

        let stats = quiz_step.statistics();
        assert_eq!(stats.correct, 1);
        assert_eq!(stats.first_attempt_correct, 0); // Doesn't count for score
        assert_eq!(stats.score_percentage, 0.0); // Only first-attempt correct counts
    }

    #[test]
    fn test_question_progress_awards_points_first_attempt_correct() {
        let mut progress = QuestionProgress::new(Uuid::new_v4());
        progress.first_attempt_correct = true;
        progress.explanation_viewed_before_answer = false;

        assert!(progress.awards_points());
    }

    #[test]
    fn test_question_progress_no_points_if_explanation_viewed() {
        let mut progress = QuestionProgress::new(Uuid::new_v4());
        progress.first_attempt_correct = true;
        progress.explanation_viewed_before_answer = true;

        assert!(!progress.awards_points());
    }

    #[test]
    fn test_question_progress_no_points_if_not_first_attempt_correct() {
        let mut progress = QuestionProgress::new(Uuid::new_v4());
        progress.first_attempt_correct = false;
        progress.explanation_viewed_before_answer = false;

        assert!(!progress.awards_points());
    }

    #[test]
    fn test_quiz_step_statistics_with_explanation_viewed() {
        let mut quiz_step = quiz_step_fixture();

        // Answer correctly but viewed explanation first
        if let Some(progress) = quiz_step.progress.get_mut(0) {
            progress.answered = true;
            progress.is_correct = Some(true);
            progress.attempts = 1;
            progress.first_attempt_correct = true;
            progress.explanation_viewed_before_answer = true; // Viewed explanation
        }

        let stats = quiz_step.statistics();
        assert_eq!(stats.correct, 1);
        assert_eq!(stats.first_attempt_correct, 0); // Doesn't count because of explanation
        assert_eq!(stats.score_percentage, 0.0);
    }
}
