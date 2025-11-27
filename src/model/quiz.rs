use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
