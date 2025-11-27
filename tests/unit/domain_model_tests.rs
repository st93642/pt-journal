use assert_matches::assert_matches;
use chrono::Utc;
use uuid::Uuid;

use pt_journal::model::*;
use pt_journal::support::*;

#[cfg(test)]
mod tests {
    use super::*;

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

        let steps = vec![step1, step2];

        let phase = Phase {
            id: Uuid::new_v4(),
            name: "Test Phase".to_string(),
            steps,
        };

        assert_eq!(phase.steps.len(), 2);
        assert_eq!(phase.name, "Test Phase");
        assert_matches!(phase.steps[0].status, StepStatus::Todo);
        assert_matches!(phase.steps[1].status, StepStatus::Done);
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
        let mut ids = std::collections::HashSet::new();

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
    fn test_add_chat_message() {
        let mut step = Step::new_tutorial(
            Uuid::new_v4(),
            "Test".to_string(),
            "Test".to_string(),
            vec![],
        );

        assert_eq!(step.chat_history.clone().len(), 0);

        let msg1 = pt_journal::model::chat::ChatMessage::new(
            pt_journal::model::chat::ChatRole::User,
            "First message".to_string(),
        );
        step.add_chat_message(msg1);
        assert_eq!(step.chat_history.clone().len(), 1);

        let msg2 = pt_journal::model::chat::ChatMessage::new(
            pt_journal::model::chat::ChatRole::Assistant,
            "Response".to_string(),
        );
        step.add_chat_message(msg2);
        assert_eq!(step.chat_history.clone().len(), 2);

        let history = step.chat_history.clone();
        assert_eq!(history[0].content, "First message");
        assert!(matches!(
            history[0].role,
            pt_journal::model::chat::ChatRole::User
        ));
        assert_eq!(history[1].content, "Response");
        assert!(matches!(
            history[1].role,
            pt_journal::model::chat::ChatRole::Assistant
        ));
    }

    #[test]
    fn test_clear_chat_history() {
        let mut step = Step::new_tutorial(
            Uuid::new_v4(),
            "Test".to_string(),
            "Test".to_string(),
            vec![],
        );

        step.add_chat_message(pt_journal::model::chat::ChatMessage::new(
            pt_journal::model::chat::ChatRole::User,
            "Message 1".to_string(),
        ));
        step.add_chat_message(pt_journal::model::chat::ChatMessage::new(
            pt_journal::model::chat::ChatRole::User,
            "Message 2".to_string(),
        ));
        assert_eq!(step.chat_history.clone().len(), 2);

        step.clear_chat_history();
        assert_eq!(step.chat_history.clone().len(), 0);
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

    #[test]
    fn test_tutorial_structure_validation() {
        // This test validates that all tutorial modules follow the unified schema
        // and have properly structured steps
        match pt_journal::tutorials::validate_tutorial_structure() {
            Ok(()) => {
                // Validation passed - all tutorial modules are properly structured
            }
            Err(e) => {
                panic!("Tutorial structure validation failed: {}", e);
            }
        }
    }
}
