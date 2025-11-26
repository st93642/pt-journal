//! Tests for UI controller logic.
//!
//! These tests focus on the business logic of controllers without requiring GTK.
//! They test helper functions and data transformations.

use pt_journal::chatbot::StepContext;
use pt_journal::model::{AppModel, ChatMessage, ChatRole, Evidence, Phase, QuizAnswer, QuizQuestion, QuizStep, Step, StepStatus};
use std::cell::RefCell;
use std::rc::Rc;
use uuid::Uuid;
use chrono;

/// Test the build_step_context helper function
#[test]
fn test_build_step_context() {
    // Create a test model with sample data
    let mut model = AppModel::default();
    model.set_selected_phase(0);
    model.set_selected_step(Some(0));

    // Clear existing phases and add our test phase
    model.session_mut().phases.clear();
    let mut phase = Phase {
        id: Uuid::new_v4(),
        name: "Test Phase".to_string(),
        steps: vec![],
        notes: String::new(),
    };
    let mut step = Step::new_tutorial(
        Uuid::new_v4(),
        "Test Step".to_string(),
        "Test Description".to_string(),
        vec![],
    );
    step.status = StepStatus::InProgress;

    // Add notes and evidence
    step.set_notes("Test note 1\nTest note 2".to_string());
    step.add_evidence(Evidence {
        id: Uuid::new_v4(),
        path: "Test evidence".to_string(),
        created_at: chrono::Utc::now(),
        kind: "test".to_string(),
        x: 0.0,
        y: 0.0,
    });

    // Add chat history
    step.add_chat_message(ChatMessage::new(ChatRole::User, "Hello".to_string()));
    step.add_chat_message(ChatMessage::new(ChatRole::Assistant, "Hi there!".to_string()));

    phase.steps.push(step);
    model.session_mut().phases.push(phase);

    let model_rc = Rc::new(RefCell::new(model));

    // Test the build_step_context logic (extracted from chat controller)
    let model_borrow = model_rc.borrow();
    let phase_idx = model_borrow.selected_phase();
    let step_idx = model_borrow.selected_step().unwrap_or(0);
    let _config = model_borrow.config().chatbot.clone();
    let phase = &model_borrow.session().phases[phase_idx];
    let step = &phase.steps[step_idx];
    let notes = step.get_notes();
    let evidence = step.get_evidence();
    let quiz_status = if step.is_quiz() {
        step.get_quiz_step().map(|q| {
            format!(
                "{}/{} correct",
                q.statistics().correct,
                q.statistics().total_questions
            )
        })
    } else {
        None
    };
    let step_ctx = StepContext {
        phase_name: phase.name.clone(),
        step_title: step.title.clone(),
        step_description: step.get_description(),
        step_status: match step.status {
            StepStatus::Done => "Done".to_string(),
            StepStatus::InProgress => "In Progress".to_string(),
            StepStatus::Todo => "Todo".to_string(),
            StepStatus::Skipped => "Skipped".to_string(),
        },
        notes_count: notes.lines().count(),
        evidence_count: evidence.len(),
        quiz_status,
    };
    let history = step.get_chat_history().clone();

    // Verify the context was built correctly
    assert_eq!(step_ctx.phase_name, "Test Phase");
    assert_eq!(step_ctx.step_title, "Test Step");
    assert_eq!(step_ctx.step_description, "Test Description");
    assert_eq!(step_ctx.step_status, "In Progress");
    assert_eq!(step_ctx.notes_count, 2);
    assert_eq!(step_ctx.evidence_count, 1);
    assert!(step_ctx.quiz_status.is_none()); // Not a quiz step
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].role, ChatRole::User);
    assert_eq!(history[0].content, "Hello");
    assert_eq!(history[1].role, ChatRole::Assistant);
    assert_eq!(history[1].content, "Hi there!");
}

/// Test that step context handles quiz steps correctly
#[test]
fn test_build_step_context_with_quiz() {
    let mut model = AppModel::default();
    model.set_selected_phase(0);
    model.set_selected_step(Some(0));

    // Clear existing phases and add our test phase
    model.session_mut().phases.clear();
    let mut phase = Phase {
        id: Uuid::new_v4(),
        name: "Quiz Phase".to_string(),
        steps: vec![],
        notes: String::new(),
    };

    // Create a simple quiz step
    let question1 = QuizQuestion {
        id: Uuid::new_v4(),
        question_text: "What is 2+2?".to_string(),
        answers: vec![
            QuizAnswer { text: "3".to_string(), is_correct: false },
            QuizAnswer { text: "4".to_string(), is_correct: true },
        ],
        explanation: "Basic math".to_string(),
        domain: "Math".to_string(),
        subdomain: "Addition".to_string(),
    };
    let question2 = QuizQuestion {
        id: Uuid::new_v4(),
        question_text: "What is the capital of France?".to_string(),
        answers: vec![
            QuizAnswer { text: "London".to_string(), is_correct: false },
            QuizAnswer { text: "Paris".to_string(), is_correct: true },
            QuizAnswer { text: "Berlin".to_string(), is_correct: false },
        ],
        explanation: "Geography".to_string(),
        domain: "Geography".to_string(),
        subdomain: "Capitals".to_string(),
    };
    let quiz_step_data = QuizStep::new(
        Uuid::new_v4(),
        "Quiz Test".to_string(),
        "Test Domain".to_string(),
        vec![question1, question2],
    );

    let mut step = Step::new_quiz(
        Uuid::new_v4(),
        "Quiz Step".to_string(),
        vec![],
        quiz_step_data,
    );
    step.status = StepStatus::InProgress;

    // Simulate answering one question correctly
    if let Some(quiz) = step.quiz_mut_safe() {
        if let Some(progress) = quiz.progress.get_mut(0) {
            progress.answered = true;
            progress.is_correct = Some(true);
            progress.attempts = 1;
            progress.first_attempt_correct = true;
            progress.explanation_viewed_before_answer = false;
        }
    }
    phase.steps.push(step);
    model.session_mut().phases.push(phase);

    let model_rc = Rc::new(RefCell::new(model));

    // Test the build_step_context logic
    let model_borrow = model_rc.borrow();
    let phase_idx = model_borrow.selected_phase();
    let step_idx = model_borrow.selected_step().unwrap_or(0);
    let step = &model_borrow.session().phases[phase_idx].steps[step_idx];
    let quiz_status = if step.is_quiz() {
        step.get_quiz_step().map(|q| {
            format!(
                "{}/{} correct",
                q.statistics().correct,
                q.statistics().total_questions
            )
        })
    } else {
        None
    };

    // Verify quiz status
    assert_eq!(quiz_status, Some("1/2 correct".to_string()));
}

/// Test that the model filtering logic works correctly
#[test]
fn test_model_filtering_logic() {
    // Simulate the logic from the pull_all_models.sh script
    let available_models = vec![
        ("gpt-oss:20b".to_string(), 13_780_162_412u64), // 13.7GB
        ("gemini-3-pro-preview".to_string(), 0u64),     // 0 bytes
        ("deepseek-v3.1:671b".to_string(), 688_586_727_753u64), // 688GB
    ];

    let max_size = 21_474_836_480u64; // 20GB in bytes
    let filtered: Vec<_> = available_models
        .into_iter()
        .filter(|(_, size)| *size <= max_size)
        .map(|(name, _)| name)
        .collect();

    assert_eq!(filtered.len(), 2);
    assert!(filtered.contains(&"gpt-oss:20b".to_string()));
    assert!(filtered.contains(&"gemini-3-pro-preview".to_string()));
    assert!(!filtered.contains(&"deepseek-v3.1:671b".to_string()));
}