use chrono::Utc;
use uuid::Uuid;

use crate::model::*;

/// Create a legacy step with data for migration testing
pub fn legacy_step_with_data() -> Step {
    Step {
        id: Uuid::new_v4(),
        title: "Legacy Step".to_string(),
        tags: vec!["legacy".to_string()],
        status: StepStatus::Todo,
        completed_at: None,
        content: StepContent::default(),
        legacy: LegacyTutorialData {
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
        },
    }
}

/// Create a quiz step fixture for testing
pub fn quiz_step_fixture() -> QuizStep {
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

/// Create a test state manager for UI tests
pub fn create_test_state() -> crate::ui::state::StateManager {
    let model = std::rc::Rc::new(std::cell::RefCell::new(AppModel::default()));
    let dispatcher = crate::dispatcher::create_dispatcher();
    crate::ui::state::StateManager::new(model, dispatcher)
}

/// Create a test state with quiz for quiz-specific tests
pub fn create_test_state_with_quiz() -> crate::ui::state::StateManager {
    let model = std::rc::Rc::new(std::cell::RefCell::new(AppModel::default()));
    let dispatcher = crate::dispatcher::create_dispatcher();

    // Replace first step of first phase with a quiz step
    {
        let mut model_mut = model.borrow_mut();
        if let Some(phase) = model_mut.session_mut().phases.get_mut(0) {
            if phase.steps.is_empty() {
                phase.steps.push(Step::new_quiz(
                    Uuid::new_v4(),
                    "Quiz Step".to_string(),
                    vec!["quiz".to_string()],
                    quiz_step_fixture(),
                ));
            } else {
                phase.steps[0] = Step::new_quiz(
                    Uuid::new_v4(),
                    "Quiz Step".to_string(),
                    vec!["quiz".to_string()],
                    quiz_step_fixture(),
                );
            }
        }
    }

    crate::ui::state::StateManager::new(model, dispatcher)
}
