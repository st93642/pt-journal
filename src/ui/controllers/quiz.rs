//! Quiz controller for handling quiz interactions.
//!
//! This controller manages all quiz-related UI interactions including
//! checking answers, viewing explanations, and navigation between questions.

use gtk4::prelude::*;
use std::rc::Rc;

use crate::model::StepStatus;
use crate::ui::detail_panel::DetailPanel;
use crate::ui::state::StateManager;

/// Quiz controller that encapsulates quiz-related UI logic.
pub struct QuizController {
    detail_panel: Rc<DetailPanel>,
    state: Rc<StateManager>,
}

impl QuizController {
    /// Create a new quiz controller.
    pub fn new(detail_panel: Rc<DetailPanel>, state: Rc<StateManager>) -> Self {
        Self {
            detail_panel,
            state,
        }
    }

    /// Bind all quiz-related event handlers.
    pub fn bind(&self) {
        self.bind_check_answer();
        self.bind_view_explanation();
        self.bind_navigation();
        self.bind_finish();
    }

    /// Bind the check answer button handler.
    fn bind_check_answer(&self) {
        let check_button = self.detail_panel.quiz_widget().check_button.clone();
        let state = self.state.clone();
        let panel = self.detail_panel.clone();

        check_button.connect_clicked(move |_| {
            let (phase_idx, step_idx, question_idx, selected_answer) = {
                let model_rc = state.model();
                let model_borrow = model_rc.borrow();
                (
                    model_borrow.selected_phase(),
                    model_borrow.selected_step(),
                    panel.quiz_widget().current_question(),
                    panel.quiz_widget().get_selected_answer(),
                )
            };

            if let (Some(step_idx), Some(answer_idx)) = (step_idx, selected_answer) {
                // Use state manager to check answer (dispatches events)
                let is_correct = state.check_answer(phase_idx, step_idx, question_idx, answer_idx);

                if let Some(correct) = is_correct {
                    // Get explanation and quiz step for UI update
                    let (explanation, quiz_step_opt) = {
                        let model_rc = state.model();
                        let model = model_rc.borrow();
                        let step = model
                            .session()
                            .phases
                            .get(phase_idx)
                            .and_then(|p| p.steps.get(step_idx));

                        if let Some(step) = step {
                            if let Some(quiz_step) = step.quiz_data.as_ref() {
                                let explanation = quiz_step
                                    .questions
                                    .get(question_idx)
                                    .map(|q| q.explanation.clone())
                                    .unwrap_or_default();
                                (explanation, Some(quiz_step.clone()))
                            } else {
                                (String::new(), None)
                            }
                        } else {
                            (String::new(), None)
                        }
                    };

                    // Show explanation with result
                    panel
                        .quiz_widget()
                        .show_explanation(&explanation, Some(correct));

                    // Update statistics
                    if let Some(quiz_step) = quiz_step_opt {
                        panel.quiz_widget().update_statistics(&quiz_step);
                    }
                }
            }
        });
    }

    /// Bind the view explanation button handler.
    fn bind_view_explanation(&self) {
        let view_explanation_button = self
            .detail_panel
            .quiz_widget()
            .view_explanation_button
            .clone();
        let state = self.state.clone();
        let panel = self.detail_panel.clone();

        view_explanation_button.connect_clicked(move |_| {
            let (phase_idx, step_idx, question_idx) = {
                let model_rc = state.model();
                let model_borrow = model_rc.borrow();
                (
                    model_borrow.selected_phase(),
                    model_borrow.selected_step(),
                    panel.quiz_widget().current_question(),
                )
            };

            if let Some(step_idx) = step_idx {
                // Use state manager to mark explanation viewed (dispatches event)
                state.view_explanation(phase_idx, step_idx, question_idx);

                // Get explanation and show it
                let explanation_opt = {
                    let model_rc = state.model();
                    let model_borrow = model_rc.borrow();
                    model_borrow
                        .session()
                        .phases
                        .get(phase_idx)
                        .and_then(|phase| phase.steps.get(step_idx))
                        .and_then(|step| step.quiz_data.as_ref())
                        .and_then(|quiz_step| quiz_step.questions.get(question_idx))
                        .map(|q| q.explanation.clone())
                };

                if let Some(explanation) = explanation_opt {
                    panel.quiz_widget().show_explanation(&explanation, None);
                }
            }
        });
    }

    /// Bind the previous/next navigation buttons.
    fn bind_navigation(&self) {
        self.bind_prev_button();
        self.bind_next_button();
    }

    /// Bind the previous button handler.
    fn bind_prev_button(&self) {
        let prev_button = self.detail_panel.quiz_widget().prev_button.clone();
        let state = self.state.clone();
        let panel = self.detail_panel.clone();

        prev_button.connect_clicked(move |_| {
            let current_idx = panel.quiz_widget().current_question();
            if current_idx > 0 {
                let new_idx = current_idx - 1;
                panel.quiz_widget().set_current_question(new_idx);

                // Dispatch quiz question changed event
                let (phase_idx, step_idx) = {
                    let model_rc = state.model();
                    let model_borrow = model_rc.borrow();
                    (model_borrow.selected_phase(), model_borrow.selected_step())
                };
                if let Some(step_idx) = step_idx {
                    state.change_quiz_question(phase_idx, step_idx, new_idx);
                }

                // Refresh the display
                let quiz_step_opt = {
                    let model_rc = state.model();
                    let model_borrow = model_rc.borrow();
                    model_borrow
                        .session()
                        .phases
                        .get(model_borrow.selected_phase())
                        .and_then(|phase| {
                            model_borrow
                                .selected_step()
                                .and_then(|sidx| phase.steps.get(sidx))
                        })
                        .and_then(|step| step.quiz_data.as_ref().cloned())
                };

                if let Some(quiz_step) = quiz_step_opt {
                    panel.quiz_widget().refresh_current_question(&quiz_step);
                }
            }
        });
    }

    /// Bind the next button handler.
    fn bind_next_button(&self) {
        let next_button = self.detail_panel.quiz_widget().next_button.clone();
        let state = self.state.clone();
        let panel = self.detail_panel.clone();

        next_button.connect_clicked(move |_| {
            let (current_idx, total_questions) = {
                let current = panel.quiz_widget().current_question();
                let model_rc = state.model();
                let model_borrow = model_rc.borrow();
                let total = model_borrow
                    .session()
                    .phases
                    .get(model_borrow.selected_phase())
                    .and_then(|phase| {
                        model_borrow
                            .selected_step()
                            .and_then(|sidx| phase.steps.get(sidx))
                    })
                    .and_then(|step| step.quiz_data.as_ref())
                    .map(|quiz_step| quiz_step.questions.len())
                    .unwrap_or(0);
                (current, total)
            };

            if current_idx + 1 < total_questions {
                let new_idx = current_idx + 1;
                panel.quiz_widget().set_current_question(new_idx);

                // Dispatch quiz question changed event
                let (phase_idx, step_idx) = {
                    let model_rc = state.model();
                    let model_borrow = model_rc.borrow();
                    (model_borrow.selected_phase(), model_borrow.selected_step())
                };
                if let Some(step_idx) = step_idx {
                    state.change_quiz_question(phase_idx, step_idx, new_idx);
                }

                // Refresh the display
                let quiz_step_opt = {
                    let model_rc = state.model();
                    let model_borrow = model_rc.borrow();
                    model_borrow
                        .session()
                        .phases
                        .get(model_borrow.selected_phase())
                        .and_then(|phase| {
                            model_borrow
                                .selected_step()
                                .and_then(|sidx| phase.steps.get(sidx))
                        })
                        .and_then(|step| step.quiz_data.as_ref().cloned())
                };

                if let Some(quiz_step) = quiz_step_opt {
                    panel.quiz_widget().refresh_current_question(&quiz_step);
                }
            }
        });
    }

    /// Bind the finish button handler.
    fn bind_finish(&self) {
        let finish_button = self.detail_panel.quiz_widget().finish_button.clone();
        let state = self.state.clone();
        let panel = self.detail_panel.clone();

        finish_button.connect_clicked(move |_| {
            let (phase_idx, step_idx) = {
                let model_rc = state.model();
                let model_borrow = model_rc.borrow();
                (model_borrow.selected_phase(), model_borrow.selected_step())
            };

            if let Some(step_idx) = step_idx {
                // Mark the quiz step as completed
                state.update_step_status(phase_idx, step_idx, StepStatus::Done);

                // Get final statistics
                let (stats, quiz_step_opt) = {
                    let model_rc = state.model();
                    let model_borrow = model_rc.borrow();
                    let step = model_borrow
                        .session()
                        .phases
                        .get(phase_idx)
                        .and_then(|phase| phase.steps.get(step_idx));

                    if let Some(step) = step {
                        if let Some(quiz_step) = step.quiz_data.as_ref() {
                            (Some(quiz_step.statistics()), Some(quiz_step.clone()))
                        } else {
                            (None, None)
                        }
                    } else {
                        (None, None)
                    }
                };

                if let (Some(stats), Some(quiz_step)) = (stats, quiz_step_opt) {
                    // Show completion message with final statistics
                    let completion_message = format!(
                        "🎉 Quiz Completed!\n\n\
                        Final Score: {:.1}%\n\
                        Questions Answered: {}/{}\n\
                        Correct Answers: {}\n\
                        First Attempt Correct: {}\n\n\
                        Well done! You can now proceed to the next step.",
                        stats.score_percentage,
                        stats.answered,
                        stats.total_questions,
                        stats.correct,
                        stats.first_attempt_correct
                    );

                    panel
                        .quiz_widget()
                        .show_explanation(&completion_message, None);

                    // Update statistics display
                    panel.quiz_widget().update_statistics(&quiz_step);
                }
            }
        });
    }
}
