use crate::model::QuizStep;
/// Quiz widget module for displaying quiz questions and handling user interactions
use gtk4::prelude::*;
use gtk4::{
    Box as GtkBox, Button, CheckButton, Frame, Label, Orientation, ScrolledWindow, Separator,
};
use std::cell::RefCell;
use std::rc::Rc;

/// Struct holding all quiz widget components
pub struct QuizWidget {
    pub container: GtkBox,
    pub question_label: Label,
    pub answer_buttons: Vec<CheckButton>,
    pub check_button: Button,
    pub view_explanation_button: Button,
    pub next_button: Button,
    pub prev_button: Button,
    pub finish_button: Button,
    pub explanation_view: gtk4::TextView,
    pub explanation_frame: Frame,
    pub stats_label: Label,
    pub progress_label: Label,
    pub current_question_index: Rc<RefCell<usize>>,
}

impl QuizWidget {
    /// Create a new quiz widget
    pub fn new() -> Self {
        let container = GtkBox::new(Orientation::Vertical, 12);
        container.set_margin_top(8);
        container.set_margin_bottom(8);
        container.set_margin_start(8);
        container.set_margin_end(8);
        container.set_vexpand(true); // Ensure it expands to fill space
        container.set_visible(true); // Ensure it's visible

        // Progress indicator (Question X of Y)
        let progress_label = Label::new(Some("Question 1 of 10"));
        progress_label.set_xalign(0.0);
        progress_label.add_css_class("heading");
        container.append(&progress_label);

        // Question text
        let question_label = Label::new(Some("Question will appear here"));
        question_label.set_wrap(true);
        question_label.set_xalign(0.0);
        question_label.set_margin_top(8);
        question_label.set_margin_bottom(8);
        question_label.add_css_class("title-2");
        container.append(&question_label);

        container.append(&Separator::new(Orientation::Horizontal));

        // Answer options (A, B, C, D) as radio buttons
        let answer_box = GtkBox::new(Orientation::Vertical, 8);
        answer_box.set_margin_top(8);
        answer_box.set_margin_bottom(8);

        let mut answer_buttons = Vec::new();
        let labels = vec!["A", "B", "C", "D"];

        for (i, label_text) in labels.iter().enumerate() {
            let button_box = GtkBox::new(Orientation::Horizontal, 8);

            // Create radio button (use CheckButton with group)
            let check = if i == 0 {
                CheckButton::new()
            } else {
                CheckButton::new()
            };

            // Group all buttons together so only one can be selected
            if i > 0 {
                check.set_group(Some(&answer_buttons[0]));
            }

            let label = Label::new(Some(&format!("{}. Answer option {}", label_text, i + 1)));
            label.set_xalign(0.0);
            label.set_wrap(true);
            label.set_hexpand(true);

            button_box.append(&check);
            button_box.append(&label);

            answer_box.append(&button_box);
            answer_buttons.push(check);
        }

        container.append(&answer_box);

        // Button row (Check Answer, Previous, Next)
        let button_row = GtkBox::new(Orientation::Horizontal, 8);
        button_row.set_margin_top(8);
        button_row.set_margin_bottom(8);

        let check_button = Button::with_label("Check Answer");
        check_button.add_css_class("suggested-action");
        button_row.append(&check_button);

        let view_explanation_button = Button::with_label("View Explanation");
        button_row.append(&view_explanation_button);

        button_row.append(&GtkBox::new(Orientation::Horizontal, 0)); // Spacer

        let prev_button = Button::with_label("← Previous");
        button_row.append(&prev_button);

        let next_button = Button::with_label("Next →");
        next_button.add_css_class("suggested-action");
        button_row.append(&next_button);

        let finish_button = Button::with_label("Finish Quiz");
        finish_button.add_css_class("destructive-action");
        button_row.append(&finish_button);

        container.append(&button_row);

        // Explanation panel (hidden by default)
        let explanation_view = gtk4::TextView::new();
        explanation_view.set_editable(false);
        explanation_view.set_wrap_mode(gtk4::WrapMode::Word);
        explanation_view.set_margin_top(8);
        explanation_view.set_margin_bottom(8);
        explanation_view.set_margin_start(8);
        explanation_view.set_margin_end(8);

        let explanation_scroll = ScrolledWindow::new();
        explanation_scroll.set_child(Some(&explanation_view));
        explanation_scroll.set_min_content_height(100);
        explanation_scroll.set_vexpand(true);

        let explanation_frame = Frame::builder()
            .label("Explanation")
            .child(&explanation_scroll)
            .build();
        explanation_frame.set_visible(false); // Hidden initially

        container.append(&explanation_frame);

        // Statistics label at the bottom
        let stats_label = Label::new(Some("Score: 0/0 (0%)"));
        stats_label.set_xalign(0.0);
        stats_label.set_margin_top(8);
        stats_label.add_css_class("dim-label");
        container.append(&stats_label);

        QuizWidget {
            container,
            question_label,
            answer_buttons,
            check_button,
            view_explanation_button,
            next_button,
            prev_button,
            finish_button,
            explanation_view,
            explanation_frame,
            stats_label,
            progress_label,
            current_question_index: Rc::new(RefCell::new(0)),
        }
    }

    /// Load a quiz step and display the first question (resets to question 1)
    pub fn load_quiz_step(&self, quiz_step: &QuizStep) {
        if quiz_step.questions.is_empty() {
            self.question_label.set_text("No questions available");
            self.set_buttons_sensitive(false);
            return;
        }

        // Always start at the first question when loading a new quiz
        *self.current_question_index.borrow_mut() = 0;

        // Refresh the display
        self.refresh_current_question(quiz_step);
    }

    /// Refresh display for the current question (without resetting index)
    pub fn refresh_current_question(&self, quiz_step: &QuizStep) {
        if quiz_step.questions.is_empty() {
            self.question_label.set_text("No questions available");
            self.set_buttons_sensitive(false);
            return;
        }

        let idx = *self.current_question_index.borrow();

        // Ensure index is valid
        let idx = if idx >= quiz_step.questions.len() {
            0
        } else {
            idx
        };

        // Update progress label
        self.progress_label.set_text(&format!(
            "Question {} of {}",
            idx + 1,
            quiz_step.questions.len()
        ));

        // Load question
        if let Some(question) = quiz_step.questions.get(idx) {
            self.question_label.set_text(&question.question_text);

            // Load answers
            for (i, (button, answer)) in self
                .answer_buttons
                .iter()
                .zip(&question.answers)
                .enumerate()
            {
                if let Some(label) = button.next_sibling() {
                    if let Some(label) = label.downcast_ref::<Label>() {
                        label.set_text(&format!("{}. {}", (b'A' + i as u8) as char, answer.text));
                    }
                }
                button.set_active(false); // Clear selection
            }

            // Check if already answered
            if let Some(progress) = quiz_step.progress.get(idx) {
                if progress.answered {
                    // Show previous answer
                    if let Some(selected_idx) = progress.selected_answer_index {
                        if let Some(button) = self.answer_buttons.get(selected_idx) {
                            button.set_active(true);
                        }
                    }

                    // Show explanation if it was viewed
                    if progress.explanation_viewed_before_answer || progress.answered {
                        self.show_explanation(&question.explanation, progress.is_correct);
                    }
                }
            }

            // Update navigation buttons
            self.prev_button.set_sensitive(idx > 0);
            self.next_button
                .set_sensitive(idx < quiz_step.questions.len() - 1);
        }

        // Update statistics
        self.update_statistics(quiz_step);
    }

    /// Show explanation panel with feedback
    pub fn show_explanation(&self, explanation: &str, is_correct: Option<bool>) {
        let feedback = match is_correct {
            Some(true) => "✓ Correct! ",
            Some(false) => "✗ Incorrect. ",
            None => "",
        };

        self.explanation_view
            .buffer()
            .set_text(&format!("{}{}", feedback, explanation));
        self.explanation_frame.set_visible(true);
    }

    /// Hide explanation panel
    pub fn hide_explanation(&self) {
        self.explanation_frame.set_visible(false);
    }

    /// Update statistics label
    pub fn update_statistics(&self, quiz_step: &QuizStep) {
        let stats = quiz_step.statistics();
        self.stats_label.set_text(&format!(
            "Progress: {}/{} answered | Correct: {} | Score: {:.1}%",
            stats.answered, stats.total_questions, stats.correct, stats.score_percentage
        ));
    }

    /// Get currently selected answer index
    pub fn get_selected_answer(&self) -> Option<usize> {
        self.answer_buttons.iter().position(|btn| btn.is_active())
    }

    /// Set sensitivity of all interactive buttons
    pub fn set_buttons_sensitive(&self, sensitive: bool) {
        self.check_button.set_sensitive(sensitive);
        self.next_button.set_sensitive(sensitive);
        self.prev_button.set_sensitive(sensitive);
        for button in &self.answer_buttons {
            button.set_sensitive(sensitive);
        }
    }

    /// Move to next question
    pub fn next_question(&self) {
        let mut idx = self.current_question_index.borrow_mut();
        *idx += 1;
    }

    /// Move to previous question
    pub fn prev_question(&self) {
        let mut idx = self.current_question_index.borrow_mut();
        if *idx > 0 {
            *idx -= 1;
        }
    }

    /// Get current question index
    pub fn current_question(&self) -> usize {
        *self.current_question_index.borrow()
    }

    /// Set current question index
    pub fn set_current_question(&self, index: usize) {
        *self.current_question_index.borrow_mut() = index;
    }
}
