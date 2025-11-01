use gtk4::prelude::*;
use gtk4::glib;
use gtk4::{Application, ApplicationWindow, Box as GtkBox, Orientation, ScrolledWindow, CheckButton, Label, TextView, ListBoxRow, FileDialog, gdk, Paned, Button};
use gtk4::gio;
use std::rc::Rc;
use std::cell::RefCell;

use crate::model::{AppModel, StepStatus};
use crate::ui::canvas::{load_step_evidence, setup_canvas};

pub fn build_ui(app: &Application, model: AppModel) {
    let model = Rc::new(RefCell::new(model));

    let window = ApplicationWindow::builder()
        .application(app)
        .title("PT Journal")
        .default_width(1100)
        .default_height(700)
        .build();

    // Add CSS styling for selected canvas items
    if let Some(display) = gdk::Display::default() {
        let css_provider = gtk4::CssProvider::new();
        css_provider.load_from_string("
            .selected {
                border: 2px solid #3584e4;
                border-radius: 4px;
            }
        ");
        gtk4::style_context_add_provider_for_display(
            &display,
            &css_provider,
            gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }

    // Header bar with Open/Save and Sidebar toggle
    let (header, btn_open, btn_save, btn_save_as, btn_sidebar) = crate::ui::header_bar::create_header_bar();
    window.set_titlebar(Some(&header));

    // Left panel: phase selector + steps list
    let (left_box, phase_model, phase_combo, steps_list) = crate::ui::sidebar::create_sidebar(&model);

    // Right panel: detail view with checkbox, title, description, notes, canvas
    let detail_panel = crate::ui::detail_panel::create_detail_panel();
    let right = detail_panel.container.clone();
    let checkbox = detail_panel.checkbox.clone();
    let title_label = detail_panel.title_label.clone();
    let desc_view = detail_panel.desc_view.clone();
    let notes_view = detail_panel.notes_view.clone();
    let canvas_fixed = detail_panel.canvas_fixed.clone();
    let canvas_items = detail_panel.canvas_items.clone();
    
    // Keep reference to full detail_panel for load_step_into_panel()
    let detail_panel_ref = Rc::new(detail_panel);

    // === WIRE UP QUIZ WIDGET BUTTONS ===
    {
        let quiz_widget = &detail_panel_ref.quiz_widget;
        let model_quiz = model.clone();
        let detail_panel_quiz = detail_panel_ref.clone();
        
        // Check Answer button
        let check_button = quiz_widget.check_button.clone();
        let model_check = model_quiz.clone();
        let panel_check = detail_panel_quiz.clone();
        check_button.connect_clicked(move |_| {
            let (phase_idx, step_idx, question_idx, selected_answer) = {
                let model_borrow = model_check.borrow();
                let phase_idx = model_borrow.selected_phase;
                let step_idx = model_borrow.selected_step;
                let question_idx = *panel_check.quiz_widget.current_question_index.borrow();
                let selected_answer = panel_check.quiz_widget.get_selected_answer();
                (phase_idx, step_idx, question_idx, selected_answer)
            };
            
            if let (Some(step_idx), Some(answer_idx)) = (step_idx, selected_answer) {
                // Check the answer and get result
                let (is_correct_result, step_clone) = {
                    let mut model_mut = model_check.borrow_mut();
                    if let Some(step) = model_mut.session.phases.get_mut(phase_idx)
                        .and_then(|p| p.steps.get_mut(step_idx))
                    {
                        if let Some(quiz_step) = step.quiz_mut_safe() {
                            // Check if answer is correct
                            let correct = quiz_step.questions.get(question_idx)
                                .and_then(|q| q.answers.get(answer_idx))
                                .map(|a| a.is_correct)
                                .unwrap_or(false);
                            
                            // Update progress
                            if let Some(progress) = quiz_step.progress.get_mut(question_idx) {
                                let first_attempt = progress.attempts == 0;
                                progress.answered = true;
                                progress.selected_answer_index = Some(answer_idx);
                                progress.is_correct = Some(correct);
                                progress.attempts += 1;
                                progress.last_attempted = Some(chrono::Utc::now());
                                
                                if first_attempt && correct && !progress.explanation_viewed_before_answer {
                                    progress.first_attempt_correct = true;
                                }
                            }
                            
                            // Get explanation
                            let explanation = quiz_step.questions.get(question_idx)
                                .map(|q| q.explanation.clone())
                                .unwrap_or_default();
                            
                            (Some((correct, explanation.clone())), step.clone())
                        } else {
                            (None, step.clone())
                        }
                    } else {
                        (None, model_mut.session.phases[phase_idx].steps[step_idx].clone())
                    }
                };
                
                // Show result
                if let Some((correct, explanation)) = is_correct_result {
                    panel_check.quiz_widget.show_explanation(&explanation, Some(correct));
                    if let Some(quiz_step) = step_clone.get_quiz_step() {
                        panel_check.quiz_widget.update_statistics(quiz_step);
                    }
                }
            }
        });
        
        // View Explanation button (marks question as non-scored)
        let view_explanation_button = quiz_widget.view_explanation_button.clone();
        let model_view = model_quiz.clone();
        let panel_view = detail_panel_quiz.clone();
        view_explanation_button.connect_clicked(move |_| {
            let (phase_idx, step_idx, question_idx) = {
                let model_borrow = model_view.borrow();
                let phase_idx = model_borrow.selected_phase;
                let step_idx = model_borrow.selected_step;
                let question_idx = *panel_view.quiz_widget.current_question_index.borrow();
                (phase_idx, step_idx, question_idx)
            };
            
            if let Some(step_idx) = step_idx {
                let (explanation, _step_clone) = {
                    let mut model_mut = model_view.borrow_mut();
                    if let Some(step) = model_mut.session.phases.get_mut(phase_idx)
                        .and_then(|p| p.steps.get_mut(step_idx))
                    {
                        if let Some(quiz_step) = step.quiz_mut_safe() {
                            // Mark that explanation was viewed before answering
                            if let Some(progress) = quiz_step.progress.get_mut(question_idx) {
                                if !progress.answered {
                                    progress.explanation_viewed_before_answer = true;
                                }
                            }
                            
                            // Get explanation
                            let explanation = quiz_step.questions.get(question_idx)
                                .map(|q| q.explanation.clone())
                                .unwrap_or_default();
                            
                            (explanation, step.clone())
                        } else {
                            (String::new(), step.clone())
                        }
                    } else {
                        (String::new(), model_mut.session.phases[phase_idx].steps[step_idx].clone())
                    }
                };
                
                panel_view.quiz_widget.show_explanation(&explanation, None);
            }
        });
        
        // Next button
        let next_button = quiz_widget.next_button.clone();
        let model_next = model_quiz.clone();
        let panel_next = detail_panel_quiz.clone();
        next_button.connect_clicked(move |_| {
            let (phase_idx, step_idx) = {
                let model_borrow = model_next.borrow();
                (model_borrow.selected_phase, model_borrow.selected_step)
            };
            
            if let Some(step_idx) = step_idx {
                // Auto-submit answer if selected but not yet checked
                let question_idx = *panel_next.quiz_widget.current_question_index.borrow();
                let selected_answer = panel_next.quiz_widget.get_selected_answer();
                
                if let Some(answer_idx) = selected_answer {
                    // Check if this question has already been answered
                    let already_answered = {
                        let model_borrow = model_next.borrow();
                        model_borrow.session.phases.get(phase_idx)
                            .and_then(|p| p.steps.get(step_idx))
                            .and_then(|s| s.get_quiz_step())
                            .and_then(|qs| qs.progress.get(question_idx))
                            .map(|p| p.answered)
                            .unwrap_or(false)
                    };
                    
                    // If not answered yet, auto-submit the answer
                    if !already_answered {
                        let mut model_mut = model_next.borrow_mut();
                        if let Some(step) = model_mut.session.phases.get_mut(phase_idx)
                            .and_then(|p| p.steps.get_mut(step_idx))
                        {
                            if let Some(quiz_step) = step.quiz_mut_safe() {
                                let correct = quiz_step.questions.get(question_idx)
                                    .and_then(|q| q.answers.get(answer_idx))
                                    .map(|a| a.is_correct)
                                    .unwrap_or(false);
                                
                                if let Some(progress) = quiz_step.progress.get_mut(question_idx) {
                                    let first_attempt = progress.attempts == 0;
                                    progress.answered = true;
                                    progress.selected_answer_index = Some(answer_idx);
                                    progress.is_correct = Some(correct);
                                    progress.attempts += 1;
                                    progress.last_attempted = Some(chrono::Utc::now());
                                    
                                    if first_attempt && correct && !progress.explanation_viewed_before_answer {
                                        progress.first_attempt_correct = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                let step_clone = {
                    let model_borrow = model_next.borrow();
                    model_borrow.session.phases.get(phase_idx)
                        .and_then(|p| p.steps.get(step_idx))
                        .cloned()
                };
                
                if let Some(step) = step_clone {
                    if let Some(quiz_step) = step.get_quiz_step() {
                        let current = *panel_next.quiz_widget.current_question_index.borrow();
                        if current + 1 < quiz_step.questions.len() {
                            *panel_next.quiz_widget.current_question_index.borrow_mut() = current + 1;
                            panel_next.quiz_widget.hide_explanation();
                            panel_next.quiz_widget.refresh_current_question(quiz_step);
                            // Update statistics to reflect the auto-submitted answer
                            panel_next.quiz_widget.update_statistics(quiz_step);
                        }
                    }
                }
            }
        });
        
        // Previous button
        let prev_button = quiz_widget.prev_button.clone();
        let model_prev = model_quiz.clone();
        let panel_prev = detail_panel_quiz.clone();
        prev_button.connect_clicked(move |_| {
            let (phase_idx, step_idx) = {
                let model_borrow = model_prev.borrow();
                (model_borrow.selected_phase, model_borrow.selected_step)
            };
            
            if let Some(step_idx) = step_idx {
                // Auto-submit answer if selected but not yet checked
                let question_idx = *panel_prev.quiz_widget.current_question_index.borrow();
                let selected_answer = panel_prev.quiz_widget.get_selected_answer();
                
                if let Some(answer_idx) = selected_answer {
                    // Check if this question has already been answered
                    let already_answered = {
                        let model_borrow = model_prev.borrow();
                        model_borrow.session.phases.get(phase_idx)
                            .and_then(|p| p.steps.get(step_idx))
                            .and_then(|s| s.get_quiz_step())
                            .and_then(|qs| qs.progress.get(question_idx))
                            .map(|p| p.answered)
                            .unwrap_or(false)
                    };
                    
                    // If not answered yet, auto-submit the answer
                    if !already_answered {
                        let mut model_mut = model_prev.borrow_mut();
                        if let Some(step) = model_mut.session.phases.get_mut(phase_idx)
                            .and_then(|p| p.steps.get_mut(step_idx))
                        {
                            if let Some(quiz_step) = step.quiz_mut_safe() {
                                let correct = quiz_step.questions.get(question_idx)
                                    .and_then(|q| q.answers.get(answer_idx))
                                    .map(|a| a.is_correct)
                                    .unwrap_or(false);
                                
                                if let Some(progress) = quiz_step.progress.get_mut(question_idx) {
                                    let first_attempt = progress.attempts == 0;
                                    progress.answered = true;
                                    progress.selected_answer_index = Some(answer_idx);
                                    progress.is_correct = Some(correct);
                                    progress.attempts += 1;
                                    progress.last_attempted = Some(chrono::Utc::now());
                                    
                                    if first_attempt && correct && !progress.explanation_viewed_before_answer {
                                        progress.first_attempt_correct = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                let step_clone = {
                    let model_borrow = model_prev.borrow();
                    model_borrow.session.phases.get(phase_idx)
                        .and_then(|p| p.steps.get(step_idx))
                        .cloned()
                };
                
                if let Some(step) = step_clone {
                    if let Some(quiz_step) = step.get_quiz_step() {
                        let current = *panel_prev.quiz_widget.current_question_index.borrow();
                        if current > 0 {
                            *panel_prev.quiz_widget.current_question_index.borrow_mut() = current - 1;
                            panel_prev.quiz_widget.hide_explanation();
                            panel_prev.quiz_widget.refresh_current_question(quiz_step);
                            // Update statistics to reflect the auto-submitted answer
                            panel_prev.quiz_widget.update_statistics(quiz_step);
                        }
                    }
                }
            }
        });
        
        // Finish Quiz button
        let finish_button = quiz_widget.finish_button.clone();
        let model_finish = model_quiz.clone();
        let panel_finish = detail_panel_quiz.clone();
        let window_finish = window.clone();
        finish_button.connect_clicked(move |_| {
            let (phase_idx, step_idx) = {
                let model_borrow = model_finish.borrow();
                (model_borrow.selected_phase, model_borrow.selected_step)
            };
            
            if let Some(step_idx) = step_idx {
                // Auto-submit current question if answered but not checked
                let question_idx = *panel_finish.quiz_widget.current_question_index.borrow();
                let selected_answer = panel_finish.quiz_widget.get_selected_answer();
                
                if let Some(answer_idx) = selected_answer {
                    let already_answered = {
                        let model_borrow = model_finish.borrow();
                        model_borrow.session.phases.get(phase_idx)
                            .and_then(|p| p.steps.get(step_idx))
                            .and_then(|s| s.get_quiz_step())
                            .and_then(|qs| qs.progress.get(question_idx))
                            .map(|p| p.answered)
                            .unwrap_or(false)
                    };
                    
                    if !already_answered {
                        let mut model_mut = model_finish.borrow_mut();
                        if let Some(step) = model_mut.session.phases.get_mut(phase_idx)
                            .and_then(|p| p.steps.get_mut(step_idx))
                        {
                            if let Some(quiz_step) = step.quiz_mut_safe() {
                                let correct = quiz_step.questions.get(question_idx)
                                    .and_then(|q| q.answers.get(answer_idx))
                                    .map(|a| a.is_correct)
                                    .unwrap_or(false);
                                
                                if let Some(progress) = quiz_step.progress.get_mut(question_idx) {
                                    let first_attempt = progress.attempts == 0;
                                    progress.answered = true;
                                    progress.selected_answer_index = Some(answer_idx);
                                    progress.is_correct = Some(correct);
                                    progress.attempts += 1;
                                    progress.last_attempted = Some(chrono::Utc::now());
                                    
                                    if first_attempt && correct && !progress.explanation_viewed_before_answer {
                                        progress.first_attempt_correct = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                let step_clone = {
                    let model_borrow = model_finish.borrow();
                    model_borrow.session.phases.get(phase_idx)
                        .and_then(|p| p.steps.get(step_idx))
                        .cloned()
                };
                
                if let Some(step) = step_clone {
                    if let Some(quiz_step) = step.get_quiz_step() {
                        let stats = quiz_step.statistics();
                        
                        // Calculate scored vs non-scored questions
                        let scored_questions: Vec<_> = quiz_step.progress.iter()
                            .filter(|p| p.awards_points())
                            .collect();
                        let non_scored_answered: Vec<_> = quiz_step.progress.iter()
                            .filter(|p| p.answered && !p.awards_points())
                            .collect();
                        let unanswered = stats.total_questions - stats.answered;
                        
                        // Build results message
                        let mut message = format!(
                            "Quiz Complete!\n\n\
                            Total Questions: {}\n\
                            Answered: {}\n\
                            Unanswered: {}\n\n\
                            === SCORING ===\n\
                            Questions Counted for Score: {} (answered correctly on first attempt without viewing explanation)\n\
                            Questions NOT Counted: {} (viewed explanation before answering, or incorrect)\n\n\
                            Final Score: {:.1}%\n",
                            stats.total_questions,
                            stats.answered,
                            unanswered,
                            scored_questions.len(),
                            non_scored_answered.len(),
                            stats.score_percentage
                        );
                        
                        // Add breakdown
                        if !scored_questions.is_empty() {
                            message.push_str("\nScored Questions:\n");
                            for (i, progress) in scored_questions.iter().enumerate() {
                                if let Some(q) = quiz_step.questions.iter().find(|q| q.id == progress.question_id) {
                                    message.push_str(&format!("  {}. {} ✓\n", i + 1, q.question_text.chars().take(50).collect::<String>()));
                                }
                            }
                        }
                        
                        if !non_scored_answered.is_empty() {
                            message.push_str("\nNot Counted (explanation viewed or incorrect):\n");
                            for (i, progress) in non_scored_answered.iter().enumerate() {
                                if let Some(q) = quiz_step.questions.iter().find(|q| q.id == progress.question_id) {
                                    let reason = if progress.explanation_viewed_before_answer {
                                        "viewed explanation first"
                                    } else if progress.is_correct == Some(false) {
                                        "incorrect"
                                    } else {
                                        "not first attempt"
                                    };
                                    message.push_str(&format!("  {}. {} ({})\n", i + 1, q.question_text.chars().take(50).collect::<String>(), reason));
                                }
                            }
                        }
                        
                        // Show results in a scrollable text view dialog
                        let dialog = gtk4::Window::builder()
                            .transient_for(&window_finish)
                            .modal(true)
                            .title("Quiz Results")
                            .default_width(600)
                            .default_height(500)
                            .build();
                        
                        let vbox = GtkBox::new(Orientation::Vertical, 12);
                        vbox.set_margin_top(12);
                        vbox.set_margin_bottom(12);
                        vbox.set_margin_start(12);
                        vbox.set_margin_end(12);
                        
                        // Results text view
                        let text_view = gtk4::TextView::new();
                        text_view.set_editable(false);
                        text_view.set_cursor_visible(false);
                        text_view.set_wrap_mode(gtk4::WrapMode::Word);
                        text_view.buffer().set_text(&message);
                        text_view.set_margin_top(8);
                        text_view.set_margin_bottom(8);
                        text_view.set_margin_start(8);
                        text_view.set_margin_end(8);
                        
                        let scrolled = gtk4::ScrolledWindow::new();
                        scrolled.set_child(Some(&text_view));
                        scrolled.set_vexpand(true);
                        vbox.append(&scrolled);
                        
                        // Close button
                        let close_button = Button::with_label("Close");
                        close_button.add_css_class("suggested-action");
                        let dialog_clone = dialog.clone();
                        close_button.connect_clicked(move |_| {
                            dialog_clone.close();
                        });
                        vbox.append(&close_button);
                        
                        dialog.set_child(Some(&vbox));
                        dialog.present();
                    }
                }
            }
        });
    }

    // Use Paned for resizable sidebar
    let paned = Paned::new(Orientation::Horizontal);
    paned.set_start_child(Some(&left_box));
    paned.set_end_child(Some(&right));
    paned.set_position(320); // Default sidebar width
    paned.set_resize_start_child(true);
    paned.set_resize_end_child(true);

    // Store paned reference for sidebar toggle
    let paned_ref = paned.clone();
    window.set_child(Some(&paned));

    // Helper to rebuild steps list for current phase
    let rebuild_steps = {
        let model_rc = model.clone();
        let steps_list_ref = steps_list.clone();
        let title_label_ref = title_label.clone();
        let desc_view_ref = desc_view.clone();
        let notes_view_ref = notes_view.clone();
        let checkbox_ref = checkbox.clone();
        let canvas_fixed_ref = canvas_fixed.clone();
        let canvas_items_ref = canvas_items.clone();
        let detail_panel_ref = detail_panel_ref.clone();
        move || {
            // clear
            while let Some(child) = steps_list_ref.first_child() { steps_list_ref.remove(&child); }
            
            // Clone all data needed for UI update to avoid holding borrows during GTK calls
            let (selected_phase, phase_steps, selected_step) = {
                let model_borrow = model_rc.borrow();
                let selected_phase = model_borrow.selected_phase;
                let phase_steps: Vec<_> = model_borrow.session.phases.get(selected_phase)
                    .map(|phase| phase.steps.iter().map(|step| {
                        (step.title.clone(), step.get_description(), step.get_description_notes(),
                         step.get_notes(), step.status.clone())
                    }).collect())
                    .unwrap_or_default();
                let selected_step = model_borrow.selected_step;
                (selected_phase, phase_steps, selected_step)
            };

            for (idx, (title, description, _description_notes, _notes, status)) in phase_steps.iter().enumerate() {
                let row = ListBoxRow::new();
                let row_box = GtkBox::new(Orientation::Horizontal, 8);
                
                let cb = CheckButton::new();
                cb.set_active(matches!(status, StepStatus::Done));
                let lbl = Label::new(Some(title));
                lbl.set_xalign(0.0);
                
                // Make the label clickable instead of the whole row
                let click_controller = gtk4::GestureClick::new();
                let model_s = model_rc.clone();
                let canvas_fixed_s = canvas_fixed_ref.clone();
                let canvas_items_s = canvas_items_ref.clone();
                let detail_panel_s = detail_panel_ref.clone();
                
                click_controller.connect_pressed(move |_, _, _, _| {
                    let mut model_borrow = model_s.borrow_mut();
                    model_borrow.selected_step = Some(idx);
                    let sp = model_borrow.selected_phase;
                    if let Some(step) = model_borrow.session.phases[sp].steps.get(idx) {
                        let step_clone = step.clone();
                        drop(model_borrow); // Release borrow before GTK calls
                        
                        // Use load_step_into_panel for conditional rendering (tutorial vs quiz)
                        crate::ui::detail_panel::load_step_into_panel(&detail_panel_s, &step_clone);
                        
                        // For tutorial steps, also load canvas evidence
                        if !step_clone.is_quiz() {
                            load_step_evidence(&canvas_fixed_s, canvas_items_s.clone(), &step_clone);
                        }
                        
                        // Focus the appropriate widget
                        if step_clone.is_quiz() {
                            detail_panel_s.quiz_widget.container.grab_focus();
                        } else {
                            canvas_fixed_s.grab_focus();
                        }
                    }
                });
                lbl.add_controller(click_controller);
                
                let info_btn = gtk4::Button::from_icon_name("dialog-information-symbolic");
                info_btn.set_valign(gtk4::Align::Center);
                info_btn.set_tooltip_text(Some("Show explanation"));

                // Create popover upfront with content
                let popover = gtk4::Popover::new();
                let pop_box = GtkBox::new(Orientation::Vertical, 6);
                
                // Use ScrolledWindow with TextView for long content
                let scrolled = ScrolledWindow::new();
                scrolled.set_min_content_height(300);
                scrolled.set_min_content_width(500);
                scrolled.set_max_content_height(500);
                scrolled.set_max_content_width(700);
                scrolled.set_propagate_natural_height(true);
                scrolled.set_propagate_natural_width(true);
                let text_view = TextView::new();
                text_view.set_editable(false);
                text_view.set_wrap_mode(gtk4::WrapMode::Word);
                text_view.set_size_request(480, 280);
                text_view.buffer().set_text(description);
                scrolled.set_child(Some(&text_view));
                
                pop_box.append(&scrolled);
                popover.set_child(Some(&pop_box));
                popover.set_has_arrow(true);
                popover.set_position(gtk4::PositionType::Bottom);

                // Set parent and popup on click
                let pop_clone = popover.clone();
                info_btn.connect_clicked(move |btn| {
                    pop_clone.set_parent(btn);
                    pop_clone.popup();
                });
                
                row_box.append(&cb);
                row_box.append(&lbl);
                row_box.append(&info_btn);
                row.set_child(Some(&row_box));

                // Toggle handler
                let model_t = model_rc.clone();
                let cb_clone = cb.clone();
                cb.connect_toggled(move |c| {
                    let mut model_borrow = model_t.borrow_mut();
                    let sp = model_borrow.selected_phase;
                    if let Some(step) = model_borrow.session.phases.get_mut(sp).and_then(|p| p.steps.get_mut(idx)) {
                        step.status = if c.is_active() { StepStatus::Done } else { StepStatus::Todo };
                    }
                });
                
                // Prevent checkbox from consuming click events
                cb_clone.set_can_focus(false);

                steps_list_ref.append(&row);
            }
            
            // Auto-select first step if none selected, or update UI for current selection
            if let Some(selected_idx) = selected_step {
                let (title, description_notes, notes, status, step_clone) = {
                    let model_borrow = model_rc.borrow();
                    if let Some(step) = model_borrow.session.phases.get(selected_phase)
                        .and_then(|phase| phase.steps.get(selected_idx)) {
                        (step.title.clone(), step.get_description_notes(),
                         step.get_notes(), step.status.clone(), step.clone())
                    } else {
                        return; // No step found
                    }
                };
                
                title_label_ref.set_label(&title);
                // Load user notes in description pane
                let desc_buffer = desc_view_ref.buffer();
                desc_buffer.set_text(&description_notes);
                checkbox_ref.set_active(matches!(status, StepStatus::Done));
                notes_view_ref.buffer().set_text(&notes);

                // Load canvas evidence for this step
                load_step_evidence(&canvas_fixed_ref, canvas_items_ref.clone(), &step_clone);
                // Focus the canvas so keyboard events work
                canvas_fixed_ref.grab_focus();
            } else if !phase_steps.is_empty() {
                model_rc.borrow_mut().selected_step = Some(0);
                let (title, description_notes, notes, status, step_clone) = {
                    let model_borrow_again = model_rc.borrow();
                    if let Some(step) = model_borrow_again.session.phases[selected_phase].steps.first() {
                        (step.title.clone(), step.get_description_notes(),
                         step.get_notes(), step.status.clone(), step.clone())
                    } else {
                        return; // No step found
                    }
                };
                
                title_label_ref.set_label(&title);
                // Load user notes in description pane
                let desc_buffer = desc_view_ref.buffer();
                desc_buffer.set_text(&description_notes);
                checkbox_ref.set_active(matches!(status, StepStatus::Done));
                notes_view_ref.buffer().set_text(&notes);

                // Load canvas evidence for this step
                load_step_evidence(&canvas_fixed_ref, canvas_items_ref.clone(), &step_clone);
                // Focus the canvas so keyboard events work
                canvas_fixed_ref.grab_focus();
            }
        }
    };

    // Initial populate
    rebuild_steps();

    // Autosave functionality - saves 2 seconds after last change
    // We don't need to cancel old timeouts - they'll just be orphaned and fire harmlessly
    let autosave_counter: Rc<RefCell<u32>> = Rc::new(RefCell::new(0));
    
    let trigger_autosave = {
        let model_autosave = model.clone();
        let counter_ref = autosave_counter.clone();
        move || {
            // Increment counter to invalidate any pending autosaves
            let current_count = {
                let mut counter = counter_ref.borrow_mut();
                *counter += 1;
                *counter
            };
            
            // Schedule new autosave in 2 seconds
            let m = model_autosave.clone();
            let counter_check = counter_ref.clone();
            glib::timeout_add_seconds_local_once(2, move || {
                // Only save if this is still the latest autosave request
                if *counter_check.borrow() == current_count {
                    let (path_opt, session) = {
                        let borrow = m.borrow();
                        (borrow.current_path.clone(), borrow.session.clone())
                    };
                    
                    if let Some(path) = path_opt {
                        match crate::store::save_session(&path, &session) {
                            Ok(_) => println!("Autosaved to: {:?}", path),
                            Err(err) => eprintln!("Autosave failed: {err:?}"),
                        }
                    }
                }
            });
        }
    };

    // Notes update (with autosave)
    {
        let model_notes = model.clone();
        let autosave_trigger = trigger_autosave.clone();
        let buf = notes_view.buffer();
        buf.connect_changed(move |b| {
            let text = b.text(&b.start_iter(), &b.end_iter(), true);
            // Get indices first with immutable borrow
            let (phase_idx, step_idx) = {
                let model_borrow = model_notes.borrow();
                (model_borrow.selected_phase, model_borrow.selected_step)
            };

            // Then update with mutable borrow
            if let Some(idx) = step_idx {
                if let Some(step) = model_notes.borrow_mut().session.phases.get_mut(phase_idx).and_then(|p| p.steps.get_mut(idx)) {
                    step.set_notes(text.to_string());
                }
            }
            
            // Trigger autosave
            autosave_trigger();
        });
    }

    // Description update (for user notes in description area, with autosave)
    {
        let model_desc = model.clone();
        let autosave_trigger = trigger_autosave.clone();
        let buf = desc_view.buffer();
        buf.connect_changed(move |b| {
            let text = b.text(&b.start_iter(), &b.end_iter(), true);
            // Get indices first with immutable borrow
            let (phase_idx, step_idx) = {
                let model_borrow = model_desc.borrow();
                (model_borrow.selected_phase, model_borrow.selected_step)
            };

            // Then update with mutable borrow
            if let Some(idx) = step_idx {
                if let Some(step) = model_desc.borrow_mut().session.phases.get_mut(phase_idx).and_then(|p| p.steps.get_mut(idx)) {
                    step.set_description_notes(text.to_string());
                }
            }
            
            // Trigger autosave
            autosave_trigger();
        });
    }

    // Phase selection change
    let phase_combo_handler_id = {
        let model_phase = model.clone();
        let steps_list_ref = steps_list.clone();
        let title_label_ref = title_label.clone();
        let desc_view_ref = desc_view.clone();
        let notes_view_ref = notes_view.clone();
        let checkbox_ref = checkbox.clone();
        let canvas_fixed_ref = canvas_fixed.clone();
        let canvas_items_ref = canvas_items.clone();
        phase_combo.connect_selected_notify(move |c| {
            let active = c.selected();
            {
                let mut model_borrow = model_phase.borrow_mut();
                model_borrow.selected_phase = active as usize;
                model_borrow.selected_step = None;
            }

            // Rebuild steps list for the new phase (inline logic to avoid borrowing conflicts)
            while let Some(child) = steps_list_ref.first_child() {
                steps_list_ref.remove(&child);
            }

            // Clone all data needed for UI update to avoid holding borrows during GTK calls
            let (selected_phase, phase_steps) = {
                let model_borrow = model_phase.borrow();
                let selected_phase = model_borrow.selected_phase;
                let phase_steps: Vec<_> = model_borrow.session.phases.get(selected_phase)
                    .map(|phase| phase.steps.iter().map(|step| {
                        (step.title.clone(), step.get_description(), step.get_description_notes(),
                         step.get_notes(), step.status.clone())
                    }).collect())
                    .unwrap_or_default();
                (selected_phase, phase_steps)
            };

            for (idx, (title, description, _description_notes, _notes, status)) in phase_steps.iter().enumerate() {
                let row = ListBoxRow::new();
                let row_box = GtkBox::new(Orientation::Horizontal, 8);

                let cb = CheckButton::new();
                cb.set_active(matches!(status, StepStatus::Done));
                let lbl = Label::new(Some(title));
                lbl.set_xalign(0.0);

                // Make the label clickable instead of the whole row
                let click_controller = gtk4::GestureClick::new();
                let model_s = model_phase.clone();
                let canvas_fixed_s = canvas_fixed_ref.clone();
                let canvas_items_s = canvas_items_ref.clone();
                let detail_panel_s = detail_panel_ref.clone();

                click_controller.connect_pressed(move |_, _, _, _| {
                    let mut model_borrow = model_s.borrow_mut();
                    model_borrow.selected_step = Some(idx);
                    let sp = model_borrow.selected_phase;
                    if let Some(step) = model_borrow.session.phases[sp].steps.get(idx) {
                        let step_clone = step.clone();
                        drop(model_borrow); // Release borrow before GTK calls
                        
                        // Use load_step_into_panel for conditional rendering (tutorial vs quiz)
                        crate::ui::detail_panel::load_step_into_panel(&detail_panel_s, &step_clone);
                        
                        // For tutorial steps, also load canvas evidence
                        if !step_clone.is_quiz() {
                            load_step_evidence(&canvas_fixed_s, canvas_items_s.clone(), &step_clone);
                        }
                        
                        // Focus the appropriate widget
                        if step_clone.is_quiz() {
                            detail_panel_s.quiz_widget.container.grab_focus();
                        } else {
                            canvas_fixed_s.grab_focus();
                        }
                    }
                });
                lbl.add_controller(click_controller);

                let info_btn = gtk4::Button::from_icon_name("dialog-information-symbolic");
                info_btn.set_valign(gtk4::Align::Center);
                info_btn.set_tooltip_text(Some("Show explanation"));

                // Create popover upfront with content
                let popover = gtk4::Popover::new();
                let pop_box = GtkBox::new(Orientation::Vertical, 6);

                // Use ScrolledWindow with TextView for long content
                let scrolled = ScrolledWindow::new();
                scrolled.set_min_content_height(300);
                scrolled.set_min_content_width(500);
                scrolled.set_max_content_height(500);
                scrolled.set_max_content_width(700);
                scrolled.set_propagate_natural_height(true);
                scrolled.set_propagate_natural_width(true);
                let text_view = TextView::new();
                text_view.set_editable(false);
                text_view.set_wrap_mode(gtk4::WrapMode::Word);
                text_view.set_size_request(480, 280);
                text_view.buffer().set_text(description);
                scrolled.set_child(Some(&text_view));

                    pop_box.append(&scrolled);
                    popover.set_child(Some(&pop_box));
                    popover.set_has_arrow(true);
                    popover.set_position(gtk4::PositionType::Bottom);

                    // Set parent and popup on click
                    let pop_clone = popover.clone();
                    info_btn.connect_clicked(move |btn| {
                        pop_clone.set_parent(btn);
                        pop_clone.popup();
                    });

                    row_box.append(&cb);
                    row_box.append(&lbl);
                    row_box.append(&info_btn);
                    row.set_child(Some(&row_box));

                    // Toggle handler
                    let model_t = model_phase.clone();
                    let cb_clone = cb.clone();
                    cb.connect_toggled(move |c| {
                        let mut model_borrow = model_t.borrow_mut();
                        let sp = model_borrow.selected_phase;
                        if let Some(step) = model_borrow.session.phases.get_mut(sp).and_then(|p| p.steps.get_mut(idx)) {
                            step.status = if c.is_active() { StepStatus::Done } else { StepStatus::Todo };
                        }
                    });

                    // Prevent checkbox from consuming click events
                    cb_clone.set_can_focus(false);

                    steps_list_ref.append(&row);
                }

            // Auto-select first step of new phase
            if !phase_steps.is_empty() {
                {
                    let mut model_borrow_mut = model_phase.borrow_mut();
                    model_borrow_mut.selected_step = Some(0);
                }
                let (title, description_notes, notes, status, step_clone) = {
                    let model_borrow_again = model_phase.borrow();
                    if let Some(step) = model_borrow_again.session.phases[selected_phase].steps.first() {
                        (step.title.clone(), step.get_description_notes(), 
                         step.get_notes(), step.status.clone(), step.clone())
                    } else {
                        return; // No step found, exit early
                    }
                };
                
                title_label_ref.set_label(&title);
                // Load user notes in description pane
                let desc_buffer = desc_view_ref.buffer();
                desc_buffer.set_text(&description_notes);
                checkbox_ref.set_active(matches!(status, StepStatus::Done));
                notes_view_ref.buffer().set_text(&notes);

                // Load canvas evidence for this step
                load_step_evidence(&canvas_fixed_ref, canvas_items_ref.clone(), &step_clone);
                // Focus the canvas so keyboard events work
                canvas_fixed_ref.grab_focus();
            }
        })
    };

    // Open dialog
    {
        let window_ref = window.clone();
        let model_ref = model.clone();
        let phase_model_ref = phase_model.clone();
        let phase_combo_ref = phase_combo.clone();
        let steps_list_ref = steps_list.clone();
        let title_label_ref = title_label.clone();
        let desc_view_ref = desc_view.clone();
        let notes_view_ref = notes_view.clone();
        let checkbox_ref = checkbox.clone();
        let canvas_fixed_ref = canvas_fixed.clone();
        let canvas_items_ref = canvas_items.clone();
        let phase_combo_handler_id_ref = Rc::new(phase_combo_handler_id);
        btn_open.connect_clicked(move |_| {
            let dialog = FileDialog::new();
            dialog.set_title("Open Session");
            
            // Set initial folder to Downloads/pt-journal-sessions
            let default_dir = crate::store::default_sessions_dir();
            if let Ok(file) = gio::File::for_path(&default_dir).query_info(
                "*",
                gio::FileQueryInfoFlags::NONE,
                gio::Cancellable::NONE,
            ) {
                if file.file_type() == gio::FileType::Directory {
                    dialog.set_initial_folder(Some(&gio::File::for_path(&default_dir)));
                }
            }
            
            let m = model_ref.clone();
            let pm = phase_model_ref.clone();
            let pc = phase_combo_ref.clone();
            let sl = steps_list_ref.clone();
            let tl = title_label_ref.clone();
            let dv = desc_view_ref.clone();
            let nv = notes_view_ref.clone();
            let cb = checkbox_ref.clone();
            let cf = canvas_fixed_ref.clone();
            let ci = canvas_items_ref.clone();
            let handler_id = phase_combo_handler_id_ref.clone();
            dialog.open(Some(&window_ref), None::<&gio::Cancellable>, move |res| {
                if let Ok(file) = res {
                    if let Some(path) = file.path() {
                        match crate::store::load_session(&path) {
                            Ok(sess) => {
                            m.borrow_mut().session = sess;
                            m.borrow_mut().selected_phase = 0;
                            m.borrow_mut().selected_step = None;
                            m.borrow_mut().current_path = Some(path.clone());
                            
                            // Defer ALL UI rebuilding to avoid borrowing conflicts
                            let pm_clone = pm.clone();
                            let sl_clone = sl.clone();
                            let tl_clone = tl.clone();
                            let dv_clone = dv.clone();
                            let nv_clone = nv.clone();
                            let cb_clone = cb.clone();
                            let cf_clone = cf.clone();
                            let ci_clone = ci.clone();
                            let m_clone = m.clone();
                            let pc_clone = pc.clone();
                            glib::idle_add_local_once(move || {
                                // Block the phase combo signal handler to prevent recursive triggering
                                glib::signal::signal_handler_block(&pc_clone, &handler_id);
                                
                                // Create new phase model items
                                let phase_names: Vec<String> = {
                                    let model_borrow = m_clone.borrow();
                                    model_borrow.session.phases.iter().map(|p| p.name.clone()).collect()
                                };
                                
                                // Replace all items in the phase model at once to avoid triggering handlers multiple times
                                let phase_names_refs: Vec<&str> = phase_names.iter().map(|s| s.as_str()).collect();
                                pm_clone.splice(0, pm_clone.n_items(), &phase_names_refs);
                                
                                // Unblock the signal handler
                                glib::signal::signal_handler_unblock(&pc_clone, &handler_id);
                                
                                // Rebuild steps list for the new phase
                                while let Some(child) = sl_clone.first_child() { sl_clone.remove(&child); }
                                
                                // Clone all step data to avoid holding borrows during GTK operations
                                let (selected_phase, steps_data) = {
                                    let model_borrow = m_clone.borrow();
                                    let selected_phase = model_borrow.selected_phase;
                                    let steps_data: Vec<_> = model_borrow.session.phases.get(selected_phase)
                                        .map(|phase| phase.steps.iter().map(|step| {
                                            (step.title.clone(), step.get_description(), 
                                             step.get_description_notes(), step.get_notes(), 
                                             step.status.clone())
                                        }).collect())
                                        .unwrap_or_default();
                                    (selected_phase, steps_data)
                                };

                                for (idx, (title, description, _desc_notes, _notes, status)) in steps_data.iter().enumerate() {
                                    let row = ListBoxRow::new();
                                    let row_box = GtkBox::new(Orientation::Horizontal, 8);

                                    let cb_widget = CheckButton::new();
                                    cb_widget.set_active(matches!(status, StepStatus::Done));
                                    let lbl = Label::new(Some(title));
                                    lbl.set_xalign(0.0);

                                    // Make the label clickable instead of the whole row
                                    let click_controller = gtk4::GestureClick::new();
                                    let model_s = m_clone.clone();
                                    let title_s = tl_clone.clone();
                                    let desc_buf_s = dv_clone.buffer();
                                    let notes_buf_s = nv_clone.buffer();
                                    let checkbox_s = cb_clone.clone();
                                    let canvas_fixed_s = cf_clone.clone();
                                    let canvas_items_s = ci_clone.clone();

                                    click_controller.connect_pressed(move |_, _, _, _| {
                                        let mut model_borrow = model_s.borrow_mut();
                                        model_borrow.selected_step = Some(idx);
                                        let sp = model_borrow.selected_phase;
                                        if let Some(step) = model_borrow.session.phases[sp].steps.get(idx) {
                                            let title = step.title.clone();
                                            let description_notes = step.get_description_notes();
                                            let notes = step.get_notes();
                                            let status = step.status.clone();
                                            let step_clone = step.clone();
                                            drop(model_borrow); // Release borrow before GTK calls
                                            
                                            title_s.set_label(&title);
                                            // Load user notes in description pane
                                            desc_buf_s.set_text(&description_notes);
                                            checkbox_s.set_active(matches!(status, StepStatus::Done));
                                            notes_buf_s.set_text(&notes);

                                            // Load canvas evidence for this step
                                            load_step_evidence(&canvas_fixed_s, canvas_items_s.clone(), &step_clone);
                                            // Focus the canvas so keyboard events work
                                            canvas_fixed_s.grab_focus();
                                        }
                                    });
                                    lbl.add_controller(click_controller);

                                    let info_btn = gtk4::Button::from_icon_name("dialog-information-symbolic");
                                    info_btn.set_valign(gtk4::Align::Center);
                                    info_btn.set_tooltip_text(Some("Show explanation"));

                                    // Create popover upfront with content
                                    let popover = gtk4::Popover::new();
                                    let pop_box = GtkBox::new(Orientation::Vertical, 6);

                                    // Use ScrolledWindow with TextView for long content
                                    let scrolled = ScrolledWindow::new();
                                    scrolled.set_min_content_height(300);
                                    scrolled.set_min_content_width(500);
                                    scrolled.set_max_content_height(500);
                                    scrolled.set_max_content_width(700);
                                    scrolled.set_propagate_natural_height(true);
                                    scrolled.set_propagate_natural_width(true);
                                    let text_view = TextView::new();
                                    text_view.set_editable(false);
                                    text_view.set_wrap_mode(gtk4::WrapMode::Word);
                                    text_view.set_size_request(480, 280);
                                    text_view.buffer().set_text(description);
                                    scrolled.set_child(Some(&text_view));

                                        pop_box.append(&scrolled);
                                        popover.set_child(Some(&pop_box));
                                        popover.set_has_arrow(true);
                                        popover.set_position(gtk4::PositionType::Bottom);

                                        // Set parent and popup on click
                                        let pop_clone = popover.clone();
                                        info_btn.connect_clicked(move |btn| {
                                            pop_clone.set_parent(btn);
                                            pop_clone.popup();
                                        });

                                        row_box.append(&cb_widget);
                                        row_box.append(&lbl);
                                        row_box.append(&info_btn);
                                        row.set_child(Some(&row_box));

                                        // Toggle handler
                                        let model_t = m_clone.clone();
                                        let cb_clone = cb_widget.clone();
                                        cb_clone.connect_toggled(move |c| {
                                            let mut model_borrow = model_t.borrow_mut();
                                            let sp = model_borrow.selected_phase;
                                            if let Some(step) = model_borrow.session.phases.get_mut(sp).and_then(|p| p.steps.get_mut(idx)) {
                                                step.status = if c.is_active() { StepStatus::Done } else { StepStatus::Todo };
                                            }
                                        });

                                        // Prevent checkbox from consuming click events
                                        cb_clone.set_can_focus(false);

                                        sl_clone.append(&row);
                                    }

                                // Auto-select first step and update UI
                                if !steps_data.is_empty() {
                                    m_clone.borrow_mut().selected_step = Some(0);
                                    let step_data = {
                                        let model_borrow_again = m_clone.borrow();
                                        model_borrow_again.session.phases[selected_phase].steps.first().map(|step| (
                                                step.title.clone(),
                                                step.get_description_notes(),
                                                matches!(step.status, StepStatus::Done),
                                                step.get_notes(),
                                                step.clone(),
                                            ))
                                    };
                                    
                                    if let Some((title, desc_notes, is_done, notes, step)) = step_data {
                                        tl_clone.set_label(&title);
                                        dv_clone.buffer().set_text(&desc_notes);
                                        cb_clone.set_active(is_done);
                                        nv_clone.buffer().set_text(&notes);
                                        load_step_evidence(&cf_clone, ci_clone.clone(), &step);
                                        cf_clone.grab_focus();
                                    }
                                }
                            });
                        }
                        Err(err) => {
                            eprintln!("Failed to open: {err:?}");
                        }
                    }
                    }
                }
            });
        });
    }

    // Save button - saves to current path or shows Save As dialog if no path
    {
        let window_ref = window.clone();
        let model_ref = model.clone();
        btn_save.connect_clicked(move |_| {
            // Clone path and session before save to avoid borrow conflicts
            let (path_opt, session) = {
                let borrow = model_ref.borrow();
                (borrow.current_path.clone(), borrow.session.clone())
            };
            
            if let Some(path) = path_opt {
                // Save to existing path
                if let Err(err) = crate::store::save_session(&path, &session) {
                    eprintln!("Failed to save: {err:?}");
                } else {
                    println!("Saved to: {:?}", path);
                }
            } else {
                // No path - show Save As dialog
                let dialog = FileDialog::new();
                dialog.set_title("Save Session As");
                
                // Set initial folder to Downloads/pt-journal-sessions
                let default_dir = crate::store::default_sessions_dir();
                if let Ok(file_info) = gio::File::for_path(&default_dir).query_info(
                    "*",
                    gio::FileQueryInfoFlags::NONE,
                    gio::Cancellable::NONE,
                ) {
                    if file_info.file_type() == gio::FileType::Directory {
                        dialog.set_initial_folder(Some(&gio::File::for_path(&default_dir)));
                    }
                }
                
                let m = model_ref.clone();
                dialog.save(Some(&window_ref), None::<&gio::Cancellable>, move |res| {
                    if let Ok(file) = res {
                        if let Some(path) = file.path() {
                            let session = m.borrow().session.clone();
                            if let Err(err) = crate::store::save_session(&path, &session) {
                                eprintln!("Failed to save: {err:?}");
                            } else {
                                m.borrow_mut().current_path = Some(path.clone());
                                println!("Saved to: {:?}", path);
                            }
                        }
                    }
                });
            }
        });
    }

    // Save As button - always shows dialog to pick new location
    {
        let window_ref = window.clone();
        let model_ref = model.clone();
        btn_save_as.connect_clicked(move |_| {
            let dialog = FileDialog::new();
            dialog.set_title("Save Session As");
            
            // Set initial folder to Downloads/pt-journal-sessions
            let default_dir = crate::store::default_sessions_dir();
            if let Ok(file_info) = gio::File::for_path(&default_dir).query_info(
                "*",
                gio::FileQueryInfoFlags::NONE,
                gio::Cancellable::NONE,
            ) {
                if file_info.file_type() == gio::FileType::Directory {
                    dialog.set_initial_folder(Some(&gio::File::for_path(&default_dir)));
                }
            }
            
            let m = model_ref.clone();
            dialog.save(Some(&window_ref), None::<&gio::Cancellable>, move |res| {
                if let Ok(file) = res {
                    if let Some(path) = file.path() {
                        let session = m.borrow().session.clone();
                        if let Err(err) = crate::store::save_session(&path, &session) {
                            eprintln!("Failed to save as: {err:?}");
                        } else {
                            m.borrow_mut().current_path = Some(path.clone());
                            println!("Saved as: {:?}", path);
                        }
                    }
                }
            });
        });
    }

    // Sidebar collapse state
    let sidebar_collapsed = Rc::new(RefCell::new(false));

    // Sidebar toggle functionality
    {
        let paned_ref = paned_ref.clone();
        let collapsed_ref = sidebar_collapsed.clone();
        btn_sidebar.connect_clicked(move |_| {
            let mut collapsed = collapsed_ref.borrow_mut();
            if *collapsed {
                // Expand sidebar
                paned_ref.set_position(320);
                *collapsed = false;
            } else {
                // Collapse sidebar
                paned_ref.set_position(0);
                *collapsed = true;
            }
        });
    }

    // Setup canvas for evidence
    setup_canvas(&canvas_fixed, canvas_items, model.clone());

    window.present();
}
