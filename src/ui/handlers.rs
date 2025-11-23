use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{ApplicationWindow, Button, CheckButton, ListBox};
use std::cell::RefCell;
use std::rc::Rc;

use crate::model::{AppModel, StepStatus};
use crate::ui::canvas::load_step_evidence;
use crate::ui::detail_panel::DetailPanel;
use crate::ui::state::StateManager;

/// Wire up quiz widget buttons (Check Answer, View Explanation, Previous/Next)
pub fn setup_quiz_handlers(detail_panel: Rc<DetailPanel>, state: Rc<StateManager>) {
    let quiz_widget = &detail_panel.quiz_widget;

    // Check Answer button
    let check_button = quiz_widget.check_button.clone();
    let state_check = state.clone();
    let panel_check = detail_panel.clone();
    check_button.connect_clicked(move |_| {
        let (phase_idx, step_idx, question_idx, selected_answer) = {
            let model_rc = state_check.model();
            let model_borrow = model_rc.borrow();
            (
                model_borrow.selected_phase,
                model_borrow.selected_step,
                panel_check.quiz_widget.current_question(),
                panel_check.quiz_widget.get_selected_answer(),
            )
        };

        if let (Some(step_idx), Some(answer_idx)) = (step_idx, selected_answer) {
            // Use state manager to check answer (dispatches events)
            let is_correct =
                state_check.check_answer(phase_idx, step_idx, question_idx, answer_idx);

            if let Some(correct) = is_correct {
                // Get explanation and quiz step for UI update
                let (explanation, quiz_step_opt) = {
                    let model_rc = state_check.model();
                    let model = model_rc.borrow();
                    let step = model
                        .session
                        .phases
                        .get(phase_idx)
                        .and_then(|p| p.steps.get(step_idx));

                    if let Some(step) = step {
                        if let Some(quiz_step) = step.get_quiz_step() {
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
                panel_check
                    .quiz_widget
                    .show_explanation(&explanation, Some(correct));

                // Update statistics
                if let Some(quiz_step) = quiz_step_opt {
                    panel_check.quiz_widget.update_statistics(&quiz_step);
                }
            }
        }
    });

    // View Explanation button
    let view_explanation_button = quiz_widget.view_explanation_button.clone();
    let state_view = state.clone();
    let panel_view = detail_panel.clone();
    view_explanation_button.connect_clicked(move |_| {
        let (phase_idx, step_idx, question_idx) = {
            let model_rc = state_view.model();
            let model_borrow = model_rc.borrow();
            (
                model_borrow.selected_phase,
                model_borrow.selected_step,
                panel_view.quiz_widget.current_question(),
            )
        };

        if let Some(step_idx) = step_idx {
            // Use state manager to mark explanation viewed (dispatches event)
            state_view.view_explanation(phase_idx, step_idx, question_idx);

            // Get explanation and show it
            let explanation_opt = {
                let model_rc = state_view.model();
                let model_borrow = model_rc.borrow();
                model_borrow
                    .session
                    .phases
                    .get(phase_idx)
                    .and_then(|phase| phase.steps.get(step_idx))
                    .and_then(|step| step.get_quiz_step())
                    .and_then(|quiz_step| quiz_step.questions.get(question_idx))
                    .map(|q| q.explanation.clone())
            };

            if let Some(explanation) = explanation_opt {
                panel_view.quiz_widget.show_explanation(&explanation, None);
            }
        }
    });

    // Previous button
    let prev_button = quiz_widget.prev_button.clone();
    let state_prev = state.clone();
    let panel_prev = detail_panel.clone();
    prev_button.connect_clicked(move |_| {
        let current_idx = panel_prev.quiz_widget.current_question();
        if current_idx > 0 {
            let new_idx = current_idx - 1;
            panel_prev.quiz_widget.set_current_question(new_idx);

            // Dispatch quiz question changed event
            let (phase_idx, step_idx) = {
                let model_rc = state_prev.model();
                let model_borrow = model_rc.borrow();
                (model_borrow.selected_phase, model_borrow.selected_step)
            };
            if let Some(step_idx) = step_idx {
                state_prev.change_quiz_question(phase_idx, step_idx, new_idx);
            }

            // Refresh the display
            let quiz_step_opt = {
                let model_rc = state_prev.model();
                let model_borrow = model_rc.borrow();
                model_borrow
                    .session
                    .phases
                    .get(model_borrow.selected_phase)
                    .and_then(|phase| {
                        model_borrow
                            .selected_step
                            .and_then(|sidx| phase.steps.get(sidx))
                    })
                    .and_then(|step| step.get_quiz_step().cloned())
            };

            if let Some(quiz_step) = quiz_step_opt {
                panel_prev.quiz_widget.refresh_current_question(&quiz_step);
            }
        }
    });

    // Next button
    let next_button = quiz_widget.next_button.clone();
    let state_next = state.clone();
    let panel_next = detail_panel.clone();
    next_button.connect_clicked(move |_| {
        let (current_idx, total_questions) = {
            let current = panel_next.quiz_widget.current_question();
            let model_rc = state_next.model();
            let model_borrow = model_rc.borrow();
            let total = model_borrow
                .session
                .phases
                .get(model_borrow.selected_phase)
                .and_then(|phase| {
                    model_borrow
                        .selected_step
                        .and_then(|sidx| phase.steps.get(sidx))
                })
                .and_then(|step| step.get_quiz_step())
                .map(|quiz_step| quiz_step.questions.len())
                .unwrap_or(0);
            (current, total)
        };

        if current_idx + 1 < total_questions {
            let new_idx = current_idx + 1;
            panel_next.quiz_widget.set_current_question(new_idx);

            // Dispatch quiz question changed event
            let (phase_idx, step_idx) = {
                let model_rc = state_next.model();
                let model_borrow = model_rc.borrow();
                (model_borrow.selected_phase, model_borrow.selected_step)
            };
            if let Some(step_idx) = step_idx {
                state_next.change_quiz_question(phase_idx, step_idx, new_idx);
            }

            // Refresh the display
            let quiz_step_opt = {
                let model_rc = state_next.model();
                let model_borrow = model_rc.borrow();
                model_borrow
                    .session
                    .phases
                    .get(model_borrow.selected_phase)
                    .and_then(|phase| {
                        model_borrow
                            .selected_step
                            .and_then(|sidx| phase.steps.get(sidx))
                    })
                    .and_then(|step| step.get_quiz_step().cloned())
            };

            if let Some(quiz_step) = quiz_step_opt {
                panel_next.quiz_widget.refresh_current_question(&quiz_step);
            }
        }
    });

    // Finish button
    let finish_button = quiz_widget.finish_button.clone();
    let state_finish = state.clone();
    let panel_finish = detail_panel.clone();
    finish_button.connect_clicked(move |_| {
        let (phase_idx, step_idx) = {
            let model_rc = state_finish.model();
            let model_borrow = model_rc.borrow();
            (model_borrow.selected_phase, model_borrow.selected_step)
        };

        if let Some(step_idx) = step_idx {
            // Mark the quiz step as completed
            state_finish.update_step_status(phase_idx, step_idx, StepStatus::Done);

            // Get final statistics
            let (stats, quiz_step_opt) = {
                let model_rc = state_finish.model();
                let model_borrow = model_rc.borrow();
                let step = model_borrow
                    .session
                    .phases
                    .get(phase_idx)
                    .and_then(|phase| phase.steps.get(step_idx));

                if let Some(step) = step {
                    if let Some(quiz_step) = step.get_quiz_step() {
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

                panel_finish
                    .quiz_widget
                    .show_explanation(&completion_message, None);

                // Update statistics display
                panel_finish.quiz_widget.update_statistics(&quiz_step);
            }
        }
    });
}

/// Wire up tool execution panel (info dialog only)
#[allow(deprecated)]
pub fn setup_tool_execution_handlers(
    detail_panel: Rc<DetailPanel>,
    _state: Rc<StateManager>,
    window: &ApplicationWindow,
) {
    let tool_panel = &detail_panel.tool_panel;
    let window_glib = window.clone().upcast::<gtk4::Window>();

    let panel_clone = tool_panel.clone();
    tool_panel
        .info_button
        .connect_clicked(move |_| panel_clone.show_instructions_dialog(&window_glib));
}

/// Wire up phase combo box selection handler
pub fn setup_phase_handler(
    phase_combo: &gtk4::DropDown,
    steps_list: &ListBox,
    state: Rc<StateManager>,
    detail_panel: Rc<DetailPanel>,
) -> Rc<glib::SignalHandlerId> {
    let _phase_model = phase_combo.model().unwrap();
    let steps_list_clone = steps_list.clone();
    let state_clone = state.clone();
    let detail_panel_clone = detail_panel.clone();

    let handler_id = phase_combo.connect_selected_notify(move |combo| {
        let selected = combo.selected();
        // Use state manager to change phase (dispatches events)
        state_clone.select_phase(selected as usize);
        rebuild_steps_list(&steps_list_clone, &state_clone.model(), &detail_panel_clone);
    });
    Rc::new(handler_id)
}

/// Wire up step selection and checkbox handlers
pub fn setup_step_handlers(
    _steps_list: &ListBox,
    _state: Rc<StateManager>,
    _detail_panel: Rc<DetailPanel>,
) {
    // We'll wire up individual step handlers during rebuild_steps_list
    // This function is called once at setup to prepare the container
}

/// Wire up notes text views (description and step notes)
pub fn setup_notes_handlers(detail_panel: Rc<DetailPanel>, state: Rc<StateManager>) {
    let desc_view = detail_panel.desc_view.clone();
    let notes_view = detail_panel.notes_view.clone();

    // Description notes handler
    let state_desc = state.clone();
    desc_view.buffer().connect_changed(move |buffer| {
        let text = buffer
            .text(&buffer.start_iter(), &buffer.end_iter(), false)
            .to_string();
        let (phase_idx, step_idx) = {
            let model_rc = state_desc.model();
            let model = model_rc.borrow();
            (model.selected_phase, model.selected_step)
        };
        if let Some(step_idx) = step_idx {
            // Use state manager to update (dispatches events)
            state_desc.update_step_description_notes(phase_idx, step_idx, text);
        }
    });

    // Step notes handler
    let state_notes = state.clone();
    notes_view.buffer().connect_changed(move |buffer| {
        let text = buffer
            .text(&buffer.start_iter(), &buffer.end_iter(), false)
            .to_string();
        let (phase_idx, step_idx) = {
            let model_rc = state_notes.model();
            let model = model_rc.borrow();
            (model.selected_phase, model.selected_step)
        };
        if let Some(step_idx) = step_idx {
            // Use state manager to update (dispatches events)
            state_notes.update_step_notes(phase_idx, step_idx, text);
        }
    });
}

/// Wire up file operation buttons (Open, Save, Save As)
#[allow(clippy::too_many_arguments)]
pub fn setup_file_handlers(
    btn_open: &Button,
    btn_save: &Button,
    btn_save_as: &Button,
    window: &ApplicationWindow,
    state: Rc<StateManager>,
    detail_panel: Rc<DetailPanel>,
    phase_combo: &gtk4::DropDown,
    phase_combo_handler_id: Rc<glib::SignalHandlerId>,
    steps_list: &ListBox,
) {
    // Cast window to gtk4::Window for file_ops
    let window_glib = window.clone().upcast::<gtk4::Window>();

    // Open button
    let window_open = window_glib.clone();
    let state_open = state.clone();
    let detail_panel_open = detail_panel.clone();
    let phase_combo_open = phase_combo.clone();
    let phase_combo_handler_id_open = phase_combo_handler_id.clone();
    let steps_list_open = steps_list.clone();

    btn_open.connect_clicked(move |_| {
        let window_clone = window_open.clone();
        let state_clone = state_open.clone();
        let detail_panel_clone = detail_panel_open.clone();
        let phase_combo_clone = phase_combo_open.clone();
        let handler_id_clone = phase_combo_handler_id_open.clone();
        let steps_list_clone = steps_list_open.clone();

        crate::ui::file_ops::open_session_dialog(&window_clone, move |session, path| {
            {
                let model_rc = state_clone.model();
                let mut model = model_rc.borrow_mut();
                model.session = session;
                model.current_path = Some(path);
                model.selected_phase = 0;
                model.selected_step = None;
            }

            glib::signal::signal_handler_block(&phase_combo_clone, &handler_id_clone);
            phase_combo_clone.set_selected(0);
            glib::signal::signal_handler_unblock(&phase_combo_clone, &handler_id_clone);

            rebuild_steps_list(&steps_list_clone, &state_clone.model(), &detail_panel_clone);
        });
    });

    // Save button
    let window_save = window_glib.clone();
    let state_save = state.clone();
    btn_save.connect_clicked(move |_| {
        let window_clone = window_save.clone();
        let model_clone = state_save.model();
        crate::ui::file_ops::save_session(&window_clone, model_clone, move |_path| {
            // Saved successfully
        });
    });

    // Save As button
    let window_save_as = window_glib.clone();
    let state_save_as = state.clone();
    btn_save_as.connect_clicked(move |_| {
        let window_clone = window_save_as.clone();
        let model = state_save_as.model();

        let session_clone = model.borrow().session.clone();
        crate::ui::file_ops::save_session_as_dialog(&window_clone, &session_clone, move |path| {
            model.borrow_mut().current_path = Some(path);
        });
    });
}

/// Wire up sidebar toggle button
pub fn setup_sidebar_handler(btn_sidebar: &Button, left_box: &gtk4::Box) {
    let left_box_clone = left_box.clone();
    btn_sidebar.connect_clicked(move |_| {
        left_box_clone.set_visible(!left_box_clone.is_visible());
    });
}

/// Helper function to rebuild the steps list when phase changes
pub fn rebuild_steps_list(
    steps_list: &ListBox,
    model: &Rc<RefCell<AppModel>>,
    detail_panel: &Rc<DetailPanel>,
) {
    // Clear existing rows
    while let Some(child) = steps_list.first_child() {
        steps_list.remove(&child);
    }

    let phase_idx = model.borrow().selected_phase;
    let steps = {
        let model_borrow = model.borrow();
        model_borrow
            .session
            .phases
            .get(phase_idx)
            .map(|phase| phase.steps.clone())
            .unwrap_or_default()
    };

    for (step_idx, step) in steps.iter().enumerate() {
        let row = gtk4::ListBoxRow::new();
        let row_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        row_box.set_margin_start(8);
        row_box.set_margin_end(8);
        row_box.set_margin_top(4);
        row_box.set_margin_bottom(4);

        let checkbox = CheckButton::new();
        checkbox.set_active(matches!(step.status, StepStatus::Done));

        let label = gtk4::Label::new(Some(&step.title));
        label.set_halign(gtk4::Align::Start);
        label.set_hexpand(true);

        // Make entire row clickable for step selection
        let click = gtk4::GestureClick::new();
        let model_row = model.clone();
        let detail_panel_row = detail_panel.clone();
        let steps_list_row = steps_list.clone();
        let row_clone = row.clone();
        click.connect_pressed(move |_, _, _, _| {
            model_row.borrow_mut().selected_step = Some(step_idx);
            load_step_into_panel(&model_row, &detail_panel_row);

            // Update selection styling
            steps_list_row.select_row(Some(&row_clone));
        });
        row.add_controller(click); // Attach to row instead of label

        // Checkbox handler
        let model_checkbox = model.clone();
        checkbox.connect_toggled(move |cb| {
            let is_checked = cb.is_active();
            let mut model_mut = model_checkbox.borrow_mut();
            let phase_idx = model_mut.selected_phase;

            if let Some(step) = model_mut
                .session
                .phases
                .get_mut(phase_idx)
                .and_then(|phase| phase.steps.get_mut(step_idx))
            {
                step.status = if is_checked {
                    StepStatus::Done
                } else {
                    StepStatus::InProgress
                };

                if is_checked {
                    step.completed_at = Some(chrono::Utc::now());
                } else {
                    step.completed_at = None;
                }
            }
        });

        row_box.append(&checkbox);
        row_box.append(&label);
        row.set_child(Some(&row_box));
        steps_list.append(&row);
    }

    // Load first step if available
    if !steps.is_empty() {
        model.borrow_mut().selected_step = Some(0);
        load_step_into_panel(model, detail_panel);
        if let Some(first_row) = steps_list.row_at_index(0) {
            steps_list.select_row(Some(&first_row));
        }
    } else {
        clear_detail_panel(detail_panel);
    }
}

/// Helper function to load a step into the detail panel
pub fn load_step_into_panel(model: &Rc<RefCell<AppModel>>, detail_panel: &Rc<DetailPanel>) {
    let (step_opt, _phase_idx, _step_idx, session_path) = {
        let model_borrow = model.borrow();
        let phase_idx = model_borrow.selected_phase;
        let step_idx = model_borrow.selected_step;
        let step = step_idx.and_then(|sidx| {
            model_borrow
                .session
                .phases
                .get(phase_idx)
                .and_then(|phase| phase.steps.get(sidx))
                .cloned()
        });
        let session_path = model_borrow.current_path.clone();
        (step, phase_idx, step_idx, session_path)
    };

    if let Some(step) = step_opt {
        // Check if this is a quiz step
        if let Some(quiz_step) = step.get_quiz_step() {
            // Show quiz view
            detail_panel.content_stack.set_visible_child_name("quiz");

            // Load the quiz
            detail_panel.quiz_widget.load_quiz_step(quiz_step);
        } else {
            // Show tutorial view
            detail_panel
                .content_stack
                .set_visible_child_name("tutorial");

            // Update checkbox
            detail_panel
                .checkbox
                .set_active(matches!(step.status, StepStatus::Done));

            // Update title
            detail_panel.title_label.set_text(&step.title);

            // Update description (with user notes if any)
            let desc_text = if step.get_description_notes().is_empty() {
                step.get_description().to_string()
            } else {
                step.get_description_notes()
            };
            detail_panel.desc_view.buffer().set_text(&desc_text);

            // Update notes
            detail_panel.notes_view.buffer().set_text(&step.get_notes());

            // Load canvas evidence with session path for resolving relative paths
            load_step_evidence(
                &detail_panel.canvas_fixed,
                detail_panel.canvas_items.clone(),
                &step,
                session_path.as_deref(),
            );
        }
    }
}

/// Helper function to clear the detail panel
pub fn clear_detail_panel(detail_panel: &Rc<DetailPanel>) {
    detail_panel.checkbox.set_active(false);
    detail_panel.title_label.set_text("");
    detail_panel.desc_view.buffer().set_text("");
    detail_panel.notes_view.buffer().set_text("");

    // Clear canvas
    detail_panel.canvas_items.borrow_mut().clear();
    while let Some(child) = detail_panel.canvas_fixed.first_child() {
        detail_panel.canvas_fixed.remove(&child);
    }
}
