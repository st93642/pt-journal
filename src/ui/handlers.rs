use gtk4::prelude::*;
use gtk4::glib;
use gtk4::{ApplicationWindow, ListBox, CheckButton, Button};
use std::rc::Rc;
use std::cell::RefCell;
use std::path::{Path, PathBuf};

use crate::model::{AppModel, StepStatus, Evidence};
use crate::ui::canvas::load_step_evidence;
use crate::ui::detail_panel::DetailPanel;

/// Helper function to get the evidence directory path
/// Works with new folder structure: session-name/session.json and session-name/evidence/
fn get_evidence_dir(session_path: Option<&Path>) -> PathBuf {
    match session_path {
        Some(path) => {
            // New format: session-name/session.json → session-name/evidence/
            // Old format: /path/to/session.json → /path/to/evidence/
            let session_dir = if path.file_name() == Some(std::ffi::OsStr::new("session.json")) {
                // New format: use parent directory of session.json
                path.parent().unwrap_or(path)
            } else {
                // Old format or direct parent path
                path.parent().unwrap_or(Path::new("."))
            };
            
            let evidence_dir = session_dir.join("evidence");
            let _ = std::fs::create_dir_all(&evidence_dir);
            evidence_dir
        }
        None => {
            let evidence_dir = PathBuf::from("./evidence");
            let _ = std::fs::create_dir_all(&evidence_dir);
            evidence_dir
        }
    }
}

/// Save tool execution output to a text file and return Evidence object
fn save_tool_output(
    tool_name: &str,
    target: &str,
    stdout: &str,
    stderr: &str,
    exit_code: i32,
    duration_secs: f64,
    session_path: Option<&Path>,
) -> Option<Evidence> {
    let evidence_dir = get_evidence_dir(session_path);
    
    // Create filename: toolname_target_MonDDHHMM_exitcode.txt
    let now = chrono::Local::now();
    let timestamp = now.format("%b%d%H%M").to_string();  // e.g., Nov0214:30 -> Nov021430
    let safe_target = target.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
    let safe_target = if safe_target.len() > 50 {
        &safe_target[..50]
    } else {
        &safe_target
    };
    let filename = format!("{}_{}_{}_{}.txt", tool_name, safe_target, timestamp, exit_code);
    let file_path = evidence_dir.join(&filename);
    
    // Create content with metadata and output
    let mut content = String::new();
    content.push_str(&format!("Tool: {}\n", tool_name));
    content.push_str(&format!("Target: {}\n", target));
    content.push_str(&format!("Exit Code: {}\n", exit_code));
    content.push_str(&format!("Duration: {:.2}s\n", duration_secs));
    content.push_str(&format!("Timestamp: {}\n", chrono::Utc::now().to_rfc3339()));
    content.push_str("\n");
    content.push_str("=".repeat(80).as_str());
    content.push_str("\n\n");
    
    if !stdout.is_empty() {
        content.push_str("=== STDOUT ===\n\n");
        content.push_str(stdout);
        content.push_str("\n\n");
    }
    
    if !stderr.is_empty() {
        content.push_str("=== STDERR ===\n\n");
        content.push_str(stderr);
        content.push_str("\n");
    }
    
    // Write to file
    match std::fs::write(&file_path, content) {
        Ok(_) => {
            // Create Evidence object with relative path
            let relative_path = format!("evidence/{}", filename);
            Some(Evidence {
                id: uuid::Uuid::new_v4(),
                path: relative_path,
                kind: format!("{}-output", tool_name),
                x: 0.0,
                y: 0.0,
                created_at: chrono::Utc::now(),
            })
        }
        Err(e) => {
            eprintln!("Failed to save tool output to {}: {}", file_path.display(), e);
            None
        }
    }
}

/// Wire up quiz widget buttons (Check Answer, View Explanation, Previous/Next)
pub fn setup_quiz_handlers(
    detail_panel: Rc<DetailPanel>,
    model: Rc<RefCell<AppModel>>,
) {
    let quiz_widget = &detail_panel.quiz_widget;
    
    // Check Answer button
    let check_button = quiz_widget.check_button.clone();
    let model_check = model.clone();
    let panel_check = detail_panel.clone();
    check_button.connect_clicked(move |_| {
        let (phase_idx, step_idx, question_idx, selected_answer) = {
            let model_borrow = model_check.borrow();
            (
                model_borrow.selected_phase,
                model_borrow.selected_step,
                panel_check.quiz_widget.current_question(),
                panel_check.quiz_widget.get_selected_answer()
            )
        };
        
        if let (Some(step_idx), Some(answer_idx)) = (step_idx, selected_answer) {
            // Update the model with the answer
            let (is_correct, explanation, quiz_step_opt) = {
                let mut model_mut = model_check.borrow_mut();
                if let Some(step) = model_mut.session.phases.get_mut(phase_idx)
                    .and_then(|phase| phase.steps.get_mut(step_idx))
                {
                    if let Some(quiz_step) = step.quiz_mut_safe() {
                        // Check answer correctness
                        let is_correct = quiz_step.questions.get(question_idx)
                            .and_then(|q| q.answers.get(answer_idx))
                            .map(|a| a.is_correct)
                            .unwrap_or(false);
                        
                        // Update progress
                        if let Some(progress) = quiz_step.progress.get_mut(question_idx) {
                            let first_attempt = progress.attempts == 0;
                            progress.answered = true;
                            progress.selected_answer_index = Some(answer_idx);
                            progress.is_correct = Some(is_correct);
                            progress.attempts += 1;
                            progress.last_attempted = Some(chrono::Utc::now());
                            
                            if first_attempt && is_correct && !progress.explanation_viewed_before_answer {
                                progress.first_attempt_correct = true;
                            }
                        }
                        
                        // Get explanation
                        let explanation = quiz_step.questions.get(question_idx)
                            .map(|q| q.explanation.clone())
                            .unwrap_or_default();
                        
                        (is_correct, explanation, Some(quiz_step.clone()))
                    } else {
                        (false, String::new(), None)
                    }
                } else {
                    (false, String::new(), None)
                }
            };
            
            // Show explanation with result
            panel_check.quiz_widget.show_explanation(&explanation, Some(is_correct));
            
            // Update statistics
            if let Some(quiz_step) = quiz_step_opt {
                panel_check.quiz_widget.update_statistics(&quiz_step);
            }
        }
    });
    
    // View Explanation button
    let view_explanation_button = quiz_widget.view_explanation_button.clone();
    let model_view = model.clone();
    let panel_view = detail_panel.clone();
    view_explanation_button.connect_clicked(move |_| {
        let (phase_idx, step_idx, question_idx) = {
            let model_borrow = model_view.borrow();
            (
                model_borrow.selected_phase,
                model_borrow.selected_step,
                panel_view.quiz_widget.current_question()
            )
        };
        
        if let Some(step_idx) = step_idx {
            // Mark that explanation was viewed before answering
            {
                let mut model_mut = model_view.borrow_mut();
                if let Some(step) = model_mut.session.phases.get_mut(phase_idx)
                    .and_then(|phase| phase.steps.get_mut(step_idx))
                {
                    if let Some(quiz_step) = step.quiz_mut_safe() {
                        if let Some(progress) = quiz_step.progress.get_mut(question_idx) {
                            if progress.attempts == 0 {
                                progress.explanation_viewed_before_answer = true;
                            }
                        }
                    }
                }
            }
            
            // Get explanation and show it
            let explanation_opt = {
                let model_borrow = model_view.borrow();
                model_borrow.session.phases.get(phase_idx)
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
    let model_prev = model.clone();
    let panel_prev = detail_panel.clone();
    prev_button.connect_clicked(move |_| {
        let current_idx = panel_prev.quiz_widget.current_question();
        if current_idx > 0 {
            let new_idx = current_idx - 1;
            panel_prev.quiz_widget.set_current_question(new_idx);
            
            // Refresh the display
            let quiz_step_opt = {
                let model_borrow = model_prev.borrow();
                model_borrow.session.phases.get(model_borrow.selected_phase)
                    .and_then(|phase| model_borrow.selected_step.and_then(|sidx| phase.steps.get(sidx)))
                    .and_then(|step| step.get_quiz_step().cloned())
            };
            
            if let Some(quiz_step) = quiz_step_opt {
                panel_prev.quiz_widget.refresh_current_question(&quiz_step);
            }
        }
    });
    
    // Next button
    let next_button = quiz_widget.next_button.clone();
    let model_next = model.clone();
    let panel_next = detail_panel.clone();
    next_button.connect_clicked(move |_| {
        let (current_idx, total_questions) = {
            let current = panel_next.quiz_widget.current_question();
            let model_borrow = model_next.borrow();
            let total = model_borrow.session.phases.get(model_borrow.selected_phase)
                .and_then(|phase| model_borrow.selected_step.and_then(|sidx| phase.steps.get(sidx)))
                .and_then(|step| step.get_quiz_step())
                .map(|quiz_step| quiz_step.questions.len())
                .unwrap_or(0);
            (current, total)
        };
        
        if current_idx + 1 < total_questions {
            let new_idx = current_idx + 1;
            panel_next.quiz_widget.set_current_question(new_idx);
            
            // Refresh the display
            let quiz_step_opt = {
                let model_borrow = model_next.borrow();
                model_borrow.session.phases.get(model_borrow.selected_phase)
                    .and_then(|phase| model_borrow.selected_step.and_then(|sidx| phase.steps.get(sidx)))
                    .and_then(|step| step.get_quiz_step().cloned())
            };
            
            if let Some(quiz_step) = quiz_step_opt {
                panel_next.quiz_widget.refresh_current_question(&quiz_step);
            }
        }
    });
}

/// Wire up tool execution panel (Execute button, tool selector)
#[allow(deprecated)]
pub fn setup_tool_execution_handlers(
    detail_panel: Rc<DetailPanel>,
    model: Rc<RefCell<AppModel>>,
    window: &ApplicationWindow,
) {
    let tool_panel = &detail_panel.tool_panel;
    let window_glib = window.clone().upcast::<gtk4::Window>();
    
    // Wire up info button to show instructions
    let window_info = window_glib.clone();
    let tool_panel_info = tool_panel.clone();
    tool_panel.info_button.connect_clicked(move |_| {
        tool_panel_info.show_instructions_dialog(&window_info);
    });
    
    // Clone all widgets needed BEFORE closure
    let execute_button = tool_panel.execute_button.clone();
    let tool_selector = tool_panel.tool_selector.clone();
    let target_entry = tool_panel.target_entry.clone();
    let args_entry = tool_panel.args_entry.clone();
    let spinner = tool_panel.spinner.clone();
    let status_label = tool_panel.status_label.clone();
    let output_view = tool_panel.output_view.clone();
    
    execute_button.clone().connect_clicked(move |_| {
        // Get inputs
        let tool_id = tool_selector.active_id().map(|s| s.to_string());
        let target = target_entry.text().to_string();
        let args_text = args_entry.text().to_string();
        let args: Vec<String> = args_text.split_whitespace().map(|s| s.to_string()).collect();
        
        // Validate
        if tool_id.is_none() {
            status_label.set_text("Error: No tool selected");
            return;
        }
        
        if target.trim().is_empty() {
            status_label.set_text("Error: Target required");
            return;
        }
        
        let tool_name = tool_id.unwrap();
        
        // Check if session exists, if not prompt for save
        let session_path = model.borrow().current_path.clone();
        if session_path.is_none() {
            // Prompt user to save session first
            let window_clone = window_glib.clone();
            let model_clone = model.clone();
            let status_clone = status_label.clone();
            
            status_label.set_text("Please save session first...");
            
            // Use file_ops to save session with dialog
            let session = model_clone.borrow().session.clone();
            crate::ui::file_ops::save_session_as_dialog(&window_clone, &session, move |path| {
                model_clone.borrow_mut().current_path = Some(path);
                status_clone.set_text("Session saved. Click Execute again.");
            });
            return;
        }
        
        // Prompt for root password
        let password = crate::ui::tool_execution::show_password_dialog(&window_glib);
        
        // Check if user cancelled
        if password.is_none() {
            status_label.set_text("Authentication cancelled");
            return;
        }
        
        let password = password.unwrap();
        
        // Clear previous output
        output_view.buffer().set_text("");
        
        // Show executing state
        spinner.set_visible(true);
        spinner.start();
        execute_button.set_sensitive(false);
        status_label.set_text("Authenticating and executing...");
        
        // Clone for channel-based execution
        let tool_name_thread = tool_name.clone();
        let target_thread = target.clone();
        let args_thread = args.clone();
        let password_thread = password.clone();
        
        // Create channel using async-channel
        let (sender, receiver) = async_channel::bounded(1);
        
        // Execute in separate thread with sudo
        std::thread::spawn(move || {
            let result = crate::ui::tool_execution::execute_tool_sync_wrapper(
                &tool_name_thread,
                &target_thread,
                &args_thread,
                Some(&password_thread)
            );
            let _ = sender.send_blocking(result);
        });
        
        // Handle result on main thread
        let spinner_result = spinner.clone();
        let execute_button_result = execute_button.clone();
        let status_label_result = status_label.clone();
        let output_view_result = output_view.clone();
        let model_result = model.clone();
        let tool_name_result = tool_name.clone();
        let target_result = target.clone();
        
        glib::spawn_future_local(async move {
            if let Ok(result) = receiver.recv().await {
                spinner_result.stop();
                spinner_result.set_visible(false);
                execute_button_result.set_sensitive(true);
                
                match result {
                    Ok(exec_result) => {
                        // Save output to file
                        let session_path = model_result.borrow().current_path.clone();
                        let evidence = save_tool_output(
                            &tool_name_result,
                            &target_result,
                            &exec_result.stdout,
                            &exec_result.stderr,
                            exec_result.exit_code,
                            exec_result.duration.as_secs_f64(),
                            session_path.as_deref(),
                        );
                        
                        // Add evidence to current step if save succeeded
                        if let Some(evidence) = evidence {
                            let mut model_mut = model_result.borrow_mut();
                            let phase_idx = model_mut.selected_phase;
                            if let Some(step_idx) = model_mut.selected_step {
                                if let Some(step) = model_mut.session.phases.get_mut(phase_idx)
                                    .and_then(|phase| phase.steps.get_mut(step_idx))
                                {
                                    step.evidence.push(evidence.clone());
                                }
                            }
                            
                            status_label_result.set_text(&format!(
                                "Complete (exit code: {}, duration: {:.2}s) - Saved to {}",
                                exec_result.exit_code,
                                exec_result.duration.as_secs_f64(),
                                evidence.path
                            ));
                        } else {
                            status_label_result.set_text(&format!(
                                "Complete (exit code: {}, duration: {:.2}s) - Failed to save output",
                                exec_result.exit_code,
                                exec_result.duration.as_secs_f64()
                            ));
                        }
                        
                        let buffer = output_view_result.buffer();
                        let mut output = String::new();
                        
                        // Add stdout
                        if !exec_result.stdout.is_empty() {
                            output.push_str("=== STDOUT ===\n");
                            output.push_str(&exec_result.stdout);
                            output.push_str("\n\n");
                        }
                        
                        // Add stderr
                        if !exec_result.stderr.is_empty() {
                            output.push_str("=== STDERR ===\n");
                            output.push_str(&exec_result.stderr);
                            output.push_str("\n\n");
                        }
                        
                        // Add evidence info
                        if !exec_result.evidence.is_empty() {
                            output.push_str(&format!("=== EVIDENCE ({} items) ===\n", exec_result.evidence.len()));
                            for evidence in &exec_result.evidence {
                                output.push_str(&format!("- {} ({})\n", evidence.path, evidence.kind));
                            }
                        }
                        
                        buffer.set_text(&output);
                    }
                    Err(e) => {
                        // Check if it's an authentication error
                        if e.contains("Authentication failed") || e.contains("Incorrect password") {
                            status_label_result.set_text("❌ Authentication failed - Incorrect password");
                            output_view_result.buffer().set_text(&format!(
                                "Authentication Error\n\n{}\n\n\
                                Please try again and ensure you enter the correct system password.\n\
                                Note: This is your sudo/root password, not the application password.",
                                e
                            ));
                        } else {
                            status_label_result.set_text(&format!("Failed: {}", e));
                            output_view_result.buffer().set_text(&format!("Error: {}", e));
                        }
                    }
                }
            }
        });
    });
    
    // Connect tool selector change to update placeholders
    let tool_selector_change = tool_panel.tool_selector.clone();
    let target_entry_change = tool_panel.target_entry.clone();
    let args_entry_change = tool_panel.args_entry.clone();
    
    tool_selector_change.connect_changed(move |combo| {
        if let Some(tool_id) = combo.active_id() {
            let tool_id_str = tool_id.as_str();
            match tool_id_str {
                "nmap" => {
                    target_entry_change.set_placeholder_text(Some("e.g., scanme.nmap.org or 192.168.1.1"));
                    args_entry_change.set_placeholder_text(Some("e.g., -p 80,443 -sV"));
                }
                "gobuster" => {
                    target_entry_change.set_placeholder_text(Some("e.g., http://example.com or example.com"));
                    args_entry_change.set_placeholder_text(Some("e.g., dir -w /path/to/wordlist.txt"));
                }
                _ => {}
            }
        }
    });
}

/// Wire up phase combo box selection handler
pub fn setup_phase_handler(
    phase_combo: &gtk4::DropDown,
    steps_list: &ListBox,
    model: Rc<RefCell<AppModel>>,
    detail_panel: Rc<DetailPanel>,
) -> Rc<glib::SignalHandlerId> {
    let _phase_model = phase_combo.model().unwrap();
    let steps_list_clone = steps_list.clone();
    let model_clone = model.clone();
    let detail_panel_clone = detail_panel.clone();
    
    let handler_id = phase_combo.connect_selected_notify(move |combo| {
        let selected = combo.selected();
        model_clone.borrow_mut().selected_phase = selected as usize;
        model_clone.borrow_mut().selected_step = None;
        rebuild_steps_list(&steps_list_clone, &model_clone, &detail_panel_clone);
    });
    
    Rc::new(handler_id)
}

/// Wire up step selection and checkbox handlers
pub fn setup_step_handlers(
    _steps_list: &ListBox,
    _model: Rc<RefCell<AppModel>>,
    _detail_panel: Rc<DetailPanel>,
) {
    // We'll wire up individual step handlers during rebuild_steps_list
    // This function is called once at setup to prepare the container
}

/// Wire up notes text views (description and step notes)
pub fn setup_notes_handlers(
    detail_panel: Rc<DetailPanel>,
    model: Rc<RefCell<AppModel>>,
) {
    let desc_view = detail_panel.desc_view.clone();
    let notes_view = detail_panel.notes_view.clone();
    
    // Description notes handler
    let model_desc = model.clone();
    desc_view.buffer().connect_changed(move |buffer| {
        let text = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false).to_string();
        let mut model_mut = model_desc.borrow_mut();
        let phase_idx = model_mut.selected_phase;
        if let Some(step_idx) = model_mut.selected_step {
            if let Some(step) = model_mut.session.phases.get_mut(phase_idx)
                .and_then(|phase| phase.steps.get_mut(step_idx))
            {
                step.set_description_notes(text);
            }
        }
    });
    
    // Step notes handler
    let model_notes = model.clone();
    notes_view.buffer().connect_changed(move |buffer| {
        let text = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false).to_string();
        let mut model_mut = model_notes.borrow_mut();
        let phase_idx = model_mut.selected_phase;
        if let Some(step_idx) = model_mut.selected_step {
            if let Some(step) = model_mut.session.phases.get_mut(phase_idx)
                .and_then(|phase| phase.steps.get_mut(step_idx))
            {
                step.set_notes(text);
            }
        }
    });
}

/// Wire up file operation buttons (Open, Save, Save As)
pub fn setup_file_handlers(
    btn_open: &Button,
    btn_save: &Button,
    btn_save_as: &Button,
    window: &ApplicationWindow,
    model: Rc<RefCell<AppModel>>,
    detail_panel: Rc<DetailPanel>,
    phase_combo: &gtk4::DropDown,
    phase_combo_handler_id: Rc<glib::SignalHandlerId>,
    steps_list: &ListBox,
) {
    // Cast window to gtk4::Window for file_ops
    let window_glib = window.clone().upcast::<gtk4::Window>();
    
    // Open button
    let window_open = window_glib.clone();
    let model_open = model.clone();
    let detail_panel_open = detail_panel.clone();
    let phase_combo_open = phase_combo.clone();
    let phase_combo_handler_id_open = phase_combo_handler_id.clone();
    let steps_list_open = steps_list.clone();
    
    btn_open.connect_clicked(move |_| {
        let window_clone = window_open.clone();
        let model_clone = model_open.clone();
        let detail_panel_clone = detail_panel_open.clone();
        let phase_combo_clone = phase_combo_open.clone();
        let handler_id_clone = phase_combo_handler_id_open.clone();
        let steps_list_clone = steps_list_open.clone();
        
        crate::ui::file_ops::open_session_dialog(&window_clone, move |session, path| {
            model_clone.borrow_mut().session = session;
            model_clone.borrow_mut().current_path = Some(path);
            model_clone.borrow_mut().selected_phase = 0;
            model_clone.borrow_mut().selected_step = None;
            
            glib::signal::signal_handler_block(&phase_combo_clone, &*handler_id_clone);
            phase_combo_clone.set_selected(0);
            glib::signal::signal_handler_unblock(&phase_combo_clone, &*handler_id_clone);
            
            rebuild_steps_list(&steps_list_clone, &model_clone, &detail_panel_clone);
        });
    });
    
    // Save button
    let window_save = window_glib.clone();
    let model_save = model.clone();
    btn_save.connect_clicked(move |_| {
        let window_clone = window_save.clone();
        let model_clone = model_save.clone();
        crate::ui::file_ops::save_session(&window_clone, model_clone, move |_path| {
            // Saved successfully
        });
    });
    
    // Save As button
    let window_save_as = window_glib.clone();
    let model_save_as = model.clone();
    btn_save_as.connect_clicked(move |_| {
        let window_clone = window_save_as.clone();
        let model_clone = model_save_as.clone();
        
        let session_clone = model_clone.borrow().session.clone();
        crate::ui::file_ops::save_session_as_dialog(&window_clone, &session_clone, move |path| {
            model_clone.borrow_mut().current_path = Some(path);
        });
    });
}

/// Wire up sidebar toggle button
pub fn setup_sidebar_handler(
    btn_sidebar: &Button,
    left_box: &gtk4::Box,
) {
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
        model_borrow.session.phases.get(phase_idx)
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
        row.add_controller(click);  // Attach to row instead of label
        
        // Checkbox handler
        let model_checkbox = model.clone();
        checkbox.connect_toggled(move |cb| {
            let is_checked = cb.is_active();
            let mut model_mut = model_checkbox.borrow_mut();
            let phase_idx = model_mut.selected_phase;
            
            if let Some(step) = model_mut.session.phases.get_mut(phase_idx)
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
pub fn load_step_into_panel(
    model: &Rc<RefCell<AppModel>>,
    detail_panel: &Rc<DetailPanel>,
) {
    let (step_opt, _phase_idx, _step_idx) = {
        let model_borrow = model.borrow();
        let phase_idx = model_borrow.selected_phase;
        let step_idx = model_borrow.selected_step;
        let step = step_idx.and_then(|sidx| {
            model_borrow.session.phases.get(phase_idx)
                .and_then(|phase| phase.steps.get(sidx))
                .cloned()
        });
        (step, phase_idx, step_idx)
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
            detail_panel.content_stack.set_visible_child_name("tutorial");
            
            // Update checkbox
            detail_panel.checkbox.set_active(matches!(step.status, StepStatus::Done));
            
            // Update title
            detail_panel.title_label.set_text(&step.title);
            
            // Update description (with user notes if any)
            let desc_text = if step.description_notes.is_empty() {
                step.get_description().to_string()
            } else {
                step.description_notes.clone()
            };
            detail_panel.desc_view.buffer().set_text(&desc_text);
            
            // Update notes
            detail_panel.notes_view.buffer().set_text(&step.get_notes());
            
            // Load canvas evidence
            load_step_evidence(
                &detail_panel.canvas_fixed,
                detail_panel.canvas_items.clone(),
                &step
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
