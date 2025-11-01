use gtk4::prelude::*;
use gtk4::glib;
use gtk4::{Application, ApplicationWindow, Box as GtkBox, Orientation, ScrolledWindow, CheckButton, Label, TextView, ListBoxRow, FileDialog, gdk, Paned};
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
    let (header, btn_open, btn_save, btn_sidebar) = crate::ui::header_bar::create_header_bar();
    window.set_titlebar(Some(&header));

    // Left panel: phase selector + steps list
    let (left_box, phase_model, phase_combo, steps_list) = crate::ui::sidebar::create_sidebar(&model);

    // Right panel: detail view with checkbox, title, description, notes, canvas
    let detail_panel = crate::ui::detail_panel::create_detail_panel();
    let right = detail_panel.container;
    let checkbox = detail_panel.checkbox;
    let title_label = detail_panel.title_label;
    let desc_view = detail_panel.desc_view;
    let notes_view = detail_panel.notes_view;
    let canvas_fixed = detail_panel.canvas_fixed;
    let canvas_items = detail_panel.canvas_items;

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
        move || {
            // clear
            while let Some(child) = steps_list_ref.first_child() { steps_list_ref.remove(&child); }
            let model_borrow = model_rc.borrow();
            let selected_phase = model_borrow.selected_phase;
            if let Some(phase) = model_borrow.session.phases.get(selected_phase) {
            for (idx, step) in phase.steps.iter().enumerate() {
                let row = ListBoxRow::new();
                let row_box = GtkBox::new(Orientation::Horizontal, 8);
                
                let cb = CheckButton::new();
                cb.set_active(matches!(step.status, StepStatus::Done));
                let lbl = Label::new(Some(&step.title));
                lbl.set_xalign(0.0);
                
                // Make the label clickable instead of the whole row
                let click_controller = gtk4::GestureClick::new();
                let model_s = model_rc.clone();
                let title_s = title_label_ref.clone();
                let desc_buf_s = desc_view_ref.buffer();
                let notes_buf_s = notes_view_ref.buffer();
                let checkbox_s = checkbox_ref.clone();
                let canvas_fixed_s = canvas_fixed_ref.clone();
                let canvas_items_s = canvas_items_ref.clone();
                
                click_controller.connect_pressed(move |_, _, _, _| {
                    let mut model_borrow = model_s.borrow_mut();
                    model_borrow.selected_step = Some(idx);
                    let sp = model_borrow.selected_phase;
                    if let Some(step) = model_borrow.session.phases[sp].steps.get(idx) {
                        title_s.set_label(&step.title);
                        // Load user notes in description pane
                        desc_buf_s.set_text(&step.description_notes);
                        checkbox_s.set_active(matches!(step.status, StepStatus::Done));
                        notes_buf_s.set_text(&step.notes);

                        // Load canvas evidence for this step
                        load_step_evidence(&canvas_fixed_s, canvas_items_s.clone(), step);
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
                text_view.buffer().set_text(&step.description);
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
            let selected_step = model_borrow.selected_step;
            if let Some(selected_idx) = selected_step {
                if let Some(step) = phase.steps.get(selected_idx) {
                    title_label_ref.set_label(&step.title);
                    // Load user notes in description pane
                    let desc_buffer = desc_view_ref.buffer();
                    desc_buffer.set_text(&step.description_notes);
                    checkbox_ref.set_active(matches!(step.status, StepStatus::Done));
                    notes_view_ref.buffer().set_text(&step.notes);

                    // Load canvas evidence for this step
                    load_step_evidence(&canvas_fixed_ref, canvas_items_ref.clone(), step);
                    // Focus the canvas so keyboard events work
                    canvas_fixed_ref.grab_focus();
                }
            } else if !phase.steps.is_empty() {
                drop(model_borrow); // Release the immutable borrow before getting mutable
                model_rc.borrow_mut().selected_step = Some(0);
                let model_borrow_again = model_rc.borrow();
                if let Some(step) = model_borrow_again.session.phases[model_borrow_again.selected_phase].steps.first() {
                    title_label_ref.set_label(&step.title);
                    // Load user notes in description pane
                    let desc_buffer = desc_view_ref.buffer();
                    desc_buffer.set_text(&step.description_notes);
                    checkbox_ref.set_active(matches!(step.status, StepStatus::Done));
                    notes_view_ref.buffer().set_text(&step.notes);

                    // Load canvas evidence for this step
                    load_step_evidence(&canvas_fixed_ref, canvas_items_ref.clone(), step);
                    // Focus the canvas so keyboard events work
                    canvas_fixed_ref.grab_focus();
                }
            }
        }
        }
    };

    // Initial populate
    rebuild_steps();

    // Notes update
    {
        let model_notes = model.clone();
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
                    step.notes = text.to_string();
                }
            }
        });
    }

    // Description update (for user notes in description area)
    {
        let model_desc = model.clone();
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
                    step.description_notes = text.to_string();
                }
            }
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

            let model_borrow = model_phase.borrow();
            let selected_phase = model_borrow.selected_phase;
            if let Some(phase) = model_borrow.session.phases.get(selected_phase) {
                for (idx, step) in phase.steps.iter().enumerate() {
                    let row = ListBoxRow::new();
                    let row_box = GtkBox::new(Orientation::Horizontal, 8);

                    let cb = CheckButton::new();
                    cb.set_active(matches!(step.status, StepStatus::Done));
                    let lbl = Label::new(Some(&step.title));
                    lbl.set_xalign(0.0);

                    // Make the label clickable instead of the whole row
                    let click_controller = gtk4::GestureClick::new();
                    let model_s = model_phase.clone();
                    let title_s = title_label_ref.clone();
                    let desc_buf_s = desc_view_ref.buffer();
                    let notes_buf_s = notes_view_ref.buffer();
                    let checkbox_s = checkbox_ref.clone();
                    let canvas_fixed_s = canvas_fixed_ref.clone();
                    let canvas_items_s = canvas_items_ref.clone();

                    click_controller.connect_pressed(move |_, _, _, _| {
                        let mut model_borrow = model_s.borrow_mut();
                        model_borrow.selected_step = Some(idx);
                        let sp = model_borrow.selected_phase;
                        if let Some(step) = model_borrow.session.phases[sp].steps.get(idx) {
                            title_s.set_label(&step.title);
                            // Load user notes in description pane
                            desc_buf_s.set_text(&step.description_notes);
                            checkbox_s.set_active(matches!(step.status, StepStatus::Done));
                            notes_buf_s.set_text(&step.notes);

                            // Load canvas evidence for this step
                            load_step_evidence(&canvas_fixed_s, canvas_items_s.clone(), step);
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
                    text_view.buffer().set_text(&step.description);
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
                if !phase.steps.is_empty() {
                    drop(model_borrow); // Release immutable borrow
                    {
                        let mut model_borrow_mut = model_phase.borrow_mut();
                        model_borrow_mut.selected_step = Some(0);
                    }
                    let model_borrow_again = model_phase.borrow();
                    if let Some(step) = model_borrow_again.session.phases[selected_phase].steps.first() {
                        title_label_ref.set_label(&step.title);
                        // Load user notes in description pane
                        let desc_buffer = desc_view_ref.buffer();
                        desc_buffer.set_text(&step.description_notes);
                        checkbox_ref.set_active(matches!(step.status, StepStatus::Done));
                        notes_view_ref.buffer().set_text(&step.notes);

                        // Load canvas evidence for this step
                        load_step_evidence(&canvas_fixed_ref, canvas_items_ref.clone(), step);
                        // Focus the canvas so keyboard events work
                        canvas_fixed_ref.grab_focus();
                    }
                }
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
                                let model_borrow = m_clone.borrow();
                                let phase_names: Vec<&str> = model_borrow.session.phases.iter().map(|p| p.name.as_str()).collect();
                                
                                // Replace all items in the phase model at once to avoid triggering handlers multiple times
                                pm_clone.splice(0, pm_clone.n_items(), &phase_names);
                                
                                // Unblock the signal handler
                                glib::signal::signal_handler_unblock(&pc_clone, &handler_id);
                                
                                // Rebuild steps list for the new phase
                                while let Some(child) = sl_clone.first_child() { sl_clone.remove(&child); }
                                let model_borrow = m_clone.borrow();
                                let selected_phase = model_borrow.selected_phase;
                                if let Some(phase) = model_borrow.session.phases.get(selected_phase) {
                                    for (idx, step) in phase.steps.iter().enumerate() {
                                        let row = ListBoxRow::new();
                                        let row_box = GtkBox::new(Orientation::Horizontal, 8);

                                        let cb_widget = CheckButton::new();
                                        cb_widget.set_active(matches!(step.status, StepStatus::Done));
                                        let lbl = Label::new(Some(&step.title));
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
                                                title_s.set_label(&step.title);
                                                // Load user notes in description pane
                                                desc_buf_s.set_text(&step.description_notes);
                                                checkbox_s.set_active(matches!(step.status, StepStatus::Done));
                                                notes_buf_s.set_text(&step.notes);

                                                // Load canvas evidence for this step
                                                load_step_evidence(&canvas_fixed_s, canvas_items_s.clone(), step);
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
                                        text_view.buffer().set_text(&step.description);
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
                                    if !phase.steps.is_empty() {
                                        drop(model_borrow); // Release immutable borrow
                                        m_clone.borrow_mut().selected_step = Some(0);
                                        let step_data = {
                                            let model_borrow_again = m_clone.borrow();
                                            model_borrow_again.session.phases[selected_phase].steps.first().map(|step| (
                                                    step.title.clone(),
                                                    step.description_notes.clone(),
                                                    matches!(step.status, StepStatus::Done),
                                                    step.notes.clone(),
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

    // Save dialog
    {
        let window_ref = window.clone();
        let model_ref = model.clone();
        btn_save.connect_clicked(move |_| {
            if let Some(path) = model_ref.borrow().current_path.clone() {
                if let Err(err) = crate::store::save_session(&path, &model_ref.borrow().session) {
                    eprintln!("Failed to save: {err:?}");
                }
                return;
            }
            let dialog = FileDialog::new();
            dialog.set_title("Save Session As");
            let m = model_ref.clone();
            dialog.save(Some(&window_ref), None::<&gio::Cancellable>, move |res| {
                if let Ok(file) = res {
                    if let Some(path) = file.path() {
                        if let Err(err) = crate::store::save_session(&path, &m.borrow().session) {
                            eprintln!("Failed to save: {err:?}");
                        } else {
                            m.borrow_mut().current_path = Some(path);
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
