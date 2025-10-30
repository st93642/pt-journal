use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow, HeaderBar, Box as GtkBox, Orientation, ScrolledWindow, ListBox, CheckButton, Label, Frame, TextView, ListBoxRow, DropDown, StringList, FileDialog, Button, DropTarget, EventControllerKey, gdk, Paned};
use gtk4::gio;
use gtk4::pango;
use gtk4::glib;
use std::rc::Rc;
use std::cell::RefCell;

use crate::model::{AppModel, StepStatus};

fn setup_image_handling(text_view: &TextView) {
    // Handle drag and drop
    let text_view_clone = text_view.clone();
    let drop_target = DropTarget::new(glib::Type::INVALID, gdk::DragAction::COPY);
    
    drop_target.set_preload(true);
    drop_target.connect_drop(move |_target, value, _x, _y| {
        // Try to get file paths first
        if let Ok(file) = value.get::<gtk4::gio::File>() && let Some(path_str) = file.path() {
            // Try creating Texture from file
            if let Ok(texture) = gdk::Texture::from_filename(&path_str) {
                let buffer = text_view_clone.buffer();
                buffer.begin_user_action();
                let mut iter = buffer.end_iter();
                buffer.insert_paintable(&mut iter, &texture);
                buffer.end_user_action();
                return true;
            }
            // Fallback: try pixbuf then texture
            if let Ok(pixbuf) = gdk::gdk_pixbuf::Pixbuf::from_file(&path_str) {
                let texture = gdk::Texture::for_pixbuf(&pixbuf);
                let buffer = text_view_clone.buffer();
                buffer.begin_user_action();
                let mut iter = buffer.end_iter();
                buffer.insert_paintable(&mut iter, &texture);
                buffer.end_user_action();
                return true;
            }
        }
        // Try direct pixbuf
        if let Ok(pix) = value.get::<gdk::gdk_pixbuf::Pixbuf>() {
            let texture = gdk::Texture::for_pixbuf(&pix);
            let buffer = text_view_clone.buffer();
            buffer.begin_user_action();
            let mut iter = buffer.end_iter();
            buffer.insert_paintable(&mut iter, &texture);
            buffer.end_user_action();
            return true;
        }
        false
    });
    
    // Accept file URIs in drag-drop
    drop_target.set_types(&[
        gtk4::gio::File::static_type(),
        gdk::gdk_pixbuf::Pixbuf::static_type(),
    ]);
    
    text_view.add_controller(drop_target);

    // Handle paste from clipboard (Ctrl+V)
    let text_view_paste = text_view.clone();
    let paste_clip = EventControllerKey::new();
    paste_clip.connect_key_pressed(move |_controller, keyval, _state, modifier| {
        // Check for Ctrl+V (paste)
        if (keyval == gdk::Key::V || keyval == gdk::Key::v) && modifier.contains(gdk::ModifierType::CONTROL_MASK) {
            let display = match gdk::Display::default() {
                Some(d) => d,
                None => return gtk4::glib::Propagation::Proceed,
            };
            let clipboard = display.clipboard();
            
            // Clone the text_view for the callback
            let text_view_cb = text_view_paste.clone();
            
            // Use the simpler read_texture_async API
            clipboard.read_texture_async(
                None::<&gio::Cancellable>,
                move |result| {
                    if let Ok(Some(texture)) = result {
                        let tv_buffer = text_view_cb.buffer();
                        // Suppress change events during paintable insertion
                        tv_buffer.begin_user_action();
                        let mut iter = tv_buffer.end_iter();
                        tv_buffer.insert_paintable(&mut iter, &texture);
                        tv_buffer.end_user_action();
                    }
                },
            );
        }
        gtk4::glib::Propagation::Proceed
    });
    text_view.add_controller(paste_clip);
}

pub fn build_ui(app: &Application, model: AppModel) {
    let model = Rc::new(RefCell::new(model));

    let window = ApplicationWindow::builder()
        .application(app)
        .title("PT Journal")
        .default_width(1100)
        .default_height(700)
        .build();

    // Header bar with Open/Save and Sidebar toggle
    let header = HeaderBar::new();
    let btn_open = Button::from_icon_name("document-open-symbolic");
    btn_open.set_tooltip_text(Some("Open session"));
    let btn_save = Button::from_icon_name("document-save-symbolic");
    btn_save.set_tooltip_text(Some("Save session"));
    let btn_sidebar = Button::from_icon_name("view-sidebar-start-symbolic");
    btn_sidebar.set_tooltip_text(Some("Toggle sidebar"));
    header.pack_start(&btn_open);
    header.pack_start(&btn_sidebar);
    header.pack_end(&btn_save);
    window.set_titlebar(Some(&header));

    // Left panel: phase selector + steps list
    let left_box = GtkBox::new(Orientation::Vertical, 6);
    let phase_model = StringList::new(&[]);
    for p in &model.borrow().session.phases { phase_model.append(&p.name); }
    let phase_combo = DropDown::new(Some(phase_model.clone()), None::<gtk4::Expression>);
    phase_combo.set_selected(model.borrow().selected_phase as u32);

    let steps_scroller = ScrolledWindow::builder()
        .min_content_width(280)
        .hexpand(false)
        .vexpand(true)
        .build();
    let steps_list = ListBox::new();
    steps_scroller.set_child(Some(&steps_list));
    left_box.append(&phase_combo);
    left_box.append(&steps_scroller);

    let right = GtkBox::new(Orientation::Vertical, 8);
    right.set_margin_top(8);
    right.set_margin_bottom(8);
    right.set_margin_start(8);
    right.set_margin_end(8);

    let checkbox = CheckButton::with_label("Completed");
    let title_label = Label::new(None);
    title_label.set_xalign(0.0);
    title_label.set_hexpand(true);

    let desc_view = TextView::new();
    desc_view.set_editable(false);
    desc_view.set_wrap_mode(gtk4::WrapMode::Word);
    desc_view.set_accepts_tab(false);
    let desc_scroll = ScrolledWindow::new();
    desc_scroll.set_child(Some(&desc_view));
    desc_scroll.set_vexpand(true);
    desc_scroll.set_min_content_height(200);
    let desc_frame = Frame::builder()
        .label("Description")
        .child(&desc_scroll)
        .margin_top(4)
        .margin_bottom(4)
        .margin_start(4)
        .margin_end(4)
        .build();

    let notes_view = TextView::new();
    notes_view.set_monospace(true);
    notes_view.set_vexpand(true);
    let notes_scroll = ScrolledWindow::new();
    notes_scroll.set_child(Some(&notes_view));
    notes_scroll.set_vexpand(true);
    let notes_frame = Frame::builder().label("Notes").child(&notes_scroll).build();

    right.append(&checkbox);
    right.append(&title_label);
    right.append(&desc_frame);
    right.append(&notes_frame);

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
                
                click_controller.connect_pressed(move |_, _, _, _| {
                    let mut model_borrow = model_s.borrow_mut();
                    model_borrow.selected_step = Some(idx);
                    let sp = model_borrow.selected_phase;
                    if let Some(step) = model_borrow.session.phases[sp].steps.get(idx) {
                        title_s.set_label(&step.title);
                        // Clear description - tutorial content only shown in popup
                        desc_buf_s.set_text("");
                        checkbox_s.set_active(matches!(step.status, StepStatus::Done));
                        notes_buf_s.set_text(&step.notes);
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
                    // Clear description - tutorial content only shown in popup
                    let desc_buffer = desc_view_ref.buffer();
                    desc_buffer.set_text("");
                    checkbox_ref.set_active(matches!(step.status, StepStatus::Done));
                    notes_view_ref.buffer().set_text(&step.notes);
                }
            } else if !phase.steps.is_empty() {
                drop(model_borrow); // Release the immutable borrow before getting mutable
                model_rc.borrow_mut().selected_step = Some(0);
                let model_borrow_again = model_rc.borrow();
                if let Some(step) = model_borrow_again.session.phases[model_borrow_again.selected_phase].steps.get(0) {
                    title_label_ref.set_label(&step.title);
                    // Clear description - tutorial content only shown in popup
                    let desc_buffer = desc_view_ref.buffer();
                    desc_buffer.set_text("");
                    checkbox_ref.set_active(matches!(step.status, StepStatus::Done));
                    notes_view_ref.buffer().set_text(&step.notes);
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
            if let Some(idx) = model_notes.borrow().selected_step {
                let sp = model_notes.borrow().selected_phase;
                if let Some(step) = model_notes.borrow_mut().session.phases.get_mut(sp).and_then(|p| p.steps.get_mut(idx)) {
                    step.notes = text.to_string();
                }
            }
        });
    }

    // Phase selection change
    {
        let model_phase = model.clone();
        let rebuild = rebuild_steps.clone();
        let title_label_ref = title_label.clone();
        let desc_view_ref = desc_view.clone();
        let notes_view_ref = notes_view.clone();
        let checkbox_ref = checkbox.clone();
        phase_combo.connect_selected_notify(move |c| {
            let active = c.selected();
            {
                let mut model_borrow = model_phase.borrow_mut();
                model_borrow.selected_phase = active as usize;
                model_borrow.selected_step = None;
            }
            rebuild();
            
            // Auto-select first step of new phase
            let model_borrow = model_phase.borrow();
            if let Some(phase) = model_borrow.session.phases.get(active as usize) {
                if !phase.steps.is_empty() {
                    drop(model_borrow); // Release immutable borrow
                    {
                        let mut model_borrow_mut = model_phase.borrow_mut();
                        model_borrow_mut.selected_step = Some(0);
                    }
                    let model_borrow_again = model_phase.borrow();
                    if let Some(step) = model_borrow_again.session.phases[active as usize].steps.get(0) {
                        title_label_ref.set_label(&step.title);
                        // Clear description - tutorial content only shown in popup
                        let desc_buffer = desc_view_ref.buffer();
                        desc_buffer.set_text("");
                        checkbox_ref.set_active(matches!(step.status, StepStatus::Done));
                        notes_view_ref.buffer().set_text(&step.notes);
                    }
                }
            }
        });
    }

    // Open dialog
    {
        let window_ref = window.clone();
        let model_ref = model.clone();
        let phase_model_ref = phase_model.clone();
        let phase_combo_ref = phase_combo.clone();
        let rebuild = rebuild_steps.clone();
        btn_open.connect_clicked(move |_| {
            let dialog = FileDialog::new();
            dialog.set_title("Open Session");
            let m = model_ref.clone();
            let pm = phase_model_ref.clone();
            let pc = phase_combo_ref.clone();
            let rb = rebuild.clone();
            dialog.open(Some(&window_ref), None::<&gio::Cancellable>, move |res| {
                if let Ok(file) = res && let Some(path) = file.path() {
                    match crate::store::load_session(&path) {
                        Ok(sess) => {
                            m.borrow_mut().session = sess;
                            m.borrow_mut().selected_phase = 0;
                            m.borrow_mut().selected_step = None;
                            m.borrow_mut().current_path = Some(path.clone());
                            // rebuild phase model
                            while pm.n_items() > 0 { pm.remove(0); }
                            for p in &m.borrow().session.phases { pm.append(&p.name); }
                            pc.set_selected(0);
                            rb();
                            
                            // Auto-select first step
                            if let Some(phase) = m.borrow().session.phases.get(0) {
                                if !phase.steps.is_empty() {
                                    m.borrow_mut().selected_step = Some(0);
                                    // rebuild() will handle UI updates
                                }
                            }
                        }
                        Err(err) => {
                            eprintln!("Failed to open: {err:?}");
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
                if let Ok(file) = res && let Some(path) = file.path() {
                    if let Err(err) = crate::store::save_session(&path, &m.borrow().session) {
                        eprintln!("Failed to save: {err:?}");
                    } else {
                        m.borrow_mut().current_path = Some(path);
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

    // Image handling for notes_view (drag-drop and paste)
    setup_image_handling(&notes_view);

    window.present();
}


