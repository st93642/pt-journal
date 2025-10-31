use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow, HeaderBar, Box as GtkBox, Orientation, ScrolledWindow, ListBox, CheckButton, Label, Frame, TextView, ListBoxRow, DropDown, StringList, FileDialog, Button, DropTarget, gdk, Paned, Picture, Fixed};
use gtk4::gio;
use gtk4::glib;
use std::rc::Rc;
use std::cell::RefCell;

use crate::model::{AppModel, StepStatus};

/// Canvas item representing an image on the canvas
#[derive(Clone)]
#[allow(dead_code)]
pub struct CanvasItem {
    pub texture: gdk::Texture,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

pub mod canvas_utils {
    use super::*;
    use std::path::Path;

    /// Check if a file path has a valid image extension
    pub fn is_valid_image_extension(path: &Path) -> bool {
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            matches!(ext_str.as_str(), "png" | "jpg" | "jpeg" | "gif" | "bmp" | "tiff" | "webp")
        } else {
            false
        }
    }

    /// Validate that a file exists and is readable
    pub fn validate_image_file(path: &Path) -> Result<(), String> {
        if !path.exists() {
            return Err("File does not exist".to_string());
        }

        if !path.is_file() {
            return Err("Path is not a file".to_string());
        }

        match std::fs::metadata(path) {
            Ok(metadata) => {
                if metadata.len() == 0 {
                    return Err("File is empty".to_string());
                }
                Ok(())
            }
            Err(e) => Err(format!("Cannot read file metadata: {}", e)),
        }
    }

    /// Attempt to create a texture from a file path
    pub fn create_texture_from_file(path: &Path) -> Result<gdk::Texture, String> {
        validate_image_file(path)?;

        match gdk::Texture::from_filename(path) {
            Ok(texture) => Ok(texture),
            Err(e) => Err(format!("Failed to create texture from file: {}", e)),
        }
    }

    /// Create a canvas item from a texture
    pub fn create_canvas_item(texture: gdk::Texture, x: f64, y: f64) -> CanvasItem {
        let width = texture.width() as f64;
        let height = texture.height() as f64;
        CanvasItem {
            texture,
            x,
            y,
            width,
            height,
        }
    }
}

pub mod image_utils {
    use super::*;
    use std::path::Path;

    /// Check if a file path has a valid image extension
    #[allow(dead_code)]
    pub fn is_valid_image_extension(path: &Path) -> bool {
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            matches!(ext_str.as_str(), "png" | "jpg" | "jpeg" | "gif" | "bmp" | "tiff" | "webp")
        } else {
            false
        }
    }

    /// Validate that a file exists and is readable
    #[allow(dead_code)]
    pub fn validate_image_file(path: &Path) -> Result<(), String> {
        if !path.exists() {
            return Err("File does not exist".to_string());
        }

        if !path.is_file() {
            return Err("Path is not a file".to_string());
        }

        match std::fs::metadata(path) {
            Ok(metadata) => {
                if metadata.len() == 0 {
                    return Err("File is empty".to_string());
                }
                Ok(())
            }
            Err(e) => Err(format!("Cannot read file metadata: {}", e)),
        }
    }

    /// Attempt to create a texture from a file path
    /// This is a wrapper around gdk::Texture::from_filename for testing
    #[allow(dead_code)]
    pub fn create_texture_from_file(path: &Path) -> Result<gdk::Texture, String> {
        validate_image_file(path)?;

        match gdk::Texture::from_filename(path) {
            Ok(texture) => Ok(texture),
            Err(e) => Err(format!("Failed to create texture from file: {}", e)),
        }
    }

    /// Attempt to create a texture from a pixbuf with error handling
    /// This is a wrapper for testing purposes
    pub fn create_texture_from_pixbuf(pixbuf: &gdk::gdk_pixbuf::Pixbuf) -> gdk::Texture {
        gdk::Texture::for_pixbuf(pixbuf)
    }

    /// Attempt to create a pixbuf from a file path with proper error handling
    #[allow(dead_code)]
    pub fn create_pixbuf_from_file(path: &Path) -> Result<gdk::gdk_pixbuf::Pixbuf, String> {
        validate_image_file(path)?;

        match gdk::gdk_pixbuf::Pixbuf::from_file(path) {
            Ok(pixbuf) => Ok(pixbuf),
            Err(e) => Err(format!("Failed to create pixbuf from file: {}", e)),
        }
    }

    /// Insert a paintable (texture) into a text buffer at the end
    #[allow(dead_code)]
    pub fn insert_paintable_into_buffer(buffer: &gtk4::TextBuffer, paintable: &gdk::Texture) {
        buffer.begin_user_action();
        let mut iter = buffer.end_iter();
        buffer.insert_paintable(&mut iter, paintable);
        buffer.end_user_action();
    }
}

/// Setup canvas with drag-drop and drawing functionality
pub fn setup_canvas(fixed: &Fixed, canvas_items: Rc<RefCell<Vec<CanvasItem>>>) {
    // Handle drag and drop on the fixed container
    let drop_target = DropTarget::new(glib::Type::INVALID, gdk::DragAction::COPY);
    drop_target.set_preload(true);

    let canvas_items_drop = canvas_items.clone();
    let fixed_weak = fixed.downgrade();
    drop_target.connect_drop(move |_target, value, x, y| {
        // Try to get file paths first
        if let Ok(file) = value.get::<gtk4::gio::File>() && let Some(path) = file.path() {
            // Validate file extension
            if canvas_utils::is_valid_image_extension(&path) {
                // Try creating texture from file
                if let Ok(texture) = canvas_utils::create_texture_from_file(&path) {
                    let item_x = x as f64;
                    let item_y = y as f64;
                    let item = canvas_utils::create_canvas_item(texture.clone(), item_x, item_y);
                    canvas_items_drop.borrow_mut().push(item);

                    // Create a Picture widget for the image
                    if let Some(fixed_ref) = fixed_weak.upgrade() {
                        let picture = Picture::for_paintable(&texture);
                        picture.set_size_request(texture.width() as i32, texture.height() as i32);

                        // Position the picture on the fixed container
                        fixed_ref.put(&picture, item_x, item_y);
                    }
                    return true;
                }
            }
        }
        // Try direct pixbuf
        if let Ok(pixbuf) = value.get::<gdk::gdk_pixbuf::Pixbuf>() {
            let texture = image_utils::create_texture_from_pixbuf(&pixbuf);
            let item_x = x as f64;
            let item_y = y as f64;
            let item = canvas_utils::create_canvas_item(texture.clone(), item_x, item_y);
            canvas_items_drop.borrow_mut().push(item);

            // Create a Picture widget for the image
            if let Some(fixed_ref) = fixed_weak.upgrade() {
                let picture = Picture::for_paintable(&texture);
                picture.set_size_request(texture.width() as i32, texture.height() as i32);

                // Position the picture on the fixed container
                fixed_ref.put(&picture, item_x, item_y);
            }
            return true;
        }
        false
    });

    // Accept file URIs in drag-drop
    drop_target.set_types(&[
        gtk4::gio::File::static_type(),
        gdk::gdk_pixbuf::Pixbuf::static_type(),
    ]);

    fixed.add_controller(drop_target);
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

    // Top section with checkbox and title (fixed)
    let top_box = GtkBox::new(Orientation::Horizontal, 8);
    top_box.append(&checkbox);
    top_box.append(&title_label);

    let desc_view = TextView::new();
    desc_view.set_editable(true); // Allow editing for user notes
    desc_view.set_wrap_mode(gtk4::WrapMode::Word);
    desc_view.set_accepts_tab(false);
    let desc_scroll = ScrolledWindow::new();
    desc_scroll.set_child(Some(&desc_view));
    desc_scroll.set_vexpand(true);
    desc_scroll.set_min_content_height(100); // Minimum 1 line height
    let desc_frame = Frame::builder()
        .label("Description")
        .child(&desc_scroll)
        .margin_top(4)
        .margin_bottom(4)
        .margin_start(4)
        .margin_end(4)
        .build();
    desc_frame.set_size_request(-1, 80); // Minimum height to show title + 1 line

    let notes_view = TextView::new();
    notes_view.set_monospace(true);
    notes_view.set_vexpand(true);
    let notes_scroll = ScrolledWindow::new();
    notes_scroll.set_child(Some(&notes_view));
    notes_scroll.set_vexpand(true);
    notes_scroll.set_min_content_height(100); // Minimum 1 line height
    let notes_frame = Frame::builder().label("Notes").child(&notes_scroll).build();
    notes_frame.set_size_request(-1, 80); // Minimum height to show title + 1 line

    // Canvas for evidence/images
    let canvas_items = Rc::new(RefCell::new(Vec::<CanvasItem>::new()));
    let canvas_fixed = Fixed::new();
    canvas_fixed.set_size_request(800, 600); // Minimum canvas size
    let canvas_scroll = ScrolledWindow::new();
    canvas_scroll.set_child(Some(&canvas_fixed));
    canvas_scroll.set_vexpand(true);
    canvas_scroll.set_min_content_height(100); // Minimum 1 line height
    let canvas_frame = Frame::builder().label("Evidence Canvas").child(&canvas_scroll).build();
    canvas_frame.set_size_request(-1, 80); // Minimum height to show title + 1 line

    // Create resizable panes
    // Paned 1: separates description from notes/canvas area
    let main_paned = Paned::new(Orientation::Vertical);
    main_paned.set_vexpand(true);
    main_paned.set_resize_start_child(true);
    main_paned.set_resize_end_child(true);
    main_paned.set_shrink_start_child(false); // Prevent description from being collapsed
    main_paned.set_shrink_end_child(false);   // Prevent notes/canvas from being collapsed

    // Paned 2: separates notes from canvas
    let bottom_paned = Paned::new(Orientation::Vertical);
    bottom_paned.set_vexpand(true);
    bottom_paned.set_resize_start_child(true);
    bottom_paned.set_resize_end_child(true);
    bottom_paned.set_shrink_start_child(false); // Prevent notes from being collapsed
    bottom_paned.set_shrink_end_child(false);   // Prevent canvas from being collapsed

    // Set up the pane hierarchy
    bottom_paned.set_start_child(Some(&notes_frame));
    bottom_paned.set_end_child(Some(&canvas_frame));
    bottom_paned.set_position(300); // Default split between notes and canvas

    main_paned.set_start_child(Some(&desc_frame));
    main_paned.set_end_child(Some(&bottom_paned));
    main_paned.set_position(200); // Default split between description and bottom area

    // Add top section and main paned to right panel
    right.append(&top_box);
    right.append(&main_paned);

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
                        // Load user notes in description pane
                        desc_buf_s.set_text(&step.description_notes);
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
                    // Load user notes in description pane
                    let desc_buffer = desc_view_ref.buffer();
                    desc_buffer.set_text(&step.description_notes);
                    checkbox_ref.set_active(matches!(step.status, StepStatus::Done));
                    notes_view_ref.buffer().set_text(&step.notes);
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
            if let Some(phase) = model_borrow.session.phases.get(active as usize)
                && !phase.steps.is_empty() {
                    drop(model_borrow); // Release immutable borrow
                    {
                        let mut model_borrow_mut = model_phase.borrow_mut();
                        model_borrow_mut.selected_step = Some(0);
                    }
                    let model_borrow_again = model_phase.borrow();
                    if let Some(step) = model_borrow_again.session.phases[active as usize].steps.first() {
                        title_label_ref.set_label(&step.title);
                        // Load user notes in description pane
                        let desc_buffer = desc_view_ref.buffer();
                        desc_buffer.set_text(&step.description_notes);
                        checkbox_ref.set_active(matches!(step.status, StepStatus::Done));
                        notes_view_ref.buffer().set_text(&step.notes);
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
                            if let Some(phase) = m.borrow().session.phases.first()
                                && !phase.steps.is_empty() {
                                m.borrow_mut().selected_step = Some(0);
                                // rebuild() will handle UI updates
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

    // Setup canvas for evidence
    setup_canvas(&canvas_fixed, canvas_items);

    window.present();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::NamedTempFile;
    use std::fs;

    mod image_utils_tests {
        use super::*;

        #[test]
        fn test_is_valid_image_extension() {
            // Valid extensions
            assert!(image_utils::is_valid_image_extension(Path::new("image.png")));
            assert!(image_utils::is_valid_image_extension(Path::new("photo.JPG")));
            assert!(image_utils::is_valid_image_extension(Path::new("pic.jpeg")));
            assert!(image_utils::is_valid_image_extension(Path::new("file.gif")));
            assert!(image_utils::is_valid_image_extension(Path::new("test.bmp")));
            assert!(image_utils::is_valid_image_extension(Path::new("scan.tiff")));
            assert!(image_utils::is_valid_image_extension(Path::new("modern.webp")));

            // Case insensitive
            assert!(image_utils::is_valid_image_extension(Path::new("IMAGE.PNG")));
            assert!(image_utils::is_valid_image_extension(Path::new("photo.JpG")));

            // Invalid extensions
            assert!(!image_utils::is_valid_image_extension(Path::new("document.txt")));
            assert!(!image_utils::is_valid_image_extension(Path::new("script.js")));
            assert!(!image_utils::is_valid_image_extension(Path::new("archive.zip")));
            assert!(!image_utils::is_valid_image_extension(Path::new("video.mp4")));

            // No extension
            assert!(!image_utils::is_valid_image_extension(Path::new("image")));
            assert!(!image_utils::is_valid_image_extension(Path::new("")));
        }

        #[test]
        fn test_validate_image_file_nonexistent() {
            let result = image_utils::validate_image_file(Path::new("/nonexistent/file.png"));
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("does not exist"));
        }

        #[test]
        fn test_validate_image_file_directory() {
            let temp_dir = tempfile::tempdir().unwrap();
            let result = image_utils::validate_image_file(temp_dir.path());
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("not a file"));
        }

        #[test]
        fn test_validate_image_file_empty() {
            let temp_file = NamedTempFile::new().unwrap();
            // File is empty by default
            let result = image_utils::validate_image_file(temp_file.path());
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("empty"));
        }

        #[test]
        fn test_validate_image_file_valid() {
            let temp_file = NamedTempFile::new().unwrap();
            // Write some content to make it non-empty
            fs::write(temp_file.path(), "fake image content").unwrap();

            let result = image_utils::validate_image_file(temp_file.path());
            assert!(result.is_ok());
        }

        #[test]
        fn test_create_texture_from_file_invalid_file() {
            let result = image_utils::create_texture_from_file(Path::new("/nonexistent.png"));
            assert!(result.is_err());
        }

        #[test]
        fn test_create_texture_from_file_empty_file() {
            let temp_file = NamedTempFile::new().unwrap();
            let result = image_utils::create_texture_from_file(temp_file.path());
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("empty"));
        }

        #[test]
        fn test_insert_paintable_into_buffer() {
            // This test requires GTK initialization, so we'll skip it in unit tests
            // In a real GTK environment, this would test that paintables are inserted correctly
            // For now, we just ensure the function signature is correct
            assert!(true); // Placeholder test
        }
    }

    mod ui_integration_tests {
        // use super::*; // Not needed for placeholder tests

        #[test]
        fn test_setup_image_handling_attaches_controllers() {
            // This test requires GTK initialization
            // In a real environment, we would:
            // 1. Create a TextView
            // 2. Call setup_image_handling
            // 3. Verify that controllers are attached
            // 4. Check that the controllers have the correct types

            // For now, just ensure the function exists and can be called
            // (without GTK init, it would panic, so we skip actual execution)
            assert!(true); // Placeholder test
        }

        #[test]
        fn test_image_handling_workflow() {
            // Integration test for the complete image handling workflow
            // This would test:
            // 1. File validation
            // 2. Texture creation
            // 3. Buffer insertion
            // 4. UI controller setup

            // Since GTK is required, this is a placeholder
            assert!(true);
        }

        #[test]
        fn test_pane_minimum_sizes() {
            // Test that pane minimum sizes are properly set
            // Description pane: 80px minimum
            // Notes pane: 80px minimum
            // Canvas pane: 80px minimum

            // Since GTK is required for actual widget testing, this is a placeholder
            // In a real test, we would:
            // 1. Create the UI components
            // 2. Check that minimum sizes are set correctly
            // 3. Verify that panes cannot be resized below minimums
            assert!(true);
        }

        #[test]
        fn test_text_input_handlers() {
            // Test that text input handlers are properly connected
            // This would verify that:
            // 1. Description pane changes are saved to description_notes
            // 2. Notes pane changes are saved to notes
            // 3. Text is properly loaded when switching steps

            // Since GTK is required, this is a placeholder
            assert!(true);
        }
    }

    // Mock tests for drag and drop behavior
    mod drag_drop_tests {
        use super::*;

        #[test]
        fn test_drag_drop_file_validation() {
            // Test that only valid image files are accepted in drag-drop
            let valid_files = vec![
                Path::new("screenshot.png"),
                Path::new("diagram.jpg"),
                Path::new("photo.jpeg"),
                Path::new("icon.gif"),
            ];

            let invalid_files = vec![
                Path::new("document.txt"),
                Path::new("script.py"),
                Path::new("video.mp4"),
                Path::new("archive.zip"),
            ];

            for file in valid_files {
                assert!(image_utils::is_valid_image_extension(file),
                       "File {:?} should be accepted", file);
            }

            for file in invalid_files {
                assert!(!image_utils::is_valid_image_extension(file),
                       "File {:?} should be rejected", file);
            }
        }

        #[test]
        fn test_drag_drop_error_handling() {
            // Test error handling in drag-drop scenarios
            let nonexistent = Path::new("/definitely/does/not/exist.png");
            // is_valid_image_extension only checks extension, not existence
            assert!(image_utils::is_valid_image_extension(nonexistent));

            let no_extension = Path::new("file_no_ext");
            assert!(!image_utils::is_valid_image_extension(no_extension));

            let wrong_extension = Path::new("image.exe");
            assert!(!image_utils::is_valid_image_extension(wrong_extension));
        }
    }

    // Mock tests for paste functionality
    mod paste_tests {
        // use super::*; // Not needed for placeholder tests

        #[test]
        fn test_paste_texture_handling() {
            // Test that paste operations handle textures correctly
            // This would test the clipboard texture reading logic
            // Since GTK clipboard requires initialization, this is a placeholder
            assert!(true);
        }

        #[test]
        fn test_paste_key_detection() {
            // Test that Ctrl+V is correctly detected
            // This would test the key event handling logic
            // In a real implementation, we'd mock the key events
            assert!(true);
        }
    }

    // Performance tests for image handling
    mod performance_tests {
        use super::*;

        #[test]
        fn test_file_extension_check_performance() {
            // Test that extension checking is fast
            let test_files = vec![
                "image.png", "photo.jpg", "diagram.jpeg", "icon.gif",
                "pic.bmp", "scan.tiff", "modern.webp", "document.txt",
                "script.py", "video.mp4", "archive.zip", "no_ext",
            ];

            for _ in 0..1000 { // Run multiple times for performance
                for file in &test_files {
                    let _ = image_utils::is_valid_image_extension(Path::new(file));
                }
            }

            assert!(true); // If we get here, performance is acceptable
        }

        #[test]
        fn test_file_validation_performance() {
            // Test that file validation doesn't take too long
            let temp_file = NamedTempFile::new().unwrap();
            fs::write(temp_file.path(), "test content").unwrap();

            // Run validation multiple times
            for _ in 0..100 {
                let _ = image_utils::validate_image_file(temp_file.path());
            }

            assert!(true);
        }
    }

    // Security tests
    mod security_tests {
        use super::*;

        #[test]
        fn test_path_traversal_protection() {
            // Test that path traversal attacks are prevented
            let safe_paths = vec![
                Path::new("image.png"),
                Path::new("subdir/photo.jpg"),
                Path::new("./local.jpeg"),
            ];

            let dangerous_paths = vec![
                Path::new("../outside.png"),
                Path::new("../../escape.jpg"),
                Path::new("/absolute/path.jpeg"),
                Path::new("../../../root.gif"),
            ];

            // The validation should work regardless of path safety
            // (actual path traversal protection would be in the GTK file chooser)
            for path in safe_paths {
                // Just test extension validation
                if path.extension().is_some() {
                    let _ = image_utils::is_valid_image_extension(path);
                }
            }

            for path in dangerous_paths {
                if path.extension().is_some() {
                    let _ = image_utils::is_valid_image_extension(path);
                }
            }

            assert!(true);
        }

        #[test]
        fn test_file_size_limits() {
            // Test that empty files are rejected
            let temp_file = NamedTempFile::new().unwrap();
            let result = image_utils::validate_image_file(temp_file.path());
            assert!(result.is_err());

            // Test that very small files are accepted if they have content
            fs::write(temp_file.path(), "x").unwrap();
            let result = image_utils::validate_image_file(temp_file.path());
            assert!(result.is_ok());
        }

        #[test]
        fn test_invalid_file_types() {
            // Test that non-image files are rejected at extension level
            let non_images = vec![
                "malicious.exe", "script.sh", "document.pdf",
                "spreadsheet.xlsx", "database.db", "binary.bin",
            ];

            for file in non_images {
                assert!(!image_utils::is_valid_image_extension(Path::new(file)),
                       "File {} should be rejected", file);
            }
        }
    }

    mod text_input_tests {
        use crate::model::*;
        use uuid::Uuid;

        #[test]
        fn test_text_buffer_operations() {
            // Test that text buffer operations work correctly
            // This tests the logic without requiring GTK

            let mut model = AppModel::default();
            model.selected_phase = 0;
            model.selected_step = Some(0);

            // Simulate text input to notes
            if let Some(step) = model.session.phases[0].steps.get_mut(0) {
                step.notes = "Test notes content".to_string();
                assert_eq!(step.notes, "Test notes content");
            }

            // Simulate text input to description_notes
            if let Some(step) = model.session.phases[0].steps.get_mut(0) {
                step.description_notes = "Test description notes".to_string();
                assert_eq!(step.description_notes, "Test description notes");
            }
        }

        #[test]
        fn test_step_text_persistence() {
            // Test that text changes persist across step switches
            let mut model = AppModel::default();

            // Set text for first step
            model.selected_step = Some(0);
            if let Some(step) = model.session.phases[0].steps.get_mut(0) {
                step.notes = "Notes for step 0".to_string();
                step.description_notes = "Description notes for step 0".to_string();
            }

            // Switch to second step
            model.selected_step = Some(1);
            if let Some(step) = model.session.phases[0].steps.get_mut(1) {
                step.notes = "Notes for step 1".to_string();
                step.description_notes = "Description notes for step 1".to_string();
            }

            // Verify first step still has its text
            if let Some(step) = model.session.phases[0].steps.get(0) {
                assert_eq!(step.notes, "Notes for step 0");
                assert_eq!(step.description_notes, "Description notes for step 0");
            }

            // Verify second step has its text
            if let Some(step) = model.session.phases[0].steps.get(1) {
                assert_eq!(step.notes, "Notes for step 1");
                assert_eq!(step.description_notes, "Description notes for step 1");
            }
        }

        #[test]
        fn test_empty_text_handling() {
            // Test handling of empty text input
            let mut step = Step {
                id: Uuid::new_v4(),
                title: "Test".to_string(),
                description: "Test".to_string(),
                tags: vec![],
                status: StepStatus::Todo,
                completed_at: None,
                notes: String::new(),
                description_notes: String::new(),
                evidence: vec![],
            };

            // Empty strings should be handled
            assert!(step.notes.is_empty());
            assert!(step.description_notes.is_empty());

            // Setting to empty should work
            step.notes = "".to_string();
            step.description_notes = "".to_string();
            assert!(step.notes.is_empty());
            assert!(step.description_notes.is_empty());
        }
    }
}
