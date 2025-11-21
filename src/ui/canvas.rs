use chrono;
use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{gdk, Fixed, Picture};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use uuid;

use super::canvas_utils::{
    create_canvas_item, create_texture_from_file, is_valid_image_extension, CanvasItem,
};
use super::image_utils::{create_texture_from_pixbuf, save_pasted_image};

/// Copy a file to the evidence directory and return relative path
fn copy_file_to_evidence(source_path: &Path, session_path: Option<&Path>) -> Option<String> {
    // Get evidence directory (creates it if needed)
    let evidence_dir = match session_path {
        Some(path) => {
            let session_dir = if path.file_name() == Some(std::ffi::OsStr::new("session.json")) {
                path.parent().unwrap_or(path)
            } else {
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
    };

    // Generate unique filename with timestamp
    let timestamp = chrono::Utc::now().timestamp_millis();
    let extension = source_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("png");
    let filename = format!("evidence_{}.{}", timestamp, extension);
    let dest_path = evidence_dir.join(&filename);

    // Copy the file
    match std::fs::copy(source_path, &dest_path) {
        Ok(_) => Some(format!("evidence/{}", filename)),
        Err(e) => {
            eprintln!("Failed to copy file to evidence directory: {}", e);
            None
        }
    }
}

/// Load evidence for a specific step onto the canvas
pub fn load_step_evidence(
    fixed: &Fixed,
    canvas_items: Rc<RefCell<Vec<CanvasItem>>>,
    step: &crate::model::Step,
    session_path: Option<&Path>,
) {
    // Clear existing canvas items and widgets
    canvas_items.borrow_mut().clear();

    // Remove all child widgets from the fixed container
    while let Some(child) = fixed.first_child() {
        fixed.remove(&child);
    }

    // Determine the base directory for resolving relative paths
    let base_dir = match session_path {
        Some(path) => {
            if path.file_name() == Some(std::ffi::OsStr::new("session.json")) {
                // New format: session.json is inside the session directory
                path.parent().unwrap_or(path).to_path_buf()
            } else {
                // Old format or direct parent
                path.parent().unwrap_or(Path::new(".")).to_path_buf()
            }
        }
        None => PathBuf::from("."),
    };

    // Load evidence from the step
    let evidence_list = step.get_evidence();
    for evidence in &evidence_list {
        // Resolve the path: if relative, resolve from base_dir; if absolute, use as-is
        let evidence_path = if Path::new(&evidence.path).is_relative() {
            base_dir.join(&evidence.path)
        } else {
            PathBuf::from(&evidence.path)
        };

        // Try to create texture from the evidence path
        match create_texture_from_file(&evidence_path) {
            Ok(texture) => {
                // Validate texture dimensions to prevent GTK crashes
                if texture.width() == 0 || texture.height() == 0 {
                    eprintln!(
                        "Warning: Skipping evidence with invalid dimensions ({}x{}): {}",
                        texture.width(),
                        texture.height(),
                        evidence.path
                    );
                    continue;
                }

                // Use stored position from evidence, or default if not available
                let item_x = evidence.x;
                let item_y = evidence.y;

                let mut item = create_canvas_item(
                    texture.clone(),
                    item_x,
                    item_y,
                    Some(evidence.path.clone()),
                );

                // Create Picture widget and add to fixed container
                let picture = Picture::for_paintable(&texture);
                picture.set_size_request(texture.width(), texture.height());
                fixed.put(&picture, item_x, item_y);

                // Store the picture widget reference
                item.picture_widget = Some(picture.clone());

                // Add click handler for selection
                let canvas_items_click = canvas_items.clone();
                let fixed_weak_click = fixed.downgrade();
                let picture_clone = picture.clone();
                let click_controller = gtk4::GestureClick::new();
                click_controller.connect_pressed(move |_, n_press, _, _| {
                    if n_press == 1 {
                        // Single click
                        select_canvas_item(&canvas_items_click, &fixed_weak_click, &picture_clone);
                    }
                });
                picture.add_controller(click_controller);

                canvas_items.borrow_mut().push(item);
            }
            Err(e) => {
                eprintln!(
                    "Warning: Failed to load evidence from {}: {}",
                    evidence.path, e
                );
                // Continue loading other evidence items
            }
        }
    }
}

/// Setup canvas with drag-drop and paste functionality
pub fn setup_canvas(
    fixed: &Fixed,
    canvas_items: Rc<RefCell<Vec<CanvasItem>>>,
    state: Rc<crate::ui::state::StateManager>,
) {
    // Handle drag and drop on the fixed container
    let drop_target = gtk4::DropTarget::new(glib::Type::INVALID, gdk::DragAction::COPY);
    drop_target.set_preload(true);

    let canvas_items_drop = canvas_items.clone();
    let state_drop = state.clone();
    let fixed_weak = fixed.downgrade();
    drop_target.connect_drop(move |_target, value, x, y| {
        handle_image_drop(&canvas_items_drop, &state_drop, &fixed_weak, value, x, y)
    });

    // Accept file URIs in drag-drop
    drop_target.set_types(&[
        gtk4::gio::File::static_type(),
        gdk::gdk_pixbuf::Pixbuf::static_type(),
    ]);

    fixed.add_controller(drop_target);

    // Handle keyboard paste (Ctrl+V) and delete (Delete key)
    let key_controller = gtk4::EventControllerKey::new();
    let canvas_items_key = canvas_items.clone();
    let state_key = state.clone();
    let fixed_weak_key = fixed.downgrade();

    key_controller.connect_key_pressed(move |_, keyval, _keycode, modifier| {
        // Check for Ctrl+V
        if keyval == gdk::Key::v && modifier.contains(gdk::ModifierType::CONTROL_MASK) {
            handle_clipboard_paste(&canvas_items_key, &state_key, &fixed_weak_key);
            return glib::Propagation::Stop;
        }
        // Check for Delete key
        if keyval == gdk::Key::Delete {
            delete_selected_items(&canvas_items_key, &fixed_weak_key, &state_key);
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });

    fixed.add_controller(key_controller);

    // Handle canvas background clicks to focus for keyboard events
    let canvas_click_controller = gtk4::GestureClick::new();
    let fixed_weak_canvas = fixed.downgrade();
    canvas_click_controller.connect_pressed(move |_, n_press, _, _| {
        if n_press == 1 {
            // Single click on canvas background
            if let Some(fixed_ref) = fixed_weak_canvas.upgrade() {
                fixed_ref.grab_focus();
            }
        }
    });
    fixed.add_controller(canvas_click_controller);

    // Right-click context menu for paste
    let right_click_controller = gtk4::GestureClick::new();
    right_click_controller.set_button(gtk4::gdk::ffi::GDK_BUTTON_SECONDARY as u32); // Right-click

    let canvas_items_menu = canvas_items.clone();
    let state_menu = state.clone();
    let fixed_weak_menu = fixed.downgrade();

    right_click_controller.connect_pressed(move |_controller, n_press, x, y| {
        if n_press == 1 {
            // Single right-click
            // Create a custom popover with a button
            let popover = gtk4::Popover::new();
            popover.set_has_arrow(true);
            popover.set_position(gtk4::PositionType::Bottom);

            // Create a button for paste
            let paste_button = gtk4::Button::with_label("Paste Image");
            paste_button.set_has_frame(false); // Make it look like a menu item
            paste_button.set_margin_start(8);
            paste_button.set_margin_end(8);
            paste_button.set_margin_top(4);
            paste_button.set_margin_bottom(4);

            let canvas_items_paste = canvas_items_menu.clone();
            let state_paste = state_menu.clone();
            let fixed_weak_paste = fixed_weak_menu.clone();

            paste_button.connect_clicked(move |_| {
                handle_clipboard_paste(&canvas_items_paste, &state_paste, &fixed_weak_paste);
            });

            // Set the button as the popover's child
            popover.set_child(Some(&paste_button));

            // Set position relative to click
            if let Some(fixed_ref) = fixed_weak_menu.upgrade() {
                popover.set_parent(&fixed_ref);
                popover.set_pointing_to(Some(&gtk4::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
                popover.popup();
            }
        }
    });

    fixed.add_controller(right_click_controller);
}

/// Add an image to the canvas
fn add_image_to_canvas(
    canvas_items: &Rc<RefCell<Vec<CanvasItem>>>,
    state: &Rc<crate::ui::state::StateManager>,
    fixed_weak: &glib::WeakRef<Fixed>,
    texture: gdk::Texture,
    x: f64,
    y: f64,
    path: Option<String>,
) {
    // Validate texture dimensions to prevent GTK crashes
    if texture.width() == 0 || texture.height() == 0 {
        eprintln!(
            "Warning: Cannot add image with invalid dimensions ({}x{}) to canvas",
            texture.width(),
            texture.height()
        );
        return;
    }

    // Create canvas item
    let mut item = create_canvas_item(texture.clone(), x, y, path.clone());

    // Create Picture widget
    let picture = Picture::for_paintable(&texture);
    picture.set_size_request(texture.width(), texture.height());

    // Add to fixed container
    if let Some(fixed_ref) = fixed_weak.upgrade() {
        fixed_ref.put(&picture, x, y);
    }

    // Store the picture widget reference
    item.picture_widget = Some(picture.clone());

    // Add click handler for selection
    let canvas_items_click = canvas_items.clone();
    let fixed_weak_click = fixed_weak.clone();
    let picture_clone = picture.clone();
    let click_controller = gtk4::GestureClick::new();
    click_controller.connect_pressed(move |_, n_press, _, _| {
        if n_press == 1 {
            // Single click
            select_canvas_item(&canvas_items_click, &fixed_weak_click, &picture_clone);
            // Focus the canvas for keyboard events
            if let Some(fixed_ref) = fixed_weak_click.upgrade() {
                fixed_ref.grab_focus();
            }
        }
    });
    picture.add_controller(click_controller);

    // Add to canvas items
    canvas_items.borrow_mut().push(item);

    // Add evidence to model using state manager (dispatches events)
    if let Some(file_path) = path {
        let (phase_idx, step_idx) = {
            let model_rc = state.model();
            let model = model_rc.borrow();
            (model.selected_phase, model.selected_step)
        };

        if let Some(step_idx) = step_idx {
            let evidence = crate::model::Evidence {
                id: uuid::Uuid::new_v4(),
                path: file_path,
                created_at: chrono::Utc::now(),
                kind: "image".to_string(),
                x,
                y,
            };
            state.add_evidence(phase_idx, step_idx, evidence);
        }
    }
}

/// Handle image drop (shared between drag-drop and paste)
fn handle_image_drop(
    canvas_items: &Rc<RefCell<Vec<CanvasItem>>>,
    state: &Rc<crate::ui::state::StateManager>,
    fixed_weak: &glib::WeakRef<Fixed>,
    value: &glib::Value,
    x: f64,
    y: f64,
) -> bool {
    // Try to get file paths first
    if let Ok(file) = value.get::<gtk4::gio::File>() {
        if let Some(path) = file.path() {
            // Validate file extension
            if is_valid_image_extension(&path) {
                // Try creating texture from file
                if let Ok(texture) = create_texture_from_file(&path) {
                    // Copy the file to evidence directory and get relative path
                    let session_path = state.model().borrow().current_path.clone();
                    let relative_path = copy_file_to_evidence(&path, session_path.as_deref());

                    add_image_to_canvas(
                        canvas_items,
                        state,
                        fixed_weak,
                        texture,
                        x,
                        y,
                        relative_path,
                    );
                    return true;
                }
            }
        }
    }
    // Try direct pixbuf
    if let Ok(pixbuf) = value.get::<gdk::gdk_pixbuf::Pixbuf>() {
        // Save pixbuf to file
        let session_path = state.model().borrow().current_path.clone();
        let image_path = save_pasted_image(None, Some(&pixbuf), session_path.as_deref());
        match create_texture_from_pixbuf(&pixbuf) {
            Ok(texture) => {
                add_image_to_canvas(canvas_items, state, fixed_weak, texture, x, y, image_path);
            }
            Err(e) => {
                eprintln!("Failed to create texture from pixbuf: {}", e);
            }
        }
        return true;
    }
    false
}

/// Calculate a paste position that avoids overlapping with existing canvas items
fn calculate_paste_position(canvas_items: &Rc<RefCell<Vec<CanvasItem>>>) -> (f64, f64) {
    let items = canvas_items.borrow();
    let x = 10.0; // Start with some margin
    let y = 10.0;
    let spacing = 20.0; // Minimum spacing between items

    // If no items, use default position
    if items.is_empty() {
        return (x, y);
    }

    // Simple vertical stacking - place new item below the bottommost item
    let mut max_bottom = 0.0f64;

    for item in items.iter() {
        let item_bottom = item.y + item.height;
        if item_bottom > max_bottom {
            max_bottom = item_bottom;
        }
    }

    // Place new item below the bottommost item
    let new_x = 10.0; // Always start from left
    let new_y = max_bottom + spacing;

    (new_x, new_y)
}

/// Handle clipboard paste operation
fn handle_clipboard_paste(
    canvas_items: &Rc<RefCell<Vec<CanvasItem>>>,
    state: &Rc<crate::ui::state::StateManager>,
    fixed_weak: &glib::WeakRef<Fixed>,
) {
    // Clone the Rc values to move into the async closure
    let canvas_items = canvas_items.clone();
    let state = state.clone();
    let fixed_weak = fixed_weak.clone();

    // Get the clipboard
    if let Some(display) = gdk::Display::default() {
        let clipboard = display.clipboard();

        // Try to read texture from clipboard
        clipboard.read_texture_async(None::<&gtk4::gio::Cancellable>, move |result| {
            match result {
                Ok(Some(texture)) => {
                    // Save texture to file
                    let session_path = state.model().borrow().current_path.clone();
                    let image_path =
                        save_pasted_image(Some(&texture), None, session_path.as_deref());
                    // Calculate position to avoid overlapping
                    let (x, y) = calculate_paste_position(&canvas_items);
                    add_image_to_canvas(
                        &canvas_items,
                        &state,
                        &fixed_weak,
                        texture,
                        x,
                        y,
                        image_path,
                    );
                }
                _ => {
                    // If texture read failed, try reading as pixbuf
                    let canvas_items_pb = canvas_items.clone();
                    let state_pb = state.clone();
                    let fixed_weak_pb = fixed_weak.clone();

                    // Clone clipboard for the second async call
                    let clipboard_clone = display.clipboard();
                    clipboard_clone.read_value_async(
                        gdk::gdk_pixbuf::Pixbuf::static_type(),
                        glib::Priority::DEFAULT,
                        None::<&gtk4::gio::Cancellable>,
                        move |result| {
                            match result {
                                Ok(value) => {
                                    if let Ok(pixbuf) = value.get::<gdk::gdk_pixbuf::Pixbuf>() {
                                        // Save pixbuf to file
                                        let session_path =
                                            state_pb.model().borrow().current_path.clone();
                                        let image_path = save_pasted_image(
                                            None,
                                            Some(&pixbuf),
                                            session_path.as_deref(),
                                        );
                                        match create_texture_from_pixbuf(&pixbuf) {
                                            Ok(texture) => {
                                                // Calculate position to avoid overlapping
                                                let (x, y) =
                                                    calculate_paste_position(&canvas_items_pb);
                                                add_image_to_canvas(
                                                    &canvas_items_pb,
                                                    &state_pb,
                                                    &fixed_weak_pb,
                                                    texture,
                                                    x,
                                                    y,
                                                    image_path,
                                                );
                                            }
                                            Err(e) => {
                                                eprintln!(
                                                    "Failed to create texture from pixbuf: {}",
                                                    e
                                                );
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    // Pixbuf read failed - could show user feedback here
                                    eprintln!("Failed to read pixbuf from clipboard");
                                }
                            }
                        },
                    );
                }
            }
        });
    }
}

/// Select a canvas item and update visual feedback
fn select_canvas_item(
    canvas_items: &Rc<RefCell<Vec<CanvasItem>>>,
    _fixed_weak: &glib::WeakRef<Fixed>,
    clicked_picture: &gtk4::Picture,
) {
    let mut items = canvas_items.borrow_mut();

    // Clear previous selection
    for item in items.iter_mut() {
        item.selected = false;
        if let Some(picture) = &item.picture_widget {
            // Remove any selection styling (we'll use CSS classes)
            picture.remove_css_class("selected");
        }
    }

    // Find and select the clicked item
    for item in items.iter_mut() {
        if let Some(picture) = &item.picture_widget {
            if picture == clicked_picture {
                item.selected = true;
                picture.add_css_class("selected");
                break;
            }
        }
    }
}

/// Delete selected canvas items
fn delete_selected_items(
    canvas_items: &Rc<RefCell<Vec<CanvasItem>>>,
    _fixed_weak: &glib::WeakRef<Fixed>,
    state: &Rc<crate::ui::state::StateManager>,
) {
    let items = canvas_items.borrow();
    let mut indices_to_remove = Vec::new();

    // Find selected items
    for (i, item) in items.iter().enumerate() {
        if item.selected {
            indices_to_remove.push(i);
        }
    }

    // Remove items in reverse order to maintain indices
    for &index in indices_to_remove.iter().rev() {
        if let Some(item) = items.get(index) {
            // Remove the picture widget from the fixed container
            if let Some(fixed_ref) = _fixed_weak.upgrade() {
                if let Some(picture) = &item.picture_widget {
                    fixed_ref.remove(picture);
                }
            }

            // Remove evidence from the model using state manager
            // Note: This is a simplified approach - in a real implementation,
            // we'd need to match the item to its evidence entry
            let (phase_idx, step_idx) = {
                let model_rc = state.model();
                let model = model_rc.borrow();
                (model.selected_phase, model.selected_step)
            };

            if let Some(step_idx) = step_idx {
                // Get a list of evidence IDs that match this item's path
                let evidence_ids_to_remove: Vec<uuid::Uuid> = {
                    let model_rc = state.model();
                    let model = model_rc.borrow();
                    if let Some(step) = model
                        .session
                        .phases
                        .get(phase_idx)
                        .and_then(|p| p.steps.get(step_idx))
                    {
                        if let Some(ref item_path) = item.path {
                            step.get_evidence()
                                .iter()
                                .filter(|e| e.path == *item_path)
                                .map(|e| e.id)
                                .collect()
                        } else {
                            Vec::new()
                        }
                    } else {
                        Vec::new()
                    }
                };

                // Remove evidence using state manager (dispatches events)
                for evidence_id in evidence_ids_to_remove {
                    state.remove_evidence(phase_idx, step_idx, evidence_id);
                }
            }
        }
    }

    // Now remove the items from the canvas_items vector
    drop(items); // Release the immutable borrow
    let mut items_mut = canvas_items.borrow_mut();
    for &index in indices_to_remove.iter().rev() {
        items_mut.remove(index);
    }
}
