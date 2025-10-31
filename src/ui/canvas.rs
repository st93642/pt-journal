use gtk4::prelude::*;
use gtk4::{Fixed, gdk, Picture};
use gtk4::glib;
use std::rc::Rc;
use std::cell::RefCell;
use uuid;
use chrono;

use super::canvas_utils::{CanvasItem, create_canvas_item, create_texture_from_file, is_valid_image_extension};
use super::image_utils::{create_texture_from_pixbuf, save_pasted_image};

/// Load evidence for a specific step onto the canvas
pub fn load_step_evidence(fixed: &Fixed, canvas_items: Rc<RefCell<Vec<CanvasItem>>>, step: &crate::model::Step) {
    // Clear existing canvas items and widgets
    canvas_items.borrow_mut().clear();

    // Remove all child widgets from the fixed container
    while let Some(child) = fixed.first_child() {
        fixed.remove(&child);
    }

    // Load evidence from the step
    for evidence in &step.evidence {
        // Try to create texture from the evidence path
        match create_texture_from_file(std::path::Path::new(&evidence.path)) {
            Ok(texture) => {
                // Validate texture dimensions to prevent GTK crashes
                if texture.width() == 0 || texture.height() == 0 {
                    eprintln!("Warning: Skipping evidence with invalid dimensions ({}x{}): {}",
                             texture.width(), texture.height(), evidence.path);
                    continue;
                }

                // Use stored position from evidence, or default if not available
                let item_x = evidence.x;
                let item_y = evidence.y;

                let mut item = create_canvas_item(texture.clone(), item_x, item_y, Some(evidence.path.clone()));

                // Create Picture widget and add to fixed container
                let picture = Picture::for_paintable(&texture);
                picture.set_size_request(texture.width() as i32, texture.height() as i32);
                fixed.put(&picture, item_x, item_y);

                // Store the picture widget reference
                item.picture_widget = Some(picture.clone());

                // Add click handler for selection
                let canvas_items_click = canvas_items.clone();
                let fixed_weak_click = fixed.downgrade();
                let picture_clone = picture.clone();
                let click_controller = gtk4::GestureClick::new();
                click_controller.connect_pressed(move |_, n_press, _, _| {
                    if n_press == 1 { // Single click
                        select_canvas_item(&canvas_items_click, &fixed_weak_click, &picture_clone);
                    }
                });
                picture.add_controller(click_controller);

                canvas_items.borrow_mut().push(item);
            }
            Err(e) => {
                eprintln!("Warning: Failed to load evidence from {}: {}", evidence.path, e);
                // Continue loading other evidence items
            }
        }
    }
}

/// Setup canvas with drag-drop and paste functionality
pub fn setup_canvas(fixed: &Fixed, canvas_items: Rc<RefCell<Vec<CanvasItem>>>, model: Rc<RefCell<crate::model::AppModel>>) {
    // Handle drag and drop on the fixed container
    let drop_target = gtk4::DropTarget::new(glib::Type::INVALID, gdk::DragAction::COPY);
    drop_target.set_preload(true);

    let canvas_items_drop = canvas_items.clone();
    let model_drop = model.clone();
    let fixed_weak = fixed.downgrade();
    drop_target.connect_drop(move |_target, value, x, y| {
        handle_image_drop(&canvas_items_drop, &model_drop, &fixed_weak, value, x, y)
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
    let model_key = model.clone();
    let fixed_weak_key = fixed.downgrade();

    key_controller.connect_key_pressed(move |_, keyval, _keycode, modifier| {
        // Check for Ctrl+V
        if keyval == gdk::Key::v && modifier.contains(gdk::ModifierType::CONTROL_MASK) {
            handle_clipboard_paste(&canvas_items_key, &model_key, &fixed_weak_key);
            return glib::Propagation::Stop;
        }
        // Check for Delete key
        if keyval == gdk::Key::Delete {
            delete_selected_items(&canvas_items_key, &fixed_weak_key, &model_key);
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });

    fixed.add_controller(key_controller);

    // Handle canvas background clicks to focus for keyboard events
    let canvas_click_controller = gtk4::GestureClick::new();
    let fixed_weak_canvas = fixed.downgrade();
    canvas_click_controller.connect_pressed(move |_, n_press, _, _| {
        if n_press == 1 { // Single click on canvas background
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
    let model_menu = model.clone();
    let fixed_weak_menu = fixed.downgrade();

    right_click_controller.connect_pressed(move |_controller, n_press, x, y| {
        if n_press == 1 { // Single right-click
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
            let model_paste = model_menu.clone();
            let fixed_weak_paste = fixed_weak_menu.clone();

            paste_button.connect_clicked(move |_| {
                handle_clipboard_paste(&canvas_items_paste, &model_paste, &fixed_weak_paste);
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
    model: &Rc<RefCell<crate::model::AppModel>>,
    fixed_weak: &glib::WeakRef<Fixed>,
    texture: gdk::Texture,
    x: f64,
    y: f64,
    path: Option<String>,
) {
    // Validate texture dimensions to prevent GTK crashes
    if texture.width() == 0 || texture.height() == 0 {
        eprintln!("Warning: Cannot add image with invalid dimensions ({}x{}) to canvas",
                 texture.width(), texture.height());
        return;
    }

    // Create canvas item
    let mut item = create_canvas_item(texture.clone(), x, y, path.clone());

    // Create Picture widget
    let picture = Picture::for_paintable(&texture);
    picture.set_size_request(texture.width() as i32, texture.height() as i32);

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
        if n_press == 1 { // Single click
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

    // Add evidence to model if we have a path
    if let Some(file_path) = path {
        let (phase_idx, step_idx) = {
            let model_borrow = model.borrow();
            (model_borrow.selected_phase, model_borrow.selected_step)
        };

        if let Some(step_idx) = step_idx {
            if let Some(step) = model.borrow_mut().session.phases.get_mut(phase_idx).and_then(|p| p.steps.get_mut(step_idx)) {
                let evidence = crate::model::Evidence {
                    id: uuid::Uuid::new_v4(),
                    path: file_path,
                    created_at: chrono::Utc::now(),
                    kind: "image".to_string(),
                    x,
                    y,
                };
                step.evidence.push(evidence);
            }
        }
    }
}

/// Handle image drop (shared between drag-drop and paste)
fn handle_image_drop(
    canvas_items: &Rc<RefCell<Vec<CanvasItem>>>,
    model: &Rc<RefCell<crate::model::AppModel>>,
    fixed_weak: &glib::WeakRef<Fixed>,
    value: &glib::Value,
    x: f64,
    y: f64,
) -> bool {
    // Try to get file paths first
    if let Ok(file) = value.get::<gtk4::gio::File>() && let Some(path) = file.path() {
        // Validate file extension
        if is_valid_image_extension(&path) {
            // Try creating texture from file
            if let Ok(texture) = create_texture_from_file(&path) {
                add_image_to_canvas(canvas_items, model, fixed_weak, texture, x, y, Some(path.to_string_lossy().to_string()));
                return true;
            }
        }
    }
    // Try direct pixbuf
    if let Ok(pixbuf) = value.get::<gdk::gdk_pixbuf::Pixbuf>() {
        // Save pixbuf to file
        let image_path = save_pasted_image(None, Some(&pixbuf));
        match create_texture_from_pixbuf(&pixbuf) {
            Ok(texture) => {
                add_image_to_canvas(canvas_items, model, fixed_weak, texture, x, y, image_path);
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
    model: &Rc<RefCell<crate::model::AppModel>>,
    fixed_weak: &glib::WeakRef<Fixed>,
) {
    // Clone the Rc values to move into the async closure
    let canvas_items = canvas_items.clone();
    let model = model.clone();
    let fixed_weak = fixed_weak.clone();

    // Get the clipboard
    if let Some(display) = gdk::Display::default() {
        let clipboard = display.clipboard();

        // Try to read texture from clipboard
        clipboard.read_texture_async(None::<&gtk4::gio::Cancellable>, move |result| {
            match result {
                Ok(Some(texture)) => {
                    // Save texture to file
                    let image_path = save_pasted_image(Some(&texture), None);
                    // Calculate position to avoid overlapping
                    let (x, y) = calculate_paste_position(&canvas_items);
                    add_image_to_canvas(&canvas_items, &model, &fixed_weak, texture, x, y, image_path);
                }
                _ => {
                    // If texture read failed, try reading as pixbuf
                    let canvas_items_pb = canvas_items.clone();
                    let model_pb = model.clone();
                    let fixed_weak_pb = fixed_weak.clone();

                    // Clone clipboard for the second async call
                    let clipboard_clone = display.clipboard();
                    clipboard_clone.read_value_async(gdk::gdk_pixbuf::Pixbuf::static_type(), glib::Priority::DEFAULT, None::<&gtk4::gio::Cancellable>, move |result| {
                        match result {
                            Ok(value) => {
                                if let Ok(pixbuf) = value.get::<gdk::gdk_pixbuf::Pixbuf>() {
                                    // Save pixbuf to file
                                    let image_path = save_pasted_image(None, Some(&pixbuf));
                                    match create_texture_from_pixbuf(&pixbuf) {
                                        Ok(texture) => {
                                            // Calculate position to avoid overlapping
                                            let (x, y) = calculate_paste_position(&canvas_items_pb);
                                            add_image_to_canvas(&canvas_items_pb, &model_pb, &fixed_weak_pb, texture, x, y, image_path);
                                        }
                                        Err(e) => {
                                            eprintln!("Failed to create texture from pixbuf: {}", e);
                                        }
                                    }
                                }
                            }
                            _ => {
                                // Pixbuf read failed - could show user feedback here
                                eprintln!("Failed to read pixbuf from clipboard");
                            }
                        }
                    });
                }
            }
        });
    }
}

/// Select a canvas item and update visual feedback
fn select_canvas_item(canvas_items: &Rc<RefCell<Vec<CanvasItem>>>, _fixed_weak: &glib::WeakRef<Fixed>, clicked_picture: &gtk4::Picture) {
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
fn delete_selected_items(canvas_items: &Rc<RefCell<Vec<CanvasItem>>>, _fixed_weak: &glib::WeakRef<Fixed>, model: &Rc<RefCell<crate::model::AppModel>>) {
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

            // Remove evidence from the model if it exists
            // Note: This is a simplified approach - in a real implementation,
            // we'd need to match the item to its evidence entry
            let (phase_idx, step_idx) = {
                let model_borrow = model.borrow();
                (model_borrow.selected_phase, model_borrow.selected_step)
            };

            if let Some(step_idx) = step_idx {
                if let Some(step) = model.borrow_mut().session.phases.get_mut(phase_idx).and_then(|p| p.steps.get_mut(step_idx)) {
                    // Remove evidence that matches this item's path (if it has one)
                    if let Some(ref item_path) = item.path {
                        step.evidence.retain(|e| e.path != *item_path);
                    }
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