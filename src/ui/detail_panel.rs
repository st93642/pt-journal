/// Detail panel module for displaying step details (checkbox, title, description, notes, canvas)
use gtk4::prelude::*;
use gtk4::{Box as GtkBox, Orientation, CheckButton, Label, TextView, Frame, ScrolledWindow, Paned, Fixed};
use std::rc::Rc;
use std::cell::RefCell;
use crate::ui::canvas_utils::CanvasItem;

/// Struct holding all detail panel widgets
pub struct DetailPanel {
    pub container: GtkBox,
    pub checkbox: CheckButton,
    pub title_label: Label,
    pub desc_view: TextView,
    pub notes_view: TextView,
    pub canvas_fixed: Fixed,
    pub canvas_items: Rc<RefCell<Vec<CanvasItem>>>,
}

/// Create the detail panel with all widgets
pub fn create_detail_panel() -> DetailPanel {
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

    // Description view (for user notes in description area)
    let desc_view = TextView::new();
    desc_view.set_editable(true);
    desc_view.set_wrap_mode(gtk4::WrapMode::Word);
    desc_view.set_accepts_tab(false);
    let desc_scroll = ScrolledWindow::new();
    desc_scroll.set_child(Some(&desc_view));
    desc_scroll.set_vexpand(true);
    desc_scroll.set_min_content_height(100);
    let desc_frame = Frame::builder()
        .label("Description")
        .child(&desc_scroll)
        .margin_top(4)
        .margin_bottom(4)
        .margin_start(4)
        .margin_end(4)
        .build();
    desc_frame.set_size_request(-1, 80);

    // Notes view
    let notes_view = TextView::new();
    notes_view.set_monospace(true);
    notes_view.set_vexpand(true);
    let notes_scroll = ScrolledWindow::new();
    notes_scroll.set_child(Some(&notes_view));
    notes_scroll.set_vexpand(true);
    notes_scroll.set_min_content_height(100);
    let notes_frame = Frame::builder()
        .label("Notes")
        .child(&notes_scroll)
        .build();
    notes_frame.set_size_request(-1, 80);

    // Canvas for evidence/images
    let canvas_items = Rc::new(RefCell::new(Vec::<CanvasItem>::new()));
    let canvas_fixed = Fixed::new();
    canvas_fixed.set_size_request(800, 600);
    canvas_fixed.set_can_focus(true);
    canvas_fixed.set_focusable(true);
    let canvas_scroll = ScrolledWindow::new();
    canvas_scroll.set_child(Some(&canvas_fixed));
    canvas_scroll.set_vexpand(true);
    canvas_scroll.set_min_content_height(100);
    let canvas_frame = Frame::builder()
        .label("Evidence Canvas")
        .child(&canvas_scroll)
        .build();
    canvas_frame.set_size_request(-1, 80);

    // Create resizable panes
    let main_paned = Paned::new(Orientation::Vertical);
    main_paned.set_vexpand(true);
    main_paned.set_resize_start_child(true);
    main_paned.set_resize_end_child(true);
    main_paned.set_shrink_start_child(false);
    main_paned.set_shrink_end_child(false);

    let bottom_paned = Paned::new(Orientation::Vertical);
    bottom_paned.set_vexpand(true);
    bottom_paned.set_resize_start_child(true);
    bottom_paned.set_resize_end_child(true);
    bottom_paned.set_shrink_start_child(false);
    bottom_paned.set_shrink_end_child(false);

    // Set up the pane hierarchy
    bottom_paned.set_start_child(Some(&notes_frame));
    bottom_paned.set_end_child(Some(&canvas_frame));
    bottom_paned.set_position(300);

    main_paned.set_start_child(Some(&desc_frame));
    main_paned.set_end_child(Some(&bottom_paned));
    main_paned.set_position(200);

    // Add top section and main paned to right panel
    right.append(&top_box);
    right.append(&main_paned);

    DetailPanel {
        container: right,
        checkbox,
        title_label,
        desc_view,
        notes_view,
        canvas_fixed,
        canvas_items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_detail_panel_creation() {
        // This test ensures the module compiles correctly
        assert!(true);
    }
}
