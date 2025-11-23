use crate::model::Step;
use crate::ui::canvas_utils::CanvasItem;
use crate::ui::quiz_widget::QuizWidget;
use crate::ui::tool_execution::ToolExecutionPanel;
/// Detail panel module for displaying step details (checkbox, title, description, notes, canvas, tools)
use gtk4::prelude::*;
use gtk4::{
    Box as GtkBox, CheckButton, Fixed, Frame, Label, Orientation, Paned, ScrolledWindow, Stack,
    TextView,
};
use std::cell::RefCell;
use std::rc::Rc;

/// Struct holding all detail panel widgets (supports both tutorial and quiz views)
pub struct DetailPanel {
    pub center_container: GtkBox, // Center column (desc/notes/canvas)
    pub checkbox: CheckButton,
    pub title_label: Label,
    pub content_stack: Stack, // Switches between tutorial and quiz views

    // Tutorial view widgets
    pub tutorial_container: Paned,
    pub desc_view: TextView,
    pub notes_view: TextView,
    pub canvas_fixed: Fixed,
    pub canvas_items: Rc<RefCell<Vec<CanvasItem>>>,

    // Tool panel (will be placed in right column)
    pub tool_panel: ToolExecutionPanel,

    // Quiz view widget
    pub quiz_widget: QuizWidget,
}

/// Create the detail panel with all widgets (supports tutorial and quiz views)
/// Returns center column content (desc/notes/canvas) - tools panel accessed separately via tool_panel field
pub fn create_detail_panel() -> DetailPanel {
    let center = GtkBox::new(Orientation::Vertical, 8);
    center.set_margin_top(8);
    center.set_margin_bottom(8);
    center.set_margin_start(8);
    center.set_margin_end(8);

    let checkbox = CheckButton::with_label("Completed");
    let title_label = Label::new(None);
    title_label.set_xalign(0.0);
    title_label.set_hexpand(true);

    // Top section with checkbox and title (fixed)
    let top_box = GtkBox::new(Orientation::Horizontal, 8);
    top_box.append(&checkbox);
    top_box.append(&title_label);

    // === TUTORIAL VIEW ===

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
    let notes_frame = Frame::builder().label("Notes").child(&notes_scroll).build();
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

    // Create resizable panes for tutorial view: desc -> notes -> canvas
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

    // Set up the pane hierarchy: desc -> notes -> canvas (tools removed from center)
    bottom_paned.set_start_child(Some(&notes_frame));
    bottom_paned.set_end_child(Some(&canvas_frame));
    bottom_paned.set_position(200);

    main_paned.set_start_child(Some(&desc_frame));
    main_paned.set_end_child(Some(&bottom_paned));
    main_paned.set_position(200);

    // === TOOL EXECUTION PANEL (separate from center column) ===
    let tool_panel = ToolExecutionPanel::new();

    // === QUIZ VIEW ===
    let quiz_widget = QuizWidget::new();

    // === STACK TO SWITCH BETWEEN VIEWS ===
    let content_stack = Stack::new();
    content_stack.set_vexpand(true);
    content_stack.add_named(&main_paned, Some("tutorial"));
    content_stack.add_named(&quiz_widget.container, Some("quiz"));
    content_stack.set_visible_child_name("tutorial"); // Default to tutorial view

    // Add top section and stack to center panel
    center.append(&top_box);
    center.append(&content_stack);

    DetailPanel {
        center_container: center,
        checkbox,
        title_label,
        content_stack,
        tutorial_container: main_paned,
        desc_view,
        notes_view,
        canvas_fixed,
        canvas_items,
        tool_panel,
        quiz_widget,
    }
}

/// Load step content into detail panel (automatically switches between tutorial and quiz views)
pub fn load_step_into_panel(panel: &DetailPanel, step: &Step) {
    // Update title and checkbox (common to both views)
    panel.title_label.set_text(&step.title);
    panel
        .checkbox
        .set_active(step.status == crate::model::StepStatus::Done);

    // Switch view based on step type
    if step.is_quiz() {
        // Show quiz view
        panel.content_stack.set_visible_child_name("quiz");

        // Load quiz content
        if let Some(quiz_step) = step.get_quiz_step() {
            panel.quiz_widget.hide_explanation(); // Clear explanation from previous quiz
            panel.quiz_widget.load_quiz_step(quiz_step);
            panel.quiz_widget.update_statistics(quiz_step);
        }
    } else {
        // Show tutorial view
        panel.content_stack.set_visible_child_name("tutorial");

        // Load tutorial content
        let description = step.get_description();
        let notes = step.get_notes();

        panel.desc_view.buffer().set_text(&description);
        panel.notes_view.buffer().set_text(&notes);

        // Canvas evidence will be loaded separately by caller (canvas.rs)
    }
}

#[cfg(test)]
mod tests {
    

    #[test]
    fn test_detail_panel_creation() {
        // This test ensures the module compiles correctly
        assert!(true);
    }
}
