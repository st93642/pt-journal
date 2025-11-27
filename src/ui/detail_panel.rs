use crate::model::Step;
use crate::ui::chat_panel::ChatPanel;
use crate::ui::quiz_widget::QuizWidget;
use crate::ui::tool_execution::ToolExecutionPanel;
/// Detail panel module for displaying step details (checkbox, title, description, chat)
use gtk4::prelude::*;
use gtk4::{
    Box as GtkBox, CheckButton, Frame, Label, Orientation, Paned, ScrolledWindow, Stack, TextView,
};
use std::rc::Rc;

/// Struct holding all detail panel widgets (supports both tutorial and quiz views)
pub struct DetailPanel {
    center_container: GtkBox, // Center column (desc/chat)
    checkbox: CheckButton,
    title_label: Label,
    content_stack: Stack, // Switches between tutorial and quiz views

    // Tutorial view widgets
    desc_view: TextView,
    chat_panel: ChatPanel,

    // Tool panel (will be placed in right column)
    tool_panel: Rc<ToolExecutionPanel>,

    // Quiz view widget
    quiz_widget: QuizWidget,
}

/// Create the detail panel with all widgets (supports tutorial and quiz views)
/// Returns center column content (desc/chat) - tools panel accessed separately via tool_panel field
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

    // Chat panel
    let chat_panel = ChatPanel::new();

    // Create resizable panes for tutorial view: desc -> chat
    let tutorial_paned = Paned::new(Orientation::Vertical);
    tutorial_paned.set_vexpand(true);
    tutorial_paned.set_resize_start_child(true);
    tutorial_paned.set_resize_end_child(true);
    tutorial_paned.set_shrink_start_child(false);
    tutorial_paned.set_shrink_end_child(false);

    // Set up the pane: desc -> chat
    tutorial_paned.set_start_child(Some(&desc_frame));
    tutorial_paned.set_end_child(Some(&chat_panel.container));
    tutorial_paned.set_position(200);

    // === TOOL EXECUTION PANEL (separate from center column) ===
    let tool_panel = Rc::new(ToolExecutionPanel::new());

    // === QUIZ VIEW ===
    let quiz_widget = QuizWidget::new();

    // === STACK TO SWITCH BETWEEN VIEWS ===
    let content_stack = Stack::new();
    content_stack.set_vexpand(true);
    content_stack.add_named(&tutorial_paned, Some("tutorial"));
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
        desc_view,
        chat_panel,
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
        if let Some(quiz_step) = step.quiz_data.as_ref() {
            panel.quiz_widget.hide_explanation(); // Clear explanation from previous quiz
            panel.quiz_widget.load_quiz_step(quiz_step);
            panel.quiz_widget.update_statistics(quiz_step);
        }
    } else {
        // Show tutorial view
        panel.content_stack.set_visible_child_name("tutorial");

        // Load tutorial content
        let description = &step.description;
        let chat_history = &step.chat_history;

        panel.desc_view.buffer().set_text(description);
        panel.chat_panel.load_history(chat_history);
    }
}

impl DetailPanel {
    /// Get the center container widget
    pub fn container(&self) -> &GtkBox {
        &self.center_container
    }

    /// Set the step title
    pub fn set_title(&self, title: &str) {
        self.title_label.set_text(title);
    }

    /// Set the completion checkbox state
    pub fn set_completion(&self, completed: bool) {
        self.checkbox.set_active(completed);
    }

    /// Get the current completion state
    pub fn is_completed(&self) -> bool {
        self.checkbox.is_active()
    }

    /// Load a tutorial step into the panel
    pub fn load_tutorial_step(
        &self,
        description: &str,
        chat_history: &[crate::model::ChatMessage],
    ) {
        self.content_stack.set_visible_child_name("tutorial");
        self.desc_view.buffer().set_text(description);
        self.chat_panel.load_history(chat_history);
    }

    /// Load a quiz step into the panel
    pub fn load_quiz_step(&self, quiz_step: &crate::model::QuizStep) {
        self.content_stack.set_visible_child_name("quiz");
        self.quiz_widget.hide_explanation();
        self.quiz_widget.load_quiz_step(quiz_step);
        self.quiz_widget.update_statistics(quiz_step);
    }

    /// Get access to the chat panel for controllers
    pub fn chat_panel(&self) -> &ChatPanel {
        &self.chat_panel
    }

    /// Get access to the tool panel for controllers
    pub fn tool_panel(&self) -> Rc<ToolExecutionPanel> {
        self.tool_panel.clone()
    }

    /// Get access to the quiz widget for controllers
    pub fn quiz_widget(&self) -> &QuizWidget {
        &self.quiz_widget
    }

    /// Get access to the description text view for controllers
    pub fn desc_view(&self) -> &TextView {
        &self.desc_view
    }

    /// Get access to the checkbox for controllers
    pub fn checkbox(&self) -> &CheckButton {
        &self.checkbox
    }
}
