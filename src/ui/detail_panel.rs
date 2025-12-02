use crate::model::Step;
use crate::ui::chat_panel::ChatPanel;
use crate::ui::quiz_widget::QuizWidget;
use crate::ui::tool_execution::ToolExecutionPanel;
/// Detail panel module for displaying step details (checkbox, title, description, chat)
use gtk4::prelude::*;
use gtk4::{
    Box as GtkBox, CheckButton, Frame, Label, Orientation, Paned, ScrolledWindow, Stack, TextView,
};
use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use std::rc::Rc;
use syntect::easy::HighlightLines;
use syntect::highlighting::{Style, ThemeSet};
use syntect::parsing::SyntaxSet;
use syntect::util::LinesWithEndings;

/// Convert syntax highlighting style to Pango markup
pub fn style_to_pango(style: &Style) -> String {
    let mut pango = String::from("<span");

    // Add font family for code
    pango.push_str(" font_family=\"monospace\"");

    // Convert foreground color
    let fg = style.foreground;
    pango.push_str(&format!(
        " foreground=\"#{:02x}{:02x}{:02x}\"",
        fg.r, fg.g, fg.b
    ));

    // Convert background color if different from default (not black)
    let bg = style.background;
    if bg.r != 0 || bg.g != 0 || bg.b != 0 {
        pango.push_str(&format!(
            " background=\"#{:02x}{:02x}{:02x}\"",
            bg.r, bg.g, bg.b
        ));
    }

    pango.push('>');
    pango
}

/// Highlight code using syntect and return Pango markup
pub fn highlight_code(code: &str, language: &str) -> String {
    // Initialize syntax set and theme set
    let ps = SyntaxSet::load_defaults_newlines();
    let ts = ThemeSet::load_defaults();

    // Get syntax definition for the language
    let syntax = ps
        .find_syntax_by_token(language)
        .unwrap_or_else(|| ps.find_syntax_plain_text());

    // Use a dark theme for better contrast (you can change this)
    let theme = &ts.themes["base16-ocean.dark"];

    let mut highlighter = HighlightLines::new(syntax, theme);
    let mut highlighted = String::new();

    // Process each line
    for line in LinesWithEndings::from(code) {
        let ranges = highlighter.highlight_line(line, &ps).unwrap_or_default();

        for (style, text) in ranges {
            highlighted.push_str(&style_to_pango(&style));
            // Escape Pango markup characters
            let escaped = text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
            highlighted.push_str(&escaped);
            highlighted.push_str("</span>");
        }
    }

    highlighted
}

/// Convert markdown to Pango markup for GTK TextView
pub fn markdown_to_pango(markdown: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    let parser = Parser::new_ext(markdown, options);

    let mut pango = String::new();
    let mut in_code_block = false;
    let mut code_block_content = String::new();
    let mut code_language = String::new();

    for event in parser {
        match event {
            Event::Start(Tag::Paragraph) => {
                // Paragraph start
            }
            Event::End(TagEnd::Paragraph) => {
                pango.push_str("\n\n");
            }
            Event::Start(Tag::Heading { level, .. }) => match level {
                HeadingLevel::H1 => pango.push_str("<span font_weight=\"bold\" size=\"larger\">"),
                HeadingLevel::H2 => pango.push_str("<span font_weight=\"bold\" size=\"large\">"),
                _ => pango.push_str("<span font_weight=\"bold\">"),
            },
            Event::End(TagEnd::Heading(..)) => {
                pango.push_str("</span>\n\n");
            }
            Event::Start(Tag::CodeBlock(kind)) => {
                in_code_block = true;
                code_language = match kind {
                    CodeBlockKind::Fenced(lang) => lang.to_string(),
                    _ => String::new(),
                };
                code_block_content.clear();
            }
            Event::End(TagEnd::CodeBlock) => {
                // Apply syntax highlighting to the collected code block content
                let highlighted = highlight_code(&code_block_content, &code_language);
                pango.push_str(&highlighted);
                pango.push('\n');
                in_code_block = false;
                code_block_content.clear();
            }
            Event::Start(Tag::Item) => {
                pango.push_str("• ");
            }
            Event::End(TagEnd::Item) => {
                pango.push('\n');
            }
            Event::Start(Tag::Emphasis) => {
                pango.push_str("<i>");
            }
            Event::End(TagEnd::Emphasis) => {
                pango.push_str("</i>");
            }
            Event::Start(Tag::Strong) => {
                pango.push_str("<b>");
            }
            Event::End(TagEnd::Strong) => {
                pango.push_str("</b>");
            }
            Event::Start(Tag::Link { .. }) => {
                // For simplicity, just make links blue
                pango.push_str("<span foreground=\"#0000ff\">");
            }
            Event::End(TagEnd::Link) => {
                pango.push_str("</span>");
            }
            Event::Text(text) => {
                if in_code_block {
                    // Collect code block content for syntax highlighting
                    code_block_content.push_str(&text);
                } else {
                    // Regular text - escape for Pango
                    let escaped = text
                        .replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;");
                    pango.push_str(&escaped);
                }
            }
            Event::Code(code) => {
                // Inline code - use basic highlighting
                pango.push_str("<span font_family=\"monospace\" background=\"#f0f0f0\">");
                let escaped = code
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;");
                pango.push_str(&escaped);
                pango.push_str("</span>");
            }
            Event::SoftBreak => {
                pango.push(' ');
            }
            Event::HardBreak => {
                pango.push('\n');
            }
            _ => {
                // Other events - ignore for now
            }
        }
    }

    pango
}

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

    // Related tools display area
    related_tools_box: GtkBox,

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

    // Related Tools section
    let related_tools_box = GtkBox::new(Orientation::Horizontal, 8);
    related_tools_box.set_margin_top(4);
    related_tools_box.set_margin_bottom(4);
    related_tools_box.set_margin_start(4);
    related_tools_box.set_margin_end(4);
    
    let related_tools_label = Label::new(Some("Related Tools:"));
    related_tools_label.set_xalign(0.0);
    related_tools_label.add_css_class("heading");
    
    let related_tools_frame = Frame::builder()
        .label_widget(&related_tools_label)
        .child(&related_tools_box)
        .build();

    // Chat panel
    let chat_panel = ChatPanel::new();

    // Create resizable panes for tutorial view: desc -> related_tools -> chat
    let tutorial_paned = Paned::new(Orientation::Vertical);
    tutorial_paned.set_vexpand(true);
    tutorial_paned.set_resize_start_child(true);
    tutorial_paned.set_resize_end_child(true);
    tutorial_paned.set_shrink_start_child(false);
    tutorial_paned.set_shrink_end_child(false);

    // Create container for desc + tools
    let desc_tools_box = GtkBox::new(Orientation::Vertical, 4);
    desc_tools_box.append(&desc_frame);
    desc_tools_box.append(&related_tools_frame);

    // Set up the pane: (desc + tools) -> chat
    tutorial_paned.set_start_child(Some(&desc_tools_box));
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
        related_tools_box,
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

    // Clear and populate related tools box
    // Remove all children from related_tools_box
    while let Some(child) = panel.related_tools_box.first_child() {
        panel.related_tools_box.remove(&child);
    }

    // Add tool buttons for each related tool
    for tool_id in &step.related_tools {
        let button = gtk4::Button::with_label(tool_id);
        button.set_css_classes(&["suggested-action", "pill"]);
        button.set_size_request(120, -1);
        panel.related_tools_box.append(&button);
    }

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

        // Convert markdown to Pango markup
        let pango_markup = markdown_to_pango(description);

        // Clear the buffer and insert markup
        let buffer = panel.desc_view.buffer();
        buffer.set_text("");
        buffer.insert_markup(&mut buffer.start_iter(), &pango_markup);

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

        // Convert markdown to Pango markup
        let pango_markup = markdown_to_pango(description);

        // Clear the buffer and insert markup
        let buffer = self.desc_view.buffer();
        buffer.set_text("");
        buffer.insert_markup(&mut buffer.start_iter(), &pango_markup);

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
