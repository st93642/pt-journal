use crate::model::{ChatMessage, ChatRole};
use gtk4::prelude::*;
use gtk4::{Box as GtkBox, Button, Label, ListBox, Orientation, ScrolledWindow, Spinner, TextView, TextBuffer};

/// Chat panel widget for displaying chat history and input
#[derive(Clone)]
pub struct ChatPanel {
    pub container: GtkBox,
    pub history_list: ListBox,
    pub input_textview: TextView,
    pub input_buffer: TextBuffer,
    pub send_button: Button,
    pub loading_spinner: Spinner,
    pub error_label: Label,
}

impl ChatPanel {
    pub fn new() -> Self {
        let container = GtkBox::new(Orientation::Vertical, 8);
        container.set_margin_top(8);
        container.set_margin_bottom(8);
        container.set_margin_start(8);
        container.set_margin_end(8);
        container.add_css_class("chat-panel");

        // Chat history
        let history_list = ListBox::new();
        history_list.set_selection_mode(gtk4::SelectionMode::None);
        history_list.add_css_class("chat-history");
        let history_scroll = ScrolledWindow::new();
        history_scroll.add_css_class("chat-history-scroll");
        history_scroll.set_child(Some(&history_list));
        history_scroll.set_vexpand(true);
        history_scroll.set_min_content_height(200);

        // Input area
        let input_box = GtkBox::new(Orientation::Vertical, 4);
        
        // Create a scrolled window for the text input
        let input_scroll = ScrolledWindow::new();
        input_scroll.set_min_content_height(60); // Make it taller
        input_scroll.set_max_content_height(120); // But not too tall
        input_scroll.add_css_class("chat-input-scroll");
        
        let input_buffer = TextBuffer::new(None);
        let input_textview = TextView::new();
        input_textview.set_buffer(Some(&input_buffer));
        input_textview.set_wrap_mode(gtk4::WrapMode::Word);
        input_textview.set_accepts_tab(false);
        input_textview.add_css_class("chat-input");
        
        // Add placeholder text by setting initial buffer content
        input_buffer.set_text("Ask about this step...");
        input_textview.add_css_class("placeholder");
        
        input_scroll.set_child(Some(&input_textview));
        
        let send_button = Button::with_label("Send");
        send_button.set_sensitive(false); // Disabled until text is entered

        input_box.append(&input_scroll);
        input_box.append(&send_button);

        // Loading indicator
        let loading_spinner = Spinner::new();
        loading_spinner.set_visible(false);

        // Error banner
        let error_label = Label::new(None);
        error_label.set_visible(false);
        error_label.add_css_class("error");

        // Connect input buffer to enable/disable send button
        let send_button_clone = send_button.clone();
        let buffer_clone = input_buffer.clone();
        input_buffer.connect_changed(move |_| {
            let text = buffer_clone.text(&buffer_clone.start_iter(), &buffer_clone.end_iter(), false);
            send_button_clone.set_sensitive(!text.trim().is_empty());
        });

        // Add to container
        container.append(&history_scroll);
        container.append(&loading_spinner);
        container.append(&error_label);
        container.append(&input_box);

        ChatPanel {
            container,
            history_list,
            input_textview,
            input_buffer,
            send_button,
            loading_spinner,
            error_label,
        }
    }

    /// Clear all messages from the chat history
    pub fn clear_history(&self) {
        while let Some(child) = self.history_list.first_child() {
            self.history_list.remove(&child);
        }
    }

    /// Add a message to the chat history
    pub fn add_message(&self, message: &ChatMessage) {
        let message_box = GtkBox::new(Orientation::Vertical, 4);
        message_box.set_margin_top(8);
        message_box.set_margin_bottom(8);
        message_box.set_margin_start(8);
        message_box.set_margin_end(8);
        message_box.add_css_class("chat-message");

        // Role label
        let role_label = Label::new(Some(match message.role {
            ChatRole::User => "You",
            ChatRole::Assistant => "Assistant",
        }));
        role_label.set_xalign(0.0);
        role_label.add_css_class(match message.role {
            ChatRole::User => "user-message",
            ChatRole::Assistant => "assistant-message",
        });

        // Timestamp
        let timestamp = message.timestamp.format("%H:%M:%S").to_string();
        let time_label = Label::new(Some(&timestamp));
        time_label.set_xalign(0.0);
        time_label.add_css_class("timestamp");

        // Message content
        let content_label = Label::new(Some(&message.content));
        content_label.set_xalign(0.0);
        content_label.set_wrap(true);
        content_label.set_wrap_mode(gtk4::pango::WrapMode::Word);
        content_label.set_max_width_chars(80);
        content_label.set_selectable(true);

        message_box.append(&role_label);
        message_box.append(&time_label);
        message_box.append(&content_label);

        self.history_list.append(&message_box);
    }

    /// Load chat history from a vector of messages
    pub fn load_history(&self, history: &[ChatMessage]) {
        self.clear_history();
        for message in history {
            self.add_message(message);
        }
    }

    /// Show loading indicator
    pub fn show_loading(&self) {
        self.loading_spinner.set_visible(true);
        self.loading_spinner.start();
        self.send_button.set_sensitive(false);
        self.input_textview.set_sensitive(false);
    }

    /// Hide loading indicator
    pub fn hide_loading(&self) {
        self.loading_spinner.set_visible(false);
        self.loading_spinner.stop();
        self.send_button.set_sensitive(true);
        self.input_textview.set_sensitive(true);
    }

    /// Show error message
    pub fn show_error(&self, error: &str) {
        self.error_label.set_text(error);
        self.error_label.set_visible(true);
    }

    /// Hide error message
    pub fn hide_error(&self) {
        self.error_label.set_visible(false);
    }

    /// Get the current input text and clear the entry
    pub fn take_input(&self) -> String {
        let text = self.input_buffer.text(&self.input_buffer.start_iter(), &self.input_buffer.end_iter(), false);
        self.input_buffer.set_text("");
        text.to_string()
    }
}

impl Default for ChatPanel {
    fn default() -> Self {
        Self::new()
    }
}
