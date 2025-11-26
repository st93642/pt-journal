use super::{
    controller::{DefaultInstructionProvider, ToolPanelController},
    interfaces::{ToolPanelView},
    terminal::VteTerminal,
};
use gtk4::glib;
use gtk4::prelude::*;
#[allow(deprecated)]
use gtk4::{
    Box as GtkBox, Button, ComboBoxText, Dialog, Frame, GestureClick, Label, Orientation,
    PopoverMenu, ResponseType, ScrolledWindow,
};
use std::cell::RefCell;
use std::process::Command;
use std::rc::Rc;
use std::time::Duration;
use vte::prelude::*;

/// Manual security tools panel with inline instructions and an embedded terminal
#[allow(deprecated)]
pub struct ToolExecutionPanel {
    pub container: GtkBox,
    pub category_selector: ComboBoxText,
    pub tool_selector: ComboBoxText,
    pub info_button: Button,
    pub instructions_scroll: ScrolledWindow,
    pub terminal: vte::Terminal,
    controller: Rc<RefCell<ToolPanelController<DefaultInstructionProvider, VteTerminal, GtkToolPanelView>>>,
}

#[allow(deprecated)]
impl ToolExecutionPanel {
    pub fn new() -> Self {
        let container = GtkBox::new(Orientation::Vertical, 12);
        container.set_margin_top(12);
        container.set_margin_bottom(12);
        container.set_margin_start(12);
        container.set_margin_end(12);
        container.set_vexpand(true);
        container.set_hexpand(true);

        // Header
        let header = Label::new(Some("Security Tool Reference"));
        header.add_css_class("title-3");
        container.append(&header);

        // Category selector row
        let category_box = GtkBox::new(Orientation::Horizontal, 8);
        let category_label = Label::new(Some("Category:"));
        category_label.set_width_chars(10);
        category_label.set_xalign(0.0);

        let category_selector = ComboBoxText::new();
        category_selector.set_hexpand(true);
        category_box.append(&category_label);
        category_box.append(&category_selector);
        container.append(&category_box);

        // Tool selector row
        let tool_box = GtkBox::new(Orientation::Horizontal, 8);
        let tool_label = Label::new(Some("Tool:"));
        tool_label.set_width_chars(10);
        tool_label.set_xalign(0.0);

        let tool_selector = ComboBoxText::new();
        tool_selector.set_hexpand(true);
        tool_box.append(&tool_label);
        tool_box.append(&tool_selector);
        container.append(&tool_box);

        // Info button row
        let info_button = Button::with_label("📖 Full Instructions");
        info_button.set_halign(gtk4::Align::Start);
        container.append(&info_button);

        // Instructions scroll area
        let instructions_scroll = ScrolledWindow::new();
        instructions_scroll.set_vexpand(true);
        instructions_scroll.set_min_content_height(200);
        container.append(&instructions_scroll);

        // Terminal section
        let terminal_frame = Frame::new(Some("Terminal"));
        let terminal_scroll = ScrolledWindow::new();
        let terminal = vte::Terminal::new();
        terminal_scroll.set_child(Some(&terminal));
        terminal_frame.set_child(Some(&terminal_scroll));
        terminal_frame.set_vexpand(true);
        terminal_frame.set_hexpand(true);
        terminal_scroll.set_vexpand(true);
        terminal_scroll.set_hexpand(true);
        // Set minimum size for terminal to prevent it from becoming too small
        terminal.set_size_request(400, 300);
        container.append(&terminal_frame);

        // Set up terminal
        let terminal_clone = terminal.clone();
        glib::idle_add_local_once(move || {
            terminal_clone.spawn_async(
                vte::PtyFlags::DEFAULT,
                None,
                &["/bin/bash"],
                &[],
                glib::SpawnFlags::DEFAULT,
                || {},
                -1,
                None::<&gtk4::gio::Cancellable>,
                |result| {
                    if let Err(e) = result {
                        eprintln!("Failed to spawn terminal: {}", e);
                    }
                },
            );
        });

        // Create the view wrapper
        let view = GtkToolPanelView {
            category_selector: category_selector.clone(),
            tool_selector: tool_selector.clone(),
            instructions_scroll: instructions_scroll.clone(),
        };

        // Create the controller
        let provider = DefaultInstructionProvider;
        let terminal_interface = VteTerminal::new(terminal.clone());
        let controller = Rc::new(RefCell::new(ToolPanelController::new(provider, terminal_interface, view)));

        let panel = Self {
            container,
            category_selector,
            tool_selector,
            info_button,
            instructions_scroll,
            terminal,
            controller,
        };

        // Initialize the panel
        panel.controller.borrow().initialize();

        // Set up event handlers AFTER initialization using idle callback to ensure GTK is ready
        let panel_clone = panel.controller.clone();
        let category_selector_clone = panel.category_selector.clone();
        let tool_selector_clone = panel.tool_selector.clone();
        let info_button_clone = panel.info_button.clone();
        let terminal_clone = panel.terminal.clone();
        
        glib::idle_add_local_once(move || {
            // Category selector handler
            let controller = panel_clone.clone();
            let _handler_id = category_selector_clone.connect_changed(move |selector| {
                let active_text = selector.active_text();
                controller.borrow().on_category_changed(active_text.as_deref());
            });
            // Store the handler ID (we'll need to access it later, but for now we'll handle blocking differently)

            // Tool selector handler
            let _controller = panel_clone.clone();
            tool_selector_clone.connect_changed(move |_| {
                _controller.borrow().on_tool_changed();
            });

            // Info button handler
            let _controller = panel_clone.clone();
            info_button_clone.connect_clicked(move |_| {
                // For the info button, we need access to the window.
                // This is a limitation of the current design - the controller
                // doesn't have access to the window. We could pass it through
                // or handle this differently.
            });

            // Set up terminal context menu
            let right_click = GestureClick::new();
            right_click.set_button(3); // Right mouse button

            let terminal_clone_inner = terminal_clone.clone();
            right_click.connect_pressed(move |_, _, _, _| {
                let menu = gtk4::gio::Menu::new();
                menu.append(Some("Copy"), Some("terminal.copy"));
                menu.append(Some("Paste"), Some("terminal.paste"));

                let popover = PopoverMenu::from_model(Some(&menu));
                popover.set_parent(&terminal_clone_inner);

                let action_group = gtk4::gio::SimpleActionGroup::new();

                let copy_action = gtk4::gio::SimpleAction::new("copy", None);
                let terminal_copy = terminal_clone_inner.clone();
                copy_action.connect_activate(move |_, _| {
                    terminal_copy.copy_clipboard_format(vte::Format::Text);
                });
                action_group.add_action(&copy_action);

                let paste_action = gtk4::gio::SimpleAction::new("paste", None);
                let terminal_paste = terminal_clone_inner.clone();
                paste_action.connect_activate(move |_, _| {
                    terminal_paste.paste_clipboard();
                });
                action_group.add_action(&paste_action);

                terminal_clone_inner.insert_action_group("terminal", Some(&action_group));
                popover.popup();
            });

            terminal_clone.add_controller(right_click);
        });

        panel
    }

    /// Returns the currently selected tool ID.
    pub fn get_selected_tool(&self) -> Option<String> {
        self.controller.borrow().selected_tool()
    }

    /// Shows the instructions dialog for the selected tool.
    pub fn show_instructions_dialog(&self, window: &gtk4::Window) {
        let controller_borrow = self.controller.borrow();
        let tool_id = controller_borrow.selected_tool();
        let state = controller_borrow.resolve_instruction_state(tool_id.as_deref());
        let dialog_title = state.dialog_title();
        let instruction_box = state.inline_widget();

        let dialog = Dialog::with_buttons(
            Some(&dialog_title),
            Some(window),
            gtk4::DialogFlags::DESTROY_WITH_PARENT,
            &[("Close", ResponseType::Close)],
        );

        dialog.set_default_size(1000, 650);
        dialog.connect_response(|dialog, response| {
            if response == ResponseType::Close {
                dialog.close();
            }
        });

        let content = dialog.content_area();
        content.set_margin_top(12);
        content.set_margin_bottom(12);
        content.set_margin_start(12);
        content.set_margin_end(12);

        let scroll = ScrolledWindow::new();
        scroll.set_vexpand(true);
        scroll.set_hexpand(true);
        scroll.set_child(Some(&instruction_box));
        content.append(&scroll);

        let window_title = dialog_title.clone();
        dialog.present();

        glib::timeout_add_local_once(Duration::from_millis(100), move || {
            let _ = Command::new("wmctrl")
                .args(["-r", &window_title, "-e", "0,0,0,-1,-1"])
                .output();

            let _ = Command::new("xdotool")
                .args(["search", "--name", &window_title, "windowmove", "0", "0"])
                .output();
        });
    }

    /// Writes text to the terminal.
    pub fn write_to_terminal(&self, text: &str) {
        // Since controller takes ownership of the terminal interface,
        // we need to provide a way to access it. For now, we'll keep
        // the direct access but this could be improved.
        self.terminal.feed(text.as_bytes());
    }

    /// Clears the terminal contents.
    pub fn clear_terminal(&self) {
        self.terminal.reset(true, true);
    }

    /// Feeds a command to the terminal (appends a newline).
    pub fn execute_in_terminal(&self, command: &str) {
        let full_command = format!("{}\n", command);
        self.terminal.feed(full_command.as_bytes());
    }
}

/// GTK-specific implementation of ToolPanelView
struct GtkToolPanelView {
    category_selector: ComboBoxText,
    tool_selector: ComboBoxText,
    instructions_scroll: ScrolledWindow,
}

impl ToolPanelView for GtkToolPanelView {
    fn set_categories(&self, categories: &[String], default_index: usize) {
        // Clear existing items
        let model = self.category_selector.model().unwrap();
        let count = model.iter_n_children(None);
        for _ in 0..count {
            self.category_selector.remove(0);
        }

        // Add new categories
        for category in categories {
            self.category_selector.append(Some(category), category);
        }

        // Set default selection
        if default_index < categories.len() {
            self.category_selector.set_active(Some(default_index as u32));
        }
    }

    fn set_tools(&self, tools: &[(&str, &str)], default_tool_id: Option<&str>) {
        // Clear existing items
        let model = self.tool_selector.model().unwrap();
        let count = model.iter_n_children(None);
        for _ in 0..count {
            self.tool_selector.remove(0);
        }

        // Add new tools
        for (id, label) in tools {
            self.tool_selector.append(Some(id), label);
        }

        // Find the index of the default tool
        let default_index = if let Some(default_id) = default_tool_id {
            tools.iter().position(|(id, _)| *id == default_id).unwrap_or(0)
        } else {
            0
        };

        // Set default selection
        let model = self.tool_selector.model().unwrap();
        let count = model.iter_n_children(None);
        if count > 0 {
            self.tool_selector.set_active(Some(default_index as u32));
            self.tool_selector.set_sensitive(true);
        } else {
            self.tool_selector.set_sensitive(false);
        }
    }

    fn render_instructions(&self, widget: GtkBox) {
        self.instructions_scroll.set_child(Some(&widget));
    }

    fn selected_tool(&self) -> Option<String> {
        self.tool_selector.active_id().map(|s| s.to_string())
    }

    fn show_instructions_dialog(&self, _title: &str, _widget: GtkBox) {
        // This method is not used in the current design since the panel
        // handles dialog creation directly. The controller calls the panel's
        // show_instructions_dialog method instead.
    }
}

impl Default for ToolExecutionPanel {
    fn default() -> Self {
        Self::new()
    }
}
