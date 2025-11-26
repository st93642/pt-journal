use super::{
    controller::{DefaultInstructionProvider, ToolPanelController},
    interfaces::{ToolPanelView},
    terminal::VteTerminal,
};
use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{
    Box as GtkBox, Button, Dialog, GestureClick, Label, Orientation,
    PopoverMenu, ResponseType, ScrolledWindow, DropDown,
};
use std::cell::RefCell;
use std::process::Command;
use std::rc::Rc;
use std::time::Duration;
use vte::prelude::*;

/// Manual security tools panel with inline instructions and an embedded terminal
pub struct ToolExecutionPanel {
    pub container: GtkBox,
    pub category_selector: DropDown,
    pub tool_selector: DropDown,
    pub info_button: Button,
    pub terminal: vte::Terminal,
    controller: Rc<RefCell<ToolPanelController<DefaultInstructionProvider, VteTerminal, GtkToolPanelView>>>,
}

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

        let category_selector = DropDown::from_strings(&[]);
        category_selector.set_hexpand(true);
        category_box.append(&category_label);
        category_box.append(&category_selector);
        container.append(&category_box);

        // Tool selector row
        let tool_box = GtkBox::new(Orientation::Horizontal, 8);
        let tool_label = Label::new(Some("Tool:"));
        tool_label.set_width_chars(10);
        tool_label.set_xalign(0.0);

        let tool_selector = DropDown::from_strings(&[]);
        tool_selector.set_hexpand(true);
        tool_box.append(&tool_label);
        tool_box.append(&tool_selector);
        container.append(&tool_box);

        // Info button row
        let info_button = Button::with_label("📖 Full Instructions");
        info_button.set_halign(gtk4::Align::Start);
        container.append(&info_button);

        // Terminal section
        let terminal_box = GtkBox::new(Orientation::Vertical, 6);
        let terminal_label = Label::new(Some("Terminal"));
        terminal_label.add_css_class("heading");
        terminal_label.set_xalign(0.0);
        terminal_box.append(&terminal_label);

        let terminal_scroll = ScrolledWindow::new();
        let terminal = vte::Terminal::new();
        terminal_scroll.set_child(Some(&terminal));
        terminal_box.append(&terminal_scroll);
        terminal_box.set_vexpand(true);
        terminal_box.set_hexpand(true);
        terminal_scroll.set_vexpand(true);
        terminal_scroll.set_hexpand(true);
        // Set minimum size for terminal to prevent it from becoming too small
        terminal.set_size_request(400, 300);
        container.append(&terminal_box);

        // Set up terminal
        terminal.spawn_async(
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

        // Create the view wrapper
        let view = GtkToolPanelView {
            category_selector: category_selector.clone(),
            tool_selector: tool_selector.clone(),
            tool_data: std::cell::RefCell::new(Vec::new()),
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
            terminal,
            controller,
        };

        // Initialize the panel
        panel.controller.borrow().initialize();

        // Set up event handlers
        let panel_clone = panel.controller.clone();
        let category_selector_clone = panel.category_selector.clone();
        let tool_selector_clone = panel.tool_selector.clone();
        let info_button_clone = panel.info_button.clone();
        let terminal_clone = panel.terminal.clone();

        // Category selector handler
        let controller = panel_clone.clone();
        category_selector_clone.connect_selected_notify(move |selector| {
            if let Some(selected) = selector.selected_item() {
                if let Some(string_object) = selected.downcast_ref::<gtk4::StringObject>() {
                    let text = string_object.string();
                    controller.borrow().on_category_changed(Some(&text));
                }
            }
        });

        // Tool selector handler
        let _controller = panel_clone.clone();
        tool_selector_clone.connect_selected_notify(move |_| {
            _controller.borrow().on_tool_changed();
        });

        // Info button handler - this will be connected by the controller
        let _info_button_clone = info_button_clone.clone();

        // Set up terminal context menu
        let right_click = GestureClick::new();
        right_click.set_button(3); // Right mouse button

        let terminal_clone_inner = terminal_clone.clone();
        right_click.connect_pressed(move |_, _, _, _| {
            let menu = gtk4::gio::Menu::new();
            menu.append(Some("Copy"), Some("terminal.copy"));
            menu.append(Some("Paste"), Some("terminal.paste"));

            let popover = PopoverMenu::builder()
                .menu_model(&menu)
                .build();
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
    category_selector: DropDown,
    tool_selector: DropDown,
    tool_data: std::cell::RefCell<Vec<(String, String)>>, // (id, label) pairs
}

impl ToolPanelView for GtkToolPanelView {
    fn set_categories(&self, categories: &[String], default_index: usize) {
        let model = gtk4::StringList::new(&categories.iter().map(|s| s.as_str()).collect::<Vec<&str>>());
        self.category_selector.set_model(Some(&model));

        // Set default selection
        if default_index < categories.len() {
            self.category_selector.set_selected(default_index as u32);
        }
    }

    fn set_tools(&self, tools: &[(&str, &str)], default_tool_id: Option<&str>) {
        let model = gtk4::StringList::new(&tools.iter().map(|(_, label)| *label).collect::<Vec<&str>>());
        self.tool_selector.set_model(Some(&model));

        // Find the index of the default tool
        let default_index = if let Some(default_id) = default_tool_id {
            tools.iter().position(|(id, _)| *id == default_id).unwrap_or(0)
        } else {
            0
        };

        // Set default selection
        if !tools.is_empty() {
            self.tool_selector.set_selected(default_index as u32);
            self.tool_selector.set_sensitive(true);
        } else {
            self.tool_selector.set_sensitive(false);
        }
    }

    fn render_instructions(&self, _widget: GtkBox) {
        // Inline instructions display has been removed to avoid duplication
        // with the "Full Instructions" dialog. Users can access full instructions
        // by clicking the "📖 Full Instructions" button.
    }

    fn selected_tool(&self) -> Option<String> {
        self.tool_selector.selected_item()
            .and_then(|item| item.downcast::<gtk4::StringObject>().ok())
            .map(|string_obj| string_obj.string().to_string())
            .and_then(|selected_label| {
                // We need to map the selected label back to the tool ID
                // This is a limitation of the current design - we should store the tool IDs separately
                // For now, we'll return the label as the ID (which may not be correct)
                Some(selected_label)
            })
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
