use super::{picker::ToolPickerModel, renderer::resolve_instruction_state};
use gtk4::glib;
use gtk4::prelude::*;
#[allow(deprecated)]
use gtk4::{
    Box as GtkBox, Button, ComboBoxText, Dialog, Frame, GestureClick, Label, Orientation,
    PopoverMenu, ResponseType, ScrolledWindow,
};
use std::process::Command;
use std::time::Duration;
use vte::prelude::*;

/// Manual security tools panel with inline instructions and an embedded terminal
#[allow(deprecated)]
#[derive(Clone)]
pub struct ToolExecutionPanel {
    pub container: GtkBox,
    pub category_selector: ComboBoxText,
    pub tool_selector: ComboBoxText,
    pub info_button: Button,
    pub instructions_scroll: ScrolledWindow,
    pub terminal: vte::Terminal,
    picker_model: ToolPickerModel,
}

#[allow(deprecated)]
impl ToolExecutionPanel {
    pub fn new() -> Self {
        let container = GtkBox::new(Orientation::Vertical, 12);
        container.set_margin_top(12);
        container.set_margin_bottom(12);
        container.set_margin_start(12);
        container.set_margin_end(12);

        // Header
        let header = Label::new(Some("Security Tool Reference"));
        header.add_css_class("title-3");
        container.append(&header);

        // Use the ToolPickerModel to determine initial selections
        let picker_model = ToolPickerModel::from_manifest();

        // Category selector row
        let category_box = GtkBox::new(Orientation::Horizontal, 8);
        let category_label = Label::new(Some("Category:"));
        category_label.set_width_chars(10);
        category_label.set_xalign(0.0);

        let category_selector = ComboBoxText::new();
        category_selector.set_hexpand(true);

        // Populate categories and set default selection
        for (idx, group) in picker_model.groups().iter().enumerate() {
            category_selector.append(Some(&group.name), &group.name);
            if idx == picker_model.default_category_index() {
                category_selector.set_active(Some(idx as u32));
            }
        }

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

        // Populate tools for the default category
        if let Some(category) = picker_model.default_category() {
            for tool in picker_model.tools_for_category(category) {
                tool_selector.append(Some(&tool.id), &tool.label);
            }
        }

        // Select the default tool
        let default_tool_id = picker_model.default_tool_id();
        if !default_tool_id.is_empty() {
            let tool_model = tool_selector.model().unwrap();
            let count = tool_model.iter_n_children(None);
            let mut found = false;
            for idx in 0..count {
                tool_selector.set_active(Some(idx as u32));
                if tool_selector.active_id().map(|s| s.to_string()).as_deref()
                    == Some(default_tool_id)
                {
                    found = true;
                    break;
                }
            }
            if !found && count > 0 {
                tool_selector.set_active(Some(0));
            } else if count == 0 {
                tool_selector.set_sensitive(false);
            }
        } else if tool_selector.model().unwrap().iter_n_children(None) > 0 {
            tool_selector.set_active(Some(0));
        } else {
            tool_selector.set_sensitive(false);
        }

        if picker_model.is_empty() {
            category_selector.set_sensitive(false);
            tool_selector.set_sensitive(false);
        }

        let info_button = Button::with_label("Open Instructions Window");
        info_button.add_css_class("flat");

        tool_box.append(&tool_label);
        tool_box.append(&tool_selector);
        tool_box.append(&info_button);
        container.append(&tool_box);

        let notice = Label::new(Some(
            "Copy any command from the instructions below and paste it into the integrated terminal to run it manually.",
        ));
        notice.set_wrap(true);
        notice.set_xalign(0.0);
        notice.add_css_class("dim-label");
        container.append(&notice);

        // Instructions frame with scrolling content
        let instructions_frame = Frame::new(Some("Command Reference"));
        instructions_frame.set_hexpand(true);
        instructions_frame.set_vexpand(true);

        let instructions_scroll = ScrolledWindow::new();
        instructions_scroll.set_hexpand(true);
        instructions_scroll.set_vexpand(true);
        instructions_scroll.set_min_content_height(320);
        instructions_scroll.set_margin_top(8);
        instructions_scroll.set_margin_bottom(8);
        instructions_scroll.set_margin_start(8);
        instructions_scroll.set_margin_end(8);

        instructions_frame.set_child(Some(&instructions_scroll));
        container.append(&instructions_frame);

        // Embedded terminal setup
        let terminal_frame = gtk4::Frame::new(Some("Terminal"));
        let terminal_scroll = gtk4::ScrolledWindow::new();
        terminal_scroll.set_min_content_height(300);
        terminal_scroll.set_vexpand(true);
        terminal_scroll.set_hexpand(true);

        let terminal = vte::Terminal::new();
        terminal.set_scroll_on_output(true);
        terminal.set_scroll_on_keystroke(true);
        terminal.set_scrollback_lines(10000);
        terminal.set_mouse_autohide(true);

        let fg = gtk4::gdk::RGBA::new(0.9, 0.9, 0.9, 1.0);
        let bg = gtk4::gdk::RGBA::new(0.12, 0.12, 0.12, 1.0);
        terminal.set_color_foreground(&fg);
        terminal.set_color_background(&bg);

        let palette = [
            gtk4::gdk::RGBA::new(0.2, 0.2, 0.2, 1.0),
            gtk4::gdk::RGBA::new(0.8, 0.3, 0.3, 1.0),
            gtk4::gdk::RGBA::new(0.4, 0.8, 0.4, 1.0),
            gtk4::gdk::RGBA::new(0.8, 0.8, 0.3, 1.0),
            gtk4::gdk::RGBA::new(0.4, 0.7, 1.0, 1.0),
            gtk4::gdk::RGBA::new(0.8, 0.4, 0.8, 1.0),
            gtk4::gdk::RGBA::new(0.4, 0.8, 0.8, 1.0),
            gtk4::gdk::RGBA::new(0.85, 0.85, 0.85, 1.0),
            gtk4::gdk::RGBA::new(0.4, 0.4, 0.4, 1.0),
            gtk4::gdk::RGBA::new(1.0, 0.4, 0.4, 1.0),
            gtk4::gdk::RGBA::new(0.5, 1.0, 0.5, 1.0),
            gtk4::gdk::RGBA::new(1.0, 1.0, 0.5, 1.0),
            gtk4::gdk::RGBA::new(0.5, 0.8, 1.0, 1.0),
            gtk4::gdk::RGBA::new(1.0, 0.5, 1.0, 1.0),
            gtk4::gdk::RGBA::new(0.5, 1.0, 1.0, 1.0),
            gtk4::gdk::RGBA::new(1.0, 1.0, 1.0, 1.0),
        ];
        let palette_refs: Vec<&gtk4::gdk::RGBA> = palette.iter().collect();
        terminal.set_colors(Some(&fg), Some(&bg), &palette_refs);

        let right_click = GestureClick::new();
        right_click.set_button(3);

        let terminal_clone = terminal.clone();
        right_click.connect_pressed(move |_gesture, _n_press, x, y| {
            let menu = gtk4::gio::Menu::new();
            menu.append(Some("Copy"), Some("terminal.copy"));
            menu.append(Some("Paste"), Some("terminal.paste"));

            let popover = PopoverMenu::from_model(Some(&menu));
            popover.set_parent(&terminal_clone);
            popover.set_has_arrow(false);
            popover.set_pointing_to(Some(&gtk4::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));

            let action_group = gtk4::gio::SimpleActionGroup::new();

            let copy_action = gtk4::gio::SimpleAction::new("copy", None);
            let terminal_copy = terminal_clone.clone();
            copy_action.connect_activate(move |_, _| {
                terminal_copy.copy_clipboard_format(vte::Format::Text);
            });
            action_group.add_action(&copy_action);

            let paste_action = gtk4::gio::SimpleAction::new("paste", None);
            let terminal_paste = terminal_clone.clone();
            paste_action.connect_activate(move |_, _| {
                terminal_paste.paste_clipboard();
            });
            action_group.add_action(&paste_action);

            terminal_clone.insert_action_group("terminal", Some(&action_group));
            popover.popup();
        });

        terminal.add_controller(right_click);

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

        terminal_scroll.set_child(Some(&terminal));
        terminal_frame.set_child(Some(&terminal_scroll));
        container.append(&terminal_frame);

        let panel = Self {
            container,
            category_selector,
            tool_selector,
            info_button,
            instructions_scroll,
            terminal,
            picker_model,
        };

        panel.render_inline_instructions();

        // Category selector handler
        let tool_clone = panel.tool_selector.clone();
        let panel_category = panel.clone();
        panel
            .category_selector
            .connect_changed(move |category_selector| {
                panel_category.update_tools_for_category(category_selector, &tool_clone);
            });

        // Tool selector handler
        let selector_clone = panel.tool_selector.clone();
        let panel_clone = panel.clone();
        selector_clone.connect_changed(move |_| {
            panel_clone.render_inline_instructions();
        });

        panel
    }

    pub fn get_selected_tool(&self) -> Option<String> {
        self.tool_selector.active_id().map(|s| s.to_string())
    }

    /// Update available tools when category selection changes
    fn update_tools_for_category(
        &self,
        category_selector: &ComboBoxText,
        tool_selector: &ComboBoxText,
    ) {
        let active_category = category_selector.active_id().map(|s| s.to_string());

        if let Some(category) = active_category {
            let has_tools = self.populate_tools_for_category(tool_selector, &category);
            if has_tools {
                tool_selector.set_sensitive(true);
                tool_selector.set_active(Some(0));
            } else {
                tool_selector.set_sensitive(false);
            }
            self.render_inline_instructions();
        }
    }

    fn populate_tools_for_category(
        &self,
        tool_selector: &ComboBoxText,
        category: &str,
    ) -> bool {
        let item_count = tool_selector.model().unwrap().iter_n_children(None);
        for _ in 0..item_count {
            tool_selector.remove(0);
        }

        let tools = self.picker_model.tools_for_category(category);
        for tool in tools {
            tool_selector.append(Some(&tool.id), &tool.label);
        }

        !tools.is_empty()
    }

    /// Rebuild inline instructions whenever the selected tool changes
    fn render_inline_instructions(&self) {
        let active_tool = self.get_selected_tool();
        let state = resolve_instruction_state(active_tool.as_deref());
        let content = state.inline_widget();
        self.instructions_scroll.set_child(Some(&content));
    }

    /// Show the instructions dialog for the selected tool
    pub fn show_instructions_dialog(&self, window: &gtk4::Window) {
        let active_tool = self.get_selected_tool();
        let state = resolve_instruction_state(active_tool.as_deref());
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

    /// Write text to the terminal
    pub fn write_to_terminal(&self, text: &str) {
        self.terminal.feed(text.as_bytes());
    }

    /// Clear the terminal contents
    pub fn clear_terminal(&self) {
        self.terminal.reset(true, true);
    }

    /// Feed a command to the terminal (appends a newline)
    pub fn execute_in_terminal(&self, command: &str) {
        let full_command = format!("{}\n", command);
        self.terminal.feed(full_command.as_bytes());
    }
}

impl Default for ToolExecutionPanel {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    static GTK_AVAILABLE: OnceLock<bool> = OnceLock::new();

    fn ensure_gtk_init() -> bool {
        *GTK_AVAILABLE.get_or_init(|| {
            // Only run GTK-dependent tests when the RUN_GTK_TESTS env var is set.
            // Running GTK tests in headless or multi-threaded test runners causes
            // "GTK may only be used from the main thread" panics. Require an
            // explicit opt-in to avoid CI/test flakiness on developer machines.
            if std::env::var("RUN_GTK_TESTS").is_err() {
                eprintln!("Skipping GTK tests: set RUN_GTK_TESTS=1 to enable");
                return false;
            }

            if let Err(err) = gtk4::init() {
                eprintln!("Failed to initialize GTK - tests will be skipped: {err}");
                false
            } else {
                true
            }
        })
    }

    #[test]
    fn test_tool_execution_panel_creation() {
        if !ensure_gtk_init() {
            return;
        }

        let panel = ToolExecutionPanel::new();
        assert_eq!(panel.get_selected_tool(), Some("nmap".to_string()));
        assert!(panel.instructions_scroll.child().is_some());
    }

    #[test]
    fn test_tool_selection_updates() {
        if !ensure_gtk_init() {
            return;
        }

        let panel = ToolExecutionPanel::new();
        let model = panel.tool_selector.model().unwrap();
        let count = model.iter_n_children(None);
        let mut found = false;
        for idx in 0..count {
            panel.tool_selector.set_active(Some(idx as u32));
            if panel.get_selected_tool() == Some("gobuster".to_string()) {
                found = true;
                break;
            }
        }
        assert!(found, "gobuster should be selectable");
        assert_eq!(panel.get_selected_tool(), Some("gobuster".to_string()));
        assert!(panel.instructions_scroll.child().is_some());
    }

    #[test]
    fn test_terminal_operations() {
        if !ensure_gtk_init() {
            return;
        }

        let panel = ToolExecutionPanel::new();
        panel.write_to_terminal("Line 1\n");
        panel.clear_terminal();
        panel.execute_in_terminal("whoami");
    }

}
