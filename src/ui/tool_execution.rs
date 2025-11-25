use crate::ui::tool_instructions;
use gtk4::glib;
use gtk4::prelude::*;
#[allow(deprecated)]
use gtk4::{
    Align, Box as GtkBox, Button, ComboBoxText, Dialog, Frame, GestureClick, Grid, Label,
    LinkButton, Orientation, PopoverMenu, ResponseType, ScrolledWindow,
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

        // Category selector row
        let category_box = GtkBox::new(Orientation::Horizontal, 8);
        let category_label = Label::new(Some("Category:"));
        category_label.set_width_chars(10);
        category_label.set_xalign(0.0);

        let category_selector = ComboBoxText::new();
        category_selector.set_hexpand(true);

        let groups = tool_instructions::grouped_manifest();
        let mut first_category: Option<String> = None;
        let mut first_tool_id: Option<String> = None;

        // Find the category containing "nmap" if it exists, otherwise use the first category
        let nmap_category = tool_instructions::manifest()
            .iter()
            .find(|entry| entry.id == "nmap")
            .map(|entry| entry.category.clone());

        if let Some(nmap_cat) = nmap_category {
            first_category = Some(nmap_cat.clone());
            if let Some(group) = groups.iter().find(|g| g.name == nmap_cat) {
                if let Some(first_tool) = group.tools.first() {
                    first_tool_id = Some(first_tool.id.clone());
                }
            }
        } else {
            // Fallback to first category
            if let Some(first_group) = groups.first() {
                first_category = Some(first_group.name.clone());
                if let Some(first_tool) = first_group.tools.first() {
                    first_tool_id = Some(first_tool.id.clone());
                }
            }
        }

        for (idx, group) in groups.iter().enumerate() {
            category_selector.append(Some(&group.name), &group.name);
            if first_category.as_ref() == Some(&group.name) {
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

        // Populate tools for the initially selected category
        if let Some(category) = first_category.clone() {
            for group in &groups {
                if group.name == category {
                    for entry in &group.tools {
                        tool_selector.append(Some(&entry.id), &entry.label);
                    }
                    break;
                }
            }
        }

        // Find and select the default tool (nmap if available, otherwise first tool)
        if let Some(default_id) = tool_instructions::manifest()
            .iter()
            .find(|entry| entry.id == "nmap")
            .map(|entry| entry.id.clone())
            .or_else(|| first_tool_id.clone())
        {
            // Find the index of the default tool in the current tool list
            let model = tool_selector.model().unwrap();
            let count = model.iter_n_children(None);
            let mut found = false;
            for idx in 0..count {
                tool_selector.set_active(Some(idx as u32));
                if tool_selector.active_id().map(|s| s.to_string()) == Some(default_id.clone()) {
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
            // Clear existing tools by removing all children
            let item_count = tool_selector.model().unwrap().iter_n_children(None);
            for _ in 0..item_count {
                tool_selector.remove(0);
            }

            // Populate with tools from selected category
            let groups = tool_instructions::grouped_manifest();
            for group in groups {
                if group.name == category {
                    for entry in group.tools {
                        tool_selector.append(Some(&entry.id), &entry.label);
                    }
                    break;
                }
            }

            // Select first tool in the category
            if tool_selector.model().unwrap().iter_n_children(None) > 0 {
                tool_selector.set_active(Some(0));
            }

            self.render_inline_instructions();
        }
    }

    /// Rebuild inline instructions whenever the selected tool changes
    fn render_inline_instructions(&self) {
        let active_tool = self.get_selected_tool().or_else(|| {
            tool_instructions::manifest()
                .first()
                .map(|entry| entry.id.clone())
        });

        let content = match active_tool {
            Some(ref tool_id) => match tool_instructions::get_instructions(tool_id) {
                Some(instructions) => build_instruction_sections(instructions),
                None => {
                    eprintln!("No instruction document found for '{tool_id}'");
                    build_missing_instructions_box(tool_id)
                }
            },
            None => build_missing_instructions_box(""),
        };

        self.instructions_scroll.set_child(Some(&content));
    }

    /// Show the instructions dialog for the selected tool
    pub fn show_instructions_dialog(&self, window: &gtk4::Window) {
        let active_tool = self.get_selected_tool().or_else(|| {
            tool_instructions::manifest()
                .first()
                .map(|entry| entry.id.clone())
        });

        let (dialog_title, instruction_box) = match active_tool {
            Some(ref tool_id) => match tool_instructions::get_instructions(tool_id) {
                Some(instructions) => (
                    format!("{} - Full Instructions", instructions.name),
                    build_instruction_sections(instructions),
                ),
                None => {
                    eprintln!("No instruction document found for '{tool_id}'");
                    (
                        format!("{} - Full Instructions", tool_id),
                        build_missing_instructions_box(tool_id),
                    )
                }
            },
            None => (
                "Tool Instructions".to_string(),
                build_missing_instructions_box(""),
            ),
        };

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

fn build_instruction_sections(instructions: &tool_instructions::ToolInstructions) -> GtkBox {
    let root = GtkBox::new(Orientation::Vertical, 12);
    root.set_margin_top(8);
    root.set_margin_bottom(8);
    root.set_margin_start(8);
    root.set_margin_end(8);

    let title = Label::new(Some(&instructions.name));
    title.add_css_class("title-4");
    title.set_xalign(0.0);
    root.append(&title);

    let summary = Label::new(Some(&instructions.summary));
    summary.set_wrap(true);
    summary.set_xalign(0.0);
    root.append(&summary);

    if let Some(details) = &instructions.details {
        let detail_label = create_instruction_label(details);
        root.append(&detail_label);
    }

    let hint = Label::new(Some(
        "💡 Tip: Use the copy buttons next to actual commands. Comments and headings are not copyable.",
    ));
    hint.set_wrap(true);
    hint.set_xalign(0.0);
    hint.add_css_class("dim-label");
    root.append(&hint);

    if !instructions.installation_guides.is_empty() {
        root.append(&build_installation_guides_section(
            &instructions.installation_guides,
        ));
    }
    if !instructions.quick_examples.is_empty() {
        root.append(&build_examples_section(&instructions.quick_examples));
    }
    if !instructions.common_flags.is_empty() {
        root.append(&build_flags_section(&instructions.common_flags));
    }
    if !instructions.operational_tips.is_empty() {
        root.append(&build_tips_section(&instructions.operational_tips));
    }
    if !instructions.step_sequences.is_empty() {
        root.append(&build_sequences_section(&instructions.step_sequences));
    }
    if !instructions.workflow_guides.is_empty() {
        root.append(&build_workflow_section(&instructions.workflow_guides));
    }
    if !instructions.output_notes.is_empty() {
        root.append(&build_output_section(&instructions.output_notes));
    }
    if !instructions.advanced_usage.is_empty() {
        root.append(&build_advanced_section(&instructions.advanced_usage));
    }
    if let Some(table) = instructions.comparison_table.as_ref() {
        if !table.columns.is_empty() && !table.rows.is_empty() {
            root.append(&build_comparison_section(table));
        }
    }
    if !instructions.resources.is_empty() {
        root.append(&build_resources_section(&instructions.resources));
    }

    root
}

fn build_missing_instructions_box(tool_id: &str) -> GtkBox {
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.set_margin_top(16);
    container.set_margin_bottom(16);
    container.set_margin_start(16);
    container.set_margin_end(16);

    let title = Label::new(Some("Instruction data unavailable"));
    title.add_css_class("title-4");
    title.set_xalign(0.0);
    container.append(&title);

    let message = if tool_id.is_empty() {
        "No tool instructions have been loaded. Check data/tool_instructions for missing files."
    } else {
        "No structured instructions are available for this selection."
    };
    let body = create_instruction_label(message);
    container.append(&body);

    container
}

fn build_installation_guides_section(guides: &[tool_instructions::InstallationGuide]) -> Frame {
    let frame = Frame::new(Some("Installation Guides"));
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.set_margin_top(8);
    container.set_margin_bottom(8);
    container.set_margin_start(8);
    container.set_margin_end(8);

    for guide in guides {
        let card = GtkBox::new(Orientation::Vertical, 4);
        card.set_margin_bottom(8);

        let heading = Label::new(Some(&guide.platform));
        heading.add_css_class("heading");
        heading.set_xalign(0.0);
        card.append(&heading);

        if let Some(summary) = &guide.summary {
            let summary_label = create_instruction_label(summary);
            summary_label.set_margin_start(12);
            card.append(&summary_label);
        }

        for step in &guide.steps {
            if step.copyable {
                let row = create_copyable_command_row(&step.detail);
                row.set_margin_start(12);
                card.append(&row);
            } else {
                let label = create_instruction_label(&step.detail);
                label.set_margin_start(12);
                card.append(&label);
            }
        }

        container.append(&card);
    }

    frame.set_child(Some(&container));
    frame
}

fn build_examples_section(examples: &[tool_instructions::CommandExample]) -> Frame {
    let frame = Frame::new(Some("Common Examples"));
    let container = GtkBox::new(Orientation::Vertical, 8);
    container.set_margin_top(8);
    container.set_margin_bottom(8);
    container.set_margin_start(8);
    container.set_margin_end(8);

    for example in examples {
        let description = Label::new(Some(&format!("• {}", example.description)));
        description.set_xalign(0.0);
        description.set_wrap(true);
        description.add_css_class("heading");
        container.append(&description);

        let command_row = create_copyable_command_row(&example.command);
        command_row.set_margin_start(20);
        container.append(&command_row);

        for note in &example.notes {
            let note_label = create_instruction_label(note);
            note_label.set_margin_start(20);
            container.append(&note_label);
        }
    }

    frame.set_child(Some(&container));
    frame
}

fn build_flags_section(flags: &[tool_instructions::FlagEntry]) -> Frame {
    let frame = Frame::new(Some("Helpful Flags"));
    let container = GtkBox::new(Orientation::Vertical, 4);
    container.set_margin_top(8);
    container.set_margin_bottom(8);
    container.set_margin_start(8);
    container.set_margin_end(8);

    for flag in flags {
        let label = Label::new(Some(&format!("{} — {}", flag.flag, flag.description)));
        label.set_xalign(0.0);
        label.set_wrap(true);
        container.append(&label);
    }

    frame.set_child(Some(&container));
    frame
}

fn build_tips_section(tips: &[String]) -> Frame {
    let frame = Frame::new(Some("Tips & Best Practices"));
    let container = GtkBox::new(Orientation::Vertical, 4);
    container.set_margin_top(8);
    container.set_margin_bottom(8);
    container.set_margin_start(8);
    container.set_margin_end(8);

    for tip in tips {
        let label = create_instruction_label(&format!("💡 {}", tip));
        container.append(&label);
    }

    frame.set_child(Some(&container));
    frame
}

fn build_sequences_section(sequences: &[tool_instructions::InstructionSequence]) -> Frame {
    let frame = Frame::new(Some("Guided Playbooks"));
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.set_margin_top(8);
    container.set_margin_bottom(8);
    container.set_margin_start(8);
    container.set_margin_end(8);

    for sequence in sequences {
        let sequence_box = GtkBox::new(Orientation::Vertical, 6);
        let heading = Label::new(Some(&sequence.title));
        heading.add_css_class("heading");
        heading.set_xalign(0.0);
        sequence_box.append(&heading);

        for (idx, step) in sequence.steps.iter().enumerate() {
            let title = Label::new(Some(&format!("{}. {}", idx + 1, step.title)));
            title.set_xalign(0.0);
            title.add_css_class("heading");
            sequence_box.append(&title);

            if let Some(details) = &step.details {
                let detail_label = create_instruction_label(details);
                detail_label.set_margin_start(16);
                sequence_box.append(&detail_label);
            }

            if let Some(command) = &step.command {
                let row = create_copyable_command_row(command);
                row.set_margin_start(16);
                sequence_box.append(&row);
            }
        }

        container.append(&sequence_box);
    }

    frame.set_child(Some(&container));
    frame
}

fn build_workflow_section(workflows: &[tool_instructions::WorkflowGuide]) -> Frame {
    let frame = Frame::new(Some("Workflow Guides"));
    let container = GtkBox::new(Orientation::Vertical, 12);
    container.set_margin_top(8);
    container.set_margin_bottom(8);
    container.set_margin_start(8);
    container.set_margin_end(8);

    for workflow in workflows {
        let workflow_box = GtkBox::new(Orientation::Vertical, 6);
        let heading = Label::new(Some(&workflow.name));
        heading.add_css_class("heading");
        heading.set_xalign(0.0);
        workflow_box.append(&heading);

        for (idx, stage) in workflow.stages.iter().enumerate() {
            let stage_label = Label::new(Some(&format!("{}. {}", idx + 1, stage.label)));
            stage_label.set_xalign(0.0);
            stage_label.add_css_class("heading");
            workflow_box.append(&stage_label);

            if let Some(description) = &stage.description {
                let desc_label = create_instruction_label(description);
                desc_label.set_margin_start(16);
                workflow_box.append(&desc_label);
            }

            if let Some(command) = &stage.command {
                let row = create_copyable_command_row(command);
                row.set_margin_start(16);
                workflow_box.append(&row);
            }
        }

        container.append(&workflow_box);
    }

    frame.set_child(Some(&container));
    frame
}

fn build_output_section(notes: &[tool_instructions::OutputNote]) -> Frame {
    let frame = Frame::new(Some("Interpreting Output"));
    let grid = Grid::new();
    grid.set_column_spacing(12);
    grid.set_row_spacing(4);
    grid.set_margin_top(8);
    grid.set_margin_bottom(8);
    grid.set_margin_start(8);
    grid.set_margin_end(8);

    let headers = ["Indicator", "Meaning", "Severity"];
    for (idx, header) in headers.iter().enumerate() {
        let label = Label::new(Some(header));
        label.add_css_class("heading");
        label.set_xalign(0.0);
        grid.attach(&label, idx as i32, 0, 1, 1);
    }

    for (row_idx, note) in notes.iter().enumerate() {
        let indicator = create_instruction_label(&note.indicator);
        grid.attach(&indicator, 0, (row_idx + 1) as i32, 1, 1);

        let meaning = create_instruction_label(&note.meaning);
        grid.attach(&meaning, 1, (row_idx + 1) as i32, 1, 1);

        let severity_text = note.severity.as_deref().unwrap_or("-");
        let severity = create_instruction_label(severity_text);
        grid.attach(&severity, 2, (row_idx + 1) as i32, 1, 1);
    }

    frame.set_child(Some(&grid));
    frame
}

fn build_advanced_section(examples: &[tool_instructions::AdvancedExample]) -> Frame {
    let frame = Frame::new(Some("Advanced Usage"));
    let container = GtkBox::new(Orientation::Vertical, 8);
    container.set_margin_top(8);
    container.set_margin_bottom(8);
    container.set_margin_start(8);
    container.set_margin_end(8);

    for example in examples {
        let title = Label::new(Some(&example.title));
        title.add_css_class("heading");
        title.set_xalign(0.0);
        container.append(&title);

        if let Some(scenario) = &example.scenario {
            let scenario_label = create_instruction_label(scenario);
            scenario_label.set_margin_start(16);
            container.append(&scenario_label);
        }

        let command_row = create_copyable_command_row(&example.command);
        command_row.set_margin_start(16);
        container.append(&command_row);

        for note in &example.notes {
            let note_label = create_instruction_label(note);
            note_label.set_margin_start(16);
            container.append(&note_label);
        }
    }

    frame.set_child(Some(&container));
    frame
}

fn build_comparison_section(table: &tool_instructions::ComparisonTable) -> Frame {
    let frame = Frame::new(Some("Tool Comparison"));
    let container = GtkBox::new(Orientation::Vertical, 8);
    container.set_margin_top(8);
    container.set_margin_bottom(8);
    container.set_margin_start(8);
    container.set_margin_end(8);

    if let Some(caption) = &table.caption {
        let caption_label = create_instruction_label(caption);
        container.append(&caption_label);
    }

    let grid = Grid::new();
    grid.set_column_spacing(12);
    grid.set_row_spacing(4);

    for (idx, header) in table.columns.iter().enumerate() {
        let label = Label::new(Some(header));
        label.add_css_class("heading");
        label.set_xalign(0.0);
        grid.attach(&label, idx as i32, 0, 1, 1);
    }

    for (row_idx, row) in table.rows.iter().enumerate() {
        for col_idx in 0..table.columns.len() {
            let value = row.get(col_idx).cloned().unwrap_or_default();
            let label = create_instruction_label(&value);
            grid.attach(&label, col_idx as i32, (row_idx + 1) as i32, 1, 1);
        }
    }

    container.append(&grid);
    frame.set_child(Some(&container));
    frame
}

fn build_resources_section(resources: &[tool_instructions::ResourceLink]) -> Frame {
    let frame = Frame::new(Some("Resources"));
    let container = GtkBox::new(Orientation::Vertical, 8);
    container.set_margin_top(8);
    container.set_margin_bottom(8);
    container.set_margin_start(8);
    container.set_margin_end(8);

    for resource in resources {
        let link = LinkButton::with_label(&resource.url, &resource.label);
        link.set_halign(Align::Start);
        container.append(&link);

        if let Some(description) = &resource.description {
            let description_label = create_instruction_label(description);
            description_label.set_margin_start(12);
            container.append(&description_label);
        }
    }

    frame.set_child(Some(&container));
    frame
}

fn create_instruction_label(text: &str) -> Label {
    let label = Label::new(Some(text));
    label.set_xalign(0.0);
    label.set_wrap(true);
    label.add_css_class("dim-label");
    label
}

fn create_copyable_command_row(command: &str) -> GtkBox {
    let row = GtkBox::new(Orientation::Horizontal, 8);

    let cmd_label = Label::new(Some(command));
    cmd_label.set_selectable(true);
    cmd_label.set_xalign(0.0);
    cmd_label.set_hexpand(true);
    cmd_label.set_wrap(true);
    cmd_label.add_css_class("monospace");

    let command_text = command.to_string();
    let copy_button = Button::with_label("📋 Copy");
    copy_button.add_css_class("flat");
    copy_button.set_tooltip_text(Some("Copy full command to clipboard"));
    copy_button.connect_clicked(move |_| {
        if let Some(display) = gtk4::gdk::Display::default() {
            let clipboard = display.clipboard();
            clipboard.set_text(&command_text);
        }
    });

    row.append(&cmd_label);
    row.append(&copy_button);
    row
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::ui::tool_instructions::{
        AdvancedExample, CommandExample, ComparisonTable, FlagEntry, GuideStep, InstallationGuide,
        InstructionSequence, OutputNote, ResourceLink, SequenceStep, ToolInstructions,
        WorkflowGuide, WorkflowStage,
    };
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

    #[test]
    fn test_renders_rich_instruction_sections() {
        if !ensure_gtk_init() {
            return;
        }

        let instructions = sample_instruction_document();
        let container = build_instruction_sections(&instructions);
        let titles = collect_frame_titles(&container);
        let expected = vec![
            "Installation Guides",
            "Common Examples",
            "Helpful Flags",
            "Tips & Best Practices",
            "Guided Playbooks",
            "Workflow Guides",
            "Interpreting Output",
            "Advanced Usage",
            "Tool Comparison",
            "Resources",
        ];

        for title in expected {
            assert!(titles.contains(&title.to_string()));
        }
    }

    fn collect_frame_titles(container: &GtkBox) -> Vec<String> {
        let mut titles = Vec::new();
        let mut child = container.first_child();
        while let Some(widget) = child {
            if let Ok(frame) = widget.clone().downcast::<Frame>() {
                if let Some(label) = frame.label() {
                    titles.push(label.to_string());
                }
            }
            child = widget.next_sibling();
        }
        titles
    }

    fn sample_instruction_document() -> ToolInstructions {
        ToolInstructions {
            id: "test".to_string(),
            name: "Test Tool".to_string(),
            summary: "Summary".to_string(),
            details: Some("More details".to_string()),
            installation_guides: vec![InstallationGuide {
                platform: "Linux".to_string(),
                summary: Some("Use apt".to_string()),
                steps: vec![
                    GuideStep {
                        detail: "sudo apt update".to_string(),
                        copyable: true,
                    },
                    GuideStep {
                        detail: "sudo apt install test".to_string(),
                        copyable: true,
                    },
                ],
            }],
            quick_examples: vec![CommandExample {
                description: "Example".to_string(),
                command: "test --run".to_string(),
                notes: vec!["Note".to_string()],
            }],
            step_sequences: vec![InstructionSequence {
                title: "Sequence".to_string(),
                steps: vec![SequenceStep {
                    title: "Step".to_string(),
                    details: Some("details".to_string()),
                    command: Some("cmd".to_string()),
                }],
            }],
            workflow_guides: vec![WorkflowGuide {
                name: "Workflow".to_string(),
                stages: vec![WorkflowStage {
                    label: "Stage".to_string(),
                    description: Some("desc".to_string()),
                    command: Some("workflow cmd".to_string()),
                }],
            }],
            output_notes: vec![OutputNote {
                indicator: "open".to_string(),
                meaning: "meaning".to_string(),
                severity: Some("info".to_string()),
            }],
            common_flags: vec![FlagEntry {
                flag: "-v".to_string(),
                description: "verbose".to_string(),
            }],
            operational_tips: vec!["tip".to_string()],
            advanced_usage: vec![AdvancedExample {
                title: "Advanced".to_string(),
                scenario: Some("scenario".to_string()),
                command: "advanced".to_string(),
                notes: vec!["note".to_string()],
            }],
            comparison_table: Some(ComparisonTable {
                caption: Some("caption".to_string()),
                columns: vec!["Metric".to_string(), "Value".to_string()],
                rows: vec![vec!["Speed".to_string(), "Fast".to_string()]],
            }),
            resources: vec![ResourceLink {
                label: "Docs".to_string(),
                url: "https://example.com".to_string(),
                description: Some("desc".to_string()),
            }],
        }
    }
}
