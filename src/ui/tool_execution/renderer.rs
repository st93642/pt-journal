//! Instruction rendering helpers for the tool execution panel.
//!
//! This module encapsulates the logic for determining which instruction
//! document should be rendered and how to build the GTK widgets that present
//! those instructions. The separation enables unit tests to exercise the
//! selection logic without initializing GTK, while keeping widget construction
//! centralized for reuse by the panel and dialog views.

use crate::ui::detail_panel::highlight_code;
use crate::ui::tool_instructions::{self, ToolInstructions};
use adw::prelude::*;
use adw::{ExpanderRow, PreferencesGroup};
use gtk4::{gdk, Align, Box as GtkBox, Button, Label, LinkButton, ListBoxRow, Orientation};

fn find_expander_image(widget: &gtk4::Widget) -> Option<gtk4::Image> {
    if widget.has_css_class("expander-row-arrow") {
        if let Ok(image) = widget.clone().downcast::<gtk4::Image>() {
            return Some(image);
        }
    }
    let mut child = widget.first_child();
    while let Some(ch) = child {
        if let Some(img) = find_expander_image(&ch) {
            return Some(img);
        }
        child = ch.next_sibling();
    }
    None
}

fn setup_expander_icons(expander: &ExpanderRow) {
    let widget = expander.upcast_ref::<gtk4::Widget>();
    if let Some(image) = find_expander_image(widget) {
        image.set_icon_name(Some("go-next-symbolic"));
        let image_clone = image.clone();
        expander.connect_expanded_notify(move |exp| {
            let icon = if exp.is_expanded() {
                "go-down-symbolic"
            } else {
                "go-next-symbolic"
            };
            image_clone.set_icon_name(Some(icon));
        });
    }
}

/// Represents the resolved instruction content for the current selection.
#[derive(Debug, Clone)]
pub enum InstructionState<'a> {
    /// Instructions were found for the selected tool.
    Available(&'a ToolInstructions),
    /// No instructions exist for the selected tool (or no tool selected).
    Missing { tool_id: Option<String> },
}

impl<'a> InstructionState<'a> {
    /// Returns the dialog title for the resolved state.
    pub fn dialog_title(&self) -> String {
        match self {
            Self::Available(instructions) => {
                format!("{} - Full Instructions", instructions.name)
            }
            Self::Missing { tool_id } => match tool_id {
                Some(id) if !id.is_empty() => format!("{} - Full Instructions", id),
                _ => "Tool Instructions".to_string(),
            },
        }
    }

    /// Builds the GTK widget for inline rendering.
    pub fn inline_widget(&self) -> GtkBox {
        match self {
            Self::Available(instructions) => build_instruction_sections(instructions),
            Self::Missing { tool_id } => {
                build_missing_instructions_box(tool_id.as_deref().unwrap_or(""))
            }
        }
    }
}

/// Resolves instruction state for the provided tool ID.
///
/// - When a tool ID is provided, we attempt to load its instructions.
/// - When `None`, we fall back to the first manifest entry when available.
/// - If no instructions exist, a missing state is returned.
pub fn resolve_instruction_state(tool_id: Option<&str>) -> InstructionState<'static> {
    if let Some(tool_id) = tool_id {
        return tool_instructions::get_instructions(tool_id)
            .map(InstructionState::Available)
            .unwrap_or_else(|| InstructionState::Missing {
                tool_id: Some(tool_id.to_string()),
            });
    }

    // Fallback to the first manifest entry when no tool is selected.
    let fallback_id = tool_instructions::manifest()
        .first()
        .map(|entry| entry.id.clone());
    if let Some(id) = fallback_id {
        return tool_instructions::get_instructions(&id)
            .map(InstructionState::Available)
            .unwrap_or_else(|| InstructionState::Missing { tool_id: Some(id) });
    }

    InstructionState::Missing { tool_id: None }
}

/// Builds the fallback widget when instruction data is unavailable.
pub fn build_missing_instructions_box(tool_id: &str) -> GtkBox {
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

/// Builds the complete inline instruction sections widget.
pub fn build_instruction_sections(instructions: &ToolInstructions) -> GtkBox {
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

fn build_installation_guides_section(
    guides: &[tool_instructions::InstallationGuide],
) -> PreferencesGroup {
    let group = PreferencesGroup::new();
    group.set_title("Installation Guides");

    for guide in guides {
        let expander = ExpanderRow::new();
        expander.set_title(&guide.platform);
        setup_expander_icons(&expander);

        if let Some(summary) = &guide.summary {
            let summary_label = create_instruction_label(summary);
            expander.add_row(&summary_label);
        }

        for step in &guide.steps {
            if step.copyable {
                let row = create_copyable_command_row(&step.detail);
                expander.add_row(&row);
            } else {
                let label = create_instruction_label(&step.detail);
                expander.add_row(&label);
            }
        }

        group.add(&expander);
    }

    group
}

fn build_examples_section(examples: &[tool_instructions::CommandExample]) -> PreferencesGroup {
    let group = PreferencesGroup::new();
    group.set_title("Common Examples");

    for example in examples {
        let expander = ExpanderRow::new();
        expander.set_title(&format!("• {}", example.description));
        setup_expander_icons(&expander);

        let command_row = create_copyable_command_row(&example.command);
        expander.add_row(&command_row);

        for note in &example.notes {
            let note_label = create_instruction_label(note);
            expander.add_row(&note_label);
        }

        group.add(&expander);
    }

    group
}

fn build_flags_section(flags: &[tool_instructions::FlagEntry]) -> PreferencesGroup {
    let group = PreferencesGroup::new();
    group.set_title("Helpful Flags");

    for flag in flags {
        let row = ListBoxRow::new();
        let label = Label::new(Some(&format!("{} — {}", flag.flag, flag.description)));
        label.set_xalign(0.0);
        label.set_wrap(true);
        row.set_child(Some(&label));
        group.add(&row);
    }

    group
}

fn build_tips_section(tips: &[String]) -> PreferencesGroup {
    let group = PreferencesGroup::new();
    group.set_title("Tips &amp; Best Practices");

    for tip in tips {
        let row = ListBoxRow::new();
        let label = create_instruction_label(&format!("💡 {}", tip));
        row.set_child(Some(&label));
        group.add(&row);
    }

    group
}

fn build_sequences_section(
    sequences: &[tool_instructions::InstructionSequence],
) -> PreferencesGroup {
    let group = PreferencesGroup::new();
    group.set_title("Guided Playbooks");

    for sequence in sequences {
        let expander = ExpanderRow::new();
        expander.set_title(&sequence.title);
        setup_expander_icons(&expander);

        for (idx, step) in sequence.steps.iter().enumerate() {
            let step_box = GtkBox::new(Orientation::Vertical, 4);
            let title = Label::new(Some(&format!("{}. {}", idx + 1, step.title)));
            title.set_xalign(0.0);
            title.add_css_class("heading");
            step_box.append(&title);

            if let Some(details) = &step.details {
                let detail_label = create_instruction_label(details);
                step_box.append(&detail_label);
            }

            if let Some(command) = &step.command {
                let row = create_copyable_command_row(command);
                step_box.append(&row);
            }

            let step_row = ListBoxRow::new();
            step_row.set_child(Some(&step_box));
            expander.add_row(&step_row);
        }

        group.add(&expander);
    }

    group
}

fn build_workflow_section(workflows: &[tool_instructions::WorkflowGuide]) -> PreferencesGroup {
    let group = PreferencesGroup::new();
    group.set_title("Workflow Guides");

    for workflow in workflows {
        let expander = ExpanderRow::new();
        expander.set_title(&workflow.name);
        setup_expander_icons(&expander);

        for (idx, stage) in workflow.stages.iter().enumerate() {
            let stage_box = GtkBox::new(Orientation::Vertical, 4);
            let stage_label = Label::new(Some(&format!("{}. {}", idx + 1, stage.label)));
            stage_label.set_xalign(0.0);
            stage_label.add_css_class("heading");
            stage_box.append(&stage_label);

            if let Some(description) = &stage.description {
                let desc_label = create_instruction_label(description);
                stage_box.append(&desc_label);
            }

            if let Some(command) = &stage.command {
                let row = create_copyable_command_row(command);
                stage_box.append(&row);
            }

            let stage_row = ListBoxRow::new();
            stage_row.set_child(Some(&stage_box));
            expander.add_row(&stage_row);
        }

        group.add(&expander);
    }

    group
}

fn build_output_section(notes: &[tool_instructions::OutputNote]) -> PreferencesGroup {
    let group = PreferencesGroup::new();
    group.set_title("Interpreting Output");

    for note in notes {
        let row = ListBoxRow::new();
        let box_container = GtkBox::new(Orientation::Horizontal, 12);

        let indicator = create_instruction_label(&note.indicator);
        box_container.append(&indicator);

        let meaning = create_instruction_label(&note.meaning);
        box_container.append(&meaning);

        let severity_text = note.severity.as_deref().unwrap_or("-");
        let severity = create_instruction_label(severity_text);
        box_container.append(&severity);

        row.set_child(Some(&box_container));
        group.add(&row);
    }

    group
}

fn build_advanced_section(examples: &[tool_instructions::AdvancedExample]) -> PreferencesGroup {
    let group = PreferencesGroup::new();
    group.set_title("Advanced Usage");

    for example in examples {
        let expander = ExpanderRow::new();
        expander.set_title(&example.title);
        setup_expander_icons(&expander);

        if let Some(scenario) = &example.scenario {
            let scenario_label = create_instruction_label(scenario);
            expander.add_row(&scenario_label);
        }

        let command_row = create_copyable_command_row(&example.command);
        expander.add_row(&command_row);

        for note in &example.notes {
            let note_label = create_instruction_label(note);
            expander.add_row(&note_label);
        }

        group.add(&expander);
    }

    group
}

fn build_comparison_section(table: &tool_instructions::ComparisonTable) -> PreferencesGroup {
    let group = PreferencesGroup::new();
    group.set_title("Tool Comparison");

    if let Some(caption) = &table.caption {
        let caption_label = create_instruction_label(caption);
        let caption_row = ListBoxRow::new();
        caption_row.set_child(Some(&caption_label));
        group.add(&caption_row);
    }

    for row in &table.rows {
        let row_container = ListBoxRow::new();
        let box_container = GtkBox::new(Orientation::Horizontal, 12);

        for col_idx in 0..table.columns.len() {
            let value = row.get(col_idx).cloned().unwrap_or_default();
            let label = create_instruction_label(&value);
            box_container.append(&label);
        }

        row_container.set_child(Some(&box_container));
        group.add(&row_container);
    }

    group
}

fn build_resources_section(resources: &[tool_instructions::ResourceLink]) -> PreferencesGroup {
    let group = PreferencesGroup::new();
    group.set_title("Resources");

    for resource in resources {
        let row = ListBoxRow::new();
        let box_container = GtkBox::new(Orientation::Vertical, 4);

        let link = LinkButton::builder()
            .uri(&resource.url)
            .label(&resource.label)
            .build();
        link.set_halign(Align::Start);
        box_container.append(&link);

        if let Some(description) = &resource.description {
            let description_label = create_instruction_label(description);
            box_container.append(&description_label);
        }

        row.set_child(Some(&box_container));
        group.add(&row);
    }

    group
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

    // Apply syntax highlighting to the command
    let highlighted_command = highlight_code(command, "bash");
    let cmd_label = Label::new(None);
    cmd_label.set_markup(&highlighted_command);
    cmd_label.set_selectable(true);
    cmd_label.set_xalign(0.0);
    cmd_label.set_hexpand(true);
    cmd_label.set_wrap(true);
    cmd_label.add_css_class("monospace");

    let command_text = command.to_string();
    let copy_button = Button::builder().icon_name("edit-copy-symbolic").build();
    copy_button.set_tooltip_text(Some("Copy full command to clipboard"));
    copy_button.connect_clicked(move |_| {
        if let Some(display) = gdk::Display::default() {
            let clipboard = display.clipboard();
            clipboard.set_text(&command_text);
        }
    });

    row.append(&cmd_label);
    row.append(&copy_button);
    row
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_tool_resolves_to_missing_state() {
        let state = resolve_instruction_state(Some("nonexistent_tool_12345"));
        assert!(
            matches!(state, InstructionState::Missing { .. }),
            "missing tool should use fallback state"
        );
    }

    #[test]
    fn none_tool_falls_back_to_manifest_first_entry() {
        let state = resolve_instruction_state(None);
        match state {
            InstructionState::Available(doc) => {
                assert!(tool_instructions::has_tool(&doc.id));
            }
            InstructionState::Missing { tool_id } => {
                // Manifest may be empty when instruction data fails to load
                if let Some(id) = tool_id {
                    assert!(!id.is_empty());
                }
            }
        }
    }

    #[test]
    fn dialog_title_for_missing_tool_has_fallback_text() {
        let state = InstructionState::Missing {
            tool_id: Some("custom-tool".to_string()),
        };
        assert_eq!(state.dialog_title(), "custom-tool - Full Instructions");

        let unnamed = InstructionState::Missing { tool_id: None };
        assert_eq!(unnamed.dialog_title(), "Tool Instructions");
    }
}
