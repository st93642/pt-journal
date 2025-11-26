//! Instruction rendering helpers for the tool execution panel.
//!
//! This module encapsulates the logic for determining which instruction
//! document should be rendered and how to build the GTK widgets that present
//! those instructions. The separation enables unit tests to exercise the
//! selection logic without initializing GTK, while keeping widget construction
//! centralized for reuse by the panel and dialog views.

use crate::ui::tool_instructions::{self, ToolInstructions};
use gtk4::prelude::*;
#[allow(deprecated)]
use gtk4::{
    Align, Box as GtkBox, Button, Frame, Grid, Label, LinkButton, Orientation,
};

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
    #[allow(deprecated)]
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
    let fallback_id = tool_instructions::manifest().first().map(|entry| entry.id.clone());
    if let Some(id) = fallback_id {
        return tool_instructions::get_instructions(&id)
            .map(InstructionState::Available)
            .unwrap_or_else(|| InstructionState::Missing {
                tool_id: Some(id),
            });
    }

    InstructionState::Missing { tool_id: None }
}

/// Builds the fallback widget when instruction data is unavailable.
#[allow(deprecated)]
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
#[allow(deprecated)]
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

#[allow(deprecated)]
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

#[allow(deprecated)]
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

#[allow(deprecated)]
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

#[allow(deprecated)]
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

#[allow(deprecated)]
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

#[allow(deprecated)]
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

#[allow(deprecated)]
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

#[allow(deprecated)]
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

#[allow(deprecated)]
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

#[allow(deprecated)]
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

#[allow(deprecated)]
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
mod tests {
    use super::*;

    #[test]
    fn missing_tool_resolves_to_missing_state() {
        let state = resolve_instruction_state(Some("nonexistent_tool_12345"));
        assert!(matches!(state, InstructionState::Missing { .. }), "missing tool should use fallback state");
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
