//! Navigation controller for handling phase and step selection.
//!
//! This controller manages navigation between phases and steps,
//! including rebuilding lists and handling selection changes.

use gtk4::prelude::*;
use gtk4::{CheckButton, GestureClick, ListBox, ListBoxRow};
use std::rc::Rc;

use crate::model::StepStatus;
use crate::ui::detail_panel::DetailPanel;
use crate::ui::state::StateManager;

/// Navigation controller that encapsulates navigation-related UI logic.
pub struct NavigationController {
    state: Rc<StateManager>,
}

impl NavigationController {
    /// Create a new navigation controller.
    pub fn new(state: Rc<StateManager>) -> Self {
        Self { state }
    }

    /// Bind phase selection handler and return the signal handler ID.
    pub fn bind_phase_handler(
        &self,
        phase_combo: &gtk4::DropDown,
        steps_list: &ListBox,
        detail_panel: &Rc<DetailPanel>,
    ) -> Rc<gtk4::glib::SignalHandlerId> {
        let steps_list_clone = steps_list.clone();
        let state_clone = self.state.clone();
        let detail_panel_clone = detail_panel.clone();

        let handler_id = phase_combo.connect_selected_notify(move |combo| {
            let selected = combo.selected();
            // Use state manager to change phase (dispatches events)
            state_clone.select_phase(selected as usize);
            rebuild_steps_list(&steps_list_clone, &state_clone, &detail_panel_clone);
        });
        Rc::new(handler_id)
    }

    /// Bind step selection handlers (wired during rebuild_steps_list).
    pub fn bind_step_handlers(&self, _steps_list: &ListBox, _detail_panel: &Rc<DetailPanel>) {
        // We'll wire up individual step handlers during rebuild_steps_list
        // This function is called once at setup to prepare the container
    }
}

/// Helper function to rebuild the steps list when phase changes
pub fn rebuild_steps_list(
    steps_list: &ListBox,
    state: &Rc<StateManager>,
    detail_panel: &Rc<DetailPanel>,
) {
    // Clear existing rows
    while let Some(child) = steps_list.first_child() {
        steps_list.remove(&child);
    }

    let phase_idx = state.current_phase();
    let step_summaries = state.get_step_summaries_for_phase(phase_idx);

    for summary in &step_summaries {
        let row = ListBoxRow::new();
        let row_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        row_box.set_margin_start(8);
        row_box.set_margin_end(8);
        row_box.set_margin_top(4);
        row_box.set_margin_bottom(4);

        let checkbox = CheckButton::new();
        checkbox.set_active(matches!(summary.status, StepStatus::Done));

        let label = gtk4::Label::new(Some(&summary.title));
        label.set_halign(gtk4::Align::Start);
        label.set_hexpand(true);

        // Make entire row clickable for step selection
        let click = GestureClick::new();
        let state_clone = state.clone();
        let detail_panel_row = detail_panel.clone();
        let steps_list_row = steps_list.clone();
        let row_clone = row.clone();
        let step_idx = summary.index;
        click.connect_pressed(move |_, _, _, _| {
            state_clone.select_step(step_idx);
            load_step_into_panel(&state_clone, &detail_panel_row);

            // Update selection styling
            steps_list_row.select_row(Some(&row_clone));
        });
        row.add_controller(click); // Attach to row instead of label

        // Checkbox handler
        let state_checkbox = state.clone();
        let checkbox_step_idx = summary.index;
        checkbox.connect_toggled(move |_| {
            state_checkbox.toggle_step_completion(phase_idx, checkbox_step_idx);
        });

        row_box.append(&checkbox);
        row_box.append(&label);
        row.set_child(Some(&row_box));
        steps_list.append(&row);
    }

    // Load first step if available
    if !step_summaries.is_empty() {
        state.select_step(0);
        load_step_into_panel(state, detail_panel);
        if let Some(first_row) = steps_list.row_at_index(0) {
            steps_list.select_row(Some(&first_row));
        }
    } else {
        clear_detail_panel(detail_panel);
    }
}

/// Helper function to load a step into the detail panel
pub fn load_step_into_panel(state: &Rc<StateManager>, detail_panel: &Rc<DetailPanel>) {
    if let Some(snapshot) = state.get_active_step_snapshot() {
        // Check if this is a quiz step
        if let Some(quiz_step) = snapshot.quiz_data {
            // For quiz steps, show the phase name as the title instead of the step title
            let phase_name = {
                let model = state.model();
                let model_ref = model.borrow();
                model_ref
                    .current_phase()
                    .map(|phase| phase.name.clone())
                    .unwrap_or_else(|| "Quiz".to_string())
            };
            detail_panel.set_title(&phase_name);

            // Show quiz view and load quiz
            detail_panel.load_quiz_step(&quiz_step);
        } else {
            // Show tutorial view and load tutorial content
            detail_panel.set_completion(matches!(snapshot.status, StepStatus::Done));
            detail_panel.set_title(&snapshot.title);

            // Update description
            detail_panel.load_tutorial_step(&snapshot.description, &snapshot.chat_history);
        }
    }
}

/// Helper function to rebuild the phase combo when phases change
pub fn rebuild_phase_combo(phase_combo: &gtk4::DropDown, state: &Rc<StateManager>) {
    let model = state.model();
    let new_model = gtk4::StringList::new(&[]);

    // Add new phase names
    for phase in &model.borrow().session().phases {
        new_model.append(&phase.name);
    }

    // Temporarily set model to None to force refresh
    phase_combo.set_model(None::<&gtk4::StringList>);
    phase_combo.set_model(Some(&new_model));

    // Force popup refresh by temporarily changing selection
    let current_selected = phase_combo.selected();
    phase_combo.set_selected(0);
    if current_selected != 0 {
        phase_combo.set_selected(current_selected);
    }

    // Ensure selected phase is still valid
    let selected = state.current_phase();
    if selected < new_model.n_items() as usize {
        phase_combo.set_selected(selected as u32);
    } else {
        // Fallback to first phase
        phase_combo.set_selected(0);
        // Note: We don't directly mutate the model here anymore
        // The phase selection should be handled through StateManager
    }

    phase_combo.queue_allocate();
    phase_combo.queue_draw();
}

/// Helper function to clear the detail panel
pub fn clear_detail_panel(detail_panel: &Rc<DetailPanel>) {
    detail_panel.checkbox().set_active(false);
    detail_panel.set_title("");
    detail_panel.desc_view().buffer().set_text("");
    detail_panel.chat_panel().clear_history();
}
