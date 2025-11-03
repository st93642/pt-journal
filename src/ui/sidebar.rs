use crate::model::AppModel;
/// Sidebar module for phase selector and steps list
use gtk4::prelude::*;
use gtk4::{Box as GtkBox, DropDown, ListBox, Orientation, ScrolledWindow, StringList};
use std::cell::RefCell;
use std::rc::Rc;

/// Create the sidebar with phase selector and steps list
/// Returns: (sidebar_box, phase_model, phase_combo, steps_list)
pub fn create_sidebar(model: &Rc<RefCell<AppModel>>) -> (GtkBox, StringList, DropDown, ListBox) {
    let left_box = GtkBox::new(Orientation::Vertical, 6);

    // Phase selector
    let phase_model = StringList::new(&[]);
    for phase in &model.borrow().session.phases {
        phase_model.append(&phase.name);
    }
    let phase_combo = DropDown::new(Some(phase_model.clone()), None::<gtk4::Expression>);
    phase_combo.set_selected(model.borrow().selected_phase as u32);

    // Steps list
    let steps_scroller = ScrolledWindow::builder()
        .min_content_width(280)
        .hexpand(false)
        .vexpand(true)
        .build();
    let steps_list = ListBox::new();
    steps_scroller.set_child(Some(&steps_list));

    left_box.append(&phase_combo);
    left_box.append(&steps_scroller);

    (left_box, phase_model, phase_combo, steps_list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sidebar_creation() {
        // This test ensures the module compiles correctly
        assert!(true);
    }
}
