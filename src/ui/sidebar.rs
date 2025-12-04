use crate::model::AppModel;
/// Sidebar module for phase selector and steps list
use gtk4::prelude::*;
use gtk4::{Box as GtkBox, DropDown, ListBox, Orientation, ScrolledWindow, StringList};
use std::cell::RefCell;
use std::rc::Rc;

/// Create the sidebar with phase selector and steps list
/// Returns: (sidebar_box, phase_combo, steps_list)
pub fn create_sidebar(model: &Rc<RefCell<AppModel>>) -> (GtkBox, DropDown, ListBox) {
    let left_box = GtkBox::new(Orientation::Vertical, 6);

    // Phase selector
    let phase_model = StringList::new(&[]);
    let phase_combo = DropDown::new(Some(phase_model), None::<gtk4::Expression>);
    phase_combo.set_selected(model.borrow().selected_phase() as u32);

    // Enable search for easier navigation through many phases
    phase_combo.set_enable_search(true);

    // Set factory for proper display in the dropdown button
    let factory = gtk4::SignalListItemFactory::new();
    factory.connect_setup(|_, item| {
        let label = gtk4::Label::new(None);
        label.set_halign(gtk4::Align::Start);
        item.downcast_ref::<gtk4::ListItem>()
            .unwrap()
            .set_child(Some(&label));
    });
    factory.connect_bind(|_, item| {
        let list_item = item.downcast_ref::<gtk4::ListItem>().unwrap();
        let label = list_item
            .child()
            .unwrap()
            .downcast::<gtk4::Label>()
            .unwrap();
        let string_object = list_item
            .item()
            .unwrap()
            .downcast::<gtk4::StringObject>()
            .unwrap();
        label.set_text(&string_object.string());
    });
    phase_combo.set_factory(Some(&factory));

    // Set list factory for the popup list items
    let list_factory = gtk4::SignalListItemFactory::new();
    list_factory.connect_setup(|_, item| {
        let label = gtk4::Label::new(None);
        label.set_halign(gtk4::Align::Start);
        label.set_margin_top(4);
        label.set_margin_bottom(4);
        label.set_margin_start(8);
        label.set_margin_end(8);
        item.downcast_ref::<gtk4::ListItem>()
            .unwrap()
            .set_child(Some(&label));
    });
    list_factory.connect_bind(|_, item| {
        let list_item = item.downcast_ref::<gtk4::ListItem>().unwrap();
        let label = list_item
            .child()
            .unwrap()
            .downcast::<gtk4::Label>()
            .unwrap();
        let string_object = list_item
            .item()
            .unwrap()
            .downcast::<gtk4::StringObject>()
            .unwrap();
        label.set_text(&string_object.string());
    });
    phase_combo.set_list_factory(Some(&list_factory));

    // Add CSS class for styling the dropdown popup height
    phase_combo.add_css_class("phase-selector");

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

    (left_box, phase_combo, steps_list)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_sidebar_creation() {
        // This test ensures the module compiles correctly
        // No assertions needed - just checking that the module compiles
    }
}
