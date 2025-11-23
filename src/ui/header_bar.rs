/// Header bar module with Open/Save/Save As buttons and sidebar toggle
use gtk4::prelude::*;
use gtk4::{Button, HeaderBar};

/// Create the application header bar
pub fn create_header_bar() -> (HeaderBar, Button, Button, Button, Button) {
    let header = HeaderBar::new();

    let btn_open = Button::from_icon_name("document-open-symbolic");
    btn_open.set_tooltip_text(Some("Open session"));

    let btn_save = Button::from_icon_name("document-save-symbolic");
    btn_save.set_tooltip_text(Some("Save session (Ctrl+S)"));

    let btn_save_as = Button::from_icon_name("document-save-as-symbolic");
    btn_save_as.set_tooltip_text(Some("Save session as... (Ctrl+Shift+S)"));

    let btn_sidebar = Button::from_icon_name("view-sidebar-start-symbolic");
    btn_sidebar.set_tooltip_text(Some("Toggle sidebar"));

    header.pack_start(&btn_open);
    header.pack_start(&btn_sidebar);
    header.pack_end(&btn_save_as);
    header.pack_end(&btn_save);

    (header, btn_open, btn_save, btn_save_as, btn_sidebar)
}

#[cfg(test)]
mod tests {
    // Note: GTK tests can segfault in headless environments
    // These tests just verify the module compiles

    #[test]
    fn test_module_compiles() {
        // This test ensures the module compiles correctly
        // No assertions needed - just checking that the module compiles
    }
}
