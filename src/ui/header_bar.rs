/// Header bar module with sidebar toggle
use gtk4::prelude::*;
use gtk4::{Button, HeaderBar};

/// Create the application header bar
pub fn create_header_bar() -> (HeaderBar, Button) {
    let header = HeaderBar::new();

    let btn_sidebar = Button::from_icon_name("open-menu-symbolic");
    btn_sidebar.set_tooltip_text(Some("Toggle sidebar"));

    header.pack_start(&btn_sidebar);

    (header, btn_sidebar)
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
