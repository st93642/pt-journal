use gtk4::prelude::*;
use gtk4::{Application, Settings};

mod model;
mod store;
mod ui;

use crate::model::AppModel;

fn main() {
    let app = Application::builder()
        .application_id("com.example.pt_journal")
        .build();

    app.connect_activate(|app| {
        if let Some(settings) = Settings::default() {
            settings.set_gtk_application_prefer_dark_theme(true);
        }
        ui::build_ui(app, AppModel::default());
    });

    app.run();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_application_creation() {
        // Test that the application can be created without panicking
        // This is a basic smoke test for the GTK application setup
        let app = Application::builder()
            .application_id("com.example.pt_journal_test")
            .build();

        // We can't run the application in tests, but we can verify it was created
        assert_eq!(app.application_id().unwrap(), "com.example.pt_journal_test");
    }
}
