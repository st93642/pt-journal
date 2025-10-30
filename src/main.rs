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
