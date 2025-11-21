/*****************************************************************************/
/*                                                                           */
/*  main.rs                                              TTTTTTTT SSSSSSS II */
/*                                                          TT    SS      II */
/*  By: st93642@students.tsi.lv                             TT    SSSSSSS II */
/*                                                          TT         SS II */
/*  Created: Nov 21 2025 23:42 st93642                      TT    SSSSSSS II */
/*  Updated: Nov 21 2025 23:42 st93642                                       */
/*                                                                           */
/*   Transport and Telecommunication Institute - Riga, Latvia                */
/*                       https://tsi.lv                                      */
/*****************************************************************************/

use gtk4::prelude::*;
use gtk4::{Application, Settings};

use pt_journal::model::AppModel;
use pt_journal::ui::main;

fn main() {
    let app = Application::builder()
        .application_id("com.example.pt_journal")
        .build();

    app.connect_activate(|app| {
        if let Some(settings) = Settings::default() {
            settings.set_gtk_application_prefer_dark_theme(true);
        }
        main::build_ui(app, AppModel::default());
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
