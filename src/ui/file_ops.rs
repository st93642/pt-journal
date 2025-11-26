use crate::model::Session;
use crate::store;
use gtk4::gio;
/// File operations module for open/save session dialogs
use gtk4::prelude::*;
use gtk4::{FileDialog, Window};
use std::path::PathBuf;

/// Callback type for successful session load
pub type OnSessionLoaded = Box<dyn Fn(Session, PathBuf)>;

/// Open a session file dialog and load the session
pub fn open_session_dialog<F>(window: &Window, on_loaded: F)
where
    F: Fn(Session, PathBuf) + 'static,
{
    let dialog = FileDialog::new();
    dialog.set_title("Open Session - Select session.json");

    // Set initial folder to default sessions directory
    let default_dir = store::default_sessions_dir();
    if default_dir.exists() {
        let file = gio::File::for_path(&default_dir);
        dialog.set_initial_folder(Some(&file));
    }

    // Create file filter for session.json files
    let filter = gtk4::FileFilter::new();
    filter.set_name(Some("PT Journal Sessions (session.json)"));
    filter.add_pattern("session.json");
    filter.add_mime_type("application/json");

    let filters = gio::ListStore::new::<gtk4::FileFilter>();
    filters.append(&filter);
    dialog.set_filters(Some(&filters));

    let window_weak = window.downgrade();
    dialog.open(Some(window), None::<&gio::Cancellable>, move |res| {
        if let Ok(file) = res {
            if let Some(path) = file.path() {
                match store::load_session(&path) {
                    Ok(session) => {
                        on_loaded(session, path);
                    }
                    Err(err) => {
                        eprintln!("Failed to open session: {err:?}");
                        if let Some(window) = window_weak.upgrade() {
                            show_error_dialog(&window, &format!("Failed to open session: {}", err));
                        }
                    }
                }
            }
        }
    });
}

/// Show an error dialog (using console for now, as MessageDialog is deprecated in GTK4.10+)
fn show_error_dialog(_window: &Window, message: &str) {
    eprintln!("Error: {}", message);
    // TODO: Replace with custom AlertDialog in GTK4.10+
}

#[cfg(test)]
mod tests {
    use crate::model::Session;

    #[test]
    fn test_session_clone() {
        let session = Session::default();
        let cloned = session.clone();
        assert_eq!(session.name, cloned.name);
        assert_eq!(session.phases.len(), cloned.phases.len());
    }
}
