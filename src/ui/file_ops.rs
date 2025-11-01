/// File operations module for open/save session dialogs
use gtk4::prelude::*;
use gtk4::{FileDialog, Window};
use gtk4::gio;
use std::rc::Rc;
use std::cell::RefCell;
use std::path::PathBuf;
use crate::model::{AppModel, Session};
use crate::store;

/// Callback type for successful session load
pub type OnSessionLoaded = Box<dyn Fn(Session, PathBuf)>;

/// Callback type for successful session save
pub type OnSessionSaved = Box<dyn Fn(PathBuf)>;

/// Open a session file dialog and load the session
pub fn open_session_dialog<F>(window: &Window, on_loaded: F)
where
    F: Fn(Session, PathBuf) + 'static,
{
    let dialog = FileDialog::new();
    dialog.set_title("Open Session");
    
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

/// Save a session to a new file (Save As dialog)
pub fn save_session_as_dialog<F>(window: &Window, session: &Session, on_saved: F)
where
    F: Fn(PathBuf) + 'static,
{
    let dialog = FileDialog::new();
    dialog.set_title("Save Session As");
    dialog.set_initial_name(Some(&format!("{}.json", session.name)));
    
    let session_clone = session.clone();
    let window_weak = window.downgrade();
    dialog.save(Some(window), None::<&gio::Cancellable>, move |res| {
        if let Ok(file) = res {
            if let Some(path) = file.path() {
                match store::save_session(&path, &session_clone) {
                    Ok(_) => {
                        on_saved(path);
                    }
                    Err(err) => {
                        eprintln!("Failed to save session: {err:?}");
                        if let Some(window) = window_weak.upgrade() {
                            show_error_dialog(&window, &format!("Failed to save session: {}", err));
                        }
                    }
                }
            }
        }
    });
}

/// Save a session to its current path, or show Save As dialog if no path
pub fn save_session<F>(
    window: &Window,
    model: Rc<RefCell<AppModel>>,
    on_saved: F,
) where
    F: Fn(PathBuf) + 'static,
{
    let current_path = model.borrow().current_path.clone();
    let session = model.borrow().session.clone();
    
    if let Some(path) = current_path {
        // Save to existing path
        match store::save_session(&path, &session) {
            Ok(_) => {
                on_saved(path);
            }
            Err(err) => {
                eprintln!("Failed to save: {err:?}");
                show_error_dialog(window, &format!("Failed to save session: {}", err));
            }
        }
    } else {
        // Show Save As dialog
        save_session_as_dialog(window, &session, on_saved);
    }
}

/// Show an error dialog (using console for now, as MessageDialog is deprecated in GTK4.10+)
fn show_error_dialog(_window: &Window, message: &str) {
    eprintln!("Error: {}", message);
    // TODO: Replace with custom AlertDialog in GTK4.10+
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Session;
    use tempfile::TempDir;
    
    #[test]
    fn test_save_session_to_existing_path() {
        let temp_dir = TempDir::new().unwrap();
        let session_path = temp_dir.path().join("test.json");
        
        let mut model = AppModel::default();
        model.current_path = Some(session_path.clone());
        model.session.name = "Test Session".to_string();
        
        // Save manually for testing
        store::save_session(&session_path, &model.session).unwrap();
        
        // Verify file exists
        assert!(session_path.exists());
        
        // Load and verify
        let loaded = store::load_session(&session_path).unwrap();
        assert_eq!(loaded.name, "Test Session");
    }
    
    #[test]
    fn test_session_clone() {
        let session = Session::default();
        let cloned = session.clone();
        assert_eq!(session.name, cloned.name);
        assert_eq!(session.phases.len(), cloned.phases.len());
    }
}
