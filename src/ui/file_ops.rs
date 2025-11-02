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

/// Save a session to a new file (Save As dialog)
pub fn save_session_as_dialog<F>(window: &Window, session: &Session, on_saved: F)
where
    F: Fn(PathBuf) + 'static,
{
    let dialog = FileDialog::new();
    dialog.set_title("Save Session As - Choose Folder Name");
    
    // Set initial folder to default sessions directory
    let default_dir = store::default_sessions_dir();
    if default_dir.exists() {
        let file = gio::File::for_path(&default_dir);
        dialog.set_initial_folder(Some(&file));
    }
    
    // Remove .json extension, just use session name as folder
    let default_name = session.name.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
    let default_name = if default_name.is_empty() {
        "pt-session".to_string()
    } else {
        default_name
    };
    
    // Set initial name without .json extension - will become folder name
    dialog.set_initial_name(Some(&default_name));
    
    let session_clone = session.clone();
    let window_weak = window.downgrade();
    
    // Use save dialog which will let user choose/create a folder
    dialog.save(Some(window), None::<&gio::Cancellable>, move |res| {
        if let Ok(file) = res {
            if let Some(mut path) = file.path() {
                // Remove any extension user might have added
                if path.extension().is_some() {
                    path.set_extension("");
                }
                
                // Path is now the session folder
                // Create folder structure and save
                match store::save_session(&path, &session_clone) {
                    Ok(_) => {
                        // Return path to session.json for consistency
                        let session_file = path.join("session.json");
                        on_saved(session_file);
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
