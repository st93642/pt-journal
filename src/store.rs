/*****************************************************************************/
/*                                                                           */
/*  store.rs                                             TTTTTTTT SSSSSSS II */
/*                                                          TT    SS      II */
/*  By: st93642@students.tsi.lv                             TT    SSSSSSS II */
/*                                                          TT         SS II */
/*  Created: Nov 21 2025 23:43 st93642                      TT    SSSSSSS II */
/*  Updated: Nov 25 2025 17:50 st93642                                       */
/*                                                                           */
/*   Transport and Telecommunication Institute - Riga, Latvia                */
/*                       https://tsi.lv                                      */
/*****************************************************************************/

use crate::model::*;
use anyhow::Result;
use directories::UserDirs;
use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
pub fn default_sessions_dir() -> PathBuf {
    // Try to use the user's Downloads folder
    if let Some(user_dirs) = UserDirs::new() {
        if let Some(download_dir) = user_dirs.download_dir() {
            let path = download_dir.join("pt-journal-sessions");
            if let Err(e) = fs::create_dir_all(&path) {
                eprintln!("Failed to create sessions directory in Downloads: {}", e);
                // Fall back to current directory
                return PathBuf::from("./pt-journal-sessions");
            }
            return path;
        }
    }

    // Fallback: create in current directory
    let path = PathBuf::from("./pt-journal-sessions");
    let _ = fs::create_dir_all(&path);
    path
}

#[allow(dead_code)]
pub fn save_session(path: &Path, session: &Session) -> Result<()> {
    // Create session folder structure
    // path should be: /path/to/session-name/session.json
    let session_dir = if path.file_name().and_then(|n| n.to_str()) == Some("session.json") {
        // Already points to session.json, use parent as session dir
        path.parent().unwrap_or(path)
    } else {
        // Path is just a directory or file, ensure we have a folder
        if path.extension().is_some() {
            // Has extension, might be old format - convert to folder
            path.parent().unwrap_or(Path::new("."))
        } else {
            // No extension, treat as folder
            path
        }
    };

    // Create session directory and evidence subdirectory
    fs::create_dir_all(session_dir)?;
    fs::create_dir_all(session_dir.join("evidence"))?;

    // Save session.json in the session folder
    let session_file = session_dir.join("session.json");
    let json = serde_json::to_string_pretty(session)?;
    fs::write(session_file, json)?;

    Ok(())
}

#[allow(dead_code)]
pub fn load_session(path: &Path) -> Result<Session> {
    let content = fs::read_to_string(path)?;
    let mut session: Session = serde_json::from_str(&content)?;

    // Migrate legacy step data to new StepContent format
    for phase in &mut session.phases {
        for step in &mut phase.steps {
            step.migrate_from_legacy();
        }
    }

    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Evidence, Session, StepStatus};
    use assert_matches::assert_matches;
    use chrono::Utc;
    use std::fs;
    use tempfile::TempDir;
    use uuid::Uuid;

    #[test]
    fn test_default_sessions_directory() {
        // Test that default directory logic works
        let path = default_sessions_dir();
        // Should contain pt-journal-sessions in the path
        assert!(path.to_string_lossy().contains("pt-journal-sessions"));
        // The directory should be created and exist
        assert!(path.exists());
        assert!(path.is_dir());
    }

    #[test]
    fn test_save_session_creates_directories() {
        let temp_dir = TempDir::new().unwrap();
        let session_folder = temp_dir
            .path()
            .join("deep")
            .join("nested")
            .join("path")
            .join("my_session");
        let session_file = session_folder.join("session.json");

        let session = Session::default();

        // Should create all intermediate directories and folder structure
        let result = save_session(&session_folder, &session);
        assert!(result.is_ok());

        // Verify file and folders exist
        assert!(session_file.exists());
        assert!(session_folder.join("evidence").exists());

        // Verify parent directories exist
        assert!(session_folder.parent().unwrap().exists());
    }

    #[test]
    fn test_save_load_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let session_folder = temp_dir.path().join("roundtrip_test");
        let session_file = session_folder.join("session.json");

        // Create a complex session
        let mut session = Session::default();
        session.name = "Roundtrip Test".to_string();
        session.notes_global = "Global test notes".to_string();

        // Modify some data
        if let Some(step) = session.phases[0].steps.get_mut(0) {
            step.status = StepStatus::Done;
            step.set_notes("Step completed".to_string());
            step.add_evidence(Evidence {
                id: Uuid::new_v4(),
                path: "/test/path.png".to_string(),
                created_at: Utc::now(),
                kind: "screenshot".to_string(),
                x: 0.0,
                y: 0.0,
            });
        }

        session.phases[0].notes = "Phase completed".to_string();

        // Save to folder and load from session.json
        save_session(&session_folder, &session).unwrap();
        let loaded = load_session(&session_file).unwrap();

        // Verify all data
        assert_eq!(loaded.name, session.name);
        assert_eq!(loaded.notes_global, session.notes_global);
        assert_eq!(loaded.phases[0].notes, session.phases[0].notes);

        let original_step = &session.phases[0].steps[0];
        let loaded_step = &loaded.phases[0].steps[0];

        assert_matches!(loaded_step.status, StepStatus::Done);
        assert_eq!(loaded_step.get_notes(), original_step.get_notes());
        assert_eq!(loaded_step.get_evidence().len(), 1);
        assert_eq!(loaded_step.get_evidence()[0].path, "/test/path.png");
    }

    #[test]
    fn test_save_session_with_unicode() {
        let temp_dir = TempDir::new().unwrap();
        let session_folder = temp_dir.path().join("unicode_test");
        let session_file = session_folder.join("session.json");

        let mut session = Session::default();
        session.name = "Тест сессии 🚀".to_string();
        session.notes_global = "Заметки с эмодзи 🎯 и unicode: ñáéíóú".to_string();

        if let Some(step) = session.phases[0].steps.get_mut(0) {
            step.set_notes("Шаги с кириллицей: Привет мир!".to_string());
        }

        save_session(&session_folder, &session).unwrap();
        let loaded = load_session(&session_file).unwrap();

        assert_eq!(loaded.name, session.name);
        assert_eq!(loaded.notes_global, session.notes_global);
        assert_eq!(
            loaded.phases[0].steps[0].get_notes(),
            session.phases[0].steps[0].get_notes()
        );
    }

    #[test]
    fn test_load_malformed_json() {
        let temp_dir = TempDir::new().unwrap();
        let invalid_path = temp_dir.path().join("invalid.json");

        // Write invalid JSON
        fs::write(&invalid_path, r#"{"invalid": json"#).unwrap();

        let result = load_session(&invalid_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let empty_path = temp_dir.path().join("empty.json");

        // Create empty file
        fs::write(&empty_path, "").unwrap();

        let result = load_session(&empty_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_save_to_readonly_directory() {
        let temp_dir = TempDir::new().unwrap();
        let readonly_dir = temp_dir.path().join("readonly");
        fs::create_dir(&readonly_dir).unwrap();

        // Make directory read-only (on Unix systems)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&readonly_dir).unwrap().permissions();
            perms.set_mode(0o444);
            fs::set_permissions(&readonly_dir, perms).unwrap();
        }

        let session_path = readonly_dir.join("session.json");
        let session = Session::default();

        // Should fail on read-only directory
        let result = save_session(&session_path, &session);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_file_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let session_folder = temp_dir.path().join("permissions_test");
        let session_file = session_folder.join("session.json");

        let session = Session::default();
        save_session(&session_folder, &session).unwrap();

        // Verify file exists and is readable
        assert!(session_file.exists());
        let metadata = fs::metadata(&session_file).unwrap();
        assert!(metadata.is_file());

        // Should be able to read the content back
        let content = fs::read_to_string(&session_file).unwrap();
        assert!(content.contains("New Engagement"));
    }

    #[test]
    fn test_backward_compatibility_without_chat_history() {
        let temp_dir = TempDir::new().unwrap();
        let session_file = temp_dir.path().join("legacy_session.json");

        // Create a JSON string without chat_history field
        let legacy_json = r#"{
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "name": "Legacy Session",
            "created_at": "2025-11-25T12:00:00Z",
            "phases": [
                {
                    "id": "550e8400-e29b-41d4-a716-446655440001",
                    "name": "Test Phase",
                    "steps": [
                        {
                            "id": "550e8400-e29b-41d4-a716-446655440002",
                            "title": "Test Step",
                            "tags": ["test"],
                            "status": "Todo",
                            "content": {
                                "Tutorial": {
                                    "description": "Test description",
                                    "description_notes": "",
                                    "notes": "",
                                    "evidence": []
                                }
                            }
                        }
                    ],
                    "notes": ""
                }
            ],
            "notes_global": ""
        }"#;

        fs::write(&session_file, legacy_json).unwrap();

        // Should load successfully with empty chat_history
        let loaded = load_session(&session_file).unwrap();
        assert_eq!(loaded.name, "Legacy Session");

        if let Some(step) = loaded.phases[0].steps.first() {
            let history = step.get_chat_history();
            assert!(history.is_empty()); // Should default to empty vec
        }
    }
}
