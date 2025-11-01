use crate::model::Session;
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
    let json = serde_json::to_string_pretty(session)?;
    fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
    fs::write(path, json)?;
    Ok(())
}

#[allow(dead_code)]
pub fn load_session(path: &Path) -> Result<Session> {
    let content = fs::read_to_string(path)?;
    let session: Session = serde_json::from_str(&content)?;
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use std::fs;
    use tempfile::TempDir;
    use assert_matches::assert_matches;
    use uuid::Uuid;
    use chrono::Utc;

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
        let nested_path = temp_dir.path().join("deep").join("nested").join("path").join("session.json");

        let session = Session::default();

        // Should create all intermediate directories
        let result = save_session(&nested_path, &session);
        assert!(result.is_ok());

        // Verify file exists
        assert!(nested_path.exists());

        // Verify parent directories exist
        assert!(nested_path.parent().unwrap().exists());
    }

    #[test]
    fn test_save_load_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let session_path = temp_dir.path().join("roundtrip_test.json");

        // Create a complex session
        let mut session = Session::default();
        session.name = "Roundtrip Test".to_string();
        session.notes_global = "Global test notes".to_string();

        // Modify some data
        if let Some(step) = session.phases[0].steps.get_mut(0) {
            step.status = StepStatus::Done;
            step.notes = "Step completed".to_string();
            step.evidence.push(Evidence {
                id: Uuid::new_v4(),
                path: "/test/path.png".to_string(),
                created_at: Utc::now(),
                kind: "screenshot".to_string(),
                x: 0.0,
                y: 0.0,
            });
        }

        session.phases[0].notes = "Phase completed".to_string();

        // Save and load
        save_session(&session_path, &session).unwrap();
        let loaded = load_session(&session_path).unwrap();

        // Verify all data
        assert_eq!(loaded.name, session.name);
        assert_eq!(loaded.notes_global, session.notes_global);
        assert_eq!(loaded.phases[0].notes, session.phases[0].notes);

        let original_step = &session.phases[0].steps[0];
        let loaded_step = &loaded.phases[0].steps[0];

        assert_matches!(loaded_step.status, StepStatus::Done);
        assert_eq!(loaded_step.notes, original_step.notes);
        assert_eq!(loaded_step.evidence.len(), 1);
        assert_eq!(loaded_step.evidence[0].path, "/test/path.png");
    }

    #[test]
    fn test_save_session_with_unicode() {
        let temp_dir = TempDir::new().unwrap();
        let session_path = temp_dir.path().join("unicode_test.json");

        let mut session = Session::default();
        session.name = "Тест сессии 🚀".to_string();
        session.notes_global = "Заметки с эмодзи 🎯 и unicode: ñáéíóú".to_string();

        if let Some(step) = session.phases[0].steps.get_mut(0) {
            step.notes = "Шаги с кириллицей: Привет мир!".to_string();
        }

        save_session(&session_path, &session).unwrap();
        let loaded = load_session(&session_path).unwrap();

        assert_eq!(loaded.name, session.name);
        assert_eq!(loaded.notes_global, session.notes_global);
        assert_eq!(loaded.phases[0].steps[0].notes, session.phases[0].steps[0].notes);
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
        let session_path = temp_dir.path().join("permissions_test.json");

        let session = Session::default();
        save_session(&session_path, &session).unwrap();

        // Verify file exists and is readable
        assert!(session_path.exists());
        let metadata = fs::metadata(&session_path).unwrap();
        assert!(metadata.is_file());

        // Should be able to read the content back
        let content = fs::read_to_string(&session_path).unwrap();
        assert!(content.contains("New Engagement"));
    }

    #[test]
    fn test_concurrent_access() {
        let temp_dir = TempDir::new().unwrap();
        let session_path = temp_dir.path().join("concurrent.json");

        let session = Session::default();

        // Save multiple times (simulating concurrent access)
        for i in 0..5 {
            let mut test_session = session.clone();
            test_session.name = format!("Concurrent Test {}", i);
            save_session(&session_path, &test_session).unwrap();

            let loaded = load_session(&session_path).unwrap();
            assert_eq!(loaded.name, format!("Concurrent Test {}", i));
        }
    }
}


