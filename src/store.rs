/*****************************************************************************/
/*                                                                           */
/*  store.rs                                             TTTTTTTT SSSSSSS II */
/*                                                          TT    SS      II */
/*  By: st93642@students.tsi.lv                             TT    SSSSSSS II */
/*                                                          TT         SS II */
/*  Created: Nov 21 2025 23:43 st93642                      TT    SSSSSSS II */
/*  Updated: Nov 26 2025 18:16 st93642                                       */
/*                                                                           */
/*   Transport and Telecommunication Institute - Riga, Latvia                */
/*                       https://tsi.lv                                      */
/*****************************************************************************/

use crate::model::*;
use anyhow::Result;
use std::path::Path;

#[allow(dead_code)]
pub fn load_session(path: &Path) -> Result<Session> {
    let content = std::fs::read_to_string(path)?;
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
    use std::fs;
    use tempfile::TempDir;

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
