use crate::model::Session;
use anyhow::Result;
use directories::ProjectDirs;
use serde_json;
use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
pub fn default_sessions_dir() -> PathBuf {
    if let Some(dirs) = ProjectDirs::from("com", "example", "pt-journal") {
        let path = dirs.data_dir().join("sessions");
        let _ = fs::create_dir_all(&path);
        path
    } else {
        PathBuf::from("./sessions")
    }
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


