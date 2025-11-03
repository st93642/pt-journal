# Session Folder Structure - Implementation Summary

## Overview
Migrated from flat file structure to organized session folders that contain all related evidence and data in one location.

## New File Structure

### Before (Old Format)
```
/path/to/
  ├── session.json              # Session data
  └── evidence/                 # Evidence files (separate)
      ├── tool_outputs.txt
      └── screenshots.png
```

### After (New Format)
```
/path/to/session-name/          # Session folder
  ├── session.json              # Session data
  └── evidence/                 # All evidence in session folder
      ├── nmap_target_timestamp_0.txt
      ├── gobuster_target_timestamp_0.txt
      └── screenshot_timestamp.png
```

## Implementation Details

### 1. File Operations (`src/ui/file_ops.rs`)
**Save Dialog Changes:**
- Dialog title: "Save Session As - Choose Folder Name"
- User enters folder name (not filename)
- Automatically removes .json extension if user adds it
- Sanitizes special characters in folder name
- Creates session-name/session.json structure
- Returns path to session.json for internal use

**Open Dialog Changes:**
- Title: "Open Session - Select session.json"
- File filter: Only shows session.json files
- Filter pattern: "session.json"
- Automatically navigates into session folders

### 2. Storage Layer (`src/store.rs`)
**`save_session()` Logic:**
- Detects if path is session.json or folder
- Creates session folder structure:
  - `session_dir/session.json`
  - `session_dir/evidence/` (for all evidence)
- Handles both old and new path formats
- Backward compatible with single-file sessions

**Code Pattern:**
```rust
let session_dir = if path.file_name() == Some("session.json") {
    // New format: use parent of session.json
    path.parent().unwrap_or(path)
} else if path.extension().is_some() {
    // Old format: .json file
    path.parent().unwrap_or(Path::new("."))
} else {
    // Already a folder
    path
};
```

### 3. Evidence Path Helpers

**`get_evidence_dir()` in `src/ui/handlers.rs`:**
- Returns evidence directory for tool outputs
- Detects session.json and uses parent folder
- Falls back to ./evidence if no session

**`get_session_images_dir()` in `src/ui/image_utils.rs`:**
- Returns evidence directory for screenshots/images
- Same logic as get_evidence_dir()
- Consistent path resolution across codebase

**Shared Logic:**
```rust
let session_dir = if path.file_name() == Some(OsStr::new("session.json")) {
    path.parent().unwrap_or(path)  // New format
} else {
    path.parent().unwrap_or(Path::new("."))  // Old format
};
let evidence_dir = session_dir.join("evidence");
```

## User Experience Changes

### Creating New Session
1. User clicks "Save As"
2. Dialog shows: "Save Session As - Choose Folder Name"
3. Default name: sanitized session name (no .json)
4. User enters folder name: e.g., "client-engagement-2025"
5. System creates:
   ```
   client-engagement-2025/
     ├── session.json
     └── evidence/ (empty)
   ```

### Opening Existing Session
1. User clicks "Open"
2. Dialog shows: "Open Session - Select session.json"
3. File filter only shows session.json files
4. User navigates to session folder and selects session.json
5. System loads session and uses parent folder for evidence

### Saving Tool Outputs (Auto-save)
1. User runs Nmap/Gobuster/etc.
2. System checks if session exists
3. If no session: prompts for session name first
4. If session exists: saves output to:
   ```
   session-name/evidence/nmap_target_1234567890_0.txt
   ```
5. Creates Evidence object and attaches to current step

### Pasting Screenshots
1. User pastes image in canvas
2. System saves to: `session-name/evidence/screenshot_timestamp.png`
3. Evidence stored relative to session.json

## Backward Compatibility

### Opening Old Sessions
- Old format: `/path/to/session.json`
- System detects single-file format
- Evidence path resolves to: `/path/to/evidence/`
- Works without migration

### Migration Strategy (Future)
- Optional: Detect old format and prompt to convert
- Create folder, move session.json inside
- Move evidence/ into session folder
- Update session path in application state

## Testing Checklist

### New Session Workflow
- [x] Create new session → folder structure created
- [x] Save As dialog prompts for folder name
- [x] Session.json saved inside folder
- [x] Evidence/ subdirectory created
- [x] Tool execution saves to evidence/
- [x] Image paste saves to evidence/

### Existing Session Workflow
- [x] Open session.json from folder
- [x] Tool execution saves correctly
- [x] Image paste works
- [x] All evidence loaded from evidence/

### Edge Cases
- [x] No session: tool execution prompts for save
- [x] User adds .json extension: automatically removed
- [x] Special characters in name: sanitized
- [x] Evidence directory creation: recursive mkdir

## Files Modified

1. **src/store.rs** (lines 28-53)
   - Updated save_session() to create folder structure
   - Handles both old and new path formats

2. **src/ui/file_ops.rs** (lines 15-50, 80-110)
   - Updated save_session_as_dialog() for folder input
   - Updated open_session_dialog() with session.json filter
   - Dialog titles clarified

3. **src/ui/handlers.rs** (lines 13-32)
   - Updated get_evidence_dir() to detect session.json
   - Works with new folder structure

4. **src/ui/image_utils.rs** (lines 100-125)
   - Updated get_session_images_dir() to detect session.json
   - Consistent with handlers.rs logic

## Benefits

1. **Organization**: All session data in one folder
2. **Portability**: Move/backup entire session folder
3. **Clarity**: Folder name = engagement name
4. **Evidence**: All evidence consolidated in one place
5. **Compatibility**: Works with old session files

## Known Issues / Future Work

- [ ] Automatic migration prompt for old sessions
- [ ] Relative path handling for evidence in session.json
- [ ] Session folder archiving/compression feature
- [ ] Evidence cleanup on step deletion

## Commit Message
```
feat: Implement session folder structure for organized storage

- Save As now creates session-name/ folder with session.json inside
- Open dialog filters for session.json files only
- All evidence (tool outputs, screenshots) stored in session-name/evidence/
- Updated save_session() to create folder + subdirectory structure
- Updated get_evidence_dir() and get_session_images_dir() to detect session.json
- Backward compatible with old single-file sessions
- Dialog titles clarified for better UX

Files modified:
- src/store.rs: Folder creation logic
- src/ui/file_ops.rs: Folder-based dialogs
- src/ui/handlers.rs: Evidence path resolution
- src/ui/image_utils.rs: Image path resolution

Structure:
session-name/
  ├── session.json
  └── evidence/
      ├── tool_outputs.txt
      └── screenshots.png
```
