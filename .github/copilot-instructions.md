# PT Journal - AI Coding Assistant Instructions

## Project Overview
PT Journal is a GTK4 desktop application for structured penetration testing documentation. It provides a phased approach to pentesting with predefined methodologies, progress tracking, and evidence collection through a canvas-based evidence system.

## Architecture
- **GUI Framework**: GTK4 with minimal Relm4 usage (mostly raw GTK4)
- **Data Model**: `Session → Phases → Steps → Evidence` (hierarchical structure in `model.rs`)
- **Persistence**: JSON serialization via `store.rs` using cross-platform directories
- **State Management**: Event-driven architecture using `dispatcher.rs` with `Rc<RefCell<AppModel>>` for GTK state
- **Event System**: Message-based dispatcher for decoupled module communication
- **UI Structure**: Main UI (`src/ui/main.rs`) with modular state management (`ui/state.rs`)

## Key Files & Components
```
src/
├── main.rs           # GTK4 app bootstrap + dark theme setup
├── model.rs          # Core data structures (Session, Phase, Step, Evidence, StepStatus)
├── store.rs          # JSON persistence (save_session/load_session)
├── dispatcher.rs     # Event-driven message dispatcher for module communication
├── lib.rs            # Module exports
├── tutorials/        # Pentesting methodology content (16+5+4+4+4=33 steps)
│   ├── mod.rs        # Loads all phase templates with UUIDs
│   ├── reconnaissance.rs
│   ├── vulnerability_analysis.rs
│   ├── exploitation.rs
│   ├── post_exploitation.rs
│   └── reporting.rs
└── ui/
    ├── main.rs       # Main UI assembly (1233 lines)
    ├── state.rs      # State manager coordinating model updates and events
    ├── file_ops.rs   # File operations (open/save dialogs) with async callbacks
    ├── header_bar.rs # Header bar creation with Open/Save/Sidebar buttons
    ├── mod.rs        # Module exports
    ├── canvas.rs     # Canvas setup, drag-drop, image paste, evidence loading
    ├── canvas_utils.rs  # CanvasItem struct, texture creation, validation
    └── image_utils.rs   # Clipboard image handling, pixbuf operations

tests/
├── integration_tests.rs  # Main integration tests with custom harness
└── test_runner.rs        # Custom test runner with progress bar
```

## Development Workflow
```bash
# Build and run
cargo build          # Debug build
cargo run            # Run debug build
cargo build --release  # Optimized build (faster)
cargo run --release

# Code quality
cargo fmt            # Format code (always run before commits)
cargo clippy         # Lint and catch common mistakes
cargo clippy --fix   # Auto-fix clippy warnings

# Testing
cargo test --lib     # Run 91 unit tests (compact output)
cargo test --test integration_tests  # Run integration tests with progress bar
cargo test           # Run all tests (91 unit + 9 integration + 3 test runner = 104 total)
```

## Critical Code Patterns

### 1. Event-Driven Architecture (NEW)
**Pattern**: Use the dispatcher for decoupled communication between modules.
```rust
use crate::dispatcher::{create_dispatcher, AppMessage};

// Create shared dispatcher
let dispatcher = create_dispatcher();

// Register handlers
dispatcher.borrow_mut().register("ui:phase_list", Box::new(move |msg| {
    match msg {
        AppMessage::PhaseSelected(idx) => {
            // Update UI for selected phase
        }
        AppMessage::RefreshStepList(phase_idx) => {
            // Rebuild step list
        }
        _ => {}
    }
}));

// Dispatch messages
dispatcher.borrow().dispatch(&AppMessage::PhaseSelected(0));
```

**Available Messages**:
- Selection: `PhaseSelected`, `StepSelected`
- Session Ops: `SessionLoaded`, `SessionSaved`, `SessionCreated`
- Status Changes: `StepCompleted`, `StepStatusChanged`
- Text Updates: `StepNotesUpdated`, `StepDescriptionNotesUpdated`, `PhaseNotesUpdated`
- Evidence: `EvidenceAdded`, `EvidenceRemoved`, `EvidenceMoved`
- UI Refresh: `RefreshPhaseList`, `RefreshStepList`, `RefreshDetailView`, `RefreshCanvas`

### 2. State Manager Pattern (NEW)
**Pattern**: Use `StateManager` for coordinated state updates.
```rust
use crate::ui::state::{StateManager, SharedModel};

let model = Rc::new(RefCell::new(AppModel::default()));
let state = StateManager::new(model.clone(), dispatcher.clone());

// State updates automatically dispatch events
state.select_phase(1);  // Dispatches PhaseSelected + RefreshStepList
state.update_step_notes(0, 0, "Notes".to_string());  // Dispatches StepNotesUpdated
state.add_evidence(0, 0, evidence);  // Dispatches EvidenceAdded
```

**Benefits**:
- Automatic event dispatching
- Consistent state updates
- Single source of truth
- Decoupled UI modules

### 3. GTK State Management (The "Clone Dance")
**Pattern**: Clone `Rc<RefCell<>>` before moving into closures to avoid borrow checker issues.
```rust
let model = Rc::new(RefCell::new(AppModel::default()));

// For signal handlers, clone all needed refs BEFORE the closure
let model_clone = model.clone();
let widget_clone = some_widget.clone();
button.connect_clicked(move |_| {
    model_clone.borrow_mut().selected_phase = 1; // Mutable access
    widget_clone.set_text(&model_clone.borrow().session.name); // Immutable access
});
```

**Critical Rule**: Never hold a `borrow()` or `borrow_mut()` across GTK widget method calls that might trigger other signals, or you'll get `RefCell` panics.

### 4. Signal Handler Blocking (Prevent Recursive Loops)
When programmatically changing widget state that triggers signals, block handlers:
```rust
// Get handler ID when connecting (wrap in Rc for sharing across closures)
let handler_id = widget.connect_signal(|w| { /* ... */ });
let handler_id = Rc::new(handler_id);

// Later, block before programmatic changes
glib::signal::signal_handler_block(&widget, &handler_id);
widget.set_value(new_value); // Won't trigger handler
glib::signal::signal_handler_unblock(&widget, &handler_id);
```
**Example**: `src/ui/main.rs:556-566` blocks `phase_combo` handler during session load to avoid recursive phase rebuilding.

### 3. Deferred UI Updates with `glib::idle_add_local_once`
When loading data that requires extensive UI rebuilding, defer to idle callback:
```rust
glib::idle_add_local_once(move || {
    // Rebuild entire phase list, steps list, etc.
    // Avoids borrowing conflicts during file load
});
```
**Why**: GTK file dialogs and other async operations can have active borrows. Deferring to idle ensures clean state.

### 4. Canvas Evidence System
**Architecture**: Evidence items are `Fixed` container children positioned at `(x, y)` coordinates.
```rust
// Load evidence from model
pub fn load_step_evidence(fixed: &Fixed, canvas_items: Rc<RefCell<Vec<CanvasItem>>>, step: &Step) {
    canvas_items.borrow_mut().clear();
    while let Some(child) = fixed.first_child() { fixed.remove(&child); }
    
    for evidence in &step.evidence {
        let texture = create_texture_from_file(&evidence.path)?;
        let picture = Picture::for_paintable(&texture);
        fixed.put(&picture, evidence.x, evidence.y); // Position at stored coords
        canvas_items.borrow_mut().push(CanvasItem { texture, x: evidence.x, y: evidence.y, /* ... */ });
    }
}
```

**Drag-drop handling** (`src/ui/canvas.rs`):
- `DropTarget` accepts `glib::Type::INVALID` to catch file URIs
- Validates image extensions: `png|jpg|jpeg|gif|bmp|tiff|webp`
- Copies dropped files to session-specific directory (avoids external file dependencies)

### 5. Paned Widget Resizing
Three nested `Paned` widgets create resizable 4-panel layout:
```rust
// main_paned: separates left sidebar from right content
let main_paned = Paned::new(Orientation::Horizontal);
main_paned.set_start_child(Some(&left_panel)); // Phases + steps list
main_paned.set_end_child(Some(&right_content));
main_paned.set_position(300); // Initial sidebar width

// Within right_content, nested vertical panes split description/notes/canvas
```
**Key properties**: `set_resize_start_child(true)`, `set_shrink_start_child(false)` to prevent collapsing.

### 6. File Operations Module (NEW)
**Location**: `src/ui/file_ops.rs`
- Async file dialogs with callbacks
- `open_session_dialog(window, on_loaded)` - Opens FileDialog and calls callback with loaded session
- `save_session_as_dialog(window, session, on_saved)` - Shows Save As dialog
- `save_session(window, model, on_saved)` - Saves to current path or shows Save As dialog
- Error handling with console logging (MessageDialog deprecated in GTK4.10+)

**Pattern**: Callback-based async operations to avoid blocking UI
```rust
use crate::ui::file_ops;

// Open session
file_ops::open_session_dialog(&window, move |session, path| {
    // Session loaded, update model
    model.borrow_mut().session = session;
    model.borrow_mut().current_path = Some(path);
    // Rebuild UI...
});

// Save session
file_ops::save_session(&window, model.clone(), move |path| {
    println!("Saved to: {:?}", path);
});
```

## Data Flow & Persistence

### Session Save/Load Pattern
```rust
// Save (src/store.rs)
pub fn save_session(path: &Path, session: &Session) -> Result<()> {
    let json = serde_json::to_string_pretty(session)?;
    fs::create_dir_all(path.parent().unwrap())?; // Create parent dirs
    fs::write(path, json)?;
    Ok(())
}

// Load
pub fn load_session(path: &Path) -> Result<Session> {
    let content = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}
```

**Storage location**: `directories::ProjectDirs::from("com", "example", "pt-journal")` resolves to:
- Linux: `~/.local/share/pt-journal/sessions/`
- macOS: `~/Library/Application Support/com.example.pt-journal/sessions/`
- Windows: `%APPDATA%\example\pt-journal\sessions\`

**Session structure** (JSON):
```json
{
  "id": "uuid-v4",
  "name": "Client Engagement Name",
  "created_at": "2025-11-01T12:00:00Z",
  "notes_global": "Overall engagement notes",
  "phases": [
    {
      "id": "uuid-v4",
      "name": "Reconnaissance",
      "notes": "Phase-level notes",
      "steps": [
        {
          "id": "uuid-v4",
          "title": "Subdomain Enumeration",
          "description": "OBJECTIVE: ...\nSTEP-BY-STEP PROCESS: ...",
          "tags": ["recon"],
          "status": "Done",
          "completed_at": "2025-11-01T14:30:00Z",
          "notes": "User notes for this step",
          "description_notes": "User notes shown in description pane",
          "evidence": [
            {"id": "uuid-v4", "path": "/path/to/screenshot.png", "kind": "screenshot", "x": 100.0, "y": 50.0, "created_at": "..."}
          ]
        }
      ]
    }
  ]
}
```

## UI Component Patterns

### Building List Items (Phases/Steps)
```rust
let list = ListBox::new();
for (idx, item) in items.iter().enumerate() {
    let row = ListBoxRow::new();
    let row_box = GtkBox::new(Orientation::Horizontal, 8);
    
    let checkbox = CheckButton::new();
    let label = Label::new(Some(&item.title));
    
    // Make label clickable for selection
    let click = gtk4::GestureClick::new();
    let model_clone = model.clone();
    click.connect_pressed(move |_, _, _, _| {
        model_clone.borrow_mut().selected_item = Some(idx);
        // Update detail views...
    });
    label.add_controller(click);
    
    row_box.append(&checkbox);
    row_box.append(&label);
    row.set_child(Some(&row_box));
    list.append(&row);
}
```

### TextView Buffer Updates (Prevent Borrow Conflicts)
```rust
// WRONG: Holding borrow during widget access
let text = model.borrow().session.notes; // Borrow still active!
textview.buffer().set_text(&text);       // May panic if signal triggers another borrow

// RIGHT: Release borrow before GTK calls
let text = {
    let borrow = model.borrow();
    borrow.session.notes.clone() // Clone data, drop borrow
};
textview.buffer().set_text(&text); // Safe
```

### Error Handling
- Use `anyhow::Result<T>` for functions that can fail
- Use `eprintln!()` for warnings (e.g., failed evidence loading in `canvas.rs:32`)
- No user-facing error dialogs yet—errors are logged to console

## Pentesting Methodology Content
Tutorial phases (`src/tutorials/`) define structured methodology:
1. **Reconnaissance** (16 steps): Subdomain enumeration, DNS records, Nmap scanning, service fingerprinting, web tech identification, TLS/SSL assessment, WHOIS, cloud infrastructure, email harvesting, screenshot capture, JavaScript analysis, parameter discovery, API discovery, GitHub reconnaissance, public exposure scanning, network mapping
2. **Vulnerability Analysis** (5 steps): Technology to CVE mapping, parameter testing, authentication weaknesses, authorization flaws, common vulnerability scanning
3. **Exploitation** (4 steps): PoC validation, credential exploitation, CVE exploitation, web app exploitation
4. **Post-Exploitation** (4 steps): Privilege escalation, lateral movement, data access, cleanup/remediation
5. **Reporting** (4 steps): Evidence consolidation, risk rating, remediation recommendations, executive summary

Each step description includes:
- **OBJECTIVE**: What you're trying to achieve
- **STEP-BY-STEP PROCESS**: Detailed commands/tools/procedures
- **WHAT TO LOOK FOR**: Expected findings and red flags
- **COMMON PITFALLS**: Mistakes to avoid
- **DOCUMENTATION REQUIREMENTS**: What to capture as evidence

**Why this matters**: When modifying tutorial content, maintain this structure. Tests validate that all steps have these sections (`lib.rs:197-209`).

## Testing Strategy
Comprehensive test suite in `src/lib.rs` (300+ lines):
- **Model tests**: Default session creation, phase/step structure, UUID uniqueness
- **Store tests**: Save/load roundtrips, Unicode handling, invalid JSON, file permissions
- **Integration tests**: Full workflow simulation (load → modify → save → reload)
- **Property tests**: Uses `proptest` for fuzz testing text preservation
- **Performance tests**: Session creation < 100ms, serialization < 50ms

**Running specific tests**:
```bash
cargo test model_tests::        # Just model tests
cargo test store_tests::        # Just persistence tests
cargo test --lib -- --nocapture # Show println! output
```

## Common Pitfalls & Solutions

### 1. `RefCell` Borrow Panics
**Symptom**: `already borrowed: BorrowMutError` at runtime.
**Cause**: Holding a borrow across GTK widget calls that trigger signals.
**Fix**: Clone data out of `RefCell` before GTK calls, or use separate borrows.

### 2. Signal Handler Loops
**Symptom**: Infinite recursion or stack overflow when changing widget values.
**Cause**: Signal handler modifies the widget that triggered it.
**Fix**: Use `signal_handler_block`/`unblock` around programmatic changes.

### 3. Canvas Items Not Appearing
**Symptom**: Images drop successfully but don't show on canvas.
**Cause**: Often invalid dimensions (`width == 0`) or missing `fixed.show_all()` equivalent in GTK4.
**Fix**: Validate texture dimensions before adding (`canvas_utils.rs:49-55`), ensure `Picture` widget has proper size request.

### 4. Lost Evidence After Reload
**Symptom**: Evidence shows in session file but not on canvas.
**Cause**: Evidence paths may be absolute or relative; file moved/deleted.
**Fix**: Copy dropped images to session-specific directory (`save_pasted_image` in `image_utils.rs`) and store relative paths.

## Dependencies & External Requirements
```toml
[dependencies]
gtk4 = "0.8"              # Requires system GTK4 libraries (libgtk-4-dev on Debian/Ubuntu)
libadwaita = "0.6"        # GNOME Adwaita styling
relm4 = "0.8"             # Minimal usage (just for component traits)
serde = "1"               # Serialization
serde_json = "1"          # JSON format
chrono = "0.4"            # DateTime handling
uuid = "1"                # Unique IDs for all entities
directories = "5"         # Cross-platform data directories
anyhow = "1"              # Error handling
thiserror = "1"           # Error derives
pulldown-cmark = "0.10"   # Markdown parsing (future use?)
once_cell = "1"           # Lazy statics

[dev-dependencies]
tempfile = "3.8"          # Temp dirs for tests
assert_matches = "1.5"    # Pattern matching assertions
proptest = "1.0"          # Property-based testing
```

**System requirements**:
- GTK4 development libraries
- Linux: `sudo apt install libgtk-4-dev`
- macOS: `brew install gtk4`

## When Making Changes

### Adding a New Pentesting Step
1. Edit appropriate tutorial file (`src/tutorials/*.rs`)
2. Add tuple to `STEPS` array: `("Title", "OBJECTIVE: ...\nSTEP-BY-STEP PROCESS: ...")`
3. Update test expectations in `lib.rs` (step counts, section validation)
4. Run `cargo test` to verify structure

### Adding New UI Components
1. Define widget in `src/ui/main.rs` (or create new module in `ui/`)
2. Clone all needed `Rc<RefCell<>>` refs BEFORE closure
3. Use StateManager for state updates to automatically dispatch events
4. Register dispatcher handlers for responding to relevant messages
5. Test for borrow conflicts by rapidly clicking/interacting
6. Use `signal_handler_block` if programmatic updates trigger handlers

### Modifying Data Model
1. Update structs in `src/model.rs`
2. Add `#[serde(default)]` for new optional fields to maintain backward compatibility
3. Update StateManager methods if new operations are needed
4. Add corresponding AppMessage variants for new events
5. Update tests in `tests/` to cover new fields
6. Test save/load with old session files to ensure migration works

## New Modular Architecture (Latest Changes)

### Event-Driven Dispatcher System
**Location**: `src/dispatcher.rs`
- Enum-based message passing for decoupled communication
- Supports multiple handlers per message type
- Thread-safe design using `Rc<RefCell<>>`
- **Tests**: 7 unit tests covering registration, dispatch, and lifecycle

### State Manager
**Location**: `src/ui/state.rs`
- Centralized state mutations with automatic event dispatching
- Methods for phase/step selection, notes updates, evidence operations
- Coordinates model changes with UI event notifications
- **Tests**: 6 unit tests covering all state operations

### Custom Test Harness
**Location**: `tests/test_runner.rs`
- Progress bar visualization: `[========>    ] 5/10`
- Compact output - only shows failures in detail
- Timing information for performance tracking
- Integration with custom test binary (bypasses default harness)

**Usage**:
```bash
cargo test --test integration_tests  # Run with progress bar
cargo test --lib                      # Run 88 unit tests (standard output)
```

### Testing Philosophy
- **Unit tests**: In-module (`#[cfg(test)]`) for isolated components
- **Integration tests**: In `tests/` directory for cross-module workflows
- **Test count**: 88 unit tests + 9 custom integration tests
- **Custom harness**: Only failures show details, successes show progress bar

## Modularization Roadmap
Future refactoring plans to further reduce main.rs size:
1. Extract header bar creation → `ui/header_bar.rs`
2. Extract sidebar (phase/step lists) → `ui/sidebar.rs`
3. Extract detail panel (description/notes/canvas) → `ui/detail_panel.rs`
4. Extract file operations (open/save dialogs) → `ui/file_ops.rs`

Target: Keep modules under 250 lines each for maintainability.

## Questions for Clarification?
- Should evidence paths be fully absolute or relative to session directory?
- Are there plans for multi-window support or is single-window sufficient?
- Should the app auto-save periodically or rely on manual save only?
- Is there a preferred maximum session file size before warnings?