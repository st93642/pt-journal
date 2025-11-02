# PT Journal - AI Coding Assistant Instructions

## Project Overview
PT Journal is a GTK4 desktop application for structured penetration testing documentation with two primary content systems:
- **Tutorial System**: 9 phases (45+ steps) covering Recon, Vulnerability Analysis, Exploitation, Post-Exploitation, Reporting, Bug Bounty Hunting, CompTIA Security+, PenTest+, and CEH methodologies
- **Quiz System**: Multiple-choice assessments (CompTIA Security+, CEH) with progress tracking and scoring

## Architecture at a Glance
- **GUI Framework**: GTK4 (raw, not Relm4-driven) with modular UI components in `src/ui/`
- **Data Model**: Hierarchical `Session → Phases → Steps → Evidence/Quiz` in `model.rs`
- **Dual Step Types**: `Step::Tutorial` (description-based) and `Step::Quiz` (MCQ-based) — determined by `StepContent` enum
- **Persistence**: JSON via `store.rs` + cross-platform directories
- **Event System**: `dispatcher.rs` for decoupled module communication (already integrated, rarely used in current code)

## Key Files & Components
```
src/
├── main.rs              # GTK4 app bootstrap + Settings::set_gtk_application_prefer_dark_theme()
├── model.rs             # Core: Session, Phase, Step (Tutorial/Quiz), Evidence, StepStatus, Quiz*
├── store.rs             # JSON persistence
├── dispatcher.rs        # Event dispatcher (available but not heavily used currently)
├── quiz/
│   └── mod.rs           # Quiz parsing: parse_question_line() — reads question|a|b|c|d|correct_idx|explanation|domain|subdomain format
├── tutorials/
│   ├── mod.rs           # load_tutorial_phases() creates 9 Phase objects from tutorial modules
│   ├── reconnaissance.rs    # 16 steps
│   ├── vulnerability_analysis.rs  # 5 steps
│   ├── exploitation.rs     # 4 steps
│   ├── post_exploitation.rs # 4 steps
│   ├── reporting.rs        # 4 steps
│   ├── bug_bounty_hunting.rs, comptia_secplus.rs, ceh.rs, pentest_exam.rs
└── ui/
    ├── main.rs          # Main app (1293 lines): window setup, signal wiring, quiz button handlers
    ├── sidebar.rs       # Phase DropDown + steps ListBox (modularized)
    ├── detail_panel.rs  # DetailPanel struct: tutorial/quiz Stack, description, notes, canvas, QuizWidget
    ├── quiz_widget.rs   # QuizWidget: question display, MCQ rendering, check/explanation buttons, statistics
    ├── header_bar.rs    # Open/Save/Save As/Sidebar buttons
    ├── canvas.rs        # load_step_evidence(), setup_canvas() — drag-drop, image paste
    ├── canvas_utils.rs  # CanvasItem struct, texture validation (PNG|JPG|etc)
    ├── file_ops.rs      # Async file dialogs with callbacks
    ├── image_utils.rs   # Clipboard image handling
    └── mod.rs           # Exports

tests/
├── integration_tests.rs  # Custom test harness (no .harness = false needed)
└── ui_tests.rs           # UI-specific tests
```

## Development Workflow
```bash
# Build and run
cargo build          # Debug build (requires: libgtk-4-dev on Linux/Ubuntu)
cargo run            # Run with debug symbols
cargo build --release  # Optimized build (faster startup)
cargo run --release

# Code quality
cargo fmt            # Format with rustfmt
cargo clippy         # Lint (check before commits)
cargo clippy --fix   # Auto-fix warnings

# Testing
cargo test --lib     # All unit tests (fast, compact output)
cargo test --test integration_tests  # Integration tests with progress bar
```

## Critical Code Patterns

### 1. Step Type Handling - Tutorial vs Quiz
**Pattern**: Steps are either Tutorial (description-based) or Quiz (MCQ-based), determined at creation time:
```rust
// Tutorial step (in src/tutorials/mod.rs)
Step::new_tutorial(Uuid::new_v4(), "Title".to_string(), "Description...".to_string(), vec!["tag".to_string()])

// Quiz step (for CompTIA Security+, CEH)
Step::new_quiz(Uuid::new_v4(), "Quiz Title".to_string(), vec![quiz_questions], "1.0 General Security")

// Use pattern matching to handle both types (src/ui/main.rs)
if let Some(quiz_step) = step.get_quiz_step() {
    // Handle quiz display + button wiring
    panel.quiz_widget.display_question(&quiz_step, 0);
} else {
    // Handle tutorial display
    detail_panel.desc_view.buffer().set_text(&step.get_description());
}
```

**Key Methods**:
- `step.get_description()` / `step.get_notes()` / `step.get_evidence()` — works for Tutorial steps
- `step.get_quiz_step()` / `step.quiz_mut_safe()` — works for Quiz steps
- `step.get_content()` — returns `&StepContent` enum for pattern matching

### 2. GTK State Management (The "Clone Dance")
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

### 3. Signal Handler Blocking (Prevent Recursive Loops)
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
**Example**: `src/ui/main.rs` blocks `phase_combo` handler during session load to avoid recursive phase rebuilding.

### 4. Deferred UI Updates with `glib::idle_add_local_once`
When loading data that requires extensive UI rebuilding, defer to idle callback:
```rust
glib::idle_add_local_once(move || {
    // Rebuild entire phase list, steps list, etc.
    // Avoids borrowing conflicts during file load
});
```
**Why**: GTK file dialogs and other async operations can have active borrows. Deferring to idle ensures clean state.

### 5. Canvas Evidence System
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
3. Register dispatcher handlers for responding to relevant messages (optional, not widely used yet)
4. Test for borrow conflicts by rapidly clicking/interacting
5. Use `signal_handler_block` if programmatic updates trigger handlers
6. For modular components, follow pattern in `sidebar.rs`, `detail_panel.rs`, `header_bar.rs`

### Modifying Data Model
1. Update structs in `src/model.rs`
2. For backwards compatibility with saved sessions, add  `# ``[serde(default)]` for new optional fields
3. Add corresponding test cases in `lib.rs`
4. Update tests in `tests/` to cover new fields
5. Test save/load with old session files to ensure migration works

### Adding Quiz Content
1. Create question data in `data/` folder (e.g., `data/comptia_secplus/` for Security+)
2. Use format: `question|a|b|c|d|correct_idx|explanation|domain|subdomain` (pipe-separated)
3. Parse via `crate::quiz::parse_question_line()` in tutorial module
4. Create `Step::new_quiz()` in appropriate phase creation function (`src/tutorials/*/rs`)
5. Verify questions load by running app and selecting quiz step

## New Modular Architecture (Latest Changes)

### Event-Driven Dispatcher System
**Location**: `src/dispatcher.rs`
- Enum-based message passing for decoupled communication
- Supports multiple handlers per message type
- Thread-safe design using `Rc<RefCell<>>`
- **Tests**: 7 unit tests covering registration, dispatch, and lifecycle

### Modularized UI Components
**Location**: `src/ui/`
- `main.rs` (1293 lines): Window setup, signal wiring for both tutorial and quiz modes
- `sidebar.rs`: Phase selector (DropDown) + steps list (ListBox) widget
- `detail_panel.rs`: DetailPanel struct with both tutorial view (description/notes/canvas) and quiz view (QuizWidget)
- `quiz_widget.rs`: Full quiz UI including question display, MCQ rendering, check/view buttons, score display
- `header_bar.rs`: App toolbar (Open/Save/Sidebar buttons)
- `canvas.rs`: Drag-drop, image paste, evidence loading for tutorial steps
- `file_ops.rs`: Async file dialogs with callbacks (no blocking)

### Custom Test Harness
**Location**: `tests/test_runner.rs`
- Progress bar visualization: `[========>    ] 5/10`
- Compact output - only shows failures in detail
- Timing information for performance tracking
- Integration with custom test binary

**Usage**:
```bash
cargo test --test integration_tests  # Run with progress bar
cargo test --lib                      # Run 91 unit tests (standard output)
```

### Testing Philosophy
- **Unit tests**: In-module tests for isolated components
- **Integration tests**: In `tests/` directory for cross-module workflows
- **Custom harness**: Only failures show details, successes show progress bar


## Questions for Clarification?
- Should evidence paths be fully absolute or relative to session directory?
- Are there plans for multi-window support or is single-window sufficient?
- Should the app auto-save periodically or rely on manual save only?
- Is there a preferred maximum session file size before warnings?