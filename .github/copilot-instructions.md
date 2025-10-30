# PT Journal - AI Coding Assistant Instructions

## Project Overview
PT Journal is a GTK4 desktop application for structured penetration testing documentation. It provides a phased approach to pentesting with predefined methodologies, progress tracking, and evidence collection.

## Architecture
- **GUI Framework**: GTK4 with Relm4 components
- **Data Model**: Session → Phases → Steps → Evidence (hierarchical structure)
- **Persistence**: JSON serialization with cross-platform data directories
- **State Management**: Rc<RefCell<>> for shared mutable GTK state

## Key Components
- `model.rs`: Data structures and comprehensive pentesting methodology with detailed step-by-step instructions
- `ui.rs`: GTK interface with resizable/collapsible sidebar, drag-drop image support
- `store.rs`: JSON save/load functionality
- `main.rs`: Application bootstrap

## Development Workflow
```bash
# Build and run
cargo build
cargo run

# Code quality
cargo fmt          # Format code
cargo clippy       # Lint (fix with --fix)
cargo test         # Run tests (none currently)
```

## Code Patterns

### State Management
Use `Rc<RefCell<>>` for GTK widget state sharing:
```rust
let model = Rc::new(RefCell::new(app_model));
// Clone for closures
let model_clone = model.clone();
```

### GTK Widget Building
Prefer builder pattern for complex widgets:
```rust
let frame = Frame::builder()
    .label("Description")
    .child(&scroll)
    .build();
```

### Data Persistence
Sessions save to `~/.local/share/pt-journal/sessions/` on Linux:
```rust
let path = directories::ProjectDirs::from("com", "example", "pt-journal")
    .unwrap()
    .data_dir()
    .join("sessions/session.json");
```

### Image Handling
Text views support embedded images via paintables:
```rust
let texture = gdk::Texture::from_filename(&path)?;
buffer.insert_paintable(&mut iter, &texture);
```

## Pentesting Methodology
The app includes comprehensive pentesting phases with detailed step-by-step instructions:
1. **Reconnaissance** (16 steps): Detailed subdomain enumeration, DNS analysis, port scanning, service fingerprinting, web crawling, TLS assessment, infrastructure mapping, cloud asset discovery, email reconnaissance, screenshot capture, JavaScript analysis, parameter discovery, and public exposure scanning
2. **Vulnerability Analysis** (5 steps): Framework mapping to CVEs, parameter testing, authentication analysis, access control testing, and common vulnerability sweeps
3. **Exploitation** (4 steps): Safe exploit validation, credential testing, CVE exploitation, and web application exploitation
4. **Post-Exploitation** (4 steps): Privilege escalation, lateral movement, data access validation, and cleanup procedures
5. **Reporting** (4 steps): Evidence consolidation, risk rating, remediation guidance, and executive summaries

Each step includes detailed objectives, step-by-step procedures, what to look for, common pitfalls, and documentation requirements - designed for both learning and professional pentesting workflows.

## File Structure Conventions
- Keep data models in `model.rs`
- UI logic in `ui.rs` (single file for now)
- Persistence utilities in `store.rs`
- Main application setup in `main.rs`

## GTK4 Integration Notes
- Requires system GTK4 libraries
- Uses `gtk4::gio` for file operations
- Sidebar uses `Paned` widget for smooth resizing with collapse/expand toggle
- Drag-drop uses `DropTarget` with type filtering
- Clipboard integration via `gdk::Display::clipboard()`
- Avoid complex Rc<RefCell<>> in GTK signal handlers to prevent reference cycles

## Error Handling
Use `anyhow::Result<>` for operations that can fail:
```rust
fn load_session(path: &Path) -> anyhow::Result<Session> {
    let content = fs::read_to_string(path)?;
    let session: serde_json::from_str(&content)?;
    Ok(session)
}
```

## GTK4 Widget Lifecycle
- GTK widgets are reference-counted; parent widgets own their children
- Avoid complex state tracking in signal handlers to prevent reference cycles
- Keep signal handler closures simple and focused on UI updates

## Dependencies
- `gtk4` + `libadwaita`: UI framework
- `relm4`: Component framework (lightly used)
- `serde` + `serde_json`: Serialization
- `chrono`: Timestamps
- `uuid`: Entity IDs
- `directories`: Cross-platform paths