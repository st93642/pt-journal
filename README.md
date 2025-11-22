# PT Journal

A GTK4 desktop application for structured penetration testing documentation and learning. PT Journal provides organized methodologies, evidence collection, and quiz-based assessment tools to help security professionals document engagements and prepare for security certifications.

## Features

### 📋 Structured Penetration Testing Phases

- **Reconnaissance** (16 steps) - Information gathering, subdomain enumeration, service fingerprinting
- **Vulnerability Analysis** (5 steps) - CVE mapping, parameter testing, authentication/authorization testing
- **Exploitation** (4 steps) - PoC validation, credential and CVE exploitation
- **Post-Exploitation** (4 steps) - Privilege escalation, lateral movement, remediation
- **Reporting** (4 steps) - Evidence consolidation, risk rating, executive summary
- **Bug Bounty Hunting** - Additional specialized steps for bug bounty workflows
- **Exam Preparation** - CompTIA Security+, PenTest+, CEH methodologies

### 🖼️ Evidence Collection

- Drag-and-drop image support with positioning on a canvas
- Automatic image preservation with relative path storage
- Clipboard image paste support
- Multiple file format support (PNG, JPG, GIF, BMP, TIFF, WebP)

### 📝 Documentation System

- Per-step notes and descriptions with user editable fields
- Phase-level and global engagement notes
- Step status tracking (Todo, In Progress, Done, Skipped)
- Hierarchical Session → Phase → Step → Evidence structure

### ✅ Quiz & Assessment System

- CompTIA Security+ practice questions with domain categorization
- CEH methodology assessment questions
- Progress tracking with first-attempt scoring
- Detailed explanations for each question
- Statistics dashboard showing performance metrics

### 💾 Cross-Platform Persistence

- JSON-based session storage with automatic formatting
- Cross-platform directory handling (Linux, macOS, Windows)
- Session export and import functionality
- Automatic migration for backward compatibility

### 🎨 User Interface

- Clean, dark-themed GTK4 interface
- Resizable paned layout (sidebar + description + notes + canvas)
- Phase selector dropdown with step list navigation
- Integrated quiz viewer with MCQ rendering and statistics

### 🛠️ Security Tool Instructions & Integration

- Comprehensive instruction catalog for 80+ pentesting tools organized by category
- Specialized coverage for Burp Suite (Community/Pro), OWASP ZAP, Metasploit Framework
- Collaboration platform guides (Dradis, Faraday) for team reporting workflows
- Social engineering campaign playbooks (Social Engineer Toolkit)
- Rich documentation including installation guides, step sequences, workflow guides, and output interpretation
- Tool execution panel with VTE terminal for running security tools directly
- Data-driven instruction system (JSON-based) for easy content updates without code changes

## System Requirements

### Linux (Ubuntu/Debian)

```bash
sudo apt install libgtk-4-dev libadwaita-1-dev
```

### macOS

```bash
brew install gtk4 libadwaita
```

### Windows

GTK4 development libraries (included via MSYS2 or precompiled packages)

### General Requirements

- Rust 1.70+ (for 2021 edition)
- Cargo package manager

## Installation

### Clone the Repository

```bash
git clone https://github.com/st93642/pt-journal.git
cd pt-journal
```

### Build from Source

#### Debug Build (Development)

```bash
cargo build
```

#### Release Build (Optimized)

```bash
cargo build --release
```

## Running the Application

### From Debug Build

```bash
cargo run
```

### From Release Build

```bash
cargo run --release
```

### Direct Execution

After building, run the binary directly:

```bash
# Debug
./target/debug/pt-journal

# Release
./target/release/pt-journal
```

## Development

### Code Quality & Formatting

```bash
# Format code with rustfmt
cargo fmt

# Lint and check for common mistakes
cargo clippy

# Auto-fix clippy warnings
cargo clippy --fix
```

### Running Tests

```bash
# Run all unit tests
cargo test --lib

# Run integration tests with progress bar
cargo test --test integration_tests

# Run with output display
cargo test --lib -- --nocapture

# Run specific test module
cargo test model_tests::

# Run all tests
cargo test
```

### Project Structure

```text
pt-journal/
├── src/
│   ├── main.rs                      # Application entry point
│   ├── lib.rs                       # Library root with test suite
│   ├── model.rs                     # Core data models (Session, Phase, Step, etc.)
│   ├── store.rs                     # JSON persistence layer
│   ├── dispatcher.rs                # Event dispatcher for module communication
│   ├── quiz/
│   │   └── mod.rs                   # Quiz question parsing
│   ├── tutorials/
│   │   ├── mod.rs                   # Tutorial phase loading
│   │   ├── reconnaissance.rs
│   │   ├── vulnerability_analysis.rs
│   │   ├── exploitation.rs
│   │   ├── post_exploitation.rs
│   │   ├── reporting.rs
│   │   ├── bug_bounty_hunting.rs
│   │   ├── comptia_secplus.rs
│   │   ├── pentest_exam.rs
│   │   └── ceh.rs
│   └── ui/
│       ├── main.rs                  # Main UI assembly
│       ├── sidebar.rs               # Phase selector & step list
│       ├── detail_panel.rs          # Step details view
│       ├── quiz_widget.rs           # Quiz display component
│       ├── header_bar.rs            # Application toolbar
│       ├── canvas.rs                # Evidence canvas
│       ├── canvas_utils.rs          # Canvas utilities
│       ├── file_ops.rs              # File dialogs
│       └── image_utils.rs           # Image handling
├── tests/
│   ├── integration_tests.rs         # Integration test suite
│   ├── test_runner.rs               # Custom test harness
│   └── ui_tests.rs                  # UI-specific tests
├── data/
│   ├── comptia_secplus/             # CompTIA Security+ questions
│   ├── ceh/                         # CEH methodology questions
│   └── pentest/                     # PenTest+ questions
└── Cargo.toml
```

## Usage

### Creating a New Session

1. Launch PT Journal
2. Application starts with a default session
3. Use File → Save As to save the session with a custom name

### Adding Evidence

1. Select a step from the left panel
2. Drag and drop images onto the canvas area, or
3. Use Ctrl+V to paste images from clipboard
4. Click and drag images to reposition them on the canvas

### Tracking Progress

1. Check the "Completed" checkbox for each completed step
2. Status automatically updates and timestamps are recorded
3. Add notes to steps for documentation

### Taking Quizzes

1. Navigate to quiz phases (CompTIA Security+, CEH, etc.)
2. Select a quiz step to view questions
3. Select an answer and click "Check Answer"
4. View explanation with scoring feedback
5. Track performance in the statistics panel

### Saving and Loading Sessions

1. **Save**: File → Save (or Ctrl+S)
2. **Save As**: File → Save As (to create new session file)
3. **Open**: File → Open (to load existing session)

Sessions are stored in your system's Downloads folder by default:

- **Linux**: `~/Downloads/pt-journal-sessions/`
- **macOS**: `~/Downloads/pt-journal-sessions/`
- **Windows**: `%USERPROFILE%\Downloads\pt-journal-sessions\`

**Evidence images** are stored in an `evidence/` subfolder next to each session file:

```text
~/Downloads/pt-journal-sessions/
├── my-engagement.json
├── evidence/
│   ├── evidence_1730544000000.png
│   ├── evidence_1730544012345.png
│   └── ...
└── another-session.json
```

This ensures all evidence files travel together with the session when you move or backup the session file. If the Downloads folder is not accessible, sessions are stored in the current working directory as `./pt-journal-sessions/`

## Architecture & Key Patterns

### Dual Step Types

PT Journal supports two step types determined at creation:

- **Tutorial Steps**: Description-based with evidence collection
- **Quiz Steps**: Multiple-choice questions with progress tracking

```rust
// Tutorial step
Step::new_tutorial(id, "Title".to_string(), "Description".to_string(), vec!["tag".to_string()])

// Quiz step
Step::new_quiz(id, "Quiz Title".to_string(), vec![questions], "1.0 Domain")
```

### GTK State Management

State is managed using `Rc<RefCell<AppModel>>` pattern for GTK closure compatibility:

```rust
let model = Rc::new(RefCell::new(AppModel::default()));
let model_clone = model.clone();
button.connect_clicked(move |_| {
    model_clone.borrow_mut().selected_phase = 0;
});
```

### Modular UI Components

The application uses modularized UI components:

- `sidebar.rs` - Phase/step navigation
- `detail_panel.rs` - Content view (tutorial/quiz)
- `quiz_widget.rs` - Quiz UI with statistics
- `canvas.rs` - Evidence management

See `.github/copilot-instructions.md` for detailed architectural documentation and critical patterns.

## Data Format

### Session Storage (JSON)

Sessions are stored in human-readable JSON format:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "ACME Corp Engagement",
  "created_at": "2025-11-02T10:30:00Z",
  "notes_global": "Client engagement notes...",
  "phases": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "name": "Reconnaissance",
      "notes": "Phase-specific notes...",
      "steps": [
        {
          "id": "550e8400-e29b-41d4-a716-446655440002",
          "title": "Subdomain Enumeration",
          "description": "OBJECTIVE: ...\nSTEP-BY-STEP PROCESS: ...",
          "tags": ["recon"],
          "status": "Done",
          "completed_at": "2025-11-02T12:00:00Z",
          "notes": "Step-specific notes...",
          "evidence": [
            {
              "id": "550e8400-e29b-41d4-a716-446655440003",
              "path": "evidence/screenshot.png",
              "kind": "screenshot",
              "x": 100.0,
              "y": 50.0,
              "created_at": "2025-11-02T11:45:00Z"
            }
          ]
        }
      ]
    }
  ]
}
```

### Quiz Question Format (Pipe-Delimited)

Quiz questions are stored in a compact pipe-delimited format:

```text
question text|option A|option B|option C|option D|correct_index|explanation|domain|subdomain
```

Example:

```text
What is the CIA triad?|Confidentiality, Integrity, Availability|Cryptography, Identity, Access|Ciphers, Integrity, Authentication|Control, Intelligence, Analysis|0|The CIA triad stands for Confidentiality, Integrity, and Availability - the three core principles of information security.|1.0 General Security Concepts|1.1 Security Controls
```

## Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| gtk4 | 0.8+ | GUI framework |
| libadwaita | 0.6+ | GNOME Adwaita styling |
| serde | 1.0+ | Serialization |
| serde_json | 1.0+ | JSON format |
| uuid | 1.0+ | Unique identifiers |
| chrono | 0.4+ | Date/time handling |
| directories | 5.0+ | Cross-platform paths |
| anyhow | 1.0+ | Error handling |

See `Cargo.toml` for complete dependency list.

## Troubleshooting

### Build Issues

#### GTK4 libraries not found

```bash
# Ubuntu/Debian
sudo apt install libgtk-4-dev libadwaita-1-dev

# macOS
brew install gtk4 libadwaita

# Fedora
sudo dnf install gtk4-devel libadwaita-devel
```

#### Cargo build fails with linking errors

- Ensure GTK4 development libraries are installed
- On Linux, you may need to set `PKG_CONFIG_PATH`:

```bash
export PKG_CONFIG_PATH=/usr/lib/pkgconfig
```

### Runtime Issues

#### Application won't start

- Check that GTK4 runtime libraries are installed
- Verify the application has appropriate permissions

#### Evidence images not displaying

- Ensure image files are in supported formats (PNG, JPG, GIF, BMP, TIFF, WebP)
- Check that image dimensions are valid (non-zero width/height)
- Verify file paths are correct in the session JSON

#### Session file won't load

- Ensure JSON is valid (use `jq` or online validators)
- Check file permissions in the sessions directory
- Try loading with a backup copy if corruption is suspected

## License

This project is provided as-is for educational and professional use in penetration testing and security research.

## Support & Documentation

- **Architecture Guide**: See `.github/copilot-instructions.md` for detailed architecture documentation and critical patterns used in the codebase
- **Test Suite**: Run `cargo test --lib` to see all available tests
- **Data Models**: Review `src/model.rs` for complete data structure documentation

**PT Journal v0.1.0** - Structured Penetration Testing Documentation
