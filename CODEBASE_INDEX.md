# PT Journal - Codebase Index

## 📋 Project Overview

**PT Journal** is a GTK4/libadwaita desktop application for structured penetration testing documentation. It provides an organized methodology for security assessments, evidence collection, and quiz-based learning for security certifications.

- **Language**: Rust 2021 Edition
- **Version**: v0.1.0 (Foundation Complete)
- **Architecture**: 4-layer modular design
- **Lines of Code**: ~21,500 lines of Rust
- **Test Coverage**: 188 tests (100% pass rate)
- **Modules**: 41 Rust source files

## 🏗️ Architecture Overview

PT Journal follows a layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│                    UI Layer (GTK4)                      │
│  Main Window, Handlers, Panels, Widgets                │
│  - canvas.rs, detail_panel.rs, quiz_widget.rs          │
│  - tool_execution.rs, sidebar.rs, handlers.rs          │
└─────────────────────────────────────────────────────────┘
                         ↓  ↓
┌─────────────────────────────────────────────────────────┐
│              Application Logic Layer                     │
│  State Management, Event Dispatching                    │
│  - state.rs, dispatcher.rs, file_ops.rs                │
└─────────────────────────────────────────────────────────┘
                         ↓  ↓
┌─────────────────────────────────────────────────────────┐
│               Domain Model Layer                         │
│  Core Business Logic, Data Structures                   │
│  - model.rs (Session, Phase, Step, Evidence)           │
└─────────────────────────────────────────────────────────┘
                         ↓  ↓
┌─────────────────────────────────────────────────────────┐
│          Infrastructure Layer                            │
│  Storage, Tools, Content Management                     │
│  - store.rs, tools/, tutorials/, quiz/                 │
└─────────────────────────────────────────────────────────┘
```

## 📁 Directory Structure

```
pt-journal/
├── src/                        # Application source code (~21,500 lines)
│   ├── main.rs                 # Application entry point (37 lines)
│   ├── lib.rs                  # Library root with comprehensive test suite (1,060 lines)
│   ├── model.rs                # Core domain models (655 lines)
│   ├── store.rs                # JSON persistence layer (273 lines)
│   ├── dispatcher.rs           # Event dispatcher (235 lines)
│   ├── quiz/                   # Quiz system
│   │   └── mod.rs             # Question parsing (335 lines)
│   ├── tutorials/              # Tutorial content (12,018 lines)
│   │   ├── mod.rs             # Tutorial loader (186 lines)
│   │   ├── reconnaissance.rs   # 16-step reconnaissance (3,323 lines)
│   │   ├── vulnerability_analysis.rs  # 5-step vuln analysis (1,390 lines)
│   │   ├── exploitation.rs     # 4-step exploitation (993 lines)
│   │   ├── post_exploitation.rs # 4-step post-exploit (854 lines)
│   │   ├── reporting.rs        # 4-step reporting (972 lines)
│   │   ├── bug_bounty_hunting.rs # Bug bounty workflows (2,700 lines)
│   │   ├── comptia_secplus.rs  # Security+ content (496 lines)
│   │   ├── pentest_exam.rs     # PenTest+ content (455 lines)
│   │   └── ceh.rs              # CEH content (649 lines)
│   ├── tools/                  # Security tool integrations
│   │   ├── mod.rs             # Public API (46 lines)
│   │   ├── traits.rs          # Core trait definitions (334 lines)
│   │   ├── executor.rs        # Tool execution engine (309 lines)
│   │   ├── registry.rs        # Tool registry (295 lines)
│   │   └── integrations/      # Tool implementations
│   │       ├── mod.rs         # Integration exports (10 lines)
│   │       ├── nmap.rs        # Nmap integration (715 lines)
│   │       └── gobuster.rs    # Gobuster integration (704 lines)
│   └── ui/                     # GTK4 user interface
│       ├── mod.rs             # UI module exports (12 lines)
│       ├── main.rs            # Main window assembly (150 lines)
│       ├── state.rs           # Application state (491 lines)
│       ├── handlers.rs        # Signal handlers (1,062 lines)
│       ├── sidebar.rs         # Navigation sidebar (45 lines)
│       ├── detail_panel.rs    # Content view (201 lines)
│       ├── quiz_widget.rs     # Quiz UI (316 lines)
│       ├── canvas.rs          # Evidence canvas (619 lines)
│       ├── canvas_utils.rs    # Canvas utilities (81 lines)
│       ├── tool_execution.rs  # Tool UI (1,146 lines)
│       ├── header_bar.rs      # App toolbar (39 lines)
│       ├── image_utils.rs     # Image handling (173 lines)
│       └── file_ops.rs        # File dialogs (188 lines)
├── tests/                      # Integration tests
│   └── integration_tests.rs    # Full workflow tests
├── data/                       # Tutorial and quiz content
│   ├── comptia_secplus/       # Security+ questions (7 directories)
│   ├── ceh/                   # CEH methodology (26 directories)
│   ├── pentest/               # PenTest+ content (7 directories)
│   └── wordlists/             # Common wordlists for tools
├── docs/                       # Technical documentation
│   ├── MODULE_CONTRACTS.md    # API contracts (15.7KB)
│   ├── README.md              # Documentation index (10.2KB)
│   ├── PERFORMANCE_BENCHMARKS.md  # Performance metrics (10.2KB)
│   ├── SESSION_FOLDER_STRUCTURE.md # Storage layout (6.9KB)
│   └── TDD_COMPLETION_REPORT.md   # Quality report (9.5KB)
├── proptest-regressions/      # Property test regression data
├── .github/                   # GitHub configuration
│   └── copilot-instructions.md # AI agent instructions
├── Cargo.toml                 # Project manifest
├── Cargo.lock                 # Dependency lock file
├── README.md                  # Project overview (14.1KB)
└── .gitignore                 # Git ignore rules
```

## 🧩 Core Modules

### 1. Model Layer (`src/model.rs`) - 655 lines

**Purpose**: Core domain models for penetration testing sessions.

**Key Types**:

- `Session` - Top-level engagement container (id, name, created_at, notes_global, phases)
- `Phase` - Methodology stage (Reconnaissance, Exploitation, etc.)
- `Step` - Individual action or quiz (with StepContent enum)
- `StepContent` - Tutorial vs Quiz abstraction
- `Evidence` - File attachments (screenshots, tool outputs)
- `StepStatus` - Todo, InProgress, Done, Skipped
- `QuizStep` - Quiz container with questions and progress
- `QuizQuestion` - Single MCQ with 4 answers
- `QuestionProgress` - User's answer history

**Critical Patterns**:

- Uses `Uuid` for all IDs (global uniqueness)
- Uses `DateTime<Utc>` for all timestamps
- `StepContent` enum abstracts Tutorial vs Quiz steps
- Getters/setters enforce encapsulation
- Legacy fields skipped during serialization

**Factory Methods**:

- `Session::default()` - Creates session with 9 tutorial phases
- `Step::new_tutorial()` - Creates tutorial step
- `Step::new_quiz()` - Creates quiz step

### 2. Store Layer (`src/store.rs`) - 273 lines

**Purpose**: Session persistence with folder structure.

**Key Functions**:

- `save_session(path, session)` - Saves to JSON with evidence folder
- `load_session(path)` - Loads from session.json
- `default_sessions_dir()` - Returns ~/Downloads/pt-journal-sessions/

**Storage Structure**:

```
~/Downloads/pt-journal-sessions/
└── session-name/
    ├── session.json     # Full session data
    └── evidence/        # Tool outputs, screenshots
        ├── Nov021430_0.txt
        └── Nov021445_1.png
```

**Features**:

- Accepts folder path OR file path (auto-detects)
- Creates evidence/ subdirectory automatically
- Preserves timestamps and UUIDs exactly
- Handles Unicode (UTF-8) correctly
- Creates parent directories as needed
- Idempotent - overwriting is safe

### 3. Tools Layer (`src/tools/`) - 5 files, 2,413 lines

**Purpose**: Security tool integration and execution framework.

**Architecture**:

```
tools/
├── traits.rs       # Core SecurityTool trait (6 methods)
├── executor.rs     # Execution engine with timeout/env support
├── registry.rs     # Tool discovery and registration
├── mod.rs          # Public API exports
└── integrations/
    ├── nmap.rs     # Nmap: 8 scan types (TcpSyn, TcpConnect, Udp, etc.)
    └── gobuster.rs # Gobuster: 3 modes (Dir, Dns, Vhost)
```

**Core Trait** (`SecurityTool`):

```rust
pub trait SecurityTool: Send + Sync {
    fn name(&self) -> &str;
    fn check_availability(&self) -> Result<bool>;
    fn build_command(&self, config: &ToolConfig) -> Result<Command>;
    fn parse_output(&self, stdout: &str, stderr: &str) -> Result<serde_json::Value>;
    fn extract_evidence(&self, output: &serde_json::Value) -> Vec<Evidence>;
    fn validate_prerequisites(&self, config: &ToolConfig) -> Result<()>;
}
```

**Configuration Pattern**:

```rust
let config = ToolConfig::builder()
    .target("10.10.10.1")
    .argument("-p22,80,443")
    .timeout(Duration::from_secs(300))
    .build()?;
```

**Integrated Tools**:

1. **Nmap** - Network scanner (8 scan types)
2. **Gobuster** - Directory/DNS/vhost enumeration (3 modes)

### 4. UI Layer (`src/ui/`) - 14 files, 4,523 lines

**Purpose**: GTK4/libadwaita user interface.

**Component Architecture**:

- `main.rs` - Window assembly, 3-pane layout
- `state.rs` - AppModel (session, current_path, selected_phase/step)
- `handlers.rs` - Signal handlers (phase/step selection, tool execution)
- `sidebar.rs` - Phase dropdown + step list
- `detail_panel.rs` - Tutorial/quiz content switcher
- `quiz_widget.rs` - MCQ display + statistics
- `canvas.rs` - Evidence positioning with drag-drop
- `tool_execution.rs` - Nmap/Gobuster UI with terminal output
- `header_bar.rs` - Open/Save buttons
- `file_ops.rs` - File dialogs (async)
- `image_utils.rs` - Image loading/validation
- `canvas_utils.rs` - Canvas geometry helpers

**State Management Pattern**:

```rust
let model = Rc<RefCell<AppModel>>::default();
let model_clone = model.clone();
button.connect_clicked(move |_| {
    model_clone.borrow_mut().selected_phase = 0;
});
```

**Critical UI Patterns**:

- All widgets created once at startup
- Signal handlers modify `AppModel` state
- UI updates deferred to `glib::idle_add_local_once`
- GTK initialization guarded with `Once` in tests
- No blocking operations on main thread
- VTE terminal for tool output streaming

### 5. Dispatcher Layer (`src/dispatcher.rs`) - 235 lines

**Purpose**: Event-driven communication between modules.

**Message Types**:

- `SessionLoaded { session }`
- `StepCompleted { step_id }`
- `EvidenceAdded { evidence }`
- `ToolExecuted { result }`

**Usage Pattern**:

```rust
let mut dispatcher = Dispatcher::new();
dispatcher.register_handler("session_loaded", Box::new(|msg| {
    if let Message::SessionLoaded { session } = msg {
        // Update UI
    }
}));
dispatcher.dispatch(Message::SessionLoaded { session });
```

### 6. Tutorial Layer (`src/tutorials/`) - 10 files, 12,018 lines

**Purpose**: Pentesting methodology content.

**Phases** (loaded by `load_tutorial_phases()`):

1. **Reconnaissance** (16 steps) - reconnaissance.rs
2. **Vulnerability Analysis** (5 steps) - vulnerability_analysis.rs
3. **Exploitation** (4 steps) - exploitation.rs
4. **Post-Exploitation** (4 steps) - post_exploitation.rs
5. **Reporting** (4 steps) - reporting.rs
6. **Bug Bounty Hunting** (varies) - bug_bounty_hunting.rs
7. **CompTIA Security+** (23 quiz steps) - comptia_secplus.rs
8. **PenTest+** (quiz-based) - pentest_exam.rs
9. **CEH** (quiz-based) - ceh.rs

**Content Structure**:

```
OBJECTIVE: What you're trying to achieve
STEP-BY-STEP PROCESS: Commands and procedures
WHAT TO LOOK FOR: Expected findings
COMMON PITFALLS: Mistakes to avoid
DOCUMENTATION REQUIREMENTS: Evidence to capture
```

### 7. Quiz Layer (`src/quiz/mod.rs`) - 335 lines

**Purpose**: Quiz question parsing and validation.

**Format**: Pipe-delimited string (9 fields)

```
question|optionA|optionB|optionC|optionD|correct_idx|explanation|domain|subdomain
```

**Example**:

```
What is the CIA triad?|Confidentiality, Integrity, Availability|...|...|...|0|The CIA triad stands for...|1.0 General Security Concepts|1.1 Security Controls
```

**Function**: `parse_question_line(line: &str) -> Result<Question>`

## 🔧 Dependencies

### Runtime Dependencies (Cargo.toml)

| Dependency | Version | Purpose |
|------------|---------|---------|
| `gtk4` | 0.9 | GUI framework (v4_12 features) |
| `vte4` | 0.8 | Terminal emulator widget |
| `libadwaita` | 0.7 | GNOME Adwaita styling |
| `relm4` | 0.9 | Reactive GUI patterns |
| `serde` | 1.0 | Serialization framework |
| `serde_json` | 1.0 | JSON format |
| `serde_yaml` | 0.9 | YAML format |
| `uuid` | 1.0 | UUID generation (v4 + serde) |
| `chrono` | 0.4 | Date/time handling |
| `anyhow` | 1.0 | Error handling |
| `thiserror` | 1.0 | Custom error types |
| `directories` | 5.0 | Cross-platform paths |
| `pulldown-cmark` | 0.10 | Markdown parsing |
| `once_cell` | 1.0 | Lazy statics |
| `regex` | 1.0 | Pattern matching |
| `async-channel` | 2.0 | Async messaging |

### Development Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `tempfile` | 3.8 | Temporary test directories |
| `assert_matches` | 1.5 | Pattern matching assertions |
| `proptest` | 1.0 | Property-based testing |

## 🧪 Testing Infrastructure

### Test Organization

```
tests/
├── Unit tests (in src/lib.rs)
│   ├── model_tests - Domain model validation (20+ tests)
│   ├── store_tests - Persistence layer (15+ tests)
│   ├── quiz_tests - Question parsing (10+ tests)
│   ├── tool_tests - Tool integration (50+ tests)
│   ├── dispatcher_tests - Event system (8+ tests)
│   ├── tutorial_tests - Content validation (5+ tests)
│   └── integration_tests - End-to-end workflows (10+ tests)
├── Integration tests (tests/integration_tests.rs)
│   ├── Full session workflow
│   ├── Tool execution pipeline
│   └── UI interaction scenarios
└── Property tests (proptest)
    ├── Session name preservation
    ├── Notes preservation
    └── Unicode handling
```

### Test Coverage

- **Total Tests**: 188
- **Pass Rate**: 100%
- **Coverage Areas**:
  - Model layer: Session, Phase, Step, Evidence, Quiz
  - Store layer: Save, load, migration, folder structure
  - Tools layer: Nmap (8 scan types), Gobuster (3 modes)
  - Quiz layer: Question parsing, progress tracking
  - Dispatcher: Event routing and handling
  - Tutorials: Phase loading, content validation
  - Integration: Full workflows, tool chains

### Running Tests

```bash
# All unit tests
cargo test --lib

# Integration tests
cargo test --test integration_tests

# Specific test module
cargo test model_tests::

# With output
cargo test -- --nocapture

# All tests
cargo test
```

## 🎨 Design Patterns

### 1. Builder Pattern

Used for tool configuration:

```rust
let config = ToolConfig::builder()
    .target("10.10.10.1")
    .argument("-p22,80,443")
    .timeout(Duration::from_secs(300))
    .build()?;
```

### 2. Observer Pattern

Event dispatcher for decoupled modules:

```rust
dispatcher.register_handler("event_type", handler);
dispatcher.dispatch(Message::EventOccurred { data });
```

### 3. Registry Pattern

Tool discovery and registration:

```rust
let mut registry = ToolRegistry::new();
registry.register(Box::new(NmapTool::default()))?;
let tool = registry.get_tool("nmap")?;
```

### 4. State Pattern

Step content abstraction:

```rust
pub enum StepContent {
    Tutorial { description, notes, evidence, ... },
    Quiz { quiz_step },
}
```

### 5. Factory Pattern

Session and step creation:

```rust
let session = Session::default(); // 9 phases pre-loaded
let step = Step::new_tutorial(id, title, description, tags);
```

### 6. Strategy Pattern

Tool execution strategies (different scan types):

```rust
pub enum NmapScanType {
    TcpSyn, TcpConnect, Udp, ScriptScan, VersionDetection, ...
}
```

## 🔌 Extension Points

### Adding a New Security Tool

1. **Create tool file**: `src/tools/integrations/mytool.rs`
2. **Implement SecurityTool trait**:

   ```rust
   pub struct MyTool { config: MyConfig }
   
   impl SecurityTool for MyTool {
       fn name(&self) -> &str { "mytool" }
       fn check_availability(&self) -> Result<bool> { /* ... */ }
       fn build_command(&self, config: &ToolConfig) -> Result<Command> { /* ... */ }
       fn parse_output(&self, stdout: &str, stderr: &str) -> Result<Value> { /* ... */ }
       fn extract_evidence(&self, output: &Value) -> Vec<Evidence> { /* ... */ }
       fn validate_prerequisites(&self, config: &ToolConfig) -> Result<()> { /* ... */ }
   }
   ```

3. **Write comprehensive tests** (20+ tests covering all methods)
4. **Register in mod.rs**: `pub use mytool::MyTool;`
5. **Add UI integration** in `src/ui/tool_execution.rs`

### Adding a New Tutorial Phase

1. **Create phase file**: `src/tutorials/my_phase.rs`
2. **Define steps**:

   ```rust
   pub fn create_my_phase() -> Phase {
       let mut phase = Phase::new(Uuid::new_v4(), "My Phase".to_string());
       phase.steps.push(Step::new_tutorial(
           Uuid::new_v4(),
           "Step Title".to_string(),
           "OBJECTIVE: ...\nSTEP-BY-STEP PROCESS: ...".to_string(),
           vec!["tag1".to_string()],
       ));
       phase
   }
   ```

3. **Export from mod.rs**: Add to `load_tutorial_phases()`
4. **Write validation tests**

### Adding a New Message Type

1. **Extend Message enum** in `src/dispatcher.rs`:

   ```rust
   pub enum Message {
       CustomEvent { data: String },
   }
   ```

2. **Register handler** where needed:

   ```rust
   dispatcher.register_handler("custom_event", handler);
   ```

### Adding a New UI Component

1. **Create component file** in `src/ui/`
2. **Follow GTK4 patterns**: Use `Rc<RefCell<>>` for shared state
3. **Connect signal handlers** with clone dance pattern
4. **Update main.rs** to include component in layout
5. **Add tests** in `tests/ui_tests.rs`

## 📊 Code Metrics

### Module Size Distribution

| Module | Files | Lines | Purpose |
|--------|-------|-------|---------|
| tutorials/ | 10 | 12,018 | Tutorial content |
| ui/ | 14 | 4,523 | User interface |
| tools/ | 5 | 2,413 | Tool integrations |
| lib.rs | 1 | 1,060 | Test suite |
| quiz/ | 1 | 335 | Quiz system |
| dispatcher.rs | 1 | 235 | Event system |
| main.rs | 1 | 37 | Entry point |
| model.rs | 1 | 655 | Domain models |
| store.rs | 1 | 273 | Persistence |

**Total**: 41 files, 21,549 lines of Rust code

### Test Distribution

| Category | Tests | Coverage |
|----------|-------|----------|
| Model Tests | 20+ | Session, Phase, Step, Evidence, Quiz |
| Store Tests | 15+ | Save, load, migration, Unicode |
| Tool Tests | 50+ | Nmap (8 types), Gobuster (3 modes) |
| Quiz Tests | 10+ | Parsing, progress, scoring |
| Dispatcher Tests | 8+ | Event routing, handlers |
| Tutorial Tests | 5+ | Phase loading, validation |
| Integration Tests | 10+ | End-to-end workflows |
| Property Tests | 10+ | Randomized input validation |

**Total**: 188 tests with 100% pass rate

## 🚀 Development Workflow

### Local Development

```bash
# Format code
cargo fmt

# Lint code
cargo clippy

# Run application
cargo run

# Run with release optimizations
cargo run --release

# Build only
cargo build

# Run tests
cargo test --lib
cargo test --test integration_tests
```

### Code Quality Standards

- ✅ All code must pass `cargo fmt`
- ✅ All code must pass `cargo clippy` with no warnings
- ✅ New features require tests (TDD methodology)
- ✅ Tests must have 100% pass rate
- ✅ Documentation for public APIs
- ✅ Follow established patterns in existing code

### Performance Targets

- Session creation: < 100ms ✅
- Save operations: < 500ms ✅
- Load operations: < 500ms ✅
- UI handler response: < 16ms (60 FPS) ✅
- Large sessions (5MB): < 1s ✅
- Tool execution: Configurable timeouts ✅

## 🔐 Security Considerations

### Tool Execution

- Tools run with user's permissions (not elevated by default)
- Some tools require root (use `requires_root()` check)
- Timeouts enforced to prevent hanging
- Command injection protected by proper escaping
- Environment variables scoped to child process

### Data Storage

- Sessions stored in user's Downloads folder by default
- Evidence files stored relative to session file
- No sensitive data in logs
- JSON format for transparency
- User controls all data locations

### Input Validation

- Quiz questions validated on parse
- Tool configurations validated before execution
- File paths sanitized before use
- Image dimensions validated before loading
- Unicode handled correctly throughout

## 📝 Documentation

### Available Documentation

| Document | Location | Size | Purpose |
|----------|----------|------|---------|
| README.md | Root | 14.1KB | Project overview, setup, usage |
| CODEBASE_INDEX.md | Root | This file | Comprehensive code reference |
| MODULE_CONTRACTS.md | docs/ | 15.7KB | API contracts, patterns |
| PERFORMANCE_BENCHMARKS.md | docs/ | 10.2KB | Performance metrics |
| SESSION_FOLDER_STRUCTURE.md | docs/ | 6.9KB | Storage layout |
| TDD_COMPLETION_REPORT.md | docs/ | 9.5KB | Quality report |
| copilot-instructions.md | .github/ | - | AI agent guidelines |

### Inline Documentation

- Rust doc comments on all public APIs
- Module-level documentation in each file
- Critical sections have explanatory comments
- Test descriptions explain expected behavior

## 🗺️ Roadmap

### Phase 1: Tool Integration Expansion (Weeks 1-4)

- Nikto - Web vulnerability scanner
- SQLMap - SQL injection tool
- FFUF - Fast web fuzzer
- Nuclei - Template-based scanner
- Burp Suite - Web proxy
- Metasploit - Exploitation framework
- Hydra - Password cracker
- Dirb - Directory brute-forcer

### Phase 2: Advanced UI Features (Weeks 5-8)

- Real-time output streaming
- Evidence management 2.0
- Workflow automation
- Tool configuration templates

### Phase 3: Platform Integration (Weeks 9-12)

- Cloud storage sync
- Team collaboration features
- Enterprise features

### Phase 4: Advanced Features (Weeks 13-16)

- AI-powered analysis
- Mobile apps
- Plugin ecosystem

## 🤝 Contributing

### High Priority Areas

1. **Tool Integrations** - Add new security tools following trait pattern
2. **UI Enhancements** - Improve workflow and automation
3. **Documentation** - Expand guides and examples
4. **Testing** - Increase coverage and add edge cases

### Contribution Checklist

- [ ] Code formatted with `cargo fmt`
- [ ] Code linted with `cargo clippy` (no warnings)
- [ ] Tests pass: `cargo test --lib`
- [ ] New features have corresponding tests
- [ ] Documentation updated
- [ ] Follow established patterns

## 📞 Support

### For Developers

- **Architecture**: See `docs/MODULE_CONTRACTS.md`
- **Extension Points**: This document, Extension Points section
- **Testing**: See test examples in `src/lib.rs`
- **Patterns**: Study existing tool integrations

### For Contributors

- **Getting Started**: See `README.md`
- **Development Plan**: (To be created)
- **Code Structure**: This document
- **API Contracts**: See `docs/MODULE_CONTRACTS.md`

---

**Last Updated**: November 21, 2025  
**Version**: v0.1.0  
**Maintainer**: PT Journal Development Team

---

*This codebase index provides comprehensive navigation and understanding of the PT Journal project structure, modules, patterns, and extension points.*
