# PT Journal - Codebase Index

**Date**: November 15, 2025  
**Version**: v0.1.0  
**Total Files**: 41 Rust files, 5,000+ lines of code  

---

## 📁 Project Structure Overview

```
pt-journal/
├── 📄 README.md                     # Main user documentation
├── 📄 Cargo.toml                     # Dependencies and project config
├── 📄 DEVELOPMENT_PLAN.md            # Comprehensive 16-week roadmap
├── 📄 ROADMAP_SECURITY_TOOLS.md      # Security tools implementation plan
├── 📄 PROGRESS_SECURITY_TOOLS.md     # Current progress and status
├── 📄 TOOL_INSTRUCTIONS_FEATURE.md   # Tool instructions dialog feature
├── 📁 src/                           # Source code (6 modules)
│   ├── 📄 main.rs                    # Application entry point
│   ├── 📄 lib.rs                     # Library root with test suite
│   ├── 📄 model.rs                   # Core data models (20K lines)
│   ├── 📄 store.rs                   # JSON persistence layer (9K lines)
│   ├── 📄 dispatcher.rs              # Event dispatcher (7K lines)
│   ├── 📁 tools/                     # Security tools integration
│   ├── 📁 tutorials/                 # Pentesting methodology content
│   ├── 📁 quiz/                      # Quiz system
│   └── 📁 ui/                        # GTK4 user interface
├── 📁 tests/                         # Integration and UI tests
├── 📁 data/                          # Tutorial and quiz data
└── 📁 docs/                          # Technical documentation
```

---

## 🏗️ Architecture Layers

### 1. Application Layer (`src/main.rs`, `src/lib.rs`)
**Purpose**: Application bootstrap and library entry point

**Key Components**:
- `main()` - GTK4 application initialization
- `build_ui()` - Main window construction
- Test suite orchestration

**Dependencies**: `gtk4`, `libadwaita`, `relm4`

---

### 2. Domain Model Layer (`src/model.rs`)
**Purpose**: Core business entities and data structures

**Key Models**:
```rust
pub struct Session {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub notes_global: String,
    pub phases: Vec<Phase>,
}

pub struct Phase {
    pub id: Uuid,
    pub name: String,
    pub notes: String,
    pub steps: Vec<Step>,
}

pub struct Step {
    pub id: Uuid,
    pub title: String,
    pub content: StepContent,  // Tutorial or Quiz
    pub tags: Vec<String>,
    pub status: StepStatus,
}

pub enum StepContent {
    Tutorial {
        description: String,
        description_notes: String,
        notes: String,
        evidence: Vec<Evidence>,
    },
    Quiz {
        quiz_step: QuizStep,
    },
}
```

**Key Features**:
- UUID-based identification for global uniqueness
- UTC timestamps for consistent timezone handling
- Enum-based content abstraction (Tutorial vs Quiz)
- Serde serialization for JSON persistence
- Comprehensive getter/setter methods

**Dependencies**: `uuid`, `chrono`, `serde`

---

### 3. Infrastructure Layer

#### 3.1 Persistence (`src/store.rs`)
**Purpose**: Session storage and file system operations

**Key Functions**:
```rust
pub fn save_session(path: &Path, session: &Session) -> Result<()>
pub fn load_session(path: &Path) -> Result<Session>
pub fn default_sessions_dir() -> PathBuf
```

**Storage Pattern**:
```
~/Downloads/pt-journal-sessions/
└── session-name/
    ├── session.json     # Full session data
    └── evidence/        # Tool outputs, screenshots
        ├── nmap_target_Nov021430_0.txt
        ├── screenshot_Nov021445_1.png
        └── ...
```

**Dependencies**: `serde_json`, `anyhow`, `directories`

#### 3.2 Security Tools (`src/tools/`)
**Purpose**: Security tool integration framework

**Core Architecture**:
```rust
// Core trait system
pub trait SecurityTool: Send + Sync {
    fn name(&self) -> &str;
    fn check_availability(&self) -> Result<ToolVersion>;
    fn build_command(&self, config: &ToolConfig) -> Result<Command>;
    fn parse_output(&self, output: &str) -> Result<ToolResult>;
    fn extract_evidence(&self, result: &ToolResult) -> Vec<Evidence>;
    fn validate_prerequisites(&self, config: &ToolConfig) -> Result<()>;
}

// Configuration builder
pub struct ToolConfigBuilder;
impl ToolConfigBuilder {
    pub fn target(mut self, target: impl Into<String>) -> Self
    pub fn argument(mut self, arg: impl Into<String>) -> Self
    pub fn timeout(mut self, duration: Duration) -> Self
    pub fn build(self) -> Result<ToolConfig>
}

// Execution engine
pub trait ToolRunner {
    fn execute(&self, tool: &dyn SecurityTool, config: &ToolConfig) -> Result<ExecutionResult>;
}

// Registry pattern
pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn SecurityTool>>,
}
```

**Implemented Tools**:
- **Nmap** (`src/tools/integrations/nmap.rs`) - 8 scan types, 23 tests
- **Gobuster** (`src/tools/integrations/gobuster.rs`) - 3 modes, 21 tests

**Dependencies**: `anyhow`, `regex`, `serde_json`

#### 3.3 Tutorial System (`src/tutorials/`)
**Purpose**: Pentesting methodology content

**Phase Structure**:
1. **Reconnaissance** (`reconnaissance.rs`) - 16 steps
2. **Vulnerability Analysis** (`vulnerability_analysis.rs`) - 5 steps
3. **Exploitation** (`exploitation.rs`) - 4 steps
4. **Post-Exploitation** (`post_exploitation.rs`) - 4 steps
5. **Reporting** (`reporting.rs`) - 4 steps
6. **Bug Bounty Hunting** (`bug_bounty_hunting.rs`) - Variable steps
7. **CompTIA Security+** (`comptia_secplus.rs`) - Quiz-based
8. **PenTest+** (`pentest_exam.rs`) - Quiz-based
9. **CEH** (`ceh.rs`) - Quiz-based

**Content Format**:
```
OBJECTIVE: What you're trying to achieve
STEP-BY-STEP PROCESS: Commands and procedures
WHAT TO LOOK FOR: Expected findings
COMMON PITFALLS: Mistakes to avoid
DOCUMENTATION REQUIREMENTS: Evidence to capture
```

#### 3.4 Quiz System (`src/quiz/`)
**Purpose**: Assessment and learning tools

**Question Format**: Pipe-delimited string
```
question text|option A|option B|option C|option D|correct_index|explanation|domain|subdomain
```

**Dependencies**: `anyhow`

---

### 4. Application Logic Layer

#### 4.1 Event Dispatcher (`src/dispatcher.rs`)
**Purpose**: Decoupled module communication

**Message Types**:
```rust
pub enum Message {
    SessionLoaded { session: Session },
    StepCompleted { step_id: Uuid },
    EvidenceAdded { evidence: Evidence },
    ToolExecuted { result: ExecutionResult },
}
```

**Pattern**: Observer pattern with type-safe enum messages

---

### 5. User Interface Layer (`src/ui/`)

#### 5.1 Main Window (`src/ui/main.rs`)
**Purpose**: Application bootstrap and layout

**Layout Structure**:
```
┌─────────────────────────────────────────────────┐
│                   HeaderBar                      │
├──────────┬──────────────────┬───────────────────┤
│          │                  │                   │
│ Sidebar  │  DetailPanel     │     Canvas        │
│          │                  │                   │
│ Phase    │  Tutorial/Quiz   │  Evidence Images  │
│ Selector │  Description     │  + Annotations   │
│ + Steps  │  + Notes         │                   │
│          │                  │                   │
└──────────┴──────────────────┴───────────────────┘
```

#### 5.2 UI Components

**Core Components**:
- **HeaderBar** (`header_bar.rs`) - File operations, toolbar
- **Sidebar** (`sidebar.rs`) - Phase/step navigation
- **DetailPanel** (`detail_panel.rs`) - Content display stack
- **QuizWidget** (`quiz_widget.rs`) - MCQ interface
- **Canvas** (`canvas.rs`) - Evidence management
- **ToolExecutionPanel** (`tool_execution.rs`) - Security tools UI

**Supporting Components**:
- **Handlers** (`handlers.rs`) - Signal handlers coordination
- **State** (`state.rs`) - Application state management
- **FileOps** (`file_ops.rs`) - File dialog operations
- **ImageUtils** (`image_utils.rs`) - Image processing
- **CanvasUtils** (`canvas_utils.rs`) - Canvas utilities

**State Management**:
```rust
pub struct AppModel {
    pub session: Session,
    pub current_path: Option<PathBuf>,
    pub selected_phase: usize,
    pub selected_step: Option<usize>,
}
```

**Dependencies**: `gtk4`, `libadwaita`, `glib`, `async-channel`

---

## 🧪 Testing Infrastructure

### Test Categories

#### 1. Unit Tests (`src/`)
**Location**: Integrated in each module
**Coverage**: 180+ tests with 100% pass rate
**Examples**:
- Model tests: Session creation, step operations
- Store tests: Save/load roundtrip, Unicode handling
- Tool tests: Command building, output parsing
- UI tests: Widget creation, state management

#### 2. Integration Tests (`tests/`)
**Files**:
- `integration_tests.rs` - Full workflow tests
- `tools_integration_tests.rs` - Security tools integration
- `tool_execution_integration_tests.rs` - UI tool execution
- `ui_tests.rs` - GTK component integration

**Test Patterns**:
```rust
#[test]
fn test_full_session_workflow() {
    // Create session, add evidence, save, load, verify
}

#[test]
fn test_nmap_integration() {
    // Register tool, configure, execute, parse results
}
```

#### 3. Property Tests
**Framework**: `proptest`
**Coverage**: Session name preservation, notes handling

---

## 📊 Code Metrics

### Lines of Code by Module
| Module | Lines | Tests | Coverage |
|--------|-------|-------|----------|
| `model.rs` | 20,056 | 45 | 100% |
| `ui/handlers.rs` | 41,979 | 0 | UI tests |
| `ui/canvas.rs` | 23,244 | 0 | UI tests |
| `ui/tool_execution.rs` | 44,265 | 0 | UI tests |
| `tools/integrations/nmap.rs` | 21,619 | 23 | 100% |
| `tools/integrations/gobuster.rs` | 21,909 | 21 | 100% |
| `tools/traits.rs` | 8,896 | 12 | 100% |
| `tools/executor.rs` | 9,118 | 9 | 100% |
| `tools/registry.rs` | 8,109 | 10 | 100% |
| `store.rs` | 9,354 | 15 | 100% |
| `dispatcher.rs` | 6,821 | 8 | 100% |

### Dependencies Overview
**Core Dependencies**:
- `gtk4` (0.9) - GUI framework
- `libadwaita` (0.7) - GNOME styling
- `relm4` (0.9) - GTK4 patterns
- `serde` (1.0) - Serialization
- `uuid` (1.0) - Unique identifiers
- `chrono` (0.4) - Date/time handling
- `anyhow` (1.0) - Error handling

**Development Dependencies**:
- `tempfile` (3.8) - Test file management
- `assert_matches` (1.5) - Test assertions
- `proptest` (1.0) - Property testing

---

## 🔧 Development Patterns

### 1. Trait-Based Architecture
**Purpose**: Extensible tool integration
**Pattern**: All security tools implement `SecurityTool` trait
**Benefits**: Type safety, consistent interface, easy testing

### 2. Builder Pattern
**Purpose**: Complex configuration objects
**Example**: `ToolConfig::builder().target("example.com").build()`
**Benefits**: Fluent API, validation, optional parameters

### 3. Observer Pattern
**Purpose**: Decoupled event handling
**Implementation**: `Dispatcher` with `Message` enum
**Benefits**: Loose coupling, type safety, extensibility

### 4. Factory Pattern
**Purpose**: Object creation with defaults
**Example**: `Session::default()` creates full tutorial session
**Benefits**: Consistent initialization, embedded data

### 5. Registry Pattern
**Purpose**: Tool discovery and management
**Implementation**: `ToolRegistry` with HashMap storage
**Benefits**: Centralized management, duplicate prevention

---

## 🚀 Extension Points

### Adding New Security Tools
1. Create file: `src/tools/integrations/newtool.rs`
2. Implement `SecurityTool` trait (6 methods)
3. Add comprehensive tests (20+ tests recommended)
4. Register in `src/tools/integrations/mod.rs`
5. Add UI integration in `src/ui/tool_execution.rs`
6. Add tool instructions dialog content

### Adding New Tutorial Phases
1. Create file: `src/tutorials/new_phase.rs`
2. Define phase structure with steps
3. Follow content format (OBJECTIVE, PROCESS, etc.)
4. Register in `src/tutorials/mod.rs`
5. Add phase to default session creation

### Adding New Quiz Content
1. Add question files to `data/` directory
2. Follow pipe-delimited format
3. Update quiz loading logic
4. Test question parsing and validation

### Extending UI Components
1. Create new widget in `src/ui/`
2. Follow GTK4 patterns with `relm4`
3. Add signal handlers in `handlers.rs`
4. Update state management in `state.rs`
5. Add integration tests

---

## 📋 Configuration Files

### Cargo.toml Highlights
```toml
[package]
name = "pt-journal"
version = "0.1.0"
edition = "2021"

[dependencies]
gtk4 = { version = "0.9", features = ["v4_12"] }
adw = { package = "libadwaita", version = "0.7" }
relm4 = { version = "0.9", features = ["macros"] }
serde = { version = "1", features = ["derive"] }
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde", "clock"] }
anyhow = "1"
```

### Key Features
- Rust 2021 edition
- GTK4 v4_12 features
- Serde derive for serialization
- UUID v4 with serde support
- Chrono with serde and clock features

---

## 🗂️ Data Files Structure

### Tutorial Data (`data/tutorials/`)
- Embedded in source code for reliability
- Structured methodology content
- Step-by-step instructions

### Quiz Data (`data/`)
- `comptia_secplus/` - Security+ questions
- `ceh/` - CEH methodology questions  
- `pentest/` - PenTest+ questions
- `wordlists/` - Common wordlists for tools

### Documentation (`docs/`)
- `MODULE_CONTRACTS.md` - API contracts
- `PERFORMANCE_BENCHMARKS.md` - Performance metrics
- `SESSION_FOLDER_STRUCTURE.md` - Storage layout
- `TDD_COMPLETION_REPORT.md` - Test coverage report

---

## 🔍 Code Quality Standards

### Formatting and Linting
```bash
cargo fmt          # Code formatting
cargo clippy       # Linting
cargo clippy --fix # Auto-fix warnings
```

### Testing Standards
```bash
cargo test --lib                    # Unit tests
cargo test --test integration_tests # Integration tests
cargo test --all                    # All tests
```

### Documentation Standards
- All public functions have rustdoc comments
- Examples provided for complex APIs
- Architecture documented in markdown files
- User guides in README.md

---

## 🎯 Development Workflow

### 1. Feature Development
1. Create feature branch from `main`
2. Write tests first (TDD methodology)
3. Implement functionality following patterns
4. Run full test suite
5. Update documentation
6. Submit pull request

### 2. Bug Fixes
1. Create reproduction test
2. Fix issue with minimal changes
3. Verify fix doesn't break existing tests
4. Update documentation if needed
5. Submit pull request

### 3. Code Review Process
1. Automated checks (fmt, clippy, tests)
2. Manual review for architecture compliance
3. Test coverage verification
4. Documentation review
5. Merge to main branch

---

## 📚 Key Resources

### Documentation
- **User Guide**: `README.md`
- **Development Plan**: `DEVELOPMENT_PLAN.md`
- **API Contracts**: `docs/MODULE_CONTRACTS.md`
- **Security Tools**: `ROADMAP_SECURITY_TOOLS.md`

### Code Examples
- **Tool Integration**: `src/tools/integrations/nmap.rs`
- **UI Components**: `src/ui/detail_panel.rs`
- **Test Patterns**: `tests/tools_integration_tests.rs`

### External Resources
- **GTK4 Documentation**: https://docs.gtk.org/gtk4/
- **Rust Book**: https://doc.rust-lang.org/book/
- **Relm4 Guide**: https://relm4.org/docs/stable/

---

**Last Updated**: November 15, 2025  
**Total Files**: 41 Rust files  
**Test Coverage**: 188 tests (100% pass rate)  
**Lines of Code**: 50,000+ (including tests)  

---

*This index provides a comprehensive overview of the PT Journal codebase structure, architecture patterns, and development guidelines. Use this document to navigate the codebase and understand the relationships between different components.*