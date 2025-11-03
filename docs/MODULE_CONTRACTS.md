# PT Journal - Module Boundaries & API Contracts

## Architecture Overview

PT Journal follows a layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│                    UI Layer (GTK4)                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │ Main Win │  │ Handlers │  │ Panels   │            │
│  └──────────┘  └──────────┘  └──────────┘            │
└─────────────────────────────────────────────────────────┘
                        ↓  ↓
┌─────────────────────────────────────────────────────────┐
│              Application Logic Layer                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │  State   │  │Dispatcher│  │ File Ops │            │
│  └──────────┘  └──────────┘  └──────────┘            │
└─────────────────────────────────────────────────────────┘
                        ↓  ↓
┌─────────────────────────────────────────────────────────┐
│               Domain Model Layer                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │ Session  │  │  Phase   │  │   Step   │            │
│  └──────────┘  └──────────┘  └──────────┘            │
└─────────────────────────────────────────────────────────┘
                        ↓  ↓
┌─────────────────────────────────────────────────────────┐
│          Infrastructure Layer                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │  Store   │  │  Tools   │  │ Tutorial │            │
│  └──────────┘  └──────────┘  └──────────┘            │
└─────────────────────────────────────────────────────────┘
```

## Module Contracts

### 1. Model Layer (`src/model.rs`)

**Purpose**: Core domain models for pentesting sessions.

**Public API**:

```rust
// Session management
pub struct Session {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub notes_global: String,
    pub phases: Vec<Phase>,
}

impl Session {
    pub fn default() -> Self  // Factory with 9 tutorial phases
}

// Step content abstraction
pub enum StepContent {
    Tutorial { description, notes, evidence, ... },
    Quiz { quiz_step },
}

impl Step {
    // Getters (work for both Tutorial and Quiz)
    pub fn get_description(&self) -> &str
    pub fn get_notes(&self) -> String
    pub fn get_evidence(&self) -> &[Evidence]
    
    // Setters (work for Tutorial only)
    pub fn set_notes(&mut self, notes: String)
    pub fn set_description_notes(&mut self, notes: String)
    pub fn add_evidence(&mut self, evidence: Evidence)
    
    // Type checking
    pub fn is_tutorial(&self) -> bool
    pub fn is_quiz(&self) -> bool
    pub fn get_quiz_step(&self) -> Option<&QuizStep>
    pub fn quiz_mut_safe(&mut self) -> Option<&mut QuizStep>
}
```

**Contracts**:

- ✅ All IDs are `Uuid` for global uniqueness
- ✅ Timestamps are `DateTime<Utc>` for consistent timezone handling
- ✅ Step content is abstracted via `StepContent` enum
- ✅ Legacy fields (`notes`, `description_notes`, `evidence`) are skipped during serialization
- ✅ Always use getters/setters - never direct field access
- ✅ Evidence paths are relative to session folder

**Dependencies**: `chrono`, `uuid`, `serde`

---

### 2. Store Layer (`src/store.rs`)

**Purpose**: Session persistence with folder structure.

**Public API**:

```rust
// Save session to folder structure
pub fn save_session(path: &Path, session: &Session) -> Result<()>

// Load session from session.json file
pub fn load_session(path: &Path) -> Result<Session>

// Get default sessions directory
pub fn default_sessions_dir() -> PathBuf  // ~/Downloads/pt-journal-sessions/
```

**Storage Structure**:

```
~/Downloads/pt-journal-sessions/
└── session-name/
    ├── session.json     # Full session data
    └── evidence/        # Tool outputs, screenshots
        ├── Nov021430_0.txt
        ├── Nov021445_1.png
        └── ...
```

**Contracts**:

- ✅ `save_session()` accepts folder path OR file path (auto-detects)
- ✅ Creates `evidence/` subdirectory automatically
- ✅ `load_session()` accepts `session.json` file path
- ✅ Preserves timestamps and UUIDs exactly
- ✅ Handles Unicode (UTF-8) correctly
- ✅ Creates parent directories as needed
- ✅ Idempotent - overwriting is safe

**Error Handling**:

- Returns `anyhow::Result` for all operations
- Fails gracefully on:
  - Missing directories (creates them)
  - Invalid JSON (returns descriptive error)
  - Permission errors (bubbles up OS error)

**Dependencies**: `serde_json`, `anyhow`, `directories`

---

### 3. Tools Layer (`src/tools/`)

**Purpose**: Security tool integration and execution.

**Public API**:

```rust
// Tool configuration
pub struct ToolConfig {
    pub target: Option<String>,
    pub arguments: Vec<String>,
    pub timeout: Option<Duration>,
    pub env_vars: HashMap<String, String>,
}

impl ToolConfig {
    pub fn builder() -> ToolConfigBuilder  // Fluent builder
}

// Execution result
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration: Duration,
    pub parsed_result: Option<serde_json::Value>,
    pub evidence: Vec<Evidence>,
}

// Tool trait
pub trait SecurityTool: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> Result<ToolVersion>;
    fn is_available(&self) -> bool;
    fn requires_root(&self) -> bool;
}

// Tool execution
pub trait ToolRunner {
    fn execute(&self, tool: &dyn SecurityTool, config: &ToolConfig) 
        -> Result<ExecutionResult>;
}
```

**Contracts**:

- ✅ All tools implement `SecurityTool` trait
- ✅ Tool names are lowercase ("nmap", "gobuster")
- ✅ Execution is synchronous (blocking)
- ✅ Timeout is enforced if specified
- ✅ Environment variables are applied to child process
- ✅ Exit codes are preserved
- ✅ Duration is measured accurately

**Available Tools**:

- `NmapTool` - 8 scan types (TcpSyn, TcpConnect, Udp, etc.)
- `GobusterTool` - 3 modes (Dir, Dns, Vhost)

**Dependencies**: `anyhow`, `regex`, `serde_json`

---

### 4. UI Layer (`src/ui/`)

**Purpose**: GTK4 user interface components.

**Modules**:

#### 4.1 Main Window (`main.rs`)

```rust
pub fn build_ui(app: &Application) -> Window
```

- Bootstraps GTK4 application
- Creates 3-column resizable layout
- Connects all signal handlers
- Sets dark theme preference

#### 4.2 Handlers (`handlers.rs`)

```rust
pub fn setup_tool_execution_handlers(...)  // Tool panel signals
pub fn setup_phase_handler(...)            // Phase dropdown
pub fn setup_step_handlers(...)            // Step list + checkboxes
pub fn setup_notes_handlers(...)           // TextBuffer changes
```

- All signal handlers in one place
- Uses "clone dance" pattern for Rc<RefCell<>>
- Blocks handlers during programmatic updates

#### 4.3 Components

- `DetailPanel` - Tutorial/quiz stack, canvas, notes
- `QuizWidget` - MCQ display, check/explanation buttons
- `ToolExecutionPanel` - Nmap/Gobuster UI
- `HeaderBar` - Open/Save buttons
- `Sidebar` - Phase/step navigation

**Contracts**:

- ✅ All widgets are created once at startup
- ✅ Signal handlers modify `AppModel` state
- ✅ UI updates are deferred to `glib::idle_add_local_once` when needed
- ✅ GTK initialization is guarded with `Once` in tests
- ✅ No blocking operations on main thread

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

### 5. Dispatcher Layer (`src/dispatcher.rs`)

**Purpose**: Event-driven communication between modules.

**Public API**:

```rust
pub enum Message {
    SessionLoaded { session: Session },
    StepCompleted { step_id: Uuid },
    EvidenceAdded { evidence: Evidence },
    ToolExecuted { result: ExecutionResult },
}

pub struct Dispatcher {
    pub fn new() -> Self
    pub fn register_handler(&mut self, message_type: &str, handler: Handler)
    pub fn dispatch(&self, message: Message)
}
```

**Contracts**:

- ✅ Messages are enum variants (type-safe)
- ✅ Handlers are `Fn(Message)` closures
- ✅ Multiple handlers per message type supported
- ✅ Thread-safe with `Rc<RefCell<>>`
- ✅ Handlers execute synchronously in registration order

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

**Future Expansion**:

- [ ] Async message handling
- [ ] Message priorities
- [ ] Event logging/replay

**Dependencies**: None (pure Rust)

---

### 6. Tutorial Layer (`src/tutorials/`)

**Purpose**: Pentesting methodology content.

**Public API**:

```rust
pub fn load_tutorial_phases() -> Vec<Phase>  // 9 phases
```

**Phases**:

1. Reconnaissance (16 steps)
2. Vulnerability Analysis (5 steps)
3. Exploitation (4 steps)
4. Post-Exploitation (4 steps)
5. Reporting (4 steps)
6. Bug Bounty Hunting (varies)
7. CompTIA Security+ (quiz-based)
8. PenTest+ (quiz-based)
9. CEH (quiz-based)

**Content Structure**:

```
OBJECTIVE: What you're trying to achieve
STEP-BY-STEP PROCESS: Commands and procedures
WHAT TO LOOK FOR: Expected findings
COMMON PITFALLS: Mistakes to avoid
DOCUMENTATION REQUIREMENTS: Evidence to capture
```

**Contracts**:

- ✅ All steps have structured descriptions
- ✅ Tutorial steps use `Step::new_tutorial()`
- ✅ Quiz steps use `Step::new_quiz()`
- ✅ Quiz questions format: `question|a|b|c|d|correct_idx|explanation|domain|subdomain`
- ✅ Tags are consistent across phases

**Dependencies**: None (embedded data)

---

### 7. Quiz Layer (`src/quiz/`)

**Purpose**: Quiz question parsing and validation.

**Public API**:

```rust
pub fn parse_question_line(line: &str) -> Result<Question>
```

**Format**: Pipe-delimited string

```
What is 2+2?|Four|Three|Five|Six|0|Basic arithmetic|Math|Addition
```

**Contracts**:

- ✅ Exactly 9 fields required
- ✅ Answer index is 0-based
- ✅ Validates answer index is in range 0-3
- ✅ Domain and subdomain for categorization

**Dependencies**: `anyhow`

---

## Testing Contracts

### Unit Tests

```rust
// Model tests
#[test] fn test_session_creation()
#[test] fn test_step_getters_setters()

// Store tests
#[test] fn test_save_load_roundtrip()
#[test] fn test_unicode_handling()

// Tool tests
#[test] fn test_tool_config_builder()
#[test] fn test_execution_result()
```

### Integration Tests

```rust
// Full workflow tests
#[test] fn test_full_session_workflow()
#[test] fn test_comprehensive_session_workflow()

// Tool execution tests (20 tests)
#[test] fn test_nmap_scan_types()
#[test] fn test_gobuster_modes()
#[test] fn test_tool_registry()
```

### Property Tests

```rust
proptest! {
    #[test] fn test_session_name_preservation(name in ".*")
    #[test] fn test_notes_preservation(notes in ".*")
    #[test] fn test_step_notes_preservation(notes in ".*")
}
```

---

## Performance Contracts

### Session Operations

- ✅ Session creation: < 100ms (includes 9 phases, 45+ steps)
- ✅ Serialization: < 500ms (to JSON)
- ✅ Deserialization: < 500ms (from JSON)

### Tool Execution

- ⚠️  Blocking (runs on main thread - use with care)
- ✅ Timeout enforcement (configurable per tool)
- ✅ Duration measurement (accurate to milliseconds)

### UI Responsiveness

- ✅ All signal handlers < 16ms (60 FPS)
- ✅ File dialogs are async (non-blocking)
- ✅ Tool execution shows spinner during wait

---

## Extension Points

### Adding a New Tool

```rust
// 1. Create tool struct
pub struct MyTool { config: MyConfig }

// 2. Implement SecurityTool trait
impl SecurityTool for MyTool {
    fn name(&self) -> &str { "mytool" }
    fn is_available(&self) -> bool { /* check */ }
    fn requires_root(&self) -> bool { true }
}

// 3. Implement build_command()
fn build_command(&self, config: &ToolConfig) -> Command { /* ... */ }

// 4. Register in registry (optional)
registry.register(Box::new(MyTool::default()))?;

// 5. Add UI integration in tool_execution.rs
tool_selector.append(Some("mytool"), "MyTool - Description");
```

### Adding a New Message Type

```rust
// 1. Extend Message enum
pub enum Message {
    // Existing...
    CustomEvent { data: String },
}

// 2. Register handler
dispatcher.register_handler("custom_event", Box::new(|msg| {
    if let Message::CustomEvent { data } = msg {
        // Handle event
    }
}));

// 3. Dispatch from anywhere
dispatcher.dispatch(Message::CustomEvent { data: "test".into() });
```

---

## Dependency Graph

```
model.rs ← store.rs ← ui/file_ops.rs ← ui/handlers.rs ← ui/main.rs
   ↑                        ↑
   |                        |
tutorials/mod.rs      quiz/mod.rs
   ↑                        ↑
   |________________________|
            model.rs

tools/traits.rs ← tools/executor.rs ← tools/integrations/* ← ui/tool_execution.rs
   ↑
   |
model.rs (for Evidence)

ui/state.rs ← ui/handlers.rs
   ↑
   |
model.rs

dispatcher.rs ← (future: all modules)
```

---

## Migration Guide

### From Direct Field Access to Getters/Setters

❌ **Old (Wrong)**:

```rust
let notes = step.notes.clone();
step.notes = "New notes".to_string();
```

✅ **New (Correct)**:

```rust
let notes = step.get_notes();
step.set_notes("New notes".to_string());
```

### From Single File to Folder Structure

❌ **Old**:

```rust
let path = temp_dir.join("session.json");
save_session(&path, &session)?;
let loaded = load_session(&path)?;
```

✅ **New**:

```rust
let folder = temp_dir.join("my_session");
let file = folder.join("session.json");
save_session(&folder, &session)?;  // Creates folder + evidence/
let loaded = load_session(&file)?;  // Loads from session.json
```

---

## Version History

- **v0.1.0** (Nov 2025)
  - Initial modular architecture
  - Session folder structure
  - Tool integration framework
  - Dispatcher pattern
  - 201/205 tests passing (98%)
