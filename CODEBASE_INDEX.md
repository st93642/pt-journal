# PT Journal - Codebase Index

## 📋 Project Overview

**PT Journal** is a GTK4/libadwaita desktop application for structured penetration testing documentation. It provides an organized methodology for security assessments, evidence collection, and quiz-based learning for security certifications.

- **Language**: Rust 2021 Edition
- **Version**: v0.1.0 (Foundation Complete)
- **Architecture**: 4-layer modular design
- **Lines of Code**: ~24,800 lines of Rust
- **Test Coverage**: 242 tests (100% pass rate)
- **Modules**: 53 Rust source files
- **Tool Catalog**: 226 tools across 32 security categories

## 🏗️ Architecture Overview

PT Journal follows a layered architecture with clear separation of concerns:

```text
┌─────────────────────────────────────────────────────────┐
│                    UI Layer (GTK4)                      │
│  Main Window, Handlers, Panels, Widgets                │
│  - chat_panel.rs, detail_panel.rs, quiz_widget.rs      │
│  - tool_execution.rs, sidebar.rs, handlers.rs          │
└─────────────────────────────────────────────────────────┘
                         ↓  ↓
┌─────────────────────────────────────────────────────────┐
│              Application Logic Layer                     │
│  State Management, Event Dispatching, Chatbot           │
│  - state.rs, dispatcher.rs, file_ops.rs, chatbot/       │
└─────────────────────────────────────────────────────────┘
                         ↓  ↓
┌─────────────────────────────────────────────────────────┐
│               Domain Model Layer                         │
│  Core Business Logic, Data Structures                   │
│  - model.rs (Session, Phase, Step, Evidence, Chat)     │
└─────────────────────────────────────────────────────────┘
                         ↓  ↓
┌─────────────────────────────────────────────────────────┐
│          Infrastructure Layer                            │
│  Storage, Tools, Content Management                     │
│  - store.rs, tools/, tutorials/, quiz/                 │
└─────────────────────────────────────────────────────────┘
```

## 📁 Directory Structure

```text
pt-journal/
├── src/                        # Application source code (~26,000 lines)
│   ├── main.rs                 # Application entry point (37 lines)
│   ├── lib.rs                  # Library root with comprehensive test suite (1,155 lines)
│   ├── model/                  # Core domain models (refactored into module)
│   │   ├── mod.rs              # Module exports and re-exports (20 lines)
│   │   ├── app_model.rs        # AppModel and UI snapshots (300 lines)
│   │   ├── chat.rs             # ChatRole and ChatMessage (50 lines)
│   │   ├── quiz.rs             # Quiz system models (200 lines)
│   │   ├── session.rs          # Session model (50 lines)
│   │   └── step.rs             # Step, Phase, Evidence, and content models (400 lines)
│   ├── config.rs               # Configuration management (200 lines)
│   ├── store.rs                # JSON persistence layer (286 lines)
│   ├── dispatcher.rs           # Event dispatcher (247 lines)
│   ├── quiz/                   # Quiz system
│   │   └── mod.rs             # Question parsing (335 lines)
│   ├── tutorials/              # Tutorial content (16,363 lines)
│   │   ├── mod.rs             # Tutorial loader (186 lines)
│   │   ├── reconnaissance.rs   # 16-step reconnaissance (3,323 lines)
│   │   ├── vulnerability_analysis.rs  # 5-step vuln analysis (1,390 lines)
│   │   ├── exploitation.rs     # 4-step exploitation (993 lines)
│   │   ├── post_exploitation.rs # 4-step post-exploit (854 lines)
│   │   ├── reporting.rs        # 4-step reporting (972 lines)
│   │   ├── bug_bounty_hunting.rs # Bug bounty workflows (2,700 lines)
│   │   ├── comptia_secplus.rs  # Security+ content (496 lines)
│   │   ├── pentest_exam.rs     # PenTest+ content (455 lines)
│   │   ├── ceh.rs              # CEH content (649 lines)
│   │   └── ... (13 more tutorial files)
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
│       ├── chat_panel.rs      # Chat interface (NEW: 180 lines)
│       ├── quiz_widget.rs     # Quiz UI (316 lines)
│       ├── tool_execution.rs  # Tool UI (1,146 lines)
│       ├── header_bar.rs      # App toolbar (39 lines)
│       └── file_ops.rs        # File dialogs (188 lines)
├── docs/                       # Documentation
│   ├── architecture.md         # System architecture details
│   ├── configuration.md        # Configuration system guide
│   ├── chatbot.md              # Chatbot integration guide
│   └── roadmap.md              # Development roadmap
├── tests/                      # Dedicated test binaries
│   ├── support/               # Shared test fixtures
│   │   └── domain.rs          # Test fixtures (legacy_step_with_data, quiz_step_fixture)
│   ├── domain_model_tests.rs  # Model layer tests (Step, Phase, Quiz, Session)
│   ├── store_tests.rs         # Persistence layer tests
│   ├── session_content_tests.rs # Session creation, content validation, performance tests
│   └── integration_tests.rs   # Full workflow tests
├── data/                       # Tutorial and quiz content
│   ├── tool_instructions/     # Security tool reference data
│   │   ├── manifest.json      # Tool catalog (226 entries, 32 categories)
│   │   └── categories/        # Modularized instruction documents
│   │       ├── reconnaissance.json             # 9 reconnaissance tools
│   │       ├── scanning_and_enumeration.json   # 12 scanning tools
│   │       ├── exploitation.json               # 12 exploitation tools
│   │       └── ... (29 more category files)
│   ├── serverless_security/   # Serverless security quiz content
│   │   └── serverless-security-quiz.txt        # 18 serverless security questions
│   └── ... (other quiz and tutorial data files)
├── .github/                   # GitHub configuration
│   └── copilot-instructions.md # AI agent instructions
├── Cargo.toml                 # Project manifest
├── Cargo.lock                 # Dependency lock file
└── CODEBASE_INDEX.md          # This documentation
```

## 🧩 Core Modules

### 1. Model Layer (`src/model/`) - 5 files, 1,020 lines

**Purpose**: Core domain models for penetration testing sessions, refactored into focused modules.

**Module Structure**:

```text
model/
├── mod.rs           # Public API re-exports (maintains backward compatibility)
├── app_model.rs     # AppModel, StepSummary, ActiveStepSnapshot
├── chat.rs          # ChatRole, ChatMessage
├── quiz.rs          # QuizAnswer, QuizQuestion, QuestionProgress, QuizStep, QuizStatistics
├── session.rs       # Session model
└── step.rs          # Step, Phase, Evidence, StepContent, LegacyTutorialData
```

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
- `ChatRole` - User vs Assistant message roles
- `ChatMessage` - Chat conversation messages (role, content, timestamp)
- `LegacyTutorialData` - Encapsulated legacy fields for serde migration

**Critical Patterns**:

- Uses `Uuid` for all IDs (global uniqueness)
- Uses `DateTime<Utc>` for all timestamps
- `StepContent` enum abstracts Tutorial vs Quiz steps
- Tutorial steps include persistent chat history
- Getters/setters enforce encapsulation
- Legacy fields encapsulated in `LegacyTutorialData` struct for migration
- Public API maintained via re-exports in `mod.rs`

**Factory Methods**:

- `Session::default()` - Creates session with 23 tutorial phases
- `Step::new_tutorial()` - Creates tutorial step
- `Step::new_quiz()` - Creates quiz step

**Migration Strategy**:

- Legacy tutorial fields encapsulated in `LegacyTutorialData`
- `migrate_from_legacy()` method handles data migration
- Serialization compatibility maintained via `#[serde(default, skip_serializing)]`
- `tutorial_mut()` helper removed to trim API surface

### 2. Config Layer (`src/config.rs`) - 200 lines

**Purpose**: Application configuration management with TOML persistence.

**Key Types**:

- `AppConfig` - Main configuration container
- `ChatbotConfig` - Multi-model offline chatbot settings (model profiles + provider config)

**Configuration Sources** (in priority order):

1. Environment variables (`PT_JOURNAL_CHATBOT_MODEL_ID`, `PT_JOURNAL_OLLAMA_ENDPOINT`, `PT_JOURNAL_OLLAMA_MODEL`)
2. TOML file (`~/.config/pt-journal/config.toml`)
3. Default values (localhost:11434 Ollama endpoint, llama3.2:latest model)

**Features**:

- Cross-platform config directory detection
- Automatic directory creation
- TOML serialization with pretty formatting
- Environment variable overrides for containerized deployments
- Provider-specific settings (Ollama HTTP endpoint and timeout)
- Thread-safe loading with error handling

**Usage Pattern**:

```rust
let config = AppConfig::load()?;
// Access chatbot settings
let endpoint = &config.chatbot.ollama.endpoint;
let active_model = config.chatbot.active_model();
println!("Using {} via {}", active_model.display_name, active_model.provider);
```

### 3. Chatbot Layer (`src/chatbot/`) - 5 files, 1,200+ lines

**Purpose**: Multi-model LLM integration with provider abstraction for pentesting assistance.

**Architecture**:

```text
chatbot/
├── mod.rs           # Module exports, ContextBuilder (122 lines)
├── provider.rs      # ChatProvider trait definition (15 lines)
├── request.rs       # ChatRequest and StepContext (40 lines)
├── service.rs       # ChatService router (157 lines)
└── ollama.rs       # OllamaProvider implementation (317 lines)
```

**Key Types**:

- `ChatService` - Main router with provider selection
- `ChatProvider` - Trait for different backends (Ollama)
- `ChatRequest` - Bundles step context, history, prompt, model profile
- `StepContext` - Current step context (phase, step, status, counts)
- `ModelProfile` - Model configuration with provider and parameters
- `ChatError` - Error types (ServiceUnavailable, Timeout, GgufPathNotFound)

**Provider Architecture**:

```rust
pub trait ChatProvider: Send + Sync {
    fn send_message(&self, request: &ChatRequest) -> Result<ChatMessage, ChatError>;
    fn check_availability(&self) -> bool;
    fn provider_name(&self) -> &'static str;
}
```

**Ollama Provider**:

- HTTP-based integration with `/api/chat` endpoint
- Availability check via `/api/tags`
- Configurable timeout and endpoint
- Handles connection errors, timeouts, invalid responses

**Configuration System**:

- **Model Profiles**: 5 seeded Ollama models + custom profiles
- **Provider Selection**: Based on `ModelProfile.provider` field
- **Parameters**: Per-model temperature, top_p, top_k, num_predict
- **Environment Variables**: Override all settings

**Core Methods**:

- `ChatService::new(config)` - Creates with configured providers
- `send_message(step_ctx, history, user_input)` - Routes to appropriate provider
- `ContextBuilder::build_session_context(session, phase_idx, step_idx)` - Summarizes session

**Testing**:

- 20+ provider tests (Ollama)
- httpmock for API mocking
- Provider routing verification
- Parameter handling validation
- Model caching tests
- Feature-gated testing (works without llama-cpp)

**Ollama Integration**:

- POST to `/api/chat` endpoint
- Payload: `{model, messages: [{role, content}, ...], stream: false}`
- System prompt includes pentesting methodology context
- Handles connection errors, timeouts, invalid responses

**Context Summarization**:

- Phase completion status (Completed/In Progress/Pending)
- Current step highlighted with `<-- CURRENT`
- Notes/evidence counts per step
- Quiz progress statistics
- Description snippets (200 char limit)

**Error Handling**:

- `ServiceUnavailable` - Ollama not running/connection failed
- `Timeout` - 30s request timeout exceeded
- `InvalidResponse` - Malformed Ollama/LLM response
- `UnsupportedProvider` - Configured provider not yet implemented in runtime
- Friendly error messages with setup instructions

**Testing**:

- httpmock for API mocking
- Validates system prompt inclusion
- Tests error path mapping
- Payload structure verification

### 4. Store Layer (`src/store.rs`) - 273 lines

**Purpose**: Session loading functionality.

**Key Functions**:

- `load_session(path)` - Loads from session.json

**Features**:

- Accepts folder path OR file path (auto-detects)
- Preserves timestamps and UUIDs exactly
- Handles Unicode (UTF-8) correctly
- Idempotent - overwriting is safe

### 3. Tools Layer (`src/tools/`) - 5 files, 2,413 lines

**Purpose**: Security tool integration and execution framework.

**Architecture**:

```text
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

### 4. UI Layer (`src/ui/`) - 12 files, 4,323 lines

**Purpose**: GTK4/libadwaita user interface.

**Component Architecture**:

- `main.rs` - Window assembly, 3-pane layout
- `state.rs` - AppModel (session, current_path, selected_phase/step)
- `handlers.rs` - Signal handlers (phase/step selection, tool execution, chat)
- `sidebar.rs` - Phase dropdown + step list
- `detail_panel.rs` - Tutorial/quiz content switcher with chat panel
- `chat_panel.rs` - Chat history, input, and message display
- `quiz_widget.rs` - MCQ display + statistics
- `tool_execution.rs` - Nmap/Gobuster UI with terminal output
- `header_bar.rs` - App toolbar (39 lines)
- `file_ops.rs` - File dialogs (async)

**Removed Components** (replaced by chatbot):

- `canvas.rs` - REMOVED: Evidence positioning (replaced by chat)
- `image_utils.rs` - REMOVED: Image loading (canvas dependency)
- `canvas_utils.rs` - REMOVED: Canvas helpers (no longer needed)

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
- Chat messages dispatched via event system

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
5. **Cloud IAM Abuse 101** (2 steps) - cloud_identity.rs
6. **Practical OAuth/OIDC Abuse** (1 step) - cloud_identity.rs
7. **SSO & Federation Misconfigurations** (1 step) - cloud_identity.rs
8. **API Security** (7 steps) - modern_web.rs
9. **Reporting** (4 steps) - reporting.rs
10. **Container & Kubernetes Security** (6 steps) - container_security.rs
11. **Serverless Security** (7 steps) - serverless_security.rs
12. **Bug Bounty Hunting** (8 steps) - bug_bounty_hunting.rs
13. **CompTIA Security+** (23 quiz steps) - comptia_secplus.rs
14. **CompTIA PenTest+** (32 quiz steps) - pentest_exam.rs
15. **Certified Ethical Hacker (CEH)** (24 quiz steps) - ceh.rs
16. **CI-CD Pipeline Attacks** (1 step) - cloud_native.rs
17. **SBOM Generation & Analysis** (1 step) - supply_chain.rs
18. **Dependency Confusion & Typosquatting** (1 step) - supply_chain.rs
19. **Artifact Integrity Checks** (1 step) - supply_chain.rs
20. **Red Team Tradecraft** (10 steps) - red_team_tradecraft.rs
21. **Purple Team/Threat Hunting** (10 steps) - purple_team_threat_hunting.rs
22. **AI & LLM Security** (7 steps) - ai_security.rs

**Content Structure**:

```text
OBJECTIVE: What you're trying to achieve
STEP-BY-STEP PROCESS: Commands and procedures
WHAT TO LOOK FOR: Expected findings
COMMON PITFALLS: Mistakes to avoid
DOCUMENTATION REQUIREMENTS: Evidence to capture
```

### 7. Quiz Layer (`src/quiz/mod.rs`) - 335 lines

**Purpose**: Quiz question parsing and validation.

**Format**: Pipe-delimited string (9 fields)

```text
question|optionA|optionB|optionC|optionD|correct_idx|explanation|domain|subdomain
```

**Example**:

```text
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
| `dirs` | 5.0 | Home directory detection |
| `pulldown-cmark` | 0.10 | Markdown parsing |
| `once_cell` | 1.0 | Lazy statics |
| `regex` | 1.0 | Pattern matching |
| `async-channel` | 2.0 | Async messaging |
| `toml` | 0.8 | TOML configuration format |

### Development Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `tempfile` | 3.8 | Temporary test directories |
| `assert_matches` | 1.5 | Pattern matching assertions |

## 🧪 Testing Infrastructure

### Test Organization

```text
tests/
├── support/                   # Shared test fixtures and utilities
│   └── domain.rs              # Domain model fixtures (legacy_step_with_data, quiz_step_fixture)
├── domain_model_tests.rs      # Model layer unit tests (Step, Phase, Quiz, Session)
├── store_tests.rs             # Persistence layer tests (JSON load/save)
├── session_content_tests.rs   # Session creation, content validation, performance tests
└── integration_tests.rs       # End-to-end workflow tests
```

### Test Coverage

- **Total Tests**: 194
- **Pass Rate**: 100%
- **Coverage Areas**:
  - Model layer: Session, Phase, Step, Evidence, Quiz (domain_model_tests.rs)
  - Store layer: Load, migration, folder structure (store_tests.rs)
  - Session content: Phase loading, content validation, performance (session_content_tests.rs)
  - Tools layer: Nmap (8 scan types), Gobuster (3 modes)
  - Quiz layer: Question parsing, progress tracking
  - Dispatcher: Event routing and handling
  - Tutorials: Phase loading, content validation
  - Integration: Full workflows, tool chains (integration_tests.rs)

### Testing Strategy

#### Domain and Quiz Tests

- Comprehensive unit tests for all business logic
- Property-based testing for edge cases
- Mock-free testing where possible

#### Executor Timeout Coverage

- Deterministic long-running commands (e.g., `python3 -c 'import time; time.sleep(1)'`)
- 100ms timeout assertions for quick failure detection
- Partial output collection verification on timeout
- Environment variable and working directory propagation tests

#### GTK-Lite UI Tests

- Handler logic testing without full GTK initialization
- State management validation with controlled inputs
- Event dispatcher testing with mock handlers
- Avoid blocking on GTK main loop in CI environments

### Running Tests

```bash
# All unit tests (production code tests)
cargo test --lib

# Domain model tests
cargo test --test domain_model_tests

# Store tests
cargo test --test store_tests

# Session content tests
cargo test --test session_content_tests

# Integration tests
cargo test --test integration_tests

# Specific test module
cargo test domain_model_tests::

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
let session = Session::default(); // 18 phases pre-loaded
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
| tutorials/ | 10 | 15,363 | Tutorial content |
| ui/ | 12 | 4,323 | User interface |
| model/ | 5 | 1,020 | Domain models (refactored) |
| tools/ | 5 | 995 | Tool integrations |
| lib.rs | 1 | 1,155 | Test suite |
| chatbot/ | 5 | 1,200+ | Multi-model LLM integration (Ollama, llama.cpp) |
| quiz/ | 1 | 335 | Quiz system |
| dispatcher.rs | 1 | 247 | Event system |
| config.rs | 1 | 200 | Configuration management |
| store.rs | 1 | 286 | Persistence |
| main.rs | 1 | 37 | Entry point |

**Total**: 52 files, 24,800 lines of Rust code

### Test Distribution

| Category | Tests | Coverage |
|----------|-------|----------|
| Domain Model Tests | 23 | Session, Phase, Step, Evidence, Quiz (domain_model_tests.rs) |
| Store Tests | 3 | Load, migration, Unicode (store_tests.rs) |
| Session Content Tests | 21 | Phase loading, content validation, performance (session_content_tests.rs) |
| Chatbot Tests | 25+ | Multi-provider integration, llama.cpp, Ollama, error handling |
| Tool Tests | 50+ | Nmap (8 types), Gobuster (3 modes) |
| Quiz Tests | 10+ | Parsing, progress, scoring |
| Dispatcher Tests | 8+ | Event routing, handlers |
| Tutorial Tests | 5+ | Phase loading, validation |
| Integration Tests | 11 | End-to-end workflows (integration_tests.rs) |
| UI Tests | 14 | Chat functionality, text input, state persistence |
| Controller Tests | 3 | Model filtering, step context building |
| Chat Provider Tests | 12 | Provider routing, model profiles |
| Test Runner Tests | 3 | Test execution framework |

**Total**: 242+ tests with 100% pass rate

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
| CODEBASE_INDEX.md | Root | This file | Comprehensive code reference |
| TOOL_INSTRUCTIONS_FEATURE.md | Root | - | Tool instruction system guide |
| docs/architecture.md | docs/ | - | System architecture details |
| docs/configuration.md | docs/ | - | Configuration system guide |
| docs/chatbot.md | docs/ | - | Chatbot integration guide |
| docs/roadmap.md | docs/ | - | Development roadmap |
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

- **Architecture**: See `CODEBASE_INDEX.md`
- **Extension Points**: This document, Extension Points section
- **Testing**: See test examples in `src/lib.rs`
- **Patterns**: Study existing tool integrations

### For Contributors

- **Getting Started**: See `CODEBASE_INDEX.md`
- **Development Plan**: (To be created)
- **Code Structure**: This document
- **API Contracts**: See `CODEBASE_INDEX.md`

---

**Last Updated**: November 27, 2025  
**Version**: v0.1.0  
**Maintainer**: PT Journal Development Team

---

*This codebase index provides comprehensive navigation and understanding of the PT Journal project structure, modules, patterns, and extension points.*
