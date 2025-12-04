# PT Journal - Codebase Architecture Index

> **GTK4/Libadwaita desktop application** for penetration testing education, built with **Rust**.
> 66+ tutorial phases | 1000+ quiz questions | Multi-provider LLM chatbot | 229+ security tools

---

## Quick Reference

| What | Where | Command |
|------|-------|---------|
| Run app | `cargo run` | Requires GTK4 system libs |
| Full test suite | `./test-all.sh` | Unit + integration + clippy + fmt + JSON |
| Unit tests only | `cargo test --test unit_tests` | |
| Config file | `~/.config/pt-journal/config.toml` | |
| Tutorial data | `data/tutorials/*.json` | |
| Quiz data | `data/{domain}/*.txt` | Pipe-delimited |

**System Dependencies (Ubuntu/Debian):**

```bash
sudo apt install libgtk-4-dev libadwaita-1-dev libvte-2.91-gtk4-dev
```

---

## 1. Core Architecture

### State Flow Pattern

```text
┌─────────────┐    ┌──────────────┐    ┌─────────────────────┐    ┌──────────┐
│ UI Component│───▶│ StateManager │───▶│ AppModel            │───▶│ EventBus │
│ (GTK Widget)│    │ (Coordinator)│    │ (Rc<RefCell<...>>)  │    │ emit()   │
└─────────────┘    └──────────────┘    └─────────────────────┘    └────┬─────┘
                                                                       │
       ┌───────────────────────────────────────────────────────────────┘
       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ UI Callbacks: on_phase_selected, on_quiz_answer_checked, on_chat_message... │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Why `Rc<RefCell<>>`?** GTK is single-threaded; this pattern provides safe interior mutability without `Arc<Mutex<>>` overhead.

### Module Organization

```text
src/
├── main.rs              # GTK Application entry point
├── lib.rs               # Public module exports
├── dispatcher.rs        # EventBus + AppEvent enum
├── error.rs             # PtError variants (thiserror)
├── store.rs             # Session persistence
├── support.rs           # Utility functions
│
├── model/               # Domain model layer
│   ├── mod.rs           # Re-exports
│   ├── app_model.rs     # AppModel, StepSummary, ActiveStepSnapshot
│   ├── session.rs       # Session (phases container)
│   ├── step.rs          # Phase, Step, StepStatus
│   ├── quiz.rs          # QuizStep, QuizQuestion, QuestionProgress
│   └── chat.rs          # ChatMessage, ChatRole
│
├── ui/                  # GTK4 UI layer
│   ├── mod.rs           # Module declarations
│   ├── main.rs          # build_ui() - 3-column layout
│   ├── state.rs         # StateManager (coordinates model + events)
│   ├── sidebar.rs       # Phase selector + step list
│   ├── detail_panel.rs  # Step content view (tutorial/quiz)
│   ├── chat_panel.rs    # LLM chat interface
│   ├── quiz_widget.rs   # Quiz question display
│   ├── header_bar.rs    # App header
│   ├── handlers.rs      # Event wiring
│   ├── tool_instructions.rs  # Tool registry + display
│   ├── controllers/     # Business logic controllers
│   └── tool_execution/  # Tool execution panel
│
├── chatbot/             # LLM provider system
│   ├── mod.rs           # ContextBuilder, re-exports
│   ├── provider.rs      # ChatProvider trait
│   ├── registry.rs      # ProviderRegistry
│   ├── service.rs       # ChatService
│   ├── request.rs       # ChatRequest, StepContext
│   ├── ollama.rs        # OllamaProvider
│   ├── openai.rs        # OpenAIProvider
│   └── azure_openai.rs  # AzureOpenAIProvider
│
├── config/              # Configuration system
│   ├── mod.rs           # Re-exports
│   ├── loader.rs        # AppConfig, ChatbotConfig, ModelProfile
│   ├── validation.rs    # ValidationError enum
│   └── validator.rs     # Validation functions
│
├── quiz/                # Quiz parsing
│   └── mod.rs           # parse_question_line(), parse_question_file()
│
├── tutorials/           # Tutorial loading
│   └── mod.rs           # load_tutorial_phases(), load_tutorial_phase()
│
└── tools/               # Tool registry
    ├── mod.rs           # Re-exports
    ├── registry.rs      # ToolRegistry
    └── traits.rs        # ToolConfig, ToolResult
```

---

## 2. Model Layer (`src/model/`)

### AppModel - Root State

```rust
pub struct AppModel {
    session: Session,                    // All phases and steps
    selected_phase: usize,               // Currently selected phase index
    selected_step: Option<usize>,        // Currently selected step index
    current_path: Option<PathBuf>,       // Session file path
    config: AppConfig,                   // Application configuration
    active_chat_model_id: String,        // Active LLM model
}
```

**Key Methods:**

```rust
// Navigation (validates indices, returns PtResult)
model.select_phase(idx) -> PtResult<()>
model.select_step(idx) -> PtResult<()>

// State mutations
model.update_step_status(phase_idx, step_idx, StepStatus) -> PtResult<()>
model.add_chat_message(phase_idx, step_idx, ChatMessage) -> PtResult<()>

// Queries (for UI rendering)
model.get_step_summaries_for_phase(idx) -> Vec<StepSummary>
model.get_active_step_snapshot() -> Option<ActiveStepSnapshot>
```

### Session & Phase

```rust
pub struct Session {
    pub phases: Vec<Phase>,  // All tutorial phases
}

pub struct Phase {
    pub id: Uuid,
    pub name: String,
    pub steps: Vec<Step>,
}

impl Default for Session {
    fn default() -> Self {
        Session { phases: load_tutorial_phases() }  // Loads all 66+ phases
    }
}
```

### Step Model

```rust
pub struct Step {
    pub id: Uuid,
    pub title: String,
    pub tags: Vec<String>,               // ["linux", "basics", "file-operations"]
    pub status: StepStatus,              // Todo | InProgress | Done | Skipped
    pub completed_at: Option<DateTime<Utc>>,
    pub description: String,             // Markdown content
    pub chat_history: Vec<ChatMessage>,  // Per-step chat history
    pub related_tools: Vec<String>,      // Tool IDs from registry
    pub quiz_data: Option<QuizStep>,     // Present only for quiz steps
}

// Constructors
Step::new_tutorial_with_tools(id, title, description, tags, related_tools)
Step::new_quiz(id, title, tags, QuizStep)

// Type checks
step.is_tutorial() -> bool
step.is_quiz() -> bool
step.quiz_mut_safe() -> Option<&mut QuizStep>
```

### Quiz Model

```rust
pub struct QuizStep {
    pub id: Uuid,
    pub title: String,
    pub domain: String,
    pub questions: Vec<QuizQuestion>,
    pub progress: Vec<QuestionProgress>,  // Parallel to questions
}

pub struct QuizQuestion {
    pub id: Uuid,
    pub question_text: String,
    pub answers: Vec<QuizAnswer>,  // Typically 4 (A-D)
    pub explanation: String,
    pub domain: String,            // "1.0 General Security Concepts"
    pub subdomain: String,         // "1.1 Security Controls"
}

pub struct QuestionProgress {
    pub answered: bool,
    pub selected_answer_index: Option<usize>,
    pub is_correct: Option<bool>,
    pub explanation_viewed_before_answer: bool,
    pub first_attempt_correct: bool,
    pub attempts: u32,
    pub last_attempted: Option<DateTime<Utc>>,
}

// Scoring: Points awarded ONLY if first_attempt_correct && !explanation_viewed_before_answer
progress.awards_points() -> bool
```

### Chat Model

```rust
pub struct ChatMessage {
    pub role: ChatRole,    // User | Assistant | System
    pub content: String,
    pub timestamp: DateTime<Utc>,
}

impl ChatMessage {
    pub fn new(role: ChatRole, content: String) -> Self
    pub fn user(content: String) -> Self
    pub fn assistant(content: String) -> Self
}
```

---

## 3. Event System (`src/dispatcher.rs`)

### AppEvent Enum

```rust
pub enum AppEvent {
    // Navigation
    PhaseSelected(usize),
    StepSelected(usize),

    // Session Operations
    SessionLoaded(PathBuf),
    SessionSaved(PathBuf),
    SessionCreated,

    // Step Status
    StepCompleted(usize, usize),           // (phase_idx, step_idx)
    StepStatusChanged(usize, usize, StepStatus),

    // Chat Operations
    ChatMessageAdded(usize, usize, ChatMessage),
    ChatRequestStarted(usize, usize),
    ChatRequestCompleted(usize, usize),
    ChatRequestFailed(usize, usize, String),
    ChatModelChanged(String),

    // UI Refresh
    RefreshStepList(usize),
    RefreshDetailView(usize, usize),

    // Quiz Operations
    QuizAnswerChecked(usize, usize, usize, bool),  // (phase, step, question, correct)
    QuizExplanationViewed(usize, usize, usize),
    QuizQuestionChanged(usize, usize, usize),
    QuizStatisticsUpdated(usize, usize),

    // Notifications
    Error(String),
    Info(String),
}
```

### EventBus

```rust
pub struct EventBus {
    pub on_phase_selected: Box<dyn Fn(usize)>,
    pub on_step_selected: Box<dyn Fn(usize)>,
    pub on_chat_message_added: Box<dyn Fn(usize, usize, ChatMessage)>,
    pub on_quiz_answer_checked: Box<dyn Fn(usize, usize, usize, bool)>,
    // ... one field per event type
}

impl EventBus {
    pub fn emit(&self, event: AppEvent)  // Routes via pattern match
    
    // Builder pattern
    pub fn with_phase_selected<F>(self, handler: F) -> Self
    pub fn with_error<F>(self, handler: F) -> Self
}

pub type SharedEventBus = Rc<RefCell<EventBus>>;
pub fn create_event_bus() -> SharedEventBus
```

---

## 4. UI Layer (`src/ui/`)

### StateManager - Coordination Layer

```rust
pub struct StateManager {
    model: SharedModel,           // Rc<RefCell<AppModel>>
    dispatcher: SharedEventBus,   // Rc<RefCell<EventBus>>
}

impl StateManager {
    // Navigation (mutates model + emits events)
    pub fn select_phase(&self, phase_idx: usize)
    pub fn select_step(&self, step_idx: usize)
    
    // Status updates
    pub fn update_step_status(&self, phase_idx, step_idx, StepStatus)
    pub fn toggle_step_completion(&self, phase_idx, step_idx)
    
    // Chat operations
    pub fn add_chat_message(&self, phase_idx, step_idx, ChatMessage)
    pub fn start_chat_request(&self, phase_idx, step_idx)
    pub fn complete_chat_request(&self, phase_idx, step_idx)
    pub fn fail_chat_request(&self, phase_idx, step_idx, error: String)
    
    // Quiz operations
    pub fn check_answer(&self, phase_idx, step_idx, question_idx, answer_idx) -> Option<bool>
    pub fn view_explanation(&self, phase_idx, step_idx, question_idx)
    pub fn change_quiz_question(&self, phase_idx, step_idx, question_idx)
    
    // Model access
    pub fn set_chat_model(&self, model_id: String)
    pub fn model(&self) -> SharedModel  // For read-only access
}
```

**Usage Pattern:**

```rust
// In UI code - NEVER mutate AppModel directly
state_manager.select_phase(idx);           // Emits PhaseSelected + RefreshStepList
state_manager.check_answer(p, s, q, ans);  // Emits QuizAnswerChecked + QuizStatisticsUpdated
state_manager.add_chat_message(p, s, msg); // Emits ChatMessageAdded
```

### UI Components

| Component | File | Purpose |
|-----------|------|---------|
| `build_ui()` | `main.rs` | Creates 3-column layout with sidebar, detail, tool panel |
| `create_sidebar()` | `sidebar.rs` | Phase selector dropdown + step list |
| `create_detail_panel()` | `detail_panel.rs` | Tutorial content or quiz widget |
| `create_chat_panel()` | `chat_panel.rs` | LLM chat with model selector |
| `QuizWidget` | `quiz_widget.rs` | Question display, A/B/C/D answers, navigation |
| `create_header_bar()` | `header_bar.rs` | App title, sidebar toggle |
| `ToolInstructions` | `tool_instructions.rs` | Tool documentation display |

### Controllers (`src/ui/controllers/`)

| Controller | Purpose |
|------------|---------|
| `NavigationController` | Phase/step selection logic |
| `QuizController` | Answer checking, question navigation, statistics |
| `ChatController` | Async model population, threaded requests, response polling |
| `ToolPanelController` | Tool execution panel binding |

---

## 5. Chatbot System (`src/chatbot/`)

### ChatProvider Trait

```rust
pub trait ChatProvider: Send + Sync {
    fn send_message(&self, request: &ChatRequest) -> PtResult<ChatMessage>;
    fn check_availability(&self) -> PtResult<bool>;
    fn provider_name(&self) -> &str;
    fn list_available_models(&self) -> PtResult<Vec<String>> { Ok(Vec::new()) }
}
```

### Provider Implementations

| Provider | File | Endpoints | Authentication |
|----------|------|-----------|----------------|
| `OllamaProvider` | `ollama.rs` | `/api/generate`, `/api/tags` | None |
| `OpenAIProvider` | `openai.rs` | `/chat/completions`, `/models` | `Authorization: Bearer` |
| `AzureOpenAIProvider` | `azure_openai.rs` | `/deployments/{name}/chat/completions` | `api-key` header |

### ChatRequest Structure

```rust
pub struct ChatRequest {
    pub model_id: String,
    pub messages: Vec<ChatMessage>,   // Full history
    pub step_context: StepContext,    // Current step info
    pub session_summary: String,      // Built by ContextBuilder
}

pub struct StepContext {
    pub phase_name: String,
    pub step_title: String,
    pub step_description: String,
    pub tags: Vec<String>,
}
```

### Adding a New Provider

1. Create `src/chatbot/{provider_name}.rs`
2. Implement `ChatProvider` trait
3. Add config struct to `src/config/loader.rs`:

   ```rust
   pub struct NewProviderConfig {
       pub api_key: Option<String>,
       pub endpoint: String,
       pub timeout_seconds: u64,
   }
   ```

4. Add to `ChatbotConfig`:

   ```rust
   pub struct ChatbotConfig {
       // ...existing fields...
       pub new_provider: NewProviderConfig,
   }
   ```

5. Register in `src/chatbot/registry.rs`

---

## 6. Configuration (`src/config/`)

### Configuration Hierarchy (highest to lowest priority)

1. **Environment variables** (`PT_JOURNAL_*`)
2. **TOML config file** (`~/.config/pt-journal/config.toml`)
3. **Default values** (in `loader.rs`)

### AppConfig Structure

```rust
pub struct AppConfig {
    pub chatbot: ChatbotConfig,
}

pub struct ChatbotConfig {
    pub default_model_id: String,        // Default: "llama3.2:latest"
    pub models: Vec<ModelProfile>,       // Available models
    pub ollama: OllamaProviderConfig,
    pub openai: OpenAIProviderConfig,
    pub azure_openai: AzureOpenAIProviderConfig,
}

pub struct ModelProfile {
    pub id: String,                      // "gpt-4o", "llama3.2:latest"
    pub display_name: String,            // "GPT-4o (OpenAI)"
    pub provider: ModelProviderKind,     // Ollama | OpenAI | AzureOpenAI
    pub prompt_template: String,
    pub parameters: ModelParameters,
}
```

### Environment Variables

| Variable | Config Path | Default |
|----------|-------------|---------|
| `PT_JOURNAL_CHATBOT_MODEL_ID` | `chatbot.default_model_id` | `llama3.2:latest` |
| `PT_JOURNAL_OLLAMA_ENDPOINT` | `chatbot.ollama.endpoint` | `http://localhost:11434` |
| `PT_JOURNAL_OLLAMA_TIMEOUT_SECONDS` | `chatbot.ollama.timeout_seconds` | `180` |
| `PT_JOURNAL_OPENAI_API_KEY` | `chatbot.openai.api_key` | None |
| `PT_JOURNAL_OPENAI_ENDPOINT` | `chatbot.openai.endpoint` | `https://api.openai.com/v1` |
| `PT_JOURNAL_AZURE_OPENAI_API_KEY` | `chatbot.azure_openai.api_key` | None |
| `PT_JOURNAL_AZURE_OPENAI_ENDPOINT` | `chatbot.azure_openai.endpoint` | None |
| `PT_JOURNAL_AZURE_OPENAI_DEPLOYMENT` | `chatbot.azure_openai.deployment_name` | None |

### Sample config.toml

```toml
[chatbot]
default_model_id = "gpt-4o"

[chatbot.ollama]
endpoint = "http://localhost:11434"
timeout_seconds = 180

[chatbot.openai]
api_key = "sk-..."
endpoint = "https://api.openai.com/v1"
timeout_seconds = 120

[chatbot.azure_openai]
api_key = "..."
endpoint = "https://your-resource.openai.azure.com"
deployment_name = "gpt-4o"
api_version = "2024-02-15-preview"
```

---

## 7. Error Handling (`src/error.rs`)

### PtError Variants

```rust
pub enum PtError {
    // Configuration
    Config { message: String, source: Option<Box<dyn Error>> },
    ConfigFileNotFound { path: String },
    ConfigFormat { message: String },

    // State Management
    InvalidPhaseIndex { phase_idx: usize },
    InvalidStepIndex { phase_idx: usize, step_idx: usize },
    InvalidQuestionIndex { phase_idx: usize, step_idx: usize, question_idx: usize },
    StateMutation { message: String },

    // UI
    UiHandler { message: String },
    InvalidUiState { message: String },

    // Chat/LLM
    Chat { message: String, source: Option<Box<dyn Error>> },
    ChatModelNotFound { model_id: String },
    ChatServiceUnavailable { message: String },
    Network { message: String },
    Provider { provider: String, message: String },

    // I/O
    Io { message: String, source: Option<Box<dyn Error>> },
    FileNotFound { path: String },

    // Tools
    Tool { message: String },
    ToolNotFound { tool_id: String },
    ToolExecution { tool_id: String, message: String },

    // Validation
    Validation { message: String },
    MissingRequiredField { field: String },
    InvalidFieldValue { field: String, message: String },
    DuplicateEntry { entry: String },

    // Generic
    Internal { message: String },
    NotSupported { operation: String },
    Timeout { operation: String },
}
```

### Usage

```rust
use crate::error::{PtError, Result as PtResult};

fn some_operation() -> PtResult<()> {
    if phase_idx >= phases.len() {
        return Err(PtError::InvalidPhaseIndex { phase_idx });
    }
    // ...
    Ok(())
}

// Helper constructors
PtError::config("message")
PtError::config_with_source("message", source_error)
PtError::validation("message")
PtError::network("message")

// Type checks
error.is_not_found()
error.is_validation_error()
error.is_config_error()
```

---

## 8. Data Formats

### Quiz Questions (`data/{domain}/*.txt`)

**Format:** 9 pipe-delimited fields per line (all required, no empty values)

```text
question|answer_a|answer_b|answer_c|answer_d|correct_index(0-3)|explanation|domain|subdomain
```

**Example:**

```text
Which type of security control is a firewall?|Detective|Technical|Administrative|Compensating|1|A firewall is a technical control that filters network traffic.|1.0 General Security Concepts|1.1 Security Controls
```

**Parser:** `src/quiz/mod.rs` → `parse_question_line()`, `parse_question_file()`

### Tutorial JSON (`data/tutorials/{id}.json`)

```json
{
  "id": "linux_basics_for_hackers",
  "title": "Linux Basics for Hackers",
  "type": "tutorial",
  "steps": [
    {
      "id": "file_operations",
      "title": "Essential File Operations",
      "content": "OBJECTIVE: Master fundamental file manipulation...\n\nSTEP-BY-STEP PROCESS:\n...",
      "tags": ["linux", "basics", "file-operations"],
      "related_tools": ["linux-exploit-suggester", "linux-smart-enumeration"]
    }
  ]
}
```

**Tag Conventions:**

- Lowercase with hyphens: `"web-exploitation"`, `"privilege-escalation"`
- No spaces or uppercase

**Related Tools:**

- Tool IDs must exist in `src/ui/tool_instructions.rs` registry
- Validated during `./test-all.sh`

### Quiz Step Detection

Quiz steps are identified by:

1. Tag `"quiz"` in `tags` array
2. Content starting with `"Quiz content loaded from "` → triggers file loading

```json
{
  "id": "security_controls_quiz",
  "title": "Security Controls Quiz",
  "content": "Quiz content loaded from comptia_secplus/1.0-general-security/1.1-security-controls.txt",
  "tags": ["quiz", "comptia-security-plus"]
}
```

---

## 9. Tutorial System (`src/tutorials/mod.rs`)

### Loading Functions

```rust
pub fn load_tutorial_phases() -> Vec<Phase>  // Returns all 66+ phases
fn load_tutorial_phase(phase_name: &str) -> Phase  // Loads single phase from JSON
fn load_quiz_from_file(file_path: &str) -> Result<Vec<QuizQuestion>, String>
```

### Phase Order (66 phases)

| Section | Phases | Topics |
|---------|--------|--------|
| 1. Foundational Skills | 1-7 | Linux basics, networking, WiFi, password cracking, Python, reverse shells |
| 2. Core PT Methodology | 8-17 | Recon → vulnerability analysis → web security → exploitation → post-exploitation |
| 3. CTF Labs | 18-19 | Linux CTF, Windows CTF |
| 4. Forensics & Threat Intel | 20-28 | CTI, disk/memory/network forensics, incident response |
| 5. Modern Security | 29-36 | Cloud IAM, OAuth, SSO, API, web, container, serverless |
| 6. Advanced Topics | 37-41 | Supply chain, red team, purple team, bug bounty |
| 7. AI-Augmented PT | 42-50 | GenAI recon, scanning, exploitation, reporting |
| 8. Reporting | 51 | |
| 9. SOC Operations | 52-56 | Splunk, Elastic SIEM, Wazuh, Sigma rules |
| 10. Certification Prep | 57-66 | CompTIA Security+, PenTest+, CEH, CISSP Domains 1-8 |

### Adding a New Tutorial

1. Create `data/tutorials/{tutorial_id}.json`
2. Register in `src/tutorials/mod.rs` → `load_tutorial_phases()` vec:

   ```rust
   vec![
       // ... existing phases ...
       load_tutorial_phase("your_new_tutorial"),
   ]
   ```

3. Run `./test-all.sh` to validate JSON and tool references

---

## 10. Tool System

### Tool Instructions (`src/ui/tool_instructions.rs`)

**Manifest:** `data/tool_instructions/manifest.json`
**Instructions:** `data/tool_instructions/categories/{category}/{tool}.json`

```rust
// API functions
get_tool_manifest() -> &[ToolManifestEntry]
get_tools_by_category(category: &str) -> Vec<ToolManifestEntry>
has_tool(tool_id: &str) -> bool
get_tool_instructions(tool_id: &str) -> Option<&ToolInstructions>
```

### ToolInstructions Structure

```rust
pub struct ToolInstructions {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub details: Option<String>,
    pub installation_guides: Vec<InstallationGuide>,  // ≥3 platforms
    pub quick_examples: Vec<CommandExample>,
    pub step_sequences: Vec<InstructionSequence>,     // Required
    pub workflow_guides: Vec<WorkflowGuide>,          // Required
    pub output_notes: Vec<OutputNote>,                // Required
    pub common_flags: Vec<FlagEntry>,
    pub operational_tips: Vec<String>,
    pub advanced_usage: Vec<AdvancedExample>,         // Required
    pub comparison_table: Option<ComparisonTable>,
    pub resources: Vec<ResourceLink>,
}
```

### Basic Tool Registry (`src/tools/`)

```rust
pub struct ToolRegistry {
    available_tools: HashSet<String>,
}

impl ToolRegistry {
    pub fn register_instructions(&mut self, tool_id: &str)
    pub fn has_instructions(&self, tool_id: &str) -> bool
    pub fn list_tools(&self) -> Vec<&String>
    pub fn count(&self) -> usize
}

pub struct ToolConfig {
    pub target: Option<String>,
    pub arguments: Vec<String>,
    pub timeout: Option<Duration>,
    pub working_dir: Option<PathBuf>,
    pub env_vars: HashMap<String, String>,
}
```

---

## 11. Test Organization

### Test Commands

```bash
./test-all.sh                       # Full suite (recommended before commits)
cargo test --test unit_tests        # Unit tests only
cargo test --test integration_tests # Integration tests (requires GTK)
cargo clippy                        # Linting
cargo fmt --check                   # Format check
```

### Unit Tests (`tests/unit/`)

| File | Tests |
|------|-------|
| `chatbot_unit_tests.rs` | Provider implementations, request building |
| `chat_provider_tests.rs` | Provider trait compliance |
| `config_validation_tests.rs` | Manifest/config validation, cross-references |
| `controller_tests.rs` | Controller logic |
| `domain_model_tests.rs` | Step, Phase, QuizStep, ChatMessage, statistics |
| `related_tools_tests.rs` | Tool reference validation |
| `session_content_tests.rs` | Session/phase content |
| `store_tests.rs` | State persistence |
| `tool_execution_unit_tests.rs` | Tool execution logic |
| `tool_registry_tests.rs` | Tool registry operations |
| `ui_tests.rs` | UI component unit tests |

### Integration Tests (`tests/integration/`)

| File | Tests |
|------|-------|
| `integration_tests.rs` | Config defaults, Session creation, ChatService routing, AppModel navigation, GTK widget creation |

---

## 12. Key Patterns & Conventions

### State Mutations

**Always use StateManager** - never mutate `AppModel` directly in UI code:

```rust
// ✅ Correct
state_manager.select_phase(idx);
state_manager.check_answer(phase_idx, step_idx, question_idx, answer_idx);

// ❌ Wrong - bypasses event system
model.borrow_mut().select_phase(idx);
```

### Error Handling

Use specific `PtError` variants:

```rust
// ✅ Correct - specific variant
Err(PtError::InvalidPhaseIndex { phase_idx })
Err(PtError::ChatServiceUnavailable { message: "Ollama not running".into() })

// ❌ Avoid - generic errors
Err(PtError::Internal { message: "something went wrong".into() })
```

### Shared State Types

```rust
// GTK single-threaded context
pub type SharedModel = Rc<RefCell<AppModel>>;
pub type SharedEventBus = Rc<RefCell<EventBus>>;

// Thread-safe (for ProviderRegistry)
pub type SharedRegistry = Arc<RwLock<ProviderRegistry>>;
```

### Quiz Scoring Logic

Points awarded only when:

```rust
progress.first_attempt_correct == true && 
progress.explanation_viewed_before_answer == false
```

### Chat History

Each step maintains its own `chat_history: Vec<ChatMessage>` - not shared across steps.

### Tag Format

- Lowercase with hyphens: `"linux"`, `"privilege-escalation"`, `"web-exploitation"`
- No spaces, no uppercase

---

## 13. File Quick Reference

| Purpose | Location |
|---------|----------|
| App entry | `src/main.rs` |
| Event types | `src/dispatcher.rs` → `AppEvent` |
| Error types | `src/error.rs` → `PtError` |
| State coordinator | `src/ui/state.rs` → `StateManager` |
| Root model | `src/model/app_model.rs` → `AppModel` |
| Quiz parsing | `src/quiz/mod.rs` → `parse_question_line()` |
| Tutorial loading | `src/tutorials/mod.rs` → `load_tutorial_phases()` |
| Chat providers | `src/chatbot/{ollama,openai,azure_openai}.rs` |
| Config loading | `src/config/loader.rs` → `AppConfig::load()` |
| Tool registry | `src/ui/tool_instructions.rs` → `has_tool()`, `get_tool_instructions()` |
| Tutorial data | `data/tutorials/*.json` |
| Quiz data | `data/{domain}/*.txt` |
| Tool instructions | `data/tool_instructions/` |
| Config file | `~/.config/pt-journal/config.toml` |

---

## 14. Common Tasks

### Add a New Tutorial

1. Create `data/tutorials/my_tutorial.json`
2. Add to `src/tutorials/mod.rs`:

   ```rust
   load_tutorial_phase("my_tutorial"),
   ```

3. Run `./test-all.sh`

### Add Quiz Questions

1. Create/edit `data/{domain}/my_quiz.txt`
2. Format: `question|a|b|c|d|correct_idx|explanation|domain|subdomain`
3. Reference from tutorial JSON with `"Quiz content loaded from {domain}/my_quiz.txt"`

### Add a Chat Provider

1. Create `src/chatbot/my_provider.rs`
2. Implement `ChatProvider` trait
3. Add config to `src/config/loader.rs`
4. Register in `src/chatbot/registry.rs`

### Add a Security Tool

1. Add to `data/tool_instructions/manifest.json`
2. Create `data/tool_instructions/categories/{category}/{tool}.json`
3. Reference via `related_tools` in tutorial steps

### Debug State Flow

1. Add logging in `StateManager` methods
2. Check `EventBus` callback registration in `src/ui/handlers.rs`
3. Verify `AppEvent` dispatch in `src/dispatcher.rs`
