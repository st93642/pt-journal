# PT Journal - AI Agent Instructions

> 📖 **Full architecture details:** See [`ARCHITECTURE.md`](../ARCHITECTURE.md) for comprehensive codebase index

## Project Overview

GTK4/Libadwaita desktop app for penetration testing education, built with **Rust**. Features 66+ tutorial phases (CEH, Security+, PenTest+, CISSP, forensics), pipe-delimited quiz system (1000+ questions), multi-provider LLM chatbot (Ollama/OpenAI/Azure), and 229+ security tool references.

## Architecture

**State Flow:** `UI Component` → `StateManager` → `AppModel` (via `Rc<RefCell<>>`) → `EventBus::emit()` → UI callbacks

```
src/
├── dispatcher.rs        # EventBus + AppEvent enum (PhaseSelected, QuizAnswerChecked, etc.)
├── error.rs             # PtError variants (thiserror) - use specific variants, not generic
├── ui/state.rs          # StateManager: coordinates model mutations + event dispatch
├── model/               # AppModel, Phase, Step, QuizStep, ChatMessage
├── chatbot/             # ChatProvider trait + ollama.rs, openai.rs, azure_openai.rs
├── quiz/mod.rs          # parse_question_line() for pipe-delimited format
├── tutorials/mod.rs     # load_tutorial_phases() → register JSON tutorials here
└── ui/tool_instructions.rs  # has_tool(), get_tool_instructions() → tool registry
```

**Why `Rc<RefCell<>>`?** GTK is single-threaded; provides safe interior mutability without `Arc<Mutex<>>` overhead. Use `Arc<RwLock<>>` only for thread-safe components like `ProviderRegistry`.

## Development Commands

```bash
./test-all.sh                       # Full suite: unit + integration + clippy + fmt + JSON validation
cargo test --test unit_tests        # Unit tests only (tests/unit/)
cargo test --test integration_tests # Integration tests (tests/integration/)
cargo run                           # Launch app (requires GTK4 libs)
cargo clippy                        # Linting
cargo fmt --check                   # Format check
```

**System deps (Ubuntu/Debian):** `libgtk-4-dev libadwaita-1-dev libvte-2.91-gtk4-dev`

## Data Formats

### Quiz Questions (`data/{domain}/*.txt`)
9 pipe-delimited fields - **all fields required, no empty values**:
```
question|answer_a|answer_b|answer_c|answer_d|correct_index(0-3)|explanation|domain|subdomain
```

### Tutorials (`data/tutorials/{id}.json`)
```json
{
  "id": "tutorial_id",
  "title": "Display Title",
  "type": "tutorial",
  "steps": [{
    "id": "step_id",
    "title": "Step Title",
    "content": "Markdown content...",
    "tags": ["lowercase-hyphenated"],
    "related_tools": ["tool-id-from-registry"]
  }]
}
```

**Registration required:** Add `load_tutorial_phase("tutorial_id")` to `src/tutorials/mod.rs` → `load_tutorial_phases()` vec.

**Quiz steps:** Use tag `"quiz"` + content `"Quiz content loaded from {path}"` to trigger quiz file loading.

**Tool validation:** `related_tools` IDs must exist in `src/ui/tool_instructions.rs` registry (validated by `./test-all.sh`).

## Key Patterns

### State Mutations (ALWAYS through StateManager)
```rust
// In UI code - never mutate AppModel directly
state_manager.select_phase(idx);           // Emits PhaseSelected + RefreshStepList
state_manager.check_answer(p, s, q, ans);  // Emits QuizAnswerChecked + QuizStatisticsUpdated
state_manager.add_chat_message(p, s, msg); // Emits ChatMessageAdded
```

### Error Handling
Use specific `PtError` variants from `src/error.rs`:
```rust
use crate::error::{PtError, Result as PtResult};
// PtError::InvalidPhaseIndex, InvalidStepIndex, Config, Chat, Validation, etc.
```

### Adding New Chat Provider
1. Implement `ChatProvider` trait in `src/chatbot/`:
```rust
pub trait ChatProvider: Send + Sync {
    fn send_message(&self, request: &ChatRequest) -> PtResult<ChatMessage>;
    fn check_availability(&self) -> PtResult<bool>;
    fn provider_name(&self) -> &str;
}
```
2. Register in `src/chatbot/registry.rs`
3. Add config struct in `src/config/loader.rs`

## Configuration

- **File:** `~/.config/pt-journal/config.toml`
- **Types:** `src/config/loader.rs` → `AppConfig`, `ChatbotConfig`, `ModelProfile`
- **Env overrides:** `PT_JOURNAL_*` prefix (e.g., `PT_JOURNAL_OPENAI_API_KEY`, `PT_JOURNAL_OLLAMA_ENDPOINT`)
- **Defaults:** Ollama at `http://localhost:11434`, model `llama3.2:latest`

## Test Organization

| Location | Purpose |
|----------|---------|
| `tests/unit/` | Module tests (chatbot, config, controllers, UI, tools) |
| `tests/integration/` | Cross-module integration scenarios |

Tests use `tempfile` for isolation. Run `./test-all.sh` before committing - includes JSON validation.
