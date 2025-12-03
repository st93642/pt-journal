# PT Journal - AI Agent Instructions

## Project Overview

GTK4/Libadwaita desktop app for penetration testing education, built with **Rust + Relm4**. Features interactive tutorials (CEH, Security+, PenTest+), pipe-delimited quiz system, multi-provider LLM chatbot, and 229+ security tool references.

## Architecture

**State Flow:** UI → `StateManager` → `AppModel` (via `Rc<RefCell<>>`) → `EventBus` → UI updates

```
src/
├── main.rs              # GTK Application entry
├── dispatcher.rs        # EventBus with AppEvent enum (PhaseSelected, ChatMessageAdded, etc.)
├── error.rs             # PtError enum (use thiserror), Result<T> alias
├── ui/state.rs          # StateManager: mutates model, emits events
├── model/app_model.rs   # AppModel: Session, Phase, Step, Quiz state
├── chatbot/             # LLM providers: ollama.rs, openai.rs, azure_openai.rs
│   └── provider.rs      # ChatProvider trait (implement for new backends)
├── quiz/mod.rs          # parse_question_line() for pipe-delimited quizzes
└── tutorials/mod.rs     # load_tutorial_phases() loads JSON from data/tutorials/
```

**Why Rc<RefCell<>>?** GTK is single-threaded; this pattern provides safe interior mutability.

## Development Commands

```bash
./test-all.sh                      # Full suite: unit + integration + clippy + fmt + JSON validation
cargo test --test unit_tests       # Unit tests only (tests/unit/)
cargo test --test integration_tests # Integration tests (tests/integration/)
cargo run                          # Launch app (requires GTK4 + libadwaita system libs)
```

**System deps:** `libgtk-4-dev libadwaita-1-dev libvte-2.91-gtk4-dev` (Ubuntu/Debian)

## Data Formats

### Quiz Questions (`data/{domain}/{subdomain}.txt`)
9 pipe-delimited fields per line:
```
question|answer_a|answer_b|answer_c|answer_d|correct_index|explanation|domain|subdomain
```
Example: `What is CIA triad?|Confidentiality...|...|...|...|0|The CIA triad...|ceh|linux-basics`

### Tutorials (`data/tutorials/{name}.json`)
```json
{
  "id": "linux_basics_for_hackers",
  "title": "Linux Basics for Hackers",
  "type": "tutorial",
  "steps": [{ "id": "step_id", "title": "Step", "content": "...", "tags": [], "related_tools": [] }]
}
```
**Register new tutorials** in `src/tutorials/mod.rs` → `load_tutorial_phases()` vec.

## Key Patterns

### Adding UI Components
1. Create in `src/ui/`, use `StateManager` for mutations
2. Emit `AppEvent` variants for cross-component updates
3. Handle events via `EventBus` callbacks in `dispatcher.rs`

### Error Handling
Always use `PtError` variants from `src/error.rs`:
```rust
use crate::error::{PtError, Result as PtResult};
// Return PtError::InvalidPhaseIndex, PtError::Chat, PtError::Config, etc.
```

### New Chat Provider
Implement `ChatProvider` trait in `src/chatbot/`:
```rust
pub trait ChatProvider: Send + Sync {
    fn send_message(&self, request: &ChatRequest) -> PtResult<ChatMessage>;
    fn check_availability(&self) -> PtResult<bool>;
    fn provider_name(&self) -> &str;
}
```
Register in `src/chatbot/registry.rs`.

## Configuration

- **File:** `~/.config/pt-journal/config.toml`
- **Types:** `src/config/config.rs` → `AppConfig`, `ChatbotConfig`
- **Env overrides:** `PT_JOURNAL_*` prefix (e.g., `PT_JOURNAL_OPENAI_API_KEY`)
- **Defaults:** Ollama at `http://localhost:11434`, model `llama3.2:latest`

## Test Organization

| Location | Purpose |
|----------|---------|
| `tests/unit/` | Module tests (chatbot, config, controllers, UI, tools) |
| `tests/integration/` | Cross-module integration scenarios |

Tests use `tempfile` crate for isolation. Mock HTTP with `httpmock`.
