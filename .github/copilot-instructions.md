# PT Journal - AI Agent Instructions

## Project Overview

PT Journal is a **GTK4/Libadwaita desktop application** for penetration testing education and journaling. Built in Rust with the Relm4 framework, it provides:
- Interactive tutorials covering security domains (CEH, CompTIA Security+, PenTest+)
- Quiz system with pipe-delimited question files
- Integrated chatbot for AI-assisted learning (Ollama/LLM backends)
- Tool instruction registry for security tools

## Architecture

### Core Layers
```
main.rs → GTK Application Entry
├── ui/ → GTK4 widgets (Relm4 components)
│   ├── state.rs → StateManager coordinates model + events
│   ├── chat_panel.rs → LLM chat interface
│   └── quiz_widget.rs → Interactive quizzes
├── model/ → Domain types (Session, Phase, Step, Quiz)
├── dispatcher.rs → Event bus (AppEvent enum + EventBus)
├── chatbot/ → LLM provider abstraction
│   ├── provider.rs → ChatProvider trait
│   └── ollama.rs → Ollama API implementation
└── tutorials/mod.rs → JSON tutorial loading
```

### Data Flow Pattern
1. **UI Actions** → `StateManager` methods
2. **StateManager** mutates `AppModel` (via `Rc<RefCell<AppModel>>`)
3. **StateManager** emits `AppEvent` through `SharedEventBus`
4. **Event handlers** update UI widgets

### Key Design Decisions
- **Rc<RefCell<>>** for shared mutable state (GTK single-threaded)
- **Event-driven** architecture via `dispatcher.rs` EventBus
- **Lazy loading** for quiz questions (large datasets)
- **JSON tutorials** in `data/tutorials/*.json` loaded at runtime

## Development Workflow

### Build & Test
```bash
# Full test suite (unit + integration + linting)
./test-all.sh

# Individual test targets
cargo test --test unit_tests      # Unit tests
cargo test --test integration_tests  # Integration tests
cargo clippy && cargo fmt         # Lint + format
```

### Test Organization
- `tests/unit/` - Module-level tests (chat, config, controllers, UI)
- `tests/integration/` - Cross-module integration tests
- Tests use `tempfile` crate for isolation

## Conventions

### Error Handling
- Use `src/error.rs` → `PtError` enum with `thiserror`
- Return `Result<T>` type alias from `error.rs`
- Structured error variants: `PtError::InvalidPhaseIndex`, `PtError::Chat`, etc.

### Adding Quiz Questions
Quiz files use pipe-delimited format (9 fields):
```
question|answer_a|answer_b|answer_c|answer_d|correct_index|explanation|domain|subdomain
```
- Location: `data/{domain}/{subdomain}.txt`
- Parse with `quiz::parse_question_line()`

### Adding Tutorials
1. Create JSON in `data/tutorials/{name}.json`:
```json
{
  "id": "name",
  "title": "Display Title",
  "type": "tutorial",
  "steps": [{ "id": "step_id", "title": "Step", "content": "...", "tags": [] }]
}
```
2. Add to `tutorials/mod.rs` → `load_tutorial_phases()` vec

### Configuration
- Config file: `~/.config/pt-journal/config.toml`
- Config types: `src/config/config.rs` → `AppConfig`, `ChatbotConfig`
- Environment overrides: `PT_JOURNAL_*` prefix

### Chat Provider Interface
Implement `ChatProvider` trait for new LLM backends:
```rust
pub trait ChatProvider: Send + Sync {
    fn send_message(&self, request: &ChatRequest) -> PtResult<ChatMessage>;
    fn check_availability(&self) -> PtResult<bool>;
    fn provider_name(&self) -> &str;
}
```

## Key Files Reference

| Purpose | File |
|---------|------|
| Application entry | `src/main.rs` |
| State management | `src/ui/state.rs`, `src/model/app_model.rs` |
| Event system | `src/dispatcher.rs` |
| Error types | `src/error.rs` |
| Quiz parsing | `src/quiz/mod.rs` |
| LLM integration | `src/chatbot/` |
| Tutorial loading | `src/tutorials/mod.rs` |
| Config schema | `src/config/config.rs` |

## Common Tasks

### Adding a UI Component
1. Create component in `src/ui/`
2. Use `StateManager` for state mutations
3. Emit `AppEvent` variants for cross-component updates
4. Add handler in `dispatcher.rs` EventBus

### Modifying the Data Model
1. Update types in `src/model/`
2. Add validation in `AppModel` methods
3. Return `PtError` for invalid operations
4. Update serialization if persisted

## External Dependencies

- **GTK4 + Libadwaita**: Native Linux UI (requires system libs)
- **VTE4**: Terminal emulation widget
- **Ollama**: Local LLM inference (configurable endpoint)
- **Serde**: JSON/YAML/TOML serialization
