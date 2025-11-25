# PT Journal – Copilot Agent Instructions

These instructions provide the context and guardrails required for AI coding assistants working on the PT Journal repository.

## 🧭 Project Context

- **Application Type**: GTK4/libadwaita desktop app for structured penetration testing documentation.
- **Core Features**: Tutorial-driven methodology, quiz system, evidence canvas, security-tool integrations (Nmap, Gobuster).
- **Architecture**: Four layers — UI → Application Logic → Domain Model → Infrastructure.
- **Data Model**: Sessions → Phases → Steps (Tutorial or Quiz) → Evidence.
- **Storage**: JSON sessions with paired `evidence/` folders under `~/Downloads/pt-journal-sessions/`.
- **Tool Pattern**: Trait-based `SecurityTool` implementations with builders, registries, and executor.

## 🧱 Key Modules

| Area | Location | Notes |
|------|----------|-------|
| Domain models | `src/model.rs` | Use getters/setters; never mutate Step content fields directly. |
| Persistence | `src/store.rs` | Handles migration + folder structure; functions return `anyhow::Result`. |
| Tools framework | `src/tools/` | Implement `SecurityTool`; always register integrations in `mod.rs`. |
| UI layer | `src/ui/` | GTK4 components with `Rc<RefCell<AppModel>>`; avoid blocking the main thread. |
| Tutorials | `src/tutorials/` | Step descriptions follow OBJECTIVE/PROCESS/LOOK-FOR format. |
| Quiz system | `src/quiz/mod.rs` | Questions use 9-field pipe-delimited format. |

## 🛠️ Development Guidelines

1. **Follow Established Patterns**
   - Builder pattern for configs (`ToolConfig::builder()`), Observer pattern for dispatcher, Registry for tools.
   - Keep tutorial content structured; quiz steps require populated `QuizStep` data.
2. **State Management**
   - UI state uses `Rc<RefCell<AppModel>>`; clone handles inside signal closures.
   - Defer expensive UI updates with `glib::idle_add_local_once`.
3. **Error Handling**
   - Use `anyhow::Result<T>` for fallible functions.
   - Propagate errors; don’t `unwrap()` in production code.
4. **Testing Requirements**
   - Every new feature must include unit and/or integration tests.
   - Tool integrations need 20+ tests covering availability, command building, parsing, evidence extraction.
   - Ensure existing 153 tests continue to pass.
5. **Performance Targets**
   - Session operations < 500ms, UI handlers < 16ms, large session handling < 1s.
   - Do not block the GTK main loop with long-running work; spawn background threads/channel updates if needed.
6. **File Organization**
   - Keep new tools under `src/tools/integrations/` with matching module exports.
   - Add tutorial phases in `src/tutorials/` and register via `load_tutorial_phases()`.
   - Store documentation in `docs/` (architecture, roadmap, performance, etc.).
7. **Coding Style**
   - Rust 2021 edition, `cargo fmt` formatting, `cargo clippy` lint clean.
   - Prefer explicit types, avoid magic strings, and keep error messages actionable.
   - Limit inline comments to complex logic; rely on descriptive names and doc comments.

## 🔍 Testing & Validation

Run relevant commands locally before finishing:
```bash
cargo fmt
cargo clippy
cargo test --lib
cargo test --test integration_tests
```
*Skip optional commands only if CI will cover them and changes are minimal; otherwise run them to avoid regressions.*

## ⚠️ Common Pitfalls

- **Step Content**: Always interact via `get_*`/`set_*` methods; Step fields may differ between Tutorial/Quiz.
- **Evidence Paths**: Keep evidence file paths relative to session folder.
- **Tool Commands**: Validate user inputs and sanitize command arguments; enforce timeouts.
- **UI Blocking**: Never execute long-running tool processes on the GTK thread.
- **Serialization**: Remember to migrate legacy step data when loading sessions (call `step.migrate_from_legacy()`).

## ✅ Definition of Done

- Code follows project style and architecture patterns.
- Necessary documentation updated (README, CODEBASE_INDEX, module docs as needed).
- Tests added/updated with 100% pass expectation.
- No warnings from `cargo clippy`; formatted via `cargo fmt`.
- New tools/components registered and discoverable in UI if applicable.

Following these instructions ensures consistent, high-quality contributions that respect PT Journal’s architecture and reliability expectations.
