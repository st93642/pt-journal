# PT Journal

A **GTK4/Libadwaita desktop application** for penetration testing education, built with Rust and the Relm4 framework.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)
![GTK](https://img.shields.io/badge/GTK-4.12-green.svg)

## Features

- 📚 **Interactive Tutorials** - Step-by-step guides covering security domains:
  - CEH (Certified Ethical Hacker)
  - CompTIA Security+ (SY0-701)
  - CompTIA PenTest+ (PT0-003)
  - Reconnaissance, exploitation, post-exploitation techniques
  - Linux and Windows CTF step-by-step guides
  - Cloud security (AWS, Azure, GCP, IAM, containers)
  - Modern web application security
  
- ❓ **Quiz System** - Test your knowledge with categorized questions organized by certification domains

- 🤖 **AI Chat Assistant** - Integrated LLM chatbot (Ollama backend) for contextual learning assistance

- 🛠️ **Tool Instructions** - Registry of security tool documentation and usage guides

## Screenshots

Screenshots coming soon.

## Installation

### Prerequisites

- Rust 1.70+ with Cargo
- GTK4 4.12+ development libraries
- Libadwaita 1.4+
- VTE4 (terminal emulation)

#### Ubuntu/Debian

```bash
sudo apt install libgtk-4-dev libadwaita-1-dev libvte-2.91-gtk4-dev
```

#### Fedora

```bash
sudo dnf install gtk4-devel libadwaita-devel vte291-gtk4-devel
```

#### Arch Linux

```bash
sudo pacman -S gtk4 libadwaita vte4
```

### Ollama Backend Setup

PT Journal uses Ollama for AI-assisted learning. To enable the chatbot feature:

1. **Install Ollama** from [ollama.ai](https://ollama.ai/)

2. **Pull a model** (recommended: llama3.2):

   ```bash
   ollama pull llama3.2
   ```

3. **Verify installation**:

   ```bash
   ollama list
   ```

The application will connect to Ollama at `http://localhost:11434` by default. You can customize the endpoint in the configuration file or via environment variables.

### Build from Source

```bash
git clone https://github.com/st93642/pt-journal.git
cd pt-journal
cargo build --release
```

### Run

```bash
cargo run --release
```

## Usage

### Three-Panel Layout

1. **Sidebar (Left)** - Phase/tutorial selection and step navigation
2. **Content (Center)** - Tutorial content and AI chat
3. **Tools (Right)** - Security tool instructions and documentation

### Tutorials

Navigate through phases and steps to learn penetration testing concepts. Each step includes:

- Detailed instructions with academic background
- Commands and tool usage examples

### Quizzes

Quiz steps present multiple-choice questions with:

- Immediate feedback on answers
- Detailed explanations
- Progress tracking per domain/subdomain

### AI Assistant

The integrated chatbot provides contextual help based on your current learning step. Configure your Ollama endpoint in the settings.

### Environment Variables

Override configuration with `PT_JOURNAL_*` prefixed environment variables:

```bash
export PT_JOURNAL_OLLAMA_ENDPOINT="http://192.168.1.100:11434"
```

## Development

### Project Structure

```text
src/
├── main.rs           # Application entry point
├── lib.rs            # Library root with module exports
├── dispatcher.rs     # Event bus (AppEvent + EventBus)
├── error.rs          # Unified PtError type
├── model/            # Domain types (Session, Phase, Step, Quiz)
├── ui/               # GTK4 widgets and controllers
│   ├── state.rs      # StateManager for model mutations
│   ├── chat_panel.rs # LLM chat interface
│   └── quiz_widget.rs# Quiz UI component
├── chatbot/          # LLM provider abstraction
├── config/           # Configuration management
├── quiz/             # Quiz parsing and logic
├── tutorials/        # JSON tutorial loading
└── tools/            # Tool registry

data/
├── tutorials/        # JSON tutorial definitions
├── ceh/              # CEH quiz questions by domain
├── comptia_secplus/  # Security+ quiz questions
├── pentest/          # PenTest+ quiz questions
└── tool_instructions/# Tool documentation
```

### Running Tests

```bash
# Full test suite
./test-all.sh

# Unit tests only
cargo test --test unit_tests

# Integration tests only
cargo test --test integration_tests

# With verbose output
cargo test -- --nocapture
```

### Code Quality

```bash
# Lint check
cargo clippy

# Format code
cargo fmt

# Check formatting
cargo fmt --check
```

## Quiz File Format

Quiz questions use a pipe-delimited format with 9 fields:

```text
question|answer_a|answer_b|answer_c|answer_d|correct_index|explanation|domain|subdomain
```

Example:

```text
What is the CIA triad?|Confidentiality, Integrity, Availability|Cryptography, Identity, Access|...|0|The CIA triad stands for...|1.0 General Security Concepts|1.1 Security Controls
```

## Adding Content

### New Tutorial

Create `data/tutorials/{name}.json`:

```json
{
  "id": "my_tutorial",
  "title": "My Tutorial",
  "description": "Tutorial description",
  "type": "tutorial",
  "steps": [
    {
      "id": "step_1",
      "title": "First Step",
      "content": "Step content with instructions...",
      "tags": ["tag1", "tag2"]
    }
  ]
}
```

Then add to `src/tutorials/mod.rs` in `load_tutorial_phases()`:

```rust
load_tutorial_phase("my_tutorial"),
```

### New Quiz Questions

Add questions to the appropriate file in `data/{domain}/{subdomain}.txt` following the pipe-delimited format.

## Architecture

### Event-Driven Design

The application uses an event bus pattern for loose coupling between components:

1. UI actions call `StateManager` methods
2. `StateManager` mutates `AppModel` via `Rc<RefCell<AppModel>>`
3. `StateManager` emits `AppEvent` through `SharedEventBus`
4. Event handlers update UI widgets

### Error Handling

All operations use the `PtError` enum from `src/error.rs` with structured variants for different failure modes:

- `PtError::InvalidPhaseIndex`
- `PtError::Chat`
- `PtError::Config`
- etc.

## Contributing

Contributions are welcome! Please ensure:

1. Code passes `cargo clippy` without warnings
2. Code is formatted with `cargo fmt`
3. All tests pass (`./test-all.sh`)
4. New features include appropriate tests

## Acknowledgments

- [GTK4-rs](https://gtk-rs.org/) - Rust bindings for GTK4
- [Relm4](https://relm4.org/) - Idiomatic GUI library for Rust
- [Ollama](https://ollama.ai/) - Local LLM inference
- [OWASP](https://owasp.org/) - Security testing guidelines
- [CompTIA](https://www.comptia.org/) - Certification frameworks
