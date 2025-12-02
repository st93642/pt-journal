# PT Journal

A **GTK4/Libadwaita desktop application** for penetration testing education, built with Rust and the Relm4 framework.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)
![GTK](https://img.shields.io/badge/GTK-4.12-green.svg)

## Features

- 📚 **Interactive Tutorials** - Step-by-step guides covering security domains:
  - CEH (Certified Ethical Hacker) - 20 domains with comprehensive coverage
  - CompTIA Security+ (SY0-701) - 5 domains aligned with latest exam
  - CompTIA PenTest+ (PT0-003) - 6 domains for penetration testing methodology
  - Reconnaissance, exploitation, post-exploitation techniques
  - **Windows CTF Tutorial** - 9-step methodology covering AD enumeration, credential harvesting, password cracking, Kerberos attacks, ACL analysis, administrative tier evasion, and security monitoring bypass
  - Linux CTF step-by-step guides
  - Cloud security (AWS, Azure, GCP, IAM, containers)
  - Modern web application security
  - **AI Agent Operations** - Autonomous workflow orchestration using AutoGen, PentestGPT, and specialized agent frameworks for penetration testing automation

- ❓ **Quiz System** - Test your knowledge with categorized questions organized by certification domains (1000+ questions across CEH, Security+, PenTest+)

- 🤖 **AI Chat Assistant** - Integrated LLM chatbot (Ollama backend) for contextual learning assistance with configurable models and parameters

- 🛠️ **Tool Instructions & Terminal** - Comprehensive security tool documentation with embedded terminal for hands-on practice:
  - 229+ security tools with detailed usage guides
  - Expanded AI security coverage including PyRIT (Microsoft AI red teaming), PentestGPT (LLM-driven pentest automation), and NeMo Guardrails (NVIDIA AI safety controls)
  - Installation instructions for multiple platforms
  - Interactive terminal with copy/paste functionality
  - Non-modal tool instruction dialogs (can interact with terminal simultaneously)

## Current State

**Latest Release: v0.1.0** (November 2025)

### Recent Enhancements

- ✅ **Expanded Windows CTF Tutorial** - Added 3 new advanced steps covering ACL analysis, administrative tier model evasion, and security monitoring bypass
- ✅ **Fixed Terminal Interaction** - Tool instruction dialogs are now non-modal, allowing simultaneous terminal usage
- ✅ **Comprehensive Test Suite** - 110 unit tests + 10 integration tests with automated validation
- ✅ **Enhanced Tool Documentation** - 80+ security tools with installation guides and usage examples
- ✅ **Improved Quiz System** - Point-based scoring with first-attempt bonuses and progress tracking

### Content Coverage

- **59 Tutorial Phases** spanning 420+ learning steps across penetration testing domains
- **23 AI-Focused Phases** covering:
  - GenAI-driven reconnaissance, exploitation, and automated reporting
  - **AI Agent Operations** - Agentic frameworks (AutoGen, PentestGPT) and autonomous workflow orchestration
  - **AI SecOps Copilots** - Intelligent incident triage, threat analysis, and security operations augmentation
  - **AI Playbook Automation** - Adaptive playbook execution, threat hunting, and compliance automation
- **1000+ Quiz Questions** covering CEH, Security+, PenTest+, CISSP, and AI agent operations certifications
- **229 Security Tools** with detailed documentation and terminal integration, including comprehensive AI security coverage with PyRIT, PentestGPT, and NeMo Guardrails
- **Multi-Platform Support** - Linux, macOS, Windows compatibility
- 📄 **AI Content Audit** - Baseline of tutorial phases and tool instructions for upcoming GenAI enhancements (see [docs/roadmap/ai_content_audit.md](docs/roadmap/ai_content_audit.md))

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
2. **Content (Center)** - Tutorial content, quiz questions, and AI chat
3. **Tools (Right)** - Security tool instructions with embedded terminal for hands-on practice

### Tutorials

Navigate through phases and steps to learn penetration testing concepts. Each step includes:

- Detailed instructions with academic background
- Commands and tool usage examples
- Security implications and common pitfalls

### Quizzes

Quiz steps present multiple-choice questions with:

- Immediate feedback on answers
- Detailed explanations
- Progress tracking per domain/subdomain
- Point system with first-attempt bonuses

### AI Assistant

The integrated chatbot provides contextual help based on your current learning step. Configure your Ollama endpoint in the settings with support for multiple models and parameters.

### Tool Instructions & Terminal

The right panel provides comprehensive security tool documentation:

- **80+ security tools** with detailed usage guides and examples
- **Embedded terminal** for hands-on practice (VTE-based)
- **Copy/paste functionality** - commands can be copied from instructions to terminal
- **Non-modal dialogs** - tool instruction windows don't block terminal interaction
- **Installation guides** for multiple platforms (Linux, macOS, Windows)
- **Advanced usage examples** and workflow guides

**Terminal Features:**

- Right-click context menu for copy/paste
- Syntax-highlighted command display
- Direct command execution
- Persistent shell session

## Development

### Project Structure

```text
src/
├── main.rs           # Application entry point
├── lib.rs            # Library root with module exports
├── dispatcher.rs     # Event bus (AppEvent + EventBus)
├── error.rs          # Unified PtError type
├── store.rs          # Session persistence and state management
├── model/            # Domain types (Session, Phase, Step, Quiz)
├── ui/               # GTK4 widgets and controllers
│   ├── state.rs      # StateManager for model mutations
│   ├── chat_panel.rs # LLM chat interface
│   ├── quiz_widget.rs# Quiz UI component
│   ├── tool_execution/# Security tool panel with terminal
│   │   ├── panel.rs  # Tool execution panel with embedded terminal
│   │   ├── terminal.rs# VTE terminal interface
│   │   ├── controller.rs# Tool panel state management
│   │   ├── renderer.rs# Instruction widget rendering
│   │   └── picker.rs # Tool selection logic
│   └── detail_panel.rs# Content display and syntax highlighting
├── chatbot/          # LLM provider abstraction
│   ├── provider.rs   # ChatProvider trait
│   └── ollama.rs     # Ollama API implementation
├── config/           # Configuration management
├── quiz/             # Quiz parsing and logic
├── tutorials/        # JSON tutorial loading
├── tools/            # Tool registry and instructions
└── support.rs        # Utility functions

data/
├── tutorials/        # JSON tutorial definitions (23 tutorials)
├── ceh/              # CEH quiz questions by domain (20 domains)
├── comptia_secplus/  # Security+ quiz questions (5 domains)
├── pentest/          # PenTest+ quiz questions (6 domains)
├── ai_security/      # AI/ML security quiz questions
├── cloud_identity/   # Cloud IAM quiz questions
├── container_security/# Container security quiz questions
├── serverless_security/# Serverless security quiz questions
└── tool_instructions/# Tool documentation (80+ tools)
```

### Running Tests

```bash
# Full test suite (unit + integration + linting + formatting + JSON validation)
./test-all.sh

# Unit tests only (110 tests covering all modules)
cargo test --test unit_tests

# Integration tests only (10 tests for cross-module functionality)
cargo test --test integration_tests

# With verbose output
cargo test -- --nocapture
```

### Code Quality

```bash
# Lint check (clippy)
cargo clippy

# Format code
cargo fmt

# Check formatting (CI validation)
cargo fmt --check

# JSON validation for all data files
find . -name "*.json" -not -path "./target/*" -exec jq empty {} \;
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
- [VTE](https://gitlab.gnome.org/GNOME/vte) - Terminal emulator widget
- [Ollama](https://ollama.ai/) - Local LLM inference
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Active Directory attack path analysis
- [Impacket](https://github.com/fortra/impacket) - Python Windows protocol library
- [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) - Network assessment tool
- [OWASP](https://owasp.org/) - Security testing guidelines
- [CompTIA](https://www.comptia.org/) - Certification frameworks
- [MITRE ATT&CK](https://attack.mitre.org/) - Cybersecurity threat framework
