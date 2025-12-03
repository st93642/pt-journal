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
  - **Practical Cyber Intelligence Curriculum** - 9-phase forensics program covering threat intelligence, digital forensics methodology, disk/memory/network forensics, and incident response
  - **Streamlined AI Security** - 8 high-quality phases covering AI/ML security fundamentals, AI-powered offensive tools, and agentic operations

- ❓ **Quiz System** - Test your knowledge with categorized questions organized by certification domains (1000+ questions across CEH, Security+, PenTest+)

- 🤖 **AI Chat Assistant** - Integrated LLM chatbot with support for OpenAI, Azure OpenAI, and local Ollama backends for contextual learning assistance with configurable models and parameters

- 🛠️ **Tool Instructions & Terminal** - Comprehensive security tool documentation with embedded terminal for hands-on practice:
  - 229+ security tools with detailed usage guides
  - **Expanded Forensics Coverage** - Autopsy, Sleuth Kit, Volatility, FTK Imager, registry analysis tools
  - **AI Security Tools** - PyRIT (Microsoft AI red teaming), PentestGPT (LLM-driven pentest automation), NeMo Guardrails (NVIDIA AI safety controls), and comprehensive LLM testing frameworks
  - Installation instructions for multiple platforms
  - Interactive terminal with copy/paste functionality
  - Non-modal tool instruction dialogs (can interact with terminal simultaneously)

## Current State

**Latest Release: v0.1.0** (November 2025)

### Recent Enhancements

- ✅ **Practical Cyber Intelligence Integration** - Added 9-phase forensics curriculum based on "Practical Cyber Intelligence: A Hands-on Guide to Digital Forensics"
- ✅ **Curriculum Streamlining** - Reduced from 67 to 52 phases (15 deprecated AI phases removed), maintaining high-quality content while improving focus
- ✅ **Enhanced Forensics Tool Coverage** - Added comprehensive documentation for Autopsy, Sleuth Kit, Volatility, and platform-specific forensics tools
- ✅ **PDF Extraction Pipeline** - Complete book content extraction with OCR fallback and structured JSON output for tutorial generation
- ✅ **Expanded Windows CTF Tutorial** - Added 3 new advanced steps covering ACL analysis, administrative tier model evasion, and security monitoring bypass
- ✅ **Fixed Terminal Interaction** - Tool instruction dialogs are now non-modal, allowing simultaneous terminal usage
- ✅ **Comprehensive Test Suite** - 110 unit tests + 10 integration tests with automated validation
- ✅ **Enhanced Tool Documentation** - 229 security tools with installation guides and usage examples
- ✅ **Improved Quiz System** - Point-based scoring with first-attempt bonuses and progress tracking

### Content Coverage

- **52 Tutorial Phases** spanning 371+ learning steps across penetration testing domains
- **Practical Cyber Intelligence Curriculum** - 9-phase forensics program based on "Practical Cyber Intelligence: A Hands-on Guide to Digital Forensics" covering:
  - Cyber Threat Intelligence Fundamentals
  - Digital Forensics Methodology  
  - Disk, Memory, SQLite, Windows, macOS, and Network Forensics
  - Incident Response Methodology
- **Streamlined AI Content** - 8 high-quality AI-focused phases (reduced from 23) covering essential modern topics:
  - AI/ML Security fundamentals
  - AI-powered offensive security tools
  - AI agentic operations for penetration testing
  - Advanced topics like RAG red teaming and bug bounty automation
- **1000+ Quiz Questions** covering CEH, Security+, PenTest+, CISSP, and specialized forensics domains
- **229 Security Tools** with detailed documentation and terminal integration, including comprehensive AI security coverage with PyRIT, PentestGPT, NeMo Guardrails, and forensics tools
- **Multi-Platform Support** - Linux, macOS, Windows compatibility
- 📄 **Curriculum Audit** - Complete tutorial catalog with Practical Cyber Intelligence integration (see [docs/curriculum/practical_cyber_intelligence.md](docs/curriculum/practical_cyber_intelligence.md))

## Documentation

### Curriculum Documentation
- **[Practical Cyber Intelligence Curriculum](docs/curriculum/practical_cyber_intelligence.md)** - Complete forensics program documentation with phase details, tool integration, and learning objectives
- **[Testing & Validation Guide](docs/curriculum/testing_validation.md)** - Comprehensive testing procedures for curriculum validation and UI testing
- **[Curriculum Audit](docs/roadmap/ai_content_audit.md)** - Current curriculum status with phase counts and content analysis

### Project Documentation
- **[Project README](README.md)** - Main project documentation with installation and usage instructions
- **[AI Content Audit](docs/roadmap/ai_content_audit.md)** - Historical audit of AI content changes and curriculum streamlining

### Quick Reference
- **Phase Count**: 52 total (down from 67, 15 deprecated AI phases removed)
- **Step Count**: 371 total (down from 471)  
- **New Content**: 9 Practical Cyber Intelligence phases (52 steps)
- **Remaining AI**: 8 high-quality AI phases (15% of curriculum)
- **Tools**: 229 documented security tools (15 forensics, 9 AI security)

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

### AI Provider Configuration

PT Journal supports multiple AI providers for the chatbot feature:

#### OpenAI

1. **Get an API key** from [platform.openai.com](https://platform.openai.com/)
2. **Configure via environment variables**:

   ```bash
   export PT_JOURNAL_OPENAI_API_KEY="your-openai-api-key"
   export PT_JOURNAL_OPENAI_ENDPOINT="https://api.openai.com/v1"  # Optional, uses default
   export PT_JOURNAL_OPENAI_TIMEOUT_SECONDS="120"  # Optional, timeout in seconds
   ```

3. **Or configure in config file** (`~/.config/pt-journal/config.toml`):

   ```toml
   [chatbot.openai]
   api_key = "your-openai-api-key"
   endpoint = "https://api.openai.com/v1"
   timeout_seconds = 120
   ```

#### Azure OpenAI

1. **Create an Azure OpenAI resource** in the Azure portal
2. **Get your endpoint and API key** from the Azure portal
3. **Configure via environment variables**:

   ```bash
   export PT_JOURNAL_AZURE_OPENAI_API_KEY="your-azure-api-key"
   export PT_JOURNAL_AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com"
   export PT_JOURNAL_AZURE_OPENAI_DEPLOYMENT="your-deployment-name"  # Optional per-model
   export PT_JOURNAL_AZURE_OPENAI_API_VERSION="2024-02-15-preview"  # Optional
   export PT_JOURNAL_AZURE_OPENAI_TIMEOUT_SECONDS="120"  # Optional, timeout in seconds
   ```

4. **Or configure in config file**:

   ```toml
   [chatbot.azure_openai]
   api_key = "your-azure-api-key"
   endpoint = "https://your-resource.openai.azure.com"
   deployment_name = "your-deployment-name"  # Optional global deployment
   api_version = "2024-02-15-preview"
   timeout_seconds = 120
   ```

#### Ollama (Local)

1. **Install Ollama** from [ollama.ai](https://ollama.ai/)
2. **Configure via environment variables**:

   ```bash
   export PT_JOURNAL_OLLAMA_ENDPOINT="http://localhost:11434"  # Optional, uses default
   export PT_JOURNAL_OLLAMA_TIMEOUT_SECONDS="180"  # Optional, timeout in seconds
   ```

3. **Or configure in config file**:

   ```toml
   [chatbot.ollama]
   endpoint = "http://localhost:11434"
   timeout_seconds = 180
   ```

#### Model Selection

Available models are automatically populated based on your configured providers:

- **OpenAI**: GPT-4o, GPT-4o Mini, GPT-4 Turbo, GPT-3.5 Turbo
- **Azure OpenAI**: Same models as OpenAI (use your deployment names)
- **Ollama**: Any models you've pulled locally (`ollama list`)

You can select the active model in the chat panel dropdown. The application will automatically use the appropriate provider based on the selected model.

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

The integrated chatbot provides contextual help based on your current learning step. Configure your preferred AI provider (OpenAI, Azure OpenAI, or local Ollama) with support for multiple models and parameters.

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
│   ├── ollama.rs     # Ollama API implementation
│   ├── openai.rs     # OpenAI API implementation
│   ├── azure_openai.rs # Azure OpenAI API implementation
│   ├── registry.rs   # Provider registry for dynamic registration
│   ├── service.rs    # Chat service with provider routing
│   └── request.rs    # Chat request/response types
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

### PDF Book Extraction & Curriculum Generation

The project includes a comprehensive PDF extraction pipeline for processing educational content from "Practical Cyber Intelligence: A Hands-on Guide to Digital Forensics":

```bash
# Install Python dependencies
pip install -r scripts/requirements.txt

# Install system dependencies (Ubuntu/Debian)
sudo apt install tesseract-ocr poppler-utils

# Extract complete book content
python3 scripts/extract_practical_cyber_intel.py \
    --pdf "./Practical Cyber Intelligence A Hands-on Guide to Digital Forensics (Jakobsen, Adam Tilmar) (Z-Library).pdf" \
    --output data/source_material/practical_cyber_intelligence

# Extract specific page range
python3 scripts/extract_practical_cyber_intel.py \
    --pdf "./Practical Cyber Intelligence*.pdf" \
    --output data/source_material/practical_cyber_intelligence \
    --pages 1-50
```

**Pipeline Features:**
- Text-first extraction using PyPDF2 with OCR fallback for complex pages
- Automatic chapter/section/paragraph hierarchy detection preserving book structure
- Structured JSON output with page numbers for content traceability
- Raw transcript for manual inspection and quality control
- Dependency validation with actionable error messages
- Comprehensive unit tests for extraction reliability

**Output Files:**
- `structured_book.json` - Hierarchical content structure (chapters → sections → paragraphs)
- `raw_transcript.txt` - Complete text with page markers for reference
- `extraction_stats.json` - Processing statistics and quality metrics

**Tutorial Generation Workflow:**
1. Extract book content using the pipeline above
2. Review structured JSON in `data/source_material/practical_cyber_intelligence/`
3. Tutorial JSON files are already created in `data/tutorials/` based on the book content:
   - `cyber_threat_intelligence_fundamentals.json`
   - `digital_forensics_methodology.json`
   - `disk_forensics_analysis.json`
   - `memory_forensics_analysis.json`
   - `sqlite_forensics.json`
   - `windows_forensics_deep_dive.json`
   - `network_forensics_fundamentals.json`
   - `macos_forensics.json`
   - `incident_response_methodology.json`
4. Run `cargo run` to test the new phases in the GTK UI
5. Validate with `./test-all.sh` to ensure all tests pass

### Running Tests & Validation

```bash
# Full test suite (unit + integration + linting + formatting + JSON validation)
./test-all.sh

# Unit tests only (comprehensive test coverage for all modules)
cargo test --test unit_tests

# Integration tests only (cross-module functionality)
cargo test --test integration_tests

# Tutorial catalog audit (verify phase/step counts and categories)
python3 scripts/tutorial_catalog_audit.py

# With verbose output
cargo test -- --nocapture

# GTK UI validation
cargo run --release
# Navigate through the new Practical Cyber Intelligence phases:
# 1. Cyber Threat Intelligence Fundamentals (Phase 20)
# 2. Digital Forensics Methodology (Phase 21)
# 3. Disk Forensics Analysis (Phase 22)
# And verify all steps display correctly with proper formatting
```

**Expected Test Results:**
- **52 phases** loaded (down from 67)
- **371 total steps** (down from 471)
- **8 AI phases** remaining (high-quality content only)
- **33 forensics-focused steps** across 9 phases
- **47 cyber-intelligence tagged steps**
- All JSON files valid and properly structured
- Tutorial validation passes for all phases

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
