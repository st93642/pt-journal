# PT Journal

A **GTK4/Libadwaita desktop application** for penetration testing education, built with Rust.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)
![GTK](https://img.shields.io/badge/GTK-4.12-green.svg)

## Features

- 📚 **66 Tutorial Phases** - CEH, Security+, PenTest+, CISSP, forensics, AI security, SOC operations
- ❓ **Quiz System** - 1000+ questions with progress tracking and explanations
- 🤖 **AI Chat Assistant** - OpenAI, Azure OpenAI, and Ollama support
- 🛠️ **229 Security Tools** - Documentation with embedded terminal for practice
- 🔍 **Related Tools** - Contextual tool suggestions per tutorial step

## Quick Start

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install libgtk-4-dev libadwaita-1-dev libvte-2.91-gtk4-dev

# Fedora
sudo dnf install gtk4-devel libadwaita-devel vte291-gtk4-devel

# Arch
sudo pacman -S gtk4 libadwaita vte4
```

### Build & Run

```bash
git clone https://github.com/st93642/pt-journal.git
cd pt-journal
cargo run --release
```

### AI Setup (Optional)

```bash
# Ollama (local, recommended)
ollama pull llama3.2

# Or set OpenAI API key
export PT_JOURNAL_OPENAI_API_KEY="your-key"
```

## Layout

| Panel | Description |
|-------|-------------|
| **Left** | Phase/step navigation |
| **Center** | Tutorial content, quizzes, AI chat |
| **Right** | Tool instructions with terminal |

## Development

```bash
./test-all.sh          # Full test suite (114 tests)
cargo test             # Unit tests only
cargo clippy && cargo fmt  # Lint and format
```

### Adding Content

**Tutorial:** Create `data/tutorials/{name}.json`, register in `src/tutorials/mod.rs`

**Quiz:** Add to `data/{domain}/{file}.txt` using pipe-delimited format:

```text
question|a|b|c|d|correct_index|explanation|domain|subdomain
```

## Configuration

Config file: `~/.config/pt-journal/config.toml`

```toml
[chatbot.ollama]
endpoint = "http://localhost:11434"

[chatbot.openai]
api_key = "sk-..."
```

## License

MIT
