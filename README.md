# PT Journal

A GTK4/libadwaita desktop application for structured penetration testing documentation and learning, featuring local AI assistance via Ollama integration.

## Features

- **Structured Methodology**: 23-phase penetration testing workflow with guided tutorials
- **Local AI Chatbot**: Ollama-powered AI assistance for pentesting guidance
- **Tool Integration**: Execute security tools with timeout enforcement and output parsing
- **Quiz System**: Interactive learning with progress tracking and scoring
- **Evidence Management**: Capture and organize findings with file attachments
- **Session Persistence**: JSON-based storage with migration support

## Quick Start

### Prerequisites

- Linux, macOS, or Windows
- Rust 1.70+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- GTK4 development libraries
- Ollama for AI features

### Installation

```bash
# Clone the repository
git clone https://github.com/st93642/pt-journal.git
cd pt-journal

# Build and run
cargo run
```

### Setup AI Chatbot

1. Install Ollama: `curl -fsSL https://ollama.ai/install.sh | sh`
2. Start Ollama service: `ollama serve`
3. Pull a model: `ollama pull llama3.2`
4. Configure PT Journal to use the model (see Configuration section)

## Pulling New Ollama Models

PT Journal uses Ollama for local AI assistance. To add new models:

### Browse Available Models

Visit the [Ollama Model Library](https://ollama.com/library) to explore available models.

### Pull a Model

Use the `ollama pull` command:

```bash
# Pull a specific model
ollama pull llama3.1:8b

# Pull a code-focused model
ollama pull codellama

# Pull a fast, efficient model
ollama pull mistral:7b

# List installed models
ollama list
```

### Configure PT Journal

After pulling models, they become available in PT Journal's model selector. You can switch models during runtime via the UI.

For advanced configuration, see [OLLAMA_SETUP.md](docs/OLLAMA_SETUP.md).

## Configuration

PT Journal supports configuration via:

1. **Environment Variables** (highest priority)

   ```bash
   export PT_JOURNAL_CHATBOT_MODEL_ID="llama3.2"
   export PT_JOURNAL_OLLAMA_ENDPOINT="http://localhost:11434"
   ```

2. **TOML Configuration File** (`~/.config/pt-journal/config.toml`)

   ```toml
   [chatbot]
   default_model_id = "llama3.2"
   ollama.endpoint = "http://localhost:11434"
   ollama.timeout_seconds = 30
   ```

3. **Default Values** (fallback)

See [configuration.md](docs/configuration.md) for complete options.

## Documentation

- **[OLLAMA_SETUP.md](docs/OLLAMA_SETUP.md)** - Complete Ollama setup guide
- **[architecture.md](docs/architecture.md)** - System architecture and design
- **[chatbot.md](docs/chatbot.md)** - Chatbot integration details
- **[configuration.md](docs/configuration.md)** - Configuration system guide
- **[CODEBASE_INDEX.md](CODEBASE_INDEX.md)** - Developer reference

## Development

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Generate documentation
cargo doc --open
```

### Code Quality

- Format code: `cargo fmt`
- Lint code: `cargo clippy`
- All tests must pass: `cargo test`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure `cargo fmt` and `cargo clippy` pass
5. Submit a pull request

See [CODEBASE_INDEX.md](CODEBASE_INDEX.md) for development guidelines.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/st93642/pt-journal/issues)
- **Discussions**: [GitHub Discussions](https://github.com/st93642/pt-journal/discussions)
- **Setup Help**: See [OLLAMA_SETUP.md](docs/OLLAMA_SETUP.md)

---

**Version**: 0.1.0  
**Last Updated**: November 26, 2025
