# PT Journal Configuration Guide

## Overview

PT Journal supports configurable settings for chatbot integration and other features through a TOML configuration file. Configuration can be customized per-user and supports environment variable overrides for containerized deployments.

## Configuration File Location

The configuration file is located at:

- **Linux/macOS**: `~/.config/pt-journal/config.toml`
- **Windows**: `%APPDATA%\pt-journal\config.toml`

The directory is created automatically when the application first saves configuration.

## Configuration Structure

```toml
[chatbot]
endpoint = "http://localhost:11434"
model = "mistral"
```

### Chatbot Configuration

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `endpoint` | string | `"http://localhost:11434"` | Ollama API endpoint URL |
| `model` | string | `"mistral"` | Default Ollama model to use |

## Configuration Priority

Settings are loaded in the following priority order (highest to lowest):

1. **Environment Variables** (runtime override)
2. **TOML Configuration File** (persistent user settings)
3. **Default Values** (fallback)

## Environment Variables

| Variable | Maps To | Example |
|----------|---------|---------|
| `PT_JOURNAL_OLLAMA_ENDPOINT` | `chatbot.endpoint` | `http://custom-ollama:8080` |
| `PT_JOURNAL_OLLAMA_MODEL` | `chatbot.model` | `llama2:13b` |

### Usage Examples

```bash
# Use custom Ollama instance
export PT_JOURNAL_OLLAMA_ENDPOINT="http://192.168.1.100:11434"
export PT_JOURNAL_OLLAMA_MODEL="codellama"

# Run PT Journal
cargo run
```

```bash
# Docker container with custom config
docker run -e PT_JOURNAL_OLLAMA_ENDPOINT=http://host.docker.internal:11434 \
           -e PT_JOURNAL_OLLAMA_MODEL=llama2 \
           pt-journal
```

## Programmatic Access

Configuration is loaded automatically when the application starts and is available through the `AppModel`:

```rust
let config = &app_model.config;
let endpoint = &config.chatbot.endpoint;
let model = &config.chatbot.model;
```

## Default Configuration

If no configuration file exists and no environment variables are set, PT Journal uses these defaults:

- **Endpoint**: `http://localhost:11434` (standard Ollama port)
- **Model**: `mistral` (popular general-purpose model)

## Migration and Compatibility

- Configuration is optional - PT Journal works without any configuration file
- Missing configuration sections use defaults
- Invalid configuration values fall back to defaults
- Configuration file is created automatically when settings are saved

## Troubleshooting

### Configuration Not Loading

1. Check file permissions on `~/.config/pt-journal/config.toml`
2. Verify TOML syntax with a TOML validator
3. Check environment variable names (case-sensitive)

### Chatbot Connection Issues

1. Verify Ollama is running: `curl http://localhost:11434/api/tags`
2. Check endpoint URL in configuration
3. Ensure model is available: `ollama list`

### Environment Variables Not Working

1. Verify variable names match exactly
2. Check variable is exported in current shell
3. Restart application after setting variables

## Advanced Configuration

### Custom Ollama Instances

```toml
[chatbot]
endpoint = "https://my-ollama-instance.com"
model = "custom-model"
```

### Multiple Model Support

The configuration currently supports one default model. Future versions may support model selection per step or context.

---

**Last Updated**: November 25, 2025
