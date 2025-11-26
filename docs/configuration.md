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
default_model_id = "llama3.2:latest"

[[chatbot.models]]
id = "llama3.2:latest"
display_name = "Meta Llama 3.2"
provider = "ollama"
prompt_template = "{{context}}"

[chatbot.ollama]
endpoint = "http://localhost:11434"
timeout_seconds = 180

[chatbot.llama_cpp]
gguf_path = "/opt/llms/custom.gguf"
context_tokens = 4096
```

### Chatbot Configuration

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `default_model_id` | string | `"llama3.2:latest"` | Model profile ID used for chats |
| `[[chatbot.models]]` | array of tables | 5 seed profiles | Offline model definitions (id, provider, template, resources) |
| `[chatbot.ollama].endpoint` | string | `"http://localhost:11434"` | Ollama API endpoint URL |
| `[chatbot.ollama].timeout_seconds` | integer | `180` | HTTP timeout for Ollama requests |
| `[chatbot.llama_cpp].gguf_path` | string | `null` | Optional llama.cpp GGUF path |
| `[chatbot.llama_cpp].context_tokens` | integer | `4096` | llama.cpp context window (tokens) |

## Configuration Priority

Settings are loaded in the following priority order (highest to lowest):

1. **Environment Variables** (runtime override)
2. **TOML Configuration File** (persistent user settings)
3. **Default Values** (fallback)

## Environment Variables

| Variable | Maps To | Example |
|----------|---------|---------|
| `PT_JOURNAL_CHATBOT_MODEL_ID` | `chatbot.default_model_id` | `phi3:mini-4k-instruct` |
| `PT_JOURNAL_OLLAMA_ENDPOINT` | `chatbot.ollama.endpoint` | `http://custom-ollama:8080` |
| `PT_JOURNAL_OLLAMA_MODEL` | `chatbot.default_model_id` (legacy alias) | `mistral:7b` |
| `PT_JOURNAL_OLLAMA_TIMEOUT_SECONDS` | `chatbot.ollama.timeout_seconds` | `240` |
| `PT_JOURNAL_LLAMA_CPP_GGUF_PATH` | `chatbot.llama_cpp.gguf_path` | `/models/phi3.gguf` |
| `PT_JOURNAL_LLAMA_CPP_CONTEXT_SIZE` | `chatbot.llama_cpp.context_tokens` | `8192` |
| `PT_JOURNAL_LLAMA_CPP_SERVER_URL` | `chatbot.llama_cpp.server_url` | `http://localhost:8081` |

### Usage Examples

```bash
# Use custom Ollama instance
export PT_JOURNAL_OLLAMA_ENDPOINT="http://192.168.1.100:11434"
export PT_JOURNAL_CHATBOT_MODEL_ID="codellama:13b"

# Run PT Journal
cargo run
```

```bash
# Docker container with custom config
docker run -e PT_JOURNAL_OLLAMA_ENDPOINT=http://host.docker.internal:11434 \
           -e PT_JOURNAL_CHATBOT_MODEL_ID=phi3:mini-4k-instruct \
           pt-journal
```

## Programmatic Access

Configuration is loaded automatically when the application starts and is available through the `AppModel`:

```rust
let config = &app_model.config;
let endpoint = &config.chatbot.ollama.endpoint;
let active_model = config.chatbot.active_model();
println!("Chatbot using {} ({})", active_model.display_name, active_model.id);
```

## Default Configuration

If no configuration file exists and no environment variables are set, PT Journal uses these defaults:

- **Ollama Endpoint**: `http://localhost:11434` (standard Ollama port)
- **Default Model ID**: `llama3.2:latest` (Meta Llama 3.2)
- **Seeded Model Profiles**: Llama 3.2, Mistral 7B, Phi-3 Mini, Intel Neural-Chat, StarCoder
- **Timeout**: `180s` for Ollama requests
- **llama.cpp Context**: `4096` tokens (GGUF path unset)

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

Define as many offline profiles as needed via `[[chatbot.models]]`. Each profile specifies an ID, display name, provider (`ollama` or `llama-cpp`), prompt template, and resource paths. Set `default_model_id` to choose the active profile; future UI updates may allow selecting different profiles per step.

---

**Last Updated**: November 25, 2025
