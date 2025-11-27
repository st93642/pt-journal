# PT Journal Configuration Guide

## Overview

PT Journal supports configurable settings for Ollama chatbot integration and other features through a TOML configuration file. Configuration can be customized per-user and supports environment variable overrides for containerized deployments.

## Configuration File Location

The configuration file is located at:

- **Linux/macOS**: `~/.config/pt-journal/config.toml`
- **Windows**: `%APPDATA%\pt-journal\config.toml`

The directory is created automatically when the application first saves configuration.

## Configuration Structure

```toml
[chatbot]
default_model_id = "llama3.2"

[[chatbot.models]]
id = "llama3.2"
display_name = "Meta Llama 3.2"
provider = "ollama"
prompt_template = "{{context}}"

[chatbot.ollama]
endpoint = "http://localhost:11434"
timeout_seconds = 180
```

### Chatbot Configuration

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `default_model_id` | string | `"llama3.2"` | Model profile ID used for chats |
| `[[chatbot.models]]` | array of tables | 5 seed profiles | Offline model definitions (id, provider, template, resources) |
| `[chatbot.ollama].endpoint` | string | `"http://localhost:11434"` | Ollama API endpoint URL |
| `[chatbot.ollama].timeout_seconds` | integer | `180` | HTTP timeout for Ollama requests |

### Model Profile Configuration

Each `[[chatbot.models]]` entry supports these fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique model identifier |
| `display_name` | string | Yes | Human-readable name for UI |
| `provider` | string | Yes | `"ollama"` |
| `prompt_template` | string | Yes | Template for prompts (e.g., `"{{context}}"`) |
| `resource_paths` | array | No | Reserved for future use |
| `parameters` | table | No | Model parameters (temperature, top_p, etc.) |

### Model Parameters

Optional per-model parameters:

```toml
parameters = { 
    temperature = 0.7,      # Randomness (0.0-1.0)
    top_p = 0.9,            # Nucleus sampling (0.0-1.0)
    top_k = 40,             # Top-k sampling (-1 for disabled)
    num_predict = 512       # Max tokens to generate
}
```

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

### Usage Examples

```bash
# Use custom Ollama instance
export PT_JOURNAL_OLLAMA_ENDPOINT="http://custom-ollama:8080"
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

// Access all available models
for profile in &config.chatbot.models {
    println!("Model: {} ({})", profile.display_name, profile.provider);
}
```

## Default Configuration

If no configuration file exists and no environment variables are set, PT Journal uses these defaults:

- **Ollama Endpoint**: `http://localhost:11434` (standard Ollama port)
- **Default Model ID**: `llama3.2:latest` (Meta Llama 3.2)
- **Seeded Model Profiles**: 5 Ollama models (Llama 3.2, Mistral 7B, Phi-3 Mini, Intel Neural-Chat, StarCoder)
- **Timeout**: `180s` for Ollama requests

### Default Seeded Models

PT Journal includes these pre-configured Ollama models:

```toml
[[chatbot.models]]
id = "llama3.2"
display_name = "Meta Llama 3.2"
provider = "ollama"

[[chatbot.models]]
id = "mistral:7b"
display_name = "Mistral 7B Instruct"
provider = "ollama"

[[chatbot.models]]
id = "phi3:mini-4k-instruct"
display_name = "Phi-3 Mini 4K"
provider = "ollama"

[[chatbot.models]]
id = "neural-chat:latest"
display_name = "Intel Neural Chat"
provider = "ollama"

[[chatbot.models]]
id = "starcoder:latest"
display_name = "StarCoder"
provider = "ollama"
```

## Migration and Compatibility

- Configuration is optional - PT Journal works without any configuration file
- Missing configuration sections use defaults
- Invalid configuration values fall back to defaults
- Configuration file is created automatically when settings are saved
- Legacy Ollama-only configurations are automatically migrated

## Troubleshooting

### Configuration Not Loading

1. Check file permissions on `~/.config/pt-journal/config.toml`
2. Verify TOML syntax with a TOML validator
3. Check environment variable names (case-sensitive)
4. Ensure all required fields are present in model profiles

### Chatbot Connection Issues

1. **Ollama**: Verify Ollama is running: `curl http://localhost:11434/api/tags`
2. Ensure model is available in the configured backend
3. Verify provider field matches backend (`"ollama"`)

### Model Selection Issues

1. Check that `default_model_id` matches an entry in `[[chatbot.models]]`
2. Verify model profile has all required fields
3. Ensure provider-specific fields are correct
4. Restart application after configuration changes

### Environment Variables Not Working

1. Verify variable names match exactly
2. Check variable is exported in current shell
3. Restart application after setting variables
4. Check for typos in variable values

## Advanced Configuration

### Custom Ollama Instances

```toml
[chatbot.ollama]
endpoint = "https://my-ollama-instance.com"
timeout_seconds = 300
```

### Performance Tuning

```toml
[[chatbot.models]]
id = "fast-model"
provider = "ollama"
parameters = { 
    temperature = 0.1,      # More deterministic
    top_p = 0.8,           # Tighter sampling
    num_predict = 256       # Shorter responses
}

[chatbot.ollama]
timeout_seconds = 60        # Faster timeout
```

---

**Last Updated**: November 25, 2025
