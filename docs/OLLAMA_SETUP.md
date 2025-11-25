# Ollama Setup Guide for PT Journal

This guide explains how to set up Ollama for local LLM integration with PT Journal's chatbot feature.

## Overview

PT Journal integrates with Ollama to provide local LLM assistance for penetration testing workflows. The chatbot helps users understand methodology, interpret results, and get guidance on next steps.

## Prerequisites

- Linux, macOS, or Windows
- At least 8GB RAM (16GB recommended)
- Internet connection for model downloads

## Installation

### Linux

```bash
# Download and install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama service
ollama serve
```

### macOS

```bash
# Install via Homebrew
brew install ollama

# Start Ollama service
ollama serve
```

### Windows

Download the installer from [ollama.ai](https://ollama.ai) and run it.

## Model Setup

PT Journal is configured to use the `llama3.2` model by default. Download and set it up:

```bash
# Pull the default model
ollama pull llama3.2

# Verify installation
ollama list
```

### Alternative Models

You can use other models by changing the configuration. Popular options:

```bash
# Larger models (require more RAM)
ollama pull llama3.1:8b    # 8B parameters
ollama pull llama3.1:70b   # 70B parameters (requires significant RAM)

# Specialized models
ollama pull codellama      # Code-focused model
ollama pull mistral        # Fast, efficient model
```

## Configuration

### Default Configuration

PT Journal uses these default settings:

```toml
[chatbot]
endpoint = "http://localhost:11434"
model = "llama3.2:latest"
timeout_seconds = 60
```

### Custom Configuration

Create `~/.config/pt-journal/config.toml` to customize:

```toml
[chatbot]
endpoint = "http://localhost:11434"  # Change if Ollama runs on different port/host
model = "llama3.1:8b"                # Use different model
timeout_seconds = 120                # Increase timeout for slower models
```

### Environment Variables

Override configuration with environment variables:

```bash
export PT_JOURNAL_OLLAMA_ENDPOINT="http://192.168.1.100:11434"
export PT_JOURNAL_OLLAMA_MODEL="mistral"
export PT_JOURNAL_OLLAMA_TIMEOUT_SECONDS="120"
```

## Testing the Setup

### Verify Ollama is Running

```bash
# Check if Ollama service is responding
curl http://localhost:11434/api/tags
```

You should see JSON output listing available models.

### Test with PT Journal

1. Start PT Journal: `cargo run`
2. Navigate to any tutorial step
3. Use the chat panel to ask a question
4. The assistant should respond with pentesting guidance

## Troubleshooting

### Common Issues

#### "Connection refused" Error

**Problem**: Ollama service is not running.

**Solution**:
```bash
# Start Ollama in background
ollama serve &

# Or run in foreground for debugging
ollama serve
```

#### "Model not found" Error

**Problem**: The configured model is not downloaded.

**Solution**:
```bash
# Download the model
ollama pull llama3.2

# List available models
ollama list
```

#### Slow Responses

**Problem**: Model is too large for available RAM.

**Solutions**:
- Use a smaller model: `ollama pull llama3.2:1b`
- Increase system RAM
- Use CPU-only mode if you have a GPU: `OLLAMA_GPU_LAYERS=0 ollama serve`

#### Timeout Errors

**Problem**: Model takes too long to respond.

**Solutions**:
- Increase timeout in config: `timeout_seconds = 60`
- Use a faster model
- Check system resources (CPU/RAM usage)

### Performance Tuning

#### GPU Acceleration

Ollama automatically uses GPU if available. To force CPU-only:

```bash
OLLAMA_GPU_LAYERS=0 ollama serve
```

#### Memory Management

Monitor memory usage:

```bash
# Check Ollama memory usage
ps aux | grep ollama

# Free up memory by unloading models
ollama stop
```

#### Model Switching

Switch between models without restarting:

```bash
# Stop current model
ollama stop

# Start different model
ollama serve &
ollama pull new_model_name
```

## Advanced Configuration

### Custom System Prompts

PT Journal includes pentesting-specific system prompts. The chatbot context includes:

- Current session phase and step
- Tutorial methodology guidance
- Evidence collection requirements
- Security testing best practices

### Network Configuration

For remote Ollama servers:

```toml
[chatbot]
endpoint = "http://remote-server:11434"
```

Ensure the remote server has proper authentication and network security.

### Multiple Models

Configure different models for different purposes:

```bash
# Download multiple models
ollama pull llama3.2      # General purpose
ollama pull codellama     # Code analysis
ollama pull mistral       # Fast responses
```

Switch models by updating the configuration file.

## Security Considerations

- Ollama runs locally - no data is sent to external services
- Chat history is stored in session files alongside other project data
- Models are downloaded from ollama.ai - verify integrity if concerned
- No authentication required for local Ollama instance

## Updating Models

Keep models current:

```bash
# Update Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Update models
ollama pull llama3.2  # Re-download latest version
```

## Support

If you encounter issues:

1. Check Ollama logs: `ollama logs`
2. Verify model installation: `ollama list`
3. Test API endpoint: `curl http://localhost:11434/api/tags`
4. Check PT Journal logs for specific error messages

For PT Journal specific issues, see the main documentation or create an issue in the repository.
