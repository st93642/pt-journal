# Multi-Model Setup Guide for PT Journal

This guide explains how to set up multiple LLM backends for PT Journal's chatbot feature, including Ollama and llama.cpp support.

## Overview

PT Journal integrates with multiple LLM backends to provide local AI assistance for penetration testing workflows. The chatbot helps users understand methodology, interpret results, and get guidance on next steps.

## Supported Backends

1. **Ollama** - Network-based LLM server (recommended for most users)
2. **llama.cpp** - Local GGUF model inference (advanced users)

## Prerequisites

- Linux, macOS, or Windows
- At least 8GB RAM (16GB recommended for larger models)
- Internet connection for model downloads
- Optional: GPU for accelerated inference

## Quick Start

### Option 1: Ollama (Recommended)

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama service
ollama serve

# Pull default model
ollama pull llama3.2

# Run PT Journal
cargo run
```

### Option 2: llama.cpp (Advanced)

```bash
# Build PT Journal with llama-cpp support
cargo build --features llama-cpp

# Download a GGUF model (example: Phi-3 Mini)
wget https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-q4.gguf

# Configure model path
export PT_JOURNAL_LLAMA_CPP_GGUF_PATH="/path/to/Phi-3-mini-4k-instruct-q4.gguf"

# Run PT Journal
cargo run --features llama-cpp
```

## Ollama Installation

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

## Recommended Models

PT Journal includes 5 pre-configured Ollama models. Install them with:

```bash
# Default model (installed automatically)
ollama pull llama3.2

# Fast, efficient model
ollama pull mistral:7b

# Small, capable model  
ollama pull phi3:mini-4k-instruct

# Conversational model
ollama pull neural-chat:latest

# Code-focused model
ollama pull starcoder:latest
```

### Alternative Models

You can use other models by adding them to the configuration:

```bash
# Larger models (require more RAM)
ollama pull llama3.1:8b    # 8B parameters
ollama pull llama3.1:70b   # 70B parameters (requires significant RAM)

# Specialized models
ollama pull codellama      # Code-focused model
ollama pull qwen:7b        # Multilingual model
```

## llama.cpp Setup (Advanced)

### Building with llama-cpp Support

PT Journal includes optional llama.cpp support for local GGUF inference:

```bash
# Build with llama-cpp feature
cargo build --features llama-cpp

# Or run directly
cargo run --features llama-cpp
```

### Downloading GGUF Models

GGUF models are single files that contain the entire model. Popular sources:

1. **Hugging Face** - <https://huggingface.co/models?search=gguf>
2. **TheBloke's Models** - <https://huggingface.co/TheBloke>

**Recommended GGUF Models**:

```bash
# Phi-3 Mini (4K context, ~2GB)
wget https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-q4.gguf

# Mistral 7B (8K context, ~4GB) 
wget https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.gguf

# Llama 3.2 3B (128K context, ~2GB)
wget https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/resolve/main/Llama-3.2-3B-Instruct-Q4_K_M.gguf
```

### llama.cpp Configuration

Create `~/.config/pt-journal/config.toml`:

```toml
[chatbot]
default_model_id = "local-phi3"

[[chatbot.models]]
id = "local-phi3"
display_name = "Phi-3 Mini (Local)"
provider = "llama-cpp"
prompt_template = "{{context}}"
resource_paths = ["/path/to/Phi-3-mini-4k-instruct-q4.gguf"]

[chatbot.llama_cpp]
gguf_path = "/path/to/Phi-3-mini-4k-instruct-q4.gguf"
context_tokens = 4096
```

**Environment Variables**:

```bash
export PT_JOURNAL_LLAMA_CPP_GGUF_PATH="/path/to/model.gguf"
export PT_JOURNAL_LLAMA_CPP_CONTEXT_SIZE="8192"
```

## Testing the Setup

### Verify Ollama is Running

```bash
# Check if Ollama service is responding
curl http://localhost:11434/api/tags
```

You should see JSON output listing available models.

### Verify GGUF Models (llama.cpp)

```bash
# Check if GGUF file exists and is readable
ls -la /path/to/model.gguf
file /path/to/model.gguf

# Test with PT Journal (with llama-cpp feature)
cargo run --features llama-cpp
```

### Test with PT Journal

1. Start PT Journal: `cargo run`
2. Navigate to any tutorial step
3. Open the chat panel (should show model selector)
4. Select a model from the dropdown
5. Ask a question about the current step
6. The assistant should respond with pentesting guidance

### Verify Model Selection

The model selector dropdown should show:

- All configured Ollama models (if Ollama is running)
- All configured llama.cpp models (if GGUF paths are valid)
- Default model should be pre-selected

## Troubleshooting

### Backend-Specific Issues

#### Ollama Backend

| Symptom | Cause | Solution |
|---------|-------|----------|
| "Connection refused" | Ollama not running | Start with `ollama serve` |
| "Model not found" | Model not downloaded | Run `ollama pull <model>` |
| Slow responses | Model too large for RAM | Use smaller model or increase RAM |
| Timeout errors | Slow inference or network | Increase `timeout_seconds` in config |

#### llama.cpp Backend

| Symptom | Cause | Solution |
|---------|-------|----------|
| "GGUF path not found" | Invalid file path | Check `gguf_path` in config or env var |
| "Model load error" | Corrupted GGUF file | Re-download model file |
| "Inference error" | Insufficient RAM | Use smaller context or model |
| "Provider not available" | llama-cpp feature disabled | Build with `--features llama-cpp` |

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

#### llama.cpp Issues

**GGUF File Problems**:

```bash
# Verify file integrity
md5sum model.gguf
# Compare with expected hash from source

# Check file permissions
chmod 644 model.gguf
```

**Memory Issues**:

```bash
# Reduce context size
export PT_JOURNAL_LLAMA_CPP_CONTEXT_SIZE="2048"

# Use smaller model
# Download a quantized version (Q2, Q3)
```

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
