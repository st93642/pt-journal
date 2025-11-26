# PT Journal Multi-Model Chatbot Integration Guide

## Overview

PT Journal includes persistent multi-model chatbot functionality that allows users to have AI-assisted conversations within tutorial steps. Chat history is automatically saved with session files, enabling continuity across application restarts. The system supports both Ollama-based models and local GGUF models via llama.cpp.

## Features

- **Multi-Model Support**: Choose between Ollama and llama.cpp backends
- **Persistent Conversations**: Chat history survives application restarts
- **Per-Step Context**: Each tutorial step maintains its own conversation
- **Role-Based Messages**: Distinguishes between user and assistant messages
- **Timestamp Tracking**: All messages include UTC timestamps
- **Configurable Backend**: Supports Ollama and llama.cpp LLM endpoints
- **Model Selector UI**: Dropdown to switch between available models dynamically
- **Provider Abstraction**: Extensible ChatProvider trait for new backends

## Data Structures

### ChatRole

```rust
pub enum ChatRole {
    User,      // Messages from the user
    Assistant, // Responses from the AI assistant
}
```

### ChatMessage

```rust
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
    pub timestamp: DateTime<Utc>,
}
```

### Step Content Extension

Tutorial steps now include a `chat_history` field:

```rust
pub enum StepContent {
    Tutorial {
        description: String,
        description_notes: String,
        notes: String,
        evidence: Vec<Evidence>,
        chat_history: Vec<ChatMessage>, // New field
    },
    Quiz { quiz_data: QuizStep },
}
```

## Usage

### Adding Messages

```rust
// Create a new message
let user_message = ChatMessage::new(ChatRole::User, "How do I scan for open ports?".to_string());

// Add to step history
step.add_chat_message(user_message);
```

### Retrieving History

```rust
// Get all messages for a step
let history = step.get_chat_history();

// Process messages
for message in history {
    match message.role {
        ChatRole::User => println!("User: {}", message.content),
        ChatRole::Assistant => println!("Assistant: {}", message.content),
    }
}
```

### Clearing History

```rust
// Clear all chat messages for a step
step.clear_chat_history();
```

## Persistence

Chat history is automatically saved and loaded with session files:

```json
{
  "content": {
    "Tutorial": {
      "description": "Port scanning tutorial...",
      "description_notes": "",
      "notes": "",
      "evidence": [],
      "chat_history": [
        {
          "role": "User",
          "content": "How do I scan for open ports?",
          "timestamp": "2025-11-25T10:30:00Z"
        },
        {
          "role": "Assistant",
          "content": "You can use nmap: nmap -p- target.com",
          "timestamp": "2025-11-25T10:30:05Z"
        }
      ]
    }
  }
}
```

## Backend Integration

PT Journal supports multiple LLM backends through a provider abstraction system.

### Ollama Provider

For network-based LLM inference.

**Configuration**:

```toml
[chatbot.ollama]
endpoint = "http://localhost:11434"
timeout_seconds = 180
```

**Environment Variables**:

```bash
export PT_JOURNAL_OLLAMA_ENDPOINT="http://custom-ollama:8080"
export PT_JOURNAL_OLLAMA_TIMEOUT_SECONDS="240"
```

### llama.cpp Provider

For local GGUF model inference.

**Features**:

- Local GGUF model inference with threading
- 30-second timeout to prevent hanging on slow models
- Model caching with `Arc<Mutex<HashMap>>`
- Context window configuration
- Feature-gated (`llama-cpp` feature)
- Stub implementation for testing without feature

**Configuration**:

```toml
[chatbot.llama_cpp]
gguf_path = "/path/to/model.gguf"  # Optional
context_tokens = 4096
server_url = "http://localhost:8081"  # Optional future feature
```

**Environment Variables**:

```bash
export PT_JOURNAL_LLAMA_CPP_GGUF_PATH="/models/phi3.gguf"
export PT_JOURNAL_LLAMA_CPP_CONTEXT_SIZE="8192"
export PT_JOURNAL_LLAMA_CPP_SERVER_URL="http://localhost:8081"
```

### Model Profiles

Configure available models in `~/.config/pt-journal/config.toml`:

```toml
[chatbot]
default_model_id = "llama3.2:latest"

[[chatbot.models]]
id = "llama3.2:latest"
display_name = "Meta Llama 3.2"
provider = "ollama"
prompt_template = "{{context}}"

[[chatbot.models]]
id = "local-phi3"
display_name = "Phi-3 Mini (Local)"
provider = "llama-cpp"
prompt_template = "{{context}}"
resource_paths = ["/models/phi3.gguf"]

[[chatbot.models]]
id = "mistral:7b"
display_name = "Mistral 7B Instruct"
provider = "ollama"
prompt_template = "{{context}}"
parameters = { temperature = 0.7, top_p = 0.9 }
```

### Default Seeded Models

PT Journal includes 5 pre-configured Ollama models:

- **Meta Llama 3.2** (`llama3.2:latest`) - Default
- **Mistral 7B Instruct** (`mistral:7b`) - Fast, efficient
- **Phi-3 Mini 4K** (`phi3:mini-4k-instruct`) - Small, capable
- **Intel Neural Chat** (`neural-chat:latest`) - Conversational
- **StarCoder** (`starcoder:latest`) - Code-focused

### Environment Variables

| Variable | Maps To | Example |
|----------|---------|---------|
| `PT_JOURNAL_CHATBOT_MODEL_ID` | `chatbot.default_model_id` | `phi3:mini-4k-instruct` |
| `PT_JOURNAL_OLLAMA_ENDPOINT` | `chatbot.ollama.endpoint` | `http://custom-ollama:8080` |
| `PT_JOURNAL_OLLAMA_MODEL` | `chatbot.default_model_id` (legacy) | `mistral:7b` |
| `PT_JOURNAL_OLLAMA_TIMEOUT_SECONDS` | `chatbot.ollama.timeout_seconds` | `240` |
| `PT_JOURNAL_LLAMA_CPP_GGUF_PATH` | `chatbot.llama_cpp.gguf_path` | `/models/phi3.gguf` |
| `PT_JOURNAL_LLAMA_CPP_CONTEXT_SIZE` | `chatbot.llama_cpp.context_tokens` | `8192` |
| `PT_JOURNAL_LLAMA_CPP_SERVER_URL` | `chatbot.llama_cpp.server_url` | `http://localhost:8081` |

## Migration

### Backward Compatibility

Existing session files without `chat_history` load successfully with empty chat histories. The field defaults to an empty vector.

### Legacy Sessions

When loading older sessions, the migration process automatically adds the `chat_history` field:

```rust
impl Step {
    pub fn migrate_from_legacy(&mut self) {
        // Existing migration logic...
        // chat_history defaults to Vec::new()
    }
}
```

## UI Integration

### Model Selector

The chat panel includes a dropdown selector for switching between available models:

- **Location**: Top of chat panel
- **Functionality**:
  - Lists all configured models with display names
  - Defaults to configured `default_model_id`
  - Disabled during chat requests
  - Updates active model immediately on selection

### Chat Interface

- **Message Input**: Multi-line text area with Enter/Shift+Enter handling
- **Send Button**: Enabled when text is entered, disabled during requests
- **History Display**: Scrollable list with user/assistant role labels
- **Loading Indicator**: Spinner during model inference
- **Error Display**: Banner for connection or model errors

### State Management

Chat messages are managed through the existing `AppModel` and UI state system:

```rust
// Access current step's chat history
let current_step = &app_model.session.phases[phase_idx].steps[step_idx];
let chat_history = current_step.get_chat_history();

// Change active model
state_manager.set_chat_model("mistral:7b".to_string());
```

### Planned Features

- **Streaming Responses**: Real-time message updates
- **Message Management**: Edit, delete, and search messages
- **Model Parameters UI**: Adjust temperature, top_p, etc. per conversation
- **Conversation Branching**: Alternative response exploration

## Security Considerations

### Data Privacy

- Chat messages are stored locally in session files
- No messages are transmitted unless explicitly configured
- User controls all data storage locations

### Input Validation

- Message content should be validated before processing
- Large messages may impact performance
- HTML/script injection protection required in UI

## Performance

### Storage Impact

- Chat messages increase session file size
- JSON serialization includes full message history
- Large conversations may slow save/load operations

### Memory Usage

- Messages kept in memory during session
- UI should implement pagination for long conversations
- Consider lazy loading for performance

### API Extensions

```rust
// Future API possibilities
pub trait ChatProvider {
    async fn send_message(&self, messages: &[ChatMessage]) -> Result<ChatMessage>;
    fn supports_streaming(&self) -> bool;
    fn max_context_length(&self) -> usize;
}
```

## Troubleshooting

### Backend-Specific Issues

#### Ollama Backend

| Symptom | Cause | Solution |
|---------|-------|----------|
| "Connection refused" | Ollama not running | Start with `ollama serve` |
| "Model not found" | Model not downloaded | Run `ollama pull <model>` |
| Slow responses | Model too large for RAM | Use smaller model or increase RAM |
| Timeout errors | Slow inference or network | Increase `timeout_seconds` |

#### llama.cpp Backend

| Symptom | Cause | Solution |
|---------|-------|----------|
| "GGUF path not found" | Invalid file path | Check `gguf_path` in config or env var |
| "Model load error" | Corrupted GGUF file | Re-download model file |
| "Inference error" | Insufficient RAM | Use smaller context or model |
| "Timeout error" | Model inference taking too long | Wait or use faster model (30s timeout) |
| "Provider not available" | llama-cpp feature disabled | Build with `--features llama-cpp` |

### Common Issues

1. **Messages Not Saving**: Check session file permissions
2. **Large Histories**: Consider clearing old conversations  
3. **Performance Issues**: Monitor session file sizes
4. **Model Selection Not Working**: Verify model profiles in config
5. **Backend Switching**: Restart app after changing provider config

### Debugging

Enable debug logging to trace chat operations:

```rust
// Check message counts
println!("Step has {} chat messages", step.get_chat_history().len());

// Verify message structure
for msg in step.get_chat_history() {
    println!("{}: {}", msg.role, msg.content.len());
}

// Check available models
let models = &app_model.config.chatbot.models;
for profile in models {
    println!("Model: {} ({})", profile.display_name, profile.provider);
}
```

### Testing Backends

```bash
# Test Ollama
curl http://localhost:11434/api/tags

# Test llama.cpp (if using server mode)
curl http://localhost:8081/completion -X POST \
  -H "Content-Type: application/json" \
  -d '{"prompt": "test", "n_predict": 10}'
```

## Testing

### Unit Tests

Chat functionality includes comprehensive tests:

```rust
#[test]
fn test_chat_message_creation() {
    let msg = ChatMessage::new(ChatRole::User, "test".to_string());
    assert_eq!(msg.role, ChatRole::User);
    assert_eq!(msg.content, "test");
}

#[test]
fn test_step_chat_history() {
    let mut step = Step::new_tutorial(Uuid::new_v4(), "Test".to_string(), "Desc".to_string(), vec![]);
    step.add_chat_message(ChatMessage::new(ChatRole::User, "Hello".to_string()));
    assert_eq!(step.get_chat_history().len(), 1);
}
```

### Integration Tests

Full workflow testing ensures persistence:

```rust
#[test]
fn test_chat_history_persistence() {
    // Save session with chat messages
    // Load session and verify messages preserved
}
```

---

**Last Updated**: November 25, 2025
