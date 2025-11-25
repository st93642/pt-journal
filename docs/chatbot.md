# PT Journal Chatbot Integration Guide

## Overview

PT Journal includes persistent chatbot functionality that allows users to have AI-assisted conversations within tutorial steps. Chat history is automatically saved with session files, enabling continuity across application restarts.

## Features

- **Persistent Conversations**: Chat history survives application restarts
- **Per-Step Context**: Each tutorial step maintains its own conversation
- **Role-Based Messages**: Distinguishes between user and assistant messages
- **Timestamp Tracking**: All messages include UTC timestamps
- **Configurable Backend**: Supports Ollama and other LLM endpoints

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

### Ollama Configuration

Chatbot functionality integrates with configurable LLM backends. See [Configuration Guide](configuration.md) for setup details.

Default configuration:

- **Endpoint**: `http://localhost:11434`
- **Model**: `mistral`

### Environment Variables

```bash
export PT_JOURNAL_OLLAMA_ENDPOINT="http://custom-ollama:8080"
export PT_JOURNAL_OLLAMA_MODEL="llama2"
```

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

### Planned Features

- **Chat Interface**: Text input and message display per tutorial step
- **Context Awareness**: Include step content in prompts
- **Streaming Responses**: Real-time message updates
- **Message Management**: Edit, delete, and search messages

### State Management

Chat messages are managed through the existing `AppModel` and UI state system:

```rust
// Access current step's chat history
let current_step = &app_model.session.phases[phase_idx].steps[step_idx];
let chat_history = current_step.get_chat_history();
```

## Visual Design Refresh

The embedded chatbot window now uses a high-contrast neon palette so that conversations stand out from tutorial content:

- **Chat History**: Each message row lives inside a `chat-history` list with a charcoal background and pale green typography for both user and assistant roles. Timestamp badges use a dimmer teal to prevent glare.
- **Input Surface**: The `chat-input` text view and surrounding scroller share a glassy dark finish with mint-colored text/caret, making prompts readable even when the GTK dark theme is enabled.
- **Panel Framing**: The outer `chat-panel` container adds a subtle emerald border and rounded corners so the entire assistant experience reads as a dedicated console inside the detail view.

These styles are installed globally through the GTK CSS provider (`CHAT_PANEL_CSS`) during UI initialization, which keeps the appearance consistent across all windows and future chat-related widgets.

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

## Future Enhancements

### Planned Features

- **Multi-Modal Support**: Image and file attachments
- **Conversation Branching**: Alternative response exploration
- **Export/Import**: Share conversations between sessions
- **Advanced Prompting**: Context-aware system prompts
- **Integration APIs**: REST endpoints for external tools

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

### Common Issues

1. **Messages Not Saving**: Check session file permissions
2. **Large Histories**: Consider clearing old conversations
3. **Performance Issues**: Monitor session file sizes
4. **Backend Connection**: Verify Ollama configuration

### Debugging

Enable debug logging to trace chat operations:

```rust
// Check message counts
println!("Step has {} chat messages", step.get_chat_history().len());

// Verify message structure
for msg in step.get_chat_history() {
    println!("{}: {}", msg.role, msg.content.len());
}
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

**Last Updated**: November 26, 2025
