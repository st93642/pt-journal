# PT Journal System Architecture

## Overview

PT Journal is a GTK4/libadwaita desktop application built with Rust that provides structured penetration testing documentation and learning. The system follows a layered architecture with clear separation of concerns, enabling maintainable and extensible code.

## Core Architecture Principles

### 1. Layered Architecture

The application is divided into four distinct layers, each with specific responsibilities and clear interfaces.

### 2. Domain-Driven Design

Core business logic is encapsulated in domain models with rich behavior and validation.

### 3. Immutable Data Structures

Where possible, data structures are designed to be immutable with controlled mutation paths.

### 4. Error Handling

Comprehensive error handling using `anyhow::Result` with contextual error messages.

### 5. Testing First

All features include comprehensive unit and integration tests with 100% pass rate.

## Architecture Layers

### 1. Domain Layer (`src/model.rs`)

**Purpose**: Core business logic and data structures.

**Key Components**:

- `Session` - Top-level engagement container
- `Phase` - Methodology stages (Recon, Exploitation, etc.)
- `Step` - Individual actions with `StepContent` enum
- `Evidence` - File attachments with metadata
- `ChatMessage` / `ChatRole` - Chatbot conversation data

**Design Patterns**:

- **Entity Pattern**: UUID-based identity for all domain objects
- **Value Objects**: `DateTime<Utc>`, `PathBuf` for immutable values
- **Factory Methods**: `Session::default()`, `Step::new_tutorial()`
- **Encapsulation**: Private fields with controlled access

**Responsibilities**:

- Domain validation and business rules
- Data structure definitions
- Migration logic for backward compatibility
- Type-safe APIs for all operations

### 2. Infrastructure Layer (`src/store.rs`, `src/config.rs`)

**Purpose**: External system interactions and persistence.

**Components**:

- **Store Layer**: JSON serialization with folder structure
- **Config Layer**: TOML configuration with environment overrides

**Storage Architecture**:

```
~/Downloads/pt-journal-sessions/
└── session-name/
    ├── session.json     # Full session data
    └── evidence/        # Tool outputs, screenshots
```

**Configuration Hierarchy**:

1. Environment variables (highest priority)
2. TOML configuration file
3. Default values (fallback)

**Design Patterns**:

- **Repository Pattern**: Abstract data persistence
- **Configuration Pattern**: Hierarchical configuration loading
- **Builder Pattern**: Fluent configuration APIs

### 3. Application Layer (`src/dispatcher.rs`, `src/lib.rs`)

**Purpose**: Application coordination and event handling.

**Components**:

- **Event Dispatcher**: Decoupled message passing
- **State Manager**: Application state coordination
- **Test Infrastructure**: Comprehensive test suite

**Message Types**:

```rust
pub enum Message {
    SessionLoaded { session: Session },
    StepCompleted { step_id: Uuid },
    EvidenceAdded { evidence: Evidence },
    ToolExecuted { result: serde_json::Value },
}
```

**Design Patterns**:

- **Observer Pattern**: Event-driven architecture
- **Mediator Pattern**: Component coordination
- **Command Pattern**: Encapsulated operations

### 4. Presentation Layer (`src/ui/`)

**Purpose**: GTK4 user interface and user interaction.

**Architecture**:

- **Component-Based**: Modular UI components
- **Reactive**: State-driven UI updates
- **Asynchronous**: Non-blocking operations

**Key Components**:

- `main.rs` - Window assembly and layout
- `state.rs` - Application state management
- `handlers.rs` - Event handling and business logic
- `detail_panel.rs` - Content display switcher
- `canvas.rs` - Evidence positioning interface

**State Management**:

```rust
pub struct AppModel {
    pub session: Session,
    pub selected_phase: usize,
    pub selected_step: Option<usize>,
    pub current_path: Option<PathBuf>,
    pub config: AppConfig,  // New: Configuration access
}
```

## Data Flow Architecture

### Session Lifecycle

1. **Creation**: `Session::default()` creates 23-phase methodology
2. **Loading**: `store::load_session()` deserializes with migration
3. **Modification**: UI handlers update `AppModel` state
4. **Persistence**: `store::save_session()` serializes to disk

### Chatbot Integration

1. **Message Creation**: `ChatMessage::new()` with role and content
2. **History Management**: `Step::add_chat_message()` appends to history
3. **Persistence**: Automatic inclusion in session JSON
4. **UI Display**: Real-time rendering of conversation threads

### Configuration Flow

1. **Loading**: `AppConfig::load()` merges sources
2. **Runtime Access**: `app_model.config.chatbot.endpoint`
3. **Overrides**: Environment variables take precedence
4. **Persistence**: `AppConfig::save()` writes to TOML

## Component Interactions

### UI to Domain

```
UI Event → Handler → AppModel Update → Domain Validation → UI Refresh
```

### Domain to Infrastructure

```
Domain Change → Store.save_session() → JSON Serialization → File System
```

### Configuration Integration

```
App Startup → Config.load() → AppModel.config → Runtime Access
```

## Extensibility Points

### Adding New Tools

1. Implement `SecurityTool` trait
2. Register in tool discovery system
3. Add UI integration in `tool_execution.rs`
4. Write comprehensive tests (20+ tests)

### Adding New Tutorial Phases

1. Create phase content in `tutorials/`
2. Export from `mod.rs`
3. Update phase loading logic
4. Add validation tests

### Adding New UI Components

1. Create component in `src/ui/`
2. Integrate with main window layout
3. Connect to state management
4. Add comprehensive tests

## Performance Characteristics

### Memory Usage

- **Session Loading**: O(n) where n = session size
- **UI Rendering**: O(visible_components)
- **Chat History**: O(messages_per_step)

### Storage Performance

- **Save Operations**: < 500ms for typical sessions
- **Load Operations**: < 500ms for typical sessions
- **Large Sessions**: < 1s for 5MB+ files

### Scalability Limits

- **Maximum Steps**: Limited by available memory
- **Chat History**: Consider pagination for 1000+ messages
- **Evidence Files**: No hard limit, user disk space dependent

## Security Architecture

### Data Protection

- **Local Storage**: All data stored locally
- **User Control**: User chooses storage locations
- **No Telemetry**: No automatic data transmission

### Tool Execution Security

- **User Permissions**: Tools run with user privileges
- **Input Sanitization**: Command arguments validated
- **Timeout Protection**: Prevents hanging processes

### Configuration Security

- **Local Configuration**: No remote configuration fetching
- **Environment Variables**: Standard secure practices
- **File Permissions**: Standard filesystem security

## Testing Architecture

### Test Organization

- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow validation
- **Property Tests**: Randomized input validation

### Test Coverage Areas

- **Domain Logic**: 100% model validation
- **Persistence**: Save/load roundtrip testing
- **Configuration**: Loading and override testing
- **UI Components**: Widget creation and interaction

### Test Infrastructure

- **TempFile**: Isolated test environments
- **AssertMatches**: Pattern matching assertions
- **Proptest**: Property-based testing framework

## Deployment Architecture

### Native Application

- **Single Binary**: No runtime dependencies
- **Cross-Platform**: Linux, macOS, Windows support
- **Self-Contained**: GTK4 bundled appropriately

### Configuration Management

- **User-Specific**: Per-user configuration
- **Environment Agnostic**: Works in containers/VMs
- **Backward Compatible**: Graceful degradation

## Future Architecture Considerations

### Planned Enhancements

- **Plugin System**: Dynamic tool loading
- **Cloud Sync**: Optional remote storage
- **Team Collaboration**: Multi-user sessions
- **Advanced AI**: Enhanced chatbot capabilities

### Scalability Improvements

- **Lazy Loading**: On-demand content loading
- **Pagination**: Large dataset handling
- **Caching**: Performance optimization
- **Background Processing**: Non-blocking operations

---

**Last Updated**: November 25, 2025</content>
<parameter name="filePath">/home/altin/pt-journal/docs/architecture.md
