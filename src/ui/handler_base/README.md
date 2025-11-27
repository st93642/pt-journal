# Handler Base Abstraction

This document describes the Handler Base Abstraction implemented as part of Step 3 of the PT Journal refactoring plan.

## Overview

The Handler Base Abstraction provides a standardized interface for handling UI events and coordinating between user interactions and application state. It follows a functional pattern where handlers are pure functions that transform event context into UI updates.

## Architecture

### Core Components

1. **`Handler` Trait**: Defines the standard interface for all event handlers
2. **`HandlerContext`**: Contains event data and optional state access
3. **`EventData`**: Enum for different types of event data
4. **`UIUpdate`**: Enum for UI update requests
5. **`HandlerError`**: Error type for handler failures

### Handler Trait

```rust
pub trait Handler {
    type Context;
    type Result;

    fn handle(&self, context: Self::Context) -> Self::Result;
}
```

Handlers implement this trait to process events and return UI updates.

### Handler Context

```rust
pub struct HandlerContext {
    pub state: Option<Rc<StateManager>>,  // Optional state access
    pub event_data: EventData,            // Event-specific data
}
```

### Event Data Types

- `None`: No event data
- `String(String)`: Text data
- `Index(usize)`: Single index
- `Bool(bool)`: Boolean value
- `Tuple((usize, usize))`: Two indices
- `Triple((usize, usize, usize))`: Three indices

### UI Update Types

- `None`: No UI update needed
- `UpdateDetailPanel`: Refresh detail panel
- `RefreshStepsList`: Refresh steps list
- `RefreshPhaseCombo`: Refresh phase combo
- `ShowError(String)`: Show error message
- `ShowSuccess(String)`: Show success message
- `UpdateQuizStats`: Update quiz statistics
- `RefreshQuizQuestion`: Refresh current question
- `Custom(String)`: Custom update

## Usage Examples

### Simple Handler (No State)

```rust
use crate::ui::handler_base::{Handler, HandlerContext, UIUpdate, HandlerError};

pub struct SidebarToggleHandler {
    left_box: gtk4::Box,
}

impl Handler for SidebarToggleHandler {
    type Context = HandlerContext;
    type Result = Result<UIUpdate, HandlerError>;

    fn handle(&self, _context: Self::Context) -> Self::Result {
        let is_visible = self.left_box.is_visible();
        self.left_box.set_visible(!is_visible);
        Ok(UIUpdate::None)
    }
}
```

### State-Aware Handler

```rust
pub struct PhaseSelectionHandler {
    steps_list: gtk4::ListBox,
    detail_panel: Rc<DetailPanel>,
}

impl Handler for PhaseSelectionHandler {
    type Context = HandlerContext;
    type Result = Result<UIUpdate, HandlerError>;

    fn handle(&self, context: Self::Context) -> Self::Result {
        let state = context.state.ok_or_else(|| {
            HandlerError::StateError("Phase selection requires state".to_string())
        })?;

        let phase_idx = match context.event_data {
            EventData::Index(idx) => idx,
            _ => return Err(HandlerError::ValidationError("Expected Index".to_string())),
        };

        state.select_phase(phase_idx);
        Ok(UIUpdate::RefreshStepsList)
    }
}
```

### Connecting to GTK Signals

```rust
use crate::ui::handler_base::{create_context, execute_handler};

pub fn setup_sidebar_handler(btn_sidebar: &Button, left_box: &gtk4::Box) {
    let handler = SidebarToggleHandler::new(left_box.clone());

    btn_sidebar.connect_clicked(move |_| {
        let context = create_context(None, EventData::None);

        if let Err(e) = execute_handler(&handler, context) {
            eprintln!("Handler error: {}", e);
        }
    });
}
```

## Benefits

1. **Consistency**: All handlers follow the same interface pattern
2. **Testability**: Handlers can be unit tested independently
3. **Separation of Concerns**: UI logic separated from GTK event handling
4. **Error Handling**: Standardized error handling across all handlers
5. **State Management**: Clear state access patterns

## Migration Strategy

The handler abstraction is designed to work alongside existing controller patterns. Migration can happen incrementally:

1. Start with simple handlers (like sidebar toggle)
2. Convert state-aware handlers gradually
3. Update controller patterns to use handler traits
4. Eventually replace controller pattern entirely

## Testing

Handlers include comprehensive unit tests:

```rust
#[test]
fn test_handler_error_variants() {
    assert!(matches!(
        HandlerError::ValidationError("test".to_string()),
        HandlerError::ValidationError(_)
    ));
}
```

## Future Enhancements

- Async handler support for long-running operations
- Handler chaining for complex event processing
- Middleware pattern for cross-cutting concerns
- Handler registration system for dynamic UI