//! Tool execution panel and helper modules.
//!
//! This module provides the main `ToolExecutionPanel` UI component along with
//! supporting helpers for tool selection logic and instruction rendering.
//!
//! ## Architecture
//!
//! The tool execution module is split into three main parts:
//!
//! - **`panel`**: The main GTK widget and UI lifecycle (signal handlers, widget tree)
//! - **`picker`**: Pure data transformation logic for category/tool selection
//! - **`renderer`**: Widget builders for rendering instruction content
//!
//! This separation makes the core selection and rendering logic testable without
//! requiring GTK initialization, while keeping the panel implementation clean.
//!
//! ## Public API
//!
//! Re-exports the main panel type for backward compatibility with existing callers:
//!
//! ```rust,ignore
//! use crate::ui::tool_execution::ToolExecutionPanel;
//!
//! let panel = ToolExecutionPanel::new();
//! let selected = panel.get_selected_tool();
//! panel.show_instructions_dialog(&window);
//! ```

mod panel;
mod picker;
mod renderer;

// Re-export the main panel for backward compatibility
pub use panel::ToolExecutionPanel;
