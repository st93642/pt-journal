pub mod registry;
/// Security tools integration module
///
/// This module provides basic types and registry for tool instructions.
/// No actual tool integrations are provided - only instruction metadata.
///
/// # Architecture
///
/// - **Traits**: Core types for tool definitions
/// - **Registry**: Tool instruction registry (no actual tool execution)
pub mod traits;

// Re-export main types for convenience
pub use registry::ToolRegistry;
pub use traits::{ToolConfig, ToolConfigBuilder, ToolResult, ToolVersion};
