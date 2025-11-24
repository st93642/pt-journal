pub mod executor;
// pub mod integrations;
pub mod registry;
/// Security tools integration module
///
/// This module provides a flexible framework for integrating external security tools
/// into the PT Journal application. It follows OOP principles with trait-based
/// polymorphism and supports TDD development.
///
/// # Architecture
///
/// - **Traits**: Core abstractions (`SecurityTool`, `ToolRunner`)
/// - **Executor**: Command execution engine with timeout handling
/// - **Registry**: Tool discovery and management
/// - **Integrations**: Concrete tool implementations (Nmap, Gobuster, etc.)
///
/// # Example
///
/// ```no_run
/// use pt_journal::tools::*;
/// use pt_journal::tools::executor::DefaultExecutor;
/// use pt_journal::tools::registry::ToolRegistry;
///
/// // Create executor and registry
/// let executor = DefaultExecutor::new();
/// let mut registry = ToolRegistry::new();
///
/// // Register tools (when implemented)
/// // registry.register(Box::new(NmapTool::new())).unwrap();
///
/// // Execute a tool
/// // let config = ToolConfig::builder()
/// //     .target("scanme.nmap.org")
/// //     .build()
/// //     .unwrap();
/// // let result = executor.execute(tool, &config).unwrap();
/// ```
pub mod traits;

// Re-export main types for convenience
pub use executor::DefaultExecutor;
pub use registry::ToolRegistry;
pub use traits::{
    ExecutionResult, SecurityTool, ToolConfig, ToolConfigBuilder, ToolResult, ToolRunner,
    ToolVersion,
};
