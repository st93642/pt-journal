//! Tool integrations module
//!
//! This module provides concrete implementations of security tools.
//! Currently, only template implementations exist - this serves as a foundation for future integrations.
//!
//! ## Adding New Tool Integrations
//!
//! To add a new tool integration:
//!
//! 1. Copy `template.rs` to a new file (e.g., `nmap.rs`)
//! 2. Implement the `SecurityTool` trait for your specific tool
//! 3. Add the module declaration below
//! 4. Add the re-export below
//! 5. Register the tool in your application initialization code
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use pt_journal::tools::integrations::NmapTool;
//! use pt_journal::tools::registry::ToolRegistry;
//!
//! let mut registry = ToolRegistry::new();
//! let nmap_tool = Box::new(NmapTool::new());
//! registry.register(nmap_tool).expect("Failed to register nmap tool");
//! ```
//!
//! ## Current Status
//!
//! - ✅ Template structure available
//! - ✅ Registry framework in place
//! - ✅ Trait definitions complete
//! - ❌ No actual tool implementations yet
//! - ❌ Tool execution not fully integrated with UI

// Template for future implementations
pub mod template;

// Re-export template (for testing and examples)
pub use template::TemplateTool;

// Future tool implementations will be added here:
// pub mod nmap;
// pub mod gobuster;
// pub mod nikto;
// pub mod sqlmap;
// etc.

// And re-exported here:
// pub use nmap::NmapTool;
// pub use gobuster::GobusterTool;
// etc.
