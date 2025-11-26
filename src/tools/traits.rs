/// Core traits for security tool integration
use anyhow::Result;
use std::process::Command;
use std::time::Duration;

/// Version information for a security tool
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl ToolVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

/// Configuration for tool execution
#[derive(Debug, Clone)]
pub struct ToolConfig {
    pub target: Option<String>,
    pub arguments: Vec<String>,
    pub timeout: Option<Duration>,
    pub working_dir: Option<std::path::PathBuf>,
    pub env_vars: std::collections::HashMap<String, String>,
}

impl ToolConfig {
    pub fn builder() -> ToolConfigBuilder {
        ToolConfigBuilder::new()
    }
}

/// Builder for ToolConfig
#[derive(Debug, Default)]
pub struct ToolConfigBuilder {
    target: Option<String>,
    arguments: Vec<String>,
    timeout: Option<Duration>,
    working_dir: Option<std::path::PathBuf>,
    env_vars: std::collections::HashMap<String, String>,
}

impl ToolConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn argument(mut self, arg: impl Into<String>) -> Self {
        self.arguments.push(arg.into());
        self
    }

    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    pub fn working_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.working_dir = Some(dir);
        self
    }

    pub fn env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> Result<ToolConfig> {
        Ok(ToolConfig {
            target: self.target,
            arguments: self.arguments,
            timeout: self.timeout,
            working_dir: self.working_dir,
            env_vars: self.env_vars,
        })
    }
}

/// Result from tool execution
#[derive(Debug, Clone)]
pub enum ToolResult {
    Raw { stdout: String, stderr: String },
    Parsed { data: serde_json::Value },
}

/// Core trait that all security tools must implement
pub trait SecurityTool: Send + Sync {
    /// Unique identifier for the tool
    fn name(&self) -> &str;

    /// Tool version check
    fn check_availability(&self) -> Result<ToolVersion>;

    /// Build command with arguments
    fn build_command(&self, config: &ToolConfig) -> Result<Command>;

    /// Parse tool output into structured format
    fn parse_output(&self, output: &str) -> Result<ToolResult>;

    /// Validate prerequisites (target, permissions, etc.)
    fn validate_prerequisites(&self, config: &ToolConfig) -> Result<()>;
}

/// Result from tool execution with metadata
#[derive(Debug)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub parsed_result: Option<ToolResult>,
    pub duration: Duration,
}

/// Execution strategy trait
pub trait ToolRunner {
    /// Execute tool synchronously
    fn execute(&self, tool: &dyn SecurityTool, config: &ToolConfig) -> Result<ExecutionResult>;
}
