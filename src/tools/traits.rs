/// Core types for security tool instructions
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

/// Configuration for tool execution (kept for compatibility)
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

/// Builder for ToolConfig (kept for compatibility)
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

    pub fn build(self) -> Result<ToolConfig, anyhow::Error> {
        Ok(ToolConfig {
            target: self.target,
            arguments: self.arguments,
            timeout: self.timeout,
            working_dir: self.working_dir,
            env_vars: self.env_vars,
        })
    }
}

/// Result from tool execution (kept for compatibility)
#[derive(Debug, Clone)]
pub enum ToolResult {
    Raw { stdout: String, stderr: String },
    Parsed { data: serde_json::Value },
}
