use crate::model::Evidence;
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

    /// Extract evidence items (screenshots, files, etc.)
    fn extract_evidence(&self, result: &ToolResult) -> Vec<Evidence>;

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
    pub evidence: Vec<Evidence>,
    pub duration: Duration,
}

/// Execution strategy trait
pub trait ToolRunner {
    /// Execute tool synchronously
    fn execute(&self, tool: &dyn SecurityTool, config: &ToolConfig) -> Result<ExecutionResult>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Mock tool for testing
    struct MockTool {
        name: String,
        should_fail: bool,
    }

    impl MockTool {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                should_fail: false,
            }
        }

        fn new_failing(name: &str) -> Self {
            Self {
                name: name.to_string(),
                should_fail: true,
            }
        }
    }

    impl SecurityTool for MockTool {
        fn name(&self) -> &str {
            &self.name
        }

        fn check_availability(&self) -> Result<ToolVersion> {
            if self.should_fail {
                anyhow::bail!("Tool not available");
            }
            Ok(ToolVersion::new(1, 0, 0))
        }

        fn build_command(&self, config: &ToolConfig) -> Result<Command> {
            let mut cmd = Command::new("echo");
            if let Some(target) = &config.target {
                cmd.arg(target);
            }
            for arg in &config.arguments {
                cmd.arg(arg);
            }
            Ok(cmd)
        }

        fn parse_output(&self, output: &str) -> Result<ToolResult> {
            Ok(ToolResult::Raw {
                stdout: output.to_string(),
                stderr: String::new(),
            })
        }

        fn extract_evidence(&self, _result: &ToolResult) -> Vec<Evidence> {
            Vec::new()
        }

        fn validate_prerequisites(&self, config: &ToolConfig) -> Result<()> {
            if config.target.is_none() {
                anyhow::bail!("Target required");
            }
            Ok(())
        }
    }

    #[test]
    fn test_tool_version_creation() {
        let version = ToolVersion::new(1, 2, 3);
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 2);
        assert_eq!(version.patch, 3);
    }

    #[test]
    fn test_tool_version_equality() {
        let v1 = ToolVersion::new(1, 0, 0);
        let v2 = ToolVersion::new(1, 0, 0);
        let v3 = ToolVersion::new(2, 0, 0);

        assert_eq!(v1, v2);
        assert_ne!(v1, v3);
    }

    #[test]
    fn test_config_builder() {
        let config = ToolConfig::builder()
            .target("example.com")
            .argument("-v")
            .argument("--output=json")
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();

        assert_eq!(config.target, Some("example.com".to_string()));
        assert_eq!(config.arguments.len(), 2);
        assert_eq!(config.arguments[0], "-v");
        assert_eq!(config.arguments[1], "--output=json");
        assert_eq!(config.timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_config_builder_with_env_vars() {
        let config = ToolConfig::builder()
            .target("192.168.1.1")
            .env_var("HTTP_PROXY", "http://proxy:8080")
            .build()
            .unwrap();

        assert_eq!(
            config.env_vars.get("HTTP_PROXY"),
            Some(&"http://proxy:8080".to_string())
        );
    }

    #[test]
    fn test_security_tool_trait_implementation() {
        let tool = MockTool::new("mock-tool");

        assert_eq!(tool.name(), "mock-tool");

        let version = tool.check_availability().unwrap();
        assert_eq!(version, ToolVersion::new(1, 0, 0));
    }

    #[test]
    fn test_security_tool_availability_failure() {
        let tool = MockTool::new_failing("failing-tool");

        let result = tool.check_availability();
        assert!(result.is_err());
    }

    #[test]
    fn test_security_tool_build_command() {
        let tool = MockTool::new("test-tool");
        let config = ToolConfig::builder()
            .target("example.com")
            .argument("-p")
            .argument("80")
            .build()
            .unwrap();

        let command = tool.build_command(&config).unwrap();
        let args: Vec<String> = command
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();

        assert!(args.contains(&"example.com".to_string()));
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"80".to_string()));
    }

    #[test]
    fn test_security_tool_validate_prerequisites() {
        let tool = MockTool::new("test-tool");

        // Valid config with target
        let valid_config = ToolConfig::builder().target("example.com").build().unwrap();
        assert!(tool.validate_prerequisites(&valid_config).is_ok());

        // Invalid config without target
        let invalid_config = ToolConfig::builder().build().unwrap();
        assert!(tool.validate_prerequisites(&invalid_config).is_err());
    }

    #[test]
    fn test_security_tool_parse_output() {
        let tool = MockTool::new("test-tool");
        let output = "test output from tool";

        let result = tool.parse_output(output).unwrap();

        match result {
            ToolResult::Raw { stdout, stderr } => {
                assert_eq!(stdout, "test output from tool");
                assert!(stderr.is_empty());
            }
            _ => panic!("Expected Raw result"),
        }
    }

    #[test]
    fn test_security_tool_extract_evidence() {
        let tool = MockTool::new("test-tool");
        let result = ToolResult::Raw {
            stdout: "output".to_string(),
            stderr: String::new(),
        };

        let evidence = tool.extract_evidence(&result);
        assert_eq!(evidence.len(), 0);
    }
}
