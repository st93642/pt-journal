/// Tool execution engine
use super::traits::*;
use anyhow::Result;
use std::time::{Duration, Instant};

/// Default executor implementation
pub struct DefaultExecutor {
    #[allow(dead_code)]
    max_concurrent: usize,
}

impl DefaultExecutor {
    pub fn new() -> Self {
        Self { max_concurrent: 4 }
    }

    pub fn with_max_concurrent(max_concurrent: usize) -> Self {
        Self { max_concurrent }
    }
}

impl Default for DefaultExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRunner for DefaultExecutor {
    fn execute(&self, tool: &dyn SecurityTool, config: &ToolConfig) -> Result<ExecutionResult> {
        let start = Instant::now();

        // Validate prerequisites
        tool.validate_prerequisites(config)?;

        // Check tool availability
        tool.check_availability()?;

        // Build command
        let mut command = tool.build_command(config)?;

        // Apply environment variables
        for (key, value) in &config.env_vars {
            command.env(key, value);
        }

        // Set working directory if specified
        if let Some(dir) = &config.working_dir {
            command.current_dir(dir);
        }

        // Execute with timeout handling
        let output = if let Some(timeout) = config.timeout {
            // For now, basic timeout implementation
            // TODO: Implement proper timeout with process termination
            let output = command.output()?;

            let duration = start.elapsed();
            if duration > timeout {
                anyhow::bail!("Command execution exceeded timeout of {:?}", timeout);
            }

            output
        } else {
            command.output()?
        };

        let duration = start.elapsed();

        // Convert output to strings
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Parse results
        let parsed_result = tool.parse_output(&stdout).ok();

        // Extract evidence if parsing succeeded
        let evidence = if let Some(ref result) = parsed_result {
            tool.extract_evidence(result)
        } else {
            Vec::new()
        };

        Ok(ExecutionResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout,
            stderr,
            parsed_result,
            evidence,
            duration,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Evidence;
    use chrono::Utc;
    use std::process::Command;
    use uuid::Uuid;

    // Mock tool that uses echo command
    struct EchoTool {
        should_fail_validation: bool,
        should_fail_availability: bool,
    }

    impl EchoTool {
        fn new() -> Self {
            Self {
                should_fail_validation: false,
                should_fail_availability: false,
            }
        }

        fn fail_validation() -> Self {
            Self {
                should_fail_validation: true,
                should_fail_availability: false,
            }
        }

        fn fail_availability() -> Self {
            Self {
                should_fail_validation: false,
                should_fail_availability: true,
            }
        }
    }

    impl SecurityTool for EchoTool {
        fn name(&self) -> &str {
            "echo"
        }

        fn check_availability(&self) -> Result<ToolVersion> {
            if self.should_fail_availability {
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
            vec![Evidence {
                id: Uuid::new_v4(),
                path: "test_evidence.txt".to_string(),
                kind: "echo-output".to_string(),
                x: 0.0,
                y: 0.0,
                created_at: Utc::now(),
            }]
        }

        fn validate_prerequisites(&self, config: &ToolConfig) -> Result<()> {
            if self.should_fail_validation {
                anyhow::bail!("Validation failed");
            }
            if config.target.is_none() {
                anyhow::bail!("Target required");
            }
            Ok(())
        }
    }

    #[test]
    fn test_executor_creation() {
        let executor = DefaultExecutor::new();
        assert_eq!(executor.max_concurrent, 4);

        let executor = DefaultExecutor::with_max_concurrent(8);
        assert_eq!(executor.max_concurrent, 8);
    }

    #[test]
    fn test_executor_runs_command() {
        let executor = DefaultExecutor::new();
        let tool = EchoTool::new();
        let config = ToolConfig::builder().target("test output").build().unwrap();

        let result = executor.execute(&tool, &config);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("test output"));
    }

    #[test]
    fn test_executor_captures_output() {
        let executor = DefaultExecutor::new();
        let tool = EchoTool::new();
        let config = ToolConfig::builder()
            .target("hello world")
            .argument("from echo")
            .build()
            .unwrap();

        let result = executor.execute(&tool, &config).unwrap();

        assert!(result.stdout.contains("hello world"));
        assert!(result.stdout.contains("from echo"));
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_executor_validates_prerequisites() {
        let executor = DefaultExecutor::new();
        let tool = EchoTool::fail_validation();
        let config = ToolConfig::builder().target("test").build().unwrap();

        let result = executor.execute(&tool, &config);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.to_string().contains("Validation failed"));
    }

    #[test]
    fn test_executor_checks_availability() {
        let executor = DefaultExecutor::new();
        let tool = EchoTool::fail_availability();
        let config = ToolConfig::builder().target("test").build().unwrap();

        let result = executor.execute(&tool, &config);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.to_string().contains("Tool not available"));
    }

    #[test]
    fn test_executor_parses_results() {
        let executor = DefaultExecutor::new();
        let tool = EchoTool::new();
        let config = ToolConfig::builder()
            .target("parsed output")
            .build()
            .unwrap();

        let result = executor.execute(&tool, &config).unwrap();

        assert!(result.parsed_result.is_some());

        if let Some(ToolResult::Raw { stdout, .. }) = result.parsed_result {
            assert!(stdout.contains("parsed output"));
        } else {
            panic!("Expected parsed result");
        }
    }

    #[test]
    fn test_executor_extracts_evidence() {
        let executor = DefaultExecutor::new();
        let tool = EchoTool::new();
        let config = ToolConfig::builder().target("test").build().unwrap();

        let result = executor.execute(&tool, &config).unwrap();

        assert_eq!(result.evidence.len(), 1);
        assert_eq!(result.evidence[0].kind, "echo-output");
    }

    #[test]
    fn test_executor_measures_duration() {
        let executor = DefaultExecutor::new();
        let tool = EchoTool::new();
        let config = ToolConfig::builder().target("test").build().unwrap();

        let result = executor.execute(&tool, &config).unwrap();

        // Duration should be measured
        assert!(result.duration > Duration::from_secs(0));
        // Should be quick for echo command
        assert!(result.duration < Duration::from_secs(5));
    }

    #[test]
    fn test_executor_applies_env_vars() {
        let executor = DefaultExecutor::new();
        let tool = EchoTool::new();
        let config = ToolConfig::builder()
            .target("test")
            .env_var("TEST_VAR", "test_value")
            .build()
            .unwrap();

        // Environment variables are applied during execution
        let result = executor.execute(&tool, &config);
        assert!(result.is_ok());
    }
}
