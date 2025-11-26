/// Tool execution engine
///
/// This module provides the default implementation for executing security tools.
/// It enforces timeouts by spawning processes and polling for completion.
/// If a configured timeout is exceeded, the process is terminated (via SIGKILL on Unix or TerminateProcess on Windows)
/// and any available partial stdout/stderr output is collected and included in the error message.
use super::traits::*;
use anyhow::Result;
use std::io::Read;
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

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
        let command = command.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let mut child = command.spawn()?;

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        let timeout_start = Instant::now();
        let timeout_duration = config.timeout.unwrap_or(std::time::Duration::MAX);

        loop {
            match child.try_wait()? {
                Some(status) => {
                    // Process finished, read any remaining output
                    if let Some(mut stdout) = child.stdout.take() {
                        stdout.read_to_end(&mut stdout_buf)?;
                    }
                    if let Some(mut stderr) = child.stderr.take() {
                        stderr.read_to_end(&mut stderr_buf)?;
                    }

                    let duration = start.elapsed();
                    let stdout = String::from_utf8_lossy(&stdout_buf).to_string();
                    let stderr = String::from_utf8_lossy(&stderr_buf).to_string();

                    let parsed_result = tool.parse_output(&stdout).ok();

                    return Ok(ExecutionResult {
                        exit_code: status.code().unwrap_or(-1),
                        stdout,
                        stderr,
                        parsed_result,
                        duration,
                    });
                }
                None => {
                    // Still running, check timeout
                    if timeout_start.elapsed() > timeout_duration {
                        // Timeout, kill the process
                        let _ = child.kill();

                        // Read partial output
                        if let Some(mut stdout) = child.stdout.take() {
                            let _ = stdout.read_to_end(&mut stdout_buf);
                        }
                        if let Some(mut stderr) = child.stderr.take() {
                            let _ = stderr.read_to_end(&mut stderr_buf);
                        }

                        let partial_stdout = String::from_utf8_lossy(&stdout_buf).to_string();
                        let partial_stderr = String::from_utf8_lossy(&stderr_buf).to_string();

                        anyhow::bail!(
                            "Command execution timed out after {:?}. Partial stdout: '{}', Partial stderr: '{}'",
                            timeout_duration,
                            partial_stdout,
                            partial_stderr
                        );
                    }

                    // Sleep briefly before checking again
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

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

    #[test]
    fn test_executor_timeout_enforced() {
        let executor = DefaultExecutor::new();
        let tool = SleepTool;
        let config = ToolConfig::builder()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();

        let result = executor.execute(&tool, &config);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.to_string().contains("timed out"));
        assert!(err.to_string().contains("Partial stdout"));
    }

    #[test]
    fn test_executor_no_timeout_when_completed() {
        let executor = DefaultExecutor::new();
        let tool = EchoTool::new();
        let config = ToolConfig::builder()
            .target("test")
            .timeout(Duration::from_secs(10)) // Long timeout
            .build()
            .unwrap();

        let result = executor.execute(&tool, &config);
        assert!(result.is_ok());
    }

    // Mock tool that sleeps
    struct SleepTool;

    impl SecurityTool for SleepTool {
        fn name(&self) -> &str {
            "sleep"
        }

        fn check_availability(&self) -> Result<ToolVersion> {
            Ok(ToolVersion::new(1, 0, 0))
        }

        fn build_command(&self, _config: &ToolConfig) -> Result<Command> {
            // Use python to sleep for 1 second
            let mut cmd = Command::new("python3");
            cmd.arg("-c").arg("import time; time.sleep(1); print('done')");
            Ok(cmd)
        }

        fn parse_output(&self, output: &str) -> Result<ToolResult> {
            Ok(ToolResult::Raw {
                stdout: output.to_string(),
                stderr: String::new(),
            })
        }

        fn validate_prerequisites(&self, _config: &ToolConfig) -> Result<()> {
            Ok(())
        }
    }
}
