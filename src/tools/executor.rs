/// Tool execution engine
///
/// This module provides the default implementation for executing security tools.
/// It enforces timeouts by spawning processes and polling for completion.
/// If a configured timeout is exceeded, the process is terminated (via SIGKILL on Unix or TerminateProcess on Windows)
/// and any available partial stdout/stderr output is collected and included in the error message.
///
/// ## Threading Constraints
///
/// - Execution is synchronous and blocking
/// - Designed for background thread usage in UI applications
/// - No internal threading; relies on caller for concurrency
///
/// ## Error Handling
///
/// - Timeouts include partial output in error messages
/// - Process spawning failures bubble up as `anyhow::Error`
/// - Invalid UTF-8 in output is lossy-converted
/// - Environment and working directory setup validated before execution
///
/// ## Security Considerations
///
/// - Commands run with user privileges only
/// - No shell interpretation of arguments
/// - Timeouts prevent resource exhaustion
/// - Output size not limited (caller responsibility)
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
