# PT Journal - Security Tools Integration Roadmap

## Executive Summary

This document outlines the implementation plan for integrating common penetration testing and security tools into PT Journal. The integration will follow Object-Oriented Programming (OOP) principles, maintain a modular architecture, and use Test-Driven Development (TDD) methodology.

## Project Goals

1. **Seamless Tool Integration**: Allow users to execute security tools directly from PT Journal
2. **Automated Evidence Collection**: Capture tool outputs and screenshots automatically
3. **Result Parsing**: Parse structured data from tool outputs for step validation
4. **Modular Architecture**: Keep tool integrations independent and easily extensible
5. **Type Safety**: Leverage Rust's type system for robust implementations
6. **Comprehensive Testing**: Ensure reliability through extensive unit and integration tests

## Architecture Overview

### Core Components

```text
src/
├── tools/
│   ├── mod.rs                      # Tool system public API
│   ├── traits.rs                   # Core traits (SecurityTool, ToolRunner, OutputParser)
│   ├── registry.rs                 # Tool registry and discovery
│   ├── executor.rs                 # Generic tool execution engine
│   ├── parser.rs                   # Output parsing framework
│   ├── evidence.rs                 # Evidence collection and attachment
│   ├── config.rs                   # Tool configuration management
│   ├── validators.rs               # Input/output validation
│   └── integrations/
│       ├── mod.rs
│       ├── nmap.rs                 # Nmap integration
│       ├── gobuster.rs             # Gobuster integration
│       ├── nikto.rs                # Nikto integration
│       ├── sqlmap.rs               # SQLMap integration
│       ├── burp.rs                 # Burp Suite integration
│       ├── metasploit.rs           # Metasploit integration
│       ├── nuclei.rs               # Nuclei integration
│       ├── ffuf.rs                 # FFUF integration
│       └── ...
├── ui/
│   └── tools/
│       ├── mod.rs
│       ├── tool_panel.rs           # Tool execution UI
│       ├── tool_selector.rs        # Tool selection widget
│       ├── output_viewer.rs        # Real-time output display
│       └── result_parser_view.rs   # Parsed results display
└── model.rs                        # Extend with ToolExecution, ToolResult models
```

## Design Patterns & Principles

### 1. **Trait-Based Abstraction**

```rust
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

/// Execution strategy trait
pub trait ToolRunner {
    /// Execute tool synchronously
    fn execute(&self, tool: &dyn SecurityTool, config: &ToolConfig) -> Result<ExecutionResult>;
    
    /// Execute tool asynchronously with progress callback
    fn execute_async(
        &self,
        tool: &dyn SecurityTool,
        config: &ToolConfig,
        on_progress: Box<dyn Fn(ProgressUpdate)>,
    ) -> Result<JoinHandle<Result<ExecutionResult>>>;
    
    /// Cancel running execution
    fn cancel(&self, execution_id: &str) -> Result<()>;
}

/// Output parsing trait for structured data extraction
pub trait OutputParser {
    type Output;
    
    /// Parse raw output into structured format
    fn parse(&self, raw: &str) -> Result<Self::Output>;
    
    /// Validate parsed output
    fn validate(&self, output: &Self::Output) -> Result<()>;
}
```

### 2. **Builder Pattern for Configuration**

```rust
pub struct ToolConfigBuilder {
    target: Option<String>,
    arguments: Vec<String>,
    timeout: Option<Duration>,
    working_dir: Option<PathBuf>,
    env_vars: HashMap<String, String>,
}

impl ToolConfigBuilder {
    pub fn new() -> Self { /* ... */ }
    
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
    
    pub fn build(self) -> Result<ToolConfig> { /* ... */ }
}
```

### 3. **Registry Pattern for Tool Discovery**

```rust
pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn SecurityTool>>,
}

impl ToolRegistry {
    pub fn new() -> Self { /* ... */ }
    
    pub fn register(&mut self, tool: Box<dyn SecurityTool>) -> Result<()> {
        let name = tool.name().to_string();
        self.tools.insert(name, tool);
        Ok(())
    }
    
    pub fn get(&self, name: &str) -> Option<&dyn SecurityTool> {
        self.tools.get(name).map(|b| b.as_ref())
    }
    
    pub fn discover_installed_tools(&mut self) -> Vec<&str> {
        // Auto-detect tools available in PATH
    }
}
```

### 4. **Command Pattern for Execution**

```rust
pub struct ToolExecution {
    id: Uuid,
    tool_name: String,
    config: ToolConfig,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    status: ExecutionStatus,
    output: Option<String>,
    parsed_result: Option<ToolResult>,
    evidence: Vec<Evidence>,
}

pub enum ExecutionStatus {
    Queued,
    Running { progress: f32 },
    Completed { exit_code: i32 },
    Failed { error: String },
    Cancelled,
}
```

## Phase 1: Foundation (Weeks 1-2)

### Objectives

- Establish core trait system
- Implement execution engine
- Create testing framework

### Implementation Steps

#### Step 1.1: Core Traits Definition

**File**: `src/tools/traits.rs`

```rust
// TDD: Write tests first
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_security_tool_trait_implementation() {
        struct MockTool;
        
        impl SecurityTool for MockTool {
            fn name(&self) -> &str { "mock-tool" }
            fn check_availability(&self) -> Result<ToolVersion> {
                Ok(ToolVersion::new(1, 0, 0))
            }
            // ... implement other methods
        }
        
        let tool = MockTool;
        assert_eq!(tool.name(), "mock-tool");
    }
}

// Implementation follows tests
pub trait SecurityTool: Send + Sync {
    // ... trait definition
}
```

#### Step 1.2: Generic Executor

**File**: `src/tools/executor.rs`

**Tests**:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_executor_runs_command() {
        let executor = DefaultExecutor::new();
        let config = ToolConfig::builder()
            .target("example.com")
            .build()
            .unwrap();
        
        let result = executor.execute(&MockTool, &config);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_executor_handles_timeout() {
        let executor = DefaultExecutor::new();
        let config = ToolConfig::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        
        let result = executor.execute(&SlowTool, &config);
        assert!(matches!(result, Err(ExecutionError::Timeout)));
    }
    
    #[test]
    fn test_executor_captures_output() {
        let executor = DefaultExecutor::new();
        let result = executor.execute(&MockTool, &config).unwrap();
        
        assert!(result.stdout.contains("expected output"));
        assert_eq!(result.exit_code, 0);
    }
}
```

**Implementation**:

```rust
pub struct DefaultExecutor {
    max_concurrent: usize,
    running: Arc<Mutex<HashMap<String, Child>>>,
}

impl DefaultExecutor {
    pub fn new() -> Self {
        Self {
            max_concurrent: 4,
            running: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl ToolRunner for DefaultExecutor {
    fn execute(&self, tool: &dyn SecurityTool, config: &ToolConfig) -> Result<ExecutionResult> {
        // Validate prerequisites
        tool.validate_prerequisites(config)?;
        
        // Check tool availability
        tool.check_availability()?;
        
        // Build command
        let mut command = tool.build_command(config)?;
        
        // Set timeout
        if let Some(timeout) = config.timeout {
            // Implement timeout logic
        }
        
        // Execute
        let output = command.output()?;
        
        // Parse results
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let parsed = tool.parse_output(&stdout)?;
        let evidence = tool.extract_evidence(&parsed);
        
        Ok(ExecutionResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout,
            stderr,
            parsed_result: Some(parsed),
            evidence,
            duration: Duration::from_secs(0), // Track actual duration
        })
    }
    
    fn execute_async(
        &self,
        tool: &dyn SecurityTool,
        config: &ToolConfig,
        on_progress: Box<dyn Fn(ProgressUpdate)>,
    ) -> Result<JoinHandle<Result<ExecutionResult>>> {
        // Implement async execution with progress callbacks
        todo!()
    }
    
    fn cancel(&self, execution_id: &str) -> Result<()> {
        let mut running = self.running.lock().unwrap();
        if let Some(mut child) = running.remove(execution_id) {
            child.kill()?;
        }
        Ok(())
    }
}
```

#### Step 1.3: Tool Registry

**File**: `src/tools/registry.rs`

**Tests**:

```rust
#[test]
fn test_registry_registers_tool() {
    let mut registry = ToolRegistry::new();
    let tool = Box::new(MockTool);
    
    assert!(registry.register(tool).is_ok());
    assert!(registry.get("mock-tool").is_some());
}

#[test]
fn test_registry_prevents_duplicates() {
    let mut registry = ToolRegistry::new();
    registry.register(Box::new(MockTool)).unwrap();
    
    let result = registry.register(Box::new(MockTool));
    assert!(matches!(result, Err(RegistryError::AlreadyRegistered(_))));
}

#[test]
fn test_registry_discovers_tools() {
    let mut registry = ToolRegistry::new();
    let discovered = registry.discover_installed_tools();
    
    // Should find common tools in PATH
    assert!(discovered.len() > 0);
}
```

## Phase 2: Core Tool Integrations (Weeks 3-6)

### Priority Tools (Ranked by Usage)

1. **Nmap** - Network scanning
2. **Gobuster** - Directory/DNS enumeration
3. **Nikto** - Web server scanning
4. **SQLMap** - SQL injection detection
5. **FFUF** - Web fuzzing
6. **Nuclei** - Vulnerability scanning

### Implementation Template (Example: Nmap)

**File**: `src/tools/integrations/nmap.rs`

#### Tests First (TDD)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_nmap_availability_check() {
        let nmap = NmapTool::new();
        let result = nmap.check_availability();
        
        // Should detect nmap installation
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_nmap_command_building() {
        let nmap = NmapTool::new();
        let config = ToolConfig::builder()
            .target("192.168.1.1")
            .argument("-sV")  // Service version detection
            .argument("-p 80,443")
            .build()
            .unwrap();
        
        let command = nmap.build_command(&config).unwrap();
        
        let args = command.get_args().collect::<Vec<_>>();
        assert!(args.contains(&"-sV"));
        assert!(args.contains(&"192.168.1.1"));
    }
    
    #[test]
    fn test_nmap_output_parsing() {
        let nmap = NmapTool::new();
        let sample_output = r#"
Starting Nmap 7.94
Nmap scan report for example.com (93.184.216.34)
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx 1.18.0
443/tcp  open  ssl/http nginx 1.18.0
"#;
        
        let result = nmap.parse_output(sample_output).unwrap();
        
        assert_eq!(result.target, "example.com");
        assert_eq!(result.open_ports.len(), 2);
        assert_eq!(result.open_ports[0].port, 80);
        assert_eq!(result.open_ports[0].service, Some("http".to_string()));
    }
    
    #[test]
    fn test_nmap_evidence_extraction() {
        let nmap = NmapTool::new();
        let result = NmapResult {
            target: "example.com".to_string(),
            open_ports: vec![
                PortInfo { port: 80, state: "open".to_string(), service: Some("http".to_string()) },
            ],
            os_detection: None,
            scan_duration: Duration::from_secs(10),
        };
        
        let evidence = nmap.extract_evidence(&result);
        
        // Should create evidence for scan results
        assert!(evidence.len() > 0);
        assert_eq!(evidence[0].kind, "nmap-scan");
    }
    
    #[test]
    fn test_nmap_validates_target() {
        let nmap = NmapTool::new();
        
        // Valid targets
        let valid_config = ToolConfig::builder()
            .target("192.168.1.1")
            .build()
            .unwrap();
        assert!(nmap.validate_prerequisites(&valid_config).is_ok());
        
        // Invalid targets
        let invalid_config = ToolConfig::builder()
            .target("not-a-valid-target!@#")
            .build()
            .unwrap();
        assert!(nmap.validate_prerequisites(&invalid_config).is_err());
    }
}
```

#### Implementation

```rust
use super::*;
use regex::Regex;
use std::process::Command;

pub struct NmapTool {
    version_regex: Regex,
    port_regex: Regex,
}

impl NmapTool {
    pub fn new() -> Self {
        Self {
            version_regex: Regex::new(r"Nmap version (\d+\.\d+)").unwrap(),
            port_regex: Regex::new(r"(\d+)/tcp\s+(\w+)\s+(.+)").unwrap(),
        }
    }
}

impl SecurityTool for NmapTool {
    fn name(&self) -> &str {
        "nmap"
    }
    
    fn check_availability(&self) -> Result<ToolVersion> {
        let output = Command::new("nmap")
            .arg("--version")
            .output()
            .map_err(|e| ToolError::NotInstalled(format!("nmap: {}", e)))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        if let Some(caps) = self.version_regex.captures(&stdout) {
            let version_str = &caps[1];
            let parts: Vec<&str> = version_str.split('.').collect();
            
            Ok(ToolVersion::new(
                parts[0].parse().unwrap_or(0),
                parts[1].parse().unwrap_or(0),
                0,
            ))
        } else {
            Err(ToolError::ParseError("Could not parse nmap version".into()))
        }
    }
    
    fn build_command(&self, config: &ToolConfig) -> Result<Command> {
        let mut cmd = Command::new("nmap");
        
        // Add output format for parsing
        cmd.arg("-oN");
        cmd.arg("-"); // Output to stdout
        
        // Add user arguments
        for arg in &config.arguments {
            cmd.arg(arg);
        }
        
        // Add target
        if let Some(target) = &config.target {
            cmd.arg(target);
        } else {
            return Err(ToolError::InvalidConfig("Target required for nmap".into()));
        }
        
        // Set working directory if specified
        if let Some(dir) = &config.working_dir {
            cmd.current_dir(dir);
        }
        
        Ok(cmd)
    }
    
    fn parse_output(&self, output: &str) -> Result<ToolResult> {
        let mut open_ports = Vec::new();
        let mut target = String::new();
        
        // Parse target
        if let Some(target_line) = output.lines().find(|l| l.contains("Nmap scan report for")) {
            target = target_line
                .split("for ")
                .nth(1)
                .unwrap_or("")
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
        }
        
        // Parse ports
        for line in output.lines() {
            if let Some(caps) = self.port_regex.captures(line) {
                let port = caps[1].parse().unwrap_or(0);
                let state = caps[2].to_string();
                let service = caps[3].trim().to_string();
                
                open_ports.push(PortInfo {
                    port,
                    state,
                    service: if service.is_empty() { None } else { Some(service) },
                });
            }
        }
        
        Ok(ToolResult::Nmap(NmapResult {
            target,
            open_ports,
            os_detection: None,
            scan_duration: Duration::from_secs(0),
        }))
    }
    
    fn extract_evidence(&self, result: &ToolResult) -> Vec<Evidence> {
        if let ToolResult::Nmap(nmap_result) = result {
            vec![Evidence {
                id: Uuid::new_v4(),
                path: format!("nmap_scan_{}.txt", nmap_result.target),
                kind: "nmap-scan".to_string(),
                x: 0.0,
                y: 0.0,
                created_at: Utc::now(),
            }]
        } else {
            Vec::new()
        }
    }
    
    fn validate_prerequisites(&self, config: &ToolConfig) -> Result<()> {
        // Validate target is provided
        if config.target.is_none() {
            return Err(ToolError::InvalidConfig("Target required".into()));
        }
        
        // Validate target format (IP, domain, or CIDR)
        let target = config.target.as_ref().unwrap();
        if !Self::is_valid_target(target) {
            return Err(ToolError::InvalidConfig(format!("Invalid target: {}", target)));
        }
        
        Ok(())
    }
}

impl NmapTool {
    fn is_valid_target(target: &str) -> bool {
        // Simple validation - can be enhanced
        !target.is_empty() && target.chars().all(|c| c.is_alphanumeric() || ".:-/".contains(c))
    }
}

// Result types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapResult {
    pub target: String,
    pub open_ports: Vec<PortInfo>,
    pub os_detection: Option<String>,
    pub scan_duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub state: String,
    pub service: Option<String>,
}
```

### Implementation Checklist for Each Tool

- [ ] Write comprehensive unit tests (TDD)
- [ ] Implement SecurityTool trait
- [ ] Create tool-specific result types
- [ ] Implement output parser with regex/JSON parsing
- [ ] Add evidence extraction logic
- [ ] Document usage examples
- [ ] Add integration tests
- [ ] Update tool registry
- [ ] Create UI widget for tool configuration
- [ ] Add to tutorial steps where relevant

## Phase 3: UI Integration (Weeks 7-8)

### Components

#### 3.1 Tool Panel Widget

**File**: `src/ui/tools/tool_panel.rs`

```rust
pub struct ToolPanel {
    pub container: GtkBox,
    pub tool_selector: ToolSelector,
    pub config_area: ScrolledWindow,
    pub execute_button: Button,
    pub output_viewer: OutputViewer,
    pub results_view: ResultsView,
}

impl ToolPanel {
    pub fn new(registry: Arc<Mutex<ToolRegistry>>) -> Self {
        // Create UI components
        let tool_selector = ToolSelector::new(registry.clone());
        let output_viewer = OutputViewer::new();
        let results_view = ResultsView::new();
        
        // Wire up signals
        tool_selector.connect_tool_selected(|tool_name| {
            // Update config area with tool-specific options
        });
        
        // ... rest of implementation
    }
}
```

#### 3.2 Real-Time Output Viewer

```rust
pub struct OutputViewer {
    text_view: TextView,
    buffer: TextBuffer,
}

impl OutputViewer {
    pub fn append_line(&self, line: &str) {
        let mut end_iter = self.buffer.end_iter();
        self.buffer.insert(&mut end_iter, &format!("{}\n", line));
        
        // Auto-scroll to bottom
        self.text_view.scroll_to_iter(&mut end_iter, 0.0, false, 0.0, 0.0);
    }
    
    pub fn set_color_for_line(&self, line_num: u32, color: &str) {
        // Colorize output (errors red, success green, etc.)
    }
}
```

## Phase 4: Advanced Features (Weeks 9-12)

### 4.1 Tool Chaining

Allow tools to be executed in sequence, passing outputs between tools.

```rust
pub struct ToolChain {
    steps: Vec<ChainStep>,
}

pub struct ChainStep {
    tool_name: String,
    config_template: ToolConfig,
    output_mapping: HashMap<String, String>, // Map output to next tool's input
}

impl ToolChain {
    pub fn execute(&self, registry: &ToolRegistry, executor: &dyn ToolRunner) -> Result<Vec<ExecutionResult>> {
        let mut results = Vec::new();
        let mut context = HashMap::new();
        
        for step in &self.steps {
            // Substitute placeholders with previous results
            let config = self.apply_context(&step.config_template, &context)?;
            
            let tool = registry.get(&step.tool_name)
                .ok_or(ToolError::NotFound(step.tool_name.clone()))?;
            
            let result = executor.execute(tool, &config)?;
            
            // Extract outputs for next step
            for (key, value_path) in &step.output_mapping {
                context.insert(key.clone(), self.extract_value(&result, value_path)?);
            }
            
            results.push(result);
        }
        
        Ok(results)
    }
}
```

Example chain:

```rust
let chain = ToolChain::builder()
    .step("nmap", |config| {
        config
            .target("$TARGET")
            .argument("-p-")
            .output_map("open_ports", "$.open_ports[*].port")
    })
    .step("gobuster", |config| {
        config
            .target("http://$TARGET:$PREV.open_ports[0]")
            .argument("-w /wordlist.txt")
    })
    .build();
```

### 4.2 Tool Templates & Presets

Pre-configured tool settings for common scenarios.

```rust
pub struct ToolTemplate {
    name: String,
    description: String,
    tool_name: String,
    config: ToolConfig,
    tags: Vec<String>,
}

// Example templates
lazy_static! {
    pub static ref TEMPLATES: Vec<ToolTemplate> = vec![
        ToolTemplate {
            name: "Quick Nmap Scan".to_string(),
            description: "Fast TCP scan of top 1000 ports".to_string(),
            tool_name: "nmap".to_string(),
            config: ToolConfig::builder()
                .argument("-F")
                .argument("-sV")
                .build().unwrap(),
            tags: vec!["reconnaissance".to_string(), "quick".to_string()],
        },
        ToolTemplate {
            name: "Full Nmap Scan".to_string(),
            description: "Comprehensive scan with service detection and OS fingerprinting".to_string(),
            tool_name: "nmap".to_string(),
            config: ToolConfig::builder()
                .argument("-p-")
                .argument("-sV")
                .argument("-sC")
                .argument("-O")
                .argument("--script vuln")
                .timeout(Duration::from_secs(3600))
                .build().unwrap(),
            tags: vec!["reconnaissance".to_string(), "comprehensive".to_string()],
        },
    ];
}
```

### 4.3 Tool Output History & Replay

Store and replay tool executions.

```rust
#[derive(Serialize, Deserialize)]
pub struct ToolExecutionRecord {
    id: Uuid,
    tool_name: String,
    config: ToolConfig,
    executed_at: DateTime<Utc>,
    result: ExecutionResult,
    session_id: Uuid,
    step_id: Uuid,
}

impl ToolExecutionRecord {
    pub fn replay(&self, executor: &dyn ToolRunner, registry: &ToolRegistry) -> Result<ExecutionResult> {
        let tool = registry.get(&self.tool_name)
            .ok_or(ToolError::NotFound(self.tool_name.clone()))?;
        
        executor.execute(tool, &self.config)
    }
}
```

## Testing Strategy

### Unit Tests (70% coverage minimum)

- Test each SecurityTool implementation independently
- Mock external tool execution for fast tests
- Test output parsers with various formats
- Test error handling and edge cases

```rust
// Example mock for testing without actual tool
pub struct MockNmap {
    should_fail: bool,
    mock_output: String,
}

impl SecurityTool for MockNmap {
    fn name(&self) -> &str { "nmap" }
    
    fn check_availability(&self) -> Result<ToolVersion> {
        if self.should_fail {
            Err(ToolError::NotInstalled("mock".into()))
        } else {
            Ok(ToolVersion::new(7, 94, 0))
        }
    }
    
    fn build_command(&self, _config: &ToolConfig) -> Result<Command> {
        // Return mock command that echoes pre-defined output
        let mut cmd = Command::new("echo");
        cmd.arg(&self.mock_output);
        Ok(cmd)
    }
    
    // ... rest of implementation
}
```

### Integration Tests

```rust
#[test]
#[ignore] // Requires actual tools installed
fn test_nmap_integration() {
    let nmap = NmapTool::new();
    let executor = DefaultExecutor::new();
    
    let config = ToolConfig::builder()
        .target("scanme.nmap.org")
        .argument("-F")
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap();
    
    let result = executor.execute(&nmap, &config);
    assert!(result.is_ok());
    
    let result = result.unwrap();
    assert!(result.parsed_result.is_some());
}
```

### UI Tests

```rust
#[test]
fn test_tool_panel_displays_output() {
    let registry = Arc::new(Mutex::new(ToolRegistry::new()));
    let panel = ToolPanel::new(registry);
    
    // Simulate tool execution
    panel.output_viewer.append_line("Starting scan...");
    panel.output_viewer.append_line("Found open port: 80");
    
    // Verify output is displayed
    let buffer_text = panel.output_viewer.text_view.buffer().text(
        &panel.output_viewer.text_view.buffer().start_iter(),
        &panel.output_viewer.text_view.buffer().end_iter(),
        false,
    );
    
    assert!(buffer_text.contains("Starting scan"));
    assert!(buffer_text.contains("Found open port: 80"));
}
```

## Data Models Extension

### Add to `src/model.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecution {
    pub id: Uuid,
    pub tool_name: String,
    pub executed_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub config: ToolConfig,
    pub status: ExecutionStatus,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub parsed_result: Option<serde_json::Value>, // Flexible storage
    pub evidence_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Queued,
    Running { progress: f32 },
    Completed,
    Failed { error: String },
    Cancelled,
}

// Extend Step to include tool executions
impl Step {
    pub fn add_tool_execution(&mut self, execution: ToolExecution) {
        // Store in StepContent
    }
    
    pub fn get_tool_executions(&self) -> Vec<&ToolExecution> {
        // Retrieve from StepContent
    }
}
```

## Dependencies to Add

```toml
[dependencies]
# Existing dependencies...

# Process execution
tokio = { version = "1.35", features = ["full"] }
async-trait = "0.1"

# Parsing
regex = "1.10"
serde_yaml = "0.9"  # Already present
xml-rs = "0.8"      # For XML output parsing (e.g., Nmap XML)

# Tool-specific
nmap-parser = "0.2"  # Optional: dedicated nmap parser
sqlparser = "0.39"   # For SQLMap output

# Testing
mockall = "0.12"     # For creating mock objects
```

## Milestones & Timeline

### Week 1-2: Foundation

- [x] Define core traits (SecurityTool, ToolRunner, OutputParser)
- [x] Implement DefaultExecutor with tests
- [x] Create ToolRegistry with discovery
- [x] Set up test infrastructure with mocks

### Week 3-4: Nmap & Gobuster

- [ ] Implement Nmap integration (TDD)
- [ ] Implement Gobuster integration (TDD)
- [ ] Create output parsers
- [ ] Add 30+ unit tests per tool
- [ ] Integration tests with actual tools

### Week 5-6: Nikto & SQLMap

- [ ] Implement Nikto integration (TDD)
- [ ] Implement SQLMap integration (TDD)
- [ ] Add evidence extraction
- [ ] Tool validation logic

### Week 7-8: UI Integration

- [ ] Create ToolPanel widget
- [ ] Implement OutputViewer
- [ ] Add ResultsView component
- [ ] Wire up GTK signals
- [ ] Real-time output streaming

### Week 9-10: FFUF & Nuclei

- [ ] Implement FFUF integration
- [ ] Implement Nuclei integration
- [ ] Add JSON output parsing
- [ ] Tool templates system

### Week 11-12: Advanced Features

- [ ] Tool chaining implementation
- [ ] Execution history & replay
- [ ] Template library
- [ ] Performance optimization
- [ ] Documentation completion

## Success Metrics

1. **Test Coverage**: ≥70% code coverage
2. **Tool Support**: 6+ security tools integrated
3. **Reliability**: <1% failure rate for valid tool executions
4. **Performance**: Tool execution overhead <50ms
5. **Usability**: Users can execute tools in <3 clicks
6. **Documentation**: 100% public API documented

## Risk Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Tool not installed | High | Graceful degradation, clear error messages, installation guides |
| Output format changes | Medium | Version detection, multiple parser strategies, fallback to raw output |
| Long-running tools | Medium | Async execution, cancellation support, progress indicators |
| Platform differences | Medium | Cross-platform testing, conditional compilation |
| Security concerns | High | Input sanitization, sandboxing, privilege checks |

## Documentation Requirements

1. **API Documentation**: Rustdoc for all public APIs
2. **Integration Guide**: How to add new tools
3. **User Guide**: How to use tool integrations
4. **Security Guide**: Safe tool execution practices
5. **Testing Guide**: How to test tool integrations

## Future Enhancements (Post-Initial Release)

- [ ] Burp Suite Pro API integration
- [ ] Metasploit RPC integration
- [ ] Custom tool definition (YAML config)
- [ ] Tool marketplace/plugin system
- [ ] Cloud tool execution (AWS/Azure)
- [ ] AI-powered result analysis
- [ ] Automated workflow recommendations
- [ ] Collaborative tool sharing

## Conclusion

This roadmap provides a comprehensive, test-driven approach to integrating security tools into PT Journal. By following OOP principles and maintaining modularity, the system will be extensible, maintainable, and reliable. The phased approach ensures continuous progress with testable milestones at each stage.
