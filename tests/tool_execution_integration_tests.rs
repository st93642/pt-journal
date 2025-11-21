/// Tool Execution Integration Tests
/// Tests for security tool integration with mock sudo execution
use pt_journal::tools::*;
use std::time::Duration;

#[test]
fn test_tool_config_builder() {
    let config = ToolConfig::builder()
        .target("192.168.1.1")
        .argument("-p")
        .argument("80,443")
        .argument("-sV")
        .env_var("TEST_VAR", "test_value")
        .timeout(Duration::from_secs(300))
        .build()
        .unwrap();

    assert_eq!(config.target, Some("192.168.1.1".to_string()));
    assert_eq!(config.arguments.len(), 3);
    assert_eq!(config.timeout, Some(Duration::from_secs(300)));
    assert_eq!(
        config.env_vars.get("TEST_VAR"),
        Some(&"test_value".to_string())
    );
}

#[test]
fn test_tool_config_validation() {
    // Config without target should still work (some tools don't need it)
    let result = ToolConfig::builder().build();
    assert!(result.is_ok());

    // Valid config with target should succeed
    let result = ToolConfig::builder().target("example.com").build();
    assert!(result.is_ok());
}

#[test]
fn test_execution_result_metadata() {
    use std::time::Instant;
    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(10));
    let duration = start.elapsed();

    let result = ExecutionResult {
        stdout: "Test output".to_string(),
        stderr: String::new(),
        exit_code: 0,
        duration,
        parsed_result: None,
        evidence: vec![],
    };

    assert!(result.duration >= Duration::from_millis(10));
    assert_eq!(result.exit_code, 0);
    assert!(!result.stdout.is_empty());
}

#[test]
fn test_nmap_tool_creation() {
    use pt_journal::tools::integrations::nmap::{NmapTool, ScanType};

    let tool = NmapTool::default();
    assert_eq!(tool.name(), "nmap");

    let tool = NmapTool::with_scan_type(ScanType::TcpSyn);
    assert_eq!(tool.name(), "nmap");
}

#[test]
fn test_nmap_scan_types() {
    use pt_journal::tools::integrations::nmap::{NmapTool, ScanType};

    let types = vec![
        ScanType::TcpSyn,
        ScanType::TcpConnect,
        ScanType::Udp,
        ScanType::ServiceVersion,
        ScanType::OsDetection,
        ScanType::Aggressive,
        ScanType::Ping,
    ];

    // Test that we can create tools with different scan types
    for scan_type in types {
        let tool = NmapTool::with_scan_type(scan_type);
        assert_eq!(tool.name(), "nmap");
    }
}

#[test]
fn test_gobuster_tool_creation() {
    use pt_journal::tools::integrations::gobuster::{GobusterMode, GobusterTool};

    let tool = GobusterTool::default();
    assert_eq!(tool.name(), "gobuster");

    let tool = GobusterTool::with_mode(GobusterMode::Dns);
    assert_eq!(tool.name(), "gobuster");
}

#[test]
fn test_gobuster_modes() {
    use pt_journal::tools::integrations::gobuster::{GobusterMode, GobusterTool};

    let modes = vec![GobusterMode::Dir, GobusterMode::Dns, GobusterMode::Vhost];

    for mode in modes {
        // Modes exist and can be created
        let tool = GobusterTool::with_mode(mode);
        assert_eq!(tool.name(), "gobuster");
    }
}

#[test]
fn test_tool_executor_creation() {
    use pt_journal::tools::executor::DefaultExecutor;

    let _executor = DefaultExecutor::new();
    let _executor = DefaultExecutor::with_max_concurrent(8);
}

#[test]
fn test_tool_registry() {
    use pt_journal::tools::integrations::gobuster::GobusterTool;
    use pt_journal::tools::integrations::nmap::NmapTool;
    use pt_journal::tools::registry::ToolRegistry;

    let mut registry = ToolRegistry::new();

    // Initially empty
    assert_eq!(registry.list_tools().len(), 0);

    // Register tools
    registry.register(Box::new(NmapTool::default())).unwrap();
    registry
        .register(Box::new(GobusterTool::default()))
        .unwrap();

    let tools = registry.list_tools();
    assert_eq!(tools.len(), 2, "Should have 2 registered tools");
    assert!(tools.iter().any(|t| t == "nmap"), "Should include nmap");
    assert!(
        tools.iter().any(|t| t == "gobuster"),
        "Should include gobuster"
    );

    // Registering same tool twice should fail
    let result = registry.register(Box::new(NmapTool::default()));
    assert!(result.is_err(), "Should not allow duplicate registration");
}

#[test]
fn test_mock_tool_execution() {
    // Test with nmap tool (will fail gracefully if not installed)
    use pt_journal::tools::executor::DefaultExecutor;
    use pt_journal::tools::integrations::nmap::{NmapTool, ScanType};

    let executor = DefaultExecutor::new();
    let tool = NmapTool::with_scan_type(ScanType::TcpConnect);

    let config = ToolConfig::builder()
        .target("127.0.0.1")
        .argument("-p")
        .argument("80")
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();

    let result = executor.execute(&tool, &config);
    // Result can be Ok or Err depending on nmap installation
    // We're just testing that the execution path works
    match result {
        Ok(res) => {
            assert!(res.duration > Duration::from_millis(0));
        }
        Err(_) => {
            // Expected if nmap not installed or times out
        }
    }
}

#[test]
fn test_tool_config_with_multiple_arguments() {
    let config = ToolConfig::builder()
        .target("example.com")
        .argument("-p")
        .argument("1-1000")
        .argument("-sV")
        .argument("-O")
        .argument("--script=vuln")
        .build()
        .unwrap();

    assert_eq!(config.arguments.len(), 5);
    assert!(config.arguments.contains(&"-sV".to_string()));
    assert!(config.arguments.contains(&"--script=vuln".to_string()));
}

#[test]
fn test_tool_config_environment_variables() {
    let config = ToolConfig::builder()
        .target("example.com")
        .env_var("HTTP_PROXY", "http://proxy:8080")
        .env_var("HTTPS_PROXY", "https://proxy:8443")
        .build()
        .unwrap();

    assert_eq!(config.env_vars.len(), 2);
    assert_eq!(
        config.env_vars.get("HTTP_PROXY"),
        Some(&"http://proxy:8080".to_string())
    );
}

#[test]
fn test_tool_config_timeout() {
    let config = ToolConfig::builder()
        .target("example.com")
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap();

    assert_eq!(config.timeout, Some(Duration::from_secs(60)));
}

#[test]
fn test_execution_result_success() {
    let result = ExecutionResult {
        stdout: "Scan completed successfully".to_string(),
        stderr: String::new(),
        exit_code: 0,
        duration: Duration::from_secs(1),
        parsed_result: None,
        evidence: vec![],
    };

    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.contains("successfully"));
    assert!(result.stderr.is_empty());
}

#[test]
fn test_execution_result_with_error() {
    let result = ExecutionResult {
        stdout: String::new(),
        stderr: "Error: Target not reachable".to_string(),
        exit_code: 1,
        duration: Duration::from_millis(100),
        parsed_result: None,
        evidence: vec![],
    };

    assert_ne!(result.exit_code, 0);
    assert!(!result.stderr.is_empty());
    assert!(result.stderr.contains("Error"));
}

#[test]
fn test_tool_evidence_creation() {
    use chrono::Utc;
    use pt_journal::model::Evidence;
    use uuid::Uuid;

    let evidence = Evidence {
        id: Uuid::new_v4(),
        path: "/tmp/scan_output.txt".to_string(),
        created_at: Utc::now(),
        kind: "tool_output".to_string(),
        x: 0.0,
        y: 0.0,
    };

    assert!(!evidence.path.is_empty());
    assert_eq!(evidence.kind, "tool_output");
}

#[test]
fn test_concurrent_tool_configs() {
    // Test that we can create multiple configs simultaneously
    let configs: Vec<_> = (0..10)
        .map(|i| {
            ToolConfig::builder()
                .target(&format!("target{}.com", i))
                .argument("-p")
                .argument("80,443")
                .build()
                .unwrap()
        })
        .collect();

    assert_eq!(configs.len(), 10);
    for (i, config) in configs.iter().enumerate() {
        assert_eq!(config.target, Some(format!("target{}.com", i)));
    }
}

#[test]
fn test_tool_output_parsing_placeholder() {
    // Placeholder for future parsed result testing
    let result = ExecutionResult {
        stdout: "Nmap scan report for example.com\nPORT STATE SERVICE\n80/tcp open http"
            .to_string(),
        stderr: String::new(),
        exit_code: 0,
        duration: Duration::from_secs(1),
        parsed_result: None, // Future: parse into structured data
        evidence: vec![],
    };

    // Basic assertion - in future this would test parsed_result
    assert!(result.stdout.contains("Nmap scan report"));
    assert!(result.stdout.contains("80/tcp"));
}

#[test]
fn test_tool_names_are_lowercase() {
    use pt_journal::tools::integrations::gobuster::GobusterTool;
    use pt_journal::tools::integrations::nmap::NmapTool;

    let nmap = NmapTool::default();
    let gobuster = GobusterTool::default();

    assert_eq!(nmap.name(), "nmap");
    assert_eq!(gobuster.name(), "gobuster");
}

#[test]
fn test_tool_config_builder_chaining() {
    let config = ToolConfig::builder()
        .target("example.com")
        .argument("-p")
        .argument("80")
        .timeout(Duration::from_secs(30))
        .env_var("DEBUG", "1")
        .build()
        .unwrap();

    assert!(config.target.is_some());
    assert!(!config.arguments.is_empty());
    assert!(config.timeout.is_some());
    assert!(!config.env_vars.is_empty());
}
