/// Integration tests for security tools module
/// 
/// These tests demonstrate the complete workflow of:
/// 1. Registering tools in the registry
/// 2. Configuring tool execution
/// 3. Running tools via executor
/// 4. Parsing results and extracting evidence

use pt_journal::tools::*;
use pt_journal::tools::executor::DefaultExecutor;
use pt_journal::tools::registry::ToolRegistry;
use pt_journal::tools::integrations::nmap::{NmapTool, ScanType};

#[test]
fn test_nmap_tool_registration() {
    let mut registry = ToolRegistry::new();
    
    let nmap = Box::new(NmapTool::new());
    let result = registry.register(nmap);
    
    assert!(result.is_ok());
    assert!(registry.has_tool("nmap"));
    assert_eq!(registry.count(), 1);
}

#[test]
fn test_nmap_tcp_connect_scan_localhost() {
    // Use TCP Connect scan (no root required)
    let tool = NmapTool::with_scan_type(ScanType::TcpConnect);
    let executor = DefaultExecutor::new();
    
    // Scan localhost port 22 (SSH usually open)
    let config = ToolConfig::builder()
        .target("127.0.0.1")
        .argument("-p")
        .argument("22")
        .build()
        .unwrap();
    
    // This will only succeed if:
    // 1. Nmap is installed
    // 2. SSH is running on localhost
    match tool.check_availability() {
        Ok(_) => {
            // Nmap is available, try the scan
            let result = executor.execute(&tool, &config);
            
            match result {
                Ok(exec_result) => {
                    println!("Scan completed in {:?}", exec_result.duration);
                    println!("Exit code: {}", exec_result.exit_code);
                    println!("Output: {}", exec_result.stdout);
                    
                    // Verify basic success
                    assert_eq!(exec_result.exit_code, 0);
                    assert!(!exec_result.stdout.is_empty());
                }
                Err(e) => {
                    println!("Scan failed (may be expected): {}", e);
                    // Don't fail the test - Nmap might not have permissions or SSH might not be running
                }
            }
        }
        Err(e) => {
            println!("Nmap not available (expected in CI/test environments): {}", e);
            // Don't fail - this is expected when Nmap isn't installed
        }
    }
}

#[test]
fn test_nmap_ping_scan() {
    // Ping scan doesn't require open ports, just checks if host is up
    let tool = NmapTool::with_scan_type(ScanType::Ping);
    let executor = DefaultExecutor::new();
    
    let config = ToolConfig::builder()
        .target("127.0.0.1")
        .build()
        .unwrap();
    
    match tool.check_availability() {
        Ok(_) => {
            let result = executor.execute(&tool, &config);
            
            if let Ok(exec_result) = result {
                println!("Ping scan output: {}", exec_result.stdout);
                assert_eq!(exec_result.exit_code, 0);
                
                // Should mention localhost is up (or similar)
                assert!(
                    exec_result.stdout.contains("127.0.0.1") || 
                    exec_result.stdout.contains("localhost")
                );
            }
        }
        Err(_) => {
            println!("Nmap not available, skipping test");
        }
    }
}

#[test]
fn test_nmap_output_parsing() {
    let tool = NmapTool::new();
    
    // Simulate Nmap output
    let mock_output = r#"
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000010s latency).
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https

Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
"#;
    
    let result = tool.parse_output(mock_output);
    assert!(result.is_ok());
    
    let parsed = result.unwrap();
    match parsed {
        ToolResult::Parsed { data } => {
            // Verify ports were parsed
            let ports = data.get("open_ports").and_then(|v| v.as_array());
            assert!(ports.is_some());
            
            let ports = ports.unwrap();
            assert_eq!(ports.len(), 3);
            
            // Verify port details
            assert_eq!(ports[0]["number"], 22);
            assert_eq!(ports[0]["protocol"], "tcp");
            assert_eq!(ports[0]["state"], "open");
        }
        _ => panic!("Expected parsed result"),
    }
}

#[test]
fn test_nmap_service_detection_parsing() {
    let tool = NmapTool::with_scan_type(ScanType::ServiceVersion);
    
    let mock_output = r#"
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
443/tcp  open  https   nginx 1.18.0
"#;
    
    let result = tool.parse_output(mock_output).unwrap();
    
    match result {
        ToolResult::Parsed { data } => {
            let services = data.get("services").and_then(|v| v.as_array());
            assert!(services.is_some());
            
            let services = services.unwrap();
            assert_eq!(services.len(), 3);
            
            // Verify service details
            assert_eq!(services[0]["port"], 22);
            assert_eq!(services[0]["name"], "ssh");
            assert!(services[0]["version"].as_str().unwrap().contains("OpenSSH"));
            
            assert_eq!(services[1]["port"], 80);
            assert_eq!(services[1]["name"], "http");
            assert!(services[1]["version"].as_str().unwrap().contains("Apache"));
        }
        _ => panic!("Expected parsed result"),
    }
}

#[test]
fn test_nmap_evidence_extraction() {
    let tool = NmapTool::new();
    
    let mock_output = r#"
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1
80/tcp   open  http    Apache httpd 2.4.41
OS details: Linux 5.4 - 5.10
"#;
    
    let parsed = tool.parse_output(mock_output).unwrap();
    let evidence = tool.extract_evidence(&parsed);
    
    // Should have evidence for ports, services, and OS
    assert!(evidence.len() >= 2);
    
    // Check evidence types
    let has_ports = evidence.iter().any(|e| e.kind == "nmap-ports");
    let has_services = evidence.iter().any(|e| e.kind == "nmap-services");
    let has_os = evidence.iter().any(|e| e.kind == "nmap-os");
    
    assert!(has_ports);
    assert!(has_services);
    assert!(has_os);
}

#[test]
fn test_full_workflow_nmap_registration_execution() {
    // Step 1: Create registry
    let mut registry = ToolRegistry::new();
    
    // Step 2: Register Nmap
    let nmap = Box::new(NmapTool::with_scan_type(ScanType::Ping));
    registry.register(nmap).unwrap();
    
    // Step 3: Verify registration
    assert!(registry.has_tool("nmap"));
    
    // Step 4: Create executor
    let executor = DefaultExecutor::new();
    
    // Step 5: Configure scan
    let config = ToolConfig::builder()
        .target("127.0.0.1")
        .build()
        .unwrap();
    
    // Step 6: Check if Nmap is available
    let tool = NmapTool::with_scan_type(ScanType::Ping);
    if tool.check_availability().is_ok() {
        // Step 7: Execute scan
        let result = executor.execute(&tool, &config);
        
        if let Ok(exec_result) = result {
            // Step 8: Verify execution
            assert_eq!(exec_result.exit_code, 0);
            println!("Full workflow test completed successfully");
            println!("Execution time: {:?}", exec_result.duration);
        }
    } else {
        println!("Nmap not available - workflow test skipped");
    }
}

#[test]
fn test_multiple_tools_in_registry() {
    let mut registry = ToolRegistry::new();
    
    // Register different Nmap configurations
    let nmap_tcp = Box::new(NmapTool::with_scan_type(ScanType::TcpConnect));
    let nmap_udp = Box::new(NmapTool::with_scan_type(ScanType::Udp));
    
    // First registration should succeed
    assert!(registry.register(nmap_tcp).is_ok());
    assert_eq!(registry.count(), 1);
    
    // Second registration of same tool should fail (duplicate name)
    let result = registry.register(nmap_udp);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("already registered"));
    
    // Count should remain 1
    assert_eq!(registry.count(), 1);
}
