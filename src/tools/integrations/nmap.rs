/// Nmap integration - Network exploration and security auditing
/// 
/// Supports various Nmap scan types:
/// - Port scanning (TCP/UDP)
/// - Service/version detection
/// - OS detection
/// - Script scanning (NSE)
/// - Output parsing and evidence extraction

use crate::model::Evidence;
use crate::tools::traits::*;
use anyhow::{anyhow, Result};
use chrono::Utc;
use regex::Regex;
use std::process::Command;
use uuid::Uuid;

/// Nmap scan types
#[derive(Debug, Clone, PartialEq)]
pub enum ScanType {
    /// TCP SYN scan (default, requires root)
    TcpSyn,
    /// TCP Connect scan (no root required)
    TcpConnect,
    /// UDP scan
    Udp,
    /// Service/version detection
    ServiceVersion,
    /// OS detection
    OsDetection,
    /// Aggressive scan (OS + version + scripts + traceroute)
    Aggressive,
    /// Ping scan (host discovery)
    Ping,
    /// Custom scan with raw arguments
    Custom(Vec<String>),
}

impl ScanType {
    fn to_args(&self) -> Vec<String> {
        match self {
            ScanType::TcpSyn => vec!["-sS".to_string()],
            ScanType::TcpConnect => vec!["-sT".to_string()],
            ScanType::Udp => vec!["-sU".to_string()],
            ScanType::ServiceVersion => vec!["-sV".to_string()],
            ScanType::OsDetection => vec!["-O".to_string()],
            ScanType::Aggressive => vec!["-A".to_string()],
            ScanType::Ping => vec!["-sn".to_string()],
            ScanType::Custom(args) => args.clone(),
        }
    }
}

/// Parsed Nmap scan result
#[derive(Debug, Clone)]
pub struct NmapResult {
    pub target: String,
    pub scan_type: String,
    pub open_ports: Vec<Port>,
    pub services: Vec<Service>,
    pub os_detection: Option<String>,
    pub script_results: Vec<ScriptResult>,
}

/// Discovered port information
#[derive(Debug, Clone)]
pub struct Port {
    pub number: u16,
    pub protocol: String, // "tcp" or "udp"
    pub state: String,    // "open", "closed", "filtered"
}

/// Service information
#[derive(Debug, Clone)]
pub struct Service {
    pub port: u16,
    pub protocol: String,
    pub name: String,
    pub version: Option<String>,
}

/// NSE script result
#[derive(Debug, Clone)]
pub struct ScriptResult {
    pub script_name: String,
    pub output: String,
}

/// Nmap tool implementation
pub struct NmapTool {
    scan_type: ScanType,
}

impl NmapTool {
    pub fn new() -> Self {
        Self {
            scan_type: ScanType::TcpSyn,
        }
    }

    pub fn with_scan_type(scan_type: ScanType) -> Self {
        Self { scan_type }
    }

    /// Parse port information from Nmap output
    fn parse_ports(output: &str) -> Vec<Port> {
        let mut ports = Vec::new();
        
        // Match lines like: "80/tcp   open  http"
        let port_regex = Regex::new(r"(\d+)/(tcp|udp)\s+(\w+)").unwrap();
        
        for line in output.lines() {
            if let Some(captures) = port_regex.captures(line) {
                if let Ok(number) = captures[1].parse::<u16>() {
                    ports.push(Port {
                        number,
                        protocol: captures[2].to_string(),
                        state: captures[3].to_string(),
                    });
                }
            }
        }
        
        ports
    }

    /// Parse service information from Nmap output
    fn parse_services(output: &str) -> Vec<Service> {
        let mut services = Vec::new();
        
        // Match lines like: "80/tcp   open  http    Apache httpd 2.4.41"
        let service_regex = Regex::new(
            r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?"
        ).unwrap();
        
        for line in output.lines() {
            if let Some(captures) = service_regex.captures(line) {
                if let Ok(port) = captures[1].parse::<u16>() {
                    let version = captures.get(4).map(|m| m.as_str().trim().to_string());
                    
                    services.push(Service {
                        port,
                        protocol: captures[2].to_string(),
                        name: captures[3].to_string(),
                        version,
                    });
                }
            }
        }
        
        services
    }

    /// Parse OS detection results
    fn parse_os_detection(output: &str) -> Option<String> {
        // Look for "OS details:" line
        let os_regex = Regex::new(r"OS details:\s*(.+)").unwrap();
        
        if let Some(captures) = os_regex.captures(output) {
            return Some(captures[1].trim().to_string());
        }
        
        // Alternative: look for "Running:" line
        let running_regex = Regex::new(r"Running:\s*(.+)").unwrap();
        if let Some(captures) = running_regex.captures(output) {
            return Some(captures[1].trim().to_string());
        }
        
        None
    }

    /// Parse NSE script results
    fn parse_script_results(output: &str) -> Vec<ScriptResult> {
        let mut results = Vec::new();
        let script_regex = Regex::new(r"\|_([^:]+):\s*(.+)").unwrap();
        
        for line in output.lines() {
            if let Some(captures) = script_regex.captures(line) {
                results.push(ScriptResult {
                    script_name: captures[1].trim().to_string(),
                    output: captures[2].trim().to_string(),
                });
            }
        }
        
        results
    }
}

impl Default for NmapTool {
    fn default() -> Self {
        Self::new()
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
            .map_err(|e| anyhow!("Nmap not found in PATH: {}", e))?;

        if !output.status.success() {
            return Err(anyhow!("Failed to get Nmap version"));
        }

        let version_str = String::from_utf8_lossy(&output.stdout);
        
        // Parse version like "Nmap version 7.94 ( https://nmap.org )"
        let version_regex = Regex::new(r"Nmap version (\d+)\.(\d+)(?:\.(\d+))?").unwrap();
        
        if let Some(captures) = version_regex.captures(&version_str) {
            let major = captures[1].parse().unwrap_or(0);
            let minor = captures[2].parse().unwrap_or(0);
            let patch = captures.get(3)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            
            return Ok(ToolVersion::new(major, minor, patch));
        }

        Err(anyhow!("Could not parse Nmap version"))
    }

    fn build_command(&self, config: &ToolConfig) -> Result<Command> {
        let mut cmd = Command::new("nmap");

        // Add scan type arguments
        for arg in self.scan_type.to_args() {
            cmd.arg(arg);
        }

        // Add custom arguments from config
        for arg in &config.arguments {
            cmd.arg(arg);
        }

        // Add target (required)
        if let Some(target) = &config.target {
            cmd.arg(target);
        } else {
            return Err(anyhow!("Target is required for Nmap scan"));
        }

        Ok(cmd)
    }

    fn parse_output(&self, output: &str) -> Result<ToolResult> {
        let ports = Self::parse_ports(output);
        let services = Self::parse_services(output);
        let os_detection = Self::parse_os_detection(output);
        let script_results = Self::parse_script_results(output);

        let result = NmapResult {
            target: String::new(), // Will be filled from config
            scan_type: format!("{:?}", self.scan_type),
            open_ports: ports,
            services,
            os_detection,
            script_results,
        };

        // Serialize to JSON for storage
        let json_data = serde_json::json!({
            "target": result.target,
            "scan_type": result.scan_type,
            "open_ports": result.open_ports.iter().map(|p| {
                serde_json::json!({
                    "number": p.number,
                    "protocol": p.protocol,
                    "state": p.state
                })
            }).collect::<Vec<_>>(),
            "services": result.services.iter().map(|s| {
                serde_json::json!({
                    "port": s.port,
                    "protocol": s.protocol,
                    "name": s.name,
                    "version": s.version
                })
            }).collect::<Vec<_>>(),
            "os_detection": result.os_detection,
            "script_results": result.script_results.iter().map(|sr| {
                serde_json::json!({
                    "script_name": sr.script_name,
                    "output": sr.output
                })
            }).collect::<Vec<_>>()
        });

        Ok(ToolResult::Parsed { data: json_data })
    }

    fn extract_evidence(&self, result: &ToolResult) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        match result {
            ToolResult::Parsed { data } => {
                // Extract from JSON data
                if let Some(open_ports) = data.get("open_ports").and_then(|v| v.as_array()) {
                    if !open_ports.is_empty() {
                        evidence.push(Evidence {
                            id: Uuid::new_v4(),
                            path: format!("nmap_ports_{}.txt", Utc::now().timestamp()),
                            kind: "nmap-ports".to_string(),
                            x: 0.0,
                            y: 0.0,
                            created_at: Utc::now(),
                        });
                    }
                }

                if let Some(services) = data.get("services").and_then(|v| v.as_array()) {
                    if !services.is_empty() {
                        evidence.push(Evidence {
                            id: Uuid::new_v4(),
                            path: format!("nmap_services_{}.txt", Utc::now().timestamp()),
                            kind: "nmap-services".to_string(),
                            x: 0.0,
                            y: 0.0,
                            created_at: Utc::now(),
                        });
                    }
                }

                if data.get("os_detection").and_then(|v| v.as_str()).is_some() {
                    evidence.push(Evidence {
                        id: Uuid::new_v4(),
                        path: format!("nmap_os_{}.txt", Utc::now().timestamp()),
                        kind: "nmap-os".to_string(),
                        x: 0.0,
                        y: 0.0,
                        created_at: Utc::now(),
                    });
                }
            }
            ToolResult::Raw { .. } => {
                // Create generic evidence for raw output
                evidence.push(Evidence {
                    id: Uuid::new_v4(),
                    path: format!("nmap_raw_{}.txt", Utc::now().timestamp()),
                    kind: "nmap-raw".to_string(),
                    x: 0.0,
                    y: 0.0,
                    created_at: Utc::now(),
                });
            }
        }

        evidence
    }

    fn validate_prerequisites(&self, config: &ToolConfig) -> Result<()> {
        // Target is required
        if config.target.is_none() {
            return Err(anyhow!("Target host/network is required"));
        }

        // Validate target format (basic check)
        if let Some(target) = &config.target {
            if target.trim().is_empty() {
                return Err(anyhow!("Target cannot be empty"));
            }
        }

        // Some scan types require root privileges
        match self.scan_type {
            ScanType::TcpSyn | ScanType::OsDetection | ScanType::Aggressive => {
                // Check if running as root (on Unix systems)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    // This is a simplified check - in production you'd check effective UID
                    // For now, just warn in validation
                }
            }
            _ => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nmap_tool_creation() {
        let tool = NmapTool::new();
        assert_eq!(tool.name(), "nmap");
        assert_eq!(tool.scan_type, ScanType::TcpSyn);
    }

    #[test]
    fn test_nmap_tool_with_scan_type() {
        let tool = NmapTool::with_scan_type(ScanType::TcpConnect);
        assert_eq!(tool.scan_type, ScanType::TcpConnect);

        let tool = NmapTool::with_scan_type(ScanType::ServiceVersion);
        assert_eq!(tool.scan_type, ScanType::ServiceVersion);
    }

    #[test]
    fn test_scan_type_to_args() {
        assert_eq!(ScanType::TcpSyn.to_args(), vec!["-sS"]);
        assert_eq!(ScanType::TcpConnect.to_args(), vec!["-sT"]);
        assert_eq!(ScanType::Udp.to_args(), vec!["-sU"]);
        assert_eq!(ScanType::ServiceVersion.to_args(), vec!["-sV"]);
        assert_eq!(ScanType::OsDetection.to_args(), vec!["-O"]);
        assert_eq!(ScanType::Aggressive.to_args(), vec!["-A"]);
        assert_eq!(ScanType::Ping.to_args(), vec!["-sn"]);
    }

    #[test]
    fn test_scan_type_custom() {
        let custom = ScanType::Custom(vec!["-p".to_string(), "80,443".to_string()]);
        assert_eq!(custom.to_args(), vec!["-p", "80,443"]);
    }

    #[test]
    fn test_build_command_requires_target() {
        let tool = NmapTool::new();
        let config = ToolConfig::builder().build().unwrap();

        let result = tool.build_command(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Target is required"));
    }

    #[test]
    fn test_build_command_with_target() {
        let tool = NmapTool::new();
        let config = ToolConfig::builder()
            .target("192.168.1.1")
            .build()
            .unwrap();

        let result = tool.build_command(&config);
        assert!(result.is_ok());

        let cmd = result.unwrap();
        let cmd_str = format!("{:?}", cmd);
        assert!(cmd_str.contains("nmap"));
        assert!(cmd_str.contains("192.168.1.1"));
    }

    #[test]
    fn test_build_command_with_scan_type() {
        let tool = NmapTool::with_scan_type(ScanType::TcpConnect);
        let config = ToolConfig::builder()
            .target("scanme.nmap.org")
            .build()
            .unwrap();

        let cmd = tool.build_command(&config).unwrap();
        let cmd_str = format!("{:?}", cmd);
        assert!(cmd_str.contains("-sT"));
        assert!(cmd_str.contains("scanme.nmap.org"));
    }

    #[test]
    fn test_build_command_with_custom_arguments() {
        let tool = NmapTool::new();
        let config = ToolConfig::builder()
            .target("localhost")
            .argument("-p")
            .argument("22,80,443")
            .argument("-T4")
            .build()
            .unwrap();

        let cmd = tool.build_command(&config).unwrap();
        let cmd_str = format!("{:?}", cmd);
        assert!(cmd_str.contains("-p"));
        assert!(cmd_str.contains("22,80,443"));
        assert!(cmd_str.contains("-T4"));
    }

    #[test]
    fn test_parse_ports() {
        let output = r#"
Starting Nmap scan...
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
8080/tcp closed http-proxy
"#;

        let ports = NmapTool::parse_ports(output);
        assert_eq!(ports.len(), 4);

        assert_eq!(ports[0].number, 22);
        assert_eq!(ports[0].protocol, "tcp");
        assert_eq!(ports[0].state, "open");

        assert_eq!(ports[1].number, 80);
        assert_eq!(ports[2].number, 443);

        assert_eq!(ports[3].number, 8080);
        assert_eq!(ports[3].state, "closed");
    }

    #[test]
    fn test_parse_ports_empty_output() {
        let output = "No ports found";
        let ports = NmapTool::parse_ports(output);
        assert_eq!(ports.len(), 0);
    }

    #[test]
    fn test_parse_services() {
        let output = r#"
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open  http    Apache httpd 2.4.41
443/tcp  open  https   nginx 1.18.0
"#;

        let services = NmapTool::parse_services(output);
        assert_eq!(services.len(), 3);

        assert_eq!(services[0].port, 22);
        assert_eq!(services[0].name, "ssh");
        assert!(services[0].version.as_ref().unwrap().contains("OpenSSH"));

        assert_eq!(services[1].port, 80);
        assert_eq!(services[1].name, "http");
        assert!(services[1].version.as_ref().unwrap().contains("Apache"));

        assert_eq!(services[2].port, 443);
        assert_eq!(services[2].name, "https");
    }

    #[test]
    fn test_parse_services_without_version() {
        let output = r#"
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
"#;

        let services = NmapTool::parse_services(output);
        assert_eq!(services.len(), 2);
        
        // Services without version info should still be parsed
        assert_eq!(services[0].port, 22);
        assert_eq!(services[0].name, "ssh");
    }

    #[test]
    fn test_parse_os_detection() {
        let output = r#"
Running: Linux 5.X
OS details: Linux 5.4 - 5.10
Network Distance: 2 hops
"#;

        let os = NmapTool::parse_os_detection(output);
        assert!(os.is_some());
        assert!(os.unwrap().contains("Linux 5.4"));
    }

    #[test]
    fn test_parse_os_detection_running() {
        let output = r#"
Running: Microsoft Windows 10|11
Network Distance: 1 hop
"#;

        let os = NmapTool::parse_os_detection(output);
        assert!(os.is_some());
        assert!(os.unwrap().contains("Windows"));
    }

    #[test]
    fn test_parse_os_detection_not_found() {
        let output = "No OS detection performed";
        let os = NmapTool::parse_os_detection(output);
        assert!(os.is_none());
    }

    #[test]
    fn test_parse_script_results() {
        let output = r#"
PORT     STATE SERVICE
80/tcp   open  http
|_http-title: Test Page
|_http-server-header: Apache/2.4.41
| ssl-cert: Subject: commonName=example.com
|_Not valid before: 2023-01-01
"#;

        let scripts = NmapTool::parse_script_results(output);
        assert!(scripts.len() >= 2);

        assert_eq!(scripts[0].script_name, "http-title");
        assert!(scripts[0].output.contains("Test Page"));

        assert_eq!(scripts[1].script_name, "http-server-header");
        assert!(scripts[1].output.contains("Apache"));
    }

    #[test]
    fn test_validate_prerequisites_requires_target() {
        let tool = NmapTool::new();
        let config = ToolConfig::builder().build().unwrap();

        let result = tool.validate_prerequisites(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Target"));
    }

    #[test]
    fn test_validate_prerequisites_empty_target() {
        let tool = NmapTool::new();
        let config = ToolConfig::builder()
            .target("   ")
            .build()
            .unwrap();

        let result = tool.validate_prerequisites(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_validate_prerequisites_valid() {
        let tool = NmapTool::new();
        let config = ToolConfig::builder()
            .target("192.168.1.1")
            .build()
            .unwrap();

        let result = tool.validate_prerequisites(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_output_creates_nmap_result() {
        let tool = NmapTool::new();
        let output = r#"
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
"#;

        let result = tool.parse_output(output);
        assert!(result.is_ok());

        match result.unwrap() {
            ToolResult::Parsed { data } => {
                // Verify we got parsed data with ports
                let ports = data.get("open_ports").and_then(|v| v.as_array());
                assert!(ports.is_some());
                assert_eq!(ports.unwrap().len(), 3);
            }
            _ => panic!("Expected Parsed result"),
        }
    }

    #[test]
    fn test_extract_evidence_from_parsed_result() {
        let tool = NmapTool::new();
        let output = r#"
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1
80/tcp   open  http    Apache httpd 2.4.41
OS details: Linux 5.4
"#;

        let parsed = tool.parse_output(output).unwrap();
        let evidence = tool.extract_evidence(&parsed);

        // Should have evidence for ports, services, and OS
        assert!(evidence.len() >= 2);
        assert!(evidence.iter().any(|e| e.kind == "nmap-ports"));
        assert!(evidence.iter().any(|e| e.kind == "nmap-services"));
    }

    #[test]
    fn test_extract_evidence_from_raw_result() {
        let tool = NmapTool::new();
        let result = ToolResult::Raw {
            stdout: "Nmap output".to_string(),
            stderr: String::new(),
        };

        let evidence = tool.extract_evidence(&result);
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].kind, "nmap-raw");
    }

    #[test]
    fn test_check_availability() {
        let tool = NmapTool::new();
        
        // This test will only pass if Nmap is installed
        match tool.check_availability() {
            Ok(version) => {
                // If Nmap is installed, verify version format
                assert!(version.major > 0);
                println!("Nmap version: {}.{}.{}", version.major, version.minor, version.patch);
            }
            Err(e) => {
                // If Nmap is not installed, verify error message
                assert!(e.to_string().contains("Nmap not found") || 
                        e.to_string().contains("Could not parse"));
                println!("Nmap not available (expected in test environment): {}", e);
            }
        }
    }
}
