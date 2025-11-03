/// Gobuster integration - Directory/subdomain enumeration and fuzzing
///
/// Supports Gobuster modes:
/// - Directory/file brute-forcing (dir mode)
/// - DNS subdomain enumeration (dns mode)
/// - Virtual host discovery (vhost mode)
/// - Output parsing and evidence extraction
use crate::model::Evidence;
use crate::tools::traits::*;
use anyhow::{anyhow, Result};
use chrono::Utc;
use regex::Regex;
use std::process::Command;
use uuid::Uuid;

/// Gobuster enumeration modes
#[derive(Debug, Clone, PartialEq)]
pub enum GobusterMode {
    /// Directory/file brute-forcing
    Dir,
    /// DNS subdomain enumeration
    Dns,
    /// Virtual host discovery
    Vhost,
}

impl GobusterMode {
    fn to_string(&self) -> &str {
        match self {
            GobusterMode::Dir => "dir",
            GobusterMode::Dns => "dns",
            GobusterMode::Vhost => "vhost",
        }
    }
}

/// Parsed Gobuster result
#[derive(Debug, Clone)]
pub struct GobusterResult {
    pub mode: String,
    pub target: String,
    pub found_items: Vec<FoundItem>,
    pub total_requests: usize,
    pub status_codes: Vec<u16>,
}

/// Discovered item (URL, subdomain, or vhost)
#[derive(Debug, Clone)]
pub struct FoundItem {
    pub path: String,
    pub status_code: Option<u16>,
    pub size: Option<usize>,
    pub item_type: String, // "directory", "file", "subdomain", "vhost"
}

/// Gobuster tool implementation
pub struct GobusterTool {
    mode: GobusterMode,
}

impl GobusterTool {
    pub fn new() -> Self {
        Self {
            mode: GobusterMode::Dir,
        }
    }

    pub fn with_mode(mode: GobusterMode) -> Self {
        Self { mode }
    }

    /// Parse directory/file findings from output
    fn parse_dir_findings(output: &str) -> Vec<FoundItem> {
        let mut items = Vec::new();

        // Match lines like: "/admin (Status: 200) [Size: 1234]"
        // or "/backup.zip (Status: 301) -> http://example.com/backup/"
        let dir_regex =
            Regex::new(r"(?m)^(/[^\s]+)\s+\(Status:\s+(\d+)\)(?:\s+\[Size:\s+(\d+)\])?").unwrap();

        for captures in dir_regex.captures_iter(output) {
            let path = captures[1].to_string();
            let status_code = captures[2].parse::<u16>().ok();
            let size = captures
                .get(3)
                .and_then(|m| m.as_str().parse::<usize>().ok());

            // Determine if it's a directory or file
            let item_type = if path.ends_with('/') {
                "directory"
            } else {
                "file"
            };

            items.push(FoundItem {
                path,
                status_code,
                size,
                item_type: item_type.to_string(),
            });
        }

        items
    }

    /// Parse DNS subdomain findings from output
    fn parse_dns_findings(output: &str) -> Vec<FoundItem> {
        let mut items = Vec::new();

        // Match lines like: "Found: admin.example.com"
        // or "admin.example.com [123.45.67.89]"
        let dns_regex =
            Regex::new(r"(?:Found:\s+)?([a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z0-9\-\.]+)").unwrap();

        for captures in dns_regex.captures_iter(output) {
            let subdomain = captures[1].to_string();

            // Skip if it's not a valid subdomain format
            if !subdomain.contains('.') {
                continue;
            }

            items.push(FoundItem {
                path: subdomain,
                status_code: None,
                size: None,
                item_type: "subdomain".to_string(),
            });
        }

        // Remove duplicates
        items.sort_by(|a, b| a.path.cmp(&b.path));
        items.dedup_by(|a, b| a.path == b.path);

        items
    }

    /// Parse vhost findings from output
    fn parse_vhost_findings(output: &str) -> Vec<FoundItem> {
        let mut items = Vec::new();

        // Match lines like: "Found: vhost.example.com (Status: 200)"
        let vhost_regex =
            Regex::new(r"(?:Found:\s+)?([a-zA-Z0-9][a-zA-Z0-9\-\.]+)(?:\s+\(Status:\s+(\d+)\))?")
                .unwrap();

        for captures in vhost_regex.captures_iter(output) {
            let vhost = captures[1].to_string();
            let status_code = captures.get(2).and_then(|m| m.as_str().parse::<u16>().ok());

            items.push(FoundItem {
                path: vhost,
                status_code,
                size: None,
                item_type: "vhost".to_string(),
            });
        }

        items
    }

    /// Count total requests made
    fn count_requests(output: &str) -> usize {
        // Look for progress indicators or total count
        let progress_regex = Regex::new(r"Progress:\s+\d+\s+/\s+(\d+)").unwrap();

        if let Some(captures) = progress_regex.captures(output) {
            return captures[1].parse::<usize>().unwrap_or(0);
        }

        0
    }

    /// Extract unique status codes encountered
    fn extract_status_codes(output: &str) -> Vec<u16> {
        let mut codes = Vec::new();
        let code_regex = Regex::new(r"Status:\s+(\d+)").unwrap();

        for captures in code_regex.captures_iter(output) {
            if let Ok(code) = captures[1].parse::<u16>() {
                codes.push(code);
            }
        }

        // Sort and deduplicate
        codes.sort();
        codes.dedup();

        codes
    }
}

impl Default for GobusterTool {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityTool for GobusterTool {
    fn name(&self) -> &str {
        "gobuster"
    }

    fn check_availability(&self) -> Result<ToolVersion> {
        let output = Command::new("gobuster")
            .arg("version")
            .output()
            .map_err(|e| anyhow!("Gobuster not found in PATH: {}", e))?;

        if !output.status.success() {
            return Err(anyhow!("Failed to get Gobuster version"));
        }

        let version_str = String::from_utf8_lossy(&output.stdout);

        // Parse version like "Gobuster v3.6"
        let version_regex = Regex::new(r"[Gg]obuster\s+v?(\d+)\.(\d+)(?:\.(\d+))?").unwrap();

        if let Some(captures) = version_regex.captures(&version_str) {
            let major = captures[1].parse().unwrap_or(0);
            let minor = captures[2].parse().unwrap_or(0);
            let patch = captures
                .get(3)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);

            return Ok(ToolVersion::new(major, minor, patch));
        }

        Err(anyhow!("Could not parse Gobuster version"))
    }

    fn build_command(&self, config: &ToolConfig) -> Result<Command> {
        let mut cmd = Command::new("gobuster");

        // Add mode
        cmd.arg(self.mode.to_string());

        // Add target URL or domain
        if let Some(target) = &config.target {
            match self.mode {
                GobusterMode::Dir | GobusterMode::Vhost => {
                    cmd.arg("-u").arg(target);
                }
                GobusterMode::Dns => {
                    cmd.arg("-d").arg(target);
                }
            }
        } else {
            return Err(anyhow!("Target is required for Gobuster"));
        }

        // Add custom arguments from config
        for arg in &config.arguments {
            cmd.arg(arg);
        }

        Ok(cmd)
    }

    fn parse_output(&self, output: &str) -> Result<ToolResult> {
        let found_items = match self.mode {
            GobusterMode::Dir => Self::parse_dir_findings(output),
            GobusterMode::Dns => Self::parse_dns_findings(output),
            GobusterMode::Vhost => Self::parse_vhost_findings(output),
        };

        let total_requests = Self::count_requests(output);
        let status_codes = Self::extract_status_codes(output);

        let result = GobusterResult {
            mode: format!("{:?}", self.mode),
            target: String::new(), // Will be filled from config
            found_items: found_items.clone(),
            total_requests,
            status_codes: status_codes.clone(),
        };

        // Serialize to JSON
        let json_data = serde_json::json!({
            "mode": result.mode,
            "target": result.target,
            "found_items": found_items.iter().map(|item| {
                serde_json::json!({
                    "path": item.path,
                    "status_code": item.status_code,
                    "size": item.size,
                    "item_type": item.item_type
                })
            }).collect::<Vec<_>>(),
            "total_requests": total_requests,
            "status_codes": status_codes
        });

        Ok(ToolResult::Parsed { data: json_data })
    }

    fn extract_evidence(&self, result: &ToolResult) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        match result {
            ToolResult::Parsed { data } => {
                if let Some(found_items) = data.get("found_items").and_then(|v| v.as_array()) {
                    if !found_items.is_empty() {
                        let mode = data
                            .get("mode")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");

                        evidence.push(Evidence {
                            id: Uuid::new_v4(),
                            path: format!(
                                "gobuster_{}_{}.txt",
                                mode.to_lowercase(),
                                Utc::now().timestamp()
                            ),
                            kind: format!("gobuster-{}", mode.to_lowercase()),
                            x: 0.0,
                            y: 0.0,
                            created_at: Utc::now(),
                        });
                    }
                }
            }
            ToolResult::Raw { .. } => {
                evidence.push(Evidence {
                    id: Uuid::new_v4(),
                    path: format!("gobuster_raw_{}.txt", Utc::now().timestamp()),
                    kind: "gobuster-raw".to_string(),
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
            return Err(anyhow!("Target URL/domain is required"));
        }

        // Validate target format based on mode
        if let Some(target) = &config.target {
            if target.trim().is_empty() {
                return Err(anyhow!("Target cannot be empty"));
            }

            match self.mode {
                GobusterMode::Dir | GobusterMode::Vhost => {
                    // Should be a URL
                    if !target.starts_with("http://") && !target.starts_with("https://") {
                        return Err(anyhow!("Target must be a valid URL (http:// or https://)"));
                    }
                }
                GobusterMode::Dns => {
                    // Should be a domain
                    if target.starts_with("http://") || target.starts_with("https://") {
                        return Err(anyhow!("DNS mode requires domain name, not URL"));
                    }
                }
            }
        }

        // Check for required wordlist in dir/vhost modes
        match self.mode {
            GobusterMode::Dir | GobusterMode::Vhost => {
                let has_wordlist = config
                    .arguments
                    .iter()
                    .any(|arg| arg == "-w" || arg == "--wordlist");

                if !has_wordlist {
                    return Err(anyhow!(
                        "Wordlist (-w) is required for {} mode",
                        self.mode.to_string()
                    ));
                }
            }
            GobusterMode::Dns => {
                let has_wordlist = config
                    .arguments
                    .iter()
                    .any(|arg| arg == "-w" || arg == "--wordlist");

                if !has_wordlist {
                    return Err(anyhow!("Wordlist (-w) is required for DNS mode"));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gobuster_tool_creation() {
        let tool = GobusterTool::new();
        assert_eq!(tool.name(), "gobuster");
        assert_eq!(tool.mode, GobusterMode::Dir);
    }

    #[test]
    fn test_gobuster_with_mode() {
        let tool = GobusterTool::with_mode(GobusterMode::Dns);
        assert_eq!(tool.mode, GobusterMode::Dns);

        let tool = GobusterTool::with_mode(GobusterMode::Vhost);
        assert_eq!(tool.mode, GobusterMode::Vhost);
    }

    #[test]
    fn test_gobuster_mode_to_string() {
        assert_eq!(GobusterMode::Dir.to_string(), "dir");
        assert_eq!(GobusterMode::Dns.to_string(), "dns");
        assert_eq!(GobusterMode::Vhost.to_string(), "vhost");
    }

    #[test]
    fn test_parse_dir_findings() {
        let output = r#"
/admin (Status: 200) [Size: 1234]
/backup (Status: 301) [Size: 0]
/config.php (Status: 403) [Size: 567]
/uploads/ (Status: 200) [Size: 890]
"#;

        let items = GobusterTool::parse_dir_findings(output);
        assert_eq!(items.len(), 4);

        assert_eq!(items[0].path, "/admin");
        assert_eq!(items[0].status_code, Some(200));
        assert_eq!(items[0].size, Some(1234));
        assert_eq!(items[0].item_type, "file");

        assert_eq!(items[3].path, "/uploads/");
        assert_eq!(items[3].item_type, "directory");
    }

    #[test]
    fn test_parse_dir_findings_empty() {
        let output = "No results found";
        let items = GobusterTool::parse_dir_findings(output);
        assert_eq!(items.len(), 0);
    }

    #[test]
    fn test_parse_dns_findings() {
        let output = r#"
Found: admin.example.com
Found: mail.example.com
Found: dev.example.com
"#;

        let items = GobusterTool::parse_dns_findings(output);
        assert_eq!(items.len(), 3);

        assert_eq!(items[0].path, "admin.example.com");
        assert_eq!(items[0].item_type, "subdomain");

        assert_eq!(items[1].path, "dev.example.com");
        assert_eq!(items[2].path, "mail.example.com");
    }

    #[test]
    fn test_parse_vhost_findings() {
        let output = r#"
Found: admin.example.com (Status: 200)
Found: staging.example.com (Status: 403)
"#;

        let items = GobusterTool::parse_vhost_findings(output);
        assert_eq!(items.len(), 2);

        assert_eq!(items[0].path, "admin.example.com");
        assert_eq!(items[0].status_code, Some(200));
        assert_eq!(items[0].item_type, "vhost");
    }

    #[test]
    fn test_extract_status_codes() {
        let output = r#"
/admin (Status: 200)
/login (Status: 200)
/backup (Status: 403)
/test (Status: 404)
"#;

        let codes = GobusterTool::extract_status_codes(output);
        assert_eq!(codes, vec![200, 403, 404]);
    }

    #[test]
    fn test_build_command_requires_target() {
        let tool = GobusterTool::new();
        let config = ToolConfig::builder().build().unwrap();

        let result = tool.build_command(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Target is required"));
    }

    #[test]
    fn test_build_command_dir_mode() {
        let tool = GobusterTool::with_mode(GobusterMode::Dir);
        let config = ToolConfig::builder()
            .target("http://example.com")
            .build()
            .unwrap();

        let result = tool.build_command(&config);
        assert!(result.is_ok());

        let cmd = result.unwrap();
        let cmd_str = format!("{:?}", cmd);
        assert!(cmd_str.contains("gobuster"));
        assert!(cmd_str.contains("dir"));
        assert!(cmd_str.contains("http://example.com"));
    }

    #[test]
    fn test_build_command_dns_mode() {
        let tool = GobusterTool::with_mode(GobusterMode::Dns);
        let config = ToolConfig::builder().target("example.com").build().unwrap();

        let cmd = tool.build_command(&config).unwrap();
        let cmd_str = format!("{:?}", cmd);
        assert!(cmd_str.contains("dns"));
        assert!(cmd_str.contains("-d"));
        assert!(cmd_str.contains("example.com"));
    }

    #[test]
    fn test_build_command_with_wordlist() {
        let tool = GobusterTool::new();
        let config = ToolConfig::builder()
            .target("http://example.com")
            .argument("-w")
            .argument("/usr/share/wordlists/dirb/common.txt")
            .argument("-t")
            .argument("50")
            .build()
            .unwrap();

        let cmd = tool.build_command(&config).unwrap();
        let cmd_str = format!("{:?}", cmd);
        assert!(cmd_str.contains("-w"));
        assert!(cmd_str.contains("common.txt"));
        assert!(cmd_str.contains("-t"));
        assert!(cmd_str.contains("50"));
    }

    #[test]
    fn test_validate_prerequisites_requires_target() {
        let tool = GobusterTool::new();
        let config = ToolConfig::builder().build().unwrap();

        let result = tool.validate_prerequisites(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Target"));
    }

    #[test]
    fn test_validate_prerequisites_dir_mode_requires_url() {
        let tool = GobusterTool::with_mode(GobusterMode::Dir);
        let config = ToolConfig::builder()
            .target("example.com")
            .argument("-w")
            .argument("wordlist.txt")
            .build()
            .unwrap();

        let result = tool.validate_prerequisites(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("URL"));
    }

    #[test]
    fn test_validate_prerequisites_dns_mode_rejects_url() {
        let tool = GobusterTool::with_mode(GobusterMode::Dns);
        let config = ToolConfig::builder()
            .target("http://example.com")
            .argument("-w")
            .argument("wordlist.txt")
            .build()
            .unwrap();

        let result = tool.validate_prerequisites(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("domain name"));
    }

    #[test]
    fn test_validate_prerequisites_requires_wordlist() {
        let tool = GobusterTool::with_mode(GobusterMode::Dir);
        let config = ToolConfig::builder()
            .target("http://example.com")
            .build()
            .unwrap();

        let result = tool.validate_prerequisites(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Wordlist"));
    }

    #[test]
    fn test_validate_prerequisites_valid_dir_mode() {
        let tool = GobusterTool::with_mode(GobusterMode::Dir);
        let config = ToolConfig::builder()
            .target("http://example.com")
            .argument("-w")
            .argument("wordlist.txt")
            .build()
            .unwrap();

        let result = tool.validate_prerequisites(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_prerequisites_valid_dns_mode() {
        let tool = GobusterTool::with_mode(GobusterMode::Dns);
        let config = ToolConfig::builder()
            .target("example.com")
            .argument("-w")
            .argument("subdomains.txt")
            .build()
            .unwrap();

        let result = tool.validate_prerequisites(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_output_dir_mode() {
        let tool = GobusterTool::with_mode(GobusterMode::Dir);
        let output = r#"
/admin (Status: 200) [Size: 1234]
/backup (Status: 301) [Size: 0]
"#;

        let result = tool.parse_output(output).unwrap();
        match result {
            ToolResult::Parsed { data } => {
                let items = data.get("found_items").and_then(|v| v.as_array()).unwrap();
                assert_eq!(items.len(), 2);
                assert_eq!(items[0]["path"], "/admin");
                assert_eq!(items[0]["status_code"], 200);
            }
            _ => panic!("Expected parsed result"),
        }
    }

    #[test]
    fn test_extract_evidence_from_findings() {
        let tool = GobusterTool::new();
        let output = r#"
/admin (Status: 200) [Size: 1234]
/backup (Status: 301) [Size: 0]
"#;

        let parsed = tool.parse_output(output).unwrap();
        let evidence = tool.extract_evidence(&parsed);

        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].kind.contains("gobuster"));
    }

    #[test]
    fn test_check_availability() {
        let tool = GobusterTool::new();

        // This test will only pass if Gobuster is installed
        match tool.check_availability() {
            Ok(version) => {
                println!(
                    "Gobuster version: {}.{}.{}",
                    version.major, version.minor, version.patch
                );
                assert!(version.major > 0 || version.minor > 0);
            }
            Err(e) => {
                println!(
                    "Gobuster not available (expected in test environment): {}",
                    e
                );
                assert!(
                    e.to_string().contains("not found")
                        || e.to_string().contains("Could not parse")
                );
            }
        }
    }
}
