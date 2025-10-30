use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepStatus {
    Todo,
    InProgress,
    Done,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Uuid,
    pub path: String,
    pub created_at: DateTime<Utc>,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub tags: Vec<String>,
    pub status: StepStatus,
    pub completed_at: Option<DateTime<Utc>>,
    pub notes: String,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase {
    pub id: Uuid,
    pub name: String,
    pub steps: Vec<Step>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub phases: Vec<Phase>,
    pub notes_global: String,
}

#[derive(Debug)]
pub struct AppModel {
    pub session: Session,
    pub selected_phase: usize,
    pub selected_step: Option<usize>,
    pub current_path: Option<PathBuf>,
}

impl Default for AppModel {
    fn default() -> Self {
        let steps: Vec<Step> = vec![
            (
                "Subdomain enumeration",
                "Discover subdomains via multiple sources (passive + active):
- Passive: cert transparency (crt.sh), DNSDB, VirusTotal, SecurityTrails
- Tools: amass, subfinder, assetfinder
- Validate and de-duplicate results."
            ),
            (
                "DNS records enumeration",
                "Resolve A/AAAA, CNAME, NS, MX, TXT, SRV records. Check zone transfer.
- Tools: dig, dnsx, amass DNS, fierce
- Look for SPF/DMARC misconfigurations."
            ),
            (
                "Port scanning",
                "Identify open TCP/UDP ports across discovered hosts.
- Tools: nmap (full TCP SYN), masscan (broad), rustscan (fast)
- Use service detection (-sV), script scans where safe."
            ),
            (
                "Service enumeration",
                "Enumerate banners, versions, and protocols for open ports.
- Tools: nmap scripts, nc, curls for HTTP(S), smbclient for SMB, enum4linux-ng"
            ),
            (
                "Web technology fingerprinting",
                "Detect web servers, frameworks, CMS, JS libs.
- Tools: httpx (probes), whatweb, wappalyzer, nuclei tech-detect templates"
            ),
            (
                "Web crawling and content discovery",
                "Crawl endpoints and discover hidden paths.
- Tools: ffuf/feroxbuster/dirsearch, gospider, katana
- Parse robots.txt, sitemap.xml, JS files for endpoints."
            ),
            (
                "Virtual hosts and subdomain brute-force",
                "Enumerate vhosts and unresolved subdomains.
- Tools: ffuf -H Host, gotator + wordlists, dnsx bruteforce"
            ),
            (
                "TLS/SSL assessment",
                "Inspect cert chain, weak ciphers, protocol versions, misconfigs.
- Tools: sslyze, testssl.sh, openssl s_client"
            ),
            (
                "WHOIS/ASN/Netblocks",
                "Map ownership, ASN ranges, and adjacent netblocks.
- Tools: whois, amass intel, ASN lookups"
            ),
            (
                "Cloud asset discovery",
                "Identify cloud buckets, storage, endpoints (S3/GCS/Azure).
- Tools: s3scanner, trufflehog (for leaked keys), cloud_enum"
            ),
            (
                "Email infrastructure reconnaissance",
                "MX/SMTP services, SPF/DKIM/DMARC records, open relays.
- Tools: dig, swaks, dmarcian (manual checks)"
            ),
            (
                "Screenshots and preview",
                "Capture HTTP(S) service screenshots for fast triage.
- Tools: gowitness, eyewitness, aquatone"
            ),
            (
                "JavaScript code review (client-side)",
                "Pull and scan JS for secrets, endpoints, and clues.
- Tools: linkfinder, trufflehog, JSParser"
            ),
            (
                "Parameter and endpoint discovery",
                "Identify parameters for later fuzzing/injection testing.
- Tools: Arjun, ParamSpider, Burp crawler"
            ),
            (
                "Public exposures and leaks",
                "Search paste sites, GitHub, public docs for exposed secrets.
- Tools: trufflehog, gitrob, Google dorks"
            ),
            (
                "Basic vulnerability scanning (safe)",
                "Run low-impact scans to identify obvious misconfigs.
- Tools: nuclei (informational templates), nikto (safe checks)"
            ),
        ]
        .into_iter()
        .map(|(title, description)| Step {
            id: Uuid::new_v4(),
            title: title.to_string(),
            description: description.to_string(),
            tags: vec!["recon".into()],
            status: StepStatus::Todo,
            completed_at: None,
            notes: String::new(),
            evidence: vec![],
        })
        .collect();
        let phase = Phase {
            id: Uuid::new_v4(),
            name: "Reconnaissance".to_string(),
            steps,
            notes: String::new(),
        };
        // Vulnerability Analysis
        let va_steps: Vec<Step> = vec![
            (
                "Fingerprint frameworks and versions",
                "Map server and framework versions to known CVEs.
- Tools: wappalyzer, httpx -tech-detect, nuclei CVE templates"
            ),
            (
                "Parameter/tamper testing",
                "Test parameters for injection, deserialization, SSRF, RCE patterns (non-destructive).
- Tools: Burp, ffuf, nuclei fuzz templates (safe)"
            ),
            (
                "Auth/session weaknesses",
                "Check for weak session handling, JWT alg none, predictable tokens, CSRF.
- Tools: Burp extensions, jwt_tool"
            ),
            (
                "Access control tests",
                "IDOR/BOLA/BFLA using role matrices and user journeys.
- Tools: Burp, Autorize/AutoRepeater"
            ),
            (
                "Common vulns sweeps",
                "XSS, SQLi, SSTI, path traversal, file upload issues (non-destructive probes)."
            ),
        ]
        .into_iter()
        .map(|(title, description)| Step { id: Uuid::new_v4(), title: title.into(), description: description.into(), tags: vec!["analysis".into()], status: StepStatus::Todo, completed_at: None, notes: String::new(), evidence: vec![] })
        .collect();
        let vuln_phase = Phase { id: Uuid::new_v4(), name: "Vulnerability Analysis".into(), steps: va_steps, notes: String::new() };

        // Exploitation
        let ex_steps: Vec<Step> = vec![
            (
                "Exploit validation",
                "Safely validate suspected vulnerabilities with minimal-impact payloads. Obtain proof-of-concept only."
            ),
            (
                "Credential attacks (scoped)",
                "Test weak creds and password reuse where allowed.
- Tools: hydra, medusa, patator, nxc (smb/winrm)"
            ),
            (
                "Exploit known CVEs",
                "Use public exploits carefully with rate limits and safety guards.
- Tools: Metasploit, PoCs in containers"
            ),
            (
                "Web exploitation",
                "XSS → cookies/session; SSRF → metadata; SQLi → data/fileread; RCE → limited shell."
            ),
        ]
        .into_iter()
        .map(|(title, description)| Step { id: Uuid::new_v4(), title: title.into(), description: description.into(), tags: vec!["exploit".into()], status: StepStatus::Todo, completed_at: None, notes: String::new(), evidence: vec![] })
        .collect();
        let exploit_phase = Phase { id: Uuid::new_v4(), name: "Exploitation".into(), steps: ex_steps, notes: String::new() };

        // Post-Exploitation
        let post_steps: Vec<Step> = vec![
            (
                "Privilege escalation (scoped)",
                "Enumerate and validate safe privesc vectors.
- Tools: linPEAS/winPEAS (read-only), manual checks"
            ),
            (
                "Lateral movement (scoped)",
                "Pivot carefully within rules; log access and gather minimal evidence."
            ),
            (
                "Data access validation",
                "Verify reachability of sensitive data classes; avoid bulk exfiltration."
            ),
            (
                "Cleanup",
                "Remove accounts, artifacts, and revert changes where applicable."
            ),
        ]
        .into_iter()
        .map(|(title, description)| Step { id: Uuid::new_v4(), title: title.into(), description: description.into(), tags: vec!["post".into()], status: StepStatus::Todo, completed_at: None, notes: String::new(), evidence: vec![] })
        .collect();
        let post_phase = Phase { id: Uuid::new_v4(), name: "Post-Exploitation".into(), steps: post_steps, notes: String::new() };

        // Reporting
        let rep_steps: Vec<Step> = vec![
            (
                "Evidence consolidation",
                "Organize notes, screenshots, and PoCs per finding."
            ),
            (
                "Risk rating and impact",
                "Rate findings (CVSS/Likelihood x Impact) with business context."
            ),
            (
                "Remediation guidance",
                "Provide actionable fixes and references."
            ),
            (
                "Executive summary",
                "High-level summary for non-technical stakeholders."
            ),
        ]
        .into_iter()
        .map(|(title, description)| Step { id: Uuid::new_v4(), title: title.into(), description: description.into(), tags: vec!["report".into()], status: StepStatus::Todo, completed_at: None, notes: String::new(), evidence: vec![] })
        .collect();
        let report_phase = Phase { id: Uuid::new_v4(), name: "Reporting".into(), steps: rep_steps, notes: String::new() };

        let session = Session {
            id: Uuid::new_v4(),
            name: "New Engagement".to_string(),
            created_at: Utc::now(),
            phases: vec![phase, vuln_phase, exploit_phase, post_phase, report_phase],
            notes_global: String::new(),
        };
        Self {
            session,
            selected_phase: 0,
            selected_step: Some(0),
            current_path: None,
        }
    }
}

// UI messages were removed in favor of a direct GTK setup.

// UI wiring is provided by the Relm4 component in `ui.rs`.


