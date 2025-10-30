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
                "OBJECTIVE: Discover all subdomains associated with the target domain to expand the attack surface.

STEP-BY-STEP PROCESS:
1. Start with passive reconnaissance (no direct interaction with target):
   - Query Certificate Transparency logs using crt.sh or similar services
   - Check DNS databases like DNSDB, VirusTotal, and SecurityTrails
   - Use search engines and archive.org for historical subdomains

2. Perform active enumeration using tools:
   - Run subfinder: subfinder -d target.com -o subfinder.txt
   - Run amass: amass enum -d target.com -o amass.txt
   - Use assetfinder: assetfinder target.com > assetfinder.txt

3. Validate and deduplicate results:
   - Combine all results: cat *.txt | sort | uniq > all_subdomains.txt
   - Test for live subdomains: httpx -l all_subdomains.txt -o live_subdomains.txt
   - Resolve DNS: dnsx -l all_subdomains.txt -o resolved.txt

4. Document findings:
   - Note which subdomains respond to HTTP/HTTPS
   - Identify any that redirect or have different SSL certificates
   - Flag subdomains that might indicate internal systems (dev, staging, api, etc.)

WHAT TO LOOK FOR:
- Development/staging environments
- API endpoints
- Third-party integrations
- Cloud storage buckets
- Email servers

COMMON PITFALLS:
- Don't forget to check for wildcard DNS records
- Some subdomains may only be accessible from specific networks
- Certificate transparency may miss recently issued certificates"
            ),
            (
                "DNS records enumeration",
                "OBJECTIVE: Map the complete DNS infrastructure to understand domain structure and find misconfigurations.

STEP-BY-STEP PROCESS:
1. Enumerate basic DNS records:
   - A/AAAA records: dig target.com A +short
   - CNAME records: dig target.com CNAME +short
   - NS records: dig target.com NS +short
   - MX records: dig target.com MX +short

2. Check for advanced records:
   - TXT records (SPF, DKIM, DMARC): dig target.com TXT +short
   - SRV records: dig target.com SRV +short
   - SOA records: dig target.com SOA +short

3. Test for zone transfer vulnerability:
   - Attempt zone transfer: dig @ns1.target.com target.com AXFR
   - Try with all name servers found in step 1

4. Analyze SPF/DMARC configurations:
   - Check SPF syntax and coverage
   - Verify DKIM selectors are properly configured
   - Review DMARC policy settings

5. Document infrastructure relationships:
   - Map which services use which providers
   - Identify any cloud services or CDNs in use
   - Note any unusual record configurations

WHAT TO LOOK FOR:
- SPF records that allow all IPs (SPF: \"v=spf1 -all\" is good)
- Missing or misconfigured DMARC records
- Zone transfer vulnerabilities
- Internal IP addresses leaked in records
- Unusual CNAME chains

COMMON PITFALLS:
- Some DNS records are only visible from specific geographic locations
- DNS caching can hide recent changes
- Some providers use proprietary record types"
            ),
            (
                "Port scanning",
                "OBJECTIVE: Identify all open ports and services running on discovered hosts.

STEP-BY-STEP PROCESS:
1. Start with a fast, broad scan to identify live hosts:
   - Use rustscan for speed: rustscan -a target.com -- -sV -O
   - Or masscan for very large ranges: masscan -p1-65535 target.com --rate=1000

2. Perform comprehensive TCP scanning:
   - Full TCP SYN scan: nmap -sS -p- -T4 target.com -oA full_tcp
   - Service version detection: nmap -sV -p 1-1000 target.com
   - OS fingerprinting: nmap -O target.com

3. Scan UDP ports (slower, often overlooked):
   - UDP scan: nmap -sU -p 53,67,68,69,123,161 target.com
   - Common UDP services: DNS, DHCP, TFTP, NTP, SNMP

4. Analyze scan results:
   - Identify unexpected open ports
   - Note service versions and potential vulnerabilities
   - Flag ports that should be closed (e.g., 23/telnet, 21/ftp)

5. Document findings with evidence:
   - Screenshot nmap output
   - Note any unusual port combinations
   - Identify potential attack vectors

WHAT TO LOOK FOR:
- Default ports for common services (80/443 web, 22 SSH, 3389 RDP)
- Non-standard ports for standard services (SSH on 2222, web on 8080)
- Legacy services that should be disabled (telnet, ftp)
- Unusual port combinations that might indicate backdoors

COMMON PITFALLS:
- Firewalls may block scanning, giving false negatives
- Some services only respond to specific source IPs
- UDP scanning is unreliable and slow
- Rate limiting can cause missed ports"
            ),
            (
                "Service enumeration",
                "OBJECTIVE: Gather detailed information about services running on open ports.

STEP-BY-STEP PROCESS:
1. Banner grabbing for basic service identification:
   - Use nc/netcat: echo \"\" | nc target.com 80
   - Or nmap scripts: nmap --script banner target.com

2. Enumerate web services (ports 80, 443, 8080, etc.):
   - Basic HTTP headers: curl -I https://target.com
   - Certificate information: openssl s_client -connect target.com:443
   - Web server identification: whatweb target.com

3. Enumerate common protocols:
   - SSH: ssh -v user@target.com (check version, key types)
   - SMTP: nc target.com 25, then HELO test.com
   - FTP: ftp target.com (check anonymous access)
   - SMB: smbclient -L //target.com

4. Use specialized enumeration tools:
   - For SMB: enum4linux-ng -a target.com
   - For SNMP: snmpwalk -v2c -c public target.com
   - For databases: Check common ports (1433 MSSQL, 3306 MySQL)

5. Document service details:
   - Exact version numbers
   - Configuration details
   - Any default credentials that work
   - Unusual service configurations

WHAT TO LOOK FOR:
- Outdated service versions with known vulnerabilities
- Services running as root/Administrator
- Default configurations or credentials
- Services that shouldn't be internet-facing
- Unusual service combinations

COMMON PITFALLS:
- Some services hide their real versions
- Firewalls may interfere with enumeration
- Some protocols require specific handshake sequences
- Virtual hosting can complicate web enumeration"
            ),
            (
                "Web technology fingerprinting",
                "OBJECTIVE: Identify web technologies, frameworks, and CMS to understand the tech stack.

STEP-BY-STEP PROCESS:
1. Use automated fingerprinting tools:
   - Wappalyzer browser extension or CLI
   - whatweb: whatweb target.com
   - httpx with tech detection: httpx -u target.com -tech-detect

2. Manual inspection of HTTP responses:
   - Check server headers: curl -I target.com
   - Look for framework-specific files/paths
   - Examine cookies for framework signatures
   - Check error pages for technology clues

3. JavaScript library analysis:
   - View page source for included libraries
   - Check /js/, /scripts/, /assets/ directories
   - Look for framework-specific JavaScript objects

4. CMS and framework-specific checks:
   - WordPress: Check for wp-admin, wp-content, wp-json
   - Joomla: Look for administrator/, components/
   - Django: Check for /admin/, /static/
   - Laravel: Look for /vendor/, artisan commands

5. Document technology stack:
   - Web server (Apache, Nginx, IIS)
   - Programming language (PHP, Python, Java, .NET)
   - Framework and version
   - Database type
   - CDN or WAF presence

WHAT TO LOOK FOR:
- Outdated framework versions with known vulnerabilities
- Default installations with known paths
- Development frameworks exposed to production
- Mixed technology stacks that might indicate legacy systems

COMMON PITFALLS:
- CDNs can mask real technology stack
- Some frameworks are heavily customized
- JavaScript frameworks may not be obvious from server-side
- Technology detection tools aren't always accurate"
            ),
            (
                "Web crawling and content discovery",
                "OBJECTIVE: Discover all accessible web content and endpoints for comprehensive coverage.

STEP-BY-STEP PROCESS:
1. Basic web crawling:
   - Use browser developer tools to explore the site
   - Follow all links and forms manually
   - Note any areas requiring authentication

2. Automated content discovery:
   - Directory enumeration: dirsearch -u target.com -w /path/to/wordlist
   - Feroxbuster: feroxbuster -u https://target.com -w wordlist.txt
   - Gobuster: gobuster dir -u target.com -w wordlist.txt

3. Parse robots.txt and sitemap.xml:
   - Check /robots.txt for disallowed paths
   - Review /sitemap.xml for all indexed URLs
   - Look for backup files (.bak, .old, .backup)

4. JavaScript source analysis:
   - Extract endpoints from JavaScript files
   - Look for API calls, AJAX requests
   - Check for exposed secrets or configurations

5. Document discovered content:
   - Map the site structure
   - Identify admin panels, login forms, API endpoints
   - Note any sensitive files found (config files, logs, backups)

WHAT TO LOOK FOR:
- Admin panels and management interfaces
- API endpoints and documentation
- File upload forms
- Password reset functionality
- Debug/error pages
- Backup files and source code

COMMON PITFALLS:
- Some content requires specific user agents
- JavaScript-heavy sites may hide endpoints
- Authentication may block content discovery
- Rate limiting can slow down automated tools"
            ),
            (
                "Virtual hosts and subdomain brute-force",
                "OBJECTIVE: Find additional subdomains and virtual hosts not discovered through passive methods.

STEP-BY-STEP PROCESS:
1. Virtual host enumeration:
   - Use ffuf with Host header: ffuf -u http://target.com -H \"Host: FUZZ.target.com\" -w subdomains.txt
   - Check for common virtual host patterns
   - Test with different IP addresses if multiple servers

2. Brute-force subdomain discovery:
   - Use dnsx: dnsx -d target.com -w subdomains.txt -o brute_subdomains.txt
   - Try common patterns: dev, staging, test, api, admin, mail
   - Use larger wordlists for comprehensive coverage

3. Certificate-based discovery:
   - Check SSL certificates for Subject Alternative Names
   - Use tools like crt.sh API for certificate searches
   - Monitor for newly issued certificates

4. Validate findings:
   - Test HTTP/HTTPS responses for each discovered subdomain
   - Check DNS resolution: dig subdomain.target.com
   - Verify SSL certificates match

5. Document virtual host relationships:
   - Map which subdomains point to which IPs
   - Identify shared hosting scenarios
   - Note any that require special DNS resolution

WHAT TO LOOK FOR:
- Development and staging environments
- Internal systems exposed externally
- Third-party services and integrations
- Regional or language-specific subdomains

COMMON PITFALLS:
- Some subdomains only resolve from specific networks
- Virtual hosts may require exact Host header matching
- DNS wildcards can cause false positives
- Some organizations use non-standard TLDs"
            ),
            (
                "TLS/SSL assessment",
                "OBJECTIVE: Evaluate SSL/TLS configuration for security weaknesses and compliance.

STEP-BY-STEP PROCESS:
1. Certificate chain validation:
   - Check certificate validity dates
   - Verify certificate chain: openssl s_client -connect target.com:443 -showcerts
   - Look for self-signed or expired certificates

2. SSL/TLS version support:
   - Test supported protocols: sslscan target.com
   - Check for deprecated SSLv3/TLSv1.0/1.1 support
   - Verify TLS 1.2/1.3 support

3. Cipher suite analysis:
   - List supported ciphers: nmap --script ssl-enum-ciphers target.com
   - Check for weak ciphers (RC4, DES, 3DES, NULL)
   - Verify perfect forward secrecy support

4. Configuration testing:
   - Test for Heartbleed vulnerability
   - Check certificate transparency
   - Verify HSTS header presence
   - Test OCSP stapling

5. Document SSL posture:
   - Certificate details and expiration
   - Supported protocols and ciphers
   - Any security issues found
   - Compliance with security standards

WHAT TO LOOK FOR:
- Weak cipher suites enabled
- Self-signed certificates in production
- Missing security headers (HSTS, HPKP)
- Certificate pinning issues
- Mixed content issues

COMMON PITFALLS:
- Some sites use different certificates for different subdomains
- Load balancers may terminate SSL before the application
- Certificate pinning can complicate testing
- Some security scanners give false positives"
            ),
            (
                "WHOIS/ASN/Netblocks",
                "OBJECTIVE: Map organizational ownership and network infrastructure.

STEP-BY-STEP PROCESS:
1. Domain WHOIS lookup:
   - whois target.com
   - Check registrar and registration dates
   - Note any privacy protection services

2. IP address analysis:
   - Resolve domain IPs: dig target.com A +short
   - WHOIS IP ownership: whois [IP address]
   - Check ARIN, RIPE, APNIC, LACNIC, AFRINIC databases

3. ASN (Autonomous System Number) research:
   - Find ASN for target: whois -h whois.cymru.com \" -v [IP]\"
   - Map ASN to organization: whois -h whois.arin.net AS[ASN]
   - Identify all IP ranges owned by the organization

4. Network mapping:
   - Use bgp.he.net to visualize network topology
   - Identify adjacent networks and peering relationships
   - Check for cloud provider usage (AWS, Azure, GCP)

5. Document infrastructure ownership:
   - Organization details and contacts
   - All IP ranges and ASNs
   - Geographic distribution of infrastructure
   - Third-party service providers

WHAT TO LOOK FOR:
- Related domains owned by the same organization
- Cloud service usage and regions
- International infrastructure presence
- Recent domain transfers or ownership changes

COMMON PITFALLS:
- WHOIS privacy services hide real ownership
- Some countries have less comprehensive WHOIS data
- IP ownership can change frequently
- Organizations may use multiple ASNs"
            ),
            (
                "Cloud asset discovery",
                "OBJECTIVE: Identify cloud-hosted assets and misconfigured cloud resources.

STEP-BY-STEP PROCESS:
1. Cloud storage bucket enumeration:
   - S3 buckets: Check common patterns like target-com, target.com, target-dev
   - Test bucket access: aws s3 ls s3://bucket-name/ --no-sign-request
   - Use automated tools: s3scanner -bucket target

2. Cloud service discovery:
   - Azure storage: Check for blob storage URLs
   - Google Cloud: Look for storage.googleapis.com buckets
   - DigitalOcean: Check spaces endpoints

3. API endpoint discovery:
   - Look for cloud API keys in public repositories
   - Check for exposed cloud metadata endpoints
   - Test common cloud service URLs

4. Misconfiguration scanning:
   - Use cloud_enum for comprehensive cloud asset discovery
   - Check for open S3 buckets with sensitive data
   - Look for exposed cloud databases or caches

5. Document cloud footprint:
   - All discovered cloud services and regions
   - Any misconfigured resources found
   - Data exposure risks identified

WHAT TO LOOK FOR:
- Open S3 buckets with sensitive data
- Exposed API keys or credentials
- Misconfigured cloud databases
- Publicly accessible cloud storage
- Unsecured cloud functions

COMMON PITFALLS:
- Cloud assets may be in different regions
- Some cloud services use non-standard URLs
- Access controls may be time or IP-based
- Some assets require specific authentication"
            ),
            (
                "Email infrastructure reconnaissance",
                "OBJECTIVE: Map email systems and identify potential phishing or spoofing opportunities.

STEP-BY-STEP PROCESS:
1. MX record analysis:
   - Find mail servers: dig target.com MX
   - Test mail server connectivity: nc mail.target.com 25
   - Identify mail server software and versions

2. SPF record examination:
   - Check SPF policy: dig target.com TXT | grep spf
   - Validate SPF syntax and coverage
   - Test SPF enforcement with spoofed emails

3. DKIM and DMARC setup:
   - Find DKIM selectors: dig selector._domainkey.target.com TXT
   - Check DMARC policy: dig _dmarc.target.com TXT
   - Test email authentication mechanisms

4. SMTP service testing:
   - Connect to SMTP: telnet mail.target.com 25
   - Test for open relay: Attempt to send email through the server
   - Check for STARTTLS support

5. Document email security posture:
   - SPF/DKIM/DMARC configuration status
   - Mail server details and security
   - Any vulnerabilities found in email infrastructure

WHAT TO LOOK FOR:
- Missing or weak SPF records
- DMARC set to none (not enforcing)
- Open mail relays
- Outdated mail server software
- Email spoofing opportunities

COMMON PITFALLS:
- Some organizations use multiple mail providers
- SPF records can be complex with includes
- DKIM selectors vary by service
- Some mail servers block automated testing"
            ),
            (
                "Screenshots and preview",
                "OBJECTIVE: Capture visual representations of discovered assets for quick assessment.

STEP-BY-STEP PROCESS:
1. Automated screenshot capture:
   - Use gowitness: gowitness scan --file urls.txt
   - Or eyewitness: eyewitness -f urls.txt --web
   - Aquatone: cat urls.txt | aquatone

2. Organize screenshots by service type:
   - Web applications
   - Administrative interfaces
   - Development environments
   - API endpoints

3. Manual review of screenshots:
   - Look for login forms and authentication mechanisms
   - Identify framework-specific interfaces
   - Note any error messages or debug information
   - Check for default installations

4. Document visual findings:
   - Create an evidence folder with organized screenshots
   - Note any interesting visual elements
   - Flag screenshots showing potential vulnerabilities

WHAT TO LOOK FOR:
- Default login pages
- Error messages revealing technology details
- Debug information in footers or headers
- Unusual UI elements or branding
- Multiple versions of the same application

COMMON PITFALLS:
- Some sites block automated screenshot tools
- JavaScript-heavy sites may not render properly
- Authentication requirements limit screenshot quality
- Screenshots can miss dynamic content"
            ),
            (
                "JavaScript code review (client-side)",
                "OBJECTIVE: Analyze client-side code for security issues and additional attack surface.

STEP-BY-STEP PROCESS:
1. Collect JavaScript files:
   - Download from /js/, /scripts/, /assets/ directories
   - Extract inline JavaScript from HTML pages
   - Use tools like getJS to automate collection

2. Static analysis for secrets:
   - Search for API keys, tokens, passwords
   - Look for hardcoded credentials
   - Check for exposed internal URLs or IPs

3. Endpoint discovery:
   - Extract AJAX calls and API endpoints
   - Find WebSocket connections
   - Identify third-party integrations

4. Code review for vulnerabilities:
   - Look for DOM-based XSS opportunities
   - Check for insecure direct object references
   - Review authentication/authorization logic
   - Identify client-side validation bypasses

5. Document client-side findings:
   - List of discovered endpoints
   - Any secrets or credentials found
   - Potential client-side vulnerabilities
   - Third-party services integrated

WHAT TO LOOK FOR:
- Hardcoded API keys or secrets
- Exposed internal network information
- Client-side validation that can be bypassed
- Unusual JavaScript libraries or frameworks
- Debug code left in production

COMMON PITFALLS:
- Minified JavaScript is hard to analyze
- Some code is loaded dynamically
- CORS policies may limit analysis
- Source maps can help with minified code"
            ),
            (
                "Parameter and endpoint discovery",
                "OBJECTIVE: Identify all input parameters and endpoints for comprehensive testing coverage.

STEP-BY-STEP PROCESS:
1. Automated parameter discovery:
   - Use Arjun: arjun -u https://target.com/endpoint
   - ParamSpider: paramspider -d target.com
   - Burp Suite crawler with parameter discovery

2. Manual parameter identification:
   - Review HTML forms for input fields
   - Check URL parameters in GET requests
   - Test POST bodies for hidden parameters
   - Analyze JavaScript for dynamic parameter usage

3. API endpoint enumeration:
   - Look for /api/, /v1/, /v2/ directories
   - Check for RESTful endpoints
   - Test common API patterns (CRUD operations)

4. Parameter type analysis:
   - Identify injection points (SQL, XSS, command injection)
   - Note file upload parameters
   - Flag parameters that might accept serialized data

5. Document parameter inventory:
   - Complete list of discovered parameters
   - Parameter types and expected values
   - Endpoints requiring authentication
   - Parameters flagged for further testing

WHAT TO LOOK FOR:
- Parameters that accept user input
- File upload functionality
- Parameters that might be vulnerable to injection
- API endpoints with different authentication levels
- Parameters that return sensitive data

COMMON PITFALLS:
- Some parameters are only used in specific workflows
- JavaScript may generate parameters dynamically
- Authentication may hide certain parameters
- API documentation might not be complete"
            ),
            (
                "Public exposures and leaks",
                "OBJECTIVE: Find sensitive information exposed through public sources and data leaks.

STEP-BY-STEP PROCESS:
1. GitHub and Git repository scanning:
   - Use gitrob: gitrob target.com
   - Search GitHub for organization repositories
   - Look for exposed credentials, keys, or configuration files

2. Paste site analysis:
   - Search pastebin, pastie, and other paste sites
   - Use Google dorks for sensitive information
   - Check for leaked credentials or source code

3. Public document analysis:
   - Search for PDFs, docs, and other files containing sensitive info
   - Look for network diagrams, architecture documents
   - Check for exposed API documentation

4. Code repository monitoring:
   - Use trufflehog for secret detection
   - Check for hardcoded passwords, keys, tokens
   - Look for exposed database connection strings

5. Document exposure findings:
   - Any credentials or secrets found
   - Exposed internal information
   - Recommendations for remediation

WHAT TO LOOK FOR:
- API keys and access tokens
- Database credentials
- Private keys and certificates
- Internal network information
- Source code with vulnerabilities

COMMON PITFALLS:
- Information may have been removed but still cached
- Some leaks are on private repositories
- Data may be spread across multiple sites
- False positives from test data"
            ),
            (
                "Basic vulnerability scanning (safe)",
                "OBJECTIVE: Perform non-intrusive scanning to identify obvious security issues.

STEP-BY-STEP PROCESS:
1. Safe vulnerability scanning:
   - Use nuclei with informational templates: nuclei -u target.com -t informational
   - Nikto safe scans: nikto -h target.com -Tuning 1
   - Skip intrusive checks that might cause issues

2. Configuration analysis:
   - Check for common misconfigurations
   - Look for information disclosure
   - Identify default installations

3. Compliance checking:
   - Verify security headers presence
   - Check for outdated software versions
   - Look for known vulnerable configurations

4. Documentation of safe findings:
   - Any informational vulnerabilities found
   - Configuration issues identified
   - Recommendations for improvement

WHAT TO LOOK FOR:
- Missing security headers
- Information disclosure in error messages
- Default credentials or configurations
- Outdated software versions
- Exposed sensitive files

COMMON PITFALLS:
- Some scanners give false positives
- Safe scans miss many real vulnerabilities
- Web application firewalls may block scanning
- Some issues require authenticated access"
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
                "OBJECTIVE: Map discovered technologies to known vulnerabilities and attack vectors.

STEP-BY-STEP PROCESS:
1. Review reconnaissance findings:
   - Compile list of all technologies identified
   - Note version numbers where available
   - Identify framework and library versions

2. Research known vulnerabilities:
   - Check CVE databases for identified versions
   - Use cve.mitre.org or NIST NVD
   - Look for end-of-life software versions

3. Framework-specific analysis:
   - WordPress: Check wpvulndb.com for plugin/theme vulnerabilities
   - Apache/Nginx: Review configuration for common misconfigurations
   - Database versions: Check for known database vulnerabilities

4. Automated vulnerability mapping:
   - Use nuclei with CVE templates: nuclei -u target.com -t cves
   - Cross-reference with discovered technologies
   - Prioritize high-impact vulnerabilities

5. Document vulnerability mapping:
   - List of technologies with versions
   - Associated CVEs and severity levels
   - Potential attack vectors identified
   - Prioritized list for exploitation testing

WHAT TO LOOK FOR:
- Outdated software with known exploits
- Default installations with known vulnerabilities
- Framework plugins with security issues
- End-of-life software still in use

COMMON PITFALLS:
- Version detection isn't always accurate
- Some vulnerabilities require specific conditions
- Patches may not be applied even for known issues
- Custom code can introduce unique vulnerabilities"
            ),
            (
                "Parameter/tamper testing",
                "OBJECTIVE: Test input parameters for common web vulnerabilities using safe, non-destructive methods.

STEP-BY-STEP PROCESS:
1. Prepare parameter inventory:
   - Use findings from parameter discovery phase
   - Categorize parameters by type (GET, POST, JSON, etc.)
   - Prioritize high-risk parameters (user input, file uploads)

2. Basic input validation testing:
   - Test for XSS: <script>alert(1)</script>
   - SQL injection: ' OR 1=1 --
   - Command injection: ; cat /etc/passwd
   - Path traversal: ../../../etc/passwd

3. Parameter manipulation:
   - Test for IDOR: Change user IDs in URLs
   - Boolean-based testing: true/false, 1/0 values
   - Type juggling: Send strings where numbers expected

4. Use automated tools safely:
   - Burp Suite Intruder for parameter testing
   - ffuf for fuzzing: ffuf -u https://target.com/page?param=FUZZ -w wordlist.txt
   - nuclei fuzzing templates (safe ones only)

5. Document testing results:
   - Parameters that show unusual behavior
   - Error messages that reveal information
   - Parameters requiring further investigation
   - Safe testing boundaries established

WHAT TO LOOK FOR:
- Unexpected error messages
- Different responses to malformed input
- Parameters that accept dangerous characters
- Time delays indicating potential injection
- Information disclosure through errors

COMMON PITFALLS:
- Some applications have input validation that blocks obvious attacks
- WAFs may interfere with testing
- Some vulnerabilities only trigger with specific encoding
- Authentication may be required for vulnerable parameters"
            ),
            (
                "Auth/session weaknesses",
                "OBJECTIVE: Evaluate authentication and session management for security weaknesses.

STEP-BY-STEP PROCESS:
1. Authentication mechanism analysis:
   - Identify login forms and authentication flows
   - Test for common usernames/passwords
   - Check password reset functionality
   - Look for multi-factor authentication

2. Session management testing:
   - Check for secure cookie flags (HttpOnly, Secure, SameSite)
   - Test session fixation vulnerabilities
   - Verify session timeout mechanisms
   - Look for session ID predictability

3. JWT token analysis (if used):
   - Decode tokens to check payload contents
   - Test \"none\" algorithm vulnerability
   - Check token expiration and refresh mechanisms
   - Verify signature validation

4. Authorization testing:
   - Test horizontal privilege escalation
   - Check vertical privilege escalation
   - Verify role-based access controls
   - Test for insecure direct object references

5. Document authentication findings:
   - Weaknesses in authentication mechanisms
   - Session management issues found
   - Authorization bypass opportunities
   - Recommendations for improvement

WHAT TO LOOK FOR:
- Weak password policies
- Session IDs in URLs
- Missing secure cookie flags
- JWT algorithm confusion
- Privilege escalation opportunities

COMMON PITFALLS:
- Some applications use non-standard auth mechanisms
- Session management may be handled by third parties
- Testing may require valid user accounts
- Some issues only appear under specific conditions"
            ),
            (
                "Access control tests",
                "OBJECTIVE: Test for broken access controls and privilege escalation opportunities.

STEP-BY-STEP PROCESS:
1. Role matrix development:
   - Identify different user roles in the application
   - Map permissions for each role
   - Create test accounts for different privilege levels

2. Horizontal privilege escalation:
   - Test accessing other users' data with same role
   - IDOR testing: Change user IDs in requests
   - Parameter manipulation for user context

3. Vertical privilege escalation:
   - Test admin functions with regular user accounts
   - Attempt to access restricted URLs directly
   - Manipulate role parameters in requests

4. Business logic testing:
   - Test workflow bypasses
   - Check for time-based access controls
   - Verify resource limits and quotas

5. API access control testing:
   - Test API endpoints with different authentication levels
   - Check for method-level authorization
   - Verify object-level permissions

6. Document access control issues:
   - Broken access controls identified
   - Privilege escalation vectors found
   - Business logic flaws discovered
   - Risk assessment of findings

WHAT TO LOOK FOR:
- Users accessing data they shouldn't see
- Admin functions accessible to regular users
- IDOR vulnerabilities
- Missing authorization checks
- Business logic bypasses

COMMON PITFALLS:
- Some applications use complex permission models
- Access controls may be enforced at different layers
- Testing requires understanding business logic
- Some issues only affect specific user combinations"
            ),
            (
                "Common vulns sweeps",
                "OBJECTIVE: Perform comprehensive testing for well-known web application vulnerabilities.

STEP-BY-STEP PROCESS:
1. Cross-Site Scripting (XSS) testing:
   - Test reflected XSS in all input parameters
   - Stored XSS in forms and comment sections
   - DOM-based XSS in client-side code
   - Use payloads: <script>alert(1)</script>, <img src=x onerror=alert(1)>

2. SQL Injection testing:
   - Classic SQLi: ' OR 1=1 --
   - Union-based: ' UNION SELECT 1,2,3 --
   - Blind SQLi: ' AND 1=1 -- vs ' AND 1=2 --
   - Time-based: ' AND SLEEP(5) --

3. Cross-Site Request Forgery (CSRF):
   - Check for CSRF tokens in state-changing requests
   - Test token validation (missing, predictable, not tied to session)
   - Verify SameSite cookie attributes

4. Security misconfigurations:
   - Directory listing enabled
   - Default error pages with sensitive information
   - Unnecessary HTTP methods enabled (PUT, DELETE, TRACE)
   - Missing security headers (CSP, X-Frame-Options, etc.)

5. Document vulnerability findings:
   - Confirmed vulnerabilities with proof-of-concept
   - Affected endpoints and parameters
   - Severity assessment and exploitability
   - Remediation recommendations

WHAT TO LOOK FOR:
- Input validation failures
- Missing security controls
- Default configurations
- Information disclosure
- Logic flaws in application flow

COMMON PITFALLS:
- Some vulnerabilities require specific conditions
- WAFs may block obvious attack patterns
- Custom encoding may be needed
- Some issues only trigger in specific browsers"
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
                "OBJECTIVE: Safely validate discovered vulnerabilities with minimal-impact proof-of-concepts.

STEP-BY-STEP PROCESS:
1. Review vulnerability analysis findings:
   - Prioritize vulnerabilities by impact and exploitability
   - Ensure you have permission for exploitation testing
   - Prepare isolated testing environment if needed

2. Proof-of-concept development:
   - Start with lowest-risk vulnerabilities
   - Develop minimal payloads that demonstrate the issue
   - Test in staging/development environments first

3. Controlled exploitation:
   - Use time-bound payloads where possible
   - Implement cleanup mechanisms
   - Monitor for unintended side effects
   - Have rollback procedures ready

4. Impact assessment:
   - Document what access was gained
   - Assess potential for lateral movement
   - Evaluate data exposure risks
   - Determine business impact

5. Evidence collection:
   - Screenshot exploitation process
   - Capture network traffic if relevant
   - Document commands and outputs
   - Note system state before/after exploitation

WHAT TO DOCUMENT:
- Exact commands used for exploitation
- System state changes observed
- Data that could be accessed
- Cleanup procedures performed
- Recommendations for remediation

ETHICAL CONSIDERATIONS:
- Only exploit with explicit permission
- Minimize impact on production systems
- Have incident response plan ready
- Respect scope limitations"
            ),
            (
                "Credential attacks (scoped)",
                "OBJECTIVE: Test for weak authentication credentials within defined scope and rules.

STEP-BY-STEP PROCESS:
1. Scope review and permission confirmation:
   - Verify which systems allow credential testing
   - Confirm rules of engagement for password attacks
   - Identify acceptable testing windows

2. Password policy analysis:
   - Review password requirements and complexity rules
   - Test for common weak passwords
   - Check for password reuse across systems

3. Brute force testing (if permitted):
   - Use hydra or medusa with small wordlists
   - Test common usernames: admin, root, user, test
   - Monitor for account lockouts

4. Dictionary attacks:
   - Use targeted wordlists based on organization knowledge
   - Test leaked passwords from previous breaches
   - Check for password reuse from known compromises

5. Credential stuffing (if in scope):
   - Test known username/password combinations
   - Use breached credential databases responsibly
   - Respect rate limiting and account lockout policies

6. Documentation and reporting:
   - Weak credentials discovered
   - Systems vulnerable to password attacks
   - Password policy recommendations
   - Account security improvements needed

WHAT TO LOOK FOR:
- Default or common passwords
- Weak password policies
- Password reuse across systems
- Accounts with excessive privileges

ETHICAL BOUNDARIES:
- Never perform unauthorized brute force
- Respect account lockout policies
- Don't test on production systems without permission
- Stop if you detect monitoring systems"
            ),
            (
                "Exploit known CVEs",
                "OBJECTIVE: Test exploitation of known vulnerabilities with proper controls and safety measures.

STEP-BY-STEP PROCESS:
1. Vulnerability prioritization:
   - Review CVEs from fingerprinting phase
   - Prioritize by CVSS score and exploitability
   - Check for public proof-of-concepts

2. Environment preparation:
   - Set up isolated testing environment
   - Ensure no impact on production systems
   - Prepare monitoring and logging

3. Proof-of-concept execution:
   - Use existing public exploits carefully
   - Test in controlled environment first
   - Implement safety controls (timeouts, rate limiting)

4. Exploit development (if needed):
   - Modify public exploits for target environment
   - Test payload delivery mechanisms
   - Verify exploit reliability

5. Impact verification:
   - Confirm vulnerability exploitation
   - Assess potential damage or data exposure
   - Test exploit cleanup and restoration

6. Comprehensive documentation:
   - CVE details and exploitation method
   - Commands and tools used
   - System changes observed
   - Remediation recommendations

SAFETY MEASURES:
- Test exploits in isolated environments
- Implement timeout and cleanup mechanisms
- Monitor for unintended side effects
- Have system restoration procedures ready

WHAT TO DOCUMENT:
- Successful exploit execution
- System access gained
- Data exposure potential
- Remediation steps required"
            ),
            (
                "Web exploitation",
                "OBJECTIVE: Demonstrate web application vulnerabilities through controlled exploitation.

STEP-BY-STEP PROCESS:
1. Vulnerability confirmation:
   - Re-test vulnerabilities from analysis phase
   - Ensure stable reproduction of issues
   - Prepare minimal-impact exploitation methods

2. XSS exploitation:
   - Craft proof-of-concept payloads
   - Demonstrate cookie theft or session hijacking
   - Show potential for phishing or defacement

3. SQL injection exploitation:
   - Extract database information safely
   - Demonstrate data manipulation capabilities
   - Show potential for privilege escalation

4. Other web vulnerabilities:
   - File inclusion: Access sensitive files
   - Command injection: Execute limited commands
   - SSRF: Access internal resources safely

5. Impact demonstration:
   - Show what an attacker could accomplish
   - Document data exposure risks
   - Demonstrate persistence mechanisms

6. Cleanup and restoration:
   - Remove any test data or changes
   - Restore system to original state
   - Verify no persistent access remains

WEB-SPECIFIC CONSIDERATIONS:
- Focus on data access rather than system compromise
- Use blind techniques where direct output isn't available
- Respect database integrity during testing
- Avoid destructive operations

DOCUMENTATION REQUIREMENTS:
- Exact payloads used
- Data accessed during testing
- Commands executed on target
- System state changes observed"
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
                "OBJECTIVE: Identify and safely demonstrate privilege escalation opportunities.

STEP-BY-STEP PROCESS:
1. Initial access assessment:
   - Document current privilege level
   - Identify potential escalation paths
   - Review system for common privilege escalation vectors

2. Local privilege escalation enumeration:
   - Check for sudo misconfigurations
   - Look for SUID/SGID binaries
   - Review cron jobs and scheduled tasks
   - Check for writable files in PATH

3. Windows-specific enumeration (if applicable):
   - Review user group memberships
   - Check for SeDebugPrivilege, SeImpersonatePrivilege
   - Look for service account misconfigurations
   - Review registry for privilege escalation opportunities

4. Linux-specific enumeration (if applicable):
   - Check kernel version for known exploits
   - Review /etc/sudoers and sudo permissions
   - Look for writable systemd service files
   - Check for Docker/container escape opportunities

5. Safe privilege escalation testing:
   - Test identified vectors in controlled manner
   - Document successful escalation methods
   - Assess impact of elevated privileges
   - Implement cleanup procedures

6. Documentation requirements:
   - Privilege escalation vectors discovered
   - Commands used for enumeration
   - Successful escalation methods
   - System access gained through escalation

PRIVILEGE ESCALATION VECTORS TO CHECK:
- Kernel exploits (review but don't execute)
- SUID binary abuse
- sudo misconfigurations
- Service account compromise
- Scheduled task manipulation
- DLL hijacking (Windows)
- LD_PRELOAD abuse (Linux)

SAFETY FIRST:
- Never execute kernel exploits in production
- Use read-only enumeration tools where possible
- Document findings without full exploitation
- Focus on configuration issues over complex exploits"
            ),
            (
                "Lateral movement (scoped)",
                "OBJECTIVE: Identify and demonstrate safe lateral movement opportunities within scope.

STEP-BY-STEP PROCESS:
1. Network reconnaissance from compromised host:
   - Map internal network topology
   - Identify other systems and services
   - Document trust relationships and access

2. Credential harvesting:
   - Review local credential stores
   - Check for saved passwords or hashes
   - Look for SSH keys, browser credentials
   - Identify service account credentials

3. Access testing to adjacent systems:
   - Test discovered credentials on other systems
   - Check for shared authentication systems
   - Verify network connectivity and firewall rules
   - Document successful lateral movement paths

4. Data movement assessment:
   - Identify sensitive data locations
   - Test access to file shares and databases
   - Check for backup systems and archives
   - Document data exposure potential

5. Persistence mechanism evaluation:
   - Identify ways to maintain access
   - Review backup access methods
   - Check for redundant authentication systems
   - Document long-term access opportunities

6. Comprehensive documentation:
   - Network paths discovered
   - Systems accessed during testing
   - Credentials found and tested
   - Data access capabilities demonstrated

LATERAL MOVEMENT TECHNIQUES:
- Pass-the-hash attacks
- Pass-the-ticket attacks
- Service account abuse
- SSH key reuse
- RDP session hijacking
- Database link abuse

SCOPE AND SAFETY:
- Only move to systems within authorized scope
- Document access without unnecessary data exfiltration
- Use read-only techniques where possible
- Maintain detailed logs of all actions"
            ),
            (
                "Data access validation",
                "OBJECTIVE: Assess what sensitive data can be accessed and document exposure risks.

STEP-BY-STEP PROCESS:
1. Data classification review:
   - Identify different data types present
   - Map data sensitivity levels (public, internal, confidential, restricted)
   - Review data handling procedures

2. Access testing by data type:
   - Test access to user databases
   - Check file share permissions
   - Review backup system access
   - Verify cloud storage permissions

3. Sensitive data identification:
   - Look for PII (Personally Identifiable Information)
   - Check for financial data or payment information
   - Identify intellectual property or trade secrets
   - Review compliance-related data (health, financial)

4. Data exposure assessment:
   - Quantify data accessibility
   - Assess encryption and protection measures
   - Document data flow and storage locations
   - Evaluate backup and archive security

5. Impact analysis:
   - Calculate potential breach impact
   - Assess regulatory compliance implications
   - Document business consequences
   - Prioritize remediation recommendations

6. Evidence collection:
   - Screenshot data access demonstrations
   - Document file permissions and access controls
   - Note encryption status of sensitive data
   - Record data classification findings

DATA TYPES TO CHECK:
- User credentials and authentication data
- Customer PII and contact information
- Financial records and payment data
- Intellectual property and source code
- Compliance-related data (health, financial)
- System configuration and secrets

ETHICAL DATA HANDLING:
- Never exfiltrate actual sensitive data
- Use sample or test data for demonstrations
- Document access capabilities without exposing real data
- Respect data privacy and compliance requirements"
            ),
            (
                "Cleanup",
                "OBJECTIVE: Restore systems to their original state and remove all testing artifacts.

STEP-BY-STEP PROCESS:
1. Access removal:
   - Delete any test user accounts created
   - Remove SSH keys or backdoors installed
   - Revoke temporary permissions granted
   - Close firewall rules opened for testing

2. File system cleanup:
   - Remove test files and directories
   - Delete uploaded webshells or test scripts
   - Clear command history and logs
   - Remove temporary files created during testing

3. Database cleanup:
   - Remove test data inserted during SQL injection testing
   - Restore modified database records
   - Clean up any test tables or procedures
   - Verify database integrity after changes

4. Service restoration:
   - Restart services that were stopped or modified
   - Restore original configuration files
   - Verify system functionality after cleanup
   - Check for any performance impacts

5. Log cleanup (ethical consideration):
   - Document what logs were modified
   - Note that log cleanup may be detectable
   - Consider leaving cleanup logs for transparency
   - Document all cleanup actions performed

6. Verification and documentation:
   - Confirm system restoration to original state
   - Document all cleanup actions taken
   - Verify no persistent access remains
   - Provide cleanup verification evidence

CLEANUP VERIFICATION CHECKLIST:
- All test accounts removed
- File system restored to original state
- Database integrity verified
- Services functioning normally
- No unauthorized access methods remain
- System performance restored

ETHICAL CLEANUP:
- Be transparent about cleanup actions
- Document everything removed or modified
- Ensure no production impact remains
- Consider detection of cleanup activities"
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
                "OBJECTIVE: Organize all findings, screenshots, and proof-of-concept data into structured evidence.

STEP-BY-STEP PROCESS:
1. Create evidence directory structure:
   - /evidence/reconnaissance/ - screenshots, scan outputs
   - /evidence/vulnerabilities/ - PoC scripts, exploit demos
   - /evidence/exploitation/ - access logs, command outputs
   - /evidence/post-exploitation/ - privilege escalation proofs

2. Screenshot organization:
   - Label all screenshots with timestamps and descriptions
   - Create before/after comparison images
   - Document tool outputs and command results
   - Include network captures where relevant

3. Proof-of-concept preservation:
   - Save working exploit code (sanitized)
   - Document exact commands used
   - Include tool configurations and outputs
   - Preserve test data and payloads

4. Finding correlation:
   - Link related findings across phases
   - Create timeline of discovery and exploitation
   - Map attack chains and escalation paths
   - Document dependencies between vulnerabilities

5. Evidence validation:
   - Verify all findings are reproducible
   - Ensure evidence supports stated impact
   - Cross-reference with testing notes
   - Remove any duplicate or irrelevant data

6. Evidence packaging:
   - Create compressed archives of evidence
   - Generate evidence manifest with descriptions
   - Include chain of custody documentation
   - Prepare for secure delivery to client

EVIDENCE TYPES TO COLLECT:
- Screenshots of vulnerable interfaces
- Network traffic captures (PCAP files)
- Command outputs and tool results
- Configuration files showing misconfigurations
- Database dumps (sanitized)
- Log entries showing successful exploitation

QUALITY ASSURANCE:
- Ensure evidence is clear and readable
- Include timestamps on all captures
- Document testing environment details
- Verify evidence supports all findings"
            ),
            (
                "Risk rating and impact",
                "OBJECTIVE: Assess the severity and business impact of each finding using standardized frameworks.

STEP-BY-STEP PROCESS:
1. Vulnerability severity assessment:
   - Use CVSS (Common Vulnerability Scoring System) v3.1
   - Consider base metrics: Attack Vector, Attack Complexity, Privileges Required
   - Factor in environmental metrics: Confidentiality, Integrity, Availability impact

2. Business impact analysis:
   - Map technical findings to business consequences
   - Assess financial impact (data breach costs, downtime, etc.)
   - Evaluate regulatory compliance implications
   - Consider reputational damage potential

3. Risk prioritization:
   - Calculate risk score: Likelihood × Impact
   - Prioritize findings by overall risk level
   - Consider exploitation difficulty and prerequisites
   - Factor in threat actor capability and intent

4. Remediation effort estimation:
   - Assess time and resources needed for fixes
   - Consider dependencies between remediation steps
   - Evaluate temporary mitigation options
   - Prioritize quick wins vs. complex fixes

5. Risk communication:
   - Translate technical risks to business language
   - Create executive summaries for different audiences
   - Develop risk heat maps and dashboards
   - Prepare risk treatment recommendations

RISK SCORING FRAMEWORKS:
- CVSS: Technical vulnerability severity
- OWASP Risk Rating: Threat × Vulnerability × Impact
- Custom business risk models
- Qualitative risk assessments

IMPACT CATEGORIES:
- Confidentiality: Data exposure, privacy violations
- Integrity: Data manipulation, system corruption
- Availability: Service disruption, denial of service
- Compliance: Regulatory violations, fines
- Financial: Direct costs, lost revenue
- Reputational: Brand damage, customer loss"
            ),
            (
                "Remediation guidance",
                "OBJECTIVE: Provide actionable, prioritized recommendations for addressing identified security issues.

STEP-BY-STEP PROCESS:
1. Remediation planning:
   - Group related findings for efficient remediation
   - Create dependency maps for fix ordering
   - Identify quick wins vs. complex changes
   - Consider maintenance windows and downtime

2. Technical remediation steps:
   - Provide specific commands and configuration changes
   - Include code examples for custom fixes
   - Reference official documentation and best practices
   - Consider both immediate and long-term solutions

3. Verification procedures:
   - Include steps to verify fixes are effective
   - Provide test cases for validation
   - Recommend monitoring and alerting setup
   - Suggest regression testing approaches

4. Risk mitigation strategies:
   - Short-term workarounds for critical issues
   - Defense-in-depth recommendations
   - Monitoring and detection improvements
   - Incident response procedure updates

5. Implementation roadmap:
   - Phase remediation by priority and effort
   - Create timelines and milestones
   - Identify responsible parties
   - Suggest follow-up assessment timing

6. Documentation and training:
   - Provide security awareness training recommendations
   - Suggest policy and procedure updates
   - Recommend security tool implementations
   - Include references to security frameworks

REMEDIATION CATEGORIES:
- Configuration changes (immediate, low effort)
- Software updates and patches (planned, medium effort)
- Architecture changes (major, high effort)
- Process improvements (ongoing, variable effort)
- Training and awareness (preventive, ongoing)

VALIDATION REQUIREMENTS:
- Technical verification steps
- Regression testing procedures
- Monitoring and alerting setup
- Follow-up assessment recommendations"
            ),
            (
                "Executive summary",
                "OBJECTIVE: Create a high-level overview for non-technical stakeholders explaining key findings and recommendations.

STEP-BY-STEP PROCESS:
1. Audience analysis:
   - Identify key stakeholders (executives, board members, department heads)
   - Understand their concerns and priorities
   - Tailor language to technical knowledge level
   - Focus on business impact over technical details

2. Key findings synthesis:
   - Summarize most critical vulnerabilities
   - Highlight systemic issues over individual findings
   - Focus on high-impact, high-likelihood risks
   - Use business language (revenue, compliance, reputation)

3. Risk landscape overview:
   - Create executive risk dashboard
   - Show risk trends and patterns
   - Compare against industry benchmarks
   - Highlight improvements from previous assessments

4. Strategic recommendations:
   - Focus on high-level remediation strategies
   - Include cost-benefit analysis where possible
   - Recommend resource allocation priorities
   - Suggest security program improvements

5. Call to action:
   - Clear next steps with timelines
   - Identify responsible parties
   - Suggest metrics for measuring progress
   - Recommend follow-up assessment timing

6. Supporting data:
   - Include key charts and visualizations
   - Reference detailed technical report
   - Provide executive briefing materials
   - Include contact information for questions

EXECUTIVE SUMMARY STRUCTURE:
- Overview of assessment scope and methodology
- High-level findings and risk assessment
- Critical vulnerabilities requiring immediate attention
- Strategic recommendations and roadmap
- Conclusion with key takeaways

COMMUNICATION BEST PRACTICES:
- Use business terminology over technical jargon
- Focus on impact rather than technical details
- Include concrete examples and analogies
- Provide clear, actionable recommendations
- Balance urgency with realistic timelines"
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


