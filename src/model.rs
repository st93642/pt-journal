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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Evidence {
    pub id: Uuid,
    pub path: String,
    pub created_at: DateTime<Utc>,
    pub kind: String,
    pub x: f64,
    pub y: f64,
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
    pub description_notes: String,
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

impl Default for Session {
    fn default() -> Self {
        // Create reconnaissance phase steps
        let recon_steps: Vec<Step> = vec![
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

WHAT TO LOOK FOR:
- Outdated framework versions with known vulnerabilities
- Unusual technology combinations
- Development frameworks in production
- Custom or proprietary software
- Technology stack consistency across subdomains

COMMON PITFALLS:
- Some applications use multiple frameworks
- Version detection may be unreliable
- Some technologies are intentionally obscured
- Framework plugins may introduce vulnerabilities"
            ),
            (
                "Web crawling and spidering",
                "OBJECTIVE: Map the web application structure and discover all accessible pages and functionality.

STEP-BY-STEP PROCESS:
1. Use automated crawling tools:
   - Burp Suite Spider or ZAP spider
   - gobuster for directory enumeration: gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt
   - ffuf for fuzzing: ffuf -u https://target.com/FUZZ -w wordlist.txt

2. Manual exploration:
   - Navigate through the application naturally
   - Test all navigation links and forms
   - Check robots.txt and sitemap.xml
   - Look for admin panels, login pages, API endpoints

3. Parameter discovery:
   - Use paramspider: python3 paramspider.py -d target.com
   - Check for GET/POST parameters in forms
   - Look for URL parameters and query strings
   - Identify API endpoints and their parameters

4. Content discovery:
   - Check for backup files: .bak, .old, .backup
   - Look for configuration files: .env, config.php, web.config
   - Find exposed directories: /admin/, /backup/, /test/
   - Discover hidden pages through comments and source code

5. Document application structure:
   - Create site map with all discovered pages
   - Note authentication requirements for different areas
   - Identify different user roles and permissions
   - Flag any unusual or hidden functionality

WHAT TO LOOK FOR:
- Admin interfaces and management consoles
- API endpoints and documentation
- File upload/download functionality
- User registration and password reset flows
- Error pages that leak information

COMMON PITFALLS:
- Some pages require specific user sessions or roles
- JavaScript-heavy applications may hide functionality
- Rate limiting can prevent thorough crawling
- Some content is only accessible after authentication"
            ),
            (
                "TLS/SSL assessment",
                "OBJECTIVE: Evaluate the security of SSL/TLS configurations and certificates.

STEP-BY-STEP PROCESS:
1. Certificate inspection:
   - Check certificate validity: openssl x509 -in cert.pem -text
   - Verify certificate chain: openssl verify -CAfile ca.pem cert.pem
   - Check expiration dates and renewal status

2. SSL/TLS configuration testing:
   - Use sslscan: sslscan target.com
   - Test with testssl.sh: ./testssl.sh target.com
   - Check supported protocols and cipher suites

3. Protocol analysis:
   - Test for deprecated protocols (SSLv2, SSLv3, TLS 1.0, 1.1)
   - Verify TLS 1.2+ support with strong ciphers
   - Check for Perfect Forward Secrecy (PFS)

4. Common vulnerabilities:
   - Heartbleed: Test with ssltest or online tools
   - POODLE: Check for SSLv3 support
   - BEAST: Verify TLS 1.1+ usage
   - CRIME: Check for TLS compression

5. Certificate Transparency monitoring:
   - Check crt.sh for certificate history
   - Monitor for unexpected certificate issuances
   - Verify certificate pinning if implemented

WHAT TO LOOK FOR:
- Self-signed certificates in production
- Certificates issued by unknown CAs
- Weak cipher suites or protocol versions
- Certificate mismatches (domain vs certificate)
- Expired or soon-to-expire certificates

COMMON PITFALLS:
- Some internal services use self-signed certificates legitimately
- Certificate pinning can break with legitimate renewals
- Some legacy systems cannot support modern TLS versions
- Load balancers may terminate TLS before the application"
            ),
            (
                "Infrastructure mapping",
                "OBJECTIVE: Create a comprehensive map of the target's infrastructure and network topology.

STEP-BY-STEP PROCESS:
1. Network mapping:
   - Use traceroute: traceroute target.com
   - Perform BGP analysis: whois -h whois.radb.net -- '-i origin AS12345'
   - Map network ranges and ASNs

2. Cloud infrastructure identification:
   - Check for cloud-specific headers and behaviors
   - Identify S3 buckets, Azure storage, GCP buckets
   - Look for cloud metadata endpoints (169.254.169.254 for AWS)

3. CDN and WAF detection:
   - Identify Cloudflare, Akamai, Imperva, etc.
   - Test WAF bypass techniques
   - Map CDN edge locations

4. Third-party service enumeration:
   - Identify analytics, tracking, and marketing scripts
   - Check for external APIs and integrations
   - Map data flows to third-party services

5. Geographic distribution:
   - Test from multiple geographic locations
   - Identify any region-specific content or restrictions
   - Map content delivery networks

WHAT TO LOOK FOR:
- Unusual network configurations
- Shadow IT or unauthorized cloud services
- Data exfiltration risks through third parties
- Single points of failure in infrastructure

COMMON PITFALLS:
- Some infrastructure is only visible from specific networks
- Cloud services may use multiple providers
- Infrastructure can change dynamically
- Some services use private networks not visible externally"
            ),
            (
                "Cloud asset discovery",
                "OBJECTIVE: Identify all cloud-hosted assets and services associated with the target.

STEP-BY-STEP PROCESS:
1. Cloud provider enumeration:
   - AWS: Use cloud_enum, s3scanner, bucket_finder
   - Azure: Check for storage accounts, app services
   - GCP: Look for storage buckets and cloud functions
   - DigitalOcean: Check for spaces and droplets

2. S3 bucket discovery:
   - Use lazys3: python lazys3.py target.com
   - Check common naming patterns: target-backup, target-dev, target-logs
   - Test for public access and misconfigurations

3. Cloud service identification:
   - Check for API gateways and serverless functions
   - Identify cloud databases and storage services
   - Look for cloud logging and monitoring services

4. Misconfiguration testing:
   - Test for open S3 buckets: aws s3 ls s3://bucket-name --no-sign-request
   - Check cloud storage permissions
   - Verify authentication requirements

5. Documentation and evidence collection:
   - Screenshot accessible cloud resources
   - Document permission levels and access controls
   - Note any data exposure or misconfigurations

WHAT TO LOOK FOR:
- Publicly accessible storage buckets
- Exposed API keys or credentials
- Misconfigured cloud databases
- Unsecured cloud functions
- Data leakage through cloud logging

COMMON PITFALLS:
- Some cloud assets are intentionally public
- Temporary credentials may expire during testing
- Cloud services may have complex permission models
- Some assets require specific authentication contexts"
            ),
            (
                "Email reconnaissance",
                "OBJECTIVE: Gather intelligence about email infrastructure and personnel.

STEP-BY-STEP PROCESS:
1. Email domain analysis:
   - Check MX records: dig target.com MX
   - Identify email providers (Google, Microsoft, etc.)
   - Test for email spoofing protections

2. Email address harvesting:
   - Use theHarvester: theharvester -d target.com -l 500 -b all
   - Check LinkedIn, company websites, and social media
   - Look for email patterns (firstname.lastname@target.com)

3. Email server enumeration:
   - Test SMTP: nc target.com 25, then VRFY/EXPN commands
   - Check for open relays
   - Identify anti-spam measures

4. Personnel intelligence:
   - LinkedIn scraping for employee information
   - Social media profiling
   - Company directory analysis

5. Phishing preparation:
   - Identify high-value targets
   - Map email communication patterns
   - Document organizational structure

WHAT TO LOOK FOR:
- Email addresses for key personnel
- Email server vulnerabilities
- Weak authentication mechanisms
- Information leakage through email headers

COMMON PITFALLS:
- Some email addresses are role-based, not personal
- Privacy laws limit what information is public
- Email harvesting tools may be rate-limited
- Some organizations use email aliases"
            ),
            (
                "Screenshot capture",
                "OBJECTIVE: Create visual documentation of discovered assets and applications.

STEP-BY-STEP PROCESS:
1. Automated screenshot tools:
   - Use eyewitness: python EyeWitness.py -f urls.txt --web
   - Gowitness: gowitness scan file -f urls.txt
   - Aquatone: cat urls.txt | aquatone

2. Manual screenshot capture:
   - Visit each discovered subdomain and path
   - Capture different states (login, error pages, admin panels)
   - Document before/after states for changes

3. Responsive design testing:
   - Capture screenshots at different viewport sizes
   - Test mobile and tablet interfaces
   - Identify responsive design issues

4. Authentication state documentation:
   - Screenshots of login pages and forms
   - Capture authenticated vs unauthenticated views
   - Document different user role interfaces

5. Evidence organization:
   - Organize screenshots by phase and asset type
   - Create timestamped evidence folders
   - Include metadata (URL, timestamp, tool used)

WHAT TO LOOK FOR:
- Default or error pages indicating technology
- Login interfaces and authentication flows
- Unusual or unexpected functionality
- Branding and customization levels

COMMON PITFALLS:
- Screenshots may not capture dynamic content
- Some pages require specific browser configurations
- Authentication states can change during testing
- Screenshot tools may miss AJAX-loaded content"
            ),
            (
                "JavaScript analysis",
                "OBJECTIVE: Analyze client-side code for security issues and hidden functionality.

STEP-BY-STEP PROCESS:
1. JavaScript file collection:
   - Use getJS: getJS -url https://target.com -output jsfiles.txt
   - Manually identify and download JS files
   - Extract inline JavaScript from HTML

2. Static analysis:
   - Use semgrep or custom regex for secrets
   - Look for hardcoded API keys, passwords, endpoints
   - Identify client-side validation logic

3. Dynamic analysis:
   - Use browser dev tools to analyze runtime behavior
   - Monitor network requests and responses
   - Check for exposed internal APIs

4. Framework and library analysis:
   - Identify JavaScript frameworks (React, Vue, Angular)
   - Check for vulnerable library versions
   - Look for framework-specific security issues

5. Source map analysis:
   - Check for .map files that expose source code
   - Analyze minified code for secrets
   - Identify development vs production code

WHAT TO LOOK FOR:
- Exposed API keys and secrets
- Client-side authentication tokens
- Hidden API endpoints
- Vulnerable JavaScript libraries
- Development debugging code left in production

COMMON PITFALLS:
- Minified code is hard to analyze manually
- Some secrets are intentionally public (public API keys)
- JavaScript may be loaded dynamically
- Source maps may not be available for all files"
            ),
            (
                "Parameter discovery",
                "OBJECTIVE: Identify all input parameters in web applications for testing.

STEP-BY-STEP PROCESS:
1. URL parameter extraction:
   - Use paramspider: python3 paramspider.py -d target.com
   - Parse URLs from crawling results
   - Extract query parameters and fragments

2. Form parameter identification:
   - Analyze HTML forms for input fields
   - Identify hidden parameters
   - Check for file upload forms

3. API parameter discovery:
   - Use postman or burp to explore APIs
   - Check for GraphQL or REST endpoints
   - Identify parameter types and formats

4. Advanced parameter techniques:
   - Use arjun for parameter fuzzing: arjun -u https://target.com/endpoint
   - Test for non-standard parameters
   - Check for parameter pollution vulnerabilities

5. Parameter documentation:
   - Create comprehensive parameter lists
   - Note parameter types and expected values
   - Identify which parameters are user-controllable

WHAT TO LOOK FOR:
- Unvalidated input parameters
- Parameters that control application behavior
- File upload parameters
- Parameters that might be vulnerable to injection

COMMON PITFALLS:
- Some parameters are only available after authentication
- AJAX requests may use different parameter formats
- Parameters may be encoded or encrypted
- Some applications use non-standard parameter naming"
            ),
            (
                "Public exposure scanning",
                "OBJECTIVE: Identify publicly exposed assets and services that shouldn't be internet-facing.

STEP-BY-STEP PROCESS:
1. Internet-wide scanning:
   - Use Shodan: shodan search target.com
   - Censys or ZoomEye for asset discovery
   - BinaryEdge for service enumeration

2. Exposed service identification:
   - Look for development servers, staging environments
   - Identify misconfigured cloud services
   - Check for exposed databases and admin interfaces

3. Vulnerability scanning:
   - Use Nessus or OpenVAS for comprehensive scanning
   - Nuclei for template-based vulnerability detection
   - Check for default credentials on exposed services

4. Data exposure verification:
   - Test for information disclosure
   - Check for exposed sensitive files
   - Verify data classification and handling

5. Risk assessment:
   - Document all exposed assets
   - Assess the risk level of each exposure
   - Prioritize remediation based on impact

WHAT TO LOOK FOR:
- Exposed development environments
- Publicly accessible databases
- Admin interfaces without authentication
- Sensitive files and documents
- Services running with default credentials

COMMON PITFALLS:
- Some exposures are intentional (public APIs)
- Internal services may be exposed through misconfigurations
- Cloud services may have complex permission models
- Some assets require specific access patterns"
            ),
            (
                "WHOIS domain analysis",
                "OBJECTIVE: Gather domain registration and ownership information for intelligence gathering.

STEP-BY-STEP PROCESS:
1. WHOIS query execution:
   - Use whois command: whois target.com
   - Check multiple WHOIS servers if needed
   - Use web interfaces like whois.icann.org

2. Domain information extraction:
   - Record registrar and registration dates
   - Note name servers and DNS configuration
   - Identify domain contacts and owners

3. Historical analysis:
   - Check domain history for ownership changes
   - Look for related domains owned by same entity
   - Identify domain age and renewal patterns

4. Privacy service detection:
   - Check for WHOIS privacy/guard services
   - Attempt to bypass privacy protections
   - Look for alternative contact information

5. Intelligence correlation:
   - Cross-reference with other reconnaissance data
   - Identify related infrastructure and services
   - Build profile of domain ownership

WHAT TO LOOK FOR:
- Domain registration privacy services
- Related domains with same ownership
- Recent domain transfers or changes
- Contact information for key personnel
- Domain expiration dates

COMMON PITFALLS:
- WHOIS privacy services hide real owner information
- Some TLDs have different WHOIS requirements
- Historical data may not be available
- Contact information may be outdated"
            ),
            (
                "Social media reconnaissance",
                "OBJECTIVE: Gather intelligence from social media platforms about the target organization and personnel.

STEP-BY-STEP PROCESS:
1. Platform identification:
   - Identify official company social media accounts
   - Find employee personal and professional profiles
   - Check for abandoned or forgotten accounts

2. Content analysis:
   - Review posts for technical information
   - Identify technologies and tools mentioned
   - Look for organizational structure clues

3. Personnel mapping:
   - Create employee directory from social profiles
   - Identify job roles and responsibilities
   - Map organizational hierarchy

4. Security awareness assessment:
   - Check for information disclosure in posts
   - Identify potential social engineering targets
   - Look for security-related discussions

5. Intelligence documentation:
   - Compile personnel database
   - Document organizational insights
   - Note potential security awareness issues

WHAT TO LOOK FOR:
- Employee names and contact information
- Technology stack mentions
- Organizational structure insights
- Security awareness indicators
- Potential social engineering vectors

COMMON PITFALLS:
- Social media data may be outdated
- Some employees maintain strict privacy settings
- Information may not be accurate or current
- Privacy laws limit data collection"
            ),
        ]
        .into_iter()
        .map(|(title, description)| Step { id: Uuid::new_v4(), title: title.into(), description: description.into(), tags: vec!["recon".into()], status: StepStatus::Todo, completed_at: None, notes: String::new(), description_notes: String::new(), evidence: vec![] })
        .collect();
        let recon_phase = Phase { id: Uuid::new_v4(), name: "Reconnaissance".into(), steps: recon_steps, notes: String::new() };

        // Create vulnerability analysis phase steps
        let vuln_steps: Vec<Step> = vec![
            (
                "Framework mapping to CVEs",
                "OBJECTIVE: Map identified technologies and versions to known vulnerabilities.

STEP-BY-STEP PROCESS:
1. Technology inventory review:
   - Compile list of all identified technologies
   - Include versions where available
   - Note operating systems, frameworks, libraries

2. Vulnerability database research:
   - Search NVD (NIST): https://nvd.nist.gov/
   - Check Exploit-DB: https://www.exploit-db.com/
   - Review vendor security advisories

3. CVE analysis:
   - Identify CVEs affecting discovered versions
   - Assess exploitability in target environment
   - Check for proof-of-concept exploits

4. Risk prioritization:
   - Score vulnerabilities using CVSS
   - Consider exploitability factors
   - Assess business impact

5. Documentation:
   - Create vulnerability matrix
   - Include CVE details and references
   - Document affected systems and components

WHAT TO LOOK FOR:
- Critical and high-severity vulnerabilities
- Recently disclosed vulnerabilities (zero-days)
- Vulnerabilities with public exploits
- End-of-life software versions

COMMON PITFALLS:
- Not all vulnerabilities are exploitable in every environment
- Some vendors dispute or downplay reported vulnerabilities
- Patch levels may not match public version numbers
- Some systems use backported security fixes"
            ),
            (
                "Parameter testing",
                "OBJECTIVE: Test input parameters for common web vulnerabilities.

STEP-BY-STEP PROCESS:
1. SQL injection testing:
   - Test all input parameters with SQL payloads
   - Use sqlmap: sqlmap -u \"https://target.com/page?id=1\" --batch
   - Check for error-based, blind, and time-based injection

2. XSS testing:
   - Test reflected XSS: <script>alert(1)</script>
   - Test stored XSS in forms and comments
   - Check DOM-based XSS in client-side code

3. Command injection:
   - Test system command execution in input fields
   - Check for shell metacharacter injection
   - Test file inclusion vulnerabilities

4. Other injection types:
   - LDAP injection in login forms
   - XPath injection in XML processing
   - NoSQL injection in MongoDB applications

5. Input validation bypass:
   - Test encoding bypasses (URL encoding, HTML encoding)
   - Check for parameter pollution
   - Test multipart form boundaries

WHAT TO LOOK FOR:
- Unescaped user input in database queries
- Reflected user input in HTML output
- Command execution through user-controlled input
- File inclusion vulnerabilities

COMMON PITFALLS:
- Some applications use prepared statements or ORM
- WAFs may block obvious payloads
- Some injection requires specific syntax
- Context matters (HTML vs JavaScript vs SQL)"
            ),
            (
                "Authentication analysis",
                "OBJECTIVE: Evaluate the security of authentication and session management mechanisms.

STEP-BY-STEP PROCESS:
1. Authentication mechanism review:
   - Identify authentication methods (forms, SSO, MFA)
   - Check password policies and complexity requirements
   - Test account lockout mechanisms

2. Session management testing:
   - Check for secure cookie flags (HttpOnly, Secure, SameSite)
   - Test session fixation vulnerabilities
   - Verify session timeout and invalidation

3. Password security assessment:
   - Test for weak password acceptance
   - Check password reset functionality
   - Verify password storage security (if accessible)

4. Multi-factor authentication:
   - Test MFA implementation and bypass attempts
   - Check for MFA fatigue attacks
   - Verify backup authentication methods

5. Authorization testing:
   - Test horizontal privilege escalation
   - Check vertical privilege escalation
   - Verify role-based access controls

WHAT TO LOOK FOR:
- Weak password requirements
- Session cookies without security flags
- Password reset vulnerabilities
- Missing or weak MFA implementation
- Insecure direct object references (IDOR)

COMMON PITFALLS:
- Some authentication is handled by third parties
- Internal applications may have weaker controls
- Session management may be handled by frameworks
- Some systems use non-standard authentication flows"
            ),
            (
                "Access control testing",
                "OBJECTIVE: Verify that users can only access resources they are authorized for.

STEP-BY-STEP PROCESS:
1. Role definition and testing:
   - Identify different user roles and permissions
   - Test each role's access to different resources
   - Check for role-based access control (RBAC)

2. Horizontal privilege escalation:
   - Attempt to access other users' data
   - Test IDOR vulnerabilities
   - Check for insecure direct object references

3. Vertical privilege escalation:
   - Attempt to gain higher privileges
   - Test admin function access from user accounts
   - Check for privilege escalation through misconfigurations

4. Business logic testing:
   - Test workflow bypasses
   - Check for logic flaws in access controls
   - Verify state transitions and permissions

5. API authorization:
   - Test API endpoints for proper authorization
   - Check for JWT token vulnerabilities
   - Verify API key and token security

WHAT TO LOOK FOR:
- Users accessing data they shouldn't see
- Admin functions accessible to regular users
- API endpoints without proper authentication
- Business logic flaws allowing unauthorized access

COMMON PITFALLS:
- Some access controls are enforced at the UI level only
- APIs may have different authorization than web interface
- Some applications use complex permission matrices
- Access controls may be bypassed through race conditions"
            ),
            (
                "Common vulnerability sweeps",
                "OBJECTIVE: Perform broad scanning for common vulnerabilities across all discovered assets.

STEP-BY-STEP PROCESS:
1. Automated vulnerability scanning:
   - Use OpenVAS or Nessus for comprehensive scanning
   - Nuclei for template-based vulnerability detection
   - Nikto for web server vulnerability scanning

2. Web application scanning:
   - OWASP ZAP or Burp Suite active scanning
   - SQLMap for automated SQL injection testing
   - Dirbuster for directory and file enumeration

3. Network vulnerability assessment:
   - Nmap vulnerability scripts
   - Test for common misconfigurations
   - Check for default credentials

4. Configuration review:
   - Check for security headers (CSP, HSTS, X-Frame-Options)
   - Verify SSL/TLS configurations
   - Test for information disclosure

5. Manual verification:
   - Verify automated findings
   - Test for bypass techniques
   - Document false positives and confirmed vulnerabilities

WHAT TO LOOK FOR:
- Outdated software with known vulnerabilities
- Misconfigurations and default settings
- Missing security controls
- Information disclosure issues

COMMON PITFALLS:
- Automated scanners produce false positives
- Some vulnerabilities require specific conditions
- Scanners may miss custom application logic issues
- Rate limiting can prevent thorough scanning"
            ),
        ]
        .into_iter()
        .map(|(title, description)| Step { id: Uuid::new_v4(), title: title.into(), description: description.into(), tags: vec!["vuln".into()], status: StepStatus::Todo, completed_at: None, notes: String::new(), description_notes: String::new(), evidence: vec![] })
        .collect();
        let vuln_phase = Phase { id: Uuid::new_v4(), name: "Vulnerability Analysis".into(), steps: vuln_steps, notes: String::new() };

        // Create exploitation phase steps
        let exploit_steps: Vec<Step> = vec![
            (
                "Safe exploit validation",
                "OBJECTIVE: Verify that identified vulnerabilities can be safely exploited without causing damage.

STEP-BY-STEP PROCESS:
1. Vulnerability verification:
   - Confirm vulnerability exists and is exploitable
   - Test in isolated environment first
   - Verify exploit conditions and prerequisites

2. Impact assessment:
   - Determine potential damage from exploitation
   - Identify data at risk
   - Assess system availability impact

3. Safe exploitation planning:
   - Develop proof-of-concept exploits
   - Create exploitation scripts with safety checks
   - Plan for exploitation rollback if needed

4. Controlled testing:
   - Test exploits in development/staging environments
   - Use virtual machines or containers for isolation
   - Monitor system behavior during exploitation

5. Documentation and evidence:
   - Record exploitation process and results
   - Capture screenshots and network traffic
   - Document impact and recovery procedures

WHAT TO LOOK FOR:
- Reliable exploit methods
- Minimal collateral damage
- Clear exploitation prerequisites
- Safe rollback procedures

COMMON PITFALLS:
- Some exploits are unreliable or environment-specific
- Testing environments may differ from production
- Some exploits require specific timing or conditions
- Rollback may not always be possible"
            ),
            (
                "Credential testing",
                "OBJECTIVE: Test discovered or default credentials against identified services.

STEP-BY-STEP PROCESS:
1. Default credential testing:
   - Test common default credentials for each service
   - Use credential lists from SecLists or similar
   - Check vendor documentation for default passwords

2. Discovered credential validation:
   - Test credentials found during reconnaissance
   - Check password reuse across services
   - Verify credential validity and permissions

3. Brute force testing:
   - Use Hydra or Medusa for credential spraying
   - Test against common password lists
   - Implement rate limiting to avoid lockouts

4. Password policy assessment:
   - Test password complexity requirements
   - Check account lockout mechanisms
   - Verify password history enforcement

5. Credential documentation:
   - Record successful authentications
   - Note credential sources and context
   - Document access levels and permissions

WHAT TO LOOK FOR:
- Default credentials that haven't been changed
- Weak passwords that can be brute-forced
- Password reuse across different systems
- Accounts with excessive privileges

COMMON PITFALLS:
- Some systems have complex lockout policies
- Brute force may trigger security alerts
- Some credentials are intentionally weak for testing
- Multi-factor authentication can block credential testing"
            ),
            (
                "CVE exploitation",
                "OBJECTIVE: Attempt exploitation of identified CVEs with available exploits.

STEP-BY-STEP PROCESS:
1. Exploit research and preparation:
   - Research available exploits for identified CVEs
   - Download proof-of-concept code from Exploit-DB
   - Review exploit requirements and limitations

2. Exploit adaptation:
   - Modify exploits for target environment
   - Test exploits in isolated lab environment
   - Verify exploit reliability and stability

3. Controlled exploitation:
   - Execute exploits with monitoring in place
   - Capture evidence of successful exploitation
   - Document system state before and after

4. Post-exploitation assessment:
   - Verify level of access gained
   - Assess exploit reliability for repeated use
   - Document any system changes or artifacts

5. Evidence collection:
   - Screenshot exploitation process
   - Capture network traffic and logs
   - Document exploit code and modifications

WHAT TO LOOK FOR:
- Reliable public exploits
- Exploits that provide useful access
- Minimal system disruption
- Clear exploitation evidence

COMMON PITFALLS:
- Many public exploits are unreliable or outdated
- Target environment may differ from exploit assumptions
- Some exploits require specific conditions or versions
- Antivirus or EDR may detect exploit attempts"
            ),
            (
                "Web application exploitation",
                "OBJECTIVE: Exploit identified web application vulnerabilities.

STEP-BY-STEP PROCESS:
1. Vulnerability prioritization:
   - Rank web vulnerabilities by severity and exploitability
   - Focus on high-impact vulnerabilities first
   - Consider business context and risk tolerance

2. Exploit development:
   - Create custom exploits for unique vulnerabilities
   - Adapt public exploits to target environment
   - Test exploits in safe environment first

3. Exploitation execution:
   - Execute exploits with proper monitoring
   - Capture evidence of successful exploitation
   - Document impact and data accessed

4. Payload delivery:
   - Use appropriate payload types (reverse shell, webshell)
   - Ensure payload reliability and persistence
   - Test payload execution and cleanup

5. Impact documentation:
   - Record data accessed or modified
   - Document privilege escalation achieved
   - Note any persistent access established

WHAT TO LOOK FOR:
- SQL injection leading to data extraction
- XSS for session hijacking or defacement
- File inclusion for code execution
- Authentication bypass vulnerabilities

COMMON PITFALLS:
- Web application firewalls may block exploits
- Some vulnerabilities require specific user context
- JavaScript-heavy applications complicate exploitation
- Session management may limit exploit windows"
            ),
        ]
        .into_iter()
        .map(|(title, description)| Step { id: Uuid::new_v4(), title: title.into(), description: description.into(), tags: vec!["exploit".into()], status: StepStatus::Todo, completed_at: None, notes: String::new(), description_notes: String::new(), evidence: vec![] })
        .collect();
        let exploit_phase = Phase { id: Uuid::new_v4(), name: "Exploitation".into(), steps: exploit_steps, notes: String::new() };

        // Create post-exploitation phase steps
        let post_steps: Vec<Step> = vec![
            (
                "Privilege escalation",
                "OBJECTIVE: Attempt to gain higher privileges on compromised systems.

STEP-BY-STEP PROCESS:
1. Current privilege assessment:
   - Determine current user privileges and permissions
   - Identify available escalation vectors
   - Check for sudo, suid binaries, or other privilege mechanisms

2. Local privilege escalation:
   - Test kernel exploits for outdated systems
   - Check for misconfigured sudo permissions
   - Look for vulnerable suid/sgid binaries

3. Windows privilege escalation:
   - Check for service misconfigurations
   - Test for token impersonation
   - Look for scheduled task vulnerabilities

4. Linux privilege escalation:
   - Check for writable files in PATH
   - Test for cron job vulnerabilities
   - Look for capability misconfigurations

5. Documentation:
   - Record privilege escalation methods used
   - Document new access levels achieved
   - Note any persistent privilege changes

WHAT TO LOOK FOR:
- Kernel vulnerabilities allowing root access
- Misconfigured service accounts with high privileges
- Weak sudo configurations
- Vulnerable scheduled tasks or cron jobs

COMMON PITFALLS:
- Some privilege escalation requires specific conditions
- Modern systems have better exploit mitigations
- Some escalation methods are noisy and detectable
- Privilege changes may not persist across reboots"
            ),
            (
                "Lateral movement",
                "OBJECTIVE: Move through the network to access additional systems and data.

STEP-BY-STEP PROCESS:
1. Network reconnaissance:
   - Map internal network from compromised host
   - Identify other systems and services
   - Check for domain trusts and authentication relationships

2. Credential harvesting:
   - Extract credentials from compromised systems
   - Check for stored passwords and hashes
   - Look for SSH keys and configuration files

3. Authentication reuse:
   - Test harvested credentials on other systems
   - Check for password reuse across the environment
   - Attempt pass-the-hash or pass-the-ticket attacks

4. Service exploitation:
   - Exploit vulnerable services on other systems
   - Use compromised credentials for access
   - Chain vulnerabilities for broader access

5. Persistence establishment:
   - Create backdoors on additional systems
   - Establish command and control channels
   - Document access paths and methods

WHAT TO LOOK FOR:
- Domain admin credentials
- Service accounts with broad access
- Vulnerable internal services
- Trust relationships between systems

COMMON PITFALLS:
- Network segmentation may limit lateral movement
- Some credentials have limited scope or expiration
- Security monitoring may detect lateral movement
- Some systems require multi-factor authentication"
            ),
            (
                "Data access validation",
                "OBJECTIVE: Locate and access sensitive data within the compromised environment.

STEP-BY-STEP PROCESS:
1. Data discovery:
   - Identify databases, file shares, and storage systems
   - Check for sensitive file types and locations
   - Look for backup files and archives

2. Database access:
   - Connect to identified databases
   - Extract table schemas and data samples
   - Check for sensitive data patterns

3. File system exploration:
   - Search for sensitive files and documents
   - Check user directories and shared folders
   - Look for configuration files with secrets

4. Data classification:
   - Identify PII, financial data, intellectual property
   - Assess data sensitivity and regulatory requirements
   - Document data locations and access controls

5. Data extraction:
   - Safely extract samples of sensitive data
   - Document data volume and types found
   - Note any encryption or protection mechanisms

WHAT TO LOOK FOR:
- Customer PII and personal data
- Financial records and payment information
- Intellectual property and trade secrets
- System credentials and configuration data

COMMON PITFALLS:
- Some data may be encrypted or access-controlled
- Large data volumes may be impractical to extract
- Some data access triggers security alerts
- Data may be distributed across multiple systems"
            ),
            (
                "Cleanup procedures",
                "OBJECTIVE: Remove evidence of compromise and restore systems to operational state.

STEP-BY-STEP PROCESS:
1. Artifact identification:
   - Identify all files, processes, and logs created
   - Check for persistence mechanisms established
   - Document all changes made during testing

2. Log cleanup:
   - Clear authentication logs
   - Remove evidence from security event logs
   - Check for centralized logging systems

3. File and process cleanup:
   - Remove uploaded files and tools
   - Terminate any background processes
   - Delete temporary files and directories

4. Configuration restoration:
   - Restore modified configuration files
   - Reset any changed passwords or permissions
   - Verify system functionality after cleanup

5. Verification:
   - Confirm all artifacts have been removed
   - Test system functionality and security
   - Document cleanup process and verification

WHAT TO LOOK FOR:
- Log entries showing compromise activities
- Unusual files or processes remaining
- Modified system configurations
- Persistence mechanisms still active

COMMON PITFALLS:
- Some logs may be immutable or replicated
- System backups may contain evidence
- Some changes may be difficult to reverse
- Cleanup itself may leave evidence"
            ),
        ]
        .into_iter()
        .map(|(title, description)| Step { id: Uuid::new_v4(), title: title.into(), description: description.into(), tags: vec!["post".into()], status: StepStatus::Todo, completed_at: None, notes: String::new(), description_notes: String::new(), evidence: vec![] })
        .collect();
        let post_phase = Phase { id: Uuid::new_v4(), name: "Post-Exploitation".into(), steps: post_steps, notes: String::new() };

        // Create reporting phase steps
        let rep_steps: Vec<Step> = vec![
            (
                "Evidence consolidation",
                "OBJECTIVE: Gather and organize all evidence collected during the penetration test.

STEP-BY-STEP PROCESS:
1. Evidence inventory:
   - Catalog all screenshots, logs, and captured data
   - Organize evidence by phase and finding
   - Verify evidence authenticity and timestamps

2. Finding correlation:
   - Link related findings across phases
   - Identify root causes and attack chains
   - Remove duplicate or redundant evidence

3. Evidence validation:
   - Verify all findings have supporting evidence
   - Check evidence quality and clarity
   - Ensure evidence tells a complete story

4. Documentation structure:
   - Create evidence folders by finding type
   - Implement consistent naming conventions
   - Prepare evidence for report inclusion

5. Chain of custody:
   - Document evidence collection methods
   - Maintain evidence integrity
   - Prepare evidence for potential legal review

WHAT TO LOOK FOR:
- Clear, unambiguous evidence of vulnerabilities
- Complete attack chains from discovery to exploitation
- High-quality screenshots and logs
- Evidence that supports risk assessments

COMMON PITFALLS:
- Some evidence may be time-sensitive
- Evidence quality varies by collection method
- Some findings may not have visual evidence
- Evidence may need to be sanitized for sharing"
            ),
            (
                "Risk rating",
                "OBJECTIVE: Assign risk scores to identified vulnerabilities and findings.

STEP-BY-STEP PROCESS:
1. Risk methodology selection:
   - Choose appropriate risk scoring system (CVSS, DREAD, etc.)
   - Define risk criteria and thresholds
   - Establish risk rating scale

2. Vulnerability assessment:
   - Score each finding individually
   - Consider exploitability, impact, and detection
   - Factor in business context and environment

3. Risk calculation:
   - Combine likelihood and impact scores
   - Apply environmental modifiers
   - Consider compensating controls

4. Risk prioritization:
   - Rank findings by overall risk level
   - Group similar vulnerabilities
   - Identify critical findings requiring immediate attention

5. Risk communication:
   - Explain risk scores and methodology
   - Provide context for risk ratings
   - Document assumptions and limitations

WHAT TO LOOK FOR:
- Critical vulnerabilities requiring immediate remediation
- High-risk findings with broad impact
- Vulnerabilities with reliable exploits available
- Findings affecting sensitive data or systems

COMMON PITFALLS:
- Risk scores are subjective and context-dependent
- Some vulnerabilities may be mitigated in production
- Risk perception varies by stakeholder
- Quantitative risk models may not capture all factors"
            ),
            (
                "Remediation guidance",
                "OBJECTIVE: Provide actionable recommendations for addressing identified vulnerabilities.

STEP-BY-STEP PROCESS:
1. Vulnerability analysis:
   - Understand root causes of each finding
   - Research appropriate remediation steps
   - Identify vendor patches and updates

2. Remediation prioritization:
   - Order fixes by risk level and ease of implementation
   - Consider dependencies between fixes
   - Balance security with operational impact

3. Detailed remediation steps:
   - Provide specific, actionable instructions
   - Include commands, configuration changes, and code fixes
   - Specify testing procedures for verification

4. Compensating controls:
   - Suggest temporary mitigations for complex fixes
   - Identify monitoring and detection improvements
   - Recommend process improvements

5. Timeline and resource requirements:
   - Estimate time and effort for each remediation
   - Identify required skills and resources
   - Suggest implementation phases

WHAT TO LOOK FOR:
- Specific, actionable remediation steps
- Vendor patches and security updates
- Configuration changes and hardening measures
- Process improvements and training needs

COMMON PITFALLS:
- Some remediations require application changes
- Patches may break functionality
- Some fixes require vendor coordination
- Remediation may require downtime or testing"
            ),
            (
                "Executive summaries",
                "OBJECTIVE: Create high-level summaries for executive and management audiences.

STEP-BY-STEP PROCESS:
1. Audience analysis:
   - Understand executive information needs
   - Focus on business impact over technical details
   - Identify key decision points and concerns

2. Executive summary structure:
   - Overview of assessment scope and objectives
   - High-level findings and risk assessment
   - Critical vulnerabilities requiring attention
   - Strategic recommendations and roadmap

3. Risk communication:
   - Use business terminology over technical jargon
   - Focus on impact rather than technical details
   - Include concrete examples and analogies

4. Strategic recommendations:
   - Provide high-level remediation strategies
   - Include cost-benefit analysis where possible
   - Recommend resource allocation priorities

5. Call to action:
   - Clear next steps with timelines
   - Identify responsible parties
   - Suggest metrics for measuring progress

WHAT TO LOOK FOR:
- Clear risk levels and business impact
- Actionable recommendations with priorities
- Realistic timelines and resource requirements
- Measurable success criteria

COMMON PITFALLS:
- Executives may want more technical detail
- Business context varies by organization
- Risk tolerance differs between stakeholders
- Some recommendations may be politically sensitive"
            ),
        ]
        .into_iter()
        .map(|(title, description)| Step { id: Uuid::new_v4(), title: title.into(), description: description.into(), tags: vec!["report".into()], status: StepStatus::Todo, completed_at: None, notes: String::new(), description_notes: String::new(), evidence: vec![] })
        .collect();
        let report_phase = Phase { id: Uuid::new_v4(), name: "Reporting".into(), steps: rep_steps, notes: String::new() };

        Session {
            id: Uuid::new_v4(),
            name: "New Engagement".to_string(),
            created_at: Utc::now(),
            phases: vec![recon_phase, vuln_phase, exploit_phase, post_phase, report_phase],
            notes_global: String::new(),
        }
    }
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
        Self {
            session: Session::default(),
            selected_phase: 0,
            selected_step: Some(0),
            current_path: None,
        }
    }
}

// UI messages were removed in favor of a direct GTK setup.

// UI wiring is provided by the Relm4 component in `ui.rs`.

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use assert_matches::assert_matches;

    #[test]
    fn test_step_status_variants() {
        // Test that all status variants work
        let todo_step = Step {
            id: Uuid::new_v4(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            tags: vec![],
            status: StepStatus::Todo,
            completed_at: None,
            notes: String::new(),
            description_notes: String::new(),
            evidence: vec![],
        };

        let in_progress_step = Step {
            status: StepStatus::InProgress,
            ..todo_step.clone()
        };

        let done_step = Step {
            status: StepStatus::Done,
            completed_at: Some(Utc::now()),
            ..todo_step.clone()
        };

        let skipped_step = Step {
            status: StepStatus::Skipped,
            ..todo_step.clone()
        };

        assert_matches!(todo_step.status, StepStatus::Todo);
        assert_matches!(in_progress_step.status, StepStatus::InProgress);
        assert_matches!(done_step.status, StepStatus::Done);
        assert_matches!(skipped_step.status, StepStatus::Skipped);
    }

    #[test]
    fn test_evidence_structure() {
        let evidence = Evidence {
            id: Uuid::new_v4(),
            path: "/path/to/file.png".to_string(),
            created_at: Utc::now(),
            kind: "screenshot".to_string(),
            x: 100.0,
            y: 200.0,
        };

        assert!(!evidence.path.is_empty());
        assert!(!evidence.kind.is_empty());
        assert!(evidence.created_at <= Utc::now());
        assert!(evidence.id != Uuid::nil());
    }

    #[test]
    fn test_phase_with_steps() {
        let steps = vec![
            Step {
                id: Uuid::new_v4(),
                title: "Step 1".to_string(),
                description: "Description 1".to_string(),
                tags: vec!["tag1".to_string()],
                status: StepStatus::Todo,
                completed_at: None,
                notes: String::new(),
                description_notes: String::new(),
                evidence: vec![],
            },
            Step {
                id: Uuid::new_v4(),
                title: "Step 2".to_string(),
                description: "Description 2".to_string(),
                tags: vec!["tag2".to_string()],
                status: StepStatus::Done,
                completed_at: Some(Utc::now()),
                notes: "Completed".to_string(),
                description_notes: String::new(),
                evidence: vec![],
            },
        ];

        let phase = Phase {
            id: Uuid::new_v4(),
            name: "Test Phase".to_string(),
            steps,
            notes: "Phase notes".to_string(),
        };

        assert_eq!(phase.steps.len(), 2);
        assert_eq!(phase.name, "Test Phase");
        assert_eq!(phase.notes, "Phase notes");
        assert_matches!(phase.steps[0].status, StepStatus::Todo);
        assert_matches!(phase.steps[1].status, StepStatus::Done);
    }

    #[test]
    fn test_session_with_phases() {
        let phase1 = Phase {
            id: Uuid::new_v4(),
            name: "Phase 1".to_string(),
            steps: vec![],
            notes: String::new(),
        };

        let phase2 = Phase {
            id: Uuid::new_v4(),
            name: "Phase 2".to_string(),
            steps: vec![],
            notes: String::new(),
        };

        let session = Session {
            id: Uuid::new_v4(),
            name: "Test Session".to_string(),
            created_at: Utc::now(),
            phases: vec![phase1, phase2],
            notes_global: "Global notes".to_string(),
        };

        assert_eq!(session.phases.len(), 2);
        assert_eq!(session.name, "Test Session");
        assert_eq!(session.notes_global, "Global notes");
        assert!(session.created_at <= Utc::now());
    }

    #[test]
    fn test_step_tags() {
        let step = Step {
            id: Uuid::new_v4(),
            title: "Tagged Step".to_string(),
            description: "Test".to_string(),
            tags: vec!["recon".to_string(), "passive".to_string(), "dns".to_string()],
            status: StepStatus::Todo,
            completed_at: None,
            notes: String::new(),
            description_notes: String::new(),
            evidence: vec![],
        };

        assert_eq!(step.tags.len(), 3);
        assert!(step.tags.contains(&"recon".to_string()));
        assert!(step.tags.contains(&"passive".to_string()));
        assert!(step.tags.contains(&"dns".to_string()));
    }

    #[test]
    fn test_unique_ids() {
        let mut ids = HashSet::new();

        // Create multiple steps and ensure IDs are unique
        for _ in 0..100 {
            let step = Step {
                id: Uuid::new_v4(),
                title: "Test".to_string(),
                description: "Test".to_string(),
                tags: vec![],
                status: StepStatus::Todo,
                completed_at: None,
                notes: String::new(),
                description_notes: String::new(),
                evidence: vec![],
            };
            assert!(ids.insert(step.id), "Duplicate ID generated: {}", step.id);
        }
    }

    #[test]
    fn test_step_description_notes() {
        let mut step = Step {
            id: Uuid::new_v4(),
            title: "Test Step".to_string(),
            description: "Test description".to_string(),
            tags: vec![],
            status: StepStatus::Todo,
            completed_at: None,
            notes: String::new(),
            description_notes: String::new(),
            evidence: vec![],
        };

        // Test description_notes updates
        step.description_notes = "User notes in description area".to_string();
        assert_eq!(step.description_notes, "User notes in description area");

        step.description_notes = "Updated description notes with more content".to_string();
        assert_eq!(step.description_notes, "Updated description notes with more content");

        // Test clearing description_notes
        step.description_notes.clear();
        assert!(step.description_notes.is_empty());
    }

    #[test]
    fn test_evidence_attachment() {
        let mut step = Step {
            id: Uuid::new_v4(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            tags: vec![],
            status: StepStatus::Todo,
            completed_at: None,
            notes: String::new(),
            description_notes: String::new(),
            evidence: vec![],
        };

        let evidence1 = Evidence {
            id: Uuid::new_v4(),
            path: "/path/to/screenshot1.png".to_string(),
            created_at: Utc::now(),
            kind: "screenshot".to_string(),
            x: 10.0,
            y: 20.0,
        };

        let evidence2 = Evidence {
            id: Uuid::new_v4(),
            path: "/path/to/log.txt".to_string(),
            created_at: Utc::now(),
            kind: "log".to_string(),
            x: 50.0,
            y: 60.0,
        };

        step.evidence.push(evidence1);
        step.evidence.push(evidence2);

        assert_eq!(step.evidence.len(), 2);
        assert_eq!(step.evidence[0].kind, "screenshot");
        assert_eq!(step.evidence[1].kind, "log");
    }
}


