pub const RECONNAISSANCE_STEPS: &[(&str, &str)] = &[
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
   - Parse URLs from crawling results
   - Extract query parameters and fragments

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
- Some assets require specific access patterns"
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
];