pub const RECONNAISSANCE_STEPS: &[(&str, &str)] = &[
    (
        "Subdomain enumeration",
        "OBJECTIVE: Discover all subdomains associated with the target domain to expand the attack surface and identify potential entry points.

ACADEMIC BACKGROUND:
Subdomain enumeration is a critical first step in penetration testing based on the principle that organizations often have inconsistent security postures across different subdomains. According to OWASP Web Security Testing Guide (WSTG-INFO-02), proper reconnaissance can reveal development environments, staging servers, and forgotten assets that may have weaker security controls than production systems.

The MITRE ATT&CK framework categorizes this activity under Reconnaissance (TA0043) > Active Scanning: Scanning IP Blocks (T1595.001) and Gather Victim Network Information: Domain Properties (T1590.001).

STEP-BY-STEP PROCESS:

1. PASSIVE RECONNAISSANCE (No Direct Target Interaction):
   a) Certificate Transparency (CT) Logs:
      - Visit crt.sh: https://crt.sh/?q=%.target.com
      - Query via API: curl -s \"https://crt.sh/?q=%.target.com&output=json\" | jq
      - Alternative: cert.sh, censys.io, certspotter.com
      - Why: SSL/TLS certificates are publicly logged and reveal all domains/subdomains

   b) DNS Aggregators and Search Engines:
      - SecurityTrails: historical DNS data and subdomain discovery
      - VirusTotal: Check passive DNS and URL scanner results
      - DNSDumpster: Free domain research tool with visual maps
      - Shodan.io: Query: ssl.cert.subject.cn:\"target.com\"
      - Google Dorks: site:*.target.com -www

   c) Web Archives:
      - Wayback Machine (archive.org): Historical subdomain snapshots
      - Common Crawl: Petabyte-scale web crawl data
      - Usage: Check old pages for links to now-defunct subdomains

   d) Code Repositories:
      - GitHub search: org:target \"target.com\" OR \"*.target.com\"
      - GitLab, Bitbucket: Search for hardcoded subdomains in config files
      - Look for: API endpoints, staging URLs, internal documentation

2. ACTIVE ENUMERATION (Direct DNS Queries):
   a) Install and Configure Tools:
      - Subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
      - Amass: sudo apt install amass OR https://github.com/owasp-amass/amass
      - Assetfinder: go install github.com/tomnomnom/assetfinder@latest
      - Findomain: https://github.com/Findomain/Findomain

   b) Run Parallel Enumeration:
      ```bash
      # Subfinder (fast, API-integrated)
      subfinder -d target.com -all -recursive -o subfinder.txt -v
      
      # Amass (comprehensive, OWASP recommended)
      amass enum -passive -d target.com -o amass_passive.txt
      amass enum -active -d target.com -o amass_active.txt -brute -w /usr/share/wordlists/dns.txt
      
      # Assetfinder (simple, effective)
      assetfinder --subs-only target.com > assetfinder.txt
      
      # DNS Bruteforce with Gobuster
      gobuster dns -d target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -o gobuster.txt
      ```

   c) Permutation Generation:
      - Install altdns: pip3 install py-altdns
      - Generate variations: altdns -i subfinder.txt -o permutations.txt -w words.txt
      - Test permutations: altdns -i permutations.txt -o resolved_permutations.txt -r -s resolved.txt

3. VALIDATION AND VERIFICATION:
   a) Combine and Deduplicate:
      ```bash
      cat subfinder.txt amass_*.txt assetfinder.txt gobuster.txt | \
      sort -u | \
      grep -v '*' > all_subdomains.txt  # Remove wildcards
      ```

   b) DNS Resolution:
      - dnsx: cat all_subdomains.txt | dnsx -silent -a -resp-only -o resolved_ips.txt
      - Check for: Multiple IPs, CNAME chains, CDN usage
      - Filter out: Dead domains, wildcard responses, honeypots

   c) HTTP/HTTPS Probing:
      - httpx: cat all_subdomains.txt | httpx -silent -status-code -tech-detect -o live_hosts.txt
      - Identify: Technologies, status codes, redirects, title tags
      - Screenshot: gowitness file -f live_hosts.txt (visual reconnaissance)

   d) Verify Ownership:
      - WHOIS lookups: whois subdomain.target.com
      - Check NS records: dig subdomain.target.com NS +short
      - Confirm in-scope: Ensure subdomains belong to target organization

4. DOCUMENTATION AND ANALYSIS:
   - Create spreadsheet with columns: Subdomain | IP | Status Code | Technologies | Notes
   - Categorize by function: API endpoints, admin panels, dev/staging, production
   - Priority ranking: Based on interesting technologies, potential vulnerabilities
   - Timeline: Note when each subdomain was discovered and last verified

WHAT TO LOOK FOR:
- Development/Staging environments (often less secure): dev.*, stage.*, test.*, qa.*
- API endpoints and microservices: api.*, ws.*, graphql.*, rest.*
- Administrative interfaces: admin.*, cpanel.*, webmail.*, login.*
- Third-party integrations and SaaS: jira.*, confluence.*, gitlab.*, jenkins.*
- Cloud storage: s3.*, azure.*, gcp.*, cdn.*, assets.*
- Email infrastructure: mail.*, smtp.*, mx.*, webmail.*
- VPN/Remote access: vpn.*, remote.*, citrix.*, owa.*
- Legacy systems: old.*, legacy.*, archive.*, backup.*
- Geographic variants: us.*, eu.*, asia.*, london.*

COMMON PITFALLS:
- Wildcard DNS Records: Test with random subdomain (asdjklqwer123.target.com) to detect wildcards
- Rate Limiting: Space out requests, use multiple DNS resolvers, respect robots.txt and scope
- Certificate Mismatch: Some subdomains use shared hosting with mismatched SSL certificates
- Geoblocking: Subdomains may only respond from specific countries/IP ranges
- Internal-Only: Some subdomains resolve only from internal networks (VPN required)
- False Positives: CDN edge nodes may show up as subdomains but aren't actual assets
- Scope Creep: Always verify subdomains are owned by target, not third-party partners

DOCUMENTATION REQUIREMENTS:
- List of all discovered subdomains (categorized by type)
- Screenshots of interesting interfaces
- Network diagram showing subdomain relationships
- Technology stack identified per subdomain
- Evidence of any immediate security concerns (default creds page, directory listings, etc.)

TOOLS REFERENCE:
- Subfinder: https://github.com/projectdiscovery/subfinder
- Amass: https://github.com/owasp-amass/amass (OWASP Project)
- crt.sh: Certificate Transparency logs
- DNSDumpster: https://dnsdumpster.com
- SecurityTrails: https://securitytrails.com
- VirusTotal: https://www.virustotal.com
- httpx: https://github.com/projectdiscovery/httpx
- dnsx: https://github.com/projectdiscovery/dnsx

FURTHER READING:
- OWASP WSTG v4.2: Section 4.2 Information Gathering
- PTES Technical Guidelines: Section 3 - Intelligence Gathering
- NIST SP 800-115: Technical Guide to Information Security Testing"
    ),
    (
        "DNS records enumeration",
        "OBJECTIVE: Map the complete DNS infrastructure to understand domain structure, identify misconfigurations, and discover additional attack vectors.

ACADEMIC BACKGROUND:
The Domain Name System (DNS) is a hierarchical distributed naming system that translates human-readable domain names into IP addresses. According to RFC 1035 and subsequent RFCs, DNS uses various record types to store different kinds of information. Security misconfigurations in DNS can expose internal network structure, enable cache poisoning attacks (CVE-2008-1447), or facilitate email spoofing.

This activity aligns with OWASP WSTG-INFO-02 (Fingerprint Web Server) and MITRE ATT&CK T1590.002 (Gather Victim Network Information: DNS).

DNS RECORD TYPES EXPLAINED:
- A Record: Maps hostname to IPv4 address
- AAAA Record: Maps hostname to IPv6 address
- CNAME: Creates an alias from one name to another
- MX: Specifies mail servers and priority
- NS: Delegates a DNS zone to authoritative name servers
- TXT: Holds arbitrary text data (SPF, DKIM, DMARC, verification tokens)
- SOA: Specifies authoritative information about DNS zone
- SRV: Generalized service location record
- PTR: Reverse DNS lookup (IP to hostname)
- CAA: Specifies which certificate authorities can issue certificates

STEP-BY-STEP PROCESS:

1. BASIC DNS RECORD ENUMERATION:
   a) A and AAAA Records (IP Addresses):
      ```bash
      # IPv4 address resolution
      dig target.com A +short
      dig @8.8.8.8 target.com A +noall +answer
      nslookup target.com
      host target.com
      
      # IPv6 address resolution
      dig target.com AAAA +short
      
      # Check all discovered subdomains
      cat subdomains.txt | while read sub; do echo \"$sub: $(dig +short $sub A)\"; done
      ```
      Analysis: Multiple A records indicate load balancing; AAAA presence shows IPv6 support

   b) CNAME Records (Aliasing):
      ```bash
      dig target.com CNAME +short
      
      # Follow CNAME chains
      dig target.com +trace
      ```
      Security note: Long CNAME chains can indicate third-party services or CDN usage

   c) Name Server Records:
      ```bash
      dig target.com NS +short
      dig target.com NS +norecurse
      whois target.com | grep \"Name Server\"
      
      # Check if nameservers are authoritative
      dig @ns1.target.com target.com SOA
      ```
      What to check: Are nameservers from same provider? Mix of providers can indicate complexity

   d) Mail Exchange Records:
      ```bash
      dig target.com MX +short
      
      # Check each mail server
      dig mx1.target.com A +short
      nmap -p 25,587,465 mx1.target.com
      ```
      Security implications: Identifies email infrastructure for phishing analysis

2. ADVANCED DNS RECORD TYPES:
   a) TXT Records (Critical for Email Security):
      ```bash
      dig target.com TXT +short
      
      # Look specifically for email authentication
      dig target.com TXT | grep -i \"spf\\|dkim\\|dmarc\"
      
      # Check DMARC record
      dig _dmarc.target.com TXT +short
      
      # Common DKIM selectors
      for selector in default google k1 dkim mail; do
          dig $selector._domainkey.target.com TXT +short
      done
      ```
      
      SPF Record Analysis:
      - v=spf1: SPF version identifier
      - ip4:192.0.2.0/24: Authorized IP ranges
      - include:_spf.google.com: Include third-party SPF records
      - -all: Fail (strict), ~all: Soft fail, +all: Pass (insecure!)
      
      DMARC Policy Checks:
      - p=none: Monitoring only (weakest)
      - p=quarantine: Move suspicious emails to spam
      - p=reject: Block spoofed emails (strongest)
      - pct=100: Apply policy to 100% of messages
      
      Security Findings:
      - SPF with +all or missing -all: Allows email spoofing
      - No DMARC record: No protection against domain spoofing
      - DMARC p=none: Monitoring only, not enforcing
      - Overly permissive SPF includes

   b) SRV Records (Service Discovery):
      ```bash
      # Common services
      dig _sip._tcp.target.com SRV +short
      dig _ldap._tcp.target.com SRV +short
      dig _jabber._tcp.target.com SRV +short
      dig _autodiscover._tcp.target.com SRV +short  # Microsoft Exchange
      
      # Enumerate all SRV records (requires wordlist)
      for service in sip ldap xmpp jabber h323 kerberos ldaps; do
          for proto in tcp udp; do
              dig _$service._$proto.target.com SRV +short
          done
      done
      ```
      What this reveals: Internal services, VoIP systems, LDAP directories

   c) CAA Records (Certificate Authority Authorization):
      ```bash
      dig target.com CAA +short
      ```
      Example: 0 issue \"letsencrypt.org\"
      Security: Restricts which CAs can issue certificates (prevents fraudulent certs)

   d) SOA Records (Zone Information):
      ```bash
      dig target.com SOA +short
      dig target.com SOA +norecurse  # Query authoritative server directly
      ```
      Information gained:
      - Primary nameserver
      - Admin email (with @ replaced by .)
      - Serial number (zone version)
      - Refresh, retry, expiry intervals
      - Minimum TTL

3. ZONE TRANSFER TESTING (AXFR):
   a) Identify Name Servers:
      ```bash
      dig target.com NS +short > nameservers.txt
      ```
   
   b) Attempt Zone Transfer on Each:
      ```bash
      # Test each nameserver
      cat nameservers.txt | while read ns; do
          echo \"[*] Testing $ns\"
          dig @$ns target.com AXFR
      done
      
      # Using host command
      host -l target.com ns1.target.com
      
      # Using nmap NSE script
      nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=target.com -p 53 ns1.target.com
      ```
   
   c) Analysis of Results:
      - Successful AXFR: CRITICAL vulnerability, immediately report
      - Provides complete DNS database: All subdomains, IPs, internal hostnames
      - Historical issue: Many DNS servers patched, but legacy systems may still be vulnerable
      - Modern protection: DNSSEC, TSIG authentication, ACLs

4. REVERSE DNS AND PTR RECORDS:
   ```bash
   # Get IP addresses first
   dig target.com A +short > ips.txt
   
   # Reverse lookup
   cat ips.txt | while read ip; do
       echo \"$ip: $(dig -x $ip +short)\"
   done
   
   # Check entire subnet (if in scope)
   for i in {1..254}; do
       dig -x 192.0.2.$i +short
   done | grep -v \"^$\" >> reverse_dns.txt
   ```
   Use cases: Discover additional hostnames, verify IP ownership, find neighboring assets

5. DNS SECURITY EXTENSIONS (DNSSEC):
   ```bash
   # Check if DNSSEC is enabled
   dig target.com +dnssec
   
   # Validate DNSSEC chain
   dig target.com +dnssec +multi
   delv @8.8.8.8 target.com
   ```
   Security assessment:
   - DNSSEC enabled: Better protection against cache poisoning
   - No DNSSEC: Vulnerable to man-in-the-middle DNS attacks
   - Misconfigured DNSSEC: Can cause legitimate resolution failures

6. DNS ANALYTICS AND PASSIVE DNS:
   a) Historical DNS Data:
      - SecurityTrails API: Historical IP addresses and nameserver changes
      - VirusTotal: Passive DNS resolution data
      - PassiveTotal (RiskIQ): Comprehensive historical DNS data
   
   b) DNS Monitoring Services:
      ```bash
      # Query SecurityTrails
      curl -H \"APIKEY: your_key\" https://api.securitytrails.com/v1/history/target.com/dns/a
      
      # VirusTotal API
      curl https://www.virustotal.com/api/v3/domains/target.com
      ```
      
   c) Analysis:
      - IP address changes: Recent migrations, cloud providers
      - Nameserver changes: Infrastructure updates, provider changes
      - Subdomain additions: Business expansion, new services

WHAT TO LOOK FOR:
- SPF Records: +all or ~all (weak), missing -all (spoofable)
- DMARC Missing: No protection against email spoofing
- DMARC p=none: Monitoring mode only, not enforcing
- Zone Transfer Enabled: Critical vulnerability exposing all DNS records
- Internal IP Addresses: RFC1918 addresses (10.x, 172.16.x, 192.168.x) in public DNS
- Wildcard Records: *.target.com pointing to catch-all server
- Deprecated Services: FTP, Telnet, old email ports in SRV records
- Inconsistent TTL Values: Very low TTL may indicate frequent changes or instability
- Third-Party Dependencies: Many includes in SPF, external MX records
- Subdomain Takeover Risks: CNAME pointing to non-existent services (GitHub Pages, AWS S3, Heroku)
- Missing CAA Records: No restriction on certificate issuance
- IPv6 Gaps: A records exist but no AAAA records (incomplete IPv6 deployment)

COMMON PITFALLS:
- DNS Caching: Results may be cached; use +trace or query authoritative servers directly
- Geographic Variations: Some DNS responses vary by geographic location (GeoDNS)
- Time-Based Changes: DNS records may change based on time of day or load
- Split-Horizon DNS: Different responses for internal vs external queries
- DNS Firewalls: May block or filter certain query types
- Rate Limiting: Excessive queries may trigger rate limits or blacklisting
- Anycast Networks: Same IP may be different physical servers in different locations
- TTL Expiration: Short TTL means records change frequently, recheck periodically

DOCUMENTATION REQUIREMENTS:
- Complete DNS record inventory (all types, all subdomains)
- Network diagram showing DNS hierarchy and dependencies
- SPF/DMARC/DKIM configuration analysis
- List of third-party services identified (email, CDN, cloud providers)
- Evidence of any vulnerabilities (zone transfer, spoofing risks, etc.)
- Historical changes and trends
- Recommendations for DNS security improvements

SECURITY IMPLICATIONS:
- Zone Transfer Enabled: Exposes entire internal network structure
- Weak SPF/DMARC: Enables email spoofing and phishing campaigns
- Internal IPs Leaked: Provides network topology information
- Subdomain Takeover: CNAME pointing to unclaimed resources
- DNS Cache Poisoning: Lack of DNSSEC enables MITM attacks
- Information Disclosure: TXT records may contain sensitive info, API keys, or credentials

TOOLS REFERENCE:
- dig: Standard DNS query tool (part of BIND utilities)
- nslookup: Legacy DNS query tool (Windows/Linux)
- host: Simple DNS lookup utility
- dnsenum: Automated DNS enumeration script
- fierce: DNS reconnaissance tool
- dnsrecon: DNS enumeration and security assessment
- amass intel: DNS intelligence gathering (OWASP)

FURTHER READING:
- RFC 1035: Domain Names - Implementation and Specification
- OWASP WSTG v4.2: WSTG-INFO-02 Fingerprint Web Server
- SANS: DNS Security Best Practices
- NIST SP 800-81-2: Secure Domain Name System (DNS) Deployment Guide
- OWASP Email Security Cheat Sheet"
    ),
    (
        "Port scanning",
        "OBJECTIVE: Identify all open ports and services running on discovered hosts to map the attack surface and potential entry points.

ACADEMIC BACKGROUND:
Port scanning is the process of sending packets to specific TCP or UDP ports on a target system and analyzing responses to determine which ports are open, closed, or filtered. This technique, formalized in RFC 793 (TCP) and RFC 768 (UDP), is fundamental to network security assessment.

According to the PTES (Penetration Testing Execution Standard), port scanning falls under the \"Vulnerability Analysis\" phase and helps identify services that may have known vulnerabilities. The MITRE ATT&CK framework categorizes this as T1046 (Network Service Scanning) under Discovery tactics.

TCP/IP PORT FUNDAMENTALS:
- Total ports available: 65,535 (0-65535) per protocol (TCP/UDP)
- Well-known ports: 0-1023 (require root/admin privileges)
- Registered ports: 1024-49151 (registered with IANA)
- Dynamic/Private ports: 49152-65535 (ephemeral, temporary)
- Common protocols: TCP (connection-oriented), UDP (connectionless)

TCP HANDSHAKE REVIEW:
1. SYN: Client initiates connection
2. SYN-ACK: Server acknowledges (port open)
3. ACK: Client completes handshake
   OR
2. RST: Server resets (port closed)
   OR
2. No response: Port filtered by firewall

SCANNING TECHNIQUES EXPLAINED:
- SYN Scan (Half-open): Sends SYN, doesn't complete handshake (stealthy)
- Connect Scan: Completes full TCP handshake (detected in logs)
- FIN/NULL/XMAS Scans: Use TCP flags to evade simple firewalls
- UDP Scan: Sends UDP packets, infers open from lack of ICMP unreachable
- ACK Scan: Determines firewall rulesets, doesn't identify open ports
- Window Scan: Analyzes TCP window field to identify open ports
- Idle/Zombie Scan: Uses third-party host to mask scanning source

STEP-BY-STEP PROCESS:

1. INITIAL HOST DISCOVERY (Determine Live Hosts):
   ```bash
   # Ping sweep for live hosts
   nmap -sn 192.168.1.0/24 -oA host_discovery
   
   # TCP SYN ping (when ICMP blocked)
   nmap -PS22,80,443 192.168.1.0/24 -oA syn_ping
   
   # Using masscan for large networks
   masscan 192.168.1.0/24 -p0-65535 --rate 10000
   
   # Fast host discovery with rustscan
   rustscan -a 192.168.1.0/24 --greppable -o live_hosts.txt
   ```
   
   Analysis: Identify which hosts respond to different probe types (some may block ICMP)

2. FAST INITIAL PORT SCAN (Top Ports):
   ```bash
   # Scan top 1000 most common ports (Nmap default)
   nmap -T4 --top-ports 1000 target.com -oA quick_scan
   
   # Top 100 ports for even faster reconnaissance
   nmap --top-ports 100 -T5 target.com
   
   # Using Rustscan (Rust-based, extremely fast)
   rustscan -a target.com -g -o rustscan_results.txt
   ```
   
   Rationale: Quickly identify primary services before comprehensive scan

3. COMPREHENSIVE TCP PORT SCANNING:
   a) Full Port Range SYN Scan:
      ```bash
      # All 65,535 TCP ports (requires root/sudo)
      sudo nmap -sS -p- -T4 -v target.com -oA full_tcp_syn
      
      # With service version detection
      sudo nmap -sS -sV -p- -T4 target.com -oA full_tcp_services
      
      # Aggressive scan (OS detection, version, scripts, traceroute)
      sudo nmap -A -p- -T4 target.com -oA aggressive_scan
      
      # Performance tuning for faster scans
      sudo nmap -sS -p- -T4 --min-rate 1000 --max-retries 1 target.com
      ```
      
      Flags explained:
      - -sS: TCP SYN scan (half-open, stealthy, requires root)
      - -sV: Version detection (identifies service and version)
      - -O: OS fingerprinting (identifies operating system)
      - -A: Aggressive scan (combines -sV, -O, scripts, traceroute)
      - -p-: Scan all 65,535 ports
      - -T4: Timing template (0-5, where 5 is fastest)
      - --min-rate: Minimum packets per second
      - --max-retries: Reduce retries for faster scans
   
   b) Alternative High-Speed Scanners:
      ```bash
      # Masscan (fastest, but less accurate)
      sudo masscan -p1-65535 target.com --rate=10000 -oL masscan_results.txt
      
      # Rate limiting (be cautious, high rates can crash systems)
      sudo masscan -p1-65535 target.com --rate=1000 --wait=5
      
      # Rustscan piped to Nmap for service detection
      rustscan -a target.com -- -sV -sC -oA rustscan_nmap
      ```
      
      Performance comparison:
      - Nmap -T4: ~30 minutes for all ports
      - Masscan --rate=10000: ~7 seconds for all ports
      - Rustscan: ~few seconds, then hands off to Nmap for accuracy

4. UDP PORT SCANNING (Often Overlooked):
   ```bash
   # Top UDP ports
   sudo nmap -sU --top-ports 100 target.com -oA udp_top100
   
   # Common UDP services
   sudo nmap -sU -p 53,67,68,69,123,135,137,138,139,161,162,445,514,631,1900 target.com
   
   # UDP with version detection (very slow)
   sudo nmap -sUV -p 53,161,162,500 target.com
   
   # Combined TCP/UDP scan
   sudo nmap -sS -sU -p T:80,443,U:53,161 target.com
   ```
   
   UDP Scanning Challenges:
   - No handshake: Hard to distinguish open from filtered
   - ICMP rate limiting: Firewalls limit \"port unreachable\" responses
   - Extremely slow: Can take hours for full scan
   - False negatives: Services may not respond to empty UDP packets
   
   Common UDP Services:
   - 53: DNS (Domain Name System)
   - 67/68: DHCP (Dynamic Host Configuration)
   - 69: TFTP (Trivial File Transfer)
   - 123: NTP (Network Time Protocol)
   - 161/162: SNMP (Simple Network Management)
   - 500: IKE (IPsec VPN)
   - 514: Syslog
   - 1900: SSDP (UPnP)

5. OPERATING SYSTEM FINGERPRINTING:
   ```bash
   # Basic OS detection
   sudo nmap -O target.com
   
   # Aggressive OS detection
   sudo nmap -O --osscan-guess target.com
   
   # OS detection with version scanning
   sudo nmap -sV -O -p- target.com -oA os_fingerprint
   ```
   
   Analysis techniques:
   - TCP/IP stack fingerprinting
   - TTL (Time To Live) values
   - Window size analysis
   - TCP options ordering
   - ICMP responses
   
   Common OS TTL values:
   - Linux/Unix: 64
   - Windows: 128
   - Network devices: 255

6. SERVICE VERSION DETECTION:
   ```bash
   # Standard version detection
   nmap -sV target.com
   
   # Intensive version detection (all probes)
   nmap -sV --version-intensity 9 target.com
   
   # Fast version detection (fewer probes)
   nmap -sV --version-intensity 0 target.com
   
   # Version detection with NSE scripts
   nmap -sV -sC target.com
   ```
   
   Version detection methods:
   - Banner grabbing: Reading service banners
   - Probe matching: Sending specific probes
   - NULL probe: Empty packets to trigger response
   - Service signatures: Matching against nmap-service-probes database

7. FIREWALL/IDS EVASION TECHNIQUES:
   ```bash
   # Fragmented packets
   nmap -f target.com
   
   # Decoy scanning (mask your IP among decoys)
   nmap -D RND:10 target.com
   
   # Spoof source IP (requires raw packet crafting)
   nmap -S 192.168.1.5 target.com
   
   # Random data length
   nmap --data-length 25 target.com
   
   # Slow scan to avoid detection
   nmap -T0 target.com  # Paranoid (very slow)
   nmap -T1 target.com  # Sneaky
   
   # Randomize target order
   nmap --randomize-hosts target1.com target2.com
   
   # Zombie/Idle scan (requires zombie host)
   nmap -sI zombie_host target.com
   ```
   
   Caution: Evasion techniques may be illegal without authorization

8. NMAP SCRIPTING ENGINE (NSE):
   ```bash
   # Run default scripts
   nmap -sC target.com
   
   # Run specific script categories
   nmap --script vuln target.com        # Vulnerability detection
   nmap --script exploit target.com     # Exploitation scripts
   nmap --script discovery target.com   # Discovery scripts
   nmap --script auth target.com        # Authentication scripts
   
   # Run specific scripts
   nmap --script ssl-enum-ciphers -p 443 target.com
   nmap --script http-enum -p 80,443 target.com
   nmap --script smb-vuln* target.com
   
   # Update script database
   nmap --script-updatedb
   ```
   
   Popular NSE Scripts:
   - ssl-heartbleed: Checks for Heartbleed vulnerability
   - http-sql-injection: Tests for SQL injection
   - smb-vuln-ms17-010: EternalBlue vulnerability
   - ftp-anon: Tests for anonymous FTP access
   - ssh-brute: SSH brute force
   - dns-zone-transfer: Tests for zone transfer

9. OUTPUT FORMATS AND ANALYSIS:
   ```bash
   # All formats simultaneously
   nmap target.com -oA scan_results
   # Creates: scan_results.nmap, scan_results.xml, scan_results.gnmap
   
   # XML format (for parsing/importing)
   nmap target.com -oX results.xml
   
   # Greppable format
   nmap target.com -oG results.gnmap
   
   # Normal output to file
   nmap target.com -oN results.txt
   
   # Parse XML results
   xsltproc scan_results.xml -o scan_results.html
   
   # Import to database
   nmap target.com -oX - | ./parse_nmap.py
   ```

10. SCAN RESULT ANALYSIS:
    ```bash
    # Extract open ports
    grep \"open\" scan_results.nmap
    
    # Count services
    grep -c \"open\" scan_results.nmap
    
    # Find specific services
    grep -i \"http\" scan_results.nmap
    
    # Parse with grep
    awk '/Nmap scan report/{getline; print}' scan_results.nmap
    ```

WHAT TO LOOK FOR:
- **Common Services**: HTTP/HTTPS (80/443), SSH (22), RDP (3389), SMB (445), FTP (21)
- **Non-Standard Ports**: Services running on unusual ports (SSH on 2222, HTTP on 8080)
- **Legacy/Insecure Protocols**: Telnet (23), FTP (21), SNMP v1/v2 (161), TFTP (69)
- **Database Ports**: MySQL (3306), PostgreSQL (5432), MSSQL (1433), MongoDB (27017), Redis (6379)
- **Admin Interfaces**: Webmin (10000), cPanel (2082/2083), phpMyAdmin (custom)
- **Development Services**: Jenkins (8080), GitLab (custom), Docker API (2375/2376)
- **Remote Access**: VNC (5900), RDP (3389), TeamViewer (5938)
- **Unusual Port Combinations**: May indicate backdoors or custom services
- **Filtered Ports**: Indicate firewall rules, reveals security posture
- **Version Numbers**: Outdated versions with known vulnerabilities
- **Banner Information**: Reveals OS, service versions, sometimes internal hostnames

SECURITY IMPLICATIONS:
- **Open Telnet/FTP**: Unencrypted credentials transmitted in plaintext
- **SMBv1 Enabled**: Vulnerable to EternalBlue (MS17-010), WannaCry, NotPetya
- **Open SNMP**: Can leak detailed system information with default \"public\" community string
- **Unnecessary Services**: Each service increases attack surface
- **Non-Standard Ports**: May indicate backdoor or attacker persistence
- **Database Direct Access**: Databases shouldn't be exposed to internet
- **Version Disclosure**: Helps attackers identify specific exploits

COMMON PITFALLS:
- **Firewall False Negatives**: IDS/IPS may drop scan packets, making ports appear closed
- **Rate Limiting**: Aggressive scanning can crash systems or trigger alerts
- **Geographic Restrictions**: Some services only respond from specific IP ranges
- **Load Balancers**: May show different ports open on different requests
- **UDP Reliability**: UDP scans are unreliable; closed ports may not send ICMP unreachable
- **Timing Issues**: Fast scans (-T5) may miss responses; slow scans (-T0/-T1) take hours
- **Permission Denied**: SYN scans require root/admin privileges
- **False Positives**: Some firewalls respond as if ports are open (honeypot)
- **Legal Issues**: Unauthorized scanning is illegal in many jurisdictions
- **Service Disruption**: Aggressive scans can cause denial of service

DOCUMENTATION REQUIREMENTS:
- Complete port inventory (all open, closed, filtered ports)
- Service version matrix (port → service → version)
- Operating system fingerprint results
- Evidence screenshots of scan outputs
- Network diagram showing scanned hosts and open services
- Timeline of when scans were performed
- List of unexpected or unusual findings
- Recommendations for port closure and service hardening

PERFORMANCE OPTIMIZATION:
- **Parallel Scanning**: Scan multiple hosts simultaneously
- **Top Ports First**: Start with --top-ports 1000, then expand
- **Rate Tuning**: Adjust --min-rate and --max-rate based on network capacity
- **Timing Templates**: Use -T4 for most scenarios (balance of speed/accuracy)
- **Skip Discovery**: Use -Pn if you know hosts are up (skips ping)
- **Batch Processing**: Scan subnets in chunks during off-hours

LEGAL AND ETHICAL CONSIDERATIONS:
- **Authorization Required**: Always obtain written permission before scanning
- **Scope Compliance**: Only scan IP ranges explicitly authorized
- **Avoid Disruption**: Use conservative timing to prevent service outages
- **Data Protection**: Scan results may contain sensitive information
- **Third-Party Systems**: Don't scan cloud services or third-party infrastructure
- **Laws Vary**: Computer Fraud and Abuse Act (US), Computer Misuse Act (UK)

TOOLS REFERENCE:
- Nmap: https://nmap.org/ (The standard, most comprehensive)
- Masscan: https://github.com/robertdavidgraham/masscan (Fastest)
- Rustscan: https://github.com/RustScan/RustScan (Modern, Rust-based)
- Unicornscan: http://www.unicornscan.org/ (Asynchronous, fast)
- ZMap: https://zmap.io/ (Internet-wide scanning)
- Angry IP Scanner: https://angryip.org/ (GUI-based, cross-platform)

FURTHER READING:
- Nmap Network Scanning by Gordon \"Fyodor\" Lyon (official book)
- PTES Technical Guidelines: Section 3.4 - Vulnerability Analysis
- OWASP WSTG-INFO-02: Fingerprint Web Server
- NIST SP 800-115: Technical Guide to Information Security Testing
- RFC 793: Transmission Control Protocol (TCP)
- RFC 768: User Datagram Protocol (UDP)
- SANS: Network Penetration Testing Best Practices"
    ),
    (
        "Service enumeration",
        "OBJECTIVE: Extract detailed information about services running on open ports to identify versions, configurations, and potential vulnerabilities for exploitation planning.

ACADEMIC BACKGROUND:
Service enumeration, also known as service fingerprinting, is the process of interacting with network services to gather intelligence about software versions, configurations, supported authentication methods, and underlying operating systems. This phase bridges port scanning and vulnerability assessment.

According to OWASP WSTG-INFO-02 (Fingerprint Web Server and Services), proper enumeration provides the foundation for identifying known vulnerabilities (CVEs) associated with specific service versions. The MITRE ATT&CK framework categorizes detailed service enumeration as T1046 (Network Service Scanning) and T1592 (Gather Victim Host Information).

The NIST SP 800-115 Technical Guide emphasizes that service enumeration should be exhaustive but non-disruptive, gathering maximum information while avoiding service crashes or authentication lockouts.

ENUMERATION METHODOLOGY:
1. **Banner Grabbing**: Capture service identification strings
2. **Protocol-Specific Queries**: Use protocol commands to elicit detailed responses
3. **NSE Script Enumeration**: Leverage Nmap scripts for deep inspection
4. **Vulnerability Cross-Reference**: Map versions to known CVEs
5. **Configuration Analysis**: Identify misconfigurations and weak settings

STEP-BY-STEP PROCESS:

1. BASIC BANNER GRABBING (All Services):
   ```bash
   # Netcat banner grab (TCP services)
   nc -v target.com 21        # FTP banner
   nc -v target.com 22        # SSH banner
   nc -v target.com 25        # SMTP banner
   nc -v target.com 80        # HTTP banner
   nc -v target.com 110       # POP3 banner
   nc -v target.com 143       # IMAP banner
   
   # Nmap banner grabbing
   nmap -sV --script banner target.com
   
   # Automated banner collection
   nmap -p 21,22,23,25,80,110,143,443,3306,3389,5432,8080 -sV --script banner target.com -oA banners
   
   # Quick banner grab with timeout
   timeout 5 bash -c 'echo \"\" | nc target.com 80'
   ```
   
   Analysis: Banner strings often reveal exact service versions (e.g., \"SSH-2.0-OpenSSH_7.4\")

2. HTTP/HTTPS WEB SERVICE ENUMERATION:
   a) HTTP Headers Analysis:
      ```bash
      # Basic header inspection
      curl -I https://target.com
      curl -s -I https://target.com | grep -i server
      
      # Verbose header analysis
      curl -v https://target.com 2>&1 | grep -i '^< '
      
      # Check all HTTP methods
      curl -X OPTIONS https://target.com -i
      
      # Examine security headers
      curl -I https://target.com | grep -iE '(X-Frame|X-XSS|Content-Security|Strict-Transport)'
      
      # Using httpx for header inspection
      echo \"target.com\" | httpx -silent -status-code -tech-detect -title -server
      ```
   
   b) SSL/TLS Certificate Analysis:
      ```bash
      # View certificate details
      openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -text -noout
      
      # Extract subject alternative names (SANs)
      openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -noout -text | grep \"DNS:\"
      
      # Check supported TLS versions
      nmap --script ssl-enum-ciphers -p 443 target.com
      
      # Detect SSL/TLS vulnerabilities
      nmap --script ssl-* -p 443 target.com
      
      # SSLScan comprehensive analysis
      sslscan target.com
      
      # TestSSL.sh detailed audit
      testssl.sh https://target.com
      ```
      
      Certificate intelligence:
      - Organization details
      - Internal hostnames in SANs
      - Certificate issuer and chain
      - Validity period
      - Weak ciphers or protocols
   
   c) Web Technology Fingerprinting:
      ```bash
      # WhatWeb identification
      whatweb -a 3 https://target.com
      
      # Wappalyzer CLI
      wappalyzer https://target.com
      
      # Using httpx with tech detection
      echo \"target.com\" | httpx -tech-detect -status-code
      
      # Nikto web scanner (includes tech detection)
      nikto -h https://target.com -o nikto_results.txt
      
      # Retire.js for JavaScript library vulnerabilities
      retire --jspath https://target.com
      ```

3. SSH SERVICE ENUMERATION (Port 22):
   ```bash
   # SSH version banner
   nc target.com 22
   
   # Detailed SSH enumeration
   nmap -p 22 --script ssh-* target.com
   
   # Check SSH key algorithms and ciphers
   nmap -p 22 --script ssh2-enum-algos target.com
   
   # SSH audit for weak configurations
   ssh-audit target.com
   
   # Detect SSH authentication methods
   nmap -p 22 --script ssh-auth-methods target.com
   
   # Try SSH connection to see supported methods
   ssh -v user@target.com
   ```
   
   Analysis points:
   - OpenSSH version (check against CVE database)
   - Supported key exchange algorithms (weak ones: diffie-hellman-group1-sha1)
   - Cipher suites (avoid: arcfour, 3des-cbc)
   - Authentication methods (password, publickey, keyboard-interactive)
   - Host key types (RSA, ECDSA, ED25519)

4. FTP SERVICE ENUMERATION (Port 21):
   ```bash
   # Anonymous FTP access test
   ftp target.com
   # Try username: anonymous, password: anonymous@example.com
   
   # Nmap FTP scripts
   nmap -p 21 --script ftp-* target.com
   
   # Check for anonymous access
   nmap -p 21 --script ftp-anon target.com
   
   # FTP bounce attack test
   nmap -p 21 --script ftp-bounce target.com
   
   # Enumerate FTP server capabilities
   echo \"HELP\" | nc target.com 21
   echo \"FEAT\" | nc target.com 21
   ```
   
   Security checks:
   - Anonymous login enabled? (major finding)
   - Writable directories (potential malware upload)
   - FTP version (ProFTPD 1.3.5 has known RCE)
   - Cleartext transmission (recommend SFTP/FTPS)

5. SMB/CIFS ENUMERATION (Ports 139, 445):
   ```bash
   # Enumerate SMB shares
   smbclient -L //target.com -N
   
   # Comprehensive SMB enumeration
   enum4linux -a target.com
   
   # Modern enum4linux-ng
   enum4linux-ng -A target.com -oA enum4linux_results
   
   # Nmap SMB scripts
   nmap -p 139,445 --script smb-* target.com
   
   # Check for SMB vulnerabilities
   nmap -p 445 --script smb-vuln-* target.com
   
   # SMB version detection
   nmap -p 445 --script smb-protocols target.com
   
   # CrackMapExec SMB enumeration
   crackmapexec smb target.com --shares
   crackmapexec smb target.com --users
   crackmapexec smb target.com --groups
   
   # NetBIOS enumeration
   nbtscan target.com
   nmblookup -A target.com
   ```
   
   Critical findings:
   - SMBv1 enabled (EternalBlue MS17-010 vulnerability)
   - Null session enumeration (no authentication required)
   - Readable/writable shares
   - User/group enumeration
   - Domain controller identification
   - Guest account enabled

6. SMTP ENUMERATION (Port 25, 587, 465):
   ```bash
   # SMTP banner grab
   nc target.com 25
   
   # SMTP commands
   telnet target.com 25
   HELO example.com
   VRFY root           # Verify user exists
   EXPN admin          # Expand mailing list
   MAIL FROM:<test@example.com>
   RCPT TO:<user@target.com>
   
   # Nmap SMTP scripts
   nmap -p 25 --script smtp-* target.com
   
   # User enumeration
   smtp-user-enum -M VRFY -U /usr/share/wordlists/users.txt -t target.com
   
   # Check for open relay
   nmap -p 25 --script smtp-open-relay target.com
   
   # SMTP commands enumeration
   nmap -p 25 --script smtp-commands target.com
   ```
   
   Analysis:
   - VRFY/EXPN enabled? (user enumeration vulnerability)
   - Open relay (can send spam)
   - SMTP version and vulnerabilities
   - Supported authentication mechanisms
   - StartTLS available?

7. SNMP ENUMERATION (Ports 161, 162):
   ```bash
   # SNMP community string brute force
   onesixtyone -c /usr/share/wordlists/snmp-strings.txt target.com
   
   # SNMP walk (requires community string)
   snmpwalk -v2c -c public target.com
   
   # System information
   snmpwalk -v2c -c public target.com system
   
   # Network interfaces
   snmpwalk -v2c -c public target.com interfaces
   
   # Running processes
   snmpwalk -v2c -c public target.com hrSWRunName
   
   # Installed software
   snmpwalk -v2c -c public target.com hrSWInstalledName
   
   # Nmap SNMP scripts
   nmap -sU -p 161 --script snmp-* target.com
   
   # SNMPv3 enumeration (requires credentials)
   snmpwalk -v3 -l authPriv -u snmpuser -a SHA -A authpass -x AES -X privpass target.com
   ```
   
   SNMP OIDs of interest:
   - 1.3.6.1.2.1.1.1.0 (System description)
   - 1.3.6.1.2.1.1.5.0 (Hostname)
   - 1.3.6.1.2.1.25.4.2.1.2 (Running processes)
   - 1.3.6.1.2.1.25.6.3.1.2 (Installed software)
   - 1.3.6.1.2.1.2.2.1.2 (Network interfaces)

8. DATABASE SERVICE ENUMERATION:
   a) MySQL/MariaDB (Port 3306):
      ```bash
      # MySQL version detection
      nmap -p 3306 --script mysql-info target.com
      
      # Enumerate MySQL users
      nmap -p 3306 --script mysql-users --script-args mysqluser=root,mysqlpass='' target.com
      
      # MySQL vulnerabilities
      nmap -p 3306 --script mysql-vuln-* target.com
      
      # MySQL empty password check
      nmap -p 3306 --script mysql-empty-password target.com
      
      # Direct connection attempt
      mysql -h target.com -u root -p
      ```
   
   b) PostgreSQL (Port 5432):
      ```bash
      # PostgreSQL version
      nmap -p 5432 --script pgsql-brute target.com
      
      # Direct connection
      psql -h target.com -U postgres
      ```
   
   c) MSSQL (Port 1433):
      ```bash
      # MSSQL info gathering
      nmap -p 1433 --script ms-sql-info target.com
      
      # MSSQL empty password
      nmap -p 1433 --script ms-sql-empty-password target.com
      
      # MSSQL command execution (if accessible)
      nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password='' target.com
      ```
   
   d) MongoDB (Port 27017):
      ```bash
      # MongoDB enumeration
      nmap -p 27017 --script mongodb-* target.com
      
      # Check for no authentication
      mongo target.com:27017
      ```
   
   e) Redis (Port 6379):
      ```bash
      # Redis banner grab
      nc target.com 6379
      INFO
      
      # Redis enumeration
      nmap -p 6379 --script redis-* target.com
      
      # Direct connection
      redis-cli -h target.com
      INFO
      CONFIG GET *
      ```

9. RDP ENUMERATION (Port 3389):
   ```bash
   # RDP certificate information
   nmap -p 3389 --script rdp-ntlm-info target.com
   
   # RDP encryption check
   nmap -p 3389 --script rdp-enum-encryption target.com
   
   # RDP BlueKeep vulnerability check
   nmap -p 3389 --script rdp-vuln-ms12-020 target.com
   
   # RDP connection with rdesktop
   rdesktop -u username target.com
   
   # Using xfreerdp for connection attempt
   xfreerdp /v:target.com /u:username /p:password
   ```

10. LDAP ENUMERATION (Ports 389, 636, 3268):
    ```bash
    # Anonymous LDAP bind attempt
    ldapsearch -x -H ldap://target.com -b \"\" -s base
    
    # Enumerate naming contexts
    ldapsearch -x -H ldap://target.com -s base namingContexts
    
    # Full LDAP dump (if anonymous allowed)
    ldapsearch -x -H ldap://target.com -b \"dc=example,dc=com\"
    
    # Nmap LDAP scripts
    nmap -p 389 --script ldap-* target.com
    
    # LDAP brute force
    nmap -p 389 --script ldap-brute target.com
    ```

11. DNS SERVICE ENUMERATION (Port 53):
    ```bash
    # DNS version query
    dig @target.com version.bind CHAOS TXT
    
    # DNS service info
    nmap -p 53 --script dns-nsid target.com
    
    # Zone transfer attempt (from DNS enumeration phase)
    dig @target.com target.com AXFR
    
    # DNS recursion test
    nmap -p 53 --script dns-recursion target.com
    ```

12. VPN SERVICE ENUMERATION:
    a) IKE/IPsec (Port 500 UDP):
       ```bash
       # IKE scan
       ike-scan target.com
       
       # Nmap IKE scripts
       nmap -sU -p 500 --script ike-version target.com
       ```
    
    b) OpenVPN (Port 1194):
       ```bash
       # OpenVPN service detection
       nmap -p 1194 --script openvpn-info target.com
       ```

WHAT TO LOOK FOR:
- **Version Numbers**: Exact versions for CVE lookup (e.g., Apache 2.4.49 = CVE-2021-41773 RCE)
- **Default Credentials**: admin/admin, root/toor, sa/sa, postgres/postgres
- **Anonymous Access**: FTP anonymous, SMB null sessions, SNMP \"public\" community
- **Weak Encryption**: SSLv3, TLS 1.0, weak ciphers (RC4, DES, 3DES)
- **Information Disclosure**: Detailed error messages, verbose banners, directory listings
- **Misconfigurations**: Open relays (SMTP), recursion (DNS), guest access (SMB)
- **Deprecated Protocols**: Telnet, FTP, SNMPv1/v2c, SMBv1
- **Service Combinations**: SQL+Web (SQL injection), LDAP+Web (LDAP injection)
- **Unusual Services**: Custom applications, development servers (Jenkins, GitLab)
- **Internal Hostnames**: In SSL certificates, SMTP banners, error messages

SECURITY IMPLICATIONS:
- **SMBv1**: Vulnerable to EternalBlue (MS17-010), WannaCry, NotPetya
- **Anonymous FTP**: Potential data leakage or malware upload point
- **SNMP \"public\"**: Entire system configuration and secrets exposed
- **Open LDAP**: Full Active Directory enumeration without authentication
- **Weak SSH**: Vulnerable to brute force, man-in-the-middle attacks
- **MySQL Root No Password**: Direct database compromise
- **Redis No Auth**: Can achieve RCE via SLAVEOF or CONFIG SET
- **Elasticsearch Open**: Data exfiltration, potential RCE
- **MongoDB No Auth**: Full database access (common misconfiguration)

COMMON PITFALLS:
- **Service Hiding Versions**: Some services obscure version info in banners
- **Virtual Hosting**: Web servers may respond differently per vhost
- **Load Balancers**: May distribute requests to different backends with different versions
- **WAFs/Firewalls**: May intercept and modify service responses
- **Rate Limiting**: Aggressive enumeration triggers IPS/IDS blocks
- **Application Firewalls**: Block enumeration attempts (e.g., SQL commands in MySQL probe)
- **Protocol Complexity**: Some protocols require specific handshakes (Kerberos, NTLM)
- **Timeouts**: Services may have connection limits or timeouts
- **Authentication Required**: Many modern services require auth before revealing info

DOCUMENTATION REQUIREMENTS:
- **Service Inventory Matrix**:
  | Port | Protocol | Service | Version | CVEs | Risk |
  |------|----------|---------|---------|------|------|
  | 22 | TCP | OpenSSH | 7.4 | CVE-2021-28041 | Medium |
  
- Complete banner captures (screenshots or text files)
- Configuration findings (enabled/disabled features)
- Evidence of misconfigurations with security impact
- Comparison against vendor best practices
- Recommendations for service hardening
- List of services that should be disabled or firewalled

AUTOMATION AND EFFICIENCY:
```bash
# All-in-one enumeration script
#!/bin/bash
TARGET=\"target.com\"

# Web services
whatweb $TARGET
nikto -h $TARGET

# SSH
ssh-audit $TARGET

# SMB
enum4linux-ng $TARGET -oA enum4linux_out

# SNMP
onesixtyone $TARGET
snmpwalk -v2c -c public $TARGET system

# Comprehensive Nmap NSE
nmap -p- -sV --script \"default and safe\" $TARGET -oA full_enum
```

TOOLS REFERENCE:
- **Nmap NSE**: https://nmap.org/nsedoc/ (600+ scripts for all services)
- **enum4linux-ng**: https://github.com/cddmp/enum4linux-ng (Modern SMB enumeration)
- **ssh-audit**: https://github.com/jtesta/ssh-audit (SSH configuration auditing)
- **testssl.sh**: https://testssl.sh/ (SSL/TLS comprehensive testing)
- **WhatWeb**: https://github.com/urbanadventurer/WhatWeb (Web tech identification)
- **Nikto**: https://github.com/sullo/nikto (Web server scanner)
- **CrackMapExec**: https://github.com/byt3bl33d3r/CrackMapExec (Multi-protocol pentesting)
- **Impacket**: https://github.com/SecureAuthCorp/impacket (Python SMB/LDAP/Kerberos)

FURTHER READING:
- OWASP WSTG-INFO-02: Fingerprint Web Server
- NIST SP 800-115: Section 7.3 - Service Identification
- SANS SEC560: Network Penetration Testing
- Nmap NSE Documentation: https://nmap.org/book/nse.html
- PTES Technical Guidelines: Section 3.4 - Service Enumeration
- CIS Benchmarks: Hardening guides for all major services"
    ),
    (
        "Web technology fingerprinting",
        "OBJECTIVE: Identify web server software, frameworks, content management systems (CMS), libraries, and underlying technologies to map the application stack and identify version-specific vulnerabilities.

ACADEMIC BACKGROUND:
Web technology fingerprinting, as defined in OWASP WSTG-INFO-02 (Fingerprint Web Server and Web Application Framework), is the systematic identification of web technologies through analysis of HTTP headers, response patterns, file structures, cookies, HTML/JavaScript signatures, and behavior patterns.

This intelligence gathering enables targeted vulnerability assessment by identifying:
- Known CVEs for specific software versions
- Default credentials and paths
- Framework-specific attack vectors
- Plugin/extension vulnerabilities
- Technology-specific misconfigurations

The MITRE ATT&CK framework categorizes this as T1594.002 (Search Victim-Owned Websites) and T1592.002 (Gather Victim Host Information: Software), emphasizing that public-facing web infrastructure reveals significant attack surface information.

According to the PTES (Penetration Testing Execution Standard), technology identification precedes vulnerability analysis and helps prioritize testing based on known attack patterns for identified technologies.

TECHNOLOGY STACK LAYERS:
1. **Web Server**: Apache, Nginx, IIS, LiteSpeed, Caddy
2. **Application Server**: Tomcat, JBoss, WebLogic, Gunicorn, Passenger
3. **Programming Language**: PHP, Python, Ruby, Java, .NET, Node.js, Go
4. **Framework**: Laravel, Django, Flask, Ruby on Rails, Express, Spring, ASP.NET
5. **CMS/Platform**: WordPress, Joomla, Drupal, Magento, SharePoint
6. **Database**: MySQL, PostgreSQL, MSSQL, MongoDB, Redis (inferred)
7. **Frontend Libraries**: React, Angular, Vue.js, jQuery, Bootstrap
8. **CDN/WAF**: Cloudflare, Akamai, AWS CloudFront, Sucuri
9. **Analytics/Tracking**: Google Analytics, Adobe Analytics, Hotjar
10. **Third-Party Services**: Payment gateways, chat widgets, CRMs

STEP-BY-STEP PROCESS:

1. AUTOMATED TECHNOLOGY DETECTION:
   a) WhatWeb (Comprehensive Scanner):
      ```bash
      # Basic scan
      whatweb https://target.com
      
      # Aggressive scan (all plugins)
      whatweb -a 3 https://target.com
      
      # Verbose output with plugin details
      whatweb -v https://target.com
      
      # JSON output for parsing
      whatweb --log-json=whatweb_results.json https://target.com
      
      # Scan multiple URLs from file
      whatweb -i urls.txt --log-json=results.json
      
      # Custom user agent
      whatweb -U \"Mozilla/5.0\" https://target.com
      ```
      
      WhatWeb identifies: Web server, CMS, JavaScript libraries, analytics, frameworks, cookies
   
   b) Wappalyzer (Technology Profiler):
      ```bash
      # CLI usage (requires npm)
      npm install -g wappalyzer
      wappalyzer https://target.com
      
      # Multiple URLs
      wappalyzer https://target.com https://target.com/admin
      
      # Browser extension (Chrome/Firefox)
      # Install from https://www.wappalyzer.com/apps/
      ```
      
      Wappalyzer categories: CMS, frameworks, web servers, analytics, CDN, databases (inferred)
   
   c) httpx (Fast HTTP Toolkit):
      ```bash
      # Technology detection
      echo \"target.com\" | httpx -tech-detect
      
      # With title and status code
      echo \"target.com\" | httpx -tech-detect -title -status-code
      
      # Server header extraction
      echo \"target.com\" | httpx -silent -server
      
      # Full headers
      echo \"target.com\" | httpx -include-response-header
      
      # Multiple subdomains
      cat subdomains.txt | httpx -tech-detect -o tech_results.txt
      ```
   
   d) Nikto (Web Server Scanner):
      ```bash
      # Full scan with tech detection
      nikto -h https://target.com -o nikto_report.txt
      
      # Faster scan (skip some checks)
      nikto -h https://target.com -Tuning 1,2,3
      
      # Identify server version and components
      nikto -h https://target.com | grep -i \"server:\"
      ```
   
   e) Webtech (Lightweight Fingerprinter):
      ```bash
      # Install and run
      go install github.com/ShivangiReja/webtech@latest
      webtech -u https://target.com
      ```

2. MANUAL HTTP HEADER ANALYSIS:
   ```bash
   # Basic header inspection
   curl -I https://target.com
   
   # Verbose connection details
   curl -v https://target.com 2>&1 | grep -i '^< '
   
   # Multiple redirects follow
   curl -IL https://target.com
   
   # Extract specific headers
   curl -s -I https://target.com | grep -i server
   curl -s -I https://target.com | grep -i x-powered-by
   curl -s -I https://target.com | grep -i x-aspnet-version
   
   # All security headers
   curl -I https://target.com | grep -iE '(X-Frame|X-XSS|X-Content|Content-Security|Strict-Transport)'
   
   # Using http (HTTPie)
   http HEAD https://target.com
   ```
   
   Key Headers to Analyze:
   - **Server**: Web server type and version (e.g., \"Apache/2.4.41\")
   - **X-Powered-By**: Backend technology (e.g., \"PHP/7.4.3\", \"Express\")
   - **X-AspNet-Version**: .NET framework version
   - **X-AspNetMvc-Version**: ASP.NET MVC version
   - **X-Drupal-Cache**: Drupal CMS
   - **X-Generator**: CMS or framework (e.g., \"Drupal 9\")
   - **X-Redirect-By**: WordPress plugin
   - **X-Pingback**: WordPress XML-RPC endpoint
   - **Via**: Proxy or load balancer information
   - **X-Varnish**: Varnish cache
   - **CF-RAY**: Cloudflare CDN
   - **X-Amz-Cf-Id**: AWS CloudFront

3. CMS IDENTIFICATION:
   a) WordPress Detection:
      ```bash
      # Check for WordPress paths
      curl -s https://target.com/wp-login.php | grep \"WordPress\"
      curl -s https://target.com/wp-admin/
      curl -I https://target.com/wp-json/wp/v2/users
      
      # Identify WordPress version
      curl -s https://target.com/ | grep 'content=\"WordPress'
      curl -s https://target.com/readme.html | grep \"Version\"
      
      # WPScan (comprehensive WordPress scanner)
      wpscan --url https://target.com --enumerate vp,vt,u
      # vp = vulnerable plugins, vt = vulnerable themes, u = users
      
      # Enumerate plugins
      wpscan --url https://target.com --enumerate p
      
      # WordPress theme detection
      curl -s https://target.com/ | grep -i \"wp-content/themes\"
      
      # WordPress version from generator meta tag
      curl -s https://target.com/ | grep -i \"<meta name=\\\"generator\\\"\"
      
      # Check wp-json API
      curl -s https://target.com/wp-json/ | jq '.'
      ```
      
      WordPress Indicators:
      - /wp-admin/, /wp-content/, /wp-includes/
      - /wp-json/wp/v2/ (REST API)
      - /xmlrpc.php (XML-RPC endpoint)
      - Generator meta tag
      - wp-emoji scripts
      - X-Redirect-By header
   
   b) Joomla Detection:
      ```bash
      # Common Joomla paths
      curl -I https://target.com/administrator/
      curl -s https://target.com/administrator/manifests/files/joomla.xml | grep version
      
      # Joomla version from XML
      curl -s https://target.com/language/en-GB/en-GB.xml | grep version
      
      # JoomScan tool
      joomscan -u https://target.com
      
      # Components enumeration
      curl -s https://target.com/ | grep -i \"com_\"
      ```
      
      Joomla Indicators:
      - /administrator/ (admin panel)
      - /components/, /modules/, /plugins/
      - /language/en-GB/
      - Joomla! meta generator tag
   
   c) Drupal Detection:
      ```bash
      # Drupal paths
      curl -I https://target.com/user/login
      curl -s https://target.com/CHANGELOG.txt | head -5
      
      # Drupal version
      curl -s https://target.com/ | grep 'content=\"Drupal'
      
      # Droopescan (Drupal scanner)
      droopescan scan drupal -u https://target.com
      
      # Check for Drupal headers
      curl -I https://target.com | grep -i x-drupal
      curl -I https://target.com | grep -i x-generator
      ```
      
      Drupal Indicators:
      - /user/login, /node/, /admin/
      - CHANGELOG.txt, README.txt
      - /sites/all/modules/, /sites/default/
      - X-Drupal-Cache header
      - Drupal.settings JavaScript object
   
   d) Magento Detection:
      ```bash
      # Magento paths
      curl -I https://target.com/admin
      curl -I https://target.com/downloader/
      
      # Magento version detection
      curl -s https://target.com/magento_version
      
      # Magescan tool
      magescan scan:all https://target.com
      ```
      
      Magento Indicators:
      - /skin/, /media/, /js/mage/
      - Mage.Cookies JavaScript
      - X-Magento-* headers
   
   e) SharePoint Detection:
      ```bash
      # SharePoint paths
      curl -I https://target.com/_layouts/
      curl -s https://target.com/ | grep -i \"MicrosoftSharePointTeamServices\"
      
      # SharePoint version
      curl -s https://target.com/ | grep -i \"x-sharepoint\"
      ```

4. WEB SERVER FINGERPRINTING:
   ```bash
   # Nginx detection
   curl -I https://target.com | grep -i nginx
   
   # Apache version and modules
   curl -I https://target.com | grep -i apache
   # Look for: Apache/2.4.41 (Ubuntu)
   
   # IIS version
   curl -I https://target.com | grep -i \"Microsoft-IIS\"
   
   # Server misconfigurations (verbose errors)
   curl -s https://target.com/nonexistent | grep -i \"apache\\|nginx\\|iis\"
   
   # Check for server tokens
   curl -I https://target.com | grep -i \"server:\"
   
   # HTTP methods allowed
   curl -X OPTIONS https://target.com -i
   ```
   
   Server-Specific Files:
   - Apache: .htaccess, /server-status, /server-info
   - Nginx: nginx.conf (shouldn't be accessible)
   - IIS: web.config, /trace.axd, /elmah.axd

5. FRAMEWORK IDENTIFICATION:
   a) JavaScript Frameworks (Frontend):
      ```bash
      # View page source for framework signatures
      curl -s https://target.com/ | grep -iE '(react|angular|vue|ember|backbone|jquery)'
      
      # React detection
      curl -s https://target.com/ | grep -i \"react\"
      curl -s https://target.com/ | grep -i \"__REACT\"
      
      # Angular detection
      curl -s https://target.com/ | grep -i \"ng-app\"
      curl -s https://target.com/ | grep -i \"angular\"
      
      # Vue.js detection
      curl -s https://target.com/ | grep -i \"vue\"
      curl -s https://target.com/ | grep -i \"v-app\"
      
      # Check JavaScript files
      curl -s https://target.com/main.js | head -20
      
      # Retire.js (JavaScript library vulnerability scanner)
      retire --js --jspath https://target.com
      ```
   
   b) Backend Frameworks:
      ```bash
      # Laravel (PHP)
      curl -s https://target.com/ | grep -i \"laravel\"
      curl -I https://target.com | grep -i \"laravel_session\"
      curl -s https://target.com/.env  # Misconfiguration check
      
      # Django (Python)
      curl -I https://target.com | grep -i \"csrftoken\"
      curl -s https://target.com/admin/  # Django admin
      
      # Flask (Python)
      curl -I https://target.com | grep -i \"session\"
      
      # Ruby on Rails
      curl -I https://target.com | grep -i \"_session\"
      curl -s https://target.com/ | grep -i \"csrf-token\"
      
      # Express (Node.js)
      curl -I https://target.com | grep -i \"express\"
      curl -I https://target.com | grep -i \"x-powered-by: Express\"
      
      # Spring (Java)
      curl -s https://target.com/ | grep -i \"spring\"
      curl -I https://target.com/actuator/  # Spring Boot Actuator
      
      # ASP.NET
      curl -I https://target.com | grep -i \"aspnet\"
      curl -s https://target.com/ | grep -i \"__VIEWSTATE\"
      ```

6. COOKIE ANALYSIS:
   ```bash
   # Extract all cookies
   curl -I https://target.com | grep -i \"set-cookie\"
   
   # Detailed cookie inspection
   curl -v https://target.com 2>&1 | grep -i cookie
   
   # Common framework cookies:
   # - PHPSESSID (PHP)
   # - JSESSIONID (Java/Tomcat)
   # - ASP.NET_SessionId (.NET)
   # - laravel_session (Laravel)
   # - csrftoken (Django)
   # - connect.sid (Express)
   # - _rails_session (Ruby on Rails)
   # - wordpress_* (WordPress)
   ```

7. SSL/TLS CERTIFICATE ANALYSIS:
   ```bash
   # Certificate details
   openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -text -noout
   
   # Issuer and organization
   openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -noout -issuer -subject
   
   # Subject Alternative Names (internal hostnames)
   openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -noout -text | grep \"DNS:\"
   
   # Certificate chain
   openssl s_client -connect target.com:443 -showcerts
   ```
   
   Certificate Intelligence:
   - Organization name and location
   - Internal domain names in SANs
   - Certificate authority (Let's Encrypt = automated, may indicate modern stack)
   - Validity period (short = good security practice)
   - Wildcard certificates

8. FILE AND DIRECTORY STRUCTURE ANALYSIS:
   ```bash
   # Common static file directories
   curl -I https://target.com/static/
   curl -I https://target.com/assets/
   curl -I https://target.com/public/
   curl -I https://target.com/dist/
   
   # JavaScript files
   curl -s https://target.com/app.js | head -50
   curl -s https://target.com/main.js | grep -i \"webpack\\|react\\|angular\\|vue\"
   
   # CSS files (framework detection)
   curl -s https://target.com/style.css | grep -i \"bootstrap\\|tailwind\\|foundation\"
   
   # Favicon analysis (framework-specific)
   curl -I https://target.com/favicon.ico
   
   # robots.txt (reveals directory structure)
   curl -s https://target.com/robots.txt
   
   # sitemap.xml (reveals URLs and structure)
   curl -s https://target.com/sitemap.xml
   ```

9. ERROR PAGE ANALYSIS:
   ```bash
   # Trigger 404 error
   curl -s https://target.com/nonexistent-page-12345 | grep -i \"server\\|version\\|error\"
   
   # Trigger 500 error (if possible)
   curl -s \"https://target.com/page?param=../../../etc/passwd\"
   
   # Check for detailed error messages (development mode)
   # Look for stack traces, file paths, framework names
   ```
   
   Framework-Specific Error Pages:
   - Django: \"DisallowedHost\", \"OperationalError\"
   - Laravel: \"Whoops, looks like something went wrong\"
   - ASP.NET: \"Server Error in '/' Application\"
   - Express: \"Cannot GET /\"
   - Rails: \"We're sorry, but something went wrong\"

10. THIRD-PARTY SERVICE IDENTIFICATION:
    ```bash
    # View page source for third-party scripts
    curl -s https://target.com/ | grep -iE '(google-analytics|gtag|facebook|twitter|stripe|paypal)'
    
    # CDN detection
    curl -I https://target.com | grep -i \"cf-ray\\|x-amz\\|x-cache\"
    
    # Analytics platforms
    curl -s https://target.com/ | grep -i \"ga('\\|gtag(\"
    
    # Payment gateways
    curl -s https://target.com/checkout | grep -iE '(stripe|paypal|square|braintree)'
    
    # Chat widgets
    curl -s https://target.com/ | grep -iE '(intercom|zendesk|livechat|drift)'
    ```

11. API ENDPOINT DISCOVERY:
    ```bash
    # Common API paths
    curl -I https://target.com/api/
    curl -I https://target.com/api/v1/
    curl -s https://target.com/api/ | jq '.'
    
    # GraphQL endpoints
    curl -s https://target.com/graphql -d '{\"query\":\"{__schema{types{name}}}\"}' -H \"Content-Type: application/json\"
    
    # Swagger/OpenAPI documentation
    curl -s https://target.com/api-docs
    curl -s https://target.com/swagger.json
    curl -s https://target.com/v2/swagger.json
    
    # REST API version discovery
    for i in {1..5}; do curl -I https://target.com/api/v$i/; done
    ```

WHAT TO LOOK FOR:
- **Outdated Versions**: PHP 5.x, jQuery < 3.0, Angular < 8, Apache < 2.4.50
- **Development Frameworks in Production**: Flask debug mode, Django DEBUG=True, Express dev environment
- **Verbose Error Messages**: Stack traces, file paths, database errors
- **Version Disclosure**: Exact version numbers in headers, meta tags, or files (README.txt, CHANGELOG.txt)
- **Default Installations**: Default favicon, unchanged admin paths, sample pages
- **Unpatched Software**: Known CVEs for identified versions
- **Deprecated Technologies**: Flash, Silverlight, Java applets, ActiveX
- **Multiple Frameworks**: Mixed technology stack (PHP + Python, unusual combinations)
- **Information Leakage**: Internal hostnames, developer comments in source, debugging endpoints
- **CDN/WAF**: Cloudflare, Akamai (may protect against some attacks)

SECURITY IMPLICATIONS:
- **PHP < 7.4**: Multiple RCE vulnerabilities (CVE-2019-11043, CVE-2019-11041)
- **WordPress < 5.8**: XSS, CSRF, privilege escalation vulnerabilities
- **Drupal < 9.2**: Drupalgeddon vulnerabilities (RCE)
- **Apache Struts**: CVE-2017-5638 (Equifax breach), multiple RCE
- **Laravel Debug Mode**: Full environment variable disclosure (DB credentials, API keys)
- **Django DEBUG=True**: Source code disclosure, SQL query leakage
- **jQuery < 3.0**: XSS via $.html() and $.get()
- **Angular < 1.6**: XSS in templates and expressions
- **Outdated TLS**: TLS 1.0/1.1 deprecated, vulnerable to BEAST, POODLE
- **Server Version Disclosure**: Helps attackers identify specific exploits

COMMON PITFALLS:
- **WAF Interference**: Cloudflare/Akamai may hide real server headers
- **Load Balancers**: May show different servers on different requests
- **Header Stripping**: Security-conscious admins disable version headers
- **Virtual Hosting**: Different technologies per vhost/subdomain
- **Custom Headers**: Some orgs add fake headers to mislead attackers
- **Caching Layers**: Varnish/Redis may modify responses
- **Microservices**: Different technologies per API endpoint
- **False Positives**: Generic error pages don't always reveal real technology

DOCUMENTATION REQUIREMENTS:
- **Technology Matrix**:
  | Layer | Technology | Version | CVEs | Risk |
  |-------|------------|---------|------|------|
  | Web Server | Nginx | 1.18.0 | CVE-2021-23017 | High |
  | CMS | WordPress | 5.7 | Multiple XSS | Medium |
  | Plugin | Contact Form 7 | 5.3.2 | SQL Injection | Critical |
  
- Screenshots of technology detection tools (WhatWeb, Wappalyzer)
- HTTP header captures showing version disclosure
- Evidence of identified frameworks (cookies, error pages, source code)
- List of third-party services and integrations
- CVE mapping for all identified versions
- Comparison against vendor security advisories
- Recommendations for version obfuscation and upgrades

AUTOMATION SCRIPT:
```bash
#!/bin/bash
TARGET=\"$1\"

echo \"[*] Technology Fingerprinting: $TARGET\"
echo \"\"

echo \"[+] WhatWeb Scan:\"
whatweb -a 3 \"$TARGET\"
echo \"\"

echo \"[+] HTTP Headers:\"
curl -I \"$TARGET\"
echo \"\"

echo \"[+] Certificate Info:\"
echo | openssl s_client -connect \"${TARGET#https://}:443\" 2>/dev/null | openssl x509 -noout -subject -issuer
echo \"\"

echo \"[+] CMS Detection:\"
curl -s \"$TARGET\" | grep -iE '(wordpress|joomla|drupal|magento)'
echo \"\"

echo \"[+] Framework Detection:\"
curl -I \"$TARGET\" | grep -iE '(x-powered-by|x-aspnet|laravel|django)'
echo \"\"

echo \"[+] JavaScript Frameworks:\"
curl -s \"$TARGET\" | grep -iE '(react|angular|vue|jquery)'
```

TOOLS REFERENCE:
- **WhatWeb**: https://github.com/urbanadventurer/WhatWeb (Most comprehensive)
- **Wappalyzer**: https://www.wappalyzer.com/ (Browser extension + CLI)
- **Webanalyze**: https://github.com/rverton/webanalyze (Go-based, fast)
- **httpx**: https://github.com/projectdiscovery/httpx (Modern HTTP toolkit)
- **WPScan**: https://wpscan.com/ (WordPress security scanner)
- **Joomscan**: https://github.com/OWASP/joomscan (Joomla scanner)
- **Droopescan**: https://github.com/droope/droopescan (Drupal/SilverStripe scanner)
- **Retire.js**: https://retirejs.github.io/retire.js/ (JavaScript library vulnerability scanner)
- **Nikto**: https://github.com/sullo/nikto (Web server scanner)

FURTHER READING:
- OWASP WSTG-INFO-02: Fingerprint Web Server
- OWASP WSTG-INFO-08: Fingerprint Web Application Framework
- NIST SP 800-115: Section 7.4 - Web Application Testing
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- CAPEC-169: Footprinting
- CVE Database: https://cve.mitre.org/ (Cross-reference versions)
- Exploit-DB: https://www.exploit-db.com/ (Known exploits for identified software)"
    ),
    (
        "Web crawling and spidering",
        "OBJECTIVE: Systematically map web application structure, discover all accessible pages, hidden directories, and functionality through automated crawling and directory enumeration to build a comprehensive attack surface map.

ACADEMIC BACKGROUND:
Web crawling (also called spidering) is the automated traversal of web applications following links and analyzing responses to discover all accessible content. As outlined in OWASP WSTG-INFO-05 (Review Webpage Content for Information Leakage) and WSTG-INFO-07 (Map Application Architecture), comprehensive content discovery reveals:
- Hidden administrative interfaces
- Backup and configuration files
- API endpoints and documentation
- Development/staging environments
- Commented-out functionality
- Forgotten test pages

The MITRE ATT&CK framework categorizes this as T1593 (Search Open Websites/Domains) under Reconnaissance, emphasizing that public-facing web content often reveals internal architecture and sensitive functionality.

According to NIST SP 800-115, content discovery should employ both passive analysis (robots.txt, sitemaps) and active enumeration (directory brute-forcing, fuzzing) to ensure comprehensive coverage.

CRAWLING METHODOLOGIES:
1. **Passive Discovery**: robots.txt, sitemap.xml, search engine caches
2. **Active Crawling**: Following links, parsing JavaScript, form submission
3. **Directory Brute-forcing**: Wordlist-based path enumeration
4. **Fuzzing**: Parameter and path mutation testing
5. **Recursive Discovery**: Following discovered links to find more content

STEP-BY-STEP PROCESS:

1. PASSIVE RECONNAISSANCE (No Direct Scanning):
   ```bash
   # robots.txt analysis (reveals disallowed paths)
   curl -s https://target.com/robots.txt
   
   # Common robots.txt interesting entries:
   # Disallow: /admin/
   # Disallow: /backup/
   # Disallow: /config/
   # Disallow: /.git/
   
   # sitemap.xml parsing (complete URL structure)
   curl -s https://target.com/sitemap.xml | grep -oP '(?<=<loc>)[^<]+'
   
   # sitemap_index.xml for large sites
   curl -s https://target.com/sitemap_index.xml
   
   # Search engine cache exploration
   # Google: site:target.com
   # Bing: site:target.com
   # Check Google cache for old/deleted pages
   
   # Wayback Machine (archive.org)
   # View historical versions for removed content
   curl -s \"http://web.archive.org/cdx/search/cdx?url=target.com/*&output=json\" | jq -r '.[] | .[2]' | sort -u
   ```
   
   Intelligence: robots.txt often reveals admin panels, backup directories, and paths developers want hidden

2. AUTOMATED WEB CRAWLERS (Spider):
   a) Burp Suite Spider:
      ```
      1. Configure Burp Proxy (127.0.0.1:8080)
      2. Navigate to Target → Site Map
      3. Right-click domain → Spider this host
      4. Configure Spider options:
         - Check \"Crawler Settings\" → Form submission
         - Set crawl limits (depth, threads)
         - Configure authentication if needed
      5. Review Site Map for discovered content
      ```
      
      Advantages: Handles JavaScript, session management, form submission
   
   b) OWASP ZAP Spider:
      ```bash
      # CLI mode
      zap-cli quick-scan -s all https://target.com
      
      # Traditional spider
      zap-cli spider https://target.com
      
      # AJAX spider (for JavaScript-heavy apps)
      zap-cli ajax-spider https://target.com
      
      # Export results
      zap-cli report -o zap_report.html -f html
      ```
      
      Advantages: Open-source, AJAX spider, automated scanning integration
   
   c) Hakrawler (Fast Go-based Crawler):
      ```bash
      # Crawl single domain
      echo \"https://target.com\" | hakrawler
      
      # Crawl with depth
      echo \"https://target.com\" | hakrawler -d 3
      
      # Include subdomains
      echo \"https://target.com\" | hakrawler -subs
      
      # Plain URLs only (no parameters)
      echo \"https://target.com\" | hakrawler -plain
      
      # Save results
      echo \"https://target.com\" | hakrawler -d 2 > crawled_urls.txt
      ```
   
   d) GoSpider (Modern Crawler):
      ```bash
      # Basic crawl
      gospider -s \"https://target.com\" -o output
      
      # With depth and concurrency
      gospider -s \"https://target.com\" -d 3 -c 10
      
      # Include subdomains
      gospider -s \"https://target.com\" --subs
      
      # Follow redirects
      gospider -s \"https://target.com\" --redirect
      ```

3. DIRECTORY AND FILE ENUMERATION (Brute-forcing):
   a) Gobuster (Fast Directory Bruteforcer):
      ```bash
      # Basic directory enumeration
      gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt
      
      # Comprehensive with extensions
      gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,html,txt,js,bak,zip
      
      # With custom status codes
      gobuster dir -u https://target.com -w wordlist.txt -s 200,204,301,302,307,401,403
      
      # Follow redirects
      gobuster dir -u https://target.com -w wordlist.txt -r
      
      # Increase threads for speed
      gobuster dir -u https://target.com -w wordlist.txt -t 50
      
      # Ignore certificate errors
      gobuster dir -u https://target.com -w wordlist.txt -k
      
      # Add custom headers (auth, user-agent)
      gobuster dir -u https://target.com -w wordlist.txt -H \"Authorization: Bearer token123\"
      
      # Recursive mode
      gobuster dir -u https://target.com -w wordlist.txt --wildcard -r
      ```
   
   b) Feroxbuster (Recursive Rust-based Scanner):
      ```bash
      # Basic scan
      feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
      
      # Recursive with depth
      feroxbuster -u https://target.com -w wordlist.txt -d 4
      
      # With extensions
      feroxbuster -u https://target.com -w wordlist.txt -x php,html,js,txt,bak
      
      # Extract links from responses
      feroxbuster -u https://target.com -w wordlist.txt --extract-links
      
      # High performance mode
      feroxbuster -u https://target.com -w wordlist.txt -t 200 --rate-limit 100
      
      # Filter by response size
      feroxbuster -u https://target.com -w wordlist.txt -S 1234
      
      # Auto-tune (adapts to server response)
      feroxbuster -u https://target.com -w wordlist.txt --auto-tune
      ```
   
   c) Dirsearch (Python Classic):
      ```bash
      # Basic scan
      dirsearch -u https://target.com
      
      # With extensions
      dirsearch -u https://target.com -e php,html,js,txt,zip,bak
      
      # Recursive
      dirsearch -u https://target.com -r
      
      # Multiple URLs from file
      dirsearch -l urls.txt
      
      # Custom wordlist
      dirsearch -u https://target.com -w /path/to/wordlist.txt
      
      # Exclude status codes
      dirsearch -u https://target.com -x 404,403
      ```
   
   d) ffuf (Fast Fuzzer):
      ```bash
      # Directory fuzzing
      ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
      
      # File fuzzing with extensions
      ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.html,.txt,.js,.bak
      
      # Recursive fuzzing
      ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2
      
      # Filter by response size
      ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 4242
      
      # Filter by response code
      ffuf -u https://target.com/FUZZ -w wordlist.txt -fc 404,403
      
      # Match regex in response
      ffuf -u https://target.com/FUZZ -w wordlist.txt -mr \"admin\"
      
      # Virtual host fuzzing
      ffuf -u https://target.com -w vhosts.txt -H \"Host: FUZZ.target.com\"
      
      # Multi-position fuzzing
      ffuf -u https://target.com/FUZZ/W2 -w paths.txt:FUZZ -w files.txt:W2
      ```

4. BACKUP AND CONFIGURATION FILE DISCOVERY:
   ```bash
   # Common backup file patterns
   ffuf -u https://target.com/FUZZ -w - << EOF
   .git/
   .git/config
   .gitignore
   .svn/
   .env
   .env.backup
   config.php.bak
   config.php.old
   config.php~
   web.config.bak
   wp-config.php.bak
   database.sql
   backup.zip
   site-backup.tar.gz
   dump.sql
   db_backup.sql
   .DS_Store
   .htaccess
   .htpasswd
   phpinfo.php
   info.php
   test.php
   debug.php
   console.php
   admin.php
   login.php.bak
   EOF
   
   # Automated backup checker
   for ext in bak old backup tmp save swp; do
       ffuf -u https://target.com/config.php.$ext -w /dev/null
   done
   ```

5. API ENDPOINT DISCOVERY:
   ```bash
   # Common API paths
   ffuf -u https://target.com/FUZZ -w - << EOF
   /api
   /api/v1
   /api/v2
   /api/v3
   /rest
   /rest/v1
   /graphql
   /swagger
   /swagger.json
   /swagger-ui
   /api-docs
   /openapi.json
   /v1/api-docs
   /v2/api-docs
   /api/swagger.json
   /api/swagger-ui.html
   /actuator
   /actuator/health
   /actuator/env
   /health
   /metrics
   /docs
   EOF
   
   # Kiterunner (API content discovery)
   kr scan https://target.com -w routes-large.kite
   
   # Arjun (parameter discovery for APIs)
   arjun -u https://target.com/api/users
   ```

6. JAVASCRIPT FILE ANALYSIS FOR ENDPOINTS:
   ```bash
   # Extract all JS files
   echo \"https://target.com\" | hakrawler | grep -E '\\.js$' > js_files.txt
   
   # Download JS files
   cat js_files.txt | while read url; do wget \"$url\"; done
   
   # Extract endpoints from JS (using regex)
   grep -rEo \"['\\\"]/(api|admin|user|dashboard|config)[^'\\\"]*\" *.js | sort -u
   
   # LinkFinder (automated endpoint extraction)
   python3 linkfinder.py -i https://target.com/app.js -o cli
   
   # JSParser (comprehensive JS analysis)
   python3 jsparser.py -u https://target.com
   
   # Extract API keys and secrets from JS
   grep -rEi \"(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret)\" *.js
   ```

7. FORM AND PARAMETER DISCOVERY:
   ```bash
   # ParamSpider (URL parameter collection)
   python3 paramspider.py -d target.com -o params.txt
   
   # Extract unique parameters
   cat params.txt | grep -oP '(?<=[?&])[^=&]+' | sort -u > unique_params.txt
   
   # Arjun (hidden parameter discovery)
   arjun -u https://target.com/search
   
   # Burp Param Miner extension
   # Install via Burp Extender, right-click request → \"Guess params\"
   ```

8. RECURSIVE AND COMPREHENSIVE DISCOVERY:
   ```bash
   # Multi-tool pipeline
   #!/bin/bash
   TARGET=\"https://target.com\"
   
   # Stage 1: Initial crawl
   echo \"[*] Stage 1: Crawling...\"
   gospider -s \"$TARGET\" -d 3 --subs -o crawl_output
   
   # Stage 2: Extract URLs
   cat crawl_output/*.txt | grep -Eo 'https?://[^ ]+' | sort -u > all_urls.txt
   
   # Stage 3: Directory enumeration on discovered paths
   echo \"[*] Stage 2: Directory enumeration...\"
   feroxbuster -u \"$TARGET\" -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,html,js,txt --extract-links -o ferox_results.txt
   
   # Stage 4: Parameter discovery
   echo \"[*] Stage 3: Parameter discovery...\"
   python3 paramspider.py -d target.com -o params.txt
   
   # Stage 5: JS endpoint extraction
   echo \"[*] Stage 4: JS analysis...\"
   cat all_urls.txt | grep '\\.js$' | while read jsurl; do
       python3 linkfinder.py -i \"$jsurl\" -o cli
   done > endpoints_from_js.txt
   
   echo \"[*] Discovery complete! Results in all_urls.txt, ferox_results.txt, params.txt, endpoints_from_js.txt\"
   ```

WHAT TO LOOK FOR:
- **Admin Interfaces**: /admin/, /administrator/, /manage/, /cpanel/, /dashboard/
- **Authentication Pages**: /login, /signin, /auth, /sso
- **API Documentation**: /api-docs, /swagger, /graphql, /openapi.json
- **Development/Staging**: /dev/, /test/, /staging/, /qa/
- **Backup Files**: *.bak, *.old, *.backup, *.tmp, *.swp, *~
- **Configuration Files**: .env, config.php, web.config, application.properties
- **Source Control**: .git/, .svn/, .hg/
- **Database Dumps**: *.sql, dump.sql, backup.sql
- **Error Pages**: Custom 404/500 pages that leak information
- **File Uploads**: /uploads/, /files/, /media/, /attachments/
- **Hidden Functionality**: Commented-out links in HTML source
- **Monitoring Endpoints**: /health, /metrics, /status, /actuator/
- **Debug Interfaces**: /debug/, /console/, /phpinfo.php
- **Legacy Content**: Old versions, deprecated features

SECURITY IMPLICATIONS:
- **Exposed Admin Panels**: Direct access to management interfaces
- **.git/ Directory**: Full source code disclosure via `git-dumper`
- **.env Files**: Database credentials, API keys, secrets
- **Backup Files**: Old configurations with default credentials
- **API Documentation**: Reveals all endpoints and parameters
- **Development Directories**: Often less secure, debug mode enabled
- **phpinfo() Pages**: Full PHP configuration disclosure
- **Database Dumps**: Complete data exfiltration
- **File Upload Directories**: May allow direct access to uploaded files
- **Comments in HTML**: Reveal internal infrastructure, IPs, hostnames

COMMON PITFALLS:
- **WAF Blocking**: Aggressive scanning triggers IP blocks
- **Rate Limiting**: Slow down scanning or use rotating proxies
- **False Positives**: 200 OK responses may be custom 404 pages (wildcard DNS)
- **JavaScript-Heavy SPAs**: Standard crawlers miss dynamically loaded content
- **Authentication Required**: Some paths only accessible when logged in
- **Virtual Hosting**: Different content per Host header
- **Load Balancers**: May distribute requests to different backends
- **Recursive Scanning Loops**: Limit recursion depth to avoid infinite loops
- **Large Wordlists**: Balance coverage vs. scan time (start with top-1000)
- **Client-Side Routing**: React/Angular apps use hash or history routing

DOCUMENTATION REQUIREMENTS:
- Complete site map with all discovered URLs
- Directory structure tree showing hierarchy
- List of interesting files and their locations
- API endpoint inventory with methods and parameters
- Screenshots of discovered admin/debug interfaces
- Evidence of exposed sensitive files
- Notes on authentication requirements per path
- Parameter lists for all discovered endpoints
- Recommendations for removing/securing exposed content

OPTIMIZED WORDLISTS:
- **Small (fast)**: /usr/share/seclists/Discovery/Web-Content/common.txt (~4k entries)
- **Medium**: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt (~30k)
- **Large (comprehensive)**: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt (~220k)
- **Technology-specific**: /usr/share/seclists/Discovery/Web-Content/CMS/ (WordPress, Joomla, etc.)
- **API-focused**: /usr/share/seclists/Discovery/Web-Content/api/ (common API paths)

TOOLS REFERENCE:
- **Burp Suite**: https://portswigger.net/burp (Industry standard spider + fuzzer)
- **OWASP ZAP**: https://www.zaproxy.org/ (Open-source security scanner)
- **Gobuster**: https://github.com/OJ/gobuster (Fast directory bruteforcer)
- **Feroxbuster**: https://github.com/epi052/feroxbuster (Modern recursive scanner)
- **ffuf**: https://github.com/ffuf/ffuf (Fast web fuzzer)
- **Dirsearch**: https://github.com/maurosoria/dirsearch (Python directory scanner)
- **Hakrawler**: https://github.com/hakluke/hakrawler (Fast web crawler)
- **GoSpider**: https://github.com/jaeles-project/gospider (Fast spider with JS parsing)
- **LinkFinder**: https://github.com/GerbenJavado/LinkFinder (Extract endpoints from JS)
- **ParamSpider**: https://github.com/devanshbatham/ParamSpider (Parameter discovery)
- **Arjun**: https://github.com/s0md3v/Arjun (HTTP parameter discovery)

FURTHER READING:
- OWASP WSTG-INFO-05: Review Webpage Content for Information Leakage
- OWASP WSTG-INFO-07: Map Application Architecture
- OWASP WSTG-CONF-05: Enumerate Infrastructure and Application Admin Interfaces
- NIST SP 800-115: Section 7.4 - Web Application Testing
- SecLists: https://github.com/danielmiessler/SecLists (Comprehensive wordlists)
- PTES Technical Guidelines: Section 3.3 - Intelligence Gathering"
    ),
    (
        "TLS/SSL assessment",
        "OBJECTIVE: Comprehensively evaluate SSL/TLS configurations, certificate validity, cipher suite strength, and protocol vulnerabilities to identify encryption weaknesses and potential man-in-the-middle attack vectors.

ACADEMIC BACKGROUND:
Transport Layer Security (TLS) and its predecessor SSL are cryptographic protocols that provide secure communications over networks. According to OWASP WSTG-CRYP-01 (Testing for Weak Transport Layer Security), improper TLS configuration is one of the most common security issues affecting web applications.

The NIST SP 800-52 Rev.2 \"Guidelines for the Selection, Configuration, and Use of TLS\" mandates:
- TLS 1.2 or higher (TLS 1.3 preferred)
- Strong cipher suites with forward secrecy
- Valid certificates from trusted Certificate Authorities
- Proper certificate validation and hostname verification

The MITRE ATT&CK framework identifies improper TLS configuration under T1040 (Network Sniffing) and T1557 (Adversary-in-the-Middle), as weak cryptography enables interception of sensitive communications.

CRITICAL TLS VULNERABILITIES:
- **Heartbleed (CVE-2014-0160)**: OpenSSL memory disclosure
- **POODLE (CVE-2014-3566)**: SSLv3 padding oracle
- **BEAST (CVE-2011-3389)**: TLS 1.0 CBC cipher attack
- **CRIME (CVE-2012-4929)**: TLS compression attack
- **FREAK (CVE-2015-0204)**: Export cipher downgrade
- **Logjam (CVE-2015-4000)**: Diffie-Hellman downgrade
- **DROWN (CVE-2016-0800)**: SSLv2 cross-protocol attack
- **SWEET32 (CVE-2016-2183)**: 64-bit block cipher attack

STEP-BY-STEP PROCESS:

1. CERTIFICATE INSPECTION AND VALIDATION:
   a) Basic Certificate Retrieval:
      ```bash
      # Retrieve certificate from server
      openssl s_client -connect target.com:443 -servername target.com < /dev/null 2>/dev/null | openssl x509 -text -noout
      
      # Save certificate to file
      echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 > target.crt
      
      # View certificate details
      openssl x509 -in target.crt -text -noout
      
      # Check certificate expiration
      openssl x509 -in target.crt -noout -dates
      
      # Extract subject and issuer
      openssl x509 -in target.crt -noout -subject -issuer
      
      # Check certificate fingerprint (SHA256)
      openssl x509 -in target.crt -noout -fingerprint -sha256
      ```
   
   b) Certificate Chain Verification:
      ```bash
      # Verify certificate chain
      openssl s_client -connect target.com:443 -showcerts
      
      # Verify against system CA bundle
      openssl verify target.crt
      
      # Verify with specific CA file
      openssl verify -CAfile ca-bundle.crt target.crt
      
      # Check certificate chain completeness
      openssl s_client -connect target.com:443 -servername target.com -showcerts 2>/dev/null | grep -E '(BEGIN CERTIFICATE|END CERTIFICATE|subject=|issuer=)'
      ```
   
   c) Subject Alternative Names (SAN) Analysis:
      ```bash
      # Extract all SANs (reveals internal domains)
      openssl x509 -in target.crt -noout -text | grep -A1 'Subject Alternative Name'
      
      # Parse SANs to list
      openssl x509 -in target.crt -noout -text | grep -oP 'DNS:\\K[^,]+'
      
      # Check for wildcard certificates
      openssl x509 -in target.crt -noout -subject | grep -o '\\*\\.'
      ```
      
      Intelligence gathering:
      - Internal hostnames in SANs
      - Infrastructure naming conventions
      - Wildcard usage patterns
      - Multiple domains on same certificate

2. COMPREHENSIVE TLS CONFIGURATION SCANNING:
   a) SSLScan (Fast Basic Analysis):
      ```bash
      # Basic SSL/TLS scan
      sslscan target.com
      
      # IPv6 scan
      sslscan --ipv6 target.com
      
      # Specify port
      sslscan target.com:8443
      
      # XML output for parsing
      sslscan --xml=sslscan_results.xml target.com
      ```
      
      Key findings:
      - Supported TLS versions
      - Accepted cipher suites
      - Certificate details
      - TLS compression status
   
   b) testssl.sh (Most Comprehensive):
      ```bash
      # Full comprehensive scan
      ./testssl.sh target.com
      
      # Fast scan (basic checks)
      ./testssl.sh --fast target.com
      
      # Check specific vulnerabilities
      ./testssl.sh --vulnerable target.com
      
      # Check only protocol support
      ./testssl.sh --protocols target.com
      
      # Check cipher suites
      ./testssl.sh --ciphers target.com
      
      # Check certificate
      ./testssl.sh --server-defaults target.com
      
      # JSON output
      ./testssl.sh --jsonfile results.json target.com
      
      # HTML report
      ./testssl.sh --htmlfile report.html target.com
      
      # Scan multiple hosts
      ./testssl.sh --file hosts.txt
      
      # Parallel scanning (4 connections)
      ./testssl.sh --parallel target.com
      ```
      
      testssl.sh checks:
      - All TLS vulnerabilities (Heartbleed, POODLE, BEAST, CRIME, etc.)
      - Protocol versions (SSLv2, SSLv3, TLS 1.0-1.3)
      - Cipher suite strength and order
      - Forward secrecy support
      - Certificate validity and trust chain
      - HSTS, HPKP headers
      - Certificate Transparency compliance
   
   c) Nmap SSL Scripts:
      ```bash
      # SSL enum ciphers
      nmap --script ssl-enum-ciphers -p 443 target.com
      
      # Check all SSL vulnerabilities
      nmap --script ssl-* -p 443 target.com
      
      # Specific vulnerability checks
      nmap --script ssl-heartbleed -p 443 target.com
      nmap --script ssl-poodle -p 443 target.com
      nmap --script ssl-dh-params -p 443 target.com
      
      # Certificate information
      nmap --script ssl-cert -p 443 target.com
      
      # Check for weak cipher suites
      nmap --script ssl-known-key -p 443 target.com
      ```
   
   d) sslyze (Python-based Analysis):
      ```bash
      # Comprehensive scan
      sslyze target.com
      
      # Check specific vulnerability
      sslyze --heartbleed target.com
      
      # Certificate info
      sslyze --certinfo target.com
      
      # Check cipher suites
      sslyze --sslv2 --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 target.com
      
      # JSON output
      sslyze --json_out=results.json target.com
      ```

3. PROTOCOL VERSION TESTING:
   ```bash
   # Test SSLv2 (should fail - deprecated since 2011)
   openssl s_client -connect target.com:443 -ssl2
   
   # Test SSLv3 (should fail - deprecated since 2015)
   openssl s_client -connect target.com:443 -ssl3
   
   # Test TLS 1.0 (should fail - deprecated since 2020)
   openssl s_client -connect target.com:443 -tls1
   
   # Test TLS 1.1 (should fail - deprecated since 2020)
   openssl s_client -connect target.com:443 -tls1_1
   
   # Test TLS 1.2 (should succeed - minimum requirement)
   openssl s_client -connect target.com:443 -tls1_2
   
   # Test TLS 1.3 (should succeed - current standard)
   openssl s_client -connect target.com:443 -tls1_3
   
   # Check protocol support summary
   for version in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
       echo -n \"Testing $version: \"
       timeout 2 openssl s_client -connect target.com:443 -$version < /dev/null 2>&1 | grep -q 'Cipher' && echo \"SUPPORTED\" || echo \"Not supported\"
   done
   ```

4. CIPHER SUITE ANALYSIS:
   ```bash
   # List all accepted ciphers
   nmap --script ssl-enum-ciphers -p 443 target.com
   
   # Test specific cipher
   openssl s_client -connect target.com:443 -cipher 'AES128-SHA'
   
   # Check for weak ciphers (NULL, EXPORT, DES, RC4, MD5)
   ./testssl.sh --ciphers target.com | grep -iE '(null|export|des|rc4|md5|weak)'
   
   # Check cipher order (server vs client preference)
   ./testssl.sh --server-preference target.com
   
   # Verify forward secrecy
   ./testssl.sh --fs target.com
   ```
   
   Cipher Suite Strength:
   - **Weak**: DES, 3DES, RC4, MD5, NULL, EXPORT, ANON
   - **Medium**: AES-CBC without forward secrecy
   - **Strong**: AES-GCM, ChaCha20-Poly1305 with ECDHE/DHE
   - **Modern**: TLS 1.3 cipher suites (AES-GCM, ChaCha20)

5. VULNERABILITY-SPECIFIC TESTING:
   a) Heartbleed (CVE-2014-0160):
      ```bash
      # Nmap check
      nmap -p 443 --script ssl-heartbleed target.com
      
      # testssl.sh check
      ./testssl.sh -H target.com
      
      # Manual check with python script
      python heartbleed-poc.py target.com 443
      ```
   
   b) POODLE (CVE-2014-3566):
      ```bash
      # Check SSLv3 support
      nmap -p 443 --script ssl-poodle target.com
      
      # testssl.sh check
      ./testssl.sh -O target.com
      ```
   
   c) BEAST (CVE-2011-3389):
      ```bash
      # Check TLS 1.0 CBC ciphers
      nmap -p 443 --script ssl-enum-ciphers target.com | grep -A20 'TLSv1.0' | grep CBC
      
      # testssl.sh check
      ./testssl.sh -B target.com
      ```
   
   d) CRIME (CVE-2012-4929):
      ```bash
      # Check TLS compression
      nmap -p 443 --script ssl-enum-ciphers target.com | grep -i compression
      
      # testssl.sh check
      ./testssl.sh -C target.com
      ```
   
   e) FREAK (CVE-2015-0204):
      ```bash
      # Check for EXPORT ciphers
      nmap -p 443 --script ssl-enum-ciphers target.com | grep -i export
      
      # testssl.sh check
      ./testssl.sh -F target.com
      ```
   
   f) Logjam (CVE-2015-4000):
      ```bash
      # Check DH parameters
      nmap -p 443 --script ssl-dh-params target.com
      
      # testssl.sh check
      ./testssl.sh -J target.com
      ```
   
   g) DROWN (CVE-2016-0800):
      ```bash
      # Check SSLv2 support
      ./testssl.sh -D target.com
      ```
   
   h) SWEET32 (CVE-2016-2183):
      ```bash
      # Check for 64-bit block ciphers (3DES, DES, Blowfish)
      ./testssl.sh --sweet32 target.com
      ```

6. CERTIFICATE TRANSPARENCY AND MONITORING:
   ```bash
   # Check Certificate Transparency logs
   curl -s \"https://crt.sh/?q=%.target.com&output=json\" | jq -r '.[].name_value' | sort -u
   
   # Verify CT compliance
   ./testssl.sh --ct target.com
   
   # Check for certificate issuance history
   curl -s \"https://crt.sh/?q=target.com&output=json\" | jq -r '.[] | \"\\(.not_before) - \\(.issuer_name)\"'
   ```

7. HTTP SECURITY HEADERS RELATED TO TLS:
   ```bash
   # Check HSTS (HTTP Strict Transport Security)
   curl -I https://target.com | grep -i strict-transport-security
   
   # Check HSTS with testssl.sh
   ./testssl.sh --headers target.com | grep -i HSTS
   
   # Check for HSTS preload eligibility
   curl -s https://hstspreload.org/api/v2/status?domain=target.com | jq
   
   # Verify HPKP (deprecated but may exist)
   curl -I https://target.com | grep -i public-key-pins
   ```

8. CERTIFICATE REVOCATION CHECKING:
   ```bash
   # Check OCSP (Online Certificate Status Protocol)
   openssl ocsp -issuer ca.crt -cert target.crt -url http://ocsp.server.com -resp_text
   
   # Check CRL (Certificate Revocation List)
   openssl x509 -in target.crt -noout -text | grep -A4 'CRL Distribution'
   
   # Verify OCSP stapling
   openssl s_client -connect target.com:443 -status -servername target.com < /dev/null 2>&1 | grep -A10 'OCSP'
   ```

WHAT TO LOOK FOR:
- **Deprecated Protocols**: SSLv2, SSLv3, TLS 1.0, TLS 1.1 (all deprecated)
- **Weak Ciphers**: DES, 3DES, RC4, MD5-based, NULL, EXPORT, ANON
- **Missing Forward Secrecy**: Ciphers without DHE or ECDHE
- **Self-Signed Certificates**: In production environments
- **Expired Certificates**: Past validity period
- **Certificate Mismatch**: Domain name doesn't match certificate CN/SAN
- **Incomplete Chain**: Missing intermediate certificates
- **Weak Key Length**: RSA < 2048 bits, ECDSA < 256 bits
- **Untrusted CA**: Certificate signed by unknown/untrusted authority
- **Missing HSTS**: No Strict-Transport-Security header
- **Compression Enabled**: TLS compression (CRIME vulnerability)
- **Known Vulnerabilities**: Heartbleed, POODLE, BEAST, FREAK, Logjam, DROWN

SECURITY IMPLICATIONS:
- **SSLv2/SSLv3**: Completely broken, enables DROWN and POODLE attacks
- **TLS 1.0/1.1**: Vulnerable to BEAST, deprecated by major browsers
- **Weak Ciphers**: Allow brute-force or cryptanalytic attacks
- **No Forward Secrecy**: Past communications can be decrypted if private key compromised
- **Heartbleed**: Memory disclosure, can leak private keys and session data
- **POODLE**: Padding oracle attack, plaintext recovery
- **Self-Signed Certs**: Enable man-in-the-middle attacks
- **Expired Certs**: Browser warnings, user trust issues
- **Missing HSTS**: Allows SSL stripping attacks
- **Weak DH Parameters**: Logjam attack, weakens key exchange

COMMON PITFALLS:
- **Internal Services**: May legitimately use self-signed certificates
- **Legacy System Support**: Some old systems require TLS 1.0 for compatibility
- **Load Balancer Termination**: TLS terminated at load balancer, backend may be HTTP
- **Certificate Pinning**: Can break with legitimate certificate renewals
- **Multiple Virtual Hosts**: Different certificates per domain on same IP
- **CDN/WAF**: May have different TLS config than origin server
- **Port Variations**: Different TLS configs on non-standard ports (8443, 8080)
- **False Positives**: Some scanners report issues not applicable to specific scenarios
- **SNI Requirements**: Server Name Indication needed for virtual hosting

DOCUMENTATION REQUIREMENTS:
- **TLS Configuration Matrix**:
  | Protocol | Status | Cipher Suites | Vulnerabilities |
  |----------|--------|---------------|-----------------|
  | TLS 1.3 | Enabled | AES-GCM, ChaCha20 | None |
  | TLS 1.2 | Enabled | AES-GCM, ECDHE | None |
  | TLS 1.1 | Disabled | N/A | BEAST |
  
- Certificate details (issuer, expiration, SANs, key length)
- Vulnerability scan results (Heartbleed, POODLE, etc.)
- Cipher suite strength analysis
- Forward secrecy support status
- HSTS configuration and preload status
- Evidence screenshots of configuration weaknesses
- Comparison against NIST/Mozilla guidelines
- Recommendations for TLS hardening

COMPLIANCE REFERENCES:
- **PCI DSS 3.2.1**: Requires TLS 1.2+ for payment card data
- **NIST SP 800-52 Rev.2**: Federal TLS configuration guidelines
- **Mozilla SSL Configuration**: https://ssl-config.mozilla.org/ (Modern/Intermediate/Old profiles)
- **FIPS 140-2**: Cryptographic module validation
- **HIPAA**: Strong encryption for health data
- **GDPR**: Encryption as privacy safeguard

TOOLS REFERENCE:
- **testssl.sh**: https://testssl.sh/ (Most comprehensive CLI scanner)
- **SSLScan**: https://github.com/rbsec/sslscan (Fast basic scanner)
- **sslyze**: https://github.com/nabla-c0d3/sslyze (Python-based analysis)
- **Nmap SSL Scripts**: https://nmap.org/nsedoc/categories/ssl.html (Built-in to Nmap)
- **SSL Labs**: https://www.ssllabs.com/ssltest/ (Online comprehensive testing)
- **Certificate Transparency**: https://crt.sh/ (Certificate search)
- **HSTS Preload**: https://hstspreload.org/ (HSTS verification)

FURTHER READING:
- OWASP WSTG-CRYP-01: Testing for Weak Transport Layer Security
- NIST SP 800-52 Rev.2: Guidelines for TLS Implementation
- RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
- RFC 6797: HTTP Strict Transport Security (HSTS)
- Mozilla Server Side TLS: https://wiki.mozilla.org/Security/Server_Side_TLS
- SSL/TLS Best Practices by Qualys: https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices"
    ),
    (
        "Infrastructure mapping",
        "OBJECTIVE: Map the complete network infrastructure, topology, and architecture to understand organizational structure, identify key network assets, and discover potential attack paths through infrastructure relationships.

STEP-BY-STEP PROCESS:

1. AUTONOMOUS SYSTEM (AS) AND BGP ANALYSIS:
   ```bash
   # Find organization's AS number
   whois -h whois.radb.net target.com | grep -i origin
   
   # Get all IP ranges for an AS
   whois -h whois.radb.net -- '-i origin AS12345' | grep -E \"^route:\"
   
   # BGP toolkit queries
   curl \"https://bgp.he.net/AS12345\" -s | grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+'
   
   # Check peering relationships
   whois -h whois.radb.net -- '-i origin AS12345' | grep -i \"import\\|export\"
   ```

2. NETWORK TOPOLOGY MAPPING:
   ```bash
   # Traceroute analysis
   traceroute -I target.com
   mtr --report target.com  # Better than traceroute
   
   # Paris traceroute (avoids load balancing issues)
   paris-traceroute target.com
   
   # TCP traceroute (when ICMP blocked)
   tcptraceroute target.com 443
   ```

3. CDN AND WAF DETECTION:
   ```bash
   # Check for CDN via headers and DNS
   curl -I https://target.com | grep -iE '(cf-ray|x-amz|x-cache|server)'
   
   # WAF detection with wafw00f
   wafw00f https://target.com
   
   # Identify CDN provider
   dig target.com | grep -A2 'ANSWER SECTION'
   ```

WHAT TO LOOK FOR:
- Network boundaries and segmentation
- Cloud vs on-premise infrastructure
- CDN and load balancer configurations
- Redundancy and failover mechanisms
- Third-party service dependencies

COMMON PITFALLS:
- Traceroute may be blocked by firewalls
- Cloud infrastructure uses dynamic IPs
- CDN masks origin server details
- Virtual networks complicate topology mapping
- Infrastructure documentation may be outdated"
    ),
    (
        "Cloud asset discovery",
        "OBJECTIVE: Identify cloud-hosted assets including storage buckets, compute instances, databases, and serverless functions that may contain sensitive data or misconfigurations.

STEP-BY-STEP PROCESS:

1. S3 BUCKET ENUMERATION (AWS):
   ```bash
   # S3Scanner (bucket discovery and permissions)
   python3 s3scanner.py --list bucket-names.txt
   
   # Test public access
   aws s3 ls s3://target-company-backup --no-sign-request
   
   # Common naming patterns
   for name in backup dev staging prod logs assets; do
       aws s3 ls s3://target-$name --no-sign-request 2>&1
   done
   
   # Cloud_enum (multi-cloud discovery)
   python3 cloud_enum.py -k target-company
   ```

2. AZURE AND GCP ENUMERATION:
   ```bash
   # Azure storage enumeration
   python3 MicroBurst.py -d target.com
   
   # GCP bucket scanning
   python3 GCPBucketBrute.py -k target-company
   
   # Check common patterns
   curl https://target-backup.storage.googleapis.com/
   curl https://targetstorageaccount.blob.core.windows.net/
   ```

3. CLOUD SERVICE IDENTIFICATION:
   ```bash
   # Check for cloud metadata endpoints
   curl http://169.254.169.254/latest/meta-data/ # AWS
   curl -H \"Metadata:true\" http://169.254.169.254/metadata/instance # Azure
   
   # Identify cloud functions
   curl https://us-central1-project-id.cloudfunctions.net/function-name
   ```

WHAT TO LOOK FOR:
- Publicly accessible storage buckets
- Exposed API keys and credentials
- Misconfigured permissions (public read/write)
- Development/staging cloud resources
- Unencrypted data at rest

SECURITY IMPLICATIONS:
- Public S3 buckets can leak sensitive data
- Writable buckets enable malware hosting
- Exposed cloud functions may execute arbitrary code
- Metadata endpoints reveal infrastructure details
- Misconfigured IAM policies grant excessive permissions

COMMON PITFALLS:
- Some buckets are intentionally public (CDN assets)
- Cloud providers rate-limit enumeration attempts
- Bucket names may not follow predictable patterns
- Regional differences affect accessibility
- Authentication may be required for full enumeration

TOOLS REFERENCE:
- cloud_enum: https://github.com/initstring/cloud_enum
- S3Scanner: https://github.com/sa7mon/S3Scanner
- MicroBurst: https://github.com/NetSPI/MicroBurst (Azure)
- GCPBucketBrute: https://github.com/RhinoSecurityLabs/GCPBucketBrute"
    ),
    (
        "Email reconnaissance",
        "OBJECTIVE: Gather email addresses, identify email infrastructure, and collect personnel information for social engineering preparation and authentication attack targeting.

STEP-BY-STEP PROCESS:

1. EMAIL ADDRESS HARVESTING:
   ```bash
   # theHarvester (comprehensive OSINT)
   theHarvester -d target.com -l 500 -b all -f results.html
   
   # Hunter.io API
   curl \"https://api.hunter.io/v2/domain-search?domain=target.com&api_key=YOUR_KEY\"
   
   # LinkedIn scraping for emails
   python3 linkedin2username.py -c \"Target Company\" -n 100
   
   # Email pattern recognition
   # Common patterns: firstname.lastname@, first.last@, flast@
   ```

2. EMAIL SERVER ENUMERATION:
   ```bash
   # Check MX records
   dig target.com MX
   
   # Identify email provider
   nslookup $(dig target.com MX +short | head -1 | awk \'{print $2}\')
   
   # SMTP banner grabbing
   nc target.com 25
   
   # Test for VRFY/EXPN commands
   telnet target.com 25
   VRFY admin
   EXPN postmaster
   
   # Check email security (SPF, DMARC, DKIM)
   dig target.com TXT | grep -E \'(spf|dmarc)\'
   dig _dmarc.target.com TXT
   ```

WHAT TO LOOK FOR:
- Email addresses of executives and IT staff
- Email naming conventions and patterns
- Weak SPF/DMARC configurations (email spoofing risk)
- Open relay misconfiguration
- VRFY/EXPN enabled (user enumeration)
- Employee LinkedIn profiles with contact info

SECURITY IMPLICATIONS:
- Email addresses enable targeted phishing
- Weak email security allows spoofing
- Personnel information aids social engineering
- VRFY command leaks valid usernames
- Email patterns enable credential stuffing

COMMON PITFALLS:
- Some email addresses are role-based not personal
- Privacy laws limit data collection
- Email harvesting tools may be rate-limited
- Organizations may use email aliases
- SMTP enumeration may trigger security alerts

TOOLS REFERENCE:
- theHarvester: https://github.com/laramies/theHarvester
- Hunter.io: https://hunter.io/ (Email finder API)
- CrossLinked: https://github.com/m8r0wn/CrossLinked (LinkedIn scraper)"
    ),
    (
        "Screenshot capture",
        "OBJECTIVE: Create visual documentation of all discovered web assets for evidence collection, visual comparison, and identification of interesting pages requiring further investigation.

STEP-BY-STEP PROCESS:

1. AUTOMATED SCREENSHOT TOOLS:
   ```bash
   # EyeWitness (comprehensive with report)
   python3 EyeWitness.py -f urls.txt --web --timeout 10 -d screenshots
   
   # Gowitness (fast Go-based)
   gowitness scan file -f urls.txt --threads 10 --timeout 10
   
   # Aquatone (pipeline-friendly)
   cat urls.txt | aquatone -out aquatone_report
   
   # HTTPScreenshot (Nmap integration)
   nmap -p 80,443,8080,8443 target.com --script http-screenshot
   
   # Webscreenshot (Python simple)
   python webscreenshot.py -i urls.txt -o screenshots/
   ```

2. RESPONSIVE DESIGN CAPTURE:
   ```bash
   # Multiple viewport sizes
   gowitness scan single --url https://target.com --resolution 1920x1080
   gowitness scan single --url https://target.com --resolution 768x1024  # Tablet
   gowitness scan single --url https://target.com --resolution 375x667   # Mobile
   ```

3. AUTHENTICATED SCREENSHOTS:
   ```bash
   # EyeWitness with cookies
   python3 EyeWitness.py -f urls.txt --web --cookie \"session=abc123\"
   
   # Aquatone with headers
   cat urls.txt | aquatone -H \"Authorization: Bearer token123\"
   ```

WHAT TO LOOK FOR:
- Default error pages revealing software versions
- Admin/login interfaces
- Exposed development/staging environments
- Unusual or legacy applications
- Custom applications worth investigating

COMMON PITFALLS:
- Screenshots may not capture dynamic JavaScript content
- Authentication states can expire during capture
- Some pages require specific user-agents or cookies
- AJAX-loaded content may be missed
- Rate limiting can slow down bulk screenshot capture

TOOLS REFERENCE:
- EyeWitness: https://github.com/FortyNorthSecurity/EyeWitness
- Gowitness: https://github.com/sensepost/gowitness
- Aquatone: https://github.com/michenriksen/aquatone"
    ),
    (
        "JavaScript analysis",
        "OBJECTIVE: Extract and analyze JavaScript files to discover hidden API endpoints, exposed secrets, client-side logic vulnerabilities, and sensitive information hardcoded in frontend code.

STEP-BY-STEP PROCESS:

1. JAVASCRIPT FILE COLLECTION:
   ```bash
   # Extract all JS files from target
   echo \"https://target.com\" | hakrawler | grep -E '\\.js($|\\?)' > js_files.txt
   
   # Using getJS
   getJS --url https://target.com --output jsfiles.txt
   
   # Download all JS files
   wget -i js_files.txt -P js_downloads/
   ```

2. ENDPOINT EXTRACTION FROM JS:
   ```bash
   # LinkFinder (regex-based endpoint extraction)
   python3 linkfinder.py -i https://target.com/app.js -o cli
   
   # Extract API endpoints
   grep -rEo \"(https?://|/)(api|v[0-9])[^'\\\"\\s]*\" js_downloads/ | sort -u
   
   # Find internal URLs
   grep -rEo \"(https?://)?(www\\.)?target\\.com[^'\\\"\\s]*\" js_downloads/ | sort -u
   ```

3. SECRET AND API KEY HUNTING:
   ```bash
   # Search for common secret patterns
   grep -rEi \"(api[_-]?key|apikey|api_secret|access[_-]?token|auth[_-]?token|client[_-]?secret)\" js_downloads/
   
   # AWS keys
   grep -rE \"AKIA[0-9A-Z]{16}\" js_downloads/
   
   # Private keys
   grep -rE \"BEGIN.*PRIVATE KEY\" js_downloads/
   
   # Passwords and credentials
   grep -rEi \"(password|passwd|pwd)\\s*[:=]\\s*['\\\"][^'\\\"]{6,}\" js_downloads/
   
   # Nuclei secret scanning
   nuclei -t exposures/ -l js_files.txt
   ```

4. SOURCE MAP ANALYSIS:
   ```bash
   # Find .map files
   grep -rE '\\.js\\.map' js_downloads/ > source_maps.txt
   
   # Download source maps
   cat source_maps.txt | while read map; do wget \"$map\"; done
   
   # Extract original source from maps
   python3 sourcemapper.py -u https://target.com/app.js.map
   ```

5. WEBPACK AND BUILD ANALYSIS:
   ```bash
   # Identify webpack bundles
   grep -l \"webpackJsonp\" js_downloads/*.js
   
   # Extract webpack module paths
   grep -oP '/\\*.*?\\*/' js_downloads/bundle.js | sort -u
   ```

WHAT TO LOOK FOR:
- Hardcoded API keys and tokens
- Internal API endpoints not in documentation
- AWS/GCP/Azure credentials
- Database connection strings
- Admin panel URLs
- Debug/development endpoints
- OAuth secrets and client IDs
- Encryption keys and salts

SECURITY IMPLICATIONS:
- Exposed API keys grant unauthorized access
- Hardcoded credentials enable authentication bypass
- Hidden endpoints may lack security controls
- Source maps reveal original unobfuscated code
- Client-side validation can be bypassed

COMMON PITFALLS:
- Minified code requires de-obfuscation tools
- Some API keys are intentionally public (analytics)
- Dynamic JavaScript loading may be missed
- Source maps may not be available for all files
- Obfuscated code can hide analysis-resistant techniques

TOOLS REFERENCE:
- LinkFinder: https://github.com/GerbenJavado/LinkFinder
- getJS: https://github.com/003random/getJS
- SecretFinder: https://github.com/m4ll0k/SecretFinder
- JSParser: https://github.com/nahamsec/JSParser"
    ),
    (
        "Parameter discovery",
        "OBJECTIVE: Identify all input parameters including GET/POST parameters, API parameters, and hidden form fields to establish complete attack surface for injection testing and fuzzing.

STEP-BY-STEP PROCESS:

1. URL PARAMETER EXTRACTION:
   ```bash
   # ParamSpider (URL parameter collection from archives)
   python3 paramspider.py -d target.com -o params.txt
   
   # Extract unique parameter names
   cat params.txt | grep -oP '(?<=[?&])[^=&]+' | sort -u > unique_params.txt
   
   # GAU (Get All URLs from archives)
   echo target.com | gau | grep \"=\" > urls_with_params.txt
   ```

2. HIDDEN PARAMETER DISCOVERY (FUZZING):
   ```bash
   # Arjun (HTTP parameter discovery)
   arjun -u https://target.com/api/users -m GET
   arjun -u https://target.com/api/users -m POST
   
   # x8 (hidden parameter discovery)
   x8 -u \"https://target.com/api/users\" -w params.txt
   
   # Param Miner (Burp extension)
   # Install via Burp Extender, right-click request → \"Guess params\"
   ```

3. API PARAMETER ENUMERATION:
   ```bash
   # GraphQL introspection
   python3 graphql-introspection.py https://target.com/graphql
   
   # REST API parameter extraction
   curl -s https://target.com/api/swagger.json | jq '.paths[][].parameters[].name' | sort -u
   
   # Test parameter variations
   ffuf -u https://target.com/api/users?FUZZ=test -w params.txt -mc 200
   ```

4. FORM PARAMETER IDENTIFICATION:
   ```bash
   # Extract forms and inputs
   curl -s https://target.com | grep -Eo '<(input|select|textarea)[^>]*' | grep -Eo 'name=\"[^\"]*\"'
   
   # Find hidden inputs
   curl -s https://target.com | grep -Eo '<input[^>]*type=\"hidden\"[^>]*>'
   ```

WHAT TO LOOK FOR:
- Parameters controlling application logic
- File upload parameters
- Sorting/filtering parameters (SQL injection risk)
- Callback/redirect parameters (open redirect risk)
- Template parameters (SSTI risk)
- Command parameters (command injection risk)
- Debug/admin parameters
- API versioning parameters

SECURITY IMPLICATIONS:
- Hidden parameters may bypass security controls
- Undocumented parameters often lack input validation
- Debug parameters may expose sensitive information
- Admin parameters may grant elevated privileges

COMMON PITFALLS:
- Some parameters only available after authentication
- AJAX requests may use different parameter formats
- Parameters may be encoded or encrypted
- Rate limiting can slow parameter fuzzing
- GraphQL and REST APIs use different parameter structures

TOOLS REFERENCE:
- Arjun: https://github.com/s0md3v/Arjun
- ParamSpider: https://github.com/devanshbatham/ParamSpider
- x8: https://github.com/Sh1Yo/x8
- GAU: https://github.com/lc/gau"
    ),
    (
        "Public exposure scanning",
        "OBJECTIVE: Identify internet-facing assets and services using global scanning engines to discover shadow IT, forgotten systems, and publicly exposed resources that should not be accessible.

STEP-BY-STEP PROCESS:

1. SHODAN RECONNAISSANCE:
   ```bash
   # Search by organization name
   shodan search \"org:Target Company\"
   
   # Search by domain
   shodan search \"hostname:target.com\"
   
   # Search by IP range
   shodan search \"net:192.168.1.0/24\"
   
   # Find specific services
   shodan search \"target.com port:3389\"  # RDP
   shodan search \"target.com port:22\"    # SSH
   shodan search \"target.com mongodb\"     # MongoDB
   
   # Download results
   shodan download results \"org:Target Company\"
   shodan parse --fields ip_str,port,product results.json.gz
   ```

2. CENSYS SCANNING:
   ```bash
   # Search via API
   curl -X POST https://search.censys.io/api/v2/hosts/search \
        -u API_ID:API_SECRET \
        -d '{\"q\":\"services.service_name: HTTP and target.com\"}'
   
   # Web interface search
   # services.service_name: SSH and target.com
   # services.service_name: RDP and target.com
   ```

3. ADDITIONAL SCANNING ENGINES:
   ```bash
   # ZoomEye
   python3 zoomeye.py search \"target.com\"
   
   # BinaryEdge
   curl \"https://api.binaryedge.io/v2/query/search?query=target.com\" \
        -H \"X-Key: API_KEY\"
   
   # FOFA (Chinese search engine)
   # domain=\"target.com\"
   ```

4. VULNERABILITY SCANNING (NUCLEI):
   ```bash
   # Scan discovered hosts for known vulnerabilities
   nuclei -l hosts.txt -t cves/ -t exposures/ -t vulnerabilities/
   
   # Specific technology checks
   nuclei -l hosts.txt -t technologies/
   
   # Scan for misconfigurations
   nuclei -l hosts.txt -t misconfiguration/
   ```

WHAT TO LOOK FOR:
- Exposed databases (MongoDB, Elasticsearch, Redis)
- RDP/VNC without authentication
- Exposed admin panels (phpMyAdmin, cPanel)
- Development servers on public internet
- IoT devices and cameras
- Default credentials on services
- Vulnerable service versions

SECURITY IMPLICATIONS:
- Exposed databases enable data exfiltration
- Open remote access services enable lateral movement
- Default credentials provide immediate access
- Shadow IT bypasses security controls
- Forgotten systems lack security patches

COMMON PITFALLS:
- Some exposures are intentional (public APIs CDN assets)
- Shodan/Censys data may be outdated
- Rate limiting affects bulk queries
- Some services require paid API access
- Regional scanning restrictions may apply

TOOLS REFERENCE:
- Shodan: https://www.shodan.io/
- Censys: https://search.censys.io/
- Nuclei: https://github.com/projectdiscovery/nuclei
- ZoomEye: https://www.zoomeye.org/"
    ),
    (
        "WHOIS domain analysis",
        "OBJECTIVE: Extract domain registration information including ownership, contacts, registration dates, and name servers to understand organizational structure and identify additional assets.

STEP-BY-STEP PROCESS:

1. BASIC WHOIS QUERIES:
   ```bash
   # Standard WHOIS lookup
   whois target.com
   
   # Specific WHOIS server
   whois -h whois.verisign-grs.com target.com
   
   # RDAP (modern alternative)
   curl https://rdap.org/domain/target.com | jq
   ```

2. EXTRACT KEY INFORMATION:
   ```bash
   # Registrar information
   whois target.com | grep -i registrar
   
   # Name servers
   whois target.com | grep -i \"name server\"
   
   # Registration dates
   whois target.com | grep -iE \"(creation|expir|updated) date\"
   ```

WHAT TO LOOK FOR:
- Registrant organization and contacts
- WHOIS privacy protection status
- Recent registration or transfer dates
- Domain expiration date
- Related domains with same registrant

COMMON PITFALLS:
- WHOIS privacy services hide real owner information
- Some TLDs have restricted WHOIS data
- Historical data may not be available
- Contact information may be outdated
- Rate limiting affects bulk WHOIS queries

TOOLS REFERENCE:
- whois: Built-in command
- WhoisXML API: https://www.whoisxmlapi.com/
- DomainTools: https://www.domaintools.com/"
    ),
    (
        "Social media reconnaissance",
        "OBJECTIVE: Gather intelligence from social media platforms about target organization and personnel for social engineering preparation.

STEP-BY-STEP PROCESS:

1. LINKEDIN RECONNAISSANCE:
   ```bash
   # CrossLinked (LinkedIn employee scraping)
   python3 CrossLinked.py -f \'{first}.{last}@target.com\' \"Target Company\"
   
   # linkedin2username (username generation)
   python3 linkedin2username.py -c \"Target Company\" -n 100
   ```

2. TWITTER/X INTELLIGENCE:
   ```bash
   # Twint (Twitter scraping without API)
   twint -s \"target.com OR @targetcompany\" --email
   
   # Search for employee tweets
   twint -s \"from:employeehandle\" -o tweets.txt
   ```

3. GITHUB/GITLAB RECON:
   ```bash
   # Search for organization repos
   curl \"https://api.github.com/orgs/targetcompany/repos\" | jq
   
   # Find employee accounts
   curl \"https://api.github.com/search/users?q=@target.com\" | jq
   
   # GitDorker (GitHub secrets scanning)
   python3 GitDorker.py -tf tokens.txt -q target.com -d dorks/
   ```

WHAT TO LOOK FOR:
- Employee names and job titles
- Technology stack mentions
- Organizational structure
- Security awareness levels
- Potential social engineering vectors

SECURITY IMPLICATIONS:
- Employee information enables targeted phishing
- Technology mentions reveal infrastructure
- Loose security awareness indicates vulnerability
- Personal information aids pretexting attacks

COMMON PITFALLS:
- Social media data may be outdated
- Privacy settings limit information access
- Information may not be accurate or current
- Privacy laws restrict data collection activities
- Social media scraping may violate terms of service

TOOLS REFERENCE:
- CrossLinked: https://github.com/m8r0wn/CrossLinked
- Twint: https://github.com/twintproject/twint
- GitDorker: https://github.com/obheda12/GitDorker"
    ),
];
