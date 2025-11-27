pub const PORT_SCANNING_STEPS: &[(&str, &str)] = &[
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
];