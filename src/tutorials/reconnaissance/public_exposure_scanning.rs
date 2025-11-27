pub const PUBLIC_EXPOSURE_SCANNING_STEPS: &[(&str, &str)] = &[
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
   curl -X POST https://search.censys.io/api/v2/hosts/search \\
        -u API_ID:API_SECRET \\
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
   curl \"https://api.binaryedge.io/v2/query/search?query=target.com\" \\
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
];