pub const SUBDOMAIN_ENUMERATION_STEPS: &[(&str, &str)] = &[
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
];