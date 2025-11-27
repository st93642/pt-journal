pub const DNS_ENUMERATION_STEPS: &[(&str, &str)] = &[
    (
        "DNS enumeration",
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
];