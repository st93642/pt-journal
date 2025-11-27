// Asset Enumeration & Mapping - Bug Bounty Hunting Module
// Comprehensive enumeration and mapping of target assets


pub const ASSET_ENUMERATION_MAPPING_STEPS: &[(&str, &str)] = &[
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
];