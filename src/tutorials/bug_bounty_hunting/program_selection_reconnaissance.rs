// Program Selection & Reconnaissance - Bug Bounty Hunting Module
// Comprehensive methodology for selecting and researching bug bounty programs

pub const PROGRAM_SELECTION_RECONNAISSANCE_STEPS: &[(&str, &str)] = &[
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
- Google VRP (https://bughunters.google.com/) - Tech giant programs

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
10. Public APIs with authentication
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

# Check HTTP headers for technology hints
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
];