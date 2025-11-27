// Report Writing & Submission - Bug Bounty Hunting Module
// Professional vulnerability report writing and submission


pub const REPORT_WRITING_SUBMISSION_STEPS: &[(&str, &str)] = &[
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
```bash
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
];