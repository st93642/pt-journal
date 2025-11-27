pub const REPORTING_STEPS: &[(&str, &str)] = &[
    (
        "Evidence consolidation",
        "OBJECTIVE: Systematically organize all evidence, screenshots, logs, and findings collected during the penetration test into a cohesive, verifiable evidence package.

ACADEMIC BACKGROUND:
PTES Reporting emphasizes evidence-based findings. NIST SP 800-115 Section 9.3 addresses assessment reporting requirements. ISO 27001 A.18.1.3 mandates protection of evidence records. Chain of custody procedures from forensic standards (NIST SP 800-86) ensure evidence integrity.

STEP-BY-STEP PROCESS:

1. Evidence Inventory and Cataloging:
```bash
# Create structured evidence directory:
mkdir -p evidence/{reconnaissance,vulnerability_analysis,exploitation,post_exploitation}
mkdir -p evidence/{screenshots,network_captures,logs,scripts}

# Document all evidence with metadata:
echo \"Evidence Inventory:
Screenshot_001.png - SQL injection in /search endpoint - 2025-11-01 14:30
network_capture_001.pcap - Exploitation traffic - 2025-11-01 14:35
linpeas_output.txt - Privilege escalation enumeration - 2025-11-01 15:00
exploit_poc.py - Custom SQL injection PoC - 2025-11-01 14:25\" > evidence/inventory.txt
```

2. Screenshot Organization and Annotation:
```bash
# Annotate screenshots with context:
# Tool: GIMP, Inkscape, or screenshot annotation tools
# Add red boxes highlighting vulnerabilities
# Include timestamps, URLs, and finding references
# Number sequentially: Finding-01_Screenshot-A.png

# Screenshot naming convention:
# [Finding-ID]_[Description]_[Timestamp].png
# Example: VULN-001_SQL-Injection-Search_20251101-1430.png
```

3. Network Traffic Captures:
```bash
# Organize packet captures by phase:
ls evidence/network_captures/
- exploitation_sql_injection.pcap
- lateral_movement_smb.pcap
- credential_harvesting_mimikatz.pcap

# Extract relevant packets:
tshark -r full_capture.pcap -Y \"http.request.uri contains 'UNION SELECT'\" -w sql_injection.pcap
tshark -r full_capture.pcap -Y \"smb\" -w smb_traffic.pcap

# Create traffic analysis summary:
tshark -r sql_injection.pcap -T fields -e ip.src -e ip.dst -e http.request.uri > traffic_summary.txt
```

4. Command Output and Log Preservation:
```bash
# Preserve all command outputs with timestamps:
script -c \"nmap -sV -sC target.com\" nmap_scan_$(date +%Y%m%d_%H%M%S).txt
sqlmap -u \"https://target.com/?id=1\" --batch | tee sqlmap_output.txt

# Organize logs by finding:
evidence/logs/
├── VULN-001-SQL-Injection/
│   ├── sqlmap_output.txt
│   ├── database_enumeration.txt
│   └── data_extraction_sample.txt
├── VULN-002-XSS/
│   ├── xss_payload_test.txt
│   └── cookie_theft_poc.txt
```

5. Proof-of-Concept Scripts and Code:
```bash
# Document all custom scripts:
evidence/scripts/
├── sql_injection_poc.py  # Custom SQLi exploit
├── xss_payload.html      # XSS demonstration
├── privilege_escalation.sh  # Privesc automation
└── README.md  # Usage instructions for each script

# Include comments in scripts:
# Author, date, target, vulnerability exploited, expected outcome
```

6. Evidence Validation and Integrity:
```bash
# Generate SHA-256 hashes for all evidence:
find evidence/ -type f -exec sha256sum {} \\; > evidence_hashes.txt

# Create evidence manifest:
echo \"Evidence Manifest:
Total Files: 47
Screenshots: 25
Network Captures: 8
Log Files: 10
Scripts: 4
Generated: 2025-11-01 16:00:00
Hash Algorithm: SHA-256
Integrity Verified: Yes\" > evidence/manifest.txt

# Sign manifest (optional):
gpg --clearsign evidence/manifest.txt
```

7. Finding Cross-Reference Matrix:
```bash
# Link evidence to specific findings:
echo \"Finding ID | Evidence Files | Page Reference
VULN-001 | Screenshot_001-003.png, sql_injection.pcap, sqlmap_output.txt | Page 12
VULN-002 | Screenshot_004-005.png, xss_demo.html | Page 15
PRIV-001 | Screenshot_006-010.png, linpeas.txt, privesc.sh | Page 18
DATA-001 | Screenshot_011.png, database_sample.txt | Page 22\" > finding_evidence_matrix.csv
```

8. Timeline Reconstruction:
```bash
# Create comprehensive timeline:
echo \"Assessment Timeline:
2025-11-01 09:00 - Kickoff meeting, scope confirmation
2025-11-01 10:00 - Reconnaissance phase initiated
2025-11-01 12:30 - Subdomain enumeration completed (16 subdomains found)
2025-11-01 14:00 - Vulnerability analysis began
2025-11-01 14:30 - SQL injection discovered in /search endpoint
2025-11-01 15:00 - SQL injection exploitation successful (database enumerated)
2025-11-01 16:00 - Privilege escalation to root via sudo misconfiguration
2025-11-01 17:00 - Lateral movement to internal database server
2025-11-01 18:00 - Data access validation completed
2025-11-01 19:00 - Cleanup procedures executed
2025-11-01 19:30 - Assessment concluded\" > assessment_timeline.txt
```

9. Quality Assurance and Peer Review:
```bash
# Checklist for evidence review:
echo \"Evidence QA Checklist:
[ ] All screenshots clearly show vulnerability exploitation
[ ] Network captures include relevant packets only (filtered)
[ ] All command outputs include timestamps and context
[ ] PoC scripts are commented and documented
[ ] Evidence file names follow naming convention
[ ] SHA-256 hashes generated for all files
[ ] Evidence organized by finding category
[ ] Cross-reference matrix complete
[ ] No sensitive client data in evidence (sanitized)
[ ] Evidence package ready for report inclusion\" > evidence/qa_checklist.txt
```

10. Evidence Package Finalization:
```bash
# Create encrypted evidence archive:
tar -czf evidence_package.tar.gz evidence/
gpg -c evidence_package.tar.gz  # Encrypt with passphrase

# Generate evidence package metadata:
echo \"Evidence Package Summary:
Package Name: evidence_package.tar.gz.gpg
Creation Date: 2025-11-01 20:00:00
Total Size: 250 MB
Total Files: 47
Encryption: GPG (AES-256)
Passphrase: [Provided separately to client]
Integrity Hash (SHA-256): a1b2c3d4e5f6...
Retention Period: 90 days per contract
Destruction Date: 2025-02-01\" > evidence_package_metadata.txt
```

WHAT TO LOOK FOR:
- **Complete Evidence Chain**: Every finding has supporting screenshots, logs, and captures
- **Clear Visual Evidence**: Screenshots highlight vulnerabilities with annotations and context
- **Reproducible PoCs**: Scripts and commands enable clients to verify findings
- **Timestamped Documentation**: All evidence includes dates, times, and sequence of events
- **Sanitized Data**: Client sensitive information redacted or removed from evidence
- **Organized Structure**: Logical folder hierarchy with clear naming conventions
- **Integrity Verification**: Hashes and signatures prove evidence hasn't been tampered with

SECURITY IMPLICATIONS:
- **Legal Defensibility**: Properly documented evidence withstands legal scrutiny in litigation
- **Audit Requirements**: Compliance audits (PCI DSS, ISO 27001) require evidence preservation
- **Incident Response**: Evidence helps security teams understand attack paths and improve defenses
- **Insurance Claims**: Cyber insurance may require penetration test evidence for claims
- **Chain of Custody**: Forensically sound evidence collection enables regulatory compliance

COMMON PITFALLS:
- **Missing Context**: Screenshots without URLs, timestamps, or descriptions lose value
- **Excessive Evidence**: Including irrelevant data dilutes important findings
- **Poor Organization**: Unstructured evidence makes report creation difficult
- **Data Exposure**: Accidentally including client sensitive data (PII, credentials, financial records)
- **Lost Evidence**: Hard drive failure without backups destroys evidence
- **Incomplete Documentation**: Forgetting to document steps makes reproduction impossible

DETECTION:
- **Complete Evidence Chain**: Every finding has supporting screenshots, logs, and captures
- **Clear Visual Evidence**: Screenshots highlight vulnerabilities with annotations and context
- **Reproducible PoCs**: Scripts and commands enable clients to verify findings
- **Timestamped Documentation**: All evidence includes dates, times, and sequence of events

REMEDIATION:
- **Organized Structure**: Logical folder hierarchy with clear naming conventions
- **Integrity Verification**: Hashes and signatures prove evidence hasn't been tampered with
- **Sanitized Data**: Client sensitive information redacted or removed from evidence
- **Backup Procedures**: Multiple copies stored securely with retention policies

TOOLS AND RESOURCES:
- **Flameshot/Shutter**: Linux screenshot tools with annotation
- **Wireshark/tshark**: Network traffic analysis and filtering
- **FFmpeg**: Video recording of exploitation demonstrations
- **Asciinema**: Terminal session recording
- **GIMP/Inkscape**: Screenshot editing and annotation"
    ),
    (
        "Risk rating",
        "OBJECTIVE: Assign quantitative risk scores to vulnerabilities using standardized methodologies (CVSS, DREAD) considering likelihood, impact, and business context.

ACADEMIC BACKGROUND:
Common Vulnerability Scoring System (CVSS) v3.1 provides industry-standard vulnerability scoring. OWASP Risk Rating Methodology combines likelihood and impact. NIST SP 800-30 defines risk assessment procedures. PCI DSS requires risk-based vulnerability management.

STEP-BY-STEP PROCESS:

1. CVSS v3.1 Scoring:
```bash
# CVSS Base Score components:
# Attack Vector (AV): Network(N)/Adjacent(A)/Local(L)/Physical(P)
# Attack Complexity (AC): Low(L)/High(H)
# Privileges Required (PR): None(N)/Low(L)/High(H)
# User Interaction (UI): None(N)/Required(R)
# Scope (S): Unchanged(U)/Changed(C)
# Confidentiality (C): None(N)/Low(L)/High(H)
# Integrity (I): None(N)/Low(L)/High(H)
# Availability (A): None(N)/Low(L)/High(H)

# Example: SQL Injection
# CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N
# Base Score: 10.0 (Critical)

# Calculate at: https://www.first.org/cvss/calculator/3.1
```

2. OWASP Risk Rating:
```bash
# Risk = Likelihood x Impact
# Likelihood factors: Skill level, motive, opportunity, size, ease of discovery, ease of exploit, awareness, intrusion detection
# Impact factors: Loss of confidentiality, integrity, availability, accountability; financial, reputation, non-compliance, privacy violations

# Example matrix:
echo \"Finding: SQL Injection in /search endpoint
Likelihood: HIGH (9/10)
  - No authentication required
  - Easy to exploit (SQLMap available)
  - Publicly accessible endpoint
Impact: HIGH (9/10)
  - Full database access
  - Customer PII exposed (10,000 records)
  - PCI DSS non-compliance
Overall Risk: CRITICAL (9x9=81/100)
Priority: P1 (Immediate remediation required)\" > risk_rating_sqli.txt
```

3. Environmental and Temporal Scoring:
```bash
# Environmental modifiers:
# - Compensating controls (WAF, IPS, monitoring)
# - Data sensitivity classification
# - System criticality (production vs test)
# - Network exposure (internet-facing vs internal)

# Temporal modifiers:
# - Exploit code maturity (PoC vs weaponized)
# - Remediation level (official fix vs workaround)
# - Report confidence (confirmed vs unconfirmed)
```

4. Risk Matrix and Heat Map:
```bash
# Create risk matrix:
echo \"Risk Assessment Matrix:
ID | Vulnerability | CVSS | Likelihood | Impact | Risk | Priority
V-001 | SQL Injection /search | 10.0 | High | High | Critical | P1
V-002 | XSS in comments | 6.1 | Medium | Medium | Medium | P2
V-003 | Info disclosure /admin | 5.3 | Low | Medium | Medium | P3
V-004 | Weak password policy | 5.0 | High | Low | Medium | P2
V-005 | Missing security headers | 4.3 | Low | Low | Low | P4\" > risk_matrix.csv
```

5. Business Impact Assessment:
```bash
# Translate technical risks to business impact:
echo \"Business Impact Analysis:
SQL Injection (V-001):
  - Financial: $500K-2M in breach costs (GDPR fines, legal fees)
  - Operational: Service disruption during patching (4-8 hours downtime)
  - Reputational: Customer trust loss, negative press coverage
  - Compliance: PCI DSS 6.5.1 violation, potential card brand fines
  - Strategic: Competitive disadvantage if breach publicized

Priority: CRITICAL - Immediate executive attention required
Recommended Action: Emergency patch deployment within 24 hours\" > business_impact.txt
```

6. Compensating Controls Assessment:
```bash
# Evaluate existing mitigations:
echo \"Compensating Controls:
SQL Injection V-001:
  - WAF in place: Partially effective (basic patterns blocked, but bypassed with encoding)
  - Input validation: None detected
  - Database permissions: Overly permissive (web app has DBA rights)
  - Monitoring: No SIEM alerts configured
  Risk Adjustment: NONE - Compensating controls inadequate
  Final Risk: CRITICAL (unchanged)\" > compensating_controls.txt
```

7. Risk Trending and Comparison:
```bash
# Compare to previous assessments:
echo \"Risk Trending Analysis:
2023 Assessment: 12 High/Critical findings
2024 Assessment: 18 High/Critical findings (+50%)
New Vulnerabilities: 10
Repeat Findings: 6 (incomplete remediation)
Improved Areas: TLS configuration, patch management
Declining Areas: Web application security, access controls
Overall Trend: WORSENING - Security posture declined year-over-year\" > risk_trending.txt
```

8. Industry Benchmarking:
```bash
# Compare to industry standards:
echo \"Industry Benchmark Comparison:
Organization Risk Profile: Above average risk
  - Critical findings: 3 (Industry avg: 1.2)
  - High findings: 8 (Industry avg: 4.5)
  - Median Time to Remediate: 90 days (Industry avg: 30 days)

Sector: Financial Services (Higher security expectations)
Percentile: 35th percentile (Below average security posture)
Recommendation: Prioritize remediation to meet industry baseline\" > industry_benchmark.txt
```

9. Risk Acceptance and Residual Risk:
```bash
# Document accepted risks and residual exposure:
echo \"Risk Acceptance Register:
V-004 Weak password policy:
  - Risk Level: Medium
  - Business Decision: Accept until Q2 2025 (resource constraints)
  - Compensating Controls: MFA enforced for all accounts
  - Residual Risk: LOW (MFA mitigates weak passwords)
  - Review Date: 2025-04-01
  - Approved By: CISO John Smith

V-005 Missing security headers:
  - Risk Level: Low
  - Business Decision: Accept indefinitely (low business impact)
  - Compensating Controls: None
  - Residual Risk: LOW
  - Review Date: Annual review\" > risk_acceptance.txt
```

10. Risk Summary for Executives:
```bash
# Executive risk dashboard:
echo \"Executive Risk Summary:
Overall Risk Rating: HIGH
Critical Findings: 3
High Findings: 8
Medium Findings: 12
Low Findings: 6
Total: 29 findings

Top 3 Risks:
1. SQL Injection - CRITICAL - Full database compromise
2. Authentication Bypass - CRITICAL - Unauthorized admin access
3. Privilege Escalation - HIGH - Server takeover possible

Required Actions:
- Emergency patch deployment (3 critical findings)
- Incident response plan activation (breach scenario planning)
- Board notification (material cybersecurity risk)
- Budget allocation ($200K for remediation, $50K for security tools)

Timeline: 30-60-90 day remediation roadmap attached\" > executive_risk_summary.txt
```

WHAT TO LOOK FOR:
- **Consistent Methodology**: All findings scored using same framework (CVSS 3.1)
- **Business Context**: Technical scores translated to financial, operational, reputational impact
- **Compensating Controls**: Existing mitigations factored into final risk rating
- **Prioritization**: Clear P1/P2/P3/P4 priorities for remediation
- **Trend Analysis**: Comparison to previous assessments shows improvement or decline

SECURITY IMPLICATIONS:
- **Resource Allocation**: Risk scores drive security budget and staffing decisions
- **Compliance**: PCI DSS, ISO 27001, NIST CSF require risk-based vulnerability management
- **Executive Awareness**: Risk ratings communicate security posture to board and leadership
- **Insurance**: Cyber insurance premiums based on risk assessments and vulnerability management

COMMON PITFALLS:
- **Inconsistent Scoring**: Different testers use different methodologies
- **Ignoring Context**: CVSS alone doesn't account for business impact or compensating controls
- **Score Inflation**: Over-rating to emphasize importance reduces credibility
- **Lack of Justification**: Risk scores without supporting rationale lack defensibility

TOOLS REFERENCE:
- **CVSS Calculator**: https://www.first.org/cvss/calculator/3.1
- **OWASP Risk Rating**: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
- **NIST SP 800-30**: https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final

DETECTION:
- **Inconsistent Scoring**: Different assessors assigning different severity levels to same vulnerability
- **Missing Business Context**: Risk scores not reflecting actual business impact or compensating controls
- **Score Inflation**: Over-rating vulnerabilities to emphasize importance or justify budget
- **Lack of Documentation**: Risk assessments without supporting evidence or rationale
- **Outdated Assessments**: Risk ratings not updated after remediation or environmental changes

REMEDIATION:
- **Standardize Methodology**: Use consistent frameworks (CVSS, OWASP Risk Rating) across all assessments
- **Cross-Validation**: Have multiple assessors review high-risk findings independently
- **Business Impact Integration**: Include financial, operational, reputational impacts in scoring
- **Compensating Controls**: Factor existing mitigations into final risk ratings
- **Regular Reviews**: Update risk assessments quarterly or after significant changes

TOOLS:
- **Risk Assessment Templates**: Standardized forms for consistent scoring
- **Risk Registers**: Databases tracking all identified risks with status and owners
- **Risk Heat Maps**: Visual representations of risk landscape for executive communication
- **Automated Scoring Tools**: Scripts or tools that calculate CVSS scores from vulnerability data
- **Risk Trending Dashboards**: Charts showing risk changes over time

FURTHER READING:
- CVSS v3.1 Specification: https://www.first.org/cvss/v3.1/specification-document
- NIST SP 800-30 Risk Assessment: https://csrc.nist.gov/publications/
- FAIR Risk Analysis: https://www.fairinstitute.org/"
    ),
    (
        "Remediation guidance",
        "OBJECTIVE: Provide specific, actionable recommendations for addressing each vulnerability with technical implementation details, timelines, and validation procedures.

ACADEMIC BACKGROUND:
NIST SP 800-40 Guide to Enterprise Patch Management emphasizes actionable remediation. OWASP Top 10 provides vulnerability-specific remediation guidance. PCI DSS 6.2 requires timely vulnerability remediation. ISO 27001 A.12.6.1 mandates technical vulnerability management.

STEP-BY-STEP PROCESS:

1. Root Cause Analysis:
```bash
# For each finding, identify root cause:
echo \"SQL Injection V-001 Root Cause Analysis:
Primary Cause: Dynamic SQL query construction with string concatenation
Secondary Causes:
  - Lack of input validation/sanitization
  - Overly permissive database user permissions (DBA rights)
  - No WAF SQL injection rules
  - Developer security awareness gaps
Underlying Issue: Secure coding standards not enforced in SDLC\" > root_cause_sqli.txt
```

2. Immediate Remediation (Quick Wins):
```bash
# V-001 SQL Injection - Immediate fixes:
echo \"Immediate Remediation (24-48 hours):
1. Deploy WAF rules to block SQL injection patterns:
   ModSecurity Rule: SecRule ARGS '@detectSQLi' 'id:1001,deny,status:403'
2. Restrict database user permissions:
   GRANT SELECT,INSERT,UPDATE ON database.* TO webapp_user@localhost;
   REVOKE ALL PRIVILEGES ON *.* FROM webapp_user@localhost;
3. Enable query logging for monitoring:
   SET GLOBAL general_log = 'ON';
Evidence: SQL injection attempts blocked, reduced database privileges verified\" > immediate_remediation.txt
```

3. Long-Term Remediation (Permanent Fix):
```bash
# V-001 SQL Injection - Permanent solution:
echo \"Long-Term Remediation (30 days):
1. Replace dynamic SQL with prepared statements:
   BEFORE:
   query = \\\"SELECT * FROM users WHERE username='\\\" + user_input + \\\"'\\\"
   
   AFTER (Python):
   cursor.execute(\\\"SELECT * FROM users WHERE username=?\\\", (user_input,))
   
   AFTER (PHP):
   \\$stmt = \\$pdo->prepare(\\\"SELECT * FROM users WHERE username=:username\\\");
   \\$stmt->execute(['username' => \\$user_input]);

2. Implement input validation library (OWASP ESAPI):
   import esapi
   safe_input = esapi.encoder().encodeForSQL(user_input)

3. Code review of all database queries:
   - Identify 47 instances of dynamic SQL
   - Prioritize user-facing endpoints
   - Refactor to use ORM (SQLAlchemy, Hibernate)

4. Deploy static code analysis (SonarQube, Semgrep):
   - Integrate into CI/CD pipeline
   - Block merges with SQL injection vulnerabilities

Timeline: 30 days
Resources Required: 2 developers, 1 security engineer
Testing: Automated SQLMap scan after fix, penetration test revalidation\" > long_term_remediation.txt
```

4. Compensating Controls (Interim Measures):
```bash
# When immediate patching isn't possible:
echo \"Compensating Controls for V-002 XSS:
Scenario: Application refactoring requires 90 days
Interim Mitigations:
1. Implement Content Security Policy (CSP):
   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
2. Enable HttpOnly and Secure cookie flags:
   Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
3. Deploy Web Application Firewall (ModSecurity):
   XSS detection rules: SecRule ARGS '@detectXSS'
4. Increase monitoring and alerting:
   SIEM rule: Alert on multiple script tag attempts in HTTP parameters

Risk Reduction: HIGH → MEDIUM
Review Date: 2025-02-01 (90-day review)
Permanent Fix Tracking: Jira TICKET-12345\" > compensating_controls.txt
```

5. Vendor Patching and Updates:
```bash
# For third-party vulnerabilities:
echo \"V-003 Apache 2.4.49 Path Traversal (CVE-2021-41773):
Remediation: Upgrade Apache HTTP Server
Current Version: 2.4.49
Fixed Version: 2.4.51+
Download: https://httpd.apache.org/download.cgi

Installation Steps (Ubuntu/Debian):
1. Stop web server: sudo systemctl stop apache2
2. Backup configuration: sudo cp -r /etc/apache2 /etc/apache2.backup
3. Update packages: sudo apt update && sudo apt upgrade apache2
4. Verify version: apache2 -v
5. Test configuration: sudo apache2ctl configtest
6. Restart service: sudo systemctl start apache2

Rollback Plan:
1. sudo apt install apache2=2.4.49 (if issues arise)
2. Restore config: sudo cp -r /etc/apache2.backup /etc/apache2
3. Notify security team

Downtime Window: Sunday 2025-11-03 02:00-04:00 AM (2-hour maintenance window)
Notification: Email stakeholders 48 hours in advance
Testing: Verify web application functionality, re-test vulnerability\" > vendor_patching.txt
```

6. Configuration Hardening:
```bash
# Security misconfigurations remediation:
echo \"V-004 Missing Security Headers:
Remediation: Configure HTTP security headers
Implementation (Apache .htaccess or httpd.conf):
Header always set Strict-Transport-Security \\\"max-age=31536000; includeSubDomains; preload\\\"
Header always set X-Content-Type-Options \\\"nosniff\\\"
Header always set X-Frame-Options \\\"SAMEORIGIN\\\"
Header always set X-XSS-Protection \\\"1; mode=block\\\"
Header always set Content-Security-Policy \\\"default-src 'self'\\\"
Header always set Referrer-Policy \\\"strict-origin-when-cross-origin\\\"
Header always set Permissions-Policy \\\"geolocation=(), microphone=(), camera=()\\\"

Nginx Configuration:
add_header Strict-Transport-Security \\\"max-age=31536000; includeSubDomains; preload\\\" always;
add_header X-Content-Type-Options \\\"nosniff\\\" always;
add_header X-Frame-Options \\\"SAMEORIGIN\\\" always;

Validation:
curl -I https://target.com | grep -E \\\"Strict-Transport|X-Content-Type|X-Frame|CSP\\\"
https://securityheaders.com/?q=https://target.com (A+ rating target)\" > security_headers.txt
```

7. Access Control Remediation:
```bash
# V-005 Broken Access Control (IDOR):
echo \"Remediation: Implement authorization checks
Code Example (Python Flask):
BEFORE:
@app.route('/api/invoice/<invoice_id>')
def get_invoice(invoice_id):
    invoice = Invoice.query.get(invoice_id)
    return jsonify(invoice)

AFTER:
@app.route('/api/invoice/<invoice_id>')
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.query.get(invoice_id)
    if invoice.user_id != current_user.id and not current_user.is_admin:
        abort(403)  # Forbidden
    return jsonify(invoice)

Implementation Steps:
1. Identify all API endpoints with object references
2. Add authorization checks: if resource.owner != current_user: abort(403)
3. Use indirect object references (UUIDs instead of sequential IDs)
4. Implement centralized authorization middleware
5. Add automated tests: test_user_cannot_access_other_user_invoice()

Testing: Use Burp Autorize extension to verify authorization checks\" > access_control_remediation.txt
```

8. Remediation Validation and Testing:
```bash
# Post-remediation verification:
echo \"Validation Procedures for V-001 SQL Injection:
1. Automated Scanning:
   sqlmap -u \\\"https://target.com/search?q=test\\\" --batch --level=5 --risk=3
   Expected: No injection vulnerabilities found

2. Manual Testing:
   Payloads: ' OR '1'='1, \\\" UNION SELECT NULL--, ' AND SLEEP(5)--
   Expected: Proper error handling, no database errors, no time delays

3. Code Review:
   Verify: All database queries use prepared statements
   Check: OWASP dependency-check passes, SonarQube security gates pass

4. Penetration Test Re-validation:
   Schedule: 2025-12-01 (30 days post-remediation)
   Scope: Targeted re-test of SQL injection findings
   Expected: All findings resolved, no new issues introduced

Acceptance Criteria:
✓ Automated scanners report no SQL injection
✓ Manual exploitation attempts fail
✓ Code review confirms prepared statements
✓ Penetration test validates remediation\" > validation_testing.txt
```

9. Remediation Tracking and Metrics:
```bash
# Create remediation dashboard:
echo \"Remediation Progress Tracking:
Finding | Severity | Status | Owner | Due Date | Completion %
V-001 | Critical | In Progress | Dev Team | 2025-11-15 | 60%
V-002 | High | Not Started | Dev Team | 2025-11-30 | 0%
V-003 | High | Completed | IT Ops | 2025-11-05 | 100%
V-004 | Medium | Testing | IT Ops | 2025-11-20 | 80%
V-005 | Medium | In Progress | Dev Team | 2025-12-15 | 40%

Metrics:
- Mean Time to Remediate (MTTR): 45 days (Target: 30 days)
- Critical Findings Resolved: 1/3 (33%)
- High Findings Resolved: 1/8 (12.5%)
- On-Track Remediations: 60%
- Overdue Remediations: 40%

Next Review: 2025-11-08 (Weekly remediation standup)\" > remediation_tracking.txt
```

10. Documentation and Knowledge Transfer:
```bash
# Create runbooks for operations team:
echo \"SQL Injection Prevention Runbook:
Purpose: Guide developers on preventing SQL injection vulnerabilities

Best Practices:
1. Always use parameterized queries/prepared statements
2. Never concatenate user input into SQL strings
3. Use ORM frameworks (SQLAlchemy, Hibernate, Entity Framework)
4. Validate and sanitize all user inputs
5. Apply principle of least privilege to database accounts
6. Enable query logging and monitoring

Code Examples: [Language-specific examples]
Testing Procedures: [SQLMap usage, manual testing]
Resources: OWASP SQL Injection Prevention Cheat Sheet

Training: Mandatory secure coding training for all developers (Scheduled: 2025-11-15)
Contact: Security Team security@company.com for questions\" > sql_injection_runbook.txt
```

WHAT TO LOOK FOR:
- **Actionable Steps**: Specific commands, code examples, configuration changes (not vague advice)
- **Timelines**: Realistic remediation windows (immediate, 30-day, 90-day)
- **Resource Requirements**: Staff, budget, downtime needed
- **Validation Procedures**: How to verify fix was successful
- **Rollback Plans**: Contingency if remediation causes issues

SECURITY IMPLICATIONS:
- **Vulnerability Window**: Delayed remediation leaves systems exposed
- **Incomplete Fixes**: Partial remediation may give false sense of security
- **Regression Risk**: Improper patches may introduce new vulnerabilities
- **Compliance Deadlines**: PCI DSS, GDPR mandate specific remediation timelines

COMMON PITFALLS:
- **Generic Advice**: \"Update software\" without specific versions or procedures
- **Unrealistic Timelines**: Demanding immediate fixes for complex architectural flaws
- **Missing Context**: Remediation without considering business constraints or dependencies
- **No Testing Guidance**: Not explaining how to verify the fix worked

TOOLS REFERENCE:
- **OWASP Dependency-Check**: https://owasp.org/www-project-dependency-check/
- **SonarQube**: https://www.sonarqube.org/ (Static code analysis)
- **Semgrep**: https://semgrep.dev/ (Security-focused SAST)
- **OWASP Cheat Sheets**: https://cheatsheetseries.owasp.org/

DETECTION:
- **Incomplete Remediation Plans**: Missing specific technical steps or timelines
- **Unrealistic Timelines**: Demanding immediate fixes for complex architectural changes
- **Generic Recommendations**: Vague advice like improve security without actionable details
- **Missing Validation Procedures**: No clear way to verify remediation effectiveness
- **Resource Constraints Ignored**: Not accounting for staff, budget, or downtime requirements

REMEDIATION:
- **Develop Detailed Action Plans**: Include specific commands, code changes, and configuration updates
- **Set Realistic Timelines**: Consider business constraints and resource availability
- **Include Validation Steps**: Define clear acceptance criteria and testing procedures
- **Plan for Rollback**: Document contingency procedures if remediation causes issues
- **Communicate Dependencies**: Identify prerequisites and interdependencies between fixes

TOOLS:
- **Jira/ServiceNow**: Remediation tracking and workflow management
- **GitLab/GitHub**: Code review and change management for software fixes
- **Ansible/Chef/Puppet**: Configuration management for infrastructure changes
- **Burp Suite/ZAP**: Web application vulnerability validation
- **OpenVAS/Nessus**: Infrastructure vulnerability scanning and verification

FURTHER READING:
- NIST SP 800-40 Patch Management: https://csrc.nist.gov/publications/
- OWASP Secure Coding Practices: https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks/"
    ),
    (
        "Executive summaries",
        "OBJECTIVE: Create concise, business-focused summaries that communicate security findings, business impact, and strategic recommendations to executive leadership and board members.

ACADEMIC BACKGROUND:
NIST SP 800-115 Section 9.3.1 emphasizes executive reporting requirements. SEC Cybersecurity Risk Management Rules mandate board-level cybersecurity reporting. ISO 27001 Clause 9.3 requires management review of security status. SOX Section 404 requires executive certification of internal controls.

STEP-BY-STEP PROCESS:

1. Executive Summary Structure (1-2 pages maximum):
```text
EXECUTIVE SUMMARY - PENETRATION TEST RESULTS
Company Name: Acme Corporation
Assessment Period: October 15-30, 2025
Report Date: November 1, 2025
Classification: CONFIDENTIAL

OVERVIEW:
Acme Corporation engaged our firm to conduct an external network and web application penetration test to assess security posture and compliance with PCI DSS requirements. The assessment identified 29 vulnerabilities including 3 CRITICAL and 8 HIGH severity findings that require immediate attention.

KEY FINDINGS:
✗ CRITICAL: SQL Injection enables unauthorized access to 10,000+ customer records including payment data
✗ CRITICAL: Authentication bypass grants administrative access without credentials
✗ CRITICAL: Unpatched server (Apache 2.4.49) vulnerable to remote code execution (CVE-2021-41773)
✗ HIGH: 8 additional high-severity findings including XSS, privilege escalation, and data exposure

BUSINESS IMPACT:
- Regulatory Risk: PCI DSS violations may result in fines ($5K-100K/month) and loss of payment processing
- Data Breach: 10,000+ customer records at risk including credit cards, SSNs, and personal information
- Financial Impact: Estimated breach costs $2-5M (notification, legal, remediation, fines)
- Reputational Damage: Customer trust erosion, competitive disadvantage, negative media coverage
- Operational Disruption: Incident response and remediation require 200+ hours, potential service downtime

RECOMMENDATIONS:
1. Immediate Action (24-48 hours): Deploy emergency patches for 3 critical vulnerabilities
2. Short-Term (30 days): Remediate 8 high-severity findings, implement WAF, enhance monitoring
3. Long-Term (90 days): Security architecture review, secure SDLC implementation, staff training
4. Strategic: Allocate $500K security budget (tools, staffing, training), appoint CISO

CONCLUSION:
Acme Corporation's current security posture presents SIGNIFICANT RISK to business operations, customer data, and regulatory compliance. Immediate executive action is required to address critical vulnerabilities and prevent potential breach incidents. Board notification and incident response planning are recommended.
```

2. Risk Heat Map Visualization:
```text
RISK ASSESSMENT HEAT MAP:

       IMPACT →
    │ Low │ Medium │ High │ Critical │
────┼─────┼────────┼──────┼──────────┤
C │     │        │  1   │    2     │ CRITICAL
R ├─────┼────────┼──────┼──────────┤
I │     │   3    │  5   │          │ HIGH
T ├─────┼────────┼──────┼──────────┤
I │  2  │   7    │  3   │          │ MEDIUM
C ├─────┼────────┼──────┼──────────┤
A │  4  │   2    │      │          │ LOW
L └─────┴────────┴──────┴──────────┘

Legend:
■ Critical (3 findings): Immediate remediation required (0-24 hours)
■ High (8 findings): Priority remediation (1-30 days)
■ Medium (12 findings): Scheduled remediation (30-90 days)
□ Low (6 findings): Opportunistic remediation (90+ days)
```

3. Business-Focused Language (Avoid Technical Jargon):
```text
WRONG (Too Technical):
\"The web application is vulnerable to CVE-2021-12345, a blind boolean-based SQL injection in the /search endpoint allowing UNION-based enumeration of the MySQL database via time-based payloads with a CVSS score of 9.8.\"

RIGHT (Business-Focused):
\"Attackers can bypass authentication and access the entire customer database (10,000+ records) including names, addresses, credit card numbers, and Social Security numbers. This exposure creates significant financial liability ($2-5M estimated breach costs), regulatory penalties (PCI DSS fines), and reputational damage.\"

KEY TRANSLATION RULES:
- SQL Injection → Unauthorized database access, data theft
- XSS → Account hijacking, defacement, customer impact
- RCE → Complete server takeover, ransomware risk
- Privilege Escalation → Internal systems compromise, lateral movement
- CVSS Score → Business impact rating (Financial/Operational/Reputational)
```

4. Financial Impact Quantification:
```text
FINANCIAL IMPACT ANALYSIS:

Direct Breach Costs:
- Forensic Investigation: $50K-150K
- Legal Fees: $100K-500K
- Regulatory Fines (GDPR): €20M or 4% revenue (up to $5M estimated)
- Credit Monitoring (10K customers): $200K
- Notification Costs: $50K
Total Direct Costs: $400K-$5.4M

Indirect Costs:
- Customer Churn (20% attrition): $2M annual revenue loss
- Stock Price Impact (10% decline): $50M market cap loss
- Increased Insurance Premiums: $100K/year
- Incident Response Labor (500 hours): $100K
Total Indirect Costs: $52.2M+

Preventative Investment:
- Immediate Remediation: $100K
- Security Program Enhancement: $400K (annual)
- ROI: $52.6M potential loss avoided vs. $500K investment = 105:1 ROI
```

5. Compliance and Regulatory Implications:
```text
COMPLIANCE IMPACT SUMMARY:

PCI DSS (Payment Card Industry Data Security Standard):
Status: NON-COMPLIANT
Violations: Requirement 6.5.1 (SQL Injection), 6.2 (Unpatched Systems), 11.3 (Penetration Testing)
Impact: Potential loss of card processing privileges, fines $5K-100K/month
Action Required: Immediate remediation, submit Report on Compliance (ROC) update

GDPR (General Data Protection Regulation):
Status: AT RISK
Violations: Article 32 (Security of Processing) - inadequate technical measures
Impact: Fines up to €20M or 4% annual global turnover
Action Required: Breach notification preparation, data protection impact assessment

HIPAA: NOT APPLICABLE (no PHI processed)
SOX: Potential Section 404 internal control deficiencies
ISO 27001: Clause A.12.6.1 (Technical Vulnerability Management) non-conformance
```

6. Competitive and Market Positioning:
```text
INDUSTRY COMPARISON:

Security Posture: BELOW AVERAGE (35th percentile for financial services sector)

Peer Comparison:
- Competitor A: 2 critical findings (vs. our 3)
- Competitor B: 4 high findings (vs. our 8)
- Industry Average: 1.2 critical, 4.5 high findings

Market Implications:
- Customer Due Diligence: Enterprise customers require SOC 2, ISO 27001 certification
- RFP Requirements: Security questionnaires reveal vulnerabilities, lost opportunities
- M&A Impact: Cyber due diligence identifies security debt, reduces valuation by 10-30%
- Insurance: Cyber insurance renewal at risk, potential coverage denial or premium increase

Recommendation: Security investment required to remain competitive and meet customer expectations
```

7. Strategic Roadmap (30-60-90 Day Plan):
```text
REMEDIATION ROADMAP:

PHASE 1: Emergency Response (0-30 Days)
Objective: Address critical vulnerabilities, prevent immediate breach
Actions:
- Deploy patches for 3 critical vulnerabilities
- Implement WAF and enhanced monitoring
- Activate incident response team
- Brief board of directors
Budget: $100K
Success Criteria: Zero critical findings, 50% high findings resolved

PHASE 2: Security Program Enhancement (30-60 Days)
Objective: Strengthen security controls, improve detection capabilities
Actions:
- Remediate remaining high-severity findings
- Deploy SIEM and log aggregation
- Implement vulnerability management program
- Conduct security awareness training
Budget: $200K
Success Criteria: 90% of high findings resolved, monitoring coverage at 80%

PHASE 3: Strategic Security Transformation (60-90 Days)
Objective: Establish sustainable security program, shift-left culture
Actions:
- Integrate security into SDLC (DevSecOps)
- Implement secure coding standards
- Establish security champions program
- Conduct annual penetration test
Budget: $200K
Success Criteria: Zero critical/high findings in follow-up assessment, security embedded in development

TOTAL INVESTMENT: $500K over 90 days
EXPECTED OUTCOME: Industry-average security posture, regulatory compliance, reduced breach risk
```

8. Executive Call to Action:
```text
REQUIRED DECISIONS AND ACTIONS:

Immediate (This Week):
□ Approve $100K emergency remediation budget
□ Authorize after-hours patching windows (minimize business disruption)
□ Brief board of directors on security findings
□ Engage legal counsel for breach preparedness
□ Notify cyber insurance carrier of vulnerabilities

Short-Term (This Month):
□ Allocate $400K for security program enhancement
□ Approve headcount for CISO or Security Manager role
□ Establish security steering committee (quarterly meetings)
□ Commission follow-up penetration test (Q1 2026)
□ Review and update incident response plan

Long-Term (This Quarter):
□ Commission third-party security architecture review
□ Evaluate security tool suite (SIEM, EDR, WAF)
□ Establish security metrics and KPIs for board reporting
□ Consider cyber insurance policy enhancement
□ Develop 3-year security strategy and budget
```

9. Visualization and Graphics:
```text
TREND ANALYSIS (Year-over-Year):

Critical Findings:  ▲ 50% increase (2→3)
High Findings:      ▲ 60% increase (5→8)
Mean Time to Fix:   ▲ 200% increase (30→90 days)
Security Budget:    ▼ 25% decrease ($400K→$300K)

CONCLUSION: Declining investment correlates with increased vulnerability exposure

PIE CHART - Vulnerability Categories:
- Web Application Flaws: 45% (13 findings)
- Configuration Errors: 28% (8 findings)
- Unpatched Software: 17% (5 findings)
- Access Control Issues: 10% (3 findings)
```

10. One-Page Executive Brief (For Board Distribution):
```text
BOARD CYBERSECURITY BRIEFING
Date: November 1, 2025 | Classification: BOARD CONFIDENTIAL

SITUATION: External penetration test identified CRITICAL security vulnerabilities exposing customer data and business operations to significant cyber risk.

RISK RATING: ★★★★★ (5/5) - SEVERE
- 3 Critical vulnerabilities enable data breach affecting 10,000+ customers
- Estimated financial impact: $2-5M (breach costs, fines, legal fees)
- Regulatory non-compliance: PCI DSS violations, potential loss of payment processing
- Reputational risk: Customer trust erosion, negative publicity

TOP 3 THREATS:
1. SQL Injection: Attackers can steal all customer data including payment cards
2. Authentication Bypass: Unauthorized administrative access to all systems
3. Unpatched Server: Known vulnerability enables complete server takeover (ransomware risk)

RECOMMENDATIONS:
✓ IMMEDIATE: Emergency patching and security controls deployment ($100K, 48 hours)
✓ SHORT-TERM: Comprehensive vulnerability remediation ($200K, 30 days)
✓ STRATEGIC: Security program investment and CISO hiring ($200K annually)

BOARD ACTION REQUIRED:
1. Approve emergency $100K security expenditure
2. Authorize security program budget increase to $500K annually
3. Direct management to brief insurance carrier and prepare incident response
4. Request monthly security updates until vulnerabilities remediated

NEXT STEPS: Management will present detailed remediation plan at next board meeting (November 15, 2025)

Contact: John Smith, CTO | jsmith@company.com | (555) 123-4567
```

WHAT TO LOOK FOR:
- **Clear Business Impact**: Financial, operational, reputational consequences (not just technical details)
- **Actionable Recommendations**: Specific decisions required with timelines and budgets
- **Risk Context**: Industry benchmarking, compliance implications, competitive positioning
- **Visual Communication**: Heat maps, trend charts, pie charts supplement narrative
- **Appropriate Length**: 1-2 page executive summary, 1-page board brief (detailed findings in appendices)

SECURITY IMPLICATIONS:
- **Board Liability**: SEC rules require board cybersecurity expertise and oversight
- **D&O Insurance**: Directors and Officers insurance claims related to cyber incidents
- **Fiduciary Duty**: Board must exercise reasonable care in cyber risk management
- **Investor Relations**: Material cybersecurity risks must be disclosed in SEC filings

COMMON PITFALLS:
- **Too Technical**: Using jargon (CVE numbers, CVSS scores) without business translation
- **Too Long**: 20-page executive summary defeats purpose of executive communication
- **No Action Items**: Describing problems without clear recommendations and next steps
- **Missing Financial Impact**: Not quantifying business consequences in dollar terms
- **Lack of Context**: No comparison to industry standards or previous assessments

TOOLS REFERENCE:
- **Visualization**: Microsoft PowerBI, Tableau, Excel charts
- **Templates**: SANS Penetration Test Report Template, OWASP Reporting Guide
- **Frameworks**: NIST CSF, CIS Controls for strategic roadmap alignment

FURTHER READING:
- SEC Cybersecurity Risk Management Rules: https://www.sec.gov/
- NIST SP 800-115 Section 9: Post-Assessment Reporting
- ISACA Board Briefing on IT Risk: https://www.isaca.org/
- NACD Cyber-Risk Oversight Handbook: https://www.nacdonline.org/"
    ),
];

use crate::model::step::Step;
use uuid::Uuid;

pub fn create_reporting_steps() -> Vec<Step> {
    REPORTING_STEPS
        .iter()
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec![
                    "reporting".to_string(),
                    "pentesting".to_string(),
                    "security-assessment".to_string(),
                ],
            )
        })
        .collect()
}