pub const WEB_TECHNOLOGY_FINGERPRINTING_STEPS: &[(&str, &str)] = &[
    (
        "Web technology fingerprinting",
        "OBJECTIVE: Identify web server software, frameworks, content management systems (CMS), libraries, and underlying technologies to map the application stack and identify version-specific vulnerabilities.

ACADEMIC BACKGROUND:
Web technology fingerprinting, as defined in OWASP WSTG-INFO-02 (Fingerprint Web Server and Web Application Framework), is the systematic identification of web technologies through analysis of HTTP headers, response patterns, file structures, cookies, HTML/JavaScript signatures, and behavior patterns.

This intelligence gathering enables targeted vulnerability assessment by identifying:
- Known CVEs for specific software versions
- Default credentials and paths
- Framework-specific attack vectors
- Plugin/extension vulnerabilities
- Technology-specific misconfigurations

The MITRE ATT&CK framework categorizes this as T1594.002 (Search Victim-Owned Websites) and T1592.002 (Gather Victim Host Information: Software), emphasizing that public-facing web infrastructure reveals significant attack surface information.

According to the PTES (Penetration Testing Execution Standard), technology identification precedes vulnerability analysis and helps prioritize testing based on known attack patterns for identified technologies.

TECHNOLOGY STACK LAYERS:
1. **Web Server**: Apache, Nginx, IIS, LiteSpeed, Caddy
2. **Application Server**: Tomcat, JBoss, WebLogic, Gunicorn, Passenger
3. **Programming Language**: PHP, Python, Ruby, Java, .NET, Node.js, Go
4. **Framework**: Laravel, Django, Flask, Ruby on Rails, Express, Spring, ASP.NET
5. **CMS/Platform**: WordPress, Joomla, Drupal, Magento, SharePoint
6. **Database**: MySQL, PostgreSQL, MSSQL, MongoDB, Redis (inferred)
7. **Frontend Libraries**: React, Angular, Vue.js, jQuery, Bootstrap
8. **CDN/WAF**: Cloudflare, Akamai, AWS CloudFront, Sucuri
9. **Analytics/Tracking**: Google Analytics, Adobe Analytics, Hotjar
10. **Third-Party Services**: Payment gateways, chat widgets, CRMs

STEP-BY-STEP PROCESS:

1. AUTOMATED TECHNOLOGY DETECTION:
   a) WhatWeb (Comprehensive Scanner):
      ```bash
      # Basic scan
      whatweb https://target.com

      # Aggressive scan (all plugins)
      whatweb -a 3 https://target.com

      # Verbose output with plugin details
      whatweb -v https://target.com

      # JSON output for parsing
      whatweb --log-json=whatweb_results.json https://target.com

      # Scan multiple URLs from file
      whatweb -i urls.txt --log-json=results.json

      # Custom user agent
      whatweb -U \"Mozilla/5.0\" https://target.com
      ```

      WhatWeb identifies: Web server, CMS, JavaScript libraries, analytics, frameworks, cookies

   b) Wappalyzer (Technology Profiler):
      ```bash
      # CLI usage (requires npm)
      npm install -g wappalyzer
      wappalyzer https://target.com

      # Multiple URLs
      wappalyzer https://target.com https://target.com/admin

      # Browser extension (Chrome/Firefox)
      # Install from https://www.wappalyzer.com/apps/
      ```

      Wappalyzer categories: CMS, frameworks, web servers, analytics, CDN, databases (inferred)

   c) httpx (Fast HTTP Toolkit):
      ```bash
      # Technology detection
      echo \"target.com\" | httpx -tech-detect

      # With title and status code
      echo \"target.com\" | httpx -tech-detect -title -status-code

      # Server header extraction
      echo \"target.com\" | httpx -silent -server

      # Full headers
      echo \"target.com\" | httpx -include-response-header

      # Multiple subdomains
      cat subdomains.txt | httpx -tech-detect -o tech_results.txt
      ```

   d) Nikto (Web Server Scanner):
      ```bash
      # Full scan with tech detection
      nikto -h https://target.com -o nikto_report.txt

      # Faster scan (skip some checks)
      nikto -h https://target.com -Tuning 1,2,3

      # Identify server version and components
      nikto -h https://target.com | grep -i \"server:\"
      ```

   e) Webtech (Lightweight Fingerprinter):
      ```bash
      # Install and run
      go install github.com/ShivangiReja/webtech@latest
      webtech -u https://target.com
      ```

2. MANUAL HTTP HEADER ANALYSIS:
   ```bash
   # Basic header inspection
   curl -I https://target.com

   # Verbose connection details
   curl -v https://target.com 2>&1 | grep -i '^< '

   # Multiple redirects follow
   curl -IL https://target.com

   # Extract specific headers
   curl -s -I https://target.com | grep -i server
   curl -s -I https://target.com | grep -i x-powered-by
   curl -s -I https://target.com | grep -i x-aspnet-version

   # All security headers
   curl -I https://target.com | grep -iE '(X-Frame|X-XSS|X-Content|Content-Security|Strict-Transport)'

   # Using http (HTTPie)
   http HEAD https://target.com
   ```

   Key Headers to Analyze:
   - **Server**: Web server type and version (e.g., \"Apache/2.4.41\")
   - **X-Powered-By**: Backend technology (e.g., \"PHP/7.4.3\", \"Express\")
   - **X-AspNet-Version**: .NET framework version
   - **X-AspNetMvc-Version**: ASP.NET MVC version
   - **X-Drupal-Cache**: Drupal CMS
   - **X-Generator**: CMS or framework (e.g., \"Drupal 9\")
   - **X-Redirect-By**: WordPress plugin
   - **X-Pingback**: WordPress XML-RPC endpoint
   - **Via**: Proxy or load balancer information
   - **X-Varnish**: Varnish cache
   - **CF-RAY**: Cloudflare CDN
   - **X-Amz-Cf-Id**: AWS CloudFront

3. CMS IDENTIFICATION:
   a) WordPress Detection:
      ```bash
      # Check for WordPress paths
      curl -s https://target.com/wp-login.php | grep \"WordPress\"
      curl -s https://target.com/wp-admin/
      curl -I https://target.com/wp-json/wp/v2/users

      # Identify WordPress version
      curl -s https://target.com/ | grep 'content=\"WordPress'
      curl -s https://target.com/readme.html | grep \"Version\"

      # WPScan (comprehensive WordPress scanner)
      wpscan --url https://target.com --enumerate vp,vt,u
      # vp = vulnerable plugins, vt = vulnerable themes, u = users

      # Enumerate plugins
      wpscan --url https://target.com --enumerate p

      # WordPress theme detection
      curl -s https://target.com/ | grep -i \"wp-content/themes\"

      # WordPress version from generator meta tag
      curl -s https://target.com/ | grep -i \"<meta name=\\\"generator\\\"\"

      # Check wp-json API
      curl -s https://target.com/wp-json/ | jq '.'
      ```

      WordPress Indicators:
      - /wp-admin/, /wp-content/, /wp-includes/
      - /wp-json/wp/v2/ (REST API)
      - /xmlrpc.php (XML-RPC endpoint)
      - Generator meta tag
      - wp-emoji scripts
      - X-Redirect-By header

   b) Joomla Detection:
      ```bash
      # Common Joomla paths
      curl -I https://target.com/administrator/
      curl -s https://target.com/administrator/manifests/files/joomla.xml | grep version

      # Joomla version from XML
      curl -s https://target.com/language/en-GB/en-GB.xml | grep version

      # JoomScan tool
      joomscan -u https://target.com

      # Components enumeration
      curl -s https://target.com/ | grep -i \"com_\"
      ```

      Joomla Indicators:
      - /administrator/ (admin panel)
      - /components/, /modules/, /plugins/
      - /language/en-GB/
      - Joomla! meta generator tag

   c) Drupal Detection:
      ```bash
      # Drupal paths
      curl -I https://target.com/user/login
      curl -s https://target.com/CHANGELOG.txt | head -5

      # Drupal version
      curl -s https://target.com/ | grep 'content=\"Drupal'

      # Droopescan (Drupal scanner)
      droopescan scan drupal -u https://target.com

      # Check for Drupal headers
      curl -I https://target.com | grep -i x-drupal
      curl -I https://target.com | grep -i x-generator
      ```

      Drupal Indicators:
      - /user/login, /node/, /admin/
      - CHANGELOG.txt, README.txt
      - /sites/all/modules/, /sites/default/
      - X-Drupal-Cache header
      - Drupal.settings JavaScript object

   d) Magento Detection:
      ```bash
      # Magento paths
      curl -I https://target.com/admin
      curl -I https://target.com/downloader/

      # Magento version detection
      curl -s https://target.com/magento_version

      # Magescan tool
      magescan scan:all https://target.com
      ```

      Magento Indicators:
      - /skin/, /media/, /js/mage/
      - Mage.Cookies JavaScript
      - X-Magento-* headers

   e) SharePoint Detection:
      ```bash
      # SharePoint paths
      curl -I https://target.com/_layouts/
      curl -s https://target.com/ | grep -i \"MicrosoftSharePointTeamServices\"

      # SharePoint version
      curl -s https://target.com/ | grep -i \"x-sharepoint\"
      ```

4. WEB SERVER FINGERPRINTING:
   ```bash
   # Nginx detection
   curl -I https://target.com | grep -i nginx

   # Apache version and modules
   curl -I https://target.com | grep -i apache
   # Look for: Apache/2.4.41 (Ubuntu)

   # IIS version
   curl -I https://target.com | grep -i \"Microsoft-IIS\"

   # Server misconfigurations (verbose errors)
   curl -s https://target.com/nonexistent | grep -i \"server\\|version\\|error\"

   # Check for server tokens
   curl -I https://target.com | grep -i \"server:\"

   # HTTP methods allowed
   curl -X OPTIONS https://target.com -i
   ```

   Server-Specific Files:
   - Apache: .htaccess, /server-status, /server-info
   - Nginx: nginx.conf (shouldn't be accessible)
   - IIS: web.config, /trace.axd, /elmah.axd

5. FRAMEWORK IDENTIFICATION:
   a) JavaScript Frameworks (Frontend):
      ```bash
      # View page source for framework signatures
      curl -s https://target.com/ | grep -iE '(react|angular|vue|ember|backbone|jquery)'

      # React detection
      curl -s https://target.com/ | grep -i \"react\"
      curl -s https://target.com/ | grep -i \"__REACT\"

      # Angular detection
      curl -s https://target.com/ | grep -i \"ng-app\"
      curl -s https://target.com/ | grep -i \"angular\"

      # Vue.js detection
      curl -s https://target.com/ | grep -i \"vue\"
      curl -s https://target.com/ | grep -i \"v-app\"

      # Check JavaScript files
      curl -s https://target.com/main.js | head -20

      # Retire.js (JavaScript library vulnerability scanner)
      retire --js --jspath https://target.com
      ```

   b) Backend Frameworks:
      ```bash
      # Laravel (PHP)
      curl -s https://target.com/ | grep -i \"laravel\"
      curl -I https://target.com | grep -i \"laravel_session\"
      curl -s https://target.com/.env  # Misconfiguration check

      # Django (Python)
      curl -I https://target.com | grep -i \"csrftoken\"
      curl -s https://target.com/admin/  # Django admin

      # Flask (Python)
      curl -I https://target.com | grep -i \"session\"

      # Ruby on Rails
      curl -I https://target.com | grep -i \"_rails_session\"
      curl -s https://target.com/ | grep -i \"csrf-token\"

      # Express (Node.js)
      curl -I https://target.com | grep -i \"express\"
      curl -I https://target.com | grep -i \"x-powered-by: Express\"

      # Spring (Java)
      curl -s https://target.com/ | grep -i \"spring\"
      curl -I https://target.com/actuator/  # Spring Boot Actuator

      # ASP.NET
      curl -I https://target.com | grep -i \"aspnet\"
      curl -s https://target.com/ | grep -i \"__VIEWSTATE\"
      ```

6. COOKIE ANALYSIS:
   ```bash
   # Extract all cookies
   curl -I https://target.com | grep -i \"set-cookie\"

   # Detailed cookie inspection
   curl -v https://target.com 2>&1 | grep -i cookie

   # Common framework cookies:
   # - PHPSESSID (PHP)
   # - JSESSIONID (Java/Tomcat)
   # - ASP.NET_SessionId (.NET)
   # - laravel_session (Laravel)
   # - csrftoken (Django)
   # - connect.sid (Express)
   # - _rails_session (Ruby on Rails)
   # - wordpress_* (WordPress)
   ```

7. SSL/TLS CERTIFICATE ANALYSIS:
   ```bash
   # Certificate details
   openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -text -noout

   # Issuer and organization
   openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -noout -issuer -subject

   # Subject Alternative Names (internal hostnames)
   openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -noout -text | grep \"DNS:\"
   ```

   Certificate Intelligence:
   - Organization name and location
   - Internal domain names in SANs
   - Certificate authority (Let's Encrypt = automated, may indicate modern stack)
   - Validity period (short = good security practice)
   - Wildcard certificates

8. FILE AND DIRECTORY STRUCTURE ANALYSIS:
   ```bash
   # Common static file directories
   curl -I https://target.com/static/
   curl -I https://target.com/assets/
   curl -I https://target.com/public/

   # JavaScript files
   curl -s https://target.com/app.js | head -50
   curl -s https://target.com/main.js | grep -i \"webpack\\|react\\|angular\\|vue\"

   # CSS files (framework detection)
   curl -s https://target.com/style.css | grep -i \"bootstrap\\|tailwind\\|foundation\"

   # Favicon analysis (framework-specific)
   curl -I https://target.com/favicon.ico

   # robots.txt (reveals directory structure)
   curl -s https://target.com/robots.txt

   # sitemap.xml (reveals URLs and structure)
   curl -s https://target.com/sitemap.xml
   ```

9. ERROR PAGE ANALYSIS:
   ```bash
   # Trigger 404 error
   curl -s https://target.com/nonexistent-page-12345 | grep -i \"server\\|version\\|error\"

   # Trigger 500 error (if possible)
   curl -s \"https://target.com/page?param=../../../etc/passwd\"

   # Check for detailed error messages (development mode)
   # Look for stack traces, file paths, framework names
   ```

   Framework-Specific Error Pages:
   - Django: \"DisallowedHost\", \"OperationalError\"
   - Laravel: \"Whoops, looks like something went wrong\"
   - ASP.NET: \"Server Error in '/' Application\"
   - Express: \"Cannot GET /\"
   - Rails: \"We're sorry, but something went wrong\"

10. THIRD-PARTY SERVICE IDENTIFICATION:
    ```bash
    # View page source for third-party scripts
    curl -s https://target.com/ | grep -iE '(google-analytics|gtag|facebook|twitter|stripe|paypal)'

    # CDN detection
    curl -I https://target.com | grep -i \"cf-ray\\|x-amz\\|x-cache\"

    # Analytics platforms
    curl -s https://target.com/ | grep -i \"ga('\\|gtag(\"

    # Payment gateways
    curl -s https://target.com/checkout | grep -iE '(stripe|paypal|square|braintree)'

    # Chat widgets
    curl -s https://target.com/ | grep -iE '(intercom|zendesk|livechat|drift)'
    ```

11. API ENDPOINT DISCOVERY:
    ```bash
    # Common API paths
    curl -I https://target.com/api/
    curl -I https://target.com/api/v1/
    curl -s https://target.com/api/ | jq '.'

    # GraphQL endpoints
    curl -s https://target.com/graphql -d '{\"query\":\"{__schema{types{name}}}\"}' -H \"Content-Type: application/json\"

    # Swagger/OpenAPI documentation
    curl -s https://target.com/api-docs
    curl -s https://target.com/swagger.json
    curl -s https://target.com/v2/swagger.json

    # REST API version discovery
    for i in {1..5}; do curl -I https://target.com/api/v$i/; done
    ```

WHAT TO LOOK FOR:
- **Outdated Versions**: PHP 5.x, jQuery < 3.0, Angular < 8, Apache < 2.4.50
- **Development Frameworks in Production**: Flask debug mode, Django DEBUG=True, Express dev environment
- **Verbose Error Messages**: Stack traces, file paths, database errors
- **Version Disclosure**: Exact version numbers in headers, meta tags, or files (README.txt, CHANGELOG.txt)
- **Default Installations**: Default favicon, unchanged admin paths, sample pages
- **Unpatched Software**: Known CVEs for identified versions
- **Deprecated Technologies**: Flash, Silverlight, Java applets, ActiveX
- **Multiple Frameworks**: Mixed technology stack (PHP + Python, unusual combinations)
- **Information Leakage**: Internal hostnames, developer comments in source, debugging endpoints
- **CDN/WAF**: Cloudflare, Akamai (may protect against some attacks)

SECURITY IMPLICATIONS:
- **PHP < 7.4**: Multiple RCE vulnerabilities (CVE-2019-11043, CVE-2019-11041)
- **WordPress < 5.8**: XSS, CSRF, privilege escalation vulnerabilities
- **Drupal < 9.2**: Drupalgeddon vulnerabilities (RCE)
- **Apache Struts**: CVE-2017-5638 (Equifax breach), multiple RCE
- **Laravel Debug Mode**: Full environment variable disclosure (DB credentials, API keys)
- **Django DEBUG=True**: Source code disclosure, SQL query leakage
- **jQuery < 3.0**: XSS via $.html() and $.get()
- **Angular < 1.6**: XSS in templates and expressions
- **Outdated TLS**: TLS 1.0/1.1 deprecated, vulnerable to BEAST, POODLE
- **Server Version Disclosure**: Helps attackers identify specific exploits

COMMON PITFALLS:
- **WAF Interference**: Cloudflare/Akamai may hide real server headers
- **Header Stripping**: Security-conscious admins disable version headers
- **Virtual Hosting**: Different technologies per vhost/subdomain
- **Custom Headers**: Some orgs add fake headers to mislead attackers
- **Caching Layers**: Varnish/Redis may modify responses
- **Microservices**: Different technologies per API endpoint
- **False Positives**: Generic error pages don't always reveal real technology

DOCUMENTATION REQUIREMENTS:
- **Technology Matrix**:
  | Layer | Technology | Version | CVEs | Risk |
  |-------|------------|---------|------|------|
  | Web Server | Nginx | 1.18.0 | CVE-2021-23017 | High |
  | CMS | WordPress | 5.7 | Multiple XSS | Medium |
  | Plugin | Contact Form 7 | 5.3.2 | SQL Injection | Critical |

- Screenshots of technology detection tools (WhatWeb, Wappalyzer)
- HTTP header captures showing version disclosure
- Evidence of identified frameworks (cookies, error pages, source code)
- List of third-party services and integrations
- CVE mapping for all identified versions
- Comparison against vendor security advisories
- Recommendations for version obfuscation and upgrades

AUTOMATION SCRIPT:
```bash
#!/bin/bash
TARGET=\"$1\"

echo \"[*] Technology Fingerprinting: $TARGET\"
echo \"\"

echo \"[+] WhatWeb Scan:\"
whatweb -a 3 \"$TARGET\"
echo \"\"

echo \"[+] HTTP Headers:\"
curl -I \"$TARGET\"
echo \"\"

echo \"[+] Certificate Info:\"
echo | openssl s_client -connect \"${TARGET#https://}:443\" 2>/dev/null | openssl x509 -noout -subject -issuer
echo \"\"

echo \"[+] CMS Detection:\"
curl -s \"$TARGET\" | grep -iE '(wordpress|joomla|drupal|magento)'
echo \"\"

echo \"[+] Framework Detection:\"
curl -I \"$TARGET\" | grep -iE '(x-powered-by|x-aspnet|laravel|django)'
echo \"\"

echo \"[+] JavaScript Frameworks:\"
curl -s \"$TARGET\" | grep -iE '(react|angular|vue|jquery)'
```

TOOLS REFERENCE:
- **WhatWeb**: https://github.com/urbanadventurer/WhatWeb (Most comprehensive)
- **Wappalyzer**: https://www.wappalyzer.com/ (Browser extension + CLI)
- **Webanalyze**: https://github.com/rverton/webanalyze (Go-based, fast)
- **httpx**: https://github.com/projectdiscovery/httpx (Modern HTTP toolkit)
- **WPScan**: https://wpscan.com/ (WordPress security scanner)
- **Joomscan**: https://github.com/OWASP/joomscan (Joomla scanner)
- **Droopescan**: https://github.com/droope/droopescan (Drupal/SilverStripe scanner)
- **Retire.js**: https://retirejs.github.io/retire.js/ (JavaScript library vulnerability scanner)
- **Nikto**: https://github.com/sullo/nikto (Web server scanner)

FURTHER READING:
- OWASP WSTG-INFO-02: Fingerprint Web Server
- OWASP WSTG-INFO-08: Fingerprint Web Application Framework
- NIST SP 800-115: Section 7.4 - Web Application Testing
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- CAPEC-169: Footprinting
- CVE Database: https://cve.mitre.org/ (Cross-reference versions)
- Exploit-DB: https://www.exploit-db.com/ (Known exploits for identified software)"
    ),
];