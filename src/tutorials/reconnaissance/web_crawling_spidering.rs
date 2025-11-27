pub const WEB_CRAWLING_SPIDERING_STEPS: &[(&str, &str)] = &[
    (
        "Web crawling and spidering",
        "OBJECTIVE: Systematically map web application structure, discover all accessible pages, hidden directories, and functionality through automated crawling and directory enumeration to build a comprehensive attack surface map.

ACADEMIC BACKGROUND:
Web crawling (also called spidering) is the automated traversal of web applications following links and analyzing responses to discover all accessible content. As outlined in OWASP WSTG-INFO-05 (Review Webpage Content for Information Leakage) and WSTG-INFO-07 (Map Application Architecture), comprehensive content discovery reveals:
- Hidden administrative interfaces
- Backup and configuration files
- API endpoints and documentation
- Development/staging environments
- Commented-out functionality
- Forgotten test pages

The MITRE ATT&CK framework categorizes this as T1593 (Search Open Websites/Domains) under Reconnaissance, emphasizing that public-facing web content often reveals internal architecture and sensitive functionality.

According to NIST SP 800-115, content discovery should employ both passive analysis (robots.txt, sitemaps) and active enumeration (directory brute-forcing, fuzzing) to ensure comprehensive coverage.

CRAWLING METHODOLOGIES:
1. **Passive Discovery**: robots.txt, sitemap.xml, search engine caches
2. **Active Crawling**: Following links, parsing JavaScript, form submission
3. **Directory Brute-forcing**: Wordlist-based path enumeration
4. **Fuzzing**: Parameter and path mutation testing
5. **Recursive Discovery**: Following discovered links to find more content

STEP-BY-STEP PROCESS:

1. PASSIVE RECONNAISSANCE (No Direct Scanning):
   ```bash
   # robots.txt analysis (reveals disallowed paths)
   curl -s https://target.com/robots.txt

   # Common robots.txt interesting entries:
   # Disallow: /admin/
   # Disallow: /backup/
   # Disallow: /config/
   # Disallow: /.git/

   # sitemap.xml parsing (complete URL structure)
   curl -s https://target.com/sitemap.xml | grep -oP '(?<=<loc>)[^<]+'

   # sitemap_index.xml for large sites
   curl -s https://target.com/sitemap_index.xml

   # Search engine cache exploration
   # Google: site:target.com
   # Bing: site:target.com
   # Check Google cache for old/deleted pages

   # Wayback Machine (archive.org)
   # View historical versions for removed content
   curl -s \"http://web.archive.org/cdx/search/cdx?url=target.com/*&output=json\" | jq -r '.[] | .[2]' | sort -u
   ```

   Intelligence: robots.txt often reveals admin panels, backup directories, and paths developers want hidden

2. AUTOMATED WEB CRAWLERS (Spider):
   a) Burp Suite Spider:
      ```
      1. Configure Burp Proxy (127.0.0.1:8080)
      2. Navigate to Target → Site Map
      3. Right-click domain → Spider this host
      4. Configure Spider options:
         - Check \"Crawler Settings\" → Form submission
         - Set crawl limits (depth, threads)
         - Configure authentication if needed
      5. Review Site Map for discovered content
      ```

      Advantages: Handles JavaScript, session management, form submission

   b) OWASP ZAP Spider:
      ```bash
      # CLI mode
      zap-cli quick-scan -s all https://target.com

      # Traditional spider
      zap-cli spider https://target.com

      # AJAX spider (for JavaScript-heavy apps)
      zap-cli ajax-spider https://target.com

      # Export results
      zap-cli report -o zap_report.html -f html
      ```

      Advantages: Open-source, AJAX spider, automated scanning integration

   c) Hakrawler (Fast Go-based Crawler):
      ```bash
      # Crawl single domain
      echo \"https://target.com\" | hakrawler

      # Crawl with depth
      echo \"https://target.com\" | hakrawler -d 3

      # Include subdomains
      echo \"https://target.com\" | hakrawler -subs

      # Plain URLs only (no parameters)
      echo \"https://target.com\" | hakrawler -plain

      # Save results
      echo \"https://target.com\" | hakrawler -d 2 > crawled_urls.txt
      ```

   d) GoSpider (Modern Crawler):
      ```bash
      # Basic crawl
      gospider -s \"https://target.com\" -o output

      # With depth and concurrency
      gospider -s \"https://target.com\" -d 3 -c 10

      # Include subdomains
      gospider -s \"https://target.com\" --subs

      # Follow redirects
      gospider -s \"https://target.com\" --redirect
      ```

3. DIRECTORY AND FILE ENUMERATION (Brute-forcing):
   a) Gobuster (Fast Directory Bruteforcer):
      ```bash
      # Basic directory enumeration
      gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt

      # Comprehensive with extensions
      gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,html,txt,js,bak,zip

      # With custom status codes
      gobuster dir -u https://target.com -w wordlist.txt -s 200,204,301,302,307,401,403

      # Follow redirects
      gobuster dir -u https://target.com -w wordlist.txt -r

      # Increase threads for speed
      gobuster dir -u https://target.com -w wordlist.txt -t 50

      # Ignore certificate errors
      gobuster dir -u https://target.com -w wordlist.txt -k

      # Add custom headers (auth, user-agent)
      gobuster dir -u https://target.com -w wordlist.txt -H \"Authorization: Bearer token123\"

      # Recursive mode
      gobuster dir -u https://target.com -w wordlist.txt --wildcard -r
      ```

   b) Feroxbuster (Recursive Rust-based Scanner):
      ```bash
      # Basic scan
      feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

      # Recursive with depth
      feroxbuster -u https://target.com -w wordlist.txt -d 4

      # With extensions
      feroxbuster -u https://target.com -w wordlist.txt -x php,html,js,txt,bak

      # Extract links from responses
      feroxbuster -u https://target.com -w wordlist.txt --extract-links

      # High performance mode
      feroxbuster -u https://target.com -w wordlist.txt -t 200 --rate-limit 100

      # Filter by response size
      feroxbuster -u https://target.com -w wordlist.txt -S 1234

      # Auto-tune (adapts to server response)
      feroxbuster -u https://target.com -w wordlist.txt --auto-tune
      ```

   c) Dirsearch (Python Classic):
      ```bash
      # Basic scan
      dirsearch -u https://target.com

      # With extensions
      dirsearch -u https://target.com -e php,html,js,txt,zip,bak

      # Recursive
      dirsearch -u https://target.com -r

      # Multiple URLs from file
      dirsearch -l urls.txt

      # Custom wordlist
      dirsearch -u https://target.com -w /path/to/wordlist.txt

      # Exclude status codes
      dirsearch -u https://target.com -x 404,403
      ```

   d) ffuf (Fast Fuzzer):
      ```bash
      # Directory fuzzing
      ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

      # File fuzzing with extensions
      ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.html,.txt,.js,.bak

      # Recursive fuzzing
      ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2

      # Filter by response size
      ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 4242

      # Filter by response code
      ffuf -u https://target.com/FUZZ -w wordlist.txt -fc 404,403

      # Match regex in response
      ffuf -u https://target.com/FUZZ -w wordlist.txt -mr \"admin\"

      # Virtual host fuzzing
      ffuf -u https://target.com -w vhosts.txt -H \"Host: FUZZ.target.com\"

      # Multi-position fuzzing
      ffuf -u https://target.com/FUZZ/W2 -w paths.txt:FUZZ -w files.txt:W2
      ```

4. BACKUP AND CONFIGURATION FILE DISCOVERY:
   ```bash
   # Common backup file patterns
   ffuf -u https://target.com/FUZZ -w - << EOF
   .git/
   .git/config
   .gitignore
   .svn/
   .env
   .env.backup
   config.php.bak
   config.php.old
   config.php~
   web.config.bak
   wp-config.php.bak
   database.sql
   backup.zip
   site-backup.tar.gz
   dump.sql
   db_backup.sql
   .DS_Store
   .htaccess
   .htpasswd
   phpinfo.php
   info.php
   test.php
   debug.php
   console.php
   admin.php
   login.php.bak
   EOF

   # Automated backup checker
   for ext in bak old backup tmp save swp; do
       ffuf -u https://target.com/config.php.$ext -w /dev/null
   done
   ```

5. API ENDPOINT DISCOVERY:
   ```bash
   # Common API paths
   ffuf -u https://target.com/FUZZ -w - << EOF
   /api
   /api/v1
   /api/v2
   /api/v3
   /rest
   /rest/v1
   /graphql
   /swagger
   /swagger.json
   /swagger-ui
   /api-docs
   /openapi.json
   /v1/api-docs
   /v2/api-docs
   /api/swagger.json
   /api/swagger-ui.html
   /actuator
   /actuator/health
   /actuator/env
   /health
   /metrics
   /docs
   EOF

   # Kiterunner (API content discovery)
   kr scan https://target.com -w routes-large.kite

   # Arjun (parameter discovery for APIs)
   arjun -u https://target.com/api/users
   ```

6. JAVASCRIPT FILE ANALYSIS FOR ENDPOINTS:
   ```bash
   # Extract all JS files
   echo \"https://target.com\" | hakrawler | grep -E '\\.js$' > js_files.txt

   # Download JS files
   cat js_files.txt | while read url; do wget \"$url\"; done

   # Extract endpoints from JS (using regex)
   grep -rEo \"['\\\"]/(api|admin|user|dashboard|config)[^'\\\"\\s]*\" *.js | sort -u

   # LinkFinder (automated endpoint extraction)
   python3 linkfinder.py -i https://target.com/app.js -o cli

   # JSParser (comprehensive JS analysis)
   python3 jsparser.py -u https://target.com

   # Extract API keys and secrets from JS
   grep -rEi \"(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret)\" *.js
   ```

7. FORM AND PARAMETER DISCOVERY:
   ```bash
   # ParamSpider (URL parameter collection)
   python3 paramspider.py -d target.com -o params.txt

   # Extract unique parameters
   cat params.txt | grep -oP '(?<=[?&])[^=&]+' | sort -u > unique_params.txt

   # Arjun (hidden parameter discovery)
   arjun -u https://target.com/search

   # Burp Param Miner extension
   # Install via Burp Extender, right-click request → \"Guess params\"
   ```

8. RECURSIVE AND COMPREHENSIVE DISCOVERY:
   ```bash
   # Multi-tool pipeline
   #!/bin/bash
   TARGET=\"https://target.com\"

   # Stage 1: Initial crawl
   echo \"[*] Stage 1: Crawling...\"
   gospider -s \"$TARGET\" -d 3 --subs -o crawl_output

   # Stage 2: Extract URLs
   cat crawl_output/*.txt | grep -Eo 'https?://[^ ]+' | sort -u > all_urls.txt

   # Stage 3: Directory enumeration on discovered paths
   echo \"[*] Stage 2: Directory enumeration...\"
   feroxbuster -u \"$TARGET\" -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,html,js,txt --extract-links -o ferox_results.txt

   # Stage 4: Parameter discovery
   echo \"[*] Stage 3: Parameter discovery...\"
   python3 paramspider.py -d target.com -o params.txt

   # Stage 5: JS endpoint extraction
   echo \"[*] Stage 4: JS analysis...\"
   cat all_urls.txt | grep '\\.js$' | while read jsurl; do
       python3 linkfinder.py -i \"$jsurl\" -o cli
   done > endpoints_from_js.txt

   echo \"[*] Discovery complete! Results in all_urls.txt, ferox_results.txt, params.txt, endpoints_from_js.txt\"
   ```

WHAT TO LOOK FOR:
- **Admin Interfaces**: /admin/, /administrator/, /manage/, /cpanel/, /dashboard/
- **Authentication Pages**: /login, /signin, /auth, /sso
- **API Documentation**: /api-docs, /swagger, /graphql, /openapi.json
- **Development/Staging**: /dev/, /test/, /staging/, /qa/
- **Backup Files**: *.bak, *.old, *.backup, *.tmp, *.swp, *~
- **Configuration Files**: .env, config.php, web.config, application.properties
- **Source Control**: .git/, .svn/, .hg/
- **Database Dumps**: *.sql, dump.sql, backup.sql
- **Error Pages**: Custom 404/500 pages that leak information
- **File Uploads**: /uploads/, /files/, /media/, /attachments/
- **Hidden Functionality**: Commented-out links in HTML source
- **Monitoring Endpoints**: /health, /metrics, /status, /actuator/
- **Debug Interfaces**: /debug/, /console/, /phpinfo.php
- **Legacy Content**: Old versions, deprecated features

SECURITY IMPLICATIONS:
- **Exposed Admin Panels**: Direct access to management interfaces
- **.git/ Directory**: Full source code disclosure via `git-dumper`
- **.env Files**: Database credentials, API keys, secrets
- **Backup Files**: Old configurations with default credentials
- **API Documentation**: Reveals all endpoints and parameters
- **Development Directories**: Often less secure, debug mode enabled
- **phpinfo() Pages**: Full PHP configuration disclosure
- **Database Dumps**: Complete data exfiltration
- **File Upload Directories**: May allow direct access to uploaded files
- **Comments in HTML**: Reveal internal infrastructure, IPs, hostnames

COMMON PITFALLS:
- **WAF Blocking**: Aggressive scanning triggers IP blocks
- **Rate Limiting**: Slow down scanning or use rotating proxies
- **False Positives**: 200 OK responses may be custom 404 pages (wildcard DNS)
- **JavaScript-Heavy SPAs**: Standard crawlers miss dynamically loaded content
- **Authentication Required**: Some paths only accessible when logged in
- **Virtual Hosting**: Different content per Host header
- **Load Balancers**: May distribute requests to different backends
- **Recursive Scanning Loops**: Limit recursion depth to avoid infinite loops
- **Large Wordlists**: Balance coverage vs. scan time (start with top-1000)
- **Client-Side Routing**: React/Angular apps use hash or history routing

DOCUMENTATION REQUIREMENTS:
- Complete site map with all discovered URLs
- Directory structure tree showing hierarchy
- List of interesting files and their locations
- API endpoint inventory with methods and parameters
- Screenshots of discovered admin/debug interfaces
- Evidence of exposed sensitive files
- Notes on authentication requirements per path
- Parameter lists for all discovered endpoints
- Recommendations for removing/securing exposed content

OPTIMIZED WORDLISTS:
- **Small (fast)**: /usr/share/seclists/Discovery/Web-Content/common.txt (~4k entries)
- **Medium**: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt (~30k)
- **Large (comprehensive)**: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt (~220k)
- **Technology-specific**: /usr/share/seclists/Discovery/Web-Content/CMS/ (WordPress, Joomla, etc.)
- **API-focused**: /usr/share/seclists/Discovery/Web-Content/api/ (common API paths)

TOOLS REFERENCE:
- **Burp Suite**: https://portswigger.net/burp (Industry standard spider + fuzzer)
- **OWASP ZAP**: https://www.zaproxy.org/ (Open-source security scanner)
- **Gobuster**: https://github.com/OJ/gobuster (Fast directory bruteforcer)
- **Feroxbuster**: https://github.com/epi052/feroxbuster (Modern recursive scanner)
- **ffuf**: https://github.com/ffuf/ffuf (Fast web fuzzer)
- **Dirsearch**: https://github.com/maurosoria/dirsearch (Python directory scanner)
- **Hakrawler**: https://github.com/hakluke/hakrawler (Fast web crawler)
- **GoSpider**: https://github.com/jaeles-project/gospider (Fast spider with JS parsing)
- **LinkFinder**: https://github.com/GerbenJavado/LinkFinder (Extract endpoints from JS)
- **ParamSpider**: https://github.com/devanshbatham/ParamSpider (Parameter discovery)
- **Arjun**: https://github.com/s0md3v/Arjun (HTTP parameter discovery)

FURTHER READING:
- OWASP WSTG-INFO-05: Review Webpage Content for Information Leakage
- OWASP WSTG-INFO-07: Map Application Architecture
- OWASP WSTG-CONF-05: Enumerate Infrastructure and Application Admin Interfaces
- NIST SP 800-115: Section 7.4 - Web Application Testing"
    ),
];