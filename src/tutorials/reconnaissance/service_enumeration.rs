pub const SERVICE_ENUMERATION_STEPS: &[(&str, &str)] = &[
    (
        "Service enumeration",
        "OBJECTIVE: Extract detailed information about services running on open ports to identify versions, configurations, and potential vulnerabilities for exploitation planning.

ACADEMIC BACKGROUND:
Service enumeration, also known as service fingerprinting, is the process of interacting with network services to gather intelligence about software versions, configurations, supported authentication methods, and underlying operating systems. This phase bridges port scanning and vulnerability assessment.

According to OWASP WSTG-INFO-02 (Fingerprint Web Server and Services), proper enumeration provides the foundation for identifying known vulnerabilities (CVEs) associated with specific service versions. The MITRE ATT&CK framework categorizes detailed service enumeration as T1046 (Network Service Scanning) and T1592 (Gather Victim Host Information).

The NIST SP 800-115 Technical Guide emphasizes that service enumeration should be exhaustive but non-disruptive, gathering maximum information while avoiding service crashes or authentication lockouts.

ENUMERATION METHODOLOGY:
1. **Banner Grabbing**: Capture service identification strings
2. **Protocol-Specific Queries**: Use protocol commands to elicit detailed responses
3. **NSE Script Enumeration**: Leverage Nmap scripts for deep inspection
4. **Vulnerability Cross-Reference**: Map versions to known CVEs
5. **Configuration Analysis**: Identify misconfigurations and weak settings

STEP-BY-STEP PROCESS:

1. BASIC BANNER GRABBING (All Services):
   ```bash
   # Netcat banner grab (TCP services)
   nc -v target.com 21        # FTP banner
   nc -v target.com 22        # SSH banner
   nc -v target.com 25        # SMTP banner
   nc -v target.com 80        # HTTP banner
   nc -v target.com 110       # POP3 banner
   nc -v target.com 143       # IMAP banner
   
   # Nmap banner grabbing
   nmap -sV --script banner target.com
   
   # Automated banner collection
   nmap -p 21,22,23,25,80,110,143,443,3306,3389,5432,8080 -sV --script banner target.com -oA banners
   
   # Quick banner grab with timeout
   timeout 5 bash -c 'echo \"\" | nc target.com 80'
   ```
   
   Analysis: Banner strings often reveal exact service versions (e.g., \"SSH-2.0-OpenSSH_7.4\")

2. HTTP/HTTPS WEB SERVICE ENUMERATION:
   a) HTTP Headers Analysis:
      ```bash
      # Basic header inspection
      curl -I https://target.com
      curl -s -I https://target.com | grep -i server
      
      # Verbose header analysis
      curl -v https://target.com 2>&1 | grep -i '^< '
      
      # Check all HTTP methods
      curl -X OPTIONS https://target.com -i
      
      # Examine security headers
      curl -I https://target.com | grep -iE '(X-Frame|X-XSS|Content-Security|Strict-Transport)'
      
      # Using httpx for header inspection
      echo \"target.com\" | httpx -silent -status-code -tech-detect -title -server
      ```
   
   b) SSL/TLS Certificate Analysis:
      ```bash
      # View certificate details
      openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -text -noout
      
      # Extract subject alternative names (SANs)
      openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -noout -text | grep \"DNS:\"
      
      # Check supported TLS versions
      nmap --script ssl-enum-ciphers -p 443 target.com
      
      # Detect SSL/TLS vulnerabilities
      nmap --script ssl-* -p 443 target.com
      
      # SSLScan comprehensive analysis
      sslscan target.com
      
      # TestSSL.sh detailed audit
      testssl.sh https://target.com
      ```
      
      Certificate intelligence:
      - Organization details
      - Internal hostnames in SANs
      - Certificate issuer and chain
      - Validity period
      - Weak ciphers or protocols
   
   c) Web Technology Fingerprinting:
      ```bash
      # WhatWeb identification
      whatweb -a 3 https://target.com
      
      # Wappalyzer CLI
      wappalyzer https://target.com
      
      # Using httpx with tech detection
      echo \"target.com\" | httpx -tech-detect -status-code
      
      # Nikto web scanner (includes tech detection)
      nikto -h https://target.com -o nikto_results.txt
      
      # Retire.js for JavaScript library vulnerabilities
      retire --jspath https://target.com
      ```

3. SSH SERVICE ENUMERATION (Port 22):
   ```bash
   # SSH version banner
   nc target.com 22
   
   # Detailed SSH enumeration
   nmap -p 22 --script ssh-* target.com
   
   # Check SSH key algorithms and ciphers
   nmap -p 22 --script ssh2-enum-algos target.com
   
   # SSH audit for weak configurations
   ssh-audit target.com
   
   # Detect SSH authentication methods
   nmap -p 22 --script ssh-auth-methods target.com
   
   # Try SSH connection to see supported methods
   ssh -v user@target.com
   ```
   
   Analysis points:
   - OpenSSH version (check against CVE database)
   - Supported key exchange algorithms (weak ones: diffie-hellman-group1-sha1)
   - Cipher suites (avoid: arcfour, 3des-cbc)
   - Authentication methods (password, publickey, keyboard-interactive)
   - Host key types (RSA, ECDSA, ED25519)

4. FTP SERVICE ENUMERATION (Port 21):
   ```bash
   # Anonymous FTP access test
   ftp target.com
   # Try username: anonymous, password: anonymous@example.com
   
   # Nmap FTP scripts
   nmap -p 21 --script ftp-* target.com
   
   # Check for anonymous access
   nmap -p 21 --script ftp-anon target.com
   
   # FTP bounce attack test
   nmap -p 21 --script ftp-bounce target.com
   
   # Enumerate FTP server capabilities
   echo \"HELP\" | nc target.com 21
   echo \"FEAT\" | nc target.com 21
   ```
   
   Security checks:
   - Anonymous login enabled? (major finding)
   - Writable directories (potential malware upload)
   - FTP version (ProFTPD 1.3.5 has known RCE)
   - Cleartext transmission (recommend SFTP/FTPS)

5. SMB/CIFS ENUMERATION (Ports 139, 445):
   ```bash
   # Enumerate SMB shares
   smbclient -L //target.com -N
   
   # Comprehensive SMB enumeration
   enum4linux -a target.com
   
   # Modern enum4linux-ng
   enum4linux-ng -A target.com -oA enum4linux_results
   
   # Nmap SMB scripts
   nmap -p 139,445 --script smb-* target.com
   
   # Check for SMB vulnerabilities
   nmap -p 445 --script smb-vuln-* target.com
   
   # SMB version detection
   nmap -p 445 --script smb-protocols target.com
   
   # CrackMapExec SMB enumeration
   crackmapexec smb target.com --shares
   crackmapexec smb target.com --users
   crackmapexec smb target.com --groups
   
   # NetBIOS enumeration
   nbtscan target.com
   nmblookup -A target.com
   ```
   
   Critical findings:
   - SMBv1 enabled (EternalBlue MS17-010 vulnerability)
   - Null session enumeration (no authentication required)
   - Readable/writable shares
   - User/group enumeration
   - Domain controller identification
   - Guest account enabled

6. SMTP ENUMERATION (Port 25, 587, 465):
   ```bash
   # SMTP banner grab
   nc target.com 25
   
   # SMTP commands
   telnet target.com 25
   HELO example.com
   VRFY root           # Verify user exists
   EXPN admin          # Expand mailing list
   MAIL FROM:<test@example.com>
   RCPT TO:<user@target.com>
   
   # Nmap SMTP scripts
   nmap -p 25 --script smtp-* target.com
   
   # User enumeration
   smtp-user-enum -M VRFY -U /usr/share/wordlists/users.txt -t target.com
   
   # Check for open relay
   nmap -p 25 --script smtp-open-relay target.com
   
   # SMTP commands enumeration
   nmap -p 25 --script smtp-commands target.com
   ```
   
   Analysis:
   - VRFY/EXPN enabled? (user enumeration vulnerability)
   - Open relay (can send spam)
   - SMTP version and vulnerabilities
   - Supported authentication mechanisms
   - StartTLS available?

7. SNMP ENUMERATION (Ports 161, 162):
   ```bash
   # SNMP community string brute force
   onesixtyone -c /usr/share/wordlists/snmp-strings.txt target.com
   
   # SNMP walk (requires community string)
   snmpwalk -v2c -c public target.com
   
   # System information
   snmpwalk -v2c -c public target.com system
   
   # Network interfaces
   snmpwalk -v2c -c public target.com interfaces
   
   # Running processes
   snmpwalk -v2c -c public target.com hrSWRunName
   
   # Installed software
   snmpwalk -v2c -c public target.com hrSWInstalledName
   
   # Nmap SNMP scripts
   nmap -sU -p 161 --script snmp-* target.com
   
   # SNMPv3 enumeration (requires credentials)
   snmpwalk -v3 -l authPriv -u snmpuser -a SHA -A authpass -x AES -X privpass target.com
   ```
   
   SNMP OIDs of interest:
   - 1.3.6.1.2.1.1.1.0 (System description)
   - 1.3.6.1.2.1.1.5.0 (Hostname)
   - 1.3.6.1.2.1.25.4.2.1.2 (Running processes)
   - 1.3.6.1.2.1.25.6.3.1.2 (Installed software)
   - 1.3.6.1.2.1.2.2.1.2 (Network interfaces)

8. DATABASE SERVICE ENUMERATION:
   a) MySQL/MariaDB (Port 3306):
      ```bash
      # MySQL version detection
      nmap -p 3306 --script mysql-info target.com
      
      # Enumerate MySQL users
      nmap -p 3306 --script mysql-users --script-args mysqluser=root,mysqlpass='' target.com
      
      # MySQL vulnerabilities
      nmap -p 3306 --script mysql-vuln-* target.com
      
      # MySQL empty password check
      nmap -p 3306 --script mysql-empty-password target.com
      
      # Direct connection attempt
      mysql -h target.com -u root -p
      ```
   
   b) PostgreSQL (Port 5432):
      ```bash
      # PostgreSQL version
      nmap -p 5432 --script pgsql-brute target.com
      
      # Direct connection
      psql -h target.com -U postgres
      ```
   
   c) MSSQL (Port 1433):
      ```bash
      # MSSQL info gathering
      nmap -p 1433 --script ms-sql-info target.com
      
      # MSSQL empty password
      nmap -p 1433 --script ms-sql-empty-password target.com
      
      # MSSQL command execution (if accessible)
      nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password='' target.com
      ```
   
   d) MongoDB (Port 27017):
      ```bash
      # MongoDB enumeration
      nmap -p 27017 --script mongodb-* target.com
      
      # Check for no authentication
      mongo target.com:27017
      ```
   
   e) Redis (Port 6379):
      ```bash
      # Redis banner grab
      nc target.com 6379
      INFO
      
      # Redis enumeration
      nmap -p 6379 --script redis-* target.com
      
      # Direct connection
      redis-cli -h target.com
      INFO
      CONFIG GET *
      ```

9. RDP ENUMERATION (Port 3389):
   ```bash
   # RDP certificate information
   nmap -p 3389 --script rdp-ntlm-info target.com
   
   # RDP encryption check
   nmap -p 3389 --script rdp-enum-encryption target.com
   
   # RDP BlueKeep vulnerability check
   nmap -p 3389 --script rdp-vuln-ms12-020 target.com
   
   # RDP connection with rdesktop
   rdesktop -u username target.com
   
   # Using xfreerdp for connection attempt
   xfreerdp /v:target.com /u:username /p:password
   ```

10. LDAP ENUMERATION (Ports 389, 636, 3268):
    ```bash
    # Anonymous LDAP bind attempt
    ldapsearch -x -H ldap://target.com -b \"\" -s base
    
    # Enumerate naming contexts
    ldapsearch -x -H ldap://target.com -s base namingContexts
    
    # Full LDAP dump (if anonymous allowed)
    ldapsearch -x -H ldap://target.com -b \"dc=example,dc=com\"
    
    # Nmap LDAP scripts
    nmap -p 389 --script ldap-* target.com
    
    # LDAP brute force
    nmap -p 389 --script ldap-brute target.com
    ```

11. DNS SERVICE ENUMERATION (Port 53):
    ```bash
    # DNS version query
    dig @target.com version.bind CHAOS TXT
    
    # DNS service info
    nmap -p 53 --script dns-nsid target.com
    
    # Zone transfer attempt (from DNS enumeration phase)
    dig @target.com target.com AXFR
    
    # DNS recursion test
    nmap -p 53 --script dns-recursion target.com
    ```

12. VPN SERVICE ENUMERATION:
    a) IKE/IPsec (Port 500 UDP):
       ```bash
       # IKE scan
       ike-scan target.com
       
       # Nmap IKE scripts
       nmap -sU -p 500 --script ike-version target.com
       ```
    
    b) OpenVPN (Port 1194):
       ```bash
       # OpenVPN service detection
       nmap -p 1194 --script openvpn-info target.com
       ```

WHAT TO LOOK FOR:
- **Version Numbers**: Exact versions for CVE lookup (e.g., Apache 2.4.49 = CVE-2021-41773 RCE)
- **Default Credentials**: admin/admin, root/toor, sa/sa, postgres/postgres
- **Anonymous Access**: FTP anonymous, SMB null sessions, SNMP \"public\" community
- **Weak Encryption**: SSLv3, TLS 1.0, weak ciphers (RC4, DES, 3DES)
- **Information Disclosure**: Detailed error messages, verbose banners, directory listings
- **Misconfigurations**: Open relays (SMTP), recursion (DNS), guest access (SMB)
- **Deprecated Protocols**: Telnet, FTP, SNMPv1/v2c, SMBv1
- **Service Combinations**: SQL+Web (SQL injection), LDAP+Web (LDAP injection)
- **Unusual Services**: Custom applications, development servers (Jenkins, GitLab)
- **Internal Hostnames**: In SSL certificates, SMTP banners, error messages

SECURITY IMPLICATIONS:
- **SMBv1**: Vulnerable to EternalBlue (MS17-010), WannaCry, NotPetya
- **Anonymous FTP**: Potential data leakage or malware upload point
- **SNMP \"public\"**: Entire system configuration and secrets exposed
- **Open LDAP**: Full Active Directory enumeration without authentication
- **Weak SSH**: Vulnerable to brute force, man-in-the-middle attacks
- **MySQL Root No Password**: Direct database compromise
- **Redis No Auth**: Can achieve RCE via SLAVEOF or CONFIG SET
- **Elasticsearch Open**: Data exfiltration, potential RCE
- **MongoDB No Auth**: Full database access (common misconfiguration)

COMMON PITFALLS:
- **Service Hiding Versions**: Some services obscure version info in banners
- **Virtual Hosting**: Web servers may respond differently per vhost
- **Load Balancers**: May distribute requests to different backends with different versions
- **WAFs/Firewalls**: May intercept and modify service responses
- **Rate Limiting**: Aggressive enumeration triggers IPS/IDS blocks
- **Application Firewalls**: Block enumeration attempts (e.g., SQL commands in MySQL probe)
- **Protocol Complexity**: Some protocols require specific handshakes (Kerberos, NTLM)
- **Timeouts**: Services may have connection limits or timeouts
- **Authentication Required**: Many modern services require auth before revealing info

DOCUMENTATION REQUIREMENTS:
- **Service Inventory Matrix**:
  | Port | Protocol | Service | Version | CVEs | Risk |
  |------|----------|---------|---------|------|------|
  | 22 | TCP | OpenSSH | 7.4 | CVE-2021-28041 | Medium |
  
- Complete banner captures (screenshots or text files)
- Configuration findings (enabled/disabled features)
- Evidence of misconfigurations with security impact
- Comparison against vendor best practices
- Recommendations for service hardening
- List of services that should be disabled or firewalled

AUTOMATION AND EFFICIENCY:
```bash
# All-in-one enumeration script
#!/bin/bash
TARGET=\"target.com\"

# Web services
whatweb $TARGET
nikto -h $TARGET

# SSH
ssh-audit $TARGET

# SMB
enum4linux-ng $TARGET -oA enum4linux_out

# SNMP
onesixtyone $TARGET
snmpwalk -v2c -c public $TARGET system

# Comprehensive Nmap NSE
nmap -p- -sV --script \"default and safe\" $TARGET -oA full_enum
```

TOOLS REFERENCE:
- **Nmap NSE**: https://nmap.org/nsedoc/ (600+ scripts for all services)
- **enum4linux-ng**: https://github.com/cddmp/enum4linux-ng (Modern SMB enumeration)
- **ssh-audit**: https://github.com/jtesta/ssh-audit (SSH configuration auditing)
- **testssl.sh**: https://testssl.sh/ (SSL/TLS comprehensive testing)
- **WhatWeb**: https://github.com/urbanadventurer/WhatWeb (Web tech identification)
- **Nikto**: https://github.com/sullo/nikto (Web server scanner)
- **CrackMapExec**: https://github.com/byt3bl33d3r/CrackMapExec (Multi-protocol pentesting)
- **Impacket**: https://github.com/SecureAuthCorp/impacket (Python SMB/LDAP/Kerberos)

FURTHER READING:
- OWASP WSTG-INFO-02: Fingerprint Web Server
- NIST SP 800-115: Section 7.3 - Service Identification
- SANS SEC560: Network Penetration Testing
- Nmap NSE Documentation: https://nmap.org/book/nse.html
- PTES Technical Guidelines: Section 3.4 - Service Enumeration
- CIS Benchmarks: Hardening guides for all major services"
    ),
];