pub const TLS_SSL_ASSESSMENT_STEPS: &[(&str, &str)] = &[
    (
        "TLS/SSL assessment",
        "OBJECTIVE: Comprehensively evaluate SSL/TLS configurations, certificate validity, cipher suite strength, and protocol vulnerabilities to identify encryption weaknesses and potential man-in-the-middle attack vectors.

ACADEMIC BACKGROUND:
Transport Layer Security (TLS) and its predecessor SSL are cryptographic protocols that provide secure communications over networks. According to OWASP WSTG-CRYP-01 (Testing for Weak Transport Layer Security), improper TLS configuration is one of the most common security issues affecting web applications.

The NIST SP 800-52 Rev.2 \"Guidelines for the Selection, Configuration, and Use of TLS\" mandates:
- TLS 1.2 or higher (TLS 1.3 preferred)
- Strong cipher suites with forward secrecy
- Valid certificates from trusted Certificate Authorities
- Proper certificate validation and hostname verification

The MITRE ATT&CK framework identifies improper TLS configuration under T1040 (Network Sniffing) and T1557 (Adversary-in-the-Middle), as weak cryptography enables interception of sensitive communications.

CRITICAL TLS VULNERABILITIES:
- **Heartbleed (CVE-2014-0160)**: OpenSSL memory disclosure
- **POODLE (CVE-2014-3566)**: SSLv3 padding oracle
- **BEAST (CVE-2011-3389)**: TLS 1.0 CBC cipher attack
- **CRIME (CVE-2012-4929)**: TLS compression attack
- **FREAK (CVE-2015-0204)**: Export cipher downgrade
- **Logjam (CVE-2015-4000)**: Diffie-Hellman downgrade
- **DROWN (CVE-2016-0800)**: SSLv2 cross-protocol attack
- **SWEET32 (CVE-2016-2183)**: 64-bit block cipher attack

STEP-BY-STEP PROCESS:

1. CERTIFICATE INSPECTION AND VALIDATION:
   a) Basic Certificate Retrieval:
      ```bash
      # Retrieve certificate from server
      openssl s_client -connect target.com:443 -servername target.com < /dev/null 2>/dev/null | openssl x509 -text -noout

      # Save certificate to file
      echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 > target.crt

      # View certificate details
      openssl x509 -in target.crt -text -noout

      # Check certificate expiration
      openssl x509 -in target.crt -noout -dates

      # Extract subject and issuer
      openssl x509 -in target.crt -noout -subject -issuer

      # Check certificate fingerprint (SHA256)
      openssl x509 -in target.crt -noout -fingerprint -sha256
      ```

   b) Certificate Chain Verification:
      ```bash
      # Verify certificate chain
      openssl s_client -connect target.com:443 -showcerts

      # Verify against system CA bundle
      openssl verify target.crt

      # Verify with specific CA file
      openssl verify -CAfile ca-bundle.crt target.crt

      # Check certificate chain completeness
      openssl s_client -connect target.com:443 -servername target.com -showcerts 2>/dev/null | grep -E '(BEGIN CERTIFICATE|END CERTIFICATE|subject=|issuer=)'
      ```

   c) Subject Alternative Names (SAN) Analysis:
      ```bash
      # Extract all SANs (reveals internal domains)
      openssl x509 -in target.crt -noout -text | grep -A1 'Subject Alternative Name'

      # Parse SANs to list
      openssl x509 -in target.crt -noout -text | grep -oP 'DNS:\\K[^,]+'

      # Check for wildcard certificates
      openssl x509 -in target.crt -noout -subject | grep -o '\\*\\.'
      ```

      Intelligence gathering:
      - Internal hostnames in SANs
      - Infrastructure naming conventions
      - Wildcard usage patterns
      - Multiple domains on same certificate

2. COMPREHENSIVE TLS CONFIGURATION SCANNING:
   a) SSLScan (Fast Basic Analysis):
      ```bash
      # Basic SSL/TLS scan
      sslscan target.com

      # IPv6 scan
      sslscan --ipv6 target.com

      # Specify port
      sslscan target.com:8443

      # XML output for parsing
      sslscan --xml=sslscan_results.xml target.com
      ```

      Key findings:
      - Supported TLS versions
      - Accepted cipher suites
      - Certificate details
      - TLS compression status

   b) testssl.sh (Most Comprehensive):
      ```bash
      # Full comprehensive scan
      ./testssl.sh target.com

      # Fast scan (basic checks)
      ./testssl.sh --fast target.com

      # Check specific vulnerabilities
      ./testssl.sh --vulnerable target.com

      # Check only protocol support
      ./testssl.sh --protocols target.com

      # Check cipher suites
      ./testssl.sh --ciphers target.com

      # Check certificate
      ./testssl.sh --server-defaults target.com

      # JSON output
      ./testssl.sh --jsonfile results.json target.com

      # HTML report
      ./testssl.sh --htmlfile report.html target.com

      # Scan multiple hosts
      ./testssl.sh --file hosts.txt

      # Parallel scanning (4 connections)
      ./testssl.sh --parallel target.com
      ```

      testssl.sh checks:
      - All TLS vulnerabilities (Heartbleed, POODLE, BEAST, CRIME, etc.)
      - Protocol versions (SSLv2, SSLv3, TLS 1.0-1.3)
      - Cipher suite strength and order
      - Forward secrecy support
      - Certificate validity and trust chain
      - HSTS, HPKP headers
      - Certificate Transparency compliance

   c) Nmap SSL Scripts:
      ```bash
      # SSL enum ciphers
      nmap --script ssl-enum-ciphers -p 443 target.com

      # Check all SSL vulnerabilities
      nmap --script ssl-* -p 443 target.com

      # Specific vulnerability checks
      nmap --script ssl-heartbleed -p 443 target.com
      nmap --script ssl-poodle -p 443 target.com
      nmap --script ssl-dh-params -p 443 target.com

      # Certificate information
      nmap --script ssl-cert -p 443 target.com

      # Check for weak cipher suites
      nmap --script ssl-known-key -p 443 target.com
      ```

   d) sslyze (Python-based Analysis):
      ```bash
      # Comprehensive scan
      sslyze target.com

      # Check specific vulnerability
      sslyze --heartbleed target.com

      # Certificate info
      sslyze --certinfo target.com

      # Check cipher suites
      sslyze --sslv2 --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 target.com

      # JSON output
      sslyze --json_out=results.json target.com
      ```

3. PROTOCOL VERSION TESTING:
   ```bash
   # Test SSLv2 (should fail - deprecated since 2011)
   openssl s_client -connect target.com:443 -ssl2

   # Test SSLv3 (should fail - deprecated since 2015)
   openssl s_client -connect target.com:443 -ssl3

   # Test TLS 1.0 (should fail - deprecated since 2020)
   openssl s_client -connect target.com:443 -tls1

   # Test TLS 1.1 (should fail - deprecated since 2020)
   openssl s_client -connect target.com:443 -tls1_1

   # Test TLS 1.2 (should succeed - minimum requirement)
   openssl s_client -connect target.com:443 -tls1_2

   # Test TLS 1.3 (should succeed - current standard)
   openssl s_client -connect target.com:443 -tls1_3

   # Check protocol support summary
   for version in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
       echo -n \"Testing $version: \"
       timeout 2 openssl s_client -connect target.com:443 -$version < /dev/null 2>&1 | grep -q 'Cipher' && echo \"SUPPORTED\" || echo \"Not supported\"
   done
   ```

4. CIPHER SUITE ANALYSIS:
   ```bash
   # List all accepted ciphers
   nmap --script ssl-enum-ciphers -p 443 target.com

   # Test specific cipher
   openssl s_client -connect target.com:443 -cipher 'AES128-SHA'

   # Check for weak ciphers (NULL, EXPORT, DES, RC4, MD5)
   ./testssl.sh --ciphers target.com | grep -iE '(null|export|des|rc4|md5|weak)'

   # Check cipher order (server vs client preference)
   ./testssl.sh --server-preference target.com

   # Verify forward secrecy
   ./testssl.sh --fs target.com
   ```

   Cipher Suite Strength:
   - **Weak**: DES, 3DES, RC4, MD5, NULL, EXPORT, ANON
   - **Medium**: AES-CBC without forward secrecy
   - **Strong**: AES-GCM, ChaCha20-Poly1305 with ECDHE/DHE
   - **Modern**: TLS 1.3 cipher suites (AES-GCM, ChaCha20)

5. VULNERABILITY-SPECIFIC TESTING:
   a) Heartbleed (CVE-2014-0160):
      ```bash
      # Nmap check
      nmap -p 443 --script ssl-heartbleed target.com

      # testssl.sh check
      ./testssl.sh -H target.com

      # Manual check with python script
      python heartbleed-poc.py target.com 443
      ```

   b) POODLE (CVE-2014-3566):
      ```bash
      # Check SSLv3 support
      nmap -p 443 --script ssl-poodle target.com

      # testssl.sh check
      ./testssl.sh -O target.com
      ```

   c) BEAST (CVE-2011-3389):
      ```bash
      # Check TLS 1.0 CBC ciphers
      nmap -p 443 --script ssl-enum-ciphers target.com | grep -A20 'TLSv1.0' | grep CBC

      # testssl.sh check
      ./testssl.sh -B target.com
      ```

   d) CRIME (CVE-2012-4929):
      ```bash
      # Check TLS compression
      nmap -p 443 --script ssl-enum-ciphers target.com | grep -i compression

      # testssl.sh check
      ./testssl.sh -C target.com
      ```

   e) FREAK (CVE-2015-0204):
      ```bash
      # Check for EXPORT ciphers
      nmap -p 443 --script ssl-enum-ciphers target.com | grep -i export

      # testssl.sh check
      ./testssl.sh -F target.com
      ```

   f) Logjam (CVE-2015-4000):
      ```bash
      # Check DH parameters
      nmap -p 443 --script ssl-dh-params target.com

      # testssl.sh check
      ./testssl.sh -J target.com
      ```

   g) DROWN (CVE-2016-0800):
      ```bash
      # Check SSLv2 support
      ./testssl.sh -D target.com
      ```

   h) SWEET32 (CVE-2016-2183):
      ```bash
      # Check for 64-bit block ciphers (3DES, DES, Blowfish)
      ./testssl.sh --sweet32 target.com
      ```

6. CERTIFICATE TRANSPARENCY AND MONITORING:
   ```bash
   # Check Certificate Transparency logs
   curl -s \"https://crt.sh/?q=%.target.com&output=json\" | jq -r '.[].name_value' | sort -u

   # Verify CT compliance
   ./testssl.sh --ct target.com

   # Check for certificate issuance history
   curl -s \"https://crt.sh/?q=target.com&output=json\" | jq -r '.[] | \"\\(.not_before) - \\(.issuer_name)\"'
   ```

7. HTTP SECURITY HEADERS RELATED TO TLS:
   ```bash
   # Check HSTS (HTTP Strict Transport Security)
   curl -I https://target.com | grep -i strict-transport-security

   # Check HSTS with testssl.sh
   ./testssl.sh --headers target.com | grep -i HSTS

   # Check for HSTS preload eligibility
   curl -s https://hstspreload.org/api/v2/status?domain=target.com | jq

   # Verify HPKP (deprecated but may exist)
   curl -I https://target.com | grep -i public-key-pins
   ```

8. CERTIFICATE REVOCATION CHECKING:
   ```bash
   # Check OCSP (Online Certificate Status Protocol)
   openssl ocsp -issuer ca.crt -cert target.crt -url http://ocsp.server.com -resp_text

   # Check CRL (Certificate Revocation List)
   openssl x509 -in target.crt -noout -text | grep -A4 'CRL Distribution'

   # Verify OCSP stapling
   openssl s_client -connect target.com:443 -status -servername target.com < /dev/null 2>&1 | grep -A10 'OCSP'
   ```

WHAT TO LOOK FOR:
- **Deprecated Protocols**: SSLv2, SSLv3, TLS 1.0, TLS 1.1 (all deprecated)
- **Weak Ciphers**: DES, 3DES, RC4, MD5-based, NULL, EXPORT, ANON
- **Missing Forward Secrecy**: Ciphers without DHE or ECDHE
- **Self-Signed Certificates**: In production environments
- **Expired Certificates**: Past validity period
- **Certificate Mismatch**: Domain name doesn't match certificate CN/SAN
- **Incomplete Chain**: Missing intermediate certificates
- **Weak Key Length**: RSA < 2048 bits, ECDSA < 256 bits
- **Untrusted CA**: Certificate signed by unknown/untrusted authority
- **Missing HSTS**: No Strict-Transport-Security header
- **Compression Enabled**: TLS compression (CRIME vulnerability)
- **Known Vulnerabilities**: Heartbleed, POODLE, BEAST, FREAK, Logjam, DROWN

SECURITY IMPLICATIONS:
- **SSLv2/SSLv3**: Completely broken, enables DROWN and POODLE attacks
- **TLS 1.0/1.1**: Vulnerable to BEAST, deprecated by major browsers
- **Weak Ciphers**: Allow brute-force or cryptanalytic attacks
- **No Forward Secrecy**: Past communications can be decrypted if private key compromised
- **Heartbleed**: Memory disclosure, can leak private keys and session data
- **POODLE**: Padding oracle attack, plaintext recovery
- **Self-Signed Certs**: Enable man-in-the-middle attacks
- **Expired Certs**: Browser warnings, user trust issues
- **Missing HSTS**: Allows SSL stripping attacks
- **Known Vulnerabilities**: Multiple critical CVEs affecting encryption

COMMON PITFALLS:
- **Internal Services**: May legitimately use self-signed certificates
- **Legacy System Support**: Some old systems require TLS 1.0 for compatibility
- **Load Balancer Termination**: TLS terminated at load balancer, backend may be HTTP
- **Certificate Pinning**: Can break with legitimate certificate renewals
- **Multiple Virtual Hosts**: Different certificates per domain on same IP
- **CDN/WAF**: May have different TLS config than origin server
- **Port Variations**: Different TLS configs on non-standard ports (8443, 8080)
- **False Positives**: Some scanners report issues not applicable to specific scenarios
- **SNI Requirements**: Server Name Indication needed for virtual hosting

DOCUMENTATION REQUIREMENTS:
- **TLS Configuration Matrix**:
  | Protocol | Status | Cipher Suites | Vulnerabilities |
  |----------|--------|---------------|-----------------|
  | TLS 1.3 | Enabled | AES-GCM, ChaCha20 | None |
  | TLS 1.2 | Enabled | AES-GCM, ECDHE | None |
  | TLS 1.1 | Disabled | N/A | BEAST |

- Certificate details (issuer, expiration, SANs, key length)
- Vulnerability scan results (Heartbleed, POODLE, etc.)
- Cipher suite strength analysis
- Forward secrecy support status
- HSTS configuration and preload status
- Evidence screenshots of configuration weaknesses
- Comparison against NIST/Mozilla guidelines
- Recommendations for TLS hardening

COMPLIANCE REFERENCES:
- **PCI DSS 3.2.1**: Requires TLS 1.2+ for payment card data
- **NIST SP 800-52 Rev.2**: Federal TLS configuration guidelines
- **Mozilla SSL Configuration**: https://ssl-config.mozilla.org/ (Modern/Intermediate/Old profiles)
- **FIPS 140-2**: Cryptographic module validation
- **HIPAA**: Strong encryption for health data
- **GDPR**: Encryption as privacy safeguard

TOOLS REFERENCE:
- **testssl.sh**: https://testssl.sh/ (Most comprehensive CLI scanner)
- **SSLScan**: https://github.com/rbsec/sslscan (Fast basic scanner)
- **sslyze**: https://github.com/nabla-c0d3/sslyze (Python-based analysis)
- **Nmap SSL Scripts**: https://nmap.org/nsedoc/categories/ssl.html (Built-in to Nmap)
- **SSL Labs**: https://www.ssllabs.com/ssltest/ (Online comprehensive testing)
- **Certificate Transparency**: https://crt.sh/ (Certificate search)
- **HSTS Preload**: https://hstspreload.org/ (HSTS verification)

FURTHER READING:
- OWASP WSTG-CRYP-01: Testing for Weak Transport Layer Security
- NIST SP 800-52 Rev.2: Guidelines for TLS Implementation
- RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
- RFC 6797: HTTP Strict Transport Security (HSTS)
- Mozilla Server Side TLS: https://wiki.mozilla.org/Security/Server_Side_TLS
- SSL/TLS Best Practices by Qualys: https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices"
    ),
];