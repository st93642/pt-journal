# CEH v12 Module Expansion Guide

## Current Status

✅ **Module 01: Introduction to Ethical Hacking** - COMPLETE (50 questions)

- File: `data/ceh/01-ethical-hacking/1.1-fundamentals.txt`
- Content: Ethical hacking fundamentals, methodologies, legal issues, types of hackers, penetration testing basics

⚠️ **Modules 02-20** - PENDING (directories created, content needed)

## File Format Template

All question files must use this exact pipe-delimited format:

```text
# Module Title
# Format: question|answer_a|answer_b|answer_c|answer_d|correct_idx|explanation|domain|subdomain

Question text here?|Answer A text|Answer B text|Answer C text|Answer D text|0|Explanation of the correct answer and why others are incorrect.|Module Name|Subdomain Name
```

**Fields**:

1. Question text (no pipes inside the text)
2. Answer A
3. Answer B  
4. Answer C
5. Answer D
6. Correct answer index (0=A, 1=B, 2=C, 3=D)
7. Detailed explanation
8. Module name (e.g., "02. Footprinting and Reconnaissance")
9. Subdomain (e.g., "2.1 Footprinting Techniques")

## Remaining Modules to Complete

### Module 02: Footprinting and Reconnaissance

**File**: `data/ceh/02-footprinting-reconnaissance/2.1-footprinting.txt`

**Content Topics**:

- Passive vs active reconnaissance
- Search engine techniques (Google dork operators)
- WHOIS, DNS enumeration
- Social media reconnaissance (OSINT)
- Web services (Netcraft, Shodan, Censys)
- Email harvesting (theHarvester, Hunter.io)
- Competitive intelligence gathering
- Website footprinting techniques
- Network reconnaissance tools
- Metadata extraction

**Tools to Cover**: Google, Maltego, theHarvester, Shodan, Censys, WHOIS, nslookup, dig, Netcraft, Recon-ng, SpiderFoot

---

### Module 03: Scanning Networks

**File**: `data/ceh/03-scanning-networks/3.1-scanning.txt`

**Content Topics**:

- TCP/UDP scanning techniques
- Nmap scan types (SYN, ACK, FIN, NULL, XMAS, etc.)
- OS fingerprinting
- Service version detection
- Banner grabbing
- Network discovery
- Ping sweeps and ICMP scanning
- Firewall/IDS evasion techniques
- Timing and performance options
- Output formats and analysis

**Tools to Cover**: Nmap, Masscan, Unicornscan, hping3, Angry IP Scanner, Advanced IP Scanner

---

### Module 04: Enumeration

**File**: `data/ceh/04-enumeration/4.1-enumeration.txt`

**Content Topics**:

- NetBIOS enumeration (Windows)
- SNMP enumeration
- LDAP enumeration
- NFS enumeration
- DNS zone transfers
- SMB/CIFS enumeration
- RPC enumeration
- User and group enumeration
- Share enumeration
- Service-specific enumeration

**Tools to Cover**: enum4linux, smbclient, rpcclient, snmpwalk, ldapsearch, nbtscan, Hyena

---

### Module 05: Vulnerability Analysis

**File**: `data/ceh/05-vulnerability-analysis/5.1-vulnerability.txt`

**Content Topics**:

- Vulnerability scanning vs penetration testing
- CVE and vulnerability databases
- CVSS scoring system
- Vulnerability classification
- Automated scanning tools
- Manual vulnerability analysis
- False positive identification
- Vulnerability prioritization
- Patch management
- Vulnerability disclosure timelines

**Tools to Cover**: Nessus, OpenVAS, Qualys, Rapid7, Nikto, OWASP ZAP scanner mode

---

### Module 06: System Hacking

**File**: `data/ceh/06-system-hacking/6.1-system-hacking.txt`

**Content Topics**:

- Password cracking techniques (dictionary, brute force, rainbow tables)
- Windows authentication (NTLM, Kerberos)
- Linux/Unix authentication
- Privilege escalation (vertical and horizontal)
- Password hash extraction
- Pass-the-hash attacks
- Keylogging and spyware
- Covering tracks and log manipulation
- Rootkits
- Backdoors and maintaining access

**Tools to Cover**: John the Ripper, Hashcat, Hydra, Medusa, Mimikatz, pwdump, SAMInside, L0phtCrack

---

### Module 07: Malware Threats

**File**: `data/ceh/07-malware-threats/7.1-malware.txt`

**Content Topics**:

- Malware types (viruses, worms, trojans, ransomware)
- Advanced Persistent Threats (APTs)
- Malware analysis (static and dynamic)
- Packers and obfuscation
- Dropper and loader mechanisms
- Command and control (C2) infrastructure
- Malware distribution methods
- Fileless malware
- Rootkits and bootkits
- Anti-virus evasion techniques

**Tools to Cover**: VirusTotal, Cuckoo Sandbox, PEStudio, Process Monitor, Process Explorer, Wireshark (for malware traffic)

---

### Module 08: Sniffing

**File**: `data/ceh/08-sniffing/8.1-sniffing.txt`

**Content Topics**:

- Packet sniffing fundamentals
- Promiscuous vs non-promiscuous mode
- ARP poisoning/spoofing
- MAC flooding
- DHCP starvation attacks
- DNS spoofing
- Man-in-the-Middle (MITM) attacks
- SSL/TLS stripping
- Switch port security
- Detecting sniffing attacks

**Tools to Cover**: Wireshark, tcpdump, Ettercap, Cain & Abel, dsniff, arpspoof, Bettercap

---

### Module 09: Social Engineering

**File**: `data/ceh/09-social-engineering/9.1-social-engineering.txt`

**Content Topics**:

- Social engineering principles and psychology
- Phishing (spear phishing, whaling, vishing)
- Pretexting and impersonation
- Baiting and quid pro quo
- Tailgating and piggybacking
- Dumpster diving
- Insider threats
- Physical security exploitation
- Social engineering toolkits
- Awareness and prevention

**Tools to Cover**: SET (Social-Engineer Toolkit), GoPhish, King Phisher, Evilginx2

---

### Module 10: Denial of Service

**File**: `data/ceh/10-denial-of-service/10.1-dos-ddos.txt`

**Content Topics**:

- DoS vs DDoS attacks
- Volumetric attacks (UDP flood, ICMP flood)
- Protocol attacks (SYN flood, fragmentation)
- Application layer attacks (HTTP flood, Slowloris)
- Amplification attacks (DNS, NTP, Memcached)
- Botnets and bot network infrastructure
- DDoS mitigation techniques
- CDN and scrubbing services
- Rate limiting and traffic filtering
- Incident response for DoS attacks

**Tools to Cover**: LOIC, HOIC, hping3, Slowloris, GoldenEye (for educational purposes only with authorization)

---

### Module 11: Session Hijacking

**File**: `data/ceh/11-session-hijacking/11.1-session-hijacking.txt`

**Content Topics**:

- Session management fundamentals
- Session tokens and cookies
- Session prediction and brute forcing
- Session fixation attacks
- Session sidejacking
- Man-in-the-Middle session interception
- Cross-site scripting (XSS) for session theft
- Session hijacking tools and techniques
- HTTPOnly and Secure cookie flags
- Session management best practices

**Tools to Cover**: Burp Suite, OWASP ZAP, Wireshark, Firesheep (historical), Hamster & Ferret

---

### Module 12: Evading IDSs, Firewalls, and Honeypots

**File**: `data/ceh/12-evading-ids-firewalls/12.1-evasion.txt`

**Content Topics**:

- IDS/IPS fundamentals (signature vs anomaly-based)
- Firewall types and architectures
- Honeypots and honeynets
- IDS evasion techniques (fragmentation, encoding)
- Firewall bypass methods (tunneling, proxying)
- Detecting honeypots
- Stealth scanning techniques
- Obfuscation and polymorphism
- Timing attacks to evade detection
- Testing IDS/IPS effectiveness

**Tools to Cover**: Nmap NSE scripts, fragroute, whisker, ADMutate, Snort/Suricata (for testing)

---

### Module 13: Hacking Web Servers

**File**: `data/ceh/13-web-servers/13.1-web-servers.txt`

**Content Topics**:

- Web server architecture and operation
- Common web server vulnerabilities
- Directory traversal attacks
- Web server misconfiguration
- Server-side include (SSI) injection
- HTTP response splitting
- WebDAV attacks
- Web server fingerprinting
- Default credentials and backdoors
- Web server hardening

**Tools to Cover**: Nikto, W3AF, Metasploit web server modules, DirBuster, Gobuster, WhatWeb

---

### Module 14: Hacking Web Applications

**File**: `data/ceh/14-web-applications/14.1-web-apps.txt`

**Content Topics**:

- OWASP Top 10 vulnerabilities
- Injection flaws (command injection, LDAP injection)
- Cross-Site Scripting (XSS) - reflected, stored, DOM-based
- Cross-Site Request Forgery (CSRF)
- Security misconfiguration
- Sensitive data exposure
- Broken authentication and session management
- Insecure direct object references (IDOR)
- XML External Entity (XXE) attacks
- Server-Side Request Forgery (SSRF)

**Tools to Cover**: Burp Suite, OWASP ZAP, SQLMap, XSSer, Commix, Wfuzz, ffuf

---

### Module 15: SQL Injection

**File**: `data/ceh/15-sql-injection/15.1-sql-injection.txt`

**Content Topics**:

- SQL injection fundamentals
- In-band SQL injection (error-based, union-based)
- Blind SQL injection (boolean-based, time-based)
- Out-of-band SQL injection
- SQL injection on different databases (MySQL, PostgreSQL, MSSQL, Oracle)
- Bypassing WAF and filters
- SQL injection tools and automation
- Database fingerprinting
- Data exfiltration techniques
- SQL injection prevention

**Tools to Cover**: SQLMap, Havij, jSQL Injection, NoSQLMap (for NoSQL databases)

---

### Module 16: Hacking Wireless Networks

**File**: `data/ceh/16-wireless-networks/16.1-wireless.txt`

**Content Topics**:

- Wireless standards (802.11 a/b/g/n/ac/ax)
- WEP, WPA, WPA2, WPA3 security protocols
- Wireless network discovery and mapping
- Rogue access points
- Evil twin attacks
- WPS attacks (Reaver)
- Deauthentication and disassociation attacks
- Wireless packet injection
- Bluetooth and RFID attacks
- Wireless security best practices

**Tools to Cover**: Aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng), Wifite, Reaver, Kismet, Wi fire, Fern Wifi Cracker

---

### Module 17: Hacking Mobile Platforms

**File**: `data/ceh/17-mobile-platforms/17.1-mobile.txt`

**Content Topics**:

- Mobile platform security (Android vs iOS)
- Mobile app vulnerabilities
- App reverse engineering and decompilation
- Insecure data storage
- Insecure communication
- Mobile malware and spyware
- Rooting and jailbreaking
- Mobile device management (MDM) bypass
- SMS and MMS attacks
- Mobile security best practices

**Tools to Cover**: MobSF, Drozer, Frida, APKTool, dex2jar, JADX, Objection

---

### Module 18: IoT and OT Hacking

**File**: `data/ceh/18-iot-ot-hacking/18.1-iot-ot.txt`

**Content Topics**:

- IoT device vulnerabilities
- SCADA and ICS security
- Industrial control system attacks
- IoT communication protocols (MQTT, CoAP, Zigbee)
- Firmware analysis and reverse engineering
- Hardware hacking basics
- Shodan and IoT search engines
- Smart home device vulnerabilities
- OT network segmentation
- ICS/SCADA security standards

**Tools to Cover**: Shodan, Censys, Firmware Analysis Toolkit, Binwalk, MQTT.fx, IoT Inspector

---

### Module 19: Cloud Computing

**File**: `data/ceh/19-cloud-computing/19.1-cloud.txt`

**Content Topics**:

- Cloud computing models (IaaS, PaaS, SaaS)
- Cloud deployment models (public, private, hybrid, multi-cloud)
- Cloud service provider vulnerabilities (AWS, Azure, GCP)
- Container security (Docker, Kubernetes)
- Serverless security (Lambda, Azure Functions)
- Cloud storage misconfigurations (S3 buckets)
- Cloud IAM attacks
- Cloud API vulnerabilities
- Cloud compliance and governance
- Shared responsibility model

**Tools to Cover**: ScoutSuite, Prowler, CloudSploit, Pacu, Cloud Custodian, AWS CLI, Azure CLI

---

### Module 20: Cryptography

**File**: `data/ceh/20-cryptography/20.1-cryptography.txt`

**Content Topics**:

- Symmetric vs asymmetric encryption
- Common algorithms (AES, RSA, ECC, DES, 3DES)
- Hashing algorithms (MD5, SHA-1, SHA-256, SHA-3)
- Digital signatures and certificates
- Public Key Infrastructure (PKI)
- SSL/TLS protocols and vulnerabilities
- Encryption attacks (brute force, birthday attack, rainbow tables)
- Cryptanalysis basics
- Crypto graphic key management
- Quantum cryptography basics

**Tools to Cover**: OpenSSL, GPG, HashCalc, HashMyFiles, Cryptool, John the Ripper (for hash cracking)

---

## Content Extraction Process

### From "CEHTM v12 - Ric Messier" Book

1. Each chapter covers one or more modules
2. Extract key concepts, definitions, and tools
3. Focus on "hands-on" and practical sections
4. Note exam tips and important call-outs

### From "CEH Study Guide - Matt Walker" Book

1. Matt Walker's book focuses on exam preparation
2. Extract practice questions from end-of-chapter reviews
3. Note "Exam Tips" and "Hacker's Toolbelt" sections
4. Use glossary terms for technical accuracy

### Additional Online Resources

- **EC-Council Official Resources**: <https://www.eccouncil.org/train-certify/certified-ethical-hacker-ceh/>
- **CEH Exam Blueprint**: Official exam objectives (version 12)
- **OWASP**: For web application security content
- **MITRE ATT&CK**: For adversary tactics and techniques
- **NIST**: For cryptography and security frameworks
- **Tool Documentation**: Official docs for Nmap, Metasploit, Burp Suite, etc.

## Question Writing Guidelines

1. **Clarity**: Questions must be clear and unambiguous
2. **Accuracy**: All technical information must be correct
3. **Relevance**: Focus on CEH exam objectives
4. **Difficulty**: Mix of easy (30%), medium (50%), hard (20%)
5. **Distractors**: Wrong answers should be plausible but clearly incorrect
6. **Explanations**: Provide detailed explanations that teach concepts
7. **Real-World**: Include practical scenarios and tool-based questions
8. **No Ambiguity**: Avoid "all of the above" or "none of the above" when possible

## Automation Script Idea

Create a Python script to help generate questions:

```python
import re

def create_ceh_question(question, answers, correct_idx, explanation, module, subdomain):
    """
    Helper function to generate properly formatted CEH questions
    """
    if len(answers) != 4:
        raise ValueError("Must provide exactly 4 answers")
    
    if not 0 <= correct_idx <= 3:
        raise ValueError("correct_idx must be 0-3")
    
    # Clean up any pipe characters in text
    question = question.replace("|", " ")
    answers = [a.replace("|", " ") for a in answers]
    explanation = explanation.replace("|", " ")
    
    # Format the question line
    line = f"{question}|{answers[0]}|{answers[1]}|{answers[2]}|{answers[3]}|{correct_idx}|{explanation}|{module}|{subdomain}"
    
    return line

# Example usage:
q = create_ceh_question(
    question="What port does HTTP use by default?",
    answers=["21", "80", "443", "8080"],
    correct_idx=1,
    explanation="HTTP uses port 80 by default. Port 443 is for HTTPS, port 21 is FTP, and 8080 is an alternative HTTP port.",
    module="02. Footprinting and Reconnaissance",
    subdomain="2.1 Footprinting Techniques"
)
print(q)
```

## Next Steps

1. **Priority**: Complete modules 2-6 first (core hacking methodology)
2. **Read Source Material**: Extract content from both CEH books
3. **Research Tools**: Add practical tool-focused questions
4. **Review & Test**: Ensure all questions parse correctly
5. **Expand**: Gradually add remaining modules

## Testing Each Module

After creating each question file:

```bash
# Test just the CEH module
cargo test --lib ceh -- --nocapture

# Test and run the application
cargo run --release

# Navigate to "Certified Ethical Hacker (CEH)" phase in the UI
# Select the new module to verify questions load correctly
```

## Estimated Time

- **Per Module**: 2-4 hours (research + writing + formatting + testing)
- **Total for Modules 2-20**: ~50-80 hours
- **Recommendation**: Complete 2-3 modules per day over 1-2 weeks

## Success Criteria

✅ Each module has >= 50 high-quality questions
✅ Questions cover all key topics from CEH curriculum
✅ All questions parse correctly (no format errors)
✅ Explanations are detailed and educational
✅ Questions include practical tool-based scenarios
✅ Difficulty mix is appropriate (30/50/20 split)
✅ Content aligns with CEH v12 exam objectives
