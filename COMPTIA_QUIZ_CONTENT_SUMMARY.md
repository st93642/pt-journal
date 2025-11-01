# CompTIA Security+ Quiz Content Summary

## Overview

This document provides a comprehensive summary of all quiz content created for the PT Journal application's CompTIA Security+ SY0-701 certification preparation phase.

## Current Status & Target

- **Current Questions**: 763 (updated after Domain 3.0 COMPLETE - **DOMAINS 1.0, 2.0, 3.0 COMPLETE** ✅)
- **Target Questions**: 1,000-1,500 questions
- **Current Progress**: 51-76% complete
- **Total Quiz Steps**: 23 subdomains
- **Domains Covered**: 5 (All CompTIA Security+ SY0-701 domains)
- **Question Format**: Multiple choice with detailed explanations and academic descriptions

## Latest Update

**Date**: November 1, 2025  
**Domain 3.0 (Security Architecture) - ✅ COMPLETE** (All subdomains: 3.1, 3.2, 3.3, 3.4)

**Most Recent Expansion**:

- **Domain 3.4 (Resilience and Recovery)**: ✅ Expanded from 13 to 52 questions (+39)
- **Domain 3.3 (Data Protection)**: ✅ Expanded from 12 to 52 questions (+40)
- **Domain 3.2 (Security Infrastructure)**: ✅ Expanded from 12 to 51 questions (+39)
- **Domain 3.1 (Architecture Models)**: ✅ Expanded from 12 to 52 questions (+40)

- **Domain 2.5 (Mitigation Techniques)**: ✅ Expanded from 12 to 52 questions (+40)

- **Domain 2.4 (Indicators of Malicious Activity)**: ✅ Expanded from 12 to 50 questions
  - **Malware types**: Fileless malware (memory-resident, PowerShell/WMI exploitation, no disk artifacts), bloatware (pre-installed unnecessary software, performance degradation), logic bombs (condition-triggered malicious code, UBS 2006/Fannie Mae 2002 examples, insider threat), ransomware (file encryption, .wncry/.locky/.encrypted extensions, WannaCry/Ryuk/REvil/Maze/Conti variants, double extortion, no-ransom payment principle), adware (unwanted toolbars, pop-ups, Superfish 2015 Lenovo), rootkits (kernel-level hiding, concealing other malware), trojans, worms (self-replicating, WannaCry/Slammer/Code Red/Sasser), keyloggers, spyware, botnets (Mirai/Emotet/ZeroAccess, DDoS infrastructure, $5-50/hour dark web rental)
  - **Behavioral indicators - Authentication**: Brute force attacks (multiple failed logins, account lockouts, password spraying, credential stuffing, off-hours attempts), impossible travel (geographically impossible logins, NY-Tokyo 10min, Azure AD detection, credential compromise), concurrent sessions (simultaneous logins from distant locations), unauthorized password reset emails (account takeover reconnaissance, phishing vs. legitimate reset distinction)
  - **Behavioral indicators - Network**: Beaconing (periodic C2 communication, fixed intervals, APT characteristic, jitter/DGA evasion, SIEM/NetFlow detection), blocked website access attempts (malware C2 cycling through backup servers, DGA domains, failed DNS lookups), unusual outbound connections (reverse shells on ports 4444/5555/1337, high ports bypassing ingress rules, Metasploit defaults, egress filtering importance), DNS tunneling (50+ character subdomains, base64/hex encoding, TXT/NULL/CNAME queries, Iodine/DNSCat2, Turla APT 2013), bandwidth spikes during off-hours (data exfiltration, Colonial Pipeline 2021 100GB, DLP evasion via compression/encryption), SMTP traffic from non-mail servers (spam botnet, Emotet millions daily, egress filtering), regular chunked data transfers (controlled exfiltration, bandwidth throttling, Sony 2014 100TB, OPM 2015 21.5M records)
  - **Behavioral indicators - System**: Missing/deleted logs (attacker anti-forensics, Target 2013 40GB credit cards hidden, centralized SIEM forwarding, append-only storage), antivirus disabled (malware neutralizing controls, Emotet/TrickBot/ransomware tactics, tamper protection/EDR importance), memory leaks (steady RAM increase, Boeing 787 248-day reboot, DoS conditions, RAII defense), unauthorized user accounts (AD persistence, SolarWinds 2020 fake accounts, Domain Admin privileges, Event ID 4720 monitoring), unauthorized scheduled tasks (persistence mechanism, Emotet extensively uses, PowerShell obfuscated commands, Task Scheduler/cron abuse), high CPU usage (cryptojacking, Monero mining, Coinhive JavaScript miner, 70-100% sustained usage, mining pool connections), system clock tampering (anti-forensics, log timeline disruption, certificate invalidation for MitM, NTP synchronization monitoring)
  - **Behavioral indicators - Processes**: Unusual parent-child relationships (Word→PowerShell, Excel→cmd.exe, NotPetya 2017 Office macros, Sysmon Event ID 1/10, EDR detection), execution from temp directories (%TEMP%/%APPDATA%/Downloads, Emotet random names, AppLocker blocking user-writable dirs), privilege escalation (SYSTEM/Administrator processes that shouldn't, Print Spooler/Dirty COW exploits, token manipulation), encoded PowerShell (-EncodedCommand/-enc, base64 obfuscation, Emotet/TrickBot/ransomware, script block logging Event ID 4104, Constrained Language Mode)
  - **Behavioral indicators - Registry/Files**: Registry persistence (Run keys, Services, Winlogon, AppInit_DLLs, Sysmon Event ID 13, Sysinternals Autoruns), Unicode/special character registry keys (evasion via invisible keys, homoglyph attacks, BadRabbit 2016, programmatic access needed vs. regedit GUI), double file extensions (document.pdf.exe, Windows hiding .exe/.scr/.vbs/.pif, Locky 2017, magic bytes validation), suspicious icons (executable with PDF/Word icon, file signature mismatch)
  - **Web-based indicators**: Directory traversal attempts (../../../../etc/passwd in logs, 404 errors reconnaissance, URL encoding %2e%2e%2f, chroot jails/input validation), SQL injection patterns (UNION SELECT, OR 1=1, ' OR '1'='1', Heartland 2008 130M cards, parameterized queries/DAM), XSS payloads (<script> tags, JavaScript in inputs, document.cookie theft, British Airways Magecart 2018 380K cards, CSP/HttpOnly flags)
  - **Advanced indicators**: Man-in-the-middle certificates (untrusted CA installation, DigiNotar 2011 Iran surveillance, SSL inspection, certificate pinning/HSTS), browser hijackers (search engine/homepage changes, Conduit/MyWebSearch/Ask/Babylon toolbars, bundled software, DNS/proxy modifications), PUPs/bundleware (performance degradation post-installation, SourceForge 2015/CNET wrappers, Custom vs. Express installation, AdwCleaner/Malwarebytes removal), port scanning (reconnaissance, sequential connections, Nmap/Masscan/Zmap, WannaCry SMB 445 scans, Snort/Suricata detection), worm propagation (simultaneous mass infections, WannaCry 200K systems in 4 days, Slammer 75K in 10min, network segmentation containment), webcam/mic activation (RAT spyware, BlackShades/DarkComet/njRAT, Miss Teen USA 2013 case, FlexiSpy/mSpy stalkerware, LED indicators, physical privacy covers)
  - **Attack patterns**: Account takeover (impossible travel, concurrent sessions, password reset spam, geolocation policies), data exfiltration (off-hours bandwidth, chunked transfers, DNS tunneling, regular intervals, DLP evasion), persistence mechanisms (registry Run keys, scheduled tasks, unauthorized accounts, fileless memory-resident), anti-forensics (log deletion, clock tampering, Unicode registry keys, process injection), cryptojacking (unauthorized mining, high CPU, Monero XMR, Coinhive/Jenkins campaigns, mining pool blocking)
  - **Real-world examples**: Emotet (botnet, email spam, scheduled tasks, %APPDATA% execution, tamper AV, millions emails daily, 2021 takedown), WannaCry/Slammer/Code Red/Sasser worms, Mirai botnet (2016, 600K IoT, 1Tbps), Target 2013 (log deletion, 40GB cards), Colonial Pipeline 2021 (100GB exfiltration), Sony 2014 (100TB over weeks), OPM 2015 (21.5M records), SolarWinds 2020 (fake accounts), DigiNotar 2011, British Airways Magecart 2018, Boeing 787 (248-day reboot), Miss Teen USA webcam hack 2013
- **Domain 2.3 (Vulnerability Types)**: ✅ Expanded from 12 to 50 questions
  - **Application vulnerabilities**: Memory injection (Code Red worm), buffer overflow (Slammer worm, arbitrary code execution), race conditions (TOC/TOU, airline seat overbooking), malicious updates (CCleaner 2017 supply chain attack)
  - **Operating system vulnerabilities**: BlueKeep (Windows remote access), end-of-life systems (Windows XP post-2014), legacy system exploitation
  - **Web-based vulnerabilities**: SQL injection (SQLI with ' OR '1'='1' --, stored procedures defense), Cross-site scripting (XSS with <script> tags, cookie stealing, input validation), file upload (PHP/JSP execution, magic bytes validation), command injection (system() exploitation, shell metacharacters), directory traversal (../ sequences, /etc/passwd access), XXE injection (XML external entities, SSRF), LDAP injection (Active Directory bypass)
  - **Hardware vulnerabilities**: Firmware vulnerabilities, end-of-life hardware, legacy system risks
  - **Virtualization vulnerabilities**: VM escape (hypervisor exploitation, lateral movement east-west), VM sprawl (uncontrolled VM creation, unpatched systems), resource reuse (data remnants on shared disks)
  - **Cloud-specific vulnerabilities**: Shared tenancy risks (side-channel attacks, multi-tenant isolation), inadequate configuration management (publicly accessible S3 buckets, exposed databases), IAM flaws (excessive permissions, weak authentication, orphaned accounts), CASB (Cloud Access Security Broker for shadow IT discovery and policy enforcement)
  - **Supply chain vulnerabilities**: Service provider breaches, hardware supply chain (counterfeit components, firmware backdoors, nation-state manufacturing compromises), software supply chain (third-party library malware, bill of materials, SCA tools)
  - **Cryptographic vulnerabilities**: CA compromise (DigiNotar 2011, Comodo breaches, fraudulent certificates), key compromise (theft, weak generation, HSMs), flawed implementation (hardcoded keys, custom crypto, ECB mode), outdated algorithms (DES 56-bit, MD5, SHA-1, RC4, DES Challenge 1997), side-channel attacks (power analysis, timing, EM, acoustic, cache-timing), flawed RNG (Debian OpenSSL 2008, predictable keys), SSL/TLS downgrade (POODLE attack, backward compatibility exploitation), SSL stripping (HTTPS→HTTP, HSTS defense)
  - **Misconfiguration vulnerabilities**: Firewall misconfigurations (overly permissive rules, FTP/Telnet/RDP exposure, compliance violations), default credentials (admin/admin, public credential databases), unpatched software (WannaCry 2017 via unpatched Windows), excessive privileges (Domain Admin for all users, privilege creep, least privilege violations)
  - **Mobile device vulnerabilities**: Jailbreaking (iOS restriction bypass, App Store evasion, MDM bypass), rooting (Android superuser access, verified boot disabled, banking app detection), sideloading (APK installation from untrusted sources, Play Protect bypass, warranty voiding)
  - **Additional injection vulnerabilities**: Integer overflow (Boeing 787 248-day reboot), memory leaks (resource exhaustion, DoS, RAII defense), zero-day vulnerabilities (Log4Shell CVE-2021-44228, ProxyLogon, EternalBlue/WannaCry, nation-state stockpiling, $1M+ prices)
  - **Real-world examples**: CCleaner supply chain (2017), Slammer worm (2003), Code Red worm (2001), BlueKeep, WannaCry (2017), POODLE attack, DigiNotar breach (2011), Debian OpenSSL (2008), Boeing 787 integer overflow, Log4Shell, SolarWinds
- **Domain 2.2 (Threat Vectors and Attack Surfaces)**: ✅ Expanded from 12 to 51 questions
  - **Message-based vectors**: Email phishing (untargeted attacks, deceptive emails, bank impersonation), SMS smishing (text message phishing, malicious links, mobile malware), Instant messaging (IM attacks, social media impersonation, end-to-end encryption advantages/vulnerabilities)
  - **Image-based vectors**: Steganography (hidden malicious code in images), embedded malware in image files, exploiting image processing vulnerabilities
  - **File-based vectors**: Malicious PDF documents with embedded scripts, macro-enabled Office documents, weaponized archives, trojanized executables, file screening and attachment blocking
  - **Voice call vectors**: Vishing (voice phishing, fake helpdesk/HR calls), caller ID spoofing, voicemail attacks, IRS impersonation scams
  - **Removable device vectors**: USB drop attacks (parking lot scenarios, reception area placement), external hard drive malware transmission, sandbox defense strategies for found devices
  - **Vulnerable software**: Client-based scanning (agent on host, continuous monitoring, central reporting), agentless scanning (Nmap, Wireshark, threat actor preference), unsupported/legacy software exploitation, patch management importance
  - **Unsecure networks**: Wireless (open authentication, WPA3 encryption, SSID broadcast disabling, MAC filtering), Wired (802.1X authentication, unused port security, patch cable removal), Bluetooth/PAN (easy pairing vulnerabilities, non-discoverable mode)
  - **Open service ports**: FTP/Telnet/SMB unnecessary services, port scanning and closure, firewall rules, principle of least functionality
  - **Default credentials**: Manufacturer defaults (admin/admin, root/password), posted on public websites, automated scanning detection
  - **Supply chain vectors**: MSPs (managed service providers, cascading breaches, privileged access risks), Vendors (risk assessments, MFA requirements, access segmentation), Suppliers (hardware backdoors, firmware compromises, trusted foundries), Software distribution (compromised update mechanisms, SolarWinds/NotPetya examples)
  - **Social engineering - Phishing variants**: Generic phishing (tax refund scams, wide net attacks), Spear phishing (targeted board of directors, personalized content), Phishing campaign simulations (mock attacks, remedial training), Smishing with malicious downloads
  - **Social engineering - Deception**: Misinformation vs. Disinformation (false information spread, intentional manipulation), Impersonation (false identity adoption, police/helpdesk), Pretexting (fabricated scenarios, fake tech support), IRS/government impersonation
  - **Social engineering - Advanced**: Business email compromise (invoice scams, payment redirect), Watering hole attacks (2013 U.S. Dept of Labor example, compromised legitimate websites), Brand impersonation (bank mimicry, trademark monitoring), Typo squatting (arnazon.com, similar domains, URL hijacking)
  - **Additional vectors**: Shadow IT (unauthorized cloud services, CASB detection), Zero-day vulnerabilities (no available patches, behavioral analysis), OSINT reconnaissance (social media monitoring for targeted attacks), Combined attack techniques (LinkedIn recruiter impersonation)
  - **Defense strategies**: Email filtering and anti-phishing tools (SPF/DKIM/DMARC), Input validation and secure coding (OWASP guidelines), Network segmentation and access controls, Security awareness training across all platforms, Multi-factor authentication for remote access, Sandbox analysis for suspicious files
  - **Real-world examples**: 2013 U.S. Department of Labor watering hole attack, IRS gift card scams, USB drop attacks in reception areas, SolarWinds supply chain breach, NotPetya ransomware via compromised updates
- **Domain 2.1 (Threat Actors and Motivations)**: ✅ Expanded from 9 to 50 questions
  - **Threat Actor Types**: Nation-state actors (government-sponsored, sophisticated attacks, espionage/war motivations), APT (Advanced Persistent Threats - focused, well-funded, long-term operations), unskilled attackers/script kiddies (pre-made tools, limited understanding, off-the-shelf exploits), hacktivists (ideological/political motives, website defacement, DDoS, digital protest), insider threats (intentional vs. unintentional, employees/contractors, revenge/financial gain/espionage), organized crime (hierarchical structure, ransomware-as-a-service, profit-driven), shadow IT (unauthorized apps/devices, productivity-driven, security risks)
  - **Attributes of Actors**: Internal vs. External classification (legitimate access vs. unauthorized entry), Resources/funding (well-resourced nation-states/APTs vs. limited-resource script kiddies), Sophistication/capability (zero-day exploits/custom malware vs. pre-made tools)
  - **10 Motivation Categories**: Data exfiltration (stealing IP, trade secrets for dark web sale/competitive advantage), espionage (nation-state intelligence gathering, military/political secrets), service disruption (targeting critical infrastructure, chaos, reputation harm), blackmail (ransomware, double extortion, threatening data leaks), financial gain (credit card fraud, cryptocurrency theft, banking trojans), philosophical/political beliefs (hacktivism, environmental activism, human rights advocacy), ethics (white hat hackers, responsible disclosure, penetration testing), revenge (disgruntled employees, personal vendettas, sabotage), disruption/chaos (nihilistic attacks, cyber vandalism, creating instability), war (state-sponsored cyber warfare, critical infrastructure attacks during conflicts)
  - **Real-world Examples**: UK school employee password lockout (2021 revenge attack), Stuxnet (nation-state malware), Anonymous (hacktivist group), ransomware-as-a-service models, impossible travel indicators, business email compromise
- **Domain 1.0 COMPLETE**: 🎉 All 4 subdomains at 50 questions each (200 total)

**Status**: All 93 tests passing ✅ | Clean build ✅ | Domain 1.0 COMPLETE ✅ | Domain 2.0 COMPLETE ✅ | **Domain 3.0 COMPLETE ✅** (All subdomains 3.1-3.4)

## Source Material

**Location**: Root directory of project (`/home/altin/Desktop/pt-journal/`)

- **CompTIA Security+.txt**: 743 formatted questions (30,657 lines)
- **CompTIA Security+ Practice.txt**: 1,000+ questions with explanations (18,429 lines)
- **CompTIA Security.txt**: 840 questions in 84 chapters (28,699 lines)
- **CompTIA Security+Exam.txt**: Study strategies and simulation guides (1,728 lines)
- **Total Source Content**: ~2,500+ questions across 79,513 lines

## Expansion Progress

### Domain 1.0: General Security Concepts ✅ COMPLETE (TARGET: 200 questions)

- **1.1 Security Controls**: ✅ 50 questions (COMPLETED)
  - Control types: Preventive, Deterrent, Detective, Corrective, Compensating, Directive
  - Control categories: Technical, Managerial, Operational, Physical
  - Real-world scenarios with academic explanations
- **1.2 Security Concepts**: ✅ 50 questions (COMPLETED)
  - CIA triad: Confidentiality, Integrity, Availability
  - AAA framework: Authentication, Authorization, Accounting
  - Zero trust architecture: Policy engine, enforcement point, continuous verification
  - Physical security: Bollards, sensors, access control vestibules, fencing
  - Deception technologies: Honeypots, honeynets, honeyfiles, honeytokens
- **1.3 Change Management**: ✅ 50 questions (COMPLETED)
  - CAB (Change Advisory Board) and approval processes
  - Backout plans and rollback procedures
  - Maintenance windows and scheduling
  - Impact analysis and testing
  - Stakeholders, ownership, and accountability
  - Dependencies and technical implications
  - Documentation, version control, and SOPs
  - Downtime, service/application restarts, legacy applications
  - Allow/deny lists and restricted activities
- **1.4 Cryptographic Solutions**: ✅ 50 questions (COMPLETED)
  - PKI: Public keys, private keys, key escrow, key exchange
  - Encryption levels: Full-disk (FDE), file-level (EFS), volume (BitLocker), database, record-level, transport (TLS)
  - Symmetric algorithms: AES (128/192/256), DES (56-bit, obsolete), 3DES (168-bit, legacy)
  - Asymmetric algorithms: RSA, Diffie-Hellman, ECC
  - Key management: TPM, HSM, KMS, key length, key longevity
  - Certificates: CA, CRL, OCSP, CSR, wildcard, root of trust, self-signed
  - Digital signatures, block ciphers, homomorphic encryption
  - Tools: Opal drives, VeraCrypt
- **Domain 1.0 Status**: 200/200 questions ✅ **100% COMPLETE**

### Domain 2.0: Threats, Vulnerabilities, and Mitigations (TARGET: 250-300 questions) - ✅ **COMPLETE** 254 questions

- **2.1 Threat Actors**: ✅ 50 questions (COMPLETED)
  - Threat actor types: Nation-state, APT, unskilled attackers, hacktivists, insiders, organized crime, shadow IT
  - Attributes: Internal/external, resources/funding, sophistication/capability
  - Motivations: Data exfiltration, espionage, service disruption, blackmail, financial gain, philosophical/political, ethics, revenge, disruption/chaos, war
  - Real-world scenarios: UK school employee revenge attack, ransomware-as-a-service, Anonymous hacktivist operations, APT characteristics
- **2.2 Threat Vectors**: ✅ 51 questions (COMPLETED)
  - Message-based: Email phishing, SMS smishing, IM attacks
  - Image/File-based: Steganography, malicious PDFs, macro documents
  - Voice: Vishing, caller ID spoofing, IRS scams
  - Removable devices: USB drops, sandbox defense
  - Vulnerable software: Client-based vs. agentless scanning
  - Unsecure networks: Wireless/wired/Bluetooth vulnerabilities
  - Open ports & default credentials
  - Supply chain: MSPs, vendors, suppliers, hardware/software compromises
  - Social engineering: Phishing variants, BEC, watering hole, brand impersonation, typo squatting
  - Real-world examples: 2013 Dept of Labor attack, SolarWinds, NotPetya
- **2.3 Vulnerabilities**: ✅ 50 questions (COMPLETED)
  - Application: Memory injection, buffer overflow, race conditions, malicious updates
  - OS-based: BlueKeep, EOL systems, legacy vulnerabilities
  - Web-based: SQL injection, XSS, command injection, directory traversal, XXE, LDAP injection, file upload
  - Hardware: Firmware, EOL, legacy systems
  - Virtualization: VM escape, VM sprawl, resource reuse
  - Cloud: Shared tenancy, misconfigurations, IAM flaws, CASB
  - Supply chain: Service/hardware/software providers
  - Cryptographic: Downgrade attacks, weak implementations, deprecated algorithms
  - Mobile: Jailbreaking, rooting, sideloading
  - Zero-day: Log4Shell, ProxyLogon, EternalBlue/WannaCry
- **2.4 Indicators of Malicious Activity**: ✅ 50 questions (COMPLETED)
  - Malware types: Fileless, bloatware, logic bombs, ransomware, adware, browser hijackers
  - Authentication indicators: Brute force, impossible travel, password resets, unauthorized accounts
  - Network indicators: Beaconing, DNS tunneling, bandwidth spikes, SMTP anomalies, botnets
  - System indicators: Missing logs, disabled AV, memory leaks, high CPU, clock tampering
  - Process indicators: Parent-child anomalies, temp execution, privilege escalation, encoded PowerShell
  - Registry/file indicators: Persistence keys, Unicode keys, double extensions
  - Web indicators: Directory traversal, SQL injection, XSS patterns
  - Advanced indicators: MitM certificates, port scanning, worm propagation, webcam/mic activation
  - Real-world examples: Emotet, WannaCry, Slammer, Mirai, Target 2013, Colonial Pipeline 2021, SolarWinds 2020
- **2.5 Mitigation Techniques**: ✅ 52 questions (COMPLETED)
  - Network controls: Segmentation, microsegmentation, VLANs, jump servers, DMZ, egress filtering, NAC, DNS sinkholing
  - Zero trust: Never trust always verify, continuous validation, policy enforcement, microsegmentation
  - Application controls: Signature-based allowlisting, application control (default-deny), input validation (allowlist), sandboxing
  - Configuration hardening: Default credentials, port security, disabling unnecessary services/protocols, Group Policy Objects, change management
  - Authentication controls: Separation of duties, mandatory vacation, rate limiting, exponential backoff, MFA
  - Patch management: Vulnerability scanning, immutable infrastructure (ephemeral systems)
  - Access controls: Least privilege for service accounts, PAM with just-in-time access, geofencing
  - Detection & response: SOAR platforms, SIEM aggregation/correlation, threat hunting, file integrity monitoring, database activity monitoring
  - Deception: Honeypots and honeynets
  - Web security: WAF with ModSecurity, Content Security Policy, HSTS, certificate pinning, DNSSEC
  - Data protection: DLP monitoring egress points
  - Development: SSDLC with security testing
  - Resilience: Robust backup/recovery (3-2-1 rule, offline/immutable backups, RTO/RPO)
  - Standards: Security baselines (CIS Benchmarks, DISA STIGs)
  - User awareness: Security awareness training for phishing recognition
  - Real-world examples: Mirai botnet 600K devices, DigiNotar 2011, Conficker/Emotet/TrickBot takedowns
- **Domain 2.0 Status**: 254/250-300 questions ✅ **101% COMPLETE** (exceeded minimum target)

### Domain 3.0: Security Architecture (TARGET: 200-240 questions) - ✅ **COMPLETE** 207 questions

- **3.1 Architecture Models**: ✅ 52 questions (COMPLETED)
  - Cloud deployment models: Public (shared multi-tenant infrastructure, cost-effective, economies of scale), private (dedicated organization resources, higher control/security, on-premises or hosted, higher cost), hybrid (combines public/private, workload portability, cloud bursting for peak demand), community (shared among organizations with common concerns like healthcare/government, regulatory compliance focus)
  - Cloud service models: IaaS (infrastructure rental: VMs, storage, networking, OS/app control, AWS EC2/Azure VMs), PaaS (development platform with runtime/middleware/database, managed by provider, Google App Engine/Azure App Services), SaaS (fully managed applications over internet, no infrastructure management, Office 365/Salesforce/Gmail), FaaS (serverless event-driven code execution, automatic scaling, AWS Lambda/Azure Functions)
  - Infrastructure concepts: Serverless (automatic scaling, pay-per-execution, no server management, cold starts), microservices (independent deployable services, polyglot development, individual scaling/updates, API communication, DevOps alignment), API gateway (centralized entry point, authentication/authorization, rate limiting, protocol translation, caching, request routing), containerization (Docker lightweight isolated environments, Kubernetes orchestration, portability, immutable infrastructure, faster deployment vs VMs)
  - Network architecture: On-premises (complete control, capital expenditure, higher upfront costs, IT maintenance responsibility, air-gapped high-security), centralized architecture (single datacenter, simple management, single point of failure risk, latency for remote users), distributed architecture (multiple locations, improved redundancy/performance, complex management, better disaster recovery)
  - Zero trust architecture: Never trust always verify, policy decision/enforcement points, continuous validation, identity-centric security, assume breach mindset, least privilege access, microsegmentation, BeyondCorp Google implementation
  - IoT architecture: Constrained devices (limited compute/memory/power, embedded systems, sensors/actuators), hub/spoke topology (central hub aggregates data, spoke sensors report to hub, reduced device complexity), fog/edge computing (processing at network edge, reduced latency, bandwidth savings, real-time analytics, local decision-making vs cloud processing)
  - ICS/SCADA: Industrial control systems (manufacturing/utilities/infrastructure automation, PLCs/RTUs/DCS/HMI), SCADA (supervisory control and data acquisition for distributed infrastructure like power grids/water treatment/pipelines), OT (operational technology running physical processes vs IT systems), air-gapped networks (physically isolated from internet for security)
  - Embedded systems: Firmware (low-level hardware control software, BIOS/UEFI, difficult updates, security risks if vulnerable), RTOS (real-time operating systems with guaranteed response times for time-critical operations like automotive/medical/aerospace), SoC (system-on-chip integrating multiple components on single chip, smartphones/IoT devices, ARM processors), hardware security modules integration
  - High availability: Active-active (all systems process requests, load sharing, horizontal scaling, no idle resources, geographic distribution), active-passive (one active one standby, failover on failure, hot/warm/cold standby variants, simpler but wasteful of standby resources)
  - Load balancing: Round-robin (sequential distribution, simple but ignores load), least connections (routes to server with fewest active connections, better utilization), weighted (assigns capacity weights to servers, heterogeneous hardware support), health checks (monitors server availability, removes failed servers from pool)
  - Considerations: Availability (uptime requirements, 99.9%/99.99%/99.999% SLAs, cost increases exponentially with nines), resilience (recover from failures, redundancy/failover/disaster recovery, graceful degradation), cost (balance budget against requirements, TCO including operational costs, cloud vs on-premises economics), responsiveness (latency requirements, geographic distribution, edge computing, CDNs), scalability (handle growth, horizontal scaling for web/stateless, vertical scaling for databases, elasticity in cloud), ease of deployment (automation, IaC, CI/CD pipelines, containerization benefits), risk transference (insurance/warranties/cloud providers sharing responsibility, SLAs with penalties, shared responsibility model understanding), ease of recovery (RTO/RPO, automated failover, backup strategies, disaster recovery testing), patch availability (update mechanisms, automated patching vs manual, security patch urgency, legacy system challenges, Windows Update/WSUS), inability to patch (embedded systems, legacy OT/ICS, compensating controls like network segmentation/monitoring), power (UPS for short outages, generators for extended, redundant power supplies, A/B power feeds), compute (CPU/RAM requirements, VM sizing, container resource limits, serverless automatic scaling, cost optimization)
  - Real-world examples: AWS availability zones for fault isolation, Google's BeyondCorp zero trust model, Tesla over-the-air firmware updates, Stuxnet targeting air-gapped SCADA (2010), Mirai botnet exploiting IoT devices (2016), Boeing 787 requiring power cycle every 248 days

### Domain Breakdown

#### Domain 1.0: General Security Concepts (4 steps, 42 questions)

1. **1.1 Security Controls** (10 questions)
   - CIA triad, control types, authentication factors
2. **1.2 Fundamental Security Concepts** (10 questions)
   - Availability, non-repudiation, AAA, zero trust, gap analysis
3. **1.3 Change Management** (10 questions)
   - Change processes, backout plans, maintenance windows, dependencies
4. **1.4 Cryptographic Solutions** (12 questions)
   - Symmetric/asymmetric encryption, PKI, hashing, digital signatures, key management

#### Domain 2.0: Threats, Vulnerabilities, and Mitigations (5 steps, 175 questions) - IN PROGRESS

1. **2.1 Threat Actors and Motivations** (50 questions) ✅ COMPLETED
   - Nation-state actors, APTs, organized crime, hacktivists, insiders (intentional/unintentional), shadow IT, unskilled attackers
   - Attributes: Internal/external, resources/funding, sophistication/capability
   - Motivations: Data exfiltration, espionage, service disruption, blackmail, financial gain, philosophical/political, ethics, revenge, disruption/chaos, war
2. **2.2 Threat Vectors and Attack Surfaces** (51 questions) ✅ COMPLETED
   - Message-based: Email phishing, SMS smishing, IM attacks (social media impersonation)
   - Image/File-based: Steganography, malicious PDFs with scripts, macro documents, weaponized archives
   - Voice calls: Vishing, caller ID spoofing, voicemail attacks, IRS/HR impersonation
   - Removable devices: USB drop attacks, sandbox defense strategies
   - Vulnerable software: Client-based scanning (agents, continuous monitoring) vs. agentless scanning (Nmap, Wireshark)
   - Unsupported systems: Legacy software exploitation, Windows Server 2003 example
   - Unsecure networks: Wireless (open auth, WPA3, SSID, MAC filtering), Wired (802.1X, unused ports), Bluetooth/PAN
   - Open service ports: FTP/Telnet/SMB, port scanning, principle of least functionality
   - Default credentials: admin/admin, manufacturer defaults on public websites
   - Supply chain: MSPs (cascading breaches), vendors (risk assessments), suppliers (hardware backdoors), software distribution compromises
   - Social engineering: Phishing/spear phishing/smishing, BEC (invoice scams), watering hole (2013 Dept of Labor), brand impersonation, typo squatting (arnazon.com), pretexting, impersonation
   - Advanced topics: Shadow IT (unauthorized cloud services), zero-day vulnerabilities, OSINT reconnaissance, combined attack techniques
3. **2.3 Vulnerability Types** (50 questions) ✅ COMPLETED
   - Application vulnerabilities: Memory injection (Code Red worm), buffer overflow (Slammer worm), race conditions (TOC/TOU), malicious updates (CCleaner 2017)
   - Operating system vulnerabilities: BlueKeep, Windows XP EOL (April 2014), legacy system exploitation
   - Web-based vulnerabilities: SQL injection (' OR '1'='1' --, stored procedures), XSS (<script> tags, cookie theft), file upload (PHP execution, magic bytes), command injection (system(), shell metacharacters), directory traversal (../ sequences, /etc/passwd), XXE injection (XML external entities, SSRF), LDAP injection (Active Directory bypass)
   - Hardware vulnerabilities: Firmware vulnerabilities, end-of-life hardware, legacy systems
   - Virtualization vulnerabilities: VM escape (hypervisor exploitation, east-west movement), VM sprawl (uncontrolled VM creation), resource reuse (data remnants)
   - Cloud-specific vulnerabilities: Shared tenancy (side-channel attacks), cloud misconfigurations (S3 buckets, security groups), IAM flaws (excessive permissions, weak auth, orphaned accounts), CASB (shadow IT discovery, DLP enforcement)
   - Supply chain vulnerabilities: Service providers, hardware supply chain (counterfeit components, firmware backdoors, nation-state manufacturing), software supply chain (third-party library malware, bill of materials, SCA tools)
   - Cryptographic vulnerabilities: CA compromise (DigiNotar 2011, Comodo), key compromise (theft, weak generation, HSMs), flawed implementation (hardcoded keys, custom crypto, "don't roll your own crypto"), outdated algorithms (DES, MD5, SHA-1, RC4, DES Challenge 1997), side-channel attacks (power analysis, timing, EM, acoustic, cache-timing), flawed RNG (Debian OpenSSL 2008, 32,768 keys), SSL/TLS downgrade (POODLE, backward compatibility), SSL stripping (HTTPS→HTTP, HSTS)
   - Misconfiguration vulnerabilities: Firewall (overly permissive FTP/Telnet/RDP, compliance violations), default credentials (admin/admin, public databases), unpatched software (WannaCry 2017), excessive privileges (Domain Admin for all, privilege creep, least privilege violations)
   - Mobile device vulnerabilities: Jailbreaking (iOS restriction bypass, MDM bypass), rooting (Android superuser, verified boot disabled, banking app detection), sideloading (APK from untrusted sources, Play Protect bypass, warranty voiding)
   - Other vulnerabilities: Integer overflow (Boeing 787 248-day reboot), memory leaks (resource exhaustion, RAII defense, JNI native code), zero-day (Log4Shell CVE-2021-44228, ProxyLogon, EternalBlue/WannaCry, nation-state stockpiling, $1M+ prices)
4. **2.4 Indicators of Malicious Activity** (50 questions) ✅ COMPLETED
   - Malware types: Fileless malware (memory-resident, PowerShell/WMI), bloatware, logic bombs (UBS 2006, Fannie Mae 2002), ransomware (WannaCry, Ryuk, REvil, Maze, Conti), adware (Superfish 2015), rootkits, trojans, worms (Mirai, Emotet, ZeroAccess), keyloggers, spyware, botnets
   - Authentication indicators: Brute force attacks, impossible travel (NY-Tokyo 10min), concurrent sessions, password reset spam, account takeover
   - Network indicators: Beaconing (C2 communication, regular intervals), blocked access attempts (DGA domains), unusual outbound (reverse shells ports 4444/5555), DNS tunneling (50+ char subdomains, base64), bandwidth spikes (off-hours exfiltration), SMTP from non-mail servers (spam botnets), chunked regular transfers
   - System indicators: Missing/deleted logs (anti-forensics), disabled AV (malware interference), memory leaks (Boeing 787), unauthorized accounts (AD persistence), scheduled tasks (Emotet), high CPU (cryptojacking, Monero mining), clock tampering
   - Process indicators: Parent-child anomalies (Word→PowerShell), temp directory execution (%TEMP%/%APPDATA%), privilege escalation (SYSTEM processes), encoded PowerShell (-EncodedCommand)
   - Registry/file indicators: Run key persistence, Unicode/special character keys (BadRabbit 2016), double extensions (document.pdf.exe, Locky 2017), suspicious icons
   - Web indicators: Directory traversal (../../../../etc/passwd), SQL injection (UNION SELECT, OR 1=1, Heartland 2008), XSS patterns (<script> tags, British Airways Magecart 2018)
   - Advanced indicators: MitM certificates (DigiNotar 2011), browser hijackers (Conduit, MyWebSearch), PUPs/bundleware (SourceForge 2015), port scanning (reconnaissance, Nmap), worm propagation (mass simultaneous infections), webcam/mic activation (RAT spyware, Miss Teen USA 2013)
   - Real-world examples: Emotet, WannaCry (200K systems, 4 days), Slammer (75K, 10min), Code Red, Mirai (600K IoT, 1Tbps), Target 2013 (40GB logs deleted), Colonial Pipeline 2021 (100GB exfiltration), Sony 2014 (100TB weeks), SolarWinds 2020
5. **2.5 Mitigation Techniques** (12/50 questions) - NEXT TARGET
   - Segmentation, least privilege, patching, defense in depth, isolation

- **3.2 Security Infrastructure**: ✅ 51 questions (COMPLETED)
  - Devices: Firewalls (packet filtering, stateful inspection, next-gen with IPS/DPI/app control, WAF for web attacks), IDS (passive monitoring, alert generation, signature/anomaly detection, Snort/Suricata), IPS (active blocking, inline deployment, false positive risks, latency considerations), load balancers (traffic distribution, SSL offloading, session persistence/sticky sessions, health checks, Layer 4 TCP/UDP vs Layer 7 application), sensors (network tap passive monitoring, SPAN/mirror ports, out-of-band analysis, IDS/IPS/DLP/forensics), jump servers/bastion hosts (hardened gateway for administrative access, SSH/RDP gateway, MFA requirement, session logging, DMZ or management VLAN placement), proxy servers (forward proxy for outbound filtering/caching/anonymity, reverse proxy for inbound load balancing/caching/SSL, explicit vs transparent configuration), VPN concentrators (IPsec site-to-site for branch offices, SSL VPN remote access clientless browser-based, split tunneling considerations)
  - Network segmentation: East-west traffic (lateral movement within datacenter, server-to-server, microsegmentation with zero trust, VMware NSX/Cisco ACI), north-south traffic (ingress/egress across perimeter, user-to-server, traditional firewalls, DDoS protection), DMZ (demilitarized zone for public-facing services, dual firewall design, bastion hosts/web/email/DNS servers, limits internal network exposure), screened subnet (DMZ variant with two firewalls creating isolated zone), extranet (controlled external partner access, B2B collaboration, VPN or dedicated connections, separate from internet DMZ), intranet (internal private network, employee-only access, SharePoint/wikis/internal portals, not internet-accessible)
  - VPN technologies: Remote access VPN (individual users to corporate network, SSL VPN clientless, IPsec VPN client-based, split tunneling risks), site-to-site VPN (permanent tunnels between locations, IPsec preferred, MPLS alternative, router-to-router or firewall-to-firewall), clientless VPN (browser-based SSL VPN, no client software, limited application access, Cisco AnyConnect/Pulse Secure), full tunnel (all traffic through VPN, maximum security, performance impact, no local internet), split tunnel (corporate traffic through VPN, internet direct, performance benefit, security risk of unprotected traffic), always-on VPN (automatic connection, transparent to users, Windows/macOS/mobile support, pre-login connection for machine authentication)
  - Port security: 802.1X (port-based NAC, RADIUS/TACACS+ authentication, EAP protocols, supplicant/authenticator/authentication server, prevents rogue devices), MAC filtering (allows/blocks by MAC address, easily spoofed, limited security, legacy environments), port security limits (max MAC addresses per port, violation actions: shutdown/restrict/protect, prevents MAC flooding), unused port disabling (shutdown inactive ports, prevents rogue connections, physical security control)
  - Routing & switching: Secure routing protocols (MD5/SHA authentication for OSPF/EIGRP/BGP, prevents route injection/hijacking), private VLANs (isolated VLANs prevent communication between same-VLAN hosts, useful for multi-tenant/DMZ, promiscuous/isolated/community ports), VLAN hopping prevention (disable auto-trunking on access ports, explicit VLAN assignment, native VLAN tagging), ARP spoofing prevention (dynamic ARP inspection validates ARP packets, static ARP entries for critical systems, DHCP snooping binding table)
  - Firewall configuration: Access control lists (ordered top-to-bottom, explicit deny at end, source/destination IPs and ports, protocol specification), application layer gateway (ALG for FTP/SIP/H.323, inspects/modifies application data, NAT traversal assistance, can cause VoIP/VPN issues), stateful vs stateless (stateful tracks connections/allows return traffic/more secure, stateless examines individual packets/faster/less memory/less secure), implicit deny (default deny all unless explicitly allowed, whitelist approach, security best practice vs implicit allow)
  - Security services: DNS filtering (blocks malicious/inappropriate domains, OpenDNS/Cisco Umbrella/Cloudflare for Families, prevents phishing/malware/C2, DNSBLs for threat intelligence), email security (gateway scanning for spam/phishing/malware, SPF/DKIM/DMARC validation, sandboxing attachments, DLP for data loss, URL rewriting/time-of-click protection), DLP (data loss prevention monitoring sensitive data exfiltration, content inspection, policy enforcement, endpoint/network/cloud deployment), NAC (network access control enforces compliance before access, posture assessment for patches/AV, quarantine VLAN for non-compliant, agent-based or agentless via 802.1X)
  - Secure protocols: DNSSEC (DNS Security Extensions with cryptographic signatures, prevents cache poisoning/spoofing, requires recursive resolver support, RRSIG records), SSH (Secure Shell encrypted remote access, replaces Telnet port 23, typically port 22, public key authentication, SFTP for file transfer), S/MIME (email encryption and signing, X.509 certificates, protects confidentiality and integrity, Outlook/Thunderbird support), SRTP (Secure Real-time Transport Protocol for encrypted VoIP, AES encryption, prevents eavesdropping, ZRTP for key exchange), LDAPS (LDAP over SSL/TLS on port 636, encrypts directory queries/authentication, prevents credential theft, Active Directory support), FTPS (FTP Secure using TLS, explicit FTPS port 21 vs implicit FTPS port 990, preferred over FTP, certificate-based encryption), SNMP v3 (encryption and authentication, replaces vulnerable v1/v2c community strings, user-based security, prevents credential theft and tampering), TLS (Transport Layer Security for encrypted communications, TLS 1.2 minimum recommended, TLS 1.3 preferred, replaced SSL, HTTPS uses TLS)
  - Real-world examples: Equifax breach 2017 (143M records via unpatched Apache Struts on web app behind inadequate segmentation), Stuxnet 2010 (crossed air-gapped networks via USB), Target 2013 (HVAC vendor access led to 40M payment cards due to inadequate network segmentation), JPMorgan Chase 2014 (76M households via single unauthenticated server)
- **3.3 Data Protection**: ✅ 52 questions (COMPLETED)
  - Encryption standards: AES-256 for sensitive data at rest (TOP SECRET approved, FIPS 140-2), symmetric encryption (single shared key, fast, AES/ChaCha20, key distribution challenge), homomorphic encryption (compute on encrypted data without decryption, 100-1000x slower, privacy-preserving cloud computing), quantum threats (Shor's algorithm breaks RSA/ECC in polynomial time), post-quantum cryptography (NIST standardizing CRYSTALS-Kyber for encryption and CRYSTALS-Dilithium for signatures, lattice-based/hash-based), key lengths (128-bit minimum, 256-bit future-proof, 2048-bit RSA minimum), backup encryption (separate keys from production, encrypt at rest and in transit, key escrow for DR, Veeam ransomware exploited unencrypted backups)
  - Data Loss Prevention: Endpoint DLP (agents on laptops/desktops, controls USB/printing/screenshots/cloud uploads, works offline), Network DLP (perimeter gateways/proxies/email servers, monitors email/web/FTP/IM, cannot inspect SSL without decryption), Discovery DLP (crawls file shares/databases/SharePoint/cloud/endpoints, creates inventory of sensitive data locations, enables risk assessment and compliance), content-aware inspection (pattern matching with regex, Luhn validation for credit cards, SSN format detection, keyword search), contextual analysis (evaluates file location, user role, destination internal/external, time of day, volume, reduces false positives)
  - Compliance regulations: GDPR Article 33 (72-hour breach notification to supervisory authorities, fines €10M or 2% global revenue), GDPR Article 17 (right to erasure/right to be forgotten, 30-day response, exceptions for legal obligations, Google Spain v. AEPD 2014), GDPR Article 5 (purpose limitation - specified explicit legitimate purposes prevent function creep, data minimization, storage limitation), PCI DSS Requirement 3 (protects cardholder data, prohibits storing CAV2/CVC2/CVV2/PIN blocks/magnetic stripe after authorization, fines $100K/month, loss of card processing), HIPAA Security Rule (protects ePHI, fines $100-$50K per violation $1.5M annual max, Anthem 80M records $16M fine, Premera 11M $6.85M), CCPA (California consumer rights: know what collected/if sold/opt-out/delete/non-discrimination, $25M+ revenue or 50K+ consumers or 50%+ revenue from sales, fines $7,500 per intentional violation, CPRA 2023 amendments), FERPA (student education records, parents/18+ students have inspection rights, requires consent for disclosure with exceptions, violations = loss of federal funding), Russian Federal Law 242-FZ (2015 data localization requires Russian citizen data on Russian servers, primary processing in Russia, LinkedIn blocked 2016)
  - Hashing & cryptographic properties: SHA-256/bcrypt for password storage (never plaintext), one-way irreversible transformation for integrity verification/digital signatures, avalanche effect (1-bit input change flips ~50% output bits prevents pattern analysis), collision resistance (computationally infeasible to find two inputs producing same hash)
  - Tokenization: Vault-based (token-to-value mappings in secure database, requires HSM protection and HA, single point of failure concern), format-preserving (maintains format/length/character set, 16-digit card → 16-digit token, NIST FF1/FF3-1 algorithms, preserves first 6 BIN/IIN routing + last 4 digits customer reference), advantage over encryption (tokens for display/logging/analytics without detokenization, unlike encrypted data requiring decryption)
  - Data anonymization: De-identification/true anonymization (irreversible removal of PII, individuals cannot be re-identified, GDPR doesn't apply, techniques: remove direct identifiers/generalize quasi-identifiers to age ranges and ZIP regions, linkage attacks can re-identify), pseudonymization (reversible replacement with pseudonyms/tokens, separate lookup table, re-identification possible with key, GDPR still treats as personal data requiring protection)
  - Data masking: Deterministic (same input → same output consistently, preserves referential integrity across databases/tables), static masking (creates persistent masked copies for non-production environments), dynamic data masking DDM (real-time transformations based on user role, shows original to privileged and masked to others without multiple copies, functions: random/partial/nulling/custom)
  - Data classification: Levels (Public - no harm, Internal Use Only - employees, Confidential - high protection, Top Secret/Classified - exceptionally grave damage), visual markings (headers/footers TOP SECRET/CONFIDENTIAL, watermarks visible/digital, cover sheets, media labels, screen banners, email subject tags), NIST SP 800-53 AC-16
  - Data states: Data in use (most vulnerable - decrypted for processing in memory/CPU, memory scraping malware, cold boot attacks, Intel SGX/AMD SEV/homomorphic encryption emerging), data at rest (full disk encryption protection), data in transit (TLS protection)
  - Data disposal: Wiping (DoD 5220.22-M 3 passes magnetic, NIST SP 800-88 vendor-specific SSD commands, Gutmann 35 passes overkill, cryptographic erasure destroy keys), degaussing (powerful magnets disrupt magnetic fields thousands gauss, effective for HDDs/tapes, does NOT work on SSDs/flash, destroys servo tracks making drives unusable)
  - Rights management: IRM/DRM (Microsoft Azure Information Protection, Adobe Policy Server, Fasoo, embeds usage policies in documents: viewing/editing/printing/copying/forwarding/expiration, persistent protection requires authentication to rights server, can remotely revoke access)
  - Additional data protection: Data retention (schedules define keep duration for legal/regulatory/business, legal holds/litigation holds override schedules to preserve evidence, tension with GDPR minimization and storage limitation), data synthesis (generates realistic fake data preserving statistical properties and relationships, ideal for dev/test/ML training/third-party sharing/demos, eliminates production data risk), data sovereignty (multi-jurisdictional compliance when cloud replicates across regions, GDPR restricts EU data transfers outside EU/EEA without adequacy decisions, map data flows and configure regions carefully), data segregation/compartmentalization (isolated segments with separate access controls, limits blast radius, examples: database segmentation by customer/region, network air gaps, separate encryption keys per classification, zero trust microsegmentation, Target 2013 POS shouldn't have reached corporate with proper segmentation), data loss vs exfiltration (data loss: accidental deletion/corruption/disasters/hardware failures/ransomware requires backups/recovery/BCP, data breach/exfiltration: unauthorized theft requires access controls/encryption/DLP/monitoring, 3-2-1 rule: 3 copies/2 media types/1 offsite, immutable/air-gapped for ransomware), breach response (containment highest priority: isolate systems/disable accounts/revoke credentials/patch vulnerabilities/block IPs/shut down attack vectors, balance stopping breach vs preserving forensic evidence, remediation: remove malware/restore clean backups/rebuild systems/implement additional controls/validate attacker removed)
- **3.4 Resilience and Recovery**: ✅ 52 questions (COMPLETED)
  - RAID levels: RAID 1 (mirroring, 100% redundancy, 50% storage efficiency, excellent read performance, simple recovery, common in OS/boot drives), RAID 5 (distributed parity across 3+ drives, 1 drive failure tolerance, (n-1)/n efficiency, good reads but slow writes due to parity, lengthy rebuild times with large modern drives increase second failure risk), RAID 6 (double parity, 2 drive failure tolerance, (n-2)/n efficiency, slower writes than RAID 5, increasingly preferred as drive sizes grow and rebuild times lengthen), RAID 10/1+0 (mirrored stripes, 50% efficiency, excellent performance and redundancy, tolerates multiple failures if not same mirror pair, faster rebuilds than RAID 5/6, preferred for high-performance databases despite higher cost)
  - Advanced backup strategies: 3-2-1 rule (3 total copies production+2 backups, 2 different media types disk/tape or local/cloud, 1 copy offsite for site-wide disasters, modern 3-2-1-1-0 adds 1 immutable/air-gapped and 0 errors via verification for ransomware protection), immutable backups (AWS S3 Object Lock, Azure Immutable Blob preventing deletion/modification for retention periods, air-gapped physically disconnected offline tape/removable drives stored offsite), Grandfather-Father-Son GFS rotation (daily son 7-14 days, weekly father 4-8 weeks, monthly grandfather months-years, balances recovery flexibility vs storage costs, meets compliance long-term retention, modern variants add yearly archival), synthetic full backups (combines last full + subsequent incrementals to create new full without accessing production, reduces load on production servers/networks, backup server synthesis, benefits: reduced backup window/less production impact/simplified restores/multiple synthetic fulls from one incremental set, requires deduplicated storage), Changed Block Tracking CBT (hypervisor-level identifies specific changed storage blocks since last backup, eliminates scanning entire VMs, dramatically reduces backup windows/network traffic/storage, VMware CBT/Hyper-V RCT/storage array snapshots, challenges: occasional corruption requiring resets losing change history/consistency across backup chains/vendor lock-in), restoration testing (monthly random file restores, quarterly full system restores, annual DR exercises, validates recoverability and identifies corrupted backups/missing files/configuration issues/procedural gaps before disasters, many organizations discover backup failures only during actual disaster recovery), system state/configuration backups (OS configs/registry/system files/boot files/AD data/app configs to rebuild servers to operational state, backing up just user data insufficient, modern: infrastructure as code in version control, golden images pre-configured templates, configuration management tools Ansible/Puppet rebuild from code), backup monitoring (automated tracking of job completion status/errors/warnings/duration trends/data volumes/success-failure rates with alerts, dashboards/reports/SIEM integration, critical: verify all systems backed up/check recurring errors/monitor backup window growth/track tape-disk usage/validate off-site copy, doesn't guarantee recoverability - regular restoration testing still required)
  - RTO/RPO economics: Near-zero RTO requires expensive active-active configs/real-time replication/automatic failover/multiple geographic locations/N+1 or 2N redundancy including hot sites/synchronous database replication/clustered applications/load balancers, longer RTOs allow cheaper warm sites 4-24hrs or cold sites with equipment contracts 24-72hrs or basic backup/restore 72+ hrs, organizations balance cost against business impact, near-zero RTO+RPO most expensive (synchronous replication ensuring zero data loss, active-active with automatic failover, real-time monitoring, multiple geographic sites, potentially millions annually, only mission-critical systems warrant, tier systems with different RTO/RPO targets based on criticality), Financial Impact metric in BIA (cost per hour/day of downtime including direct revenue loss/SLA penalties/overtime costs/lost productivity/customer churn, combined with operational impact to prioritize recovery, high-impact systems get lower RTOs and more expensive HA, e.g. e-commerce $100K/hour vs internal HR $5K/hour justifying different investments)
  - High availability: Active-active with failover (multiple systems simultaneously processing requests load sharing, each capable of handling full load if others fail, load balancers automatically redirect traffic with no manual intervention, provides HA and horizontal scalability, examples: clustered web servers behind load balancers, distributed databases with multi-master replication, N+1 where N systems handle normal load and +1 provides failure capacity), failover clustering (Microsoft Failover Clustering, Linux HA clustering with Pacemaker, automatically detects node failures and migrates applications/services/IP addresses to surviving nodes, shared or replicated storage ensures new node accesses same data, heartbeat mechanisms detect failures triggering automated failover, applications must be cluster-aware or support shared storage, challenges: split-brain prevention/quorum configuration/ensuring apps handle abrupt migration, typical 30sec-several minutes depending on complexity), availability percentages (quantifies uptime as percentage: 99% = 3.65 days downtime/year, 99.9% three nines = 8.76 hours/year, 99.99% four nines = 52.56 minutes/year, 99.999% five nines = 5.26 minutes/year, higher availability exponentially more investment, calculation: Total Time - Downtime / Total Time, SLAs specify with penalties for non-compliance, five nines requires eliminating all SPOFs/automatic failover/redundant components/comprehensive monitoring/rapid incident response), read replicas (creates database copies handling read queries offloading read load from primary which handles writes, replication typically asynchronous with slight lag seconds, provides horizontal read scaling/geographic read distribution for low latency/failover targets, technologies: MySQL read replicas/PostgreSQL streaming replication/MongoDB replica sets/cloud database read replicas AWS RDS/Azure SQL, not full HA since manual/automatic promotion required for write failover, significantly improves availability and performance for read-heavy workloads)
  - Replication: Synchronous (writes data to primary and secondary simultaneously before acknowledging completion, ensures zero data loss RPO=0 but introduces latency from round-trip time, changes not committed until confirmed at both locations, requires high-bandwidth low-latency network and sites relatively close typically <100 miles, mission-critical applications where data loss unacceptable, network failures can impact primary site performance requiring careful design), multi-master/active-active (allows multiple sites to accept writes simultaneously, provides low-latency local writes and eliminates SPOFs, introduces complexity for conflict resolution when different sites modify same data concurrently, conflict resolution strategies: last-write-wins based on timestamps/application-specific logic/manual intervention, technologies: MySQL Group Replication/PostgreSQL with BDR/Cassandra, requires careful design to avoid split-brain and data inconsistency)
  - Business continuity & DR: DRP (Disaster Recovery Plan provides detailed step-by-step procedures for recovering IT systems/applications/data after disasters, includes: recovery procedures/contact lists/system priorities/backup locations/restoration sequences/testing schedules, BIA identifies critical processes and impacts, BCP broader covering entire business operations not just IT, RTO is metric defining recovery time requirements, DRP subset of BCP focusing on technical recovery), BIA (Business Impact Analysis foundation of business continuity planning, identifies critical business functions/their dependencies systems/people/vendors/facilities/impact of disruptions financial/operational/reputational/establishes recovery priorities with RTO/RPO requirements, informs resource allocation for resilience investments - most critical functions receive lowest RTOs and most expensive protections, deliverables: criticality rankings/dependency maps/financial impact calculations/recovery strategy recommendations, should be reviewed annually or when significant business changes), phased recovery (prioritizes resuming mission-critical functions first as identified in BIA then gradually restores less-critical systems as resources allow, Phase 1 core business systems hours, Phase 2 important but non-critical days, Phase 3 remaining systems weeks, manages limited recovery resources effectively/delivers business value incrementally/allows learning from Phase 1 before expanding, requires clear prioritization from BIA and predetermined recovery sequences, alternative big bang recovery attempts everything simultaneously risking delays and resource conflicts), IRP (Incident Response Plans define immediate response procedures for security incidents and operational disruptions: detection/triage/containment/eradication/recovery/lessons learned, focuses on initial hours/days - stopping ongoing damage/preserving evidence/stabilizing operations, DRP takes over for longer-term IT recovery and BCP addresses broader business continuity including alternate facilities/communication plans/keeping business operating, organizations need all three with clear handoff criteria from IRP to DRP/BCP)
  - DR testing: Tabletop exercises (gather key personnel to discuss recovery procedures/roles/decision-making in response to hypothetical disaster scenarios without actually executing recovery, least disruptive and cheapest testing, useful for training/identifying gaps in documentation/validating contact information/building team familiarity, doesn't validate that systems actually work or documented procedures accurate, organizations should progress from tabletop → walkthrough → simulation → parallel → full tests as maturity increases), parallel testing (activates DR site and processes real transactions in parallel with production, fully testing systems/procedures/staff readiness without actually failing over or impacting users, validates RTO/RPO assumptions/identifies issues in recovery procedures/builds staff confidence, expensive and complex to coordinate, may not test final switchover procedures, full interruption tests provide more realistic validation but risk actual outages if problems occur)
  - Recovery sites: Warm sites (hardware installed and operational, network connectivity configured, potentially some data pre-staged, require restoration of current data and configuration before going operational, recovery 4-24 hours, balance cost and recovery speed - more expensive than cold but cheaper than hot, organizations may maintain warm for less-critical while using hot for mission-critical, cloud blurred these categories with on-demand provisioning), DRaaS (Disaster Recovery as a Service uses cloud providers for recovery infrastructure eliminating need to maintain physical recovery sites, organizations replicate data continuously to cloud and during disasters spin up VMs to resume operations, benefits: pay-as-you-go costs no idle infrastructure/geographic flexibility/rapid provisioning/elastic scaling, providers: AWS Elastic Disaster Recovery/Azure Site Recovery/Zerto, challenges: ensuring adequate bandwidth for replication and recovery/testing actual cloud recovery procedures)
  - Power protection: Standby generators (diesel/natural gas/propane provide power for extended outages hours-days after utility fails and UPS battery depletes, typically start automatically within seconds-minutes when UPS signals power loss, key considerations: fuel capacity how many days/regular testing and maintenance/automatic transfer switches/load testing/fuel delivery contracts for extended outages, require permits/noise mitigation/ventilation/regular exercise, critical for datacenters and continuous operation facilities), A/B power (provides two completely independent utility feeds from different substations and electrical grids, protecting against single substation failures/grid maintenance/local distribution problems, each feed powers separate PDUs with equipment using dual power supplies connected to both A-side and B-side, standard for tier 3/4 datacenters, cost includes: dual utility service contracts/redundant distribution infrastructure/dual-corded equipment, facilities combine A/B power with generators and UPS for comprehensive protection, most outages trace to power issues - redundancy here critical)
  - Failure modes: Split-brain (network connectivity loss between clustered nodes causes both to believe other failed with both attempting to take over as primary, can cause data corruption/conflicting updates/inconsistency, prevention mechanisms: quorum requiring majority of nodes to operate/fencing-STONITH Shoot The Other Node In The Head forcibly powering off suspected failed nodes/witness servers third-party arbitrators, particularly problematic in stretched clusters across geographic locations with unreliable WAN links), SPOF elimination (ensuring no single component failure can disrupt operations by implementing redundancy for critical components: dual power supplies/redundant network connections/clustered servers/RAID storage/multiple ISPs/geographically distributed datacenters, SPOF analysis systematically evaluates architecture to identify failure risks, example SPOFs: single network router/lone domain controller/sole database server/single backup repository/critical employee human SPOF, high availability requires addressing all SPOFs which can be expensive - organizations balance cost against availability requirements)
  - Advanced storage: Instant VM recovery (booting virtual machines directly from backup storage deduplicated disk-based backups within minutes, enabling RTO measured in minutes rather than hours needed for full restoration, VMs run from backup while permanent restoration happens in background, technologies: Veeam Instant VM Recovery/Rubrik Live Mount/Commvault IntelliSnap, transformative for DR testing boot DR VMs without impacting production and actual disasters immediate recovery while final restoration proceeds, requires enterprise backup solutions with VM-aware backups), database point-in-time recovery (full recovery model maintains complete transaction logs allowing point-in-time recovery - databases can be restored to any specific moment by applying transaction logs, enables recovering to just before errors occurred accidental deletions/corruption rather than only to last full/differential backup, requires more storage for logs and regular transaction log backups, simple recovery truncates logs after checkpoints preventing point-in-time recovery but reducing storage, full recovery essential for mission-critical databases where minimizing data loss paramount), online backups with snapshots (VSS snapshots/storage array snapshots/database-native snapshots capture consistent point-in-time copies while databases remain operational and accessible, application-consistent snapshots quiesce I/O/flush buffers/create consistent state before snapshot, eliminates backup windows that previously required taking databases offline, technologies: VMware snapshots with VSS integration/NetApp SnapShot/Oracle RMAN, however snapshots alone aren't backups - must be replicated to secondary storage for DR since snapshot and source share infrastructure)
  - Environmental: HVAC (maintains appropriate temperature typically 64-81°F/18-27°C and humidity 40-60% for IT equipment, overheating causes equipment failure/thermal throttling/reduced lifespan, undercooling wastes energy, inadequate humidity causes static discharge/excessive humidity causes condensation and corrosion, datacenter HVAC includes redundant cooling units N+1 or 2N, hot/cold aisle containment for efficiency, environmental monitoring with alerts, cooling failures leading causes of datacenter outages - equipment generates enormous heat requiring continuous cooling)
  - Network redundancy: Dual ISP with automatic failover (maintains connections to two different Internet service providers with routers/SD-WAN automatically switching traffic to backup ISP when primary fails, protects against ISP outages/circuit failures/routing issues, implementation: BGP with provider-independent address space expensive/SD-WAN solutions/basic router failover, considerations: ensure ISPs use diverse physical paths not just different providers over same infrastructure/test failover regularly/monitor both links, load balancing across both ISPs provides additional bandwidth when both operational)
  - Regional disasters: Earthquakes/hurricanes/widespread power grid failures/regional ISP outages affect entire geographic areas requiring recovery sites hundreds or thousands miles away, demands: geographically dispersed hot sites/continuous data replication/diverse network paths/possibly different public cloud regions, critical infrastructure sectors finance/healthcare/telecommunications mandate geographic diversity, stretched clusters across nearby locations protect against building failures but not regional disasters, regulatory requirements often mandate minimum distances 100+ miles between primary and recovery sites for financial institutions
- **Domain 3.0 Status**: 207/200-240 questions ✅ **103% COMPLETE** (exceeded target)

#### Domain 4.0: Security Operations (5 steps, 50 questions)

1. **4.1 Security Techniques** (10 questions)
   - Baselines, hardening, MDM, wireless security, sandboxing
2. **4.2 Asset Management** (10 questions)
   - Asset lifecycle, inventory, decommissioning, data sanitization
3. **4.3 Vulnerability Management** (10 questions)
   - CVSS, CVE, scanning, penetration testing, bug bounties
4. **4.4 Monitoring Concepts** (10 questions)
   - SIEM, EDR, log aggregation, SNMP, NetFlow, behavioral analytics
5. **4.5 Enhancing Enterprise Capabilities** (10 questions)
   - Firewall rules, ACLs, DNS filtering, NAC, DLP, threat hunting

#### Domain 5.0: Security Program Management and Oversight (5 steps, 52 questions)

1. **5.1 Governance and Compliance Elements** (10 questions)
   - Security governance, policies, standards, procedures, regulations
2. **5.2 Risk Management Processes** (11 questions)
   - Risk identification, assessment, mitigation, acceptance, ALE calculations
3. **5.3 Third-Party Risk and Compliance** (10 questions)
   - Vendor management, SLAs, NDAs, supply chain risk, auditing
4. **5.4 Compliance and Auditing** (10 questions)
   - HIPAA, GDPR, PCI DSS, SOX, audit types, compliance reporting
5. **5.5 Security Awareness and Incident Response** (11 questions)
   - Security training, incident response lifecycle, CSIRT, forensics

## File Structure

```
data/comptia_secplus/
├── 1.0-general-security/
│   ├── 1.1-security-controls.txt (10 questions)
│   ├── 1.2-security-concepts.txt (10 questions)
│   ├── 1.3-change-management.txt (10 questions)
│   └── 1.4-cryptographic-solutions.txt (12 questions)
├── 2.0-threats-vulnerabilities/
│   ├── 2.1-threat-actors.txt (10 questions)
│   ├── 2.2-threat-vectors.txt (12 questions)
│   ├── 2.3-vulnerabilities.txt (12 questions)
│   ├── 2.4-indicators-malicious-activity.txt (12 questions)
│   └── 2.5-mitigation-techniques.txt (12 questions)
├── 3.0-security-architecture/
│   ├── 3.1-architecture-models.txt (12 questions)
│   ├── 3.2-security-infrastructure.txt (12 questions)
│   ├── 3.3-data-protection.txt (12 questions)
│   └── 3.4-resilience-recovery.txt (13 questions)
├── 4.0-security-operations/
│   ├── 4.1-security-techniques.txt (10 questions)
│   ├── 4.2-asset-management.txt (10 questions)
│   ├── 4.3-vulnerability-management.txt (10 questions)
│   ├── 4.4-monitoring-concepts.txt (10 questions)
│   └── 4.5-enterprise-capabilities.txt (10 questions)
└── 5.0-governance-risk-compliance/
    ├── 5.1-governance-elements.txt (10 questions)
    ├── 5.2-risk-management.txt (11 questions)
    ├── 5.3-third-party-risk.txt (10 questions)
    ├── 5.4-compliance-auditing.txt (10 questions)
    └── 5.5-security-awareness-ir.txt (11 questions)
```

## Implementation Details

### Code Changes

1. **src/tutorials/comptia_secplus.rs**
   - Updated all 5 `get_domain_X_steps()` functions to load question files
   - Each function creates quiz steps using `create_quiz_step_from_file()`
   - Error handling with warnings for missing files

2. **src/lib.rs**
   - Updated test expectations for 23 quiz steps (was 1)
   - Adjusted serialization performance test timeout (50ms → 200ms) to accommodate larger content

### Testing

- **All 93 tests passing**
- Quiz loading validated
- Question parsing verified
- Serialization/deserialization working correctly

## Quality Standards

All questions follow these standards:

- **4 answer choices** with exactly 1 correct answer
- **Detailed explanations** explaining why answer is correct and why others are wrong
- **Context-appropriate difficulty** aligned with CompTIA Security+ exam
- **Clear, unambiguous wording** avoiding trick questions
- **Domain and subdomain tagging** for proper organization

## Usage

Users can now:

1. Navigate to CompTIA Security+ phase in PT Journal
2. Select any of 23 quiz steps organized by domain
3. Answer multiple-choice questions with immediate feedback
4. View detailed explanations after answering
5. Track progress with first-attempt-correct scoring
6. View statistics showing performance across all domains

## Sources

Questions created based on:

- CompTIA Security+ SY0-701 exam objectives
- Security certification study materials
- Industry best practices and standards
- Real-world security scenarios

## Next Steps (Optional Enhancements)

1. Add more questions to increase variety (target: 15-20 questions per subdomain)
2. Create performance-based simulation questions
3. Add adaptive difficulty based on user performance
4. Implement spaced repetition for retention
5. Add domain-specific study resources and references
