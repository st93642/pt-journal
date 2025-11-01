# CompTIA Security+ Quiz Content Summary

## Overview

This document provides a comprehensive summary of all quiz content created for the PT Journal application's CompTIA Security+ SY0-701 certification preparation phase.

## Current Status & Target

- **Current Questions**: 488 (updated after Domain 2.2 COMPLETE)
- **Target Questions**: 1,000-1,500 questions
- **Current Progress**: 33-49% complete
- **Total Quiz Steps**: 23 subdomains
- **Domains Covered**: 5 (All CompTIA Security+ SY0-701 domains)
- **Question Format**: Multiple choice with detailed explanations and academic descriptions

## Latest Update

**Date**: November 1, 2025  
**Domain 2.0 (Threats, Vulnerabilities, and Mitigations) - IN PROGRESS**

**Recent Expansions**:
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

**Status**: All 93 tests passing ✅ | Clean build ✅ | Domain 1.0 COMPLETE ✅ | Domain 2.1 COMPLETE ✅

## Source Material

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

### Domain 2.0: Threats, Vulnerabilities, and Mitigations (TARGET: 250-300 questions) - IN PROGRESS

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
- **2.3 Vulnerabilities**: 12/50 questions (next target)
- **2.4 Indicators**: 12/50 questions
- **2.5 Mitigations**: 12/50 questions
- **Domain 2.0 Status**: 137/250-300 questions (46-55% complete)

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

#### Domain 2.0: Threats, Vulnerabilities, and Mitigations (5 steps, 137 questions) - IN PROGRESS

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
3. **2.3 Vulnerability Types** (12 questions)
   - Phishing, smishing, vishing, social engineering, removable media, supply chain
3. **2.3 Vulnerability Types** (12 questions)
   - SQL injection, XSS, buffer overflow, zero-day, privilege escalation
4. **2.4 Indicators of Malicious Activity** (12 questions)
   - Ransomware, trojans, worms, DDoS, MitM, ARP poisoning, keyloggers
5. **2.5 Mitigation Techniques** (12 questions)
   - Segmentation, least privilege, patching, defense in depth, isolation

#### Domain 3.0: Security Architecture (4 steps, 49 questions)

1. **3.1 Architecture Models** (12 questions)
   - Cloud models (IaaS/PaaS/SaaS), zero trust, virtualization, containerization
2. **3.2 Security Infrastructure** (12 questions)
   - Firewalls, IDS/IPS, VPN, load balancers, WAF, RADIUS
3. **3.3 Data Protection** (12 questions)
   - Data classification, encryption (at rest/in transit/in use), tokenization, DLP
4. **3.4 Resilience and Recovery** (13 questions)
   - RTO/RPO, backup types, high availability, disaster recovery, RAID

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
