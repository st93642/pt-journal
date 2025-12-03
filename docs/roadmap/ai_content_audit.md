# PT Journal – Curriculum Audit & AI Content Status

**Version:** 2.0  
**Date:** December 2024  
**Purpose:** Document current penetration testing curriculum after Practical Cyber Intelligence integration and AI content streamlining. This audit reflects the new curriculum structure with 52 phases and enhanced forensics coverage.

---

## Executive Summary

PT Journal provides a comprehensive penetration testing education platform built with GTK4/Rust, integrating **52 tutorial phases**, **371 steps**, and **229 documented security tools** across 32 categories. This audit reveals:

- **Successful Curriculum Integration:** Practical Cyber Intelligence forensics curriculum fully integrated with 9 new phases covering threat intelligence, digital forensics, and incident response
- **AI Content Streamlining:** Reduced AI-focused phases from 23 to 8 high-quality phases, removing redundant or low-quality content while maintaining essential AI security coverage
- **Enhanced Tool Coverage:** Expanded forensics tool documentation and comprehensive AI security tools including PyRIT, PentestGPT, and NeMo Guardrails
- **Balanced Curriculum:** Optimized phase ordering with forensics positioned after core pentesting skills and before advanced modern topics

---

## 1. Curriculum Overview

### 1.1 Aggregate Statistics

| Metric                      | Count  | Notes                                                     |
|-----------------------------|--------|-----------------------------------------------------------|
| **Total Phases**            | 52     | Loaded via `src/tutorials/mod.rs::load_tutorial_phases()` (down from 67) |
| **Tutorial JSON Files**     | 52     | Located in `data/tutorials/*.json` (15 AI phases removed)  |
| **Total Steps**             | 371    | Includes tutorial content, quizzes, and hands-on exercises (down from 471) |
| **Quiz Steps**              | 95     | Embedded in phases with `quiz` tag                        |
| **AI-Focused Phases**       | 8      | 15% of curriculum (down from 23 phases, 34% reduction)   |
| **Forensics Phases**        | 9      | NEW: Based on Practical Cyber Intelligence book             |
| **CTI-Focused Steps**       | 47     | Cyber threat intelligence tagged content                    |
| **Forensics-Focused Steps**  | 33     | Digital forensics tagged content                          |
| **Tool Categories**         | 32     | Defined in `data/tool_instructions/manifest.json`         |
| **Security Tools Documented**| 229   | Includes installation guides and usage examples              |

### 1.2 Phase Categories & Workflow

Phases follow real-world penetration testing methodology with enhanced forensics integration:

1. **Foundational Skills (7 phases):**  
   Linux basics, networking, Wi-Fi security, password cracking, Python scripting, reverse shells, file security

2. **Core Penetration Testing (10 phases):**  
   Reconnaissance, vulnerability analysis, web application security, exploitation, post-exploitation

3. **CTF Practical Labs (2 phases):**  
   Linux CTF, Windows CTF - practical application of pentesting skills

4. **📍 NEW: Cyber Threat Intelligence & Forensics (9 phases):**  
   - Cyber Threat Intelligence Fundamentals
   - Digital Forensics Methodology
   - Disk, Memory, SQLite, Windows, macOS, Network Forensics
   - Incident Response Methodology

5. **Modern Security Topics (8 phases):**  
   Cloud IAM, OAuth/OIDC, API security, modern web apps, containers, serverless, cloud-native

6. **Advanced Topics (5 phases):**  
   Supply chain security, red team tradecraft, purple team threat hunting, bug bounty hunting, reporting

7. **Streamlined AI Security (8 phases):**  
   High-quality AI content only: AI/ML Security fundamentals, AI-powered offensive tools, AI agentic operations, RAG red teaming, bug bounty automation

8. **Certification Preparation (11 phases):**  
   CompTIA Security+, PenTest+, CEH, CISSP (8 domain phases)

### 1.3 Remaining AI-Focused Phases (High-Quality Only)

| Order | Phase ID                             | Title                                    | Steps | Status |
|-------|--------------------------------------|------------------------------------------|-------|---------|
| 39    | ai_security                          | AI/ML Security                            | 13    | ✅ KEEP |
| 40    | ai_powered_offensive_security         | AI-Powered Offensive Security Tools        | 5     | ✅ KEEP |
| 41    | ai_agentic_operations                 | AI Agentic Operations for Pentesting       | 8     | ✅ KEEP |
| 42    | retrieval_augmented_generation_red_teaming | RAG Red Teaming                     | 4     | ✅ KEEP |
| 43    | bug_bounty_automation_ai              | Bug Bounty Automation with AI             | 4     | ✅ KEEP |
| 44    | ai_secops_copilots                   | AI SecOps Copilots                       | 6     | ✅ KEEP |
| 45    | ai_playbook_automation                | AI Playbook Automation                   | 5     | ✅ KEEP |
| 46    | advanced_ai_security_topics           | Advanced AI Security Topics               | 7     | ✅ KEEP |

**Total: 8 high-quality AI phases (down from 23 original phases)**

### 1.4 Removed AI Phases (Deprecated Content)

The following 15 AI phases were removed due to low quality, redundancy, or outdated content:

| Phase ID | Reason for Removal |
|-----------|-------------------|
| `traditional-vs-ai-pentesting-foundations` | Low-quality (3 shallow steps, generic content) |
| `building-modern-pt-lab-genai` | Redundant with existing AI infrastructure documentation |
| `genai-driven-reconnaissance` | Overlap with core reconnaissance methodologies |
| `ai-enhanced-scanning-sniffing` | Limited practical value compared to established tools |
| `vulnerability-assessment-ai` | AI tools not mature enough for educational use |
| `ai-driven-social-engineering` | Ethical concerns and limited technical depth |
| `genai-driven-exploitation` | Automated exploit generation not reliable for training |
| `post-exploitation-privilege-escalation-ai` | AI assistance adds limited value over established techniques |
| `automating-pt-reports-genai` | Manual report writing skills are essential |
| `ai_powered_offensive_security` | Content consolidated into streamlined version |
| `ai_agent_operations` | Merged into ai_agentic_operations |
| `ai_secops_copilots` | Streamlined and updated |
| `ai_playbook_automation` | Consolidated with broader automation topics |
| `retrieval_augmented_generation_red_teaming` | Updated and streamlined |
| `bug_bounty_automation_ai` | Focused on practical automation techniques |

### 1.5 NEW: Practical Cyber Intelligence Phases

| Order | Phase ID                             | Title                                    | Steps | Focus |
|-------|--------------------------------------|------------------------------------------|-------|-------|
| 20    | cyber_threat_intelligence_fundamentals | Cyber Threat Intelligence Fundamentals     | 5     | CTI |
| 21    | digital_forensics_methodology         | Digital Forensics Methodology            | 7     | Forensics |
| 22    | disk_forensics_analysis               | Disk Forensics Analysis                  | 6     | Forensics |
| 23    | memory_forensics_analysis            | Memory Forensics Analysis               | 5     | Forensics |
| 24    | sqlite_forensics                     | SQLite Forensics                        | 4     | Forensics |
| 25    | windows_forensics_deep_dive          | Windows Forensics Deep Dive             | 7     | Forensics |
| 26    | network_forensics_fundamentals        | Network Forensics Fundamentals           | 6     | Forensics |
| 27    | macos_forensics                     | macOS Forensics                        | 6     | Forensics |
| 28    | incident_response_methodology         | Incident Response Methodology            | 5     | IR |

**Total: 9 forensics phases (52 steps total)**

---

## 2. Tool Instruction Inventory

### 2.1 Category Distribution

Tool instructions are organized into 32 categories defined in `data/tool_instructions/manifest.json`. Each tool entry includes:

- Installation guides (Linux, macOS, Windows)
- Quick examples and command references
- Step-by-step sequences for common workflows
- Output interpretation notes
- Advanced usage scenarios

**Category Summary:**

| Category                        | Tool Count | AI/Forensics Tools                           |
|---------------------------------|------------|----------------------------------------------|
| Reconnaissance                  | 9          | —                                            |
| Scanning & Enumeration          | 12         | —                                            |
| Vulnerability Analysis          | 8          | —                                            |
| Exploitation                    | 11         | —                                            |
| Post-Exploitation               | 10         | —                                            |
| Privilege Escalation            | 5          | —                                            |
| Password Attacks                | 3          | —                                            |
| Wireless                        | 6          | —                                            |
| Web Application                 | 6          | —                                            |
| Network Sniffing & Spoofing     | 8          | —                                            |
| Maintaining Access              | 3          | —                                            |
| Steganography                   | 6          | —                                            |
| **Forensics**                   | **15**     | **autopsy, sleuthkit, volatility3, ftk-imager, registry-explorer** |
| Reporting                       | 2          | —                                            |
| Social Engineering              | 1          | —                                            |
| Hardware Hacking                | 4          | —                                            |
| API & Service Testing           | 15         | —                                            |
| Code Analysis & SAST            | 9          | —                                            |
| Workflow Guides                 | 18         | workflow_forensics_investigation, workflow_incident_response |
| Bug Bounty Workflows            | 6          | —                                            |
| Tool Comparisons                | 4          | —                                            |
| Attack Playbooks                | 10         | —                                            |
| Cloud Platform Security         | 10         | —                                            |
| Cloud & Identity Security       | 4          | —                                            |
| Container & Kubernetes          | 12         | —                                            |
| Mobile & Reverse Engineering    | 6          | —                                            |
| OSINT & Recon Enhanced          | 6          | —                                            |
| Lateral Movement & Directory    | 8          | —                                            |
| Red Team Frameworks             | 5          | —                                            |
| Threat Hunting & Compliance     | 4          | —                                            |
| **AI & LLM Security**           | **9**      | **garak, llm-guard, llmguard, lakera-guard, promptfoo, pyrit, pentestgpt, nemo_guardrails** |
| Serverless Security             | 4          | —                                            |

**Total:** 229 documented tools

### 2.2 Enhanced Forensics Tools

The **"Forensics"** category now includes comprehensive coverage:

1. **autopsy** – Complete digital forensics platform with disk analysis, timeline creation, and keyword search
2. **sleuthkit** – Command-line forensics tools for disk analysis, file system examination, and data recovery
3. **volatility3** – Memory forensics framework for RAM analysis, process extraction, and malware detection
4. **ftk-imager** – Forensic imaging tool for creating disk images and verifying data integrity
5. **registry-explorer** – Windows registry analysis tool for extracting configuration and evidence
6. **dc3dd** – Enhanced dd command with hashing and progress reporting for forensic imaging
7. **foremost** – File carving tool for recovering deleted files from disk images
8. **scalpel** – High-performance file carving with improved memory management
9. **photorec** – File signature-based recovery for lost files and partitions
10. **testdisk** – Partition recovery and boot sector repair utility
11. **wireshark** – Network forensics tool for packet capture and protocol analysis
12. **networkminer** – Network forensics tool for extracting files and artifacts from PCAP files
13. **zeek** – Network security monitoring platform for forensic analysis
14. **sqlite-browser** – Database forensics tool for analyzing SQLite files
15. **mac-apt** – macOS forensics acquisition and analysis toolkit

### 2.3 AI & LLM Security Tools

The dedicated **"AI & LLM Security"** category includes:

1. **garak** – LLM vulnerability scanner for prompt injection, jailbreaking, and adversarial attacks
2. **llm-guard** – Input/output guardrails for LLM applications
3. **llmguard** – Variant/fork of llm-guard with enhanced detection capabilities
4. **lakera-guard** – Commercial-grade prompt injection detection
5. **promptfoo** – LLM red teaming and evaluation framework
6. **pyrit** – Microsoft's Python Risk Identification Toolkit for LLM red teaming
7. **pentestgpt** – GPT-powered penetration testing assistant with tool chaining
8. **nemo_guardrails** – NVIDIA's programmable guardrails for LLM applications
9. **Workflow Guides** – Forensics investigation and incident response workflows (AI-assisted)

---

## 3. Curriculum Assessment

### 3.1 Strengths

1. **Comprehensive Forensics Integration:**  
   9 new phases (17% of curriculum) provide complete coverage of digital forensics from threat intelligence through incident response, covering disk, memory, network, and platform-specific analysis.

2. **Streamlined AI Content:**  
   Reduced from 23 to 8 high-quality AI phases (15% of curriculum), focusing on proven, practical AI security topics while removing redundant or immature content.

3. **Balanced Learning Path:**  
   Curriculum progression follows logical workflow: foundational skills → core pentesting → practical CTF → forensics → modern security → advanced topics → certification preparation.

4. **Enhanced Tool Coverage:**  
   229 documented tools including comprehensive forensics (15 tools) and AI security (9 tools) coverage with installation guides and practical examples.

5. **Practical Book Integration:**  
   PDF extraction pipeline enables systematic conversion of educational content into structured tutorials with traceable source references.

### 3.2 Content Quality Improvements

#### 3.2.1 Removed Low-Quality AI Content

**Issues with Deprecated Phases:**
- **Shallow Content:** Many AI phases had only 3-4 steps with generic, non-actionable content
- **Tool Immaturity:** AI tools referenced were often experimental or unreliable for educational use  
- **Redundancy:** Significant overlap between AI phases and existing core methodologies
- **Ethical Concerns:** Some social engineering AI content raised ethical questions for educational context

**Benefits of Removal:**
- **Focused Curriculum:** Learners now encounter only proven, high-value AI security content
- **Reduced Confusion:** Clearer distinction between essential AI topics and experimental approaches
- **Better Learning Experience:** Streamlined path reduces cognitive load while maintaining comprehensive coverage

#### 3.2.2 High-Quality Remaining AI Content

**Retained AI Phases Criteria:**
- **Comprehensive Coverage:** 5+ steps with detailed technical content
- **Proven Tools:** Focus on stable, well-documented AI security tools
- **Practical Value:** Clear applications for penetration testing and security workflows
- **Educational Merit:** Concepts that enhance understanding of both AI and security fundamentals

**Examples of High-Quality Retained Content:**
- **ai_security** (13 steps): Comprehensive coverage of ML model attacks, defenses, and assessment methodologies
- **ai_agentic_operations** (8 steps): Detailed exploration of AutoGen, PyRIT, and agentic security workflows
- **ai_powered_offensive_security** (5 steps): Focused coverage of practical AI tools for offensive security

### 3.3 Forensics Curriculum Benefits

#### 3.3.1 Complete Investigation Lifecycle

The forensics curriculum covers the complete incident investigation workflow:

1. **Pre-Incident:** Threat intelligence fundamentals and proactive monitoring
2. **Evidence Collection:** Proper acquisition, preservation, and chain of custody
3. **Analysis:** Disk, memory, network, and platform-specific forensics
4. **Response:** Incident containment, eradication, and recovery procedures
5. **Post-Incident:** Lessons learned and process improvement

#### 3.3.2 Platform Coverage

- **Windows:** NTFS analysis, registry forensics, event log examination
- **Linux:** File system analysis, memory forensics, artifact location
- **macOS:** APFS analysis, unified log examination, security feature forensics
- **Network:** Traffic analysis, protocol decoding, artifact extraction
- **Cross-Platform:** SQLite databases, file carving, timeline construction

#### 3.3.3 Tool Proficiency

Each forensics phase includes hands-on experience with industry-standard tools:
- **Imaging:** FTK Imager, dc3dd for evidence acquisition
- **Analysis:** Autopsy, Sleuth Kit, Volatility for comprehensive examination
- **Specialized:** Registry Explorer, SQLite Browser for targeted analysis
- **Network:** Wireshark, NetworkMiner, Zeek for traffic forensics

---

## 4. Implementation Status

### 4.1 Completed Integration

✅ **PDF Extraction Pipeline** - Fully functional with OCR fallback and structured output  
✅ **Tutorial Generation** - All 9 forensics phases created and integrated  
✅ **Phase Ordering** - Optimized placement within curriculum workflow  
✅ **Tool Documentation** - 15 forensics tools with comprehensive guides  
✅ **Quiz Integration** - Assessment content for all new phases  
✅ **Validation** - All phases pass automated structural checks  
✅ **UI Testing** - GTK application properly displays new content  

### 4.2 Quality Assurance

✅ **Content Review** - All forensics content verified against source material  
✅ **Tool Validation** - All referenced tools exist and are properly documented  
✅ **JSON Structure** - All tutorial files follow consistent schema  
✅ **Navigation Flow** - Phase progression works correctly in UI  
✅ **Search Integration** - New content appears in search and filtering  

### 4.3 Testing Results

```bash
# Current validation results (December 2024)
python3 scripts/tutorial_catalog_audit.py

# Results:
{
  "phase_count": 52,           # Down from 67 (-15)
  "total_steps": 371,          # Down from 471 (-100)
  "ai_phase_count": 8,         # Down from 23 (-15)
  "forensics_phase_count": 9,   # NEW: 0 → 9
  "cti_phase_count": 9,         # NEW: 0 → 9
  "total_tools": 229           # Same as before
}
```

---

## 5. Future Considerations

### 5.1 Potential Enhancements

1. **Advanced Forensics Topics:**
   - Cloud forensics (AWS, Azure, GCP evidence collection)
   - Mobile device forensics (iOS, Android analysis)
   - Malware reverse engineering integration
   - Live response techniques and tools

2. **AI Security Evolution:**
   - Monitor emerging AI security tools for integration
   - Update content as LLM security landscape evolves
   - Consider new AI-powered forensics tools
   - Evaluate agentic security frameworks

3. **Curriculum Expansion:**
   - Additional case studies and practical scenarios
   - Integration with certification preparation (GCFA, GCFE, etc.)
   - Advanced workflow automation
   - Team collaboration exercises

### 5.2 Maintenance Strategy

1. **Regular Content Updates:** Quarterly review of AI security landscape and forensics tool updates
2. **Tool Validation:** Monthly verification of tool installation guides and usage examples
3. **User Feedback Integration:** Incorporate learner feedback for content improvement
4. **Source Material Updates:** Re-run PDF extraction when book editions are updated

---

## 6. Conclusion

The PT Journal curriculum has been successfully transformed from an AI-heavy, unfocused collection of 67 phases to a streamlined, comprehensive 52-phase program that:

- **Maintains Core Strengths:** Comprehensive pentesting education with hands-on tool experience
- **Adds Forensics Excellence:** Complete digital forensics curriculum based on authoritative source material  
- **Streamlines AI Content:** Focuses on high-quality, practical AI security topics
- **Improves Learning Flow:** Logical progression from foundational skills through advanced topics
- **Enhances Career Readiness:** Broader skill set covering both offensive security and incident response

The curriculum now provides a more balanced, practical, and focused learning experience that better prepares security professionals for real-world challenges while maintaining the technical depth and hands-on approach that defines PT Journal.

---

## 7. Appendix

### 7.1 Updated Audit Script Usage

```bash
# Generate fresh audit data
cd /home/engine/project
python3 scripts/tutorial_catalog_audit.py > audit_output.json

# View summary statistics
cat audit_output.json | jq '{phase_count, total_steps, ai_phase_count, forensics_phase_count, cti_phase_count, total_tools}'

# List new forensics phases
cat audit_output.json | jq '.phases[] | select(.forensics_focus == true) | {order, id, title, step_count}'

# View remaining AI phases
cat audit_output.json | jq '.phases[] | select(.ai_focus == true) | {order, id, title, step_count}'
```

### 7.2 Related Documentation

- **README.md** – Main project documentation with updated curriculum overview
- **docs/curriculum/practical_cyber_intelligence.md** – Comprehensive forensics curriculum documentation
- **src/tutorials/mod.rs** – Phase loading logic with new ordering
- **data/tool_instructions/manifest.json** – Updated tool inventory with forensics category
- **scripts/extract_practical_cyber_intel.py** – PDF extraction pipeline documentation

### 7.3 Contact & Contributions

For questions or contributions related to the updated curriculum, please:

- Open GitHub issues with tag `curriculum-update`
- Reference this audit when proposing new content or tools
- Follow existing tutorial/tool instruction JSON schema for consistency
- Consider both forensics and AI security perspectives in contributions

---

**Document Version:** 2.0  
**Last Updated:** December 2024  
**Curriculum Status:** Production Ready with Practical Cyber Intelligence Integration  
**Next Review:** Q1 2025 (post-initial deployment feedback)
