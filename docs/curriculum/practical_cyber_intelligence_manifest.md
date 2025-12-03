# Practical Cyber Intelligence - Curriculum Manifest

## Overview

This document maps the book **"Practical Cyber Intelligence: A Hands-on Guide to Digital Forensics"** by Adam Tilmar Jakobsen to PT Journal tutorial phases. It also defines replacement decisions for existing AI-focused phases.

**Source Material Status:** Partial extraction (3 pages - Table of Contents only). Full book content extraction required before tutorial authoring.

---

## Book Chapter Structure

Based on the extracted Table of Contents, the book covers:

| Chapter | Title | Sections | Source Pages |
|---------|-------|----------|--------------|
| 1 | Intelligence Analysis | 1.1 Intelligence Life Cycle, 1.2 Cyber Threat Intelligence Frameworks, 1.3 Summary | TBD |
| 2 | Digital Forensics | 2.1 Device Collection, 2.2 Preservation, 2.3 Acquisition, 2.4 Processing, 2.5 Analysis, 2.6 Documentation and Reporting, 2.7 Summary | TBD |
| 3 | Disk Forensics | 3.1 Acquisition, 3.2 Preparation, 3.3 Analysis, 3.4 File and Data Carving, 3.5 Summary | TBD |
| 4 | Memory Forensics | 4.1 Acquisition, 4.2 Analysis, 4.3 Summary | TBD |
| 5 | SQLite Forensics | 5.1 Analyzing, 5.2 Summary | TBD |
| 6 | Windows Forensics | 6.1 New Technology File System (NTFS), 6.2 Acquisition, 6.3 Analysis, 6.4 Evidence Location, 6.5 Summary | TBD |
| 7 | macOS Forensics | 7.1 File System, 7.2 Security, 7.3 Acquisition, 7.4 Analysis, 7.5 Evidence Location, 7.6 Summary | TBD |

---

## Planned Tutorial Phase Mapping

### Phase 1: `cyber_threat_intelligence_fundamentals`

| Property | Value |
|----------|-------|
| **phase_id** | `cyber_threat_intelligence_fundamentals` |
| **title** | Cyber Threat Intelligence Fundamentals |
| **description** | Intelligence lifecycle, CTI frameworks, and strategic threat analysis methodologies |
| **source_chapters** | Chapter 1 (1.1-1.3) |
| **expected_steps** | 4-5 |
| **canonical_tags** | `["threat-intelligence", "intelligence-cycle", "frameworks", "analysis", "cti"]` |
| **related_tools** | `["misp", "maltego", "opencti", "yeti"]` |
| **replaces_existing** | None |
| **quiz_attachment** | New quiz file: `threat_intelligence/cti-fundamentals-quiz.txt` |

**Steps:**

1. Intelligence Life Cycle (Direction, Collection, Processing, Analysis, Dissemination)
2. Cyber Threat Intelligence Frameworks (MITRE ATT&CK, Diamond Model, Kill Chain)
3. Intelligence Sources and Collection Methods
4. Strategic vs Tactical vs Operational Intelligence
5. Assessment: CTI Fundamentals Quiz

---

### Phase 2: `digital_forensics_methodology`

| Property | Value |
|----------|-------|
| **phase_id** | `digital_forensics_methodology` |
| **title** | Digital Forensics Methodology |
| **description** | End-to-end forensic investigation process from evidence collection to court-ready reporting |
| **source_chapters** | Chapter 2 (2.1-2.7) |
| **expected_steps** | 7-8 |
| **canonical_tags** | `["forensics", "dfir", "evidence", "chain-of-custody", "acquisition"]` |
| **related_tools** | `["autopsy", "ftk", "encase", "sleuthkit", "dc3dd"]` |
| **replaces_existing** | None |
| **quiz_attachment** | New quiz file: `forensics/dfir-methodology-quiz.txt` |

**Steps:**

1. Device Collection and Scene Documentation
2. Evidence Preservation and Chain of Custody
3. Forensic Acquisition Methods (Live vs Dead, Logical vs Physical)
4. Evidence Processing Workflows
5. Analysis Techniques and Methodologies
6. Documentation and Reporting Standards
7. Legal Considerations and Expert Testimony
8. Assessment: DFIR Methodology Quiz

---

### Phase 3: `disk_forensics_analysis`

| Property | Value |
|----------|-------|
| **phase_id** | `disk_forensics_analysis` |
| **title** | Disk Forensics Analysis |
| **description** | File system analysis, data carving, and disk-level evidence extraction |
| **source_chapters** | Chapter 3 (3.1-3.5) |
| **expected_steps** | 5-6 |
| **canonical_tags** | `["forensics", "disk", "file-carving", "filesystem", "evidence"]` |
| **related_tools** | `["autopsy", "sleuthkit", "foremost", "scalpel", "photorec", "testdisk"]` |
| **replaces_existing** | None |
| **quiz_attachment** | New quiz file: `forensics/disk-forensics-quiz.txt` |

**Steps:**

1. Disk Acquisition (dd, dc3dd, FTK Imager)
2. Evidence Preparation and Verification
3. File System Analysis (NTFS, EXT4, FAT, APFS)
4. File and Data Carving Techniques
5. Deleted File Recovery
6. Assessment: Disk Forensics Quiz

---

### Phase 4: `memory_forensics_analysis`

| Property | Value |
|----------|-------|
| **phase_id** | `memory_forensics_analysis` |
| **title** | Memory Forensics Analysis |
| **description** | RAM acquisition and volatile memory analysis for incident response |
| **source_chapters** | Chapter 4 (4.1-4.3) |
| **expected_steps** | 4-5 |
| **canonical_tags** | `["forensics", "memory", "volatility", "ram", "malware"]` |
| **related_tools** | `["volatility3", "rekall", "winpmem", "lime", "dumpit"]` |
| **replaces_existing** | None |
| **quiz_attachment** | New quiz file: `forensics/memory-forensics-quiz.txt` |

**Steps:**

1. Memory Acquisition Techniques (Live Capture)
2. Volatility Framework Analysis
3. Process and Network Analysis
4. Malware Detection in Memory
5. Assessment: Memory Forensics Quiz

---

### Phase 5: `sqlite_forensics`

| Property | Value |
|----------|-------|
| **phase_id** | `sqlite_forensics` |
| **title** | SQLite Forensics |
| **description** | Analyzing SQLite databases for browser history, messaging apps, and application data |
| **source_chapters** | Chapter 5 (5.1-5.2) |
| **expected_steps** | 3-4 |
| **canonical_tags** | `["forensics", "sqlite", "database", "browser", "messaging"]` |
| **related_tools** | `["sqlite-browser", "sqlitebrowser", "autopsy"]` |
| **replaces_existing** | None |
| **quiz_attachment** | Combined with disk-forensics-quiz.txt |

**Steps:**

1. SQLite Database Structure and Analysis
2. Browser and Messaging App Artifacts
3. WAL File Analysis and Recovery
4. Assessment: SQLite Forensics Quiz

---

### Phase 6: `windows_forensics_deep_dive`

| Property | Value |
|----------|-------|
| **phase_id** | `windows_forensics_deep_dive` |
| **title** | Windows Forensics Deep Dive |
| **description** | NTFS analysis, Windows artifacts, registry forensics, and event log analysis |
| **source_chapters** | Chapter 6 (6.1-6.5) |
| **expected_steps** | 6-7 |
| **canonical_tags** | `["forensics", "windows", "ntfs", "registry", "eventlog", "artifacts"]` |
| **related_tools** | `["autopsy", "regripper", "registry-explorer", "evtx-dump", "timeline-explorer"]` |
| **replaces_existing** | Complements `windows_ctf` (no replacement) |
| **quiz_attachment** | New quiz file: `forensics/windows-forensics-quiz.txt` |

**Steps:**

1. NTFS File System Internals (MFT, $J, $I30)
2. Windows Acquisition Strategies
3. Registry Analysis (SAM, SYSTEM, SOFTWARE, NTUSER.DAT)
4. Event Log Analysis
5. Evidence Location Quick Reference
6. Timeline Construction
7. Assessment: Windows Forensics Quiz

---

### Phase 7: `macos_forensics`

| Property | Value |
|----------|-------|
| **phase_id** | `macos_forensics` |
| **title** | macOS Forensics |
| **description** | APFS analysis, macOS security features, and Apple-specific artifacts |
| **source_chapters** | Chapter 7 (7.1-7.6) |
| **expected_steps** | 6-7 |
| **canonical_tags** | `["forensics", "macos", "apfs", "apple", "unified-log"]` |
| **related_tools** | `["mac-apt", "plist-parser", "unified-log-parser"]` |
| **replaces_existing** | None |
| **quiz_attachment** | New quiz file: `forensics/macos-forensics-quiz.txt` |

**Steps:**

1. APFS File System Structure
2. macOS Security Features (SIP, Gatekeeper, FileVault)
3. macOS Acquisition Challenges
4. macOS Artifact Analysis
5. Evidence Location Reference
6. Unified Log Analysis
7. Assessment: macOS Forensics Quiz

---

## AI Phase Replacement Plan

### Decision Framework

| Decision | Meaning |
|----------|---------|
| **KEEP** | Phase is high-quality, provides unique value, no changes needed |
| **REPLACE** | Phase is low-quality or redundant, will be removed when new content is ready |
| **MERGE** | Phase content should be combined with another phase |
| **RETAIN-REVIEW** | Keep for now, but schedule for quality review |

---

### Current AI Phases Assessment

| Phase ID | Title | Decision | Rationale |
|----------|-------|----------|-----------|
| `traditional-vs-ai-pentesting-foundations` | Foundations of Pentesting with AI Integration | **REPLACE** | Low-quality (3 shallow steps, generic content). Replace with proper foundations from book or new authoring. |
| `building-modern-pt-lab-genai` | Building a Modern PT Lab with GenAI | **RETAIN-REVIEW** | Potentially useful, needs quality assessment |
| `genai-driven-reconnaissance` | GenAI-Driven Reconnaissance | **RETAIN-REVIEW** | Topic valid, content quality unknown |
| `ai-enhanced-scanning-sniffing` | AI-Enhanced Scanning and Sniffing | **RETAIN-REVIEW** | Topic valid, content quality unknown |
| `vulnerability-assessment-ai` | Vulnerability Assessment with AI | **RETAIN-REVIEW** | Topic valid, content quality unknown |
| `ai-driven-social-engineering` | AI-Driven Social Engineering | **RETAIN-REVIEW** | Topic valid, content quality unknown |
| `genai-driven-exploitation` | GenAI-Driven Exploitation | **RETAIN-REVIEW** | Topic valid, content quality unknown |
| `post-exploitation-privilege-escalation-ai` | Post-Exploitation with AI | **RETAIN-REVIEW** | Topic valid, content quality unknown |
| `automating-pt-reports-genai` | Automating PT Reports with GenAI | **RETAIN-REVIEW** | Topic valid, content quality unknown |
| `ai_security` | AI/ML Security | **KEEP** | High-quality (13 comprehensive steps, detailed content, proper methodology structure) |
| `ai_powered_offensive_security` | AI-Powered Offensive Security Tools | **KEEP** | High-quality (5 detailed steps with code examples, realistic tooling) |
| `retrieval_augmented_generation_red_teaming` | RAG Red Teaming | **RETAIN-REVIEW** | Specialized topic, needs assessment |
| `bug_bounty_automation_ai` | Bug Bounty Automation with AI | **RETAIN-REVIEW** | Topic valid, content quality unknown |
| `ai_agentic_operations` | AI Agentic Operations for Pentesting | **KEEP** | High-quality (8 comprehensive steps covering AutoGen, PyRIT, safety guardrails) |
| `ai_secops_copilots` | AI SecOps Copilots | **RETAIN-REVIEW** | Topic valid, content quality unknown |
| `ai_playbook_automation` | AI Playbook Automation | **RETAIN-REVIEW** | Topic valid, content quality unknown |

---

### Summary of Replacement Actions

**Phases to KEEP (3):**

- `ai_security`
- `ai_powered_offensive_security`
- `ai_agentic_operations`

**Phases to REPLACE (1):**

- `traditional-vs-ai-pentesting-foundations` → Remove from `load_tutorial_phases()` once new forensics content is ready

**Phases to RETAIN-REVIEW (12):**
All other AI phases require content quality review before final decision.

---

## Ordering Rules for `load_tutorial_phases()`

### Proposed Phase Ordering

The new Cyber Intelligence / Forensics phases should be inserted **after Linux/Windows CTF tutorials** and **before modern security topics**:

```rust
pub fn load_tutorial_phases() -> Vec<Phase> {
    vec![
        // ============================================
        // SECTION 1: Foundational Skills (positions 1-7)
        // ============================================
        load_tutorial_phase("linux_basics_for_hackers"),
        load_tutorial_phase("networking_fundamentals"),
        load_tutorial_phase("wifi_security_attacks"),
        load_tutorial_phase("password_cracking_techniques"),
        load_tutorial_phase("python_penetration_testing"),
        load_tutorial_phase("reverse_shells_guide"),
        load_tutorial_phase("file_security_practices"),
        
        // ============================================
        // SECTION 2: Reconnaissance (positions 8-11)
        // ============================================
        load_tutorial_phase("reconnaissance"),
        // REMOVE: load_tutorial_phase("traditional-vs-ai-pentesting-foundations"),
        // ... existing reconnaissance phases
        
        // ============================================
        // SECTION 3: Core PT Methodology (positions ~12-25)
        // ============================================
        // ... existing scanning, vulnerability, exploitation phases
        
        // ============================================
        // SECTION 4: CTF Practical Labs (positions ~26-27)
        // ============================================
        load_tutorial_phase("linux_ctf"),
        load_tutorial_phase("windows_ctf"),
        
        // ============================================
        // SECTION 5: CYBER THREAT INTELLIGENCE & FORENSICS (NEW - positions ~28-34)
        // Insert after CTF labs, before cloud/modern topics
        // ============================================
        load_tutorial_phase("cyber_threat_intelligence_fundamentals"),  // NEW
        load_tutorial_phase("digital_forensics_methodology"),           // NEW
        load_tutorial_phase("disk_forensics_analysis"),                 // NEW
        load_tutorial_phase("memory_forensics_analysis"),               // NEW
        load_tutorial_phase("sqlite_forensics"),                        // NEW
        load_tutorial_phase("windows_forensics_deep_dive"),             // NEW
        load_tutorial_phase("macos_forensics"),                         // NEW
        
        // ============================================
        // SECTION 6: Modern Security Topics (positions ~35-42)
        // ============================================
        load_tutorial_phase("cloud_iam"),
        load_tutorial_phase("practical_oauth"),
        // ... existing cloud, container, serverless phases
        
        // ============================================
        // SECTION 7: Advanced AI Topics (positions ~43-48)
        // ============================================
        load_tutorial_phase("ai_security"),                             // KEEP
        load_tutorial_phase("ai_powered_offensive_security"),           // KEEP
        load_tutorial_phase("ai_agentic_operations"),                   // KEEP
        // ... other retained AI phases
        
        // ============================================
        // SECTION 8: Certification Prep (positions ~49+)
        // ============================================
        load_tutorial_phase("comptia_secplus"),
        load_tutorial_phase("pentest_exam"),
        load_tutorial_phase("ceh"),
        // ... CISSP domains
    ]
}
```

### Ordering Rationale

1. **Forensics after CTF Labs**: CTF exercises establish practical pentesting skills; forensics is the post-incident analysis phase (chronologically follows exploitation)

2. **CTI before Forensics**: Threat intelligence provides context for forensic investigations

3. **Platform-specific forensics grouped**: Windows → macOS forensics maintains logical flow

4. **Before Cloud/Modern**: Forensics is foundational knowledge needed before advanced cloud and AI topics

5. **AI phases remain at end of advanced section**: High-quality AI phases stay in "Advanced Topics" section

---

## Quiz Content Requirements

### New Quiz Files Needed

| Quiz File Path | Associated Phase | Estimated Questions |
|----------------|------------------|---------------------|
| `data/threat_intelligence/cti-fundamentals-quiz.txt` | `cyber_threat_intelligence_fundamentals` | 20-30 |
| `data/forensics/dfir-methodology-quiz.txt` | `digital_forensics_methodology` | 25-35 |
| `data/forensics/disk-forensics-quiz.txt` | `disk_forensics_analysis` + `sqlite_forensics` | 30-40 |
| `data/forensics/memory-forensics-quiz.txt` | `memory_forensics_analysis` | 20-25 |
| `data/forensics/windows-forensics-quiz.txt` | `windows_forensics_deep_dive` | 30-40 |
| `data/forensics/macos-forensics-quiz.txt` | `macos_forensics` | 20-25 |

### Existing Quizzes to Retain

The following existing quizzes remain attached to their current phases:

- `ai_security/ai-security-quiz.txt` → `ai_security`
- `ai_powered_offensive_security/ai-offensive-security-quiz.txt` → `ai_powered_offensive_security`
- `ai_agent_operations/ai-agent-operations-assessment.txt` → `ai_agentic_operations`

---

## Implementation Checklist

### Phase 1: Full Book Extraction

- [ ] Re-run `extract_practical_cyber_intel.py` with complete PDF
- [ ] Verify all 7 chapters are extracted
- [ ] Review structured JSON for section boundaries

### Phase 2: Tutorial JSON Authoring

- [ ] Create `cyber_threat_intelligence_fundamentals.json`
- [ ] Create `digital_forensics_methodology.json`
- [ ] Create `disk_forensics_analysis.json`
- [ ] Create `memory_forensics_analysis.json`
- [ ] Create `sqlite_forensics.json`
- [ ] Create `windows_forensics_deep_dive.json`
- [ ] Create `macos_forensics.json`

### Phase 3: Quiz Content Creation

- [ ] Create quiz files in `data/forensics/` directory
- [ ] Create quiz files in `data/threat_intelligence/` directory
- [ ] Validate quiz format (9 pipe-delimited fields)

### Phase 4: Code Changes

- [ ] Update `src/tutorials/mod.rs` with new phases
- [ ] Remove `traditional-vs-ai-pentesting-foundations` from `load_tutorial_phases()`
- [ ] Add tool validations for new forensic tools
- [ ] Run `./test-all.sh` to verify

### Phase 5: Quality Review

- [ ] Review RETAIN-REVIEW phases for quality decision
- [ ] Update this manifest with final decisions
- [ ] Document any additional phase removals

---

## Version History

| Date | Change | Author |
|------|--------|--------|
| 2025-12-03 | Initial manifest creation | AI Agent |
