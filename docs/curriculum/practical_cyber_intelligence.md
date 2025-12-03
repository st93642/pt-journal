# Practical Cyber Intelligence Curriculum

## Overview

PT Journal now features a comprehensive **Practical Cyber Intelligence & Digital Forensics** curriculum based on the book *"Practical Cyber Intelligence: A Hands-on Guide to Digital Forensics"* by Adam Tilmar Jakobsen. This curriculum provides hands-on training in threat intelligence analysis, digital forensics methodologies, and incident response techniques.

## Curriculum Structure

The forensics curriculum consists of **9 integrated phases** positioned strategically within the overall PT Journal learning path:

### Phase 20: Cyber Threat Intelligence Fundamentals
- **Topics**: Intelligence lifecycle, CTI frameworks, strategic threat analysis
- **Tools**: MISP, Maltego, OpenCTI, YETI
- **Skills**: Threat modeling, indicator management, intelligence reporting

### Phase 21: Digital Forensics Methodology  
- **Topics**: Evidence collection, preservation, acquisition, processing, analysis, reporting
- **Tools**: Autopsy, FTK Imager, dc3dd, forensic workstations
- **Skills**: Chain of custody, forensic imaging, documentation standards

### Phase 22: Disk Forensics Analysis
- **Topics**: File system analysis, data carving, disk-level evidence extraction
- **Tools**: Autopsy, Sleuth Kit, Foremost, Scalpel, PhotoRec, TestDisk
- **Skills**: NTFS/EXT4/APFS analysis, deleted file recovery, evidence reconstruction

### Phase 23: Memory Forensics Analysis
- **Topics**: RAM acquisition, volatile memory analysis, malware detection
- **Tools**: Volatility Framework, Rekall, WinPmem, Lime, DumpIt
- **Skills**: Process analysis, network artifact extraction, memory-based malware detection

### Phase 24: SQLite Forensics
- **Topics**: Database analysis, browser artifacts, messaging app forensics
- **Tools**: SQLite Browser, Autopsy plugins
- **Skills**: WAL file analysis, database reconstruction, artifact correlation

### Phase 25: Windows Forensics Deep Dive
- **Topics**: NTFS internals, registry analysis, event logs, evidence location
- **Tools**: Autopsy, Registry Explorer, EVTX tools, timeline analysis
- **Skills**: MFT analysis, SAM/SYSTEM extraction, event log correlation

### Phase 26: Network Forensics Fundamentals
- **Topics**: Network traffic analysis, packet capture, protocol analysis
- **Tools**: Wireshark, tcpdump, NetworkMiner, Zeek
- **Skills**: Traffic reconstruction, protocol decoding, anomaly detection

### Phase 27: macOS Forensics
- **Topics**: APFS analysis, macOS security features, Apple-specific artifacts
- **Tools**: Mac-APT, plist parsers, unified log analysis
- **Skills**: SIP analysis, FileVault handling, artifact location

### Phase 28: Incident Response Methodology
- **Topics**: IR lifecycle, containment, eradication, recovery, lessons learned
- **Tools**: SIEM platforms, IR orchestration tools, evidence collection kits
- **Skills**: Incident triage, root cause analysis, reporting procedures

## PDF Extraction & Tutorial Generation

### Source Material
- **Book**: "Practical Cyber Intelligence: A Hands-on Guide to Digital Forensics"
- **Author**: Adam Tilmar Jakobsen
- **Pages**: Complete text (7 chapters, 200+ pages)

### Extraction Pipeline

The curriculum is generated using an automated PDF extraction pipeline. The **structured extraction artifacts are already included** in `data/source_material/practical_cyber_intelligence/` — you only need to run the extraction script if you want to re-extract or update from the source PDF.

> **Note**: The PDF file is **not included in the repository** due to size and licensing. Contributors must obtain "Practical Cyber Intelligence: A Hands-on Guide to Digital Forensics" by Adam Tilmar Jakobsen externally and place it in the project root before running the extraction script.

```bash
# Install dependencies
pip install -r scripts/requirements.txt
sudo apt install tesseract-ocr poppler-utils

# Extract complete book content (PDF must be supplied externally)
python3 scripts/extract_practical_cyber_intel.py \
    --pdf "./Practical Cyber Intelligence.pdf" \
    --output data/source_material/practical_cyber_intelligence
```

### Pipeline Features

1. **Text-First Extraction**: Uses PyPDF2 for efficient text extraction
2. **OCR Fallback**: Automatic OCR for pages with insufficient text using Tesseract
3. **Structure Preservation**: Maintains chapter → section → paragraph hierarchy
4. **Page Tracking**: All content tagged with source page numbers for verification
5. **Quality Metrics**: Detailed statistics on extraction success rates

### Output Structure

```
data/source_material/practical_cyber_intelligence/
├── structured_book.json     # Hierarchical content structure
├── raw_transcript.txt       # Complete text with page markers
└── extraction_stats.json    # Processing statistics
```

### Tutorial JSON Generation

The extracted content is automatically converted into PT Journal tutorial phases:

```
data/tutorials/
├── cyber_threat_intelligence_fundamentals.json
├── digital_forensics_methodology.json
├── disk_forensics_analysis.json
├── memory_forensics_analysis.json
├── sqlite_forensics.json
├── windows_forensics_deep_dive.json
├── network_forensics_fundamentals.json
├── macos_forensics.json
└── incident_response_methodology.json
```

## Integration with PT Journal

### Phase Ordering

The forensics phases are strategically positioned after core penetration testing skills and before advanced modern security topics:

1. **Foundational Skills** (Phases 1-7): Linux, networking, Python, etc.
2. **Core PT Methodology** (Phases 8-19): Reconnaissance through exploitation
3. **CTF Practical Labs** (Phases 18-19): Linux and Windows CTF exercises
4. **📍 Cyber Intelligence & Forensics** (Phases 20-28): **NEW CURRICULUM**
5. **Modern Security Topics** (Phases 29-36): Cloud, containers, APIs
6. **Advanced Topics** (Phases 37-41): Supply chain, red team, bug bounty
7. **Certification Preparation** (Phases 42-52): CEH, Security+, PenTest+, CISSP

### Tool Integration

Each forensics phase includes comprehensive tool documentation:

- **Installation Guides**: Linux, macOS, Windows instructions
- **Usage Examples**: Step-by-step command sequences
- **Workflow Integration**: How tools fit into forensic investigations
- **Output Interpretation**: Understanding analysis results

### Quiz Integration

Each phase includes assessment quizzes with:

- **Knowledge Checks**: Concept understanding and terminology
- **Practical Scenarios**: Case study-based questions
- **Tool Proficiency**: Command usage and interpretation
- **Methodology**: Proper forensic procedures and legal considerations

## Validation & Testing

### Automated Validation

```bash
# Verify curriculum integration
python3 scripts/tutorial_catalog_audit.py

# Expected results:
# - 52 total phases (down from 67)
# - 371 total steps (down from 471)
# - 33 forensics-focused steps
# - 47 cyber-intelligence tagged steps
# - 9 forensics phases present and validated
```

### UI Testing

```bash
# Launch GTK application
cargo run --release

# Navigate to new forensics phases:
# 1. Cyber Threat Intelligence Fundamentals (Phase 20)
# 2. Digital Forensics Methodology (Phase 21)
# 3. Disk Forensics Analysis (Phase 22)
# 4. Memory Forensics Analysis (Phase 23)
# 5. SQLite Forensics (Phase 24)
# 6. Windows Forensics Deep Dive (Phase 25)
# 7. Network Forensics Fundamentals (Phase 26)
# 8. macOS Forensics (Phase 27)
# 9. Incident Response Methodology (Phase 28)

# Verify:
# - All steps display with proper formatting
# - Related tools appear in tool panel
# - Quiz questions load correctly
# - Navigation between phases works smoothly
```

### Test Suite Validation

```bash
# Run comprehensive test suite
./test-all.sh

# Verify:
# - All 52 phases load without errors
# - JSON structure validation passes
# - Tool references are valid
# - Quiz content is properly formatted
```

## Curriculum Benefits

### For Learners

1. **Comprehensive Coverage**: Complete forensics workflow from intelligence collection to incident response
2. **Hands-On Experience**: Real-world tools and scenarios throughout the curriculum
3. **Structured Learning**: Progressive skill building with each phase building on previous knowledge
4. **Certification Preparation**: Content aligned with industry forensics certifications

### For Organizations

1. **Workforce Development**: Complete training pipeline for DFIR teams
2. **Standardized Procedures**: Consistent methodologies across team members
3. **Tool Proficiency**: Hands-on experience with industry-standard forensic tools
4. **Documentation Skills**: Emphasis on proper evidence handling and reporting

### Integration with Existing Content

1. **Complementary Skills**: Forensics knowledge enhances penetration testing capabilities
2. **Complete Attack Lifecycle**: From initial intelligence through post-incident analysis
3. **Tool Synergy**: Many tools used in both pentesting and forensics contexts
4. **Career Development**: Broader skill set for security professionals

## Future Enhancements

### Planned Additions

1. **Additional Case Studies**: Real-world scenarios for practical application
2. **Advanced Memory Analysis**: Malware forensics and reverse engineering integration
3. **Cloud Forensics**: AWS, Azure, GCP evidence collection and analysis
4. **Mobile Forensics**: iOS and Android device analysis
5. **Network Forensics Deep Dive**: Advanced traffic analysis and attribution

### Tool Expansion

1. **Automated Analysis**: Machine learning tools for pattern recognition
2. **Timeline Visualization**: Advanced timeline construction tools
3. **Collaboration Platforms**: Team-based forensic analysis workflows
4. **Reporting Automation**: Template-driven report generation

## Contributing

### Adding New Forensics Content

1. **Extract Content**: Use the PDF pipeline for new source materials
2. **Create Tutorial JSON**: Follow existing structure and patterns
3. **Add Tool Documentation**: Include comprehensive tool guides
4. **Develop Quiz Content**: Create assessment questions for each phase
5. **Update Validation**: Ensure new phases pass all automated checks

### Quality Standards

- **Accuracy**: All technical content verified against authoritative sources
- **Completeness**: Each phase includes theory, tools, and practical exercises
- **Consistency**: Uniform formatting and structure across all phases
- **Testing**: All content passes automated validation and manual review

---

**Curriculum Version**: 1.0  
**Last Updated**: December 2024  
**Source**: "Practical Cyber Intelligence: A Hands-on Guide to Digital Forensics" by Adam Tilmar Jakobsen  
**Integration**: PT Journal v0.1.0+