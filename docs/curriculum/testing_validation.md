# Testing & Validation Guide

## Overview

This guide provides comprehensive testing procedures for validating the Practical Cyber Intelligence curriculum integration and ensuring UI functionality after curriculum changes.

## Prerequisites

### System Dependencies

```bash
# Install required system packages (Ubuntu/Debian)
sudo apt update
sudo apt install -y \
    libgtk-4-dev \
    libadwaita-1-dev \
    libvte-2.91-gtk4-dev \
    libgtksourceview-5-dev \
    tesseract-ocr \
    poppler-utils

# Install Python dependencies for PDF extraction
pip install -r scripts/requirements.txt
```

### Rust Environment

```bash
# Ensure Rust is up to date
rustup update
cargo --version  # Should be 1.70+ 
```

## Automated Testing

### 1. Complete Test Suite

```bash
# Run all tests, linting, and validation
./test-all.sh

# Expected results:
# ✅ Unit tests pass (110+ tests)
# ✅ Integration tests pass (10+ tests)
# ✅ Clippy passes without warnings
# ✅ Code formatting is correct
# ✅ All JSON files are valid
```

### 2. Tutorial Catalog Audit

```bash
# Validate curriculum structure
python3 scripts/tutorial_catalog_audit.py

# Expected key metrics:
{
  "phase_count": 52,           # Total phases loaded
  "total_steps": 371,          # Total steps across all phases
  "ai_phase_count": 8,         # AI-focused phases remaining
  "forensics_phase_count": 9,   # NEW: Practical Cyber Intelligence phases
  "cti_phase_count": 9,         # Cyber threat intelligence phases
  "total_tools": 229           # Tools documented
}

# Verify specific phases exist:
python3 scripts/tutorial_catalog_audit.py | \
  jq '.phases[] | select(.forensics_focus == true) | {order, id, title}'

# Should return 9 forensics phases:
# 1. cyber_threat_intelligence_fundamentals
# 2. digital_forensics_methodology
# 3. disk_forensics_analysis
# 4. memory_forensics_analysis
# 5. sqlite_forensics
# 6. windows_forensics_deep_dive
# 7. network_forensics_fundamentals
# 8. macos_forensics
# 9. incident_response_methodology
```

### 3. JSON Structure Validation

```bash
# Validate all tutorial JSON files
find data/tutorials -name "*.json" -exec echo "Validating {}" \; -exec jq empty {} \;

# Validate tool instruction files
find data/tool_instructions -name "*.json" -exec echo "Validating {}" \; -exec jq empty {} \;

# Expected: No errors, all files valid JSON
```

### 4. Tutorial Structure Validation

```bash
# Run Rust tests for tutorial validation
cargo test tutorial_validation -- --nocapture

# Expected output:
# All 52 phases load successfully
# All phases have at least 1 step
# All steps have valid titles and content
# All tags follow naming conventions
# All referenced tool IDs exist
```

## GTK UI Testing

### 1. Application Startup

```bash
# Build and run the application
cargo run --release

# Expected behavior:
# ✅ Application launches without errors
# ✅ Main window appears with three-panel layout
# ✅ Sidebar shows 52 phases in correct order
# ✅ No missing phase titles or descriptions
```

### 2. Phase Navigation Testing

Navigate through the new Practical Cyber Intelligence phases:

#### Phase 20: Cyber Threat Intelligence Fundamentals
1. **Scroll to Phase 20** in the sidebar
2. **Click on the phase** to expand steps
3. **Verify step titles**:
   - Intelligence Life Cycle and Frameworks
   - Cyber Threat Intelligence Sources
   - Strategic vs Tactical Intelligence
   - CTI Tools and Platforms
   - Assessment: CTI Fundamentals Quiz
4. **Click each step** to verify content loads
5. **Check "Related Tools"** section appears with MISP, Maltego, OpenCTI, YETI

#### Phase 21: Digital Forensics Methodology
1. **Navigate to Phase 21**
2. **Verify step titles**:
   - Evidence Collection and Scene Documentation
   - Evidence Preservation and Chain of Custody
   - Forensic Acquisition Methods
   - Evidence Processing Workflows
   - Analysis Techniques and Methodologies
   - Documentation and Reporting Standards
   - Assessment: DFIR Methodology Quiz
3. **Test quiz functionality**:
   - Click quiz step
   - Verify questions load correctly
   - Test answer selection and submission
   - Check score calculation and feedback

#### Phase 22: Disk Forensics Analysis
1. **Navigate to Phase 22**
2. **Verify tool integration**:
   - Click "Related Tools" buttons for Autopsy, Sleuth Kit, etc.
   - Verify tool instructions appear in right panel
   - Test terminal integration with tool commands
3. **Check content formatting**:
   - Code blocks are properly highlighted
   - Images/commands render correctly
   - Step navigation works smoothly

### 3. Tool Panel Testing

For each forensics tool in the new phases:

```bash
# Test tool documentation access
# In UI, click each tool name in "Related Tools" section:

# Expected for each tool:
# ✅ Tool instructions load in right panel
# ✅ Installation tabs (Linux/macOS/Windows) work
# ✅ Quick examples display correctly
# ✅ Terminal integration works (can copy/paste commands)
# ✅ Non-modal dialog allows simultaneous terminal use
```

Key tools to test:
- **autopsy** - Comprehensive forensics platform
- **sleuthkit** - Command-line forensics tools
- **volatility3** - Memory forensics framework
- **ftk-imager** - Forensic imaging tool
- **wireshark** - Network forensics tool

### 4. Search and Filtering

```bash
# Test search functionality:
# 1. Use search box to find "forensics"
# 2. Verify all 9 forensics phases appear in results
# 3. Search for specific tools: "autopsy", "volatility"
# 4. Verify relevant phases are highlighted

# Test filtering:
# 1. Filter by tags: "forensics", "cti", "cyber-intelligence"
# 2. Verify correct phases are shown/hidden
# 3. Test tag combinations
```

### 5. Session Persistence

```bash
# Test session saving/loading:
# 1. Navigate to Phase 22, Step 3
# 2. Add some notes to a step
# 3. Close and restart application
# 4. Verify session is restored to correct position
# 5. Check notes are preserved
```

## Regression Testing Checklist

### Core Functionality

- [ ] **Application launches** without crashes or errors
- [ ] **All 52 phases load** with correct titles and descriptions
- [ ] **Phase ordering matches** expected curriculum flow
- [ ] **Navigation between phases** works smoothly
- [ ] **Step content displays** correctly with proper formatting
- [ ] **Quiz functionality works** for all quiz steps
- [ ] **Search and filtering** operate correctly
- [ ] **Session persistence** saves and restores state

### New Forensics Content

- [ ] **All 9 forensics phases appear** in correct positions (20-28)
- [ ] **Forensics step content** loads without errors
- [ ] **Related tools** display correctly for forensics phases
- [ ] **Tool documentation** is accessible and complete
- [ ] **Quiz questions** load and function properly
- [ ] **Content formatting** is consistent with other phases

### AI Content Validation

- [ ] **Only 8 AI phases remain** (down from 23)
- [ ] **Deprecated AI phases are removed** from navigation
- [ ] **Remaining AI content** is high-quality and functional
- [ ] **AI tool documentation** is still accessible
- [ ] **No broken references** to removed phases

### Tool Integration

- [ ] **All 229 tools** are documented and accessible
- [ ] **Forensics tools** (15 total) are properly categorized
- [ ] **AI security tools** (9 total) remain functional
- [ ] **Tool installation guides** work across platforms
- [ ] **Terminal integration** works for all tool commands
- [ ] **Related tools sections** link correctly

### Performance

- [ ] **Application startup time** is reasonable (< 10 seconds)
- [ ] **Phase switching** is responsive (< 2 seconds)
- [ ] **Search performance** is acceptable with large content
- [ ] **Memory usage** is stable during extended use
- [ ] **No memory leaks** during phase navigation

## Test Data Validation

### Expected Phase Counts

```bash
# Verify these exact counts:
Total Phases: 52
Forensics Phases: 9 (positions 20-28)
AI Phases: 8 (positions 39-46)
Certification Phases: 11 (positions 42-52)
Total Steps: 371
Total Tools: 229
```

### Expected Forensics Phase IDs

```bash
# These exact phase IDs should exist:
cyber_threat_intelligence_fundamentals
digital_forensics_methodology
disk_forensics_analysis
memory_forensics_analysis
sqlite_forensics
windows_forensics_deep_dive
network_forensics_fundamentals
macos_forensics
incident_response_methodology
```

### Expected Tool Categories

```bash
# Enhanced tool categories should include:
Forensics: 15 tools (autopsy, sleuthkit, volatility3, etc.)
AI & LLM Security: 9 tools (garak, pyrit, pentestgpt, etc.)
```

## Troubleshooting

### Common Issues

#### Application Won't Start
```bash
# Check GTK dependencies
ldd target/release/pt-journal | grep "not found"

# Install missing packages
sudo apt install libgtksourceview-5-dev

# Check Rust version
rustc --version  # Should be 1.70+
```

#### Missing Phases
```bash
# Verify tutorial files exist
ls data/tutorials/cyber_threat_intelligence_fundamentals.json

# Check phase loading
cargo test --bin pt-journal -- --nocapture | grep "Loading phase"
```

#### Tool Documentation Issues
```bash
# Validate tool JSON structure
jq empty data/tool_instructions/categories/forensics.json

# Check tool references
grep -r "autopsy" data/tutorials/ | head -5
```

#### Quiz Problems
```bash
# Verify quiz file format
head -1 data/forensics/dfir-methodology-quiz.txt
# Should have 9 pipe-delimited fields

# Test quiz parsing
cargo test quiz_parsing -- --nocapture
```

### Performance Issues

```bash
# Profile startup time
time cargo run --release

# Check memory usage
valgrind --tool=massif cargo run --release

# Monitor for leaks
valgrind --leak-check=full cargo run --release
```

## Continuous Integration

### Pre-commit Hooks

```bash
# Ensure these checks pass before commits:
./test-all.sh
python3 scripts/tutorial_catalog_audit.py
cargo clippy
cargo fmt --check
```

### Automated Validation

```bash
# CI pipeline should run:
# 1. Unit tests (cargo test)
# 2. Integration tests (cargo test --test integration_tests)
# 3. JSON validation (find . -name "*.json" -exec jq empty {} \;)
# 4. Tutorial audit (python3 scripts/tutorial_catalog_audit.py)
# 5. Clippy linting (cargo clippy)
# 6. Format checking (cargo fmt --check)
```

## Test Results Recording

### Template for Test Results

```markdown
## Test Results - [Date]

### Environment
- OS: [Ubuntu 22.04 / macOS 14 / Windows 11]
- Rust Version: [1.75.0]
- GTK Version: [4.12.5]

### Automated Tests
- Unit Tests: ✅ [115/115 passed]
- Integration Tests: ✅ [12/12 passed]
- Clippy: ✅ No warnings
- JSON Validation: ✅ All files valid
- Tutorial Audit: ✅ All metrics correct

### UI Testing
- Application Startup: ✅ [3.2 seconds]
- Phase Navigation: ✅ All 52 phases accessible
- Forensics Content: ✅ All 9 phases load correctly
- Tool Integration: ✅ All 229 tools documented
- Quiz Functionality: ✅ All quizzes work
- Search Performance: ✅ < 500ms response time

### Issues Found
- [List any issues discovered]
- [Severity and impact assessment]
- [Resolution steps taken]

### Performance Metrics
- Startup Time: [3.2 seconds]
- Memory Usage: [120MB steady state]
- Phase Switch Time: [0.8 seconds average]
- Search Response: [250ms average]

### Regression Status
- ✅ No regressions detected
- ✅ All new functionality working
- ✅ Performance maintained or improved
```

## Conclusion

Following this comprehensive testing guide ensures that the Practical Cyber Intelligence curriculum integration is successful and maintains the high quality standards of PT Journal. Regular execution of these tests validates both the new forensics content and the overall stability of the application.

For any issues discovered during testing, document them thoroughly and address them before releasing the updated curriculum to users.

---

**Testing Guide Version:** 1.0  
**Last Updated:** December 2024  
**Curriculum Version:** PT Journal v0.1.0+ with Practical Cyber Intelligence