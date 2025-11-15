# PT Journal - Documentation

This directory contains comprehensive technical documentation for the PT Journal project.

## 📚 Documentation Index

### 🏗️ Core Architecture

#### 📋 [MODULE_CONTRACTS.md](MODULE_CONTRACTS.md)
**Purpose**: API contracts and module boundaries  
**Size**: 16KB (581 lines)  
**Contents**:
- Architecture overview with layer diagrams
- API contracts for 7 core modules (Model, Store, Tools, UI, Dispatcher, Tutorial, Quiz)
- Testing contracts and patterns
- Performance contracts and benchmarks
- Extension points with code examples
- Dependency graph and migration guide

**Use this when**:
- Adding new modules or features
- Understanding module boundaries and contracts
- Extending the tool system
- Learning architectural patterns

---

### 📊 Project Management & Planning

#### 🚀 [../DEVELOPMENT_PLAN.md](../DEVELOPMENT_PLAN.md)
**Purpose**: Comprehensive 16-week development roadmap  
**Size**: 25KB+ lines  
**Contents**:
- 4-phase development plan (16 weeks)
- Current state analysis and metrics
- Tool integration priorities (8 new tools)
- UI enhancement roadmap
- Platform integration strategy
- Resource planning and team structure
- Success metrics and KPIs

**Use this when**:
- Planning development sprints
- Understanding project direction
- Contributing to specific features
- Resource allocation and timeline planning

#### 🗺️ [../ROADMAP_SECURITY_TOOLS.md](../ROADMAP_SECURITY_TOOLS.md)
**Purpose**: Security tools implementation roadmap  
**Size**: 44KB (1103 lines)  
**Contents**:
- Detailed implementation methodology
- Design patterns and principles
- Tool integration templates
- Phase-by-phase implementation plan
- Testing strategies and TDD methodology

**Use this when**:
- Implementing new security tools
- Understanding tool integration patterns
- Following established development practices

#### 📈 [../PROGRESS_SECURITY_TOOLS.md](../PROGRESS_SECURITY_TOOLS.md)
**Purpose**: Current progress and status report  
**Size**: 12KB (350 lines)  
**Contents**:
- Completed work summary (Phases 1-3)
- Implementation metrics (188 tests, 100% pass rate)
- Architecture highlights and patterns used
- File structure and code organization
- Usage examples and best practices
- Next steps and immediate priorities

**Use this when**:
- Understanding current project status
- Learning from implemented patterns
- Planning next development steps

---

### 📖 Reference & Guides

#### 🗂️ [../CODEBASE_INDEX.md](../CODEBASE_INDEX.md)
**Purpose**: Comprehensive codebase overview  
**Size**: 20KB+ lines  
**Contents**:
- Complete file structure and organization
- Architecture layers and component breakdown
- Code metrics and dependency analysis
- Development patterns and extension points
- Testing infrastructure and quality standards
- Development workflow and processes

**Use this when**:
- Navigating the codebase
- Understanding project structure
- Onboarding new developers
- Learning established patterns

#### 🛠️ [../TOOL_INSTRUCTIONS_FEATURE.md](../TOOL_INSTRUCTIONS_FEATURE.md)
**Purpose**: Tool instructions dialog feature documentation  
**Size**: 10KB (291 lines)  
**Contents**:
- Feature overview and implementation details
- UI components and user experience flow
- Technical implementation patterns
- Copyable command system
- Evidence timestamp format updates

**Use this when**:
- Understanding the tool instructions feature
- Extending the instruction system
- Learning UI implementation patterns

---

### 📊 Quality & Performance

#### 📊 [PERFORMANCE_BENCHMARKS.md](PERFORMANCE_BENCHMARKS.md)
**Purpose**: Performance metrics and regression tracking  
**Size**: 11KB (475 lines)  
**Contents**:
- Current performance status (v0.1.0)
- Session operation metrics
- Large session handling benchmarks
- Tool execution performance
- UI responsiveness metrics
- Regression tracking methodology
- Known bottlenecks and optimization roadmap

**Use this when**:
- Validating performance changes
- Tracking performance regressions
- Planning optimizations
- Understanding performance targets

#### ✅ [TDD_COMPLETION_REPORT.md](TDD_COMPLETION_REPORT.md)
**Purpose**: Status report for TDD/modularization tasks  
**Size**: 9.2KB (350+ lines)  
**Contents**:
- Task completion status tracking
- Test coverage summary (188/188 tests, 100%)
- Documentation deliverables status
- Build validation results
- Files modified and changes made
- Key achievements and recommendations

**Use this when**:
- Reviewing project progress and quality
- Understanding test coverage and quality metrics
- Planning quality assurance activities

---

### 📁 Storage & Data Management

#### 📂 [SESSION_FOLDER_STRUCTURE.md](SESSION_FOLDER_STRUCTURE.md)
**Purpose**: Session storage layout and evidence management  
**Size**: 8KB (300+ lines)  
**Contents**:
- Session folder organization
- Evidence file naming conventions
- Cross-platform directory handling
- Migration and compatibility guide
- Backup and restore procedures

**Use this when**:
- Understanding session storage
- Managing evidence files
- Implementing storage-related features

---

## 🎯 Quick Reference

### Current Project Status
- **Version**: v0.1.0 (Foundation Complete)
- **Test Coverage**: 188/188 tests passing (100%)
- **Security Tools**: Nmap + Gobuster integrations complete
- **Architecture**: 4-layer design with clear separation of concerns
- **Development Phase**: Ready for expansion (Phase 1 of 4)

### Performance Targets
- Session creation: < 100ms ✅
- Save/load operations: < 500ms each ✅
- UI handler response: < 16ms ✅
- Large sessions (5MB): < 1s ✅
- Tool execution: Configurable timeouts ✅

### Module Architecture
```
┌─────────────────────────────────────────┐
│              UI Layer (GTK4)             │
│  Main Window, Components, Handlers      │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│         Application Logic Layer          │
│  State Management, Event Dispatcher      │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│           Domain Model Layer             │
│  Session → Phase → Step → Evidence       │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│        Infrastructure Layer              │
│  Store, Tools, Tutorials, Quiz          │
└─────────────────────────────────────────┘
```

### Key Files for Contributors
- **Getting Started**: `../README.md`
- **Development Plan**: `../DEVELOPMENT_PLAN.md`
- **Code Structure**: `../CODEBASE_INDEX.md`
- **API Contracts**: `MODULE_CONTRACTS.md`
- **Tool Integration**: `../ROADMAP_SECURITY_TOOLS.md`

---

## 🔗 Related Documentation

### Project Documentation
- **Main README**: `../README.md` - Project overview, setup, and usage
- **Development Plan**: `../DEVELOPMENT_PLAN.md` - Complete 16-week roadmap
- **Codebase Index**: `../CODEBASE_INDEX.md` - Comprehensive code overview

### Technical Documentation
- **Module Contracts**: `MODULE_CONTRACTS.md` - API boundaries and patterns
- **Performance**: `PERFORMANCE_BENCHMARKS.md` - Metrics and benchmarks
- **Quality**: `TDD_COMPLETION_REPORT.md` - Test coverage and quality status

### Feature Documentation
- **Security Tools**: `../ROADMAP_SECURITY_TOOLS.md` - Tool integration roadmap
- **Progress Report**: `../PROGRESS_SECURITY_TOOLS.md` - Current status
- **Tool Instructions**: `../TOOL_INSTRUCTIONS_FEATURE.md` - Feature details

### Source Documentation
- **Inline Rust Docs**: `../src/` - Comprehensive API documentation
- **Copilot Instructions**: `.github/copilot-instructions.md` - AI assistant context
- **Test Examples**: `../tests/` - Integration and unit test patterns

---

## 🔄 Maintenance Schedule

These documents should be updated when:

### Regular Updates (Monthly)
- [ ] Progress metrics and test coverage
- [ ] Performance benchmarks and regression tracking
- [ ] Current development status and milestones

### Major Updates (Per Release)
- [ ] API contracts and module boundaries
- [ ] Architecture documentation and patterns
- [ ] Development plan and roadmap adjustments

### Event-Driven Updates
- [ ] New modules or major features added
- [ ] Significant architectural changes
- [ ] New tool integrations completed
- [ ] Performance targets modified
- [ ] Quality standards or processes updated

---

## 📞 Getting Help

### For Contributors
1. **Start Here**: `../README.md` - Setup and basic usage
2. **Plan Work**: `../DEVELOPMENT_PLAN.md` - Current priorities
3. **Understand Code**: `../CODEBASE_INDEX.md` - Structure overview
4. **Follow Patterns**: `MODULE_CONTRACTS.md` - API contracts

### For Users
1. **User Guide**: `../README.md` - Installation and usage
2. **Features**: `../PROGRESS_SECURITY_TOOLS.md` - Available tools
3. **Troubleshooting**: `../README.md#troubleshooting` - Common issues

### For Developers
1. **Architecture**: `MODULE_CONTRACTS.md` - System design
2. **Extension**: `../CODEBASE_INDEX.md#extension-points` - Adding features
3. **Quality**: `TDD_COMPLETION_REPORT.md` - Testing standards

---

**Last Updated**: November 15, 2025  
**Documentation Version**: v0.1.0  
**Maintainer**: PT Journal Development Team  

---

*This documentation index provides comprehensive navigation of all PT Journal documentation. Use this guide to find the right information for your needs, whether you're a user, contributor, or developer.*
