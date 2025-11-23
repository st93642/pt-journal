# Tool Instructions Categories

This directory contains modularized tool instruction files, organized by category.

## Structure

Each JSON file contains an array of tool instruction objects for tools in that specific category.
The files are named using the category name converted to lowercase with spaces and special characters replaced by underscores.

## Categories

- `reconnaissance.json` - Reconnaissance and information gathering tools
- `scanning_and_enumeration.json` - Network scanning and enumeration tools  
- `vulnerability_analysis.json` - Vulnerability assessment tools
- `exploitation.json` - Exploitation frameworks and tools
- `post_exploitation.json` - Post-exploitation tools
- `privilege_escalation.json` - Privilege escalation tools
- `password_attacks.json` - Password cracking and brute force tools
- `wireless.json` - Wireless security tools
- `web_application.json` - Web application security tools
- `network_sniffing_and_spoofing.json` - Network analysis and spoofing tools
- `maintaining_access.json` - Persistence and maintaining access tools
- `steganography.json` - Steganography and data hiding tools
- `forensics.json` - Digital forensics tools
- `reporting.json` - Reporting and documentation tools
- `social_engineering.json` - Social engineering tools
- `hardware_hacking.json` - Hardware hacking and SDR tools
- `workflow_guides.json` - Security assessment workflow guides
- `tool_comparisons.json` - Tool comparison guides
- `bug_bounty_workflows.json` - Bug bounty specific workflows
- `attack_playbooks.json` - Detailed attack playbooks
- `api_and_service_testing.json` - API and service testing tools
- `code_analysis_and_sast.json` - Static analysis and SAST tools
- `cloud_platform_security.json` - Cloud security assessment tools
- `container_and_kubernetes.json` - Container and Kubernetes security tools
- `mobile_and_reverse_engineering.json` - Mobile app and reverse engineering tools
- `osint_and_recon_enhanced.json` - Enhanced OSINT and reconnaissance tools
- `lateral_movement_and_directory.json` - Lateral movement and directory services tools
- `red_team_frameworks.json` - Red teaming frameworks
- `threat_hunting_and_compliance.json` - Threat hunting and compliance tools

## Loading

The application automatically loads all JSON files from this directory and combines them into a single instruction registry.
