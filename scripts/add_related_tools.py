#!/usr/bin/env python3
"""
Add related_tools to tutorial JSON files based on content analysis.
Maps tutorial steps to appropriate tools from the tool_instructions categories.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Set

# Valid tool IDs from data/tool_instructions/categories/
VALID_TOOL_IDS = {
    "adrecon", "adversary-emulation-playbook", "aircrack-ng", "amass", "androidsuite",
    "apktool", "awscli", "aws-sam-cli", "azcli", "azure-functions-core-tools", "bandit",
    "bettercap", "binwalk", "bloodhound-python", "bloomrpc", "boofuzz", "brakeman",
    "bugbounty_api_testing", "bugbounty_mobile_app_testing", "bugbounty_owasp_top10",
    "bugbounty_reporting_cvss", "bugbounty_scope_recon", "bugbounty_web_app_testing",
    "bulk_extractor", "bully", "burp-api-scanner", "burpsuite", "caldera", "censys-api",
    "cewl", "chisel", "clair", "cloud-iam-enum", "cloud-iam-priv-esc-playbook",
    "cloudmapper", "cloud-storage-misconfig-playbook", "commix", "comparison_directory_fuzzers",
    "comparison_port_scanners", "comparison_sql_testing", "comparison_web_proxies",
    "crtsh", "crunch", "cryptcat", "dependency-check", "dirb", "dirbuster", "dnscat2",
    "dnsenum", "dnsrecon", "dns-tunneling", "docker", "dradis", "driftnet", "dsniff",
    "edr-opsec-checklist", "empire", "enum4linux", "eslint-security", "ettercap",
    "evil-winrm", "exiftool", "falco", "faraday", "fcrackzip", "federation-attack-scenarios",
    "ffuf", "ffuf-api", "foremost", "frida", "garak", "gcloud", "gcp-enum",
    "gcp-functions-framework", "gnuradio", "gobuster", "gqrx", "graphql-introspector",
    "graphqlmap", "graphql-testing", "grpc-security", "grpcurl", "grype", "hackrf",
    "hashcat", "hashid", "helm", "hexedit", "holehe", "hunter-io", "hydra",
    "impacket-scripts", "inql", "insomnia", "iossuite", "jadx", "john", "joomscan",
    "kismet", "kubeaudit", "kube-bench", "kubectl", "kube-hunter", "kubesploit",
    "lakera-guard", "ldapdump", "ldapsearch", "ligolo-ng", "linpeas",
    "linux-exploit-suggester", "linux-smart-enumeration", "llm-guard", "llmguard",
    "loganalysis", "lynis", "maltego", "masscan", "mdk4", "medusa", "metasploit",
    "microburst", "mimikatz", "mitmproxy", "ml-pipeline-audit", "mobsf", "naabu",
    "ncrack", "nemo_guardrails", "newman", "nikto", "nmap", "nuclei", "onesixtyone",
    "openapi-scanner", "outguess", "owasp-zap", "pacu", "patator", "pdfcrack",
    "pentestgpt", "photon", "playbook_covert_data_extraction",
    "playbook_credential_spraying_brute_force", "playbook_evidence_collection_artifact_removal",
    "playbook_exploit_development_workflow", "playbook_hash_cracking_pass_the_hash",
    "playbook_multi_stage_credential_harvesting", "playbook_persistence_mechanism_installation",
    "playbook_shellcode_creation_obfuscation", "playbook_token_theft_session_hijacking",
    "playbook_zero_day_cve_exploitation", "poshc2", "postman", "powersploit", "promptfoo",
    "prowler", "proxychains", "pspy", "pwncat", "pyrit", "reaver", "recon-ng",
    "registry-scanner", "retire-js", "sbd", "scalpel", "scoutsuite", "searchsploit",
    "semgrep", "serverless-framework", "setoolkit", "shodan-cli", "sigma", "sliver",
    "smbmap", "snmpwalk", "snyk", "socks-tunneling", "sonarqube", "spiderfoot", "sqlmap",
    "ssh-portforward", "sslyze", "sso-oauth-oidc-misconfig-playbook", "steghide", "strings",
    "subjack", "sublist3r", "swagger-codegen", "tcpdump", "testssl", "theHarvester",
    "threat-hunting-cloud", "trivy", "trufflehog", "tshark", "unix-privesc-check", "urh",
    "wappalyzer", "weevely", "wfuzz", "whatweb", "whoisutils", "wifite",
    "windows-exploit-suggester", "winpeas", "wireshark", "workflow_cloud_iam_assessment",
    "workflow_cloud_security_assessment", "workflow_evasion_obfuscation",
    "workflow_hipaa_compliance", "workflow_incident_response_forensics",
    "workflow_infra_pentest", "workflow_internal_network_ptes", "workflow_modern_api_testing",
    "workflow_osint_assessment", "workflow_pci_dss_assessment",
    "workflow_physical_security_malware", "workflow_red_purple_team_collaboration",
    "workflow_social_engineering_campaign", "workflow_supply_chain_security",
    "workflow_threat_hunting_lifecycle", "workflow_web_app_pentest", "workflow_wireless_audit",
    "workflow_wireless_security_assessment", "wpscan", "xxd", "yara", "zerologon"
}

# Keyword to tool mapping - maps content keywords to tool IDs
KEYWORD_TOOL_MAP = {
    # Reconnaissance & OSINT
    "reconnaissance": ["amass", "theHarvester", "spiderfoot", "recon-ng", "maltego", "shodan-cli"],
    "osint": ["maltego", "theHarvester", "spiderfoot", "recon-ng", "holehe", "hunter-io"],
    "subdomain": ["amass", "sublist3r", "gobuster", "ffuf", "subjack"],
    "dns": ["dnsenum", "dnsrecon", "amass", "dns-tunneling", "dnscat2"],
    "whois": ["whoisutils", "recon-ng", "maltego"],
    "email": ["theHarvester", "hunter-io", "holehe"],
    "shodan": ["shodan-cli"],
    "censys": ["censys-api"],
    "harvester": ["theHarvester"],
    
    # Network Scanning
    "nmap": ["nmap", "masscan", "naabu"],
    "port scan": ["nmap", "masscan", "naabu", "comparison_port_scanners"],
    "scan": ["nmap", "nikto", "nuclei", "masscan"],
    "enumeration": ["enum4linux", "smbmap", "snmpwalk", "ldapsearch"],
    "smb": ["enum4linux", "smbmap", "impacket-scripts"],
    "snmp": ["snmpwalk", "onesixtyone"],
    "ldap": ["ldapsearch", "ldapdump", "bloodhound-python"],
    
    # Web Application
    "web application": ["burpsuite", "owasp-zap", "nikto", "wappalyzer"],
    "sql injection": ["sqlmap", "commix", "comparison_sql_testing"],
    "sqlmap": ["sqlmap"],
    "xss": ["burpsuite", "owasp-zap"],
    "directory": ["dirb", "dirbuster", "gobuster", "ffuf", "comparison_directory_fuzzers"],
    "fuzzing": ["ffuf", "wfuzz", "boofuzz", "gobuster"],
    "burp": ["burpsuite", "burp-api-scanner"],
    "zap": ["owasp-zap"],
    "nikto": ["nikto"],
    "wordpress": ["wpscan"],
    "joomla": ["joomscan"],
    "cms": ["wpscan", "joomscan", "nikto"],
    "api": ["burp-api-scanner", "ffuf-api", "postman", "newman", "insomnia", "swagger-codegen"],
    "graphql": ["graphqlmap", "graphql-introspector", "graphql-testing", "inql"],
    "grpc": ["grpc-security", "grpcurl", "bloomrpc"],
    "rest api": ["postman", "newman", "burp-api-scanner", "ffuf-api"],
    "openapi": ["openapi-scanner", "swagger-codegen"],
    
    # Password & Authentication
    "password": ["hashcat", "john", "hydra", "crunch", "cewl"],
    "hash": ["hashcat", "john", "hashid"],
    "brute force": ["hydra", "medusa", "ncrack", "patator", "playbook_credential_spraying_brute_force"],
    "dictionary": ["cewl", "crunch"],
    "crack": ["hashcat", "john", "fcrackzip", "pdfcrack", "pyrit"],
    "hydra": ["hydra"],
    "mimikatz": ["mimikatz", "impacket-scripts"],
    "credentials": ["mimikatz", "playbook_multi_stage_credential_harvesting"],
    "oauth": ["sso-oauth-oidc-misconfig-playbook", "federation-attack-scenarios"],
    "sso": ["sso-oauth-oidc-misconfig-playbook"],
    "oidc": ["sso-oauth-oidc-misconfig-playbook"],
    "saml": ["federation-attack-scenarios"],
    
    # Exploitation
    "metasploit": ["metasploit", "searchsploit"],
    "exploit": ["metasploit", "searchsploit", "linux-exploit-suggester", "windows-exploit-suggester"],
    "msfconsole": ["metasploit"],
    "shellcode": ["playbook_shellcode_creation_obfuscation"],
    "reverse shell": ["pwncat", "weevely", "metasploit"],
    "payload": ["metasploit", "empire", "sliver"],
    "buffer overflow": ["playbook_exploit_development_workflow", "boofuzz"],
    
    # Post Exploitation
    "post exploitation": ["linpeas", "winpeas", "pspy", "mimikatz"],
    "privilege escalation": ["linpeas", "winpeas", "linux-exploit-suggester", "windows-exploit-suggester", "unix-privesc-check"],
    "linpeas": ["linpeas", "linux-smart-enumeration"],
    "winpeas": ["winpeas"],
    "lateral movement": ["impacket-scripts", "bloodhound-python", "evil-winrm"],
    "persistence": ["playbook_persistence_mechanism_installation", "empire", "poshc2"],
    "pivoting": ["chisel", "ligolo-ng", "proxychains", "ssh-portforward", "socks-tunneling"],
    "tunneling": ["chisel", "ligolo-ng", "dns-tunneling", "dnscat2", "cryptcat"],
    "c2": ["empire", "sliver", "poshc2", "caldera"],
    "command and control": ["empire", "sliver", "poshc2", "caldera"],
    
    # Wireless
    "wireless": ["aircrack-ng", "wifite", "bettercap", "kismet", "workflow_wireless_audit"],
    "wifi": ["aircrack-ng", "wifite", "reaver", "bully", "pyrit"],
    "aircrack": ["aircrack-ng"],
    "wpa": ["aircrack-ng", "reaver", "bully", "pyrit"],
    "wps": ["reaver", "bully"],
    "bluetooth": ["bettercap"],
    "sdr": ["gnuradio", "hackrf", "gqrx", "urh"],
    "radio": ["gnuradio", "hackrf", "gqrx", "urh"],
    
    # Network Sniffing
    "sniffing": ["wireshark", "tcpdump", "tshark", "bettercap", "ettercap"],
    "wireshark": ["wireshark", "tshark"],
    "tcpdump": ["tcpdump"],
    "packet": ["wireshark", "tcpdump", "tshark", "scalpel"],
    "mitm": ["bettercap", "ettercap", "mitmproxy", "driftnet"],
    "arp": ["bettercap", "ettercap", "dsniff"],
    "spoofing": ["bettercap", "ettercap", "dsniff"],
    
    # Cloud Security
    "aws": ["awscli", "pacu", "prowler", "scoutsuite", "cloudmapper"],
    "azure": ["azcli", "microburst", "scoutsuite", "prowler"],
    "gcp": ["gcloud", "gcp-enum", "scoutsuite", "prowler"],
    "cloud": ["prowler", "scoutsuite", "cloudmapper", "workflow_cloud_security_assessment"],
    "iam": ["cloud-iam-enum", "cloud-iam-priv-esc-playbook", "pacu"],
    "s3": ["awscli", "cloud-storage-misconfig-playbook"],
    "lambda": ["aws-sam-cli", "serverless-framework"],
    "serverless": ["serverless-framework", "aws-sam-cli", "gcp-functions-framework", "azure-functions-core-tools"],
    
    # Container & Kubernetes
    "docker": ["docker", "trivy", "clair", "grype"],
    "kubernetes": ["kubectl", "kube-bench", "kubeaudit", "kube-hunter", "kubesploit", "helm"],
    "k8s": ["kubectl", "kube-bench", "kubeaudit", "kube-hunter"],
    "container": ["docker", "trivy", "clair", "grype", "falco"],
    "helm": ["helm"],
    "registry": ["registry-scanner", "trivy"],
    
    # Code Analysis
    "sast": ["semgrep", "bandit", "brakeman", "sonarqube", "eslint-security"],
    "code analysis": ["semgrep", "bandit", "brakeman", "sonarqube"],
    "static analysis": ["semgrep", "bandit", "brakeman", "sonarqube"],
    "secrets": ["trufflehog", "semgrep"],
    "dependency": ["dependency-check", "snyk", "retire-js", "grype"],
    "vulnerability scan": ["nuclei", "nikto", "trivy", "grype", "snyk"],
    
    # Forensics
    "forensics": ["bulk_extractor", "foremost", "scalpel", "binwalk", "strings", "xxd"],
    "memory": ["bulk_extractor", "strings"],
    "disk": ["foremost", "scalpel", "bulk_extractor"],
    "carving": ["foremost", "scalpel", "bulk_extractor"],
    "steganography": ["steghide", "outguess", "exiftool", "binwalk"],
    "metadata": ["exiftool", "strings"],
    "binary": ["binwalk", "strings", "xxd", "hexedit"],
    "reverse engineering": ["frida", "jadx", "apktool", "binwalk", "strings"],
    "malware": ["yara", "sigma", "strings", "binwalk"],
    
    # Mobile
    "android": ["androidsuite", "apktool", "jadx", "frida", "mobsf"],
    "ios": ["iossuite", "frida", "mobsf"],
    "mobile": ["mobsf", "frida", "apktool", "jadx"],
    "apk": ["apktool", "jadx", "mobsf"],
    
    # Social Engineering
    "social engineering": ["setoolkit", "workflow_social_engineering_campaign"],
    "phishing": ["setoolkit", "workflow_social_engineering_campaign"],
    "spear phishing": ["setoolkit"],
    
    # Reporting
    "report": ["dradis", "faraday", "bugbounty_reporting_cvss"],
    "cvss": ["bugbounty_reporting_cvss"],
    "documentation": ["dradis", "faraday"],
    
    # AI/LLM Security
    "llm": ["garak", "promptfoo", "llm-guard", "llmguard", "lakera-guard", "nemo_guardrails"],
    "ai security": ["garak", "promptfoo", "ml-pipeline-audit", "pentestgpt"],
    "prompt injection": ["garak", "promptfoo"],
    "ml": ["ml-pipeline-audit", "garak"],
    "guardrails": ["nemo_guardrails", "lakera-guard", "llm-guard"],
    
    # Red Team
    "red team": ["caldera", "empire", "sliver", "workflow_red_purple_team_collaboration"],
    "adversary": ["caldera", "adversary-emulation-playbook"],
    "emulation": ["caldera", "adversary-emulation-playbook"],
    "evasion": ["workflow_evasion_obfuscation", "edr-opsec-checklist"],
    "edr": ["edr-opsec-checklist"],
    
    # Threat Hunting
    "threat hunting": ["sigma", "yara", "threat-hunting-cloud", "workflow_threat_hunting_lifecycle"],
    "sigma": ["sigma"],
    "yara": ["yara"],
    "detection": ["sigma", "yara", "falco"],
    "siem": ["sigma", "loganalysis"],
    "log analysis": ["loganalysis", "sigma"],
    
    # Compliance
    "compliance": ["lynis", "workflow_pci_dss_assessment", "workflow_hipaa_compliance"],
    "hardening": ["lynis", "kube-bench"],
    "audit": ["lynis", "kubeaudit", "prowler"],
    
    # Active Directory
    "active directory": ["bloodhound-python", "adrecon", "impacket-scripts", "mimikatz"],
    "ad": ["bloodhound-python", "adrecon", "impacket-scripts"],
    "bloodhound": ["bloodhound-python"],
    "kerberos": ["impacket-scripts", "mimikatz"],
    "zerologon": ["zerologon"],
    
    # SSL/TLS
    "ssl": ["sslyze", "testssl"],
    "tls": ["sslyze", "testssl"],
    "certificate": ["sslyze", "testssl", "crtsh"],
    
    # Linux specific
    "linux": ["linpeas", "linux-smart-enumeration", "linux-exploit-suggester", "unix-privesc-check", "pspy"],
    "cron": ["pspy"],
    "suid": ["linpeas", "linux-smart-enumeration"],
    
    # Windows specific  
    "windows": ["winpeas", "windows-exploit-suggester", "mimikatz", "powersploit", "evil-winrm"],
    "powershell": ["powersploit", "poshc2", "empire"],
    "winrm": ["evil-winrm"],
    "registry": ["registry-scanner", "winpeas"],
}

# Tutorial-specific tool mappings (for tutorials that need specific tools)
TUTORIAL_SPECIFIC_TOOLS = {
    "linux_basics_for_hackers": {
        "file_operations": [],
        "wildcards_pipes": [],
        "networking_interfaces": ["nmap", "tcpdump", "wireshark"],
        "essential_commands": ["linpeas", "pspy"],
    },
    "networking_fundamentals": {
        "*": ["nmap", "wireshark", "tcpdump", "masscan"],
    },
    "wifi_security_attacks": {
        "*": ["aircrack-ng", "wifite", "bettercap", "reaver", "bully", "kismet"],
    },
    "password_cracking_techniques": {
        "*": ["hashcat", "john", "hydra", "crunch", "cewl", "hashid"],
    },
    "python_penetration_testing": {
        "*": ["metasploit", "burpsuite", "nmap"],
    },
    "reverse_shells_guide": {
        "*": ["metasploit", "pwncat", "weevely", "chisel", "ligolo-ng"],
    },
    "file_security_practices": {
        "*": ["steghide", "exiftool", "binwalk", "foremost"],
    },
    "reconnaissance": {
        "*": ["amass", "theHarvester", "recon-ng", "maltego", "shodan-cli", "spiderfoot"],
    },
    "advanced_reconnaissance_techniques": {
        "*": ["amass", "sublist3r", "gobuster", "ffuf", "censys-api", "crtsh"],
    },
    "vulnerability_analysis": {
        "*": ["nmap", "nikto", "nuclei", "searchsploit", "trivy"],
    },
    "exploitation": {
        "*": ["metasploit", "searchsploit", "burpsuite", "sqlmap"],
    },
    "post_exploitation": {
        "*": ["linpeas", "winpeas", "mimikatz", "bloodhound-python", "pspy"],
    },
    "linux_ctf": {
        "*": ["linpeas", "pspy", "nmap", "gobuster", "searchsploit"],
    },
    "windows_ctf": {
        "*": ["winpeas", "mimikatz", "bloodhound-python", "evil-winrm", "powersploit"],
    },
    "cloud_iam": {
        "*": ["awscli", "azcli", "gcloud", "pacu", "cloud-iam-enum"],
    },
    "practical_oauth": {
        "*": ["burpsuite", "sso-oauth-oidc-misconfig-playbook", "federation-attack-scenarios"],
    },
    "sso_federation": {
        "*": ["sso-oauth-oidc-misconfig-playbook", "federation-attack-scenarios", "burpsuite"],
    },
    "api_security": {
        "*": ["burp-api-scanner", "postman", "ffuf-api", "graphqlmap", "openapi-scanner"],
    },
    "modern_web": {
        "*": ["burpsuite", "owasp-zap", "nikto", "wappalyzer", "nuclei"],
    },
    "container_security": {
        "*": ["docker", "trivy", "clair", "grype", "falco"],
    },
    "serverless_security": {
        "*": ["serverless-framework", "aws-sam-cli", "prowler", "scoutsuite"],
    },
    "cloud_native": {
        "*": ["kubectl", "kube-bench", "kubeaudit", "kube-hunter", "helm", "trivy"],
    },
    "supply_chain": {
        "*": ["trufflehog", "snyk", "dependency-check", "semgrep", "grype"],
    },
    "red_team_tradecraft": {
        "*": ["empire", "sliver", "caldera", "edr-opsec-checklist", "poshc2"],
    },
    "purple_team_threat_hunting": {
        "*": ["sigma", "yara", "caldera", "workflow_threat_hunting_lifecycle"],
    },
    "bug_bounty_hunting": {
        "*": ["burpsuite", "nuclei", "ffuf", "amass", "bugbounty_web_app_testing"],
    },
    "reporting": {
        "*": ["dradis", "faraday", "bugbounty_reporting_cvss"],
    },
    "comptia_secplus": {
        "*": ["nmap", "wireshark", "burpsuite"],
    },
    "pentest_exam": {
        "*": ["nmap", "metasploit", "burpsuite", "linpeas", "winpeas"],
    },
    "ceh": {
        "*": ["nmap", "metasploit", "burpsuite", "wireshark", "sqlmap"],
    },
}


def extract_tools_from_content(content: str, step_id: str, tutorial_id: str) -> List[str]:
    """Extract relevant tools based on content keywords."""
    content_lower = content.lower()
    tools: Set[str] = set()
    
    # Check tutorial-specific mappings first
    if tutorial_id in TUTORIAL_SPECIFIC_TOOLS:
        tutorial_tools = TUTORIAL_SPECIFIC_TOOLS[tutorial_id]
        if step_id in tutorial_tools:
            tools.update(tutorial_tools[step_id])
        elif "*" in tutorial_tools:
            tools.update(tutorial_tools["*"])
    
    # Then check keyword mappings
    for keyword, tool_list in KEYWORD_TOOL_MAP.items():
        if keyword in content_lower:
            for tool in tool_list:
                if tool in VALID_TOOL_IDS:
                    tools.add(tool)
    
    # Limit to 5 most relevant tools (prioritize exact matches)
    tool_list = list(tools)
    
    # Score tools by relevance (how many times related keywords appear)
    tool_scores = {}
    for tool in tool_list:
        score = 0
        tool_lower = tool.lower().replace("-", " ").replace("_", " ")
        for part in tool_lower.split():
            if part in content_lower:
                score += content_lower.count(part)
        tool_scores[tool] = score
    
    # Sort by score and return top 5
    sorted_tools = sorted(tool_list, key=lambda t: tool_scores.get(t, 0), reverse=True)
    return sorted_tools[:5]


def process_tutorial_file(filepath: Path) -> bool:
    """Process a single tutorial JSON file and add related_tools."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        tutorial_id = data.get('id', filepath.stem)
        modified = False
        
        for step in data.get('steps', []):
            # Skip if step already has related_tools with content
            if step.get('related_tools') and len(step['related_tools']) > 0:
                continue
            
            step_id = step.get('id', '')
            content = step.get('content', '')
            title = step.get('title', '')
            tags = step.get('tags', [])
            
            # Combine content for analysis
            full_content = f"{title} {content} {' '.join(tags)}"
            
            # Extract tools
            tools = extract_tools_from_content(full_content, step_id, tutorial_id)
            
            if tools:
                step['related_tools'] = tools
                modified = True
            else:
                # Ensure empty list exists
                if 'related_tools' not in step:
                    step['related_tools'] = []
                    modified = True
        
        if modified:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        
        return False
    
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False


def main():
    """Process all tutorial JSON files."""
    tutorials_dir = Path("data/tutorials")
    
    if not tutorials_dir.exists():
        print(f"Error: {tutorials_dir} not found")
        return
    
    json_files = list(tutorials_dir.glob("*.json"))
    print(f"Found {len(json_files)} tutorial files")
    
    modified_count = 0
    for filepath in sorted(json_files):
        if process_tutorial_file(filepath):
            print(f"✓ Modified: {filepath.name}")
            modified_count += 1
        else:
            print(f"  Skipped: {filepath.name} (already has tools or no matches)")
    
    print(f"\nModified {modified_count} of {len(json_files)} files")


if __name__ == "__main__":
    main()
