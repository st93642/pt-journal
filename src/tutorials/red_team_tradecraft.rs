/// Red Team Tradecraft tutorial module
///
/// This module provides structured step tuples for EDR-aware testing and ATT&CK-mapped adversary emulation.
/// Covers operational security, detection avoidance, and realistic threat actor behaviors.
use crate::model::Step;
use uuid::Uuid;

/// Red Team Tradecraft steps
pub const RED_TEAM_STEPS: &[(&str, &str)] = &[
    ("EDR Evasion Fundamentals", "OBJECTIVE: Understand EDR detection surfaces and basic evasion techniques\n\nSTEP-BY-STEP PROCESS:\n1. Identify EDR products (CrowdStrike, Defender ATP, Carbon Black)\n2. Map detection capabilities (process injection, fileless malware, network beacons)\n3. Implement basic evasion (obfuscation, living-off-the-land)\n\nWHAT TO LOOK FOR:\n- EDR agent processes and services\n- Telemetry collection points\n- Behavioral analysis triggers"),
    ("Living Off The Land (LotL)", "OBJECTIVE: Use native system tools to avoid custom malware detection\n\nSTEP-BY-STEP PROCESS:\n1. Enumerate built-in tools (PowerShell, WMI, BITS, COM objects)\n2. Chain native commands for persistence and lateral movement\n3. Avoid dropping files when possible\n\nWHAT TO LOOK FOR:\n- Suspicious command-line arguments\n- Unusual process parent-child relationships\n- Native tool abuse patterns"),
    ("Fileless Malware Techniques", "OBJECTIVE: Execute code without touching disk to evade file-based detection\n\nSTEP-BY-STEP PROCESS:\n1. Use PowerShell reflection and memory-only execution\n2. Implement process injection (APC, thread hijacking)\n3. Leverage script engines (JScript, VBScript) for execution\n\nWHAT TO LOOK FOR:\n- Memory-resident code artifacts\n- Reflective loading indicators\n- Script engine abuse"),
    ("Command & Control (C2) Obfuscation", "OBJECTIVE: Hide C2 communications from network detection\n\nSTEP-BY-STEP PROCESS:\n1. Implement domain fronting and CDN abuse\n2. Use DNS tunneling and protocol smuggling\n3. Apply traffic encryption and shaping\n\nWHAT TO LOOK FOR:\n- Unusual outbound connections\n- Encrypted traffic patterns\n- DNS query anomalies"),
    ("Credential Access Without Detection", "OBJECTIVE: Harvest credentials while avoiding authentication monitoring\n\nSTEP-BY-STEP PROCESS:\n1. Use LSASS dumping with evasion techniques\n2. Implement pass-the-hash/token theft\n3. Leverage Kerberoasting and ASREPRoasting\n\nWHAT TO LOOK FOR:\n- Memory access patterns\n- Authentication anomalies\n- Ticket manipulation indicators"),
    ("Lateral Movement Tradecraft", "OBJECTIVE: Move through networks using EDR-aware techniques\n\nSTEP-BY-STEP PROCESS:\n1. Use WMI and PowerShell remoting\n2. Implement DCOM/RPC abuse\n3. Leverage RDP and VNC with session hijacking\n\nWHAT TO LOOK FOR:\n- Remote execution artifacts\n- Network session anomalies\n- Administrative tool abuse"),
    ("Persistence Mechanisms", "OBJECTIVE: Maintain access using hard-to-detect persistence methods\n\nSTEP-BY-STEP PROCESS:\n1. Implement scheduled task abuse\n2. Use registry autoruns with camouflage\n3. Create service backdoors with legitimate names\n\nWHAT TO LOOK FOR:\n- Startup modification indicators\n- Service creation events\n- Registry key changes"),
    ("Data Exfiltration Techniques", "OBJECTIVE: Extract data without triggering DLP or network monitoring\n\nSTEP-BY-STEP PROCESS:\n1. Use DNS exfiltration and covert channels\n2. Implement chunked transfers with encryption\n3. Leverage cloud storage abuse\n\nWHAT TO LOOK FOR:\n- Unusual data flows\n- Encrypted outbound traffic\n- Cloud service anomalies"),
    ("Anti-Forensic Measures", "OBJECTIVE: Cover tracks and avoid forensic detection\n\nSTEP-BY-STEP PROCESS:\n1. Implement log manipulation and clearing\n2. Use timestomping and artifact removal\n3. Deploy anti-forensic tools\n\nWHAT TO LOOK FOR:\n- Log modification events\n- File timestamp changes\n- Evidence destruction indicators"),
    ("ATT&CK Framework Mapping", "OBJECTIVE: Structure operations using MITRE ATT&CK for comprehensive coverage\n\nSTEP-BY-STEP PROCESS:\n1. Map tactics (Recon, Initial Access, Execution, etc.)\n2. Select techniques based on target environment\n3. Chain techniques for realistic emulation\n\nWHAT TO LOOK FOR:\n- Technique implementation artifacts\n- Tactic progression indicators\n- Emulation scenario coverage")
];

/// Create tutorial steps for Red Team Tradecraft
pub fn create_red_team_steps() -> Vec<Step> {
    RED_TEAM_STEPS
        .iter()
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec![
                    "redteam".to_string(),
                    "mitre".to_string(),
                    "edr".to_string(),
                ],
            )
        })
        .collect()
}
