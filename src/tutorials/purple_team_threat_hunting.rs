/// Purple Team/Threat Hunting tutorial module
///
/// This module provides structured step tuples for detection validation, logging assessment,
/// and threat hunting for credential theft, cloud control plane abuse, and web shells.
use crate::model::Step;
use uuid::Uuid;

/// Purple Team/Threat Hunting steps
pub const PURPLE_TEAM_STEPS: &[(&str, &str)] = &[
    ("Detection & Logging Validation", "OBJECTIVE: Assess and validate security control effectiveness\n\nSTEP-BY-STEP PROCESS:\n1. Review SIEM/log aggregation configurations\n2. Test detection rule coverage and accuracy\n3. Validate alert generation and response workflows\n\nWHAT TO LOOK FOR:\n- Log source completeness\n- Detection rule gaps\n- Alert fatigue indicators"),
    ("Credential Theft Hunting", "OBJECTIVE: Hunt for credential access and theft activities\n\nSTEP-BY-STEP PROCESS:\n1. Monitor for LSASS access patterns\n2. Detect pass-the-hash/token manipulation\n3. Identify Kerberoasting and ASREPRoasting attempts\n\nWHAT TO LOOK FOR:\n- Memory dumping artifacts\n- Authentication anomalies\n- Ticket request patterns"),
    ("Cloud Control Plane Abuse Detection", "OBJECTIVE: Identify cloud infrastructure manipulation\n\nSTEP-BY-STEP PROCESS:\n1. Monitor IAM policy changes and privilege escalation\n2. Detect resource creation/abuse patterns\n3. Identify data exfiltration via cloud services\n\nWHAT TO LOOK FOR:\n- Unusual API calls\n- Resource creation spikes\n- Cross-account access"),
    ("Web Shell Detection & Response", "OBJECTIVE: Find and remediate web shell deployments\n\nSTEP-BY-STEP PROCESS:\n1. Scan for anomalous web files and scripts\n2. Monitor for command execution patterns\n3. Validate file integrity and permissions\n\nWHAT TO LOOK FOR:\n- Unexpected file modifications\n- Command execution from web processes\n- Network beaconing"),
    ("Log Analysis Fundamentals", "OBJECTIVE: Master log analysis for threat detection\n\nSTEP-BY-STEP PROCESS:\n1. Understand log formats and sources\n2. Implement log parsing and correlation\n3. Create hunting hypotheses and queries\n\nWHAT TO LOOK FOR:\n- Log parsing errors\n- Correlation rule effectiveness\n- Query performance issues"),
    ("Sigma Rule Development", "OBJECTIVE: Create and test Sigma detection rules\n\nSTEP-BY-STEP PROCESS:\n1. Map threat behaviors to Sigma format\n2. Test rules against log samples\n3. Deploy and monitor rule effectiveness\n\nWHAT TO LOOK FOR:\n- Rule syntax errors\n- False positive rates\n- Detection coverage gaps"),
    ("YARA Signature Creation", "OBJECTIVE: Develop YARA rules for file-based hunting\n\nSTEP-BY-STEP PROCESS:\n1. Analyze malware samples and IOCs\n2. Create YARA signatures with conditions\n3. Test and refine rules against datasets\n\nWHAT TO LOOK FOR:\n- Signature collision issues\n- Performance impact\n- Detection accuracy"),
    ("Network Traffic Analysis", "OBJECTIVE: Hunt threats through network telemetry\n\nSTEP-BY-STEP PROCESS:\n1. Analyze flow logs and packet captures\n2. Identify anomalous communication patterns\n3. Correlate network and host indicators\n\nWHAT TO LOOK FOR:\n- Unusual port usage\n- Data exfiltration attempts\n- C2 communication"),
    ("Endpoint Detection Validation", "OBJECTIVE: Test and improve EDR effectiveness\n\nSTEP-BY-STEP PROCESS:\n1. Execute known techniques against EDR\n2. Monitor detection and response\n3. Tune rules and reduce false positives\n\nWHAT TO LOOK FOR:\n- Detection gaps\n- Alert quality issues\n- Response effectiveness"),
    ("Threat Hunting Methodology", "OBJECTIVE: Implement structured threat hunting programs\n\nSTEP-BY-STEP PROCESS:\n1. Define hunting hypotheses and triggers\n2. Execute hunts using multiple data sources\n3. Document findings and improve detections\n\nWHAT TO LOOK FOR:\n- Hypothesis validation\n- Data source coverage\n- Process improvement opportunities")
];

/// Create tutorial steps for Purple Team/Threat Hunting
pub fn create_purple_team_steps() -> Vec<Step> {
    PURPLE_TEAM_STEPS
        .iter()
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec![
                    "purple".to_string(),
                    "threat-hunting".to_string(),
                    "detection".to_string(),
                ],
            )
        })
        .collect()
}
