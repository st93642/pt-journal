// pub mod ai_security; // Now loaded from JSON
// pub mod bug_bounty_hunting; // Now loaded from JSON
// pub mod ceh; // Now loaded from JSON
// pub mod cloud_identity; // Now loaded from JSON
// pub mod cloud_native; // Now loaded from JSON
// pub mod comptia_secplus; // Now loaded from JSON
// pub mod container_security; // Now loaded from JSON
// pub mod modern_web; // Now loaded from JSON
// pub mod pentest_exam; // Now loaded from JSON
// pub mod post_exploitation; // Now loaded from JSON
// pub mod purple_team_threat_hunting; // Now loaded from JSON
// pub mod reconnaissance; // Now loaded from JSON
// pub mod red_team_tradecraft; // Now loaded from JSON
// pub mod serverless_security; // Now loaded from JSON
// pub mod supply_chain; // Now loaded from JSON
// pub mod vulnerability_analysis; // Now loaded from JSON

use crate::model::{Phase, Step};
use serde::{Deserialize, Serialize};
use std::fs;
use uuid::Uuid;

/// JSON structure for tutorial data loaded from files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TutorialData {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub r#type: String,
    pub steps: Vec<TutorialStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TutorialStep {
    pub id: String,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
    #[serde(default)]
    pub related_tools: Vec<String>,
}

/// Load all tutorial phases with their default content
/// Phases are ordered to reflect real-world penetration testing workflow:
/// 1. Foundational skills (Linux, networking, Python)
/// 2. Core pentesting methodology (reconnaissance through exploitation)
/// 3. CTF practical labs
/// 4. Cyber Threat Intelligence & Digital Forensics (from Practical Cyber Intelligence book)
/// 5. Modern security topics (cloud, web, containers)
/// 6. Advanced techniques (red team, bug bounty, supply chain)
/// 7. Quiz-based certification preparation (at the end)
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
        // SECTION 2: Core PT Methodology (positions 8-17)
        // ============================================
        load_tutorial_phase("reconnaissance"),
        load_tutorial_phase("advanced_reconnaissance_techniques"),
        load_tutorial_phase("vulnerability_analysis"),
        load_tutorial_phase("advanced-web-app-security-fundamentals"),
        load_tutorial_phase("cross-site-scripting-xss-exploitation-prevention"),
        load_tutorial_phase("authentication-authorization-vulnerabilities"),
        load_tutorial_phase("injection-vulnerabilities-deep-dive"),
        load_tutorial_phase("server-side-attacks-csrf-ssrf-file-inclusion"),
        load_tutorial_phase("exploitation"),
        load_tutorial_phase("post_exploitation"),
        // ============================================
        // SECTION 3: CTF Practical Labs (positions 18-19)
        // ============================================
        load_tutorial_phase("linux_ctf"),
        load_tutorial_phase("windows_ctf"),
        // ============================================
        // SECTION 4: Cyber Threat Intelligence & Forensics (positions 20-28)
        // Based on Practical Cyber Intelligence book curriculum
        // ============================================
        load_tutorial_phase("cyber_threat_intelligence_fundamentals"),
        load_tutorial_phase("digital_forensics_methodology"),
        load_tutorial_phase("disk_forensics_analysis"),
        load_tutorial_phase("memory_forensics_analysis"),
        load_tutorial_phase("sqlite_forensics"),
        load_tutorial_phase("windows_forensics_deep_dive"),
        load_tutorial_phase("network_forensics_fundamentals"),
        load_tutorial_phase("macos_forensics"),
        load_tutorial_phase("incident_response_methodology"),
        // ============================================
        // SECTION 5: Modern Security Topics (positions 29-36)
        // ============================================
        load_tutorial_phase("cloud_iam"),
        load_tutorial_phase("practical_oauth"),
        load_tutorial_phase("sso_federation"),
        load_tutorial_phase("api_security"),
        load_tutorial_phase("modern_web"),
        load_tutorial_phase("container_security"),
        load_tutorial_phase("serverless_security"),
        load_tutorial_phase("cloud_native"),
        // ============================================
        // SECTION 6: Advanced Topics (positions 37-41)
        // ============================================
        load_tutorial_phase("supply_chain"),
        load_tutorial_phase("red_team_tradecraft"),
        load_tutorial_phase("purple_team_threat_hunting"),
        load_tutorial_phase("bug_bounty_hunting"),
        // ============================================
        // SECTION 7: AI-Augmented Penetration Testing (positions 42-50)
        // Modern AI security content covering OWASP LLM Top 10 2025,
        // MITRE ATLAS framework, and AI-enhanced pentesting techniques
        // ============================================
        load_tutorial_phase("traditional-vs-ai-pentesting-foundations"),
        load_tutorial_phase("building-modern-pt-lab-genai"),
        load_tutorial_phase("genai-driven-reconnaissance"),
        load_tutorial_phase("ai-enhanced-scanning-sniffing"),
        load_tutorial_phase("vulnerability-assessment-ai"),
        load_tutorial_phase("ai-driven-social-engineering"),
        load_tutorial_phase("genai-driven-exploitation"),
        load_tutorial_phase("post-exploitation-privilege-escalation-ai"),
        load_tutorial_phase("automating-pt-reports-genai"),
        // ============================================
        // SECTION 8: Reporting (position 51)
        // ============================================
        load_tutorial_phase("reporting"),
        // ============================================
        // SECTION 9: SOC Operations & Blue Team (positions 52-56)
        // Security Operations Center tools, SIEM platforms, detection
        // engineering, and incident response workflows
        // ============================================
        load_tutorial_phase("splunk_soc_fundamentals"),
        load_tutorial_phase("elastic_siem_security"),
        load_tutorial_phase("wazuh_xdr_siem"),
        load_tutorial_phase("sigma_detection_rules"),
        load_tutorial_phase("soc_incident_response_workflow"),
        // ============================================
        // SECTION 10: Certification Preparation (positions 57-67)
        // ============================================
        load_tutorial_phase("comptia_secplus"),
        load_tutorial_phase("pentest_exam"),
        load_tutorial_phase("ceh"),
        load_tutorial_phase("cissp-domain-1"),
        load_tutorial_phase("cissp-domain-2"),
        load_tutorial_phase("cissp-domain-3"),
        load_tutorial_phase("cissp-domain-4"),
        load_tutorial_phase("cissp-domain-5"),
        load_tutorial_phase("cissp-domain-6"),
        load_tutorial_phase("cissp-domain-7"),
        load_tutorial_phase("cissp-domain-8"),
    ]
}

/// Load quiz questions from a file
fn load_quiz_from_file(file_path: &str) -> Result<Vec<crate::model::QuizQuestion>, String> {
    // Construct path relative to data directory
    let full_path = format!("data/{}", file_path);

    // Read file content
    let content = fs::read_to_string(&full_path)
        .map_err(|e| format!("Failed to read quiz file {}: {}", full_path, e))?;

    // Parse questions
    crate::quiz::parse_question_file(&content)
        .map_err(|e| format!("Failed to parse questions from {}: {}", full_path, e))
}

/// Load a tutorial phase from JSON file
fn load_tutorial_phase(phase_name: &str) -> Phase {
    let json_path = format!("data/tutorials/{}.json", phase_name);
    match fs::read_to_string(&json_path) {
        Ok(content) => {
            match serde_json::from_str::<TutorialData>(&content) {
                Ok(tutorial_data) => {
                    let steps = tutorial_data
                        .steps
                        .into_iter()
                        .map(|step_data| {
                            // Check if this is a quiz step
                            if step_data.tags.contains(&"quiz".to_string()) {
                                // For quiz steps, load the quiz data from the referenced file
                                // The content field contains the path to the quiz file
                                if step_data.content.starts_with("Quiz content loaded from ") {
                                    let quiz_file_path = step_data
                                        .content
                                        .strip_prefix("Quiz content loaded from ")
                                        .unwrap_or(&step_data.content);

                                    match load_quiz_from_file(quiz_file_path) {
                                        Ok(questions) => {
                                            let quiz_step = crate::model::QuizStep::new(
                                                Uuid::new_v4(),
                                                step_data.title.clone(),
                                                phase_name.to_string(),
                                                questions,
                                            );
                                            Step::new_quiz(
                                                Uuid::new_v4(),
                                                step_data.title,
                                                step_data.tags,
                                                quiz_step,
                                            )
                                        }
                                        Err(_e) => {
                                            // Fallback to tutorial step
                                            Step::new_tutorial_with_tools(
                                                Uuid::new_v4(),
                                                step_data.title,
                                                format!("Error loading quiz: {}", _e),
                                                step_data.tags,
                                                step_data.related_tools,
                                            )
                                        }
                                    }
                                } else {
                                    // Fallback to tutorial step if content doesn't reference a file
                                    Step::new_tutorial_with_tools(
                                        Uuid::new_v4(),
                                        step_data.title,
                                        step_data.content,
                                        step_data.tags,
                                        step_data.related_tools,
                                    )
                                }
                            } else {
                                // Regular tutorial step
                                Step::new_tutorial_with_tools(
                                    Uuid::new_v4(),
                                    step_data.title,
                                    step_data.content,
                                    step_data.tags,
                                    step_data.related_tools,
                                )
                            }
                        })
                        .collect();

                    Phase {
                        id: Uuid::new_v4(),
                        name: tutorial_data.title,
                        steps,
                    }
                }
                Err(_e) => {
                    // Fallback to empty phase
                    Phase {
                        id: Uuid::new_v4(),
                        name: phase_name.to_string(),
                        steps: Vec::new(),
                    }
                }
            }
        }
        Err(_e) => {
            // Fallback to empty phase
            Phase {
                id: Uuid::new_v4(),
                name: phase_name.to_string(),
                steps: Vec::new(),
            }
        }
    }
}

/// Validate tutorial structure consistency across all modules
/// This function validates all phases that are loaded by load_tutorial_phases()
pub fn validate_tutorial_structure() -> Result<(), String> {
    // Define all phase IDs that should be validated (matches load_tutorial_phases order)
    let phase_ids = vec![
        // Section 1: Foundational Skills
        "linux_basics_for_hackers",
        "networking_fundamentals",
        "wifi_security_attacks",
        "password_cracking_techniques",
        "python_penetration_testing",
        "reverse_shells_guide",
        "file_security_practices",
        // Section 2: Core PT Methodology
        "reconnaissance",
        "advanced_reconnaissance_techniques",
        "vulnerability_analysis",
        "advanced-web-app-security-fundamentals",
        "cross-site-scripting-xss-exploitation-prevention",
        "authentication-authorization-vulnerabilities",
        "injection-vulnerabilities-deep-dive",
        "server-side-attacks-csrf-ssrf-file-inclusion",
        "exploitation",
        "post_exploitation",
        // Section 3: CTF Practical Labs
        "linux_ctf",
        "windows_ctf",
        // Section 4: Cyber Threat Intelligence & Forensics (from Practical Cyber Intelligence book)
        "cyber_threat_intelligence_fundamentals",
        "digital_forensics_methodology",
        "disk_forensics_analysis",
        "memory_forensics_analysis",
        "sqlite_forensics",
        "windows_forensics_deep_dive",
        "network_forensics_fundamentals",
        "macos_forensics",
        "incident_response_methodology",
        // Section 5: Modern Security Topics
        "cloud_iam",
        "practical_oauth",
        "sso_federation",
        "api_security",
        "modern_web",
        "container_security",
        "serverless_security",
        "cloud_native",
        // Section 6: Advanced Topics
        "supply_chain",
        "red_team_tradecraft",
        "purple_team_threat_hunting",
        "bug_bounty_hunting",
        // Section 7: AI-Augmented Penetration Testing
        "traditional-vs-ai-pentesting-foundations",
        "building-modern-pt-lab-genai",
        "genai-driven-reconnaissance",
        "ai-enhanced-scanning-sniffing",
        "vulnerability-assessment-ai",
        "ai-driven-social-engineering",
        "genai-driven-exploitation",
        "post-exploitation-privilege-escalation-ai",
        "automating-pt-reports-genai",
        // Section 8: Reporting
        "reporting",
        // Section 9: SOC Operations & Blue Team
        "splunk_soc_fundamentals",
        "elastic_siem_security",
        "wazuh_xdr_siem",
        "sigma_detection_rules",
        "soc_incident_response_workflow",
        // Section 10: Certification Preparation
        "comptia_secplus",
        "pentest_exam",
        "ceh",
        "cissp-domain-1",
        "cissp-domain-2",
        "cissp-domain-3",
        "cissp-domain-4",
        "cissp-domain-5",
        "cissp-domain-6",
        "cissp-domain-7",
        "cissp-domain-8",
    ];

    // Validate each phase
    for phase_id in &phase_ids {
        let phase = load_tutorial_phase(phase_id);
        validate_step_structure(&phase.steps, phase_id)?;

        // Check that module has at least one step
        if phase.steps.is_empty() {
            return Err(format!("{} module has no steps", phase_id));
        }
    }

    Ok(())
}

/// Validate the structure of tutorial steps
fn validate_step_structure(steps: &[Step], module_name: &str) -> Result<(), String> {
    for (index, step) in steps.iter().enumerate() {
        // Check that step has a non-empty title
        if step.title.trim().is_empty() {
            return Err(format!("{}: Step {} has empty title", module_name, index));
        }

        // Check that step has a description (tutorial steps only)
        if step.is_tutorial() && step.description.trim().is_empty() {
            return Err(format!(
                "{}: Step '{}' has empty description",
                module_name, step.title
            ));
        }

        // Check that step has appropriate tags
        if step.tags.is_empty() {
            return Err(format!(
                "{}: Step '{}' has no tags",
                module_name, step.title
            ));
        }

        // Check that tags follow naming conventions (lowercase, hyphens)
        for tag in &step.tags {
            if tag.contains(' ') {
                return Err(format!(
                    "{}: Step '{}' has tag with spaces: '{}'",
                    module_name, step.title, tag
                ));
            }
            if tag.chars().any(|c| c.is_uppercase()) {
                return Err(format!(
                    "{}: Step '{}' has tag with uppercase: '{}'",
                    module_name, step.title, tag
                ));
            }
        }

        // Check that step has a valid UUID
        if step.id.to_string().len() != 36 {
            return Err(format!(
                "{}: Step '{}' has invalid UUID",
                module_name, step.title
            ));
        }

        // Validate related_tools - check if all referenced tool IDs exist
        for tool_id in &step.related_tools {
            if !crate::ui::tool_instructions::has_tool(tool_id) {
                return Err(format!(
                    "{}: Step '{}' references non-existent tool ID: '{}'",
                    module_name, step.title, tool_id
                ));
            }
        }
    }

    Ok(())
}
