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
}

/// Load all tutorial phases with their default content
/// Phases are ordered to reflect real-world penetration testing workflow:
/// 1. Initial reconnaissance and intelligence gathering
/// 2. Core penetration testing methodology
/// 3. Modern security topics (cloud, web, containers, etc.)
/// 4. Advanced techniques (red team, bug bounty, supply chain)
/// 5. Quiz-based certification preparation (at the end)
pub fn load_tutorial_phases() -> Vec<Phase> {
    vec![
        // Phase 1: Linux basics and foundational skills
        load_tutorial_phase("linux_basics_for_hackers"),
        load_tutorial_phase("networking_fundamentals"),
        load_tutorial_phase("wifi_security_attacks"),
        load_tutorial_phase("password_cracking_techniques"),
        load_tutorial_phase("python_penetration_testing"),
        load_tutorial_phase("reverse_shells_guide"),
        load_tutorial_phase("file_security_practices"),
        // Phase 2: Initial reconnaissance (intelligence gathering)
        load_tutorial_phase("reconnaissance"),
        // Phase 2: Foundations of pentesting with AI integration
        load_tutorial_phase("traditional-vs-ai-pentesting-foundations"),
        // Phase 3: Building a modern PT lab with GenAI
        load_tutorial_phase("building-modern-pt-lab-genai"),
        // Phase 4: GenAI-driven reconnaissance techniques
        load_tutorial_phase("genai-driven-reconnaissance"),
        // Phase 5: AI-enhanced scanning and sniffing
        load_tutorial_phase("ai-enhanced-scanning-sniffing"),
        // Phase 6: Vulnerability assessment with AI tools
        load_tutorial_phase("vulnerability-assessment-ai"),
        // Phase 7: AI-driven social engineering attacks
        load_tutorial_phase("ai-driven-social-engineering"),
        // Phase 8: GenAI-driven exploitation techniques
        load_tutorial_phase("genai-driven-exploitation"),
        // Phase 9: Post-exploitation and privilege escalation with AI
        load_tutorial_phase("post-exploitation-privilege-escalation-ai"),
        // Phase 10: Automating penetration testing reports with GenAI
        load_tutorial_phase("automating-pt-reports-genai"),
        // Phase 7: Advanced reconnaissance techniques (AI-powered OSINT, certificates, metadata)
        load_tutorial_phase("advanced_reconnaissance_techniques"),
        // Phase 3-8: Core penetration testing methodology
        load_tutorial_phase("vulnerability_analysis"),
        load_tutorial_phase("advanced-web-app-security-fundamentals"),
        load_tutorial_phase("cross-site-scripting-xss-exploitation-prevention"),
        load_tutorial_phase("authentication-authorization-vulnerabilities"),
        load_tutorial_phase("injection-vulnerabilities-deep-dive"),
        load_tutorial_phase("server-side-attacks-csrf-ssrf-file-inclusion"),
        load_tutorial_phase("exploitation"),
        load_tutorial_phase("post_exploitation"),
        // Phase 8: Linux CTF (practical application of methodology)
        load_tutorial_phase("linux_ctf"),
        // Phase 9: Windows CTF (Windows/AD practical application)
        load_tutorial_phase("windows_ctf"),
        // Phase 10-17: Modern security topics (cloud, identity, web, containers)
        load_tutorial_phase("cloud_iam"),
        load_tutorial_phase("practical_oauth"),
        load_tutorial_phase("sso_federation"),
        load_tutorial_phase("api_security"),
        load_tutorial_phase("modern_web"),
        load_tutorial_phase("container_security"),
        load_tutorial_phase("serverless_security"),
        load_tutorial_phase("cloud_native"),
        // Phase 18-23: Advanced topics (supply chain, AI, RAG, red/purple team)
        load_tutorial_phase("supply_chain"),
        load_tutorial_phase("ai_security"),
        load_tutorial_phase("ai_powered_offensive_security"),
        load_tutorial_phase("retrieval_augmented_generation_red_teaming"),
        load_tutorial_phase("bug_bounty_automation_ai"),
        load_tutorial_phase("red_team_tradecraft"),
        load_tutorial_phase("purple_team_threat_hunting"),
        load_tutorial_phase("bug_bounty_hunting"),
        // Phase 23: Reporting (final documentation phase)
        load_tutorial_phase("reporting"),
        // Phase 24-26: Quiz-based certification preparation (post-testing validation)
        load_tutorial_phase("comptia_secplus"),
        load_tutorial_phase("pentest_exam"),
        load_tutorial_phase("ceh"),
        load_tutorial_phase("cissp-domain-1"),
        load_tutorial_phase("cissp-domain-2"),
        load_tutorial_phase("cissp-domain-3"),
        load_tutorial_phase("cissp-domain-4"),
        load_tutorial_phase("cissp-domain-5"),
        // create_cicd_pipeline_attacks_phase(), // Now part of cloud_native JSON
        // create_sbom_analysis_phase(), // Now part of supply_chain JSON
        // create_dependency_confusion_phase(), // Now part of supply_chain JSON
        // create_artifact_integrity_phase(), // Now part of supply_chain JSON
        // create_red_team_tradecraft_phase(), // Now loaded from JSON
        // create_purple_team_threat_hunting_phase(), // Now loaded from JSON
        // create_ai_security_phase(), // Now loaded from JSON
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
                                            Step::new_tutorial(
                                                Uuid::new_v4(),
                                                step_data.title,
                                                format!("Error loading quiz: {}", _e),
                                                step_data.tags,
                                            )
                                        }
                                    }
                                } else {
                                    // Fallback to tutorial step if content doesn't reference a file
                                    Step::new_tutorial(
                                        Uuid::new_v4(),
                                        step_data.title,
                                        step_data.content,
                                        step_data.tags,
                                    )
                                }
                            } else {
                                // Regular tutorial step
                                Step::new_tutorial(
                                    Uuid::new_v4(),
                                    step_data.title,
                                    step_data.content,
                                    step_data.tags,
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
pub fn validate_tutorial_structure() -> Result<(), String> {
    // Validate Linux basics for hackers module (loaded from JSON)
    let linux_basics_phase = load_tutorial_phase("linux_basics_for_hackers");
    validate_step_structure(&linux_basics_phase.steps, "linux_basics_for_hackers")?;

    // Validate networking fundamentals module (loaded from JSON)
    let networking_fundamentals_phase = load_tutorial_phase("networking_fundamentals");
    validate_step_structure(
        &networking_fundamentals_phase.steps,
        "networking_fundamentals",
    )?;

    // Validate Wi-Fi security attacks module (loaded from JSON)
    let wifi_security_phase = load_tutorial_phase("wifi_security_attacks");
    validate_step_structure(&wifi_security_phase.steps, "wifi_security_attacks")?;

    // Validate password cracking techniques module (loaded from JSON)
    let password_cracking_phase = load_tutorial_phase("password_cracking_techniques");
    validate_step_structure(
        &password_cracking_phase.steps,
        "password_cracking_techniques",
    )?;

    // Validate Python penetration testing module (loaded from JSON)
    let python_penetration_phase = load_tutorial_phase("python_penetration_testing");
    validate_step_structure(
        &python_penetration_phase.steps,
        "python_penetration_testing",
    )?;

    // Validate reverse shells guide module (loaded from JSON)
    let reverse_shells_phase = load_tutorial_phase("reverse_shells_guide");
    validate_step_structure(&reverse_shells_phase.steps, "reverse_shells_guide")?;

    // Validate file security practices module (loaded from JSON)
    let file_security_phase = load_tutorial_phase("file_security_practices");
    validate_step_structure(&file_security_phase.steps, "file_security_practices")?;

    // Validate reconnaissance module (loaded from JSON)
    let recon_phase = load_tutorial_phase("reconnaissance");
    validate_step_structure(&recon_phase.steps, "reconnaissance")?;

    // Validate traditional vs AI pentesting foundations module (loaded from JSON)
    let foundations_phase = load_tutorial_phase("traditional-vs-ai-pentesting-foundations");
    validate_step_structure(
        &foundations_phase.steps,
        "traditional-vs-ai-pentesting-foundations",
    )?;

    // Validate building modern PT lab with GenAI module (loaded from JSON)
    let lab_phase = load_tutorial_phase("building-modern-pt-lab-genai");
    validate_step_structure(&lab_phase.steps, "building-modern-pt-lab-genai")?;

    // Validate GenAI-driven reconnaissance module (loaded from JSON)
    let genai_recon_phase = load_tutorial_phase("genai-driven-reconnaissance");
    validate_step_structure(&genai_recon_phase.steps, "genai-driven-reconnaissance")?;

    // Validate AI-enhanced scanning and sniffing module (loaded from JSON)
    let scanning_phase = load_tutorial_phase("ai-enhanced-scanning-sniffing");
    validate_step_structure(&scanning_phase.steps, "ai-enhanced-scanning-sniffing")?;

    // Validate vulnerability assessment with AI module (loaded from JSON)
    let vuln_ai_phase = load_tutorial_phase("vulnerability-assessment-ai");
    validate_step_structure(&vuln_ai_phase.steps, "vulnerability-assessment-ai")?;

    // Validate AI-driven social engineering module (loaded from JSON)
    let social_engineering_phase = load_tutorial_phase("ai-driven-social-engineering");
    validate_step_structure(
        &social_engineering_phase.steps,
        "ai-driven-social-engineering",
    )?;

    // Validate GenAI-driven exploitation module (loaded from JSON)
    let exploitation_phase = load_tutorial_phase("genai-driven-exploitation");
    validate_step_structure(&exploitation_phase.steps, "genai-driven-exploitation")?;

    // Validate post-exploitation and privilege escalation with AI module (loaded from JSON)
    let post_exploitation_phase = load_tutorial_phase("post-exploitation-privilege-escalation-ai");
    validate_step_structure(
        &post_exploitation_phase.steps,
        "post-exploitation-privilege-escalation-ai",
    )?;

    // Validate automating PT reports with GenAI module (loaded from JSON)
    let reports_phase = load_tutorial_phase("automating-pt-reports-genai");
    validate_step_structure(&reports_phase.steps, "automating-pt-reports-genai")?;

    // Validate advanced reconnaissance techniques module (loaded from JSON)
    let advanced_recon_phase = load_tutorial_phase("advanced_reconnaissance_techniques");
    validate_step_structure(
        &advanced_recon_phase.steps,
        "advanced_reconnaissance_techniques",
    )?;

    // Validate vulnerability analysis module (loaded from JSON)
    let vuln_analysis_phase = load_tutorial_phase("vulnerability_analysis");
    validate_step_structure(&vuln_analysis_phase.steps, "vulnerability_analysis")?;

    // Validate advanced web app security fundamentals module (loaded from JSON)
    let advanced_web_phase = load_tutorial_phase("advanced-web-app-security-fundamentals");
    validate_step_structure(
        &advanced_web_phase.steps,
        "advanced-web-app-security-fundamentals",
    )?;

    // Validate cross-site scripting module (loaded from JSON)
    let xss_phase = load_tutorial_phase("cross-site-scripting-xss-exploitation-prevention");
    validate_step_structure(
        &xss_phase.steps,
        "cross-site-scripting-xss-exploitation-prevention",
    )?;

    // Validate authentication and authorization vulnerabilities module (loaded from JSON)
    let auth_phase = load_tutorial_phase("authentication-authorization-vulnerabilities");
    validate_step_structure(
        &auth_phase.steps,
        "authentication-authorization-vulnerabilities",
    )?;

    // Validate injection vulnerabilities deep dive module (loaded from JSON)
    let injection_phase = load_tutorial_phase("injection-vulnerabilities-deep-dive");
    validate_step_structure(
        &injection_phase.steps,
        "injection-vulnerabilities-deep-dive",
    )?;

    // Validate server-side attacks module (loaded from JSON)
    let server_side_attacks_phase =
        load_tutorial_phase("server-side-attacks-csrf-ssrf-file-inclusion");
    validate_step_structure(
        &server_side_attacks_phase.steps,
        "server-side-attacks-csrf-ssrf-file-inclusion",
    )?;

    // Validate exploitation module (loaded from JSON)
    let exploit_phase = load_tutorial_phase("exploitation");
    validate_step_structure(&exploit_phase.steps, "exploitation")?;

    // Validate post-exploitation module (loaded from JSON)
    let post_phase = load_tutorial_phase("post_exploitation");
    validate_step_structure(&post_phase.steps, "post_exploitation")?;

    // Validate Linux CTF module (loaded from JSON)
    let linux_ctf_phase = load_tutorial_phase("linux_ctf");
    validate_step_structure(&linux_ctf_phase.steps, "linux_ctf")?;

    // Validate Windows CTF module (loaded from JSON)
    let windows_ctf_phase = load_tutorial_phase("windows_ctf");
    validate_step_structure(&windows_ctf_phase.steps, "windows_ctf")?;

    // Validate cloud IAM module (loaded from JSON)
    let cloud_iam_phase = load_tutorial_phase("cloud_iam");
    validate_step_structure(&cloud_iam_phase.steps, "cloud_iam")?;

    // Validate practical OAuth module (loaded from JSON)
    let oauth_phase = load_tutorial_phase("practical_oauth");
    validate_step_structure(&oauth_phase.steps, "practical_oauth")?;

    // Validate SSO federation module (loaded from JSON)
    let federation_phase = load_tutorial_phase("sso_federation");
    validate_step_structure(&federation_phase.steps, "sso_federation")?;

    // Validate API security module (loaded from JSON)
    let api_security_phase = load_tutorial_phase("api_security");
    validate_step_structure(&api_security_phase.steps, "api_security")?;

    // Validate reporting module (loaded from JSON)
    let reporting_phase = load_tutorial_phase("reporting");
    validate_step_structure(&reporting_phase.steps, "reporting")?;

    // Validate container security module (loaded from JSON)
    let container_security_phase = load_tutorial_phase("container_security");
    validate_step_structure(&container_security_phase.steps, "container_security")?;

    // Validate serverless security module (loaded from JSON)
    let serverless_security_phase = load_tutorial_phase("serverless_security");
    validate_step_structure(&serverless_security_phase.steps, "serverless_security")?;

    // Validate bug bounty hunting module (loaded from JSON)
    let bug_bounty_hunting_phase = load_tutorial_phase("bug_bounty_hunting");
    validate_step_structure(&bug_bounty_hunting_phase.steps, "bug_bounty_hunting")?;

    // Validate CompTIA Security+ module (loaded from JSON)
    let comptia_secplus_phase = load_tutorial_phase("comptia_secplus");
    validate_step_structure(&comptia_secplus_phase.steps, "comptia_secplus")?;

    // Validate PenTest+ module (loaded from JSON)
    let pentest_exam_phase = load_tutorial_phase("pentest_exam");
    validate_step_structure(&pentest_exam_phase.steps, "pentest_exam")?;

    // Validate CEH module (loaded from JSON)
    let ceh_phase = load_tutorial_phase("ceh");
    validate_step_structure(&ceh_phase.steps, "ceh")?;

    // Validate CISSP Domain 1 module (loaded from JSON)
    let cissp_domain_1_phase = load_tutorial_phase("cissp-domain-1");
    validate_step_structure(&cissp_domain_1_phase.steps, "cissp-domain-1")?;

    // Validate CISSP Domain 2 module (loaded from JSON)
    let cissp_domain_2_phase = load_tutorial_phase("cissp-domain-2");
    validate_step_structure(&cissp_domain_2_phase.steps, "cissp-domain-2")?;

    // Validate CISSP Domain 3 module (loaded from JSON)
    let cissp_domain_3_phase = load_tutorial_phase("cissp-domain-3");
    validate_step_structure(&cissp_domain_3_phase.steps, "cissp-domain-3")?;

    // Validate CISSP Domain 4 module (loaded from JSON)
    let cissp_domain_4_phase = load_tutorial_phase("cissp-domain-4");
    validate_step_structure(&cissp_domain_4_phase.steps, "cissp-domain-4")?;

    // Validate CISSP Domain 5 module (loaded from JSON)
    let cissp_domain_5_phase = load_tutorial_phase("cissp-domain-5");
    validate_step_structure(&cissp_domain_5_phase.steps, "cissp-domain-5")?;

    // Validate Cloud Native module (loaded from JSON)
    let cloud_native_phase = load_tutorial_phase("cloud_native");
    validate_step_structure(&cloud_native_phase.steps, "cloud_native")?;

    // Validate AI Security module (loaded from JSON)
    let ai_security_phase = load_tutorial_phase("ai_security");
    validate_step_structure(&ai_security_phase.steps, "ai_security")?;

    // Validate AI-Powered Offensive Security module (loaded from JSON)
    let ai_powered_offensive_security_phase = load_tutorial_phase("ai_powered_offensive_security");
    validate_step_structure(
        &ai_powered_offensive_security_phase.steps,
        "ai_powered_offensive_security",
    )?;

    // Validate Retrieval-Augmented Generation Red Teaming module (loaded from JSON)
    let rag_red_teaming_phase = load_tutorial_phase("retrieval_augmented_generation_red_teaming");
    validate_step_structure(
        &rag_red_teaming_phase.steps,
        "retrieval_augmented_generation_red_teaming",
    )?;

    // Validate Bug Bounty Automation with AI module (loaded from JSON)
    let bug_bounty_automation_ai_phase = load_tutorial_phase("bug_bounty_automation_ai");
    validate_step_structure(
        &bug_bounty_automation_ai_phase.steps,
        "bug_bounty_automation_ai",
    )?;

    // Validate Supply Chain module (loaded from JSON)
    let supply_chain_phase = load_tutorial_phase("supply_chain");
    validate_step_structure(&supply_chain_phase.steps, "supply_chain")?;

    // Validate Purple Team Threat Hunting module (loaded from JSON)
    let purple_team_phase = load_tutorial_phase("purple_team_threat_hunting");
    validate_step_structure(&purple_team_phase.steps, "purple_team_threat_hunting")?;

    // Validate Red Team Tradecraft module (loaded from JSON)
    let red_team_phase = load_tutorial_phase("red_team_tradecraft");
    validate_step_structure(&red_team_phase.steps, "red_team_tradecraft")?;

    // Validate Modern Web module (loaded from JSON)
    let modern_web_phase = load_tutorial_phase("modern_web");
    validate_step_structure(&modern_web_phase.steps, "modern_web")?;

    // Validate that all modules have at least one step
    if linux_basics_phase.steps.is_empty() {
        return Err("Linux basics for hackers module has no steps".to_string());
    }
    if networking_fundamentals_phase.steps.is_empty() {
        return Err("Networking fundamentals module has no steps".to_string());
    }
    if wifi_security_phase.steps.is_empty() {
        return Err("Wi-Fi security attacks module has no steps".to_string());
    }
    if password_cracking_phase.steps.is_empty() {
        return Err("Password cracking techniques module has no steps".to_string());
    }
    if python_penetration_phase.steps.is_empty() {
        return Err("Python penetration testing module has no steps".to_string());
    }
    if reverse_shells_phase.steps.is_empty() {
        return Err("Reverse shells guide module has no steps".to_string());
    }
    if file_security_phase.steps.is_empty() {
        return Err("File security practices module has no steps".to_string());
    }
    if recon_phase.steps.is_empty() {
        return Err("Reconnaissance module has no steps".to_string());
    }
    if foundations_phase.steps.is_empty() {
        return Err("Traditional vs AI pentesting foundations module has no steps".to_string());
    }
    if lab_phase.steps.is_empty() {
        return Err("Building modern PT lab with GenAI module has no steps".to_string());
    }
    if genai_recon_phase.steps.is_empty() {
        return Err("GenAI-driven reconnaissance module has no steps".to_string());
    }
    if scanning_phase.steps.is_empty() {
        return Err("AI-enhanced scanning and sniffing module has no steps".to_string());
    }
    if vuln_ai_phase.steps.is_empty() {
        return Err("Vulnerability assessment with AI module has no steps".to_string());
    }
    if social_engineering_phase.steps.is_empty() {
        return Err("AI-driven social engineering module has no steps".to_string());
    }
    if exploitation_phase.steps.is_empty() {
        return Err("GenAI-driven exploitation module has no steps".to_string());
    }
    if post_exploitation_phase.steps.is_empty() {
        return Err(
            "Post-exploitation and privilege escalation with AI module has no steps".to_string(),
        );
    }
    if reports_phase.steps.is_empty() {
        return Err("Automating PT reports with GenAI module has no steps".to_string());
    }
    if advanced_recon_phase.steps.is_empty() {
        return Err("Advanced reconnaissance techniques module has no steps".to_string());
    }
    if vuln_analysis_phase.steps.is_empty() {
        return Err("Vulnerability analysis module has no steps".to_string());
    }
    if advanced_web_phase.steps.is_empty() {
        return Err("Advanced web app security fundamentals module has no steps".to_string());
    }
    if xss_phase.steps.is_empty() {
        return Err("Cross-site scripting module has no steps".to_string());
    }
    if auth_phase.steps.is_empty() {
        return Err(
            "Authentication and authorization vulnerabilities module has no steps".to_string(),
        );
    }
    if injection_phase.steps.is_empty() {
        return Err("Injection vulnerabilities deep dive module has no steps".to_string());
    }
    if server_side_attacks_phase.steps.is_empty() {
        return Err("Server-side attacks module has no steps".to_string());
    }
    if exploit_phase.steps.is_empty() {
        return Err("Exploitation module has no steps".to_string());
    }
    if post_phase.steps.is_empty() {
        return Err("Post-exploitation module has no steps".to_string());
    }
    if linux_ctf_phase.steps.is_empty() {
        return Err("Linux CTF module has no steps".to_string());
    }
    if windows_ctf_phase.steps.is_empty() {
        return Err("Windows CTF module has no steps".to_string());
    }
    if cloud_iam_phase.steps.is_empty() {
        return Err("Cloud IAM module has no steps".to_string());
    }
    if oauth_phase.steps.is_empty() {
        return Err("Practical OAuth module has no steps".to_string());
    }
    if federation_phase.steps.is_empty() {
        return Err("SSO Federation module has no steps".to_string());
    }
    if api_security_phase.steps.is_empty() {
        return Err("API Security module has no steps".to_string());
    }
    if reporting_phase.steps.is_empty() {
        return Err("Reporting module has no steps".to_string());
    }
    if container_security_phase.steps.is_empty() {
        return Err("Container Security module has no steps".to_string());
    }
    if serverless_security_phase.steps.is_empty() {
        return Err("Serverless Security module has no steps".to_string());
    }
    if bug_bounty_hunting_phase.steps.is_empty() {
        return Err("Bug Bounty Hunting module has no steps".to_string());
    }
    if comptia_secplus_phase.steps.is_empty() {
        return Err("CompTIA Security+ module has no steps".to_string());
    }
    if pentest_exam_phase.steps.is_empty() {
        return Err("PenTest+ module has no steps".to_string());
    }
    if ceh_phase.steps.is_empty() {
        return Err("CEH module has no steps".to_string());
    }
    if cissp_domain_1_phase.steps.is_empty() {
        return Err("CISSP Domain 1 module has no steps".to_string());
    }
    if cissp_domain_2_phase.steps.is_empty() {
        return Err("CISSP Domain 2 module has no steps".to_string());
    }
    if cissp_domain_3_phase.steps.is_empty() {
        return Err("CISSP Domain 3 module has no steps".to_string());
    }
    if cissp_domain_4_phase.steps.is_empty() {
        return Err("CISSP Domain 4 module has no steps".to_string());
    }
    if cissp_domain_5_phase.steps.is_empty() {
        return Err("CISSP Domain 5 module has no steps".to_string());
    }
    if cloud_native_phase.steps.is_empty() {
        return Err("Cloud Native module has no steps".to_string());
    }
    if ai_security_phase.steps.is_empty() {
        return Err("AI Security module has no steps".to_string());
    }
    if ai_powered_offensive_security_phase.steps.is_empty() {
        return Err("AI-Powered Offensive Security module has no steps".to_string());
    }
    if rag_red_teaming_phase.steps.is_empty() {
        return Err("Retrieval-Augmented Generation Red Teaming module has no steps".to_string());
    }
    if bug_bounty_automation_ai_phase.steps.is_empty() {
        return Err("Bug Bounty Automation with AI module has no steps".to_string());
    }
    if supply_chain_phase.steps.is_empty() {
        return Err("Supply Chain module has no steps".to_string());
    }
    if purple_team_phase.steps.is_empty() {
        return Err("Purple Team Threat Hunting module has no steps".to_string());
    }
    if red_team_phase.steps.is_empty() {
        return Err("Red Team Tradecraft module has no steps".to_string());
    }
    if modern_web_phase.steps.is_empty() {
        return Err("Modern Web module has no steps".to_string());
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
    }

    Ok(())
}
