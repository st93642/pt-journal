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
        // Phase 1: Initial reconnaissance (intelligence gathering)
        load_tutorial_phase("reconnaissance"),
        // Phase 2-4: Core penetration testing methodology
        load_tutorial_phase("vulnerability_analysis"),
        load_tutorial_phase("exploitation"),
        load_tutorial_phase("post_exploitation"),
        // Phase 5: Linux CTF (practical application of methodology)
        load_tutorial_phase("linux_ctf"),
        // Phase 6: Windows CTF (Windows/AD practical application)
        load_tutorial_phase("windows_ctf"),
        // Phase 7-14: Modern security topics (cloud, identity, web, containers)
        load_tutorial_phase("cloud_iam"),
        load_tutorial_phase("practical_oauth"),
        load_tutorial_phase("sso_federation"),
        load_tutorial_phase("api_security"),
        load_tutorial_phase("modern_web"),
        load_tutorial_phase("container_security"),
        load_tutorial_phase("serverless_security"),
        load_tutorial_phase("cloud_native"),
        // Phase 15-19: Advanced topics (supply chain, AI, red/purple team)
        load_tutorial_phase("supply_chain"),
        load_tutorial_phase("ai_security"),
        load_tutorial_phase("red_team_tradecraft"),
        load_tutorial_phase("purple_team_threat_hunting"),
        load_tutorial_phase("bug_bounty_hunting"),
        // Phase 20: Reporting (final documentation phase)
        load_tutorial_phase("reporting"),
        // Phase 21-23: Quiz-based certification preparation (post-testing validation)
        load_tutorial_phase("comptia_secplus"),
        load_tutorial_phase("pentest_exam"),
        load_tutorial_phase("ceh"),
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
    // Validate reconnaissance module (loaded from JSON)
    let recon_phase = load_tutorial_phase("reconnaissance");
    validate_step_structure(&recon_phase.steps, "reconnaissance")?;

    // Validate vulnerability analysis module (loaded from JSON)
    let vuln_phase = load_tutorial_phase("vulnerability_analysis");
    validate_step_structure(&vuln_phase.steps, "vulnerability_analysis")?;

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

    // Validate Cloud Native module (loaded from JSON)
    let cloud_native_phase = load_tutorial_phase("cloud_native");
    validate_step_structure(&cloud_native_phase.steps, "cloud_native")?;

    // Validate AI Security module (loaded from JSON)
    let ai_security_phase = load_tutorial_phase("ai_security");
    validate_step_structure(&ai_security_phase.steps, "ai_security")?;

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
    if recon_phase.steps.is_empty() {
        return Err("Reconnaissance module has no steps".to_string());
    }
    if vuln_phase.steps.is_empty() {
        return Err("Vulnerability analysis module has no steps".to_string());
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
    if cloud_native_phase.steps.is_empty() {
        return Err("Cloud Native module has no steps".to_string());
    }
    if ai_security_phase.steps.is_empty() {
        return Err("AI Security module has no steps".to_string());
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
