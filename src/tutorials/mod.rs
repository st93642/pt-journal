pub mod ai_security;
pub mod bug_bounty_hunting;
pub mod ceh;
// pub mod cloud_identity; // Now loaded from JSON
pub mod cloud_native;
pub mod comptia_secplus;
pub mod container_security;
// pub mod exploitation; // Now loaded from JSON
pub mod modern_web;
pub mod pentest_exam;
// pub mod post_exploitation; // Now loaded from JSON
pub mod purple_team_threat_hunting;
// pub mod reconnaissance; // Now loaded from JSON
pub mod red_team_tradecraft;
pub mod serverless_security;
pub mod supply_chain;
// pub mod vulnerability_analysis; // Now loaded from JSON

use crate::model::{Phase, Step};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

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
pub fn load_tutorial_phases() -> Vec<Phase> {
    vec![
        load_tutorial_phase("reconnaissance"),
        load_tutorial_phase("vulnerability_analysis"),
        load_tutorial_phase("exploitation"),
        load_tutorial_phase("post_exploitation"),
        load_tutorial_phase("cloud_iam"),
        load_tutorial_phase("practical_oauth"),
        load_tutorial_phase("sso_federation"),
        load_tutorial_phase("api_security"),
        load_tutorial_phase("reporting"),
        create_container_security_phase(),
        create_serverless_security_phase(),
        create_bug_bounty_hunting_phase(),
        create_comptia_secplus_phase(),
        create_pentest_exam_phase(),
        create_ceh_phase(),
        create_cicd_pipeline_attacks_phase(),
        create_sbom_analysis_phase(),
        create_dependency_confusion_phase(),
        create_artifact_integrity_phase(),
        create_red_team_tradecraft_phase(),
        create_purple_team_threat_hunting_phase(),
        create_ai_security_phase(),
    ]
}

/// Load quiz questions from a file
fn load_quiz_from_file(file_path: &str) -> Result<Vec<crate::model::QuizQuestion>, String> {
    // Read file content
    let content = fs::read_to_string(file_path).map_err(|e| {
        format!("Failed to read quiz file {}: {}", file_path, e)
    })?;

    // Parse questions
    crate::quiz::parse_question_file(&content).map_err(|e| {
        format!("Failed to parse questions from {}: {}", file_path, e)
    })
}

/// Load a tutorial phase from JSON file
fn load_tutorial_phase(phase_name: &str) -> Phase {
    let json_path = format!("data/tutorials/{}.json", phase_name);
    match fs::read_to_string(&json_path) {
        Ok(content) => {
            match serde_json::from_str::<TutorialData>(&content) {
                Ok(tutorial_data) => {
                    let steps = tutorial_data.steps.into_iter().map(|step_data| {
                        // Check if this is a quiz step
                        if step_data.tags.contains(&"quiz".to_string()) {
                            // For quiz steps, load the quiz data from the referenced file
                            // The content field contains the path to the quiz file
                            if step_data.content.starts_with("Quiz content loaded from ") {
                                let quiz_file_path = step_data.content
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
                                    Err(e) => {
                                        eprintln!("Failed to load quiz from {}: {}", quiz_file_path, e);
                                        // Fallback to tutorial step
                                        Step::new_tutorial(
                                            Uuid::new_v4(),
                                            step_data.title,
                                            format!("Error loading quiz: {}", e),
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
                    }).collect();

                    Phase {
                        id: Uuid::new_v4(),
                        name: tutorial_data.title,
                        steps,
                        notes: String::new(),
                    }
                }
                Err(e) => {
                    eprintln!("Failed to parse {}: {}", json_path, e);
                    // Fallback to empty phase
                    Phase {
                        id: Uuid::new_v4(),
                        name: phase_name.to_string(),
                        steps: Vec::new(),
                        notes: format!("Error loading tutorial: {}", e),
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to read {}: {}", json_path, e);
            // Fallback to empty phase
            Phase {
                id: Uuid::new_v4(),
                name: phase_name.to_string(),
                steps: Vec::new(),
                notes: format!("File not found: {}", e),
            }
        }
    }
}

fn create_container_security_phase() -> Phase {
    let steps = container_security::get_container_security_steps();

    Phase {
        id: Uuid::new_v4(),
        name: "Container & Kubernetes Security".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_serverless_security_phase() -> Phase {
    let steps = serverless_security::get_serverless_security_steps();

    Phase {
        id: Uuid::new_v4(),
        name: "Serverless Security".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_cicd_pipeline_attacks_phase() -> Phase {
    let steps = vec![cloud_native::cicd_pipeline_attacks_phase()];

    Phase {
        id: Uuid::new_v4(),
        name: "CI-CD Pipeline Attacks".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_sbom_analysis_phase() -> Phase {
    let steps = vec![supply_chain::sbom_analysis_phase()];

    Phase {
        id: Uuid::new_v4(),
        name: "SBOM Generation & Analysis".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_dependency_confusion_phase() -> Phase {
    let steps = vec![supply_chain::dependency_confusion_phase()];

    Phase {
        id: Uuid::new_v4(),
        name: "Dependency Confusion & Typosquatting".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_artifact_integrity_phase() -> Phase {
    let steps = vec![supply_chain::artifact_integrity_phase()];

    Phase {
        id: Uuid::new_v4(),
        name: "Artifact Integrity Checks".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_comptia_secplus_phase() -> Phase {
    let steps = comptia_secplus::get_all_comptia_steps();

    Phase {
        id: Uuid::new_v4(),
        name: "CompTIA Security+".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_bug_bounty_hunting_phase() -> Phase {
    bug_bounty_hunting::load_phase()
}

fn create_pentest_exam_phase() -> Phase {
    let steps = pentest_exam::get_all_pentest_steps();

    Phase {
        id: Uuid::new_v4(),
        name: "CompTIA PenTest+".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_ceh_phase() -> Phase {
    let steps = ceh::get_all_ceh_steps();

    Phase {
        id: Uuid::new_v4(),
        name: "Certified Ethical Hacker (CEH)".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_red_team_tradecraft_phase() -> Phase {
    let steps = red_team_tradecraft::create_red_team_steps();

    Phase {
        id: Uuid::new_v4(),
        name: "Red Team Tradecraft".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_purple_team_threat_hunting_phase() -> Phase {
    let steps = purple_team_threat_hunting::create_purple_team_steps();

    Phase {
        id: Uuid::new_v4(),
        name: "Purple Team/Threat Hunting".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_ai_security_phase() -> Phase {
    let mut steps = Vec::new();

    // Add Model Threat Modeling steps
    for (title, description) in ai_security::MODEL_THREAT_MODELING_STEPS.iter() {
        steps.push(Step::new_tutorial(
            Uuid::new_v4(),
            title.to_string(),
            description.to_string(),
            vec![
                "ai".to_string(),
                "threat-modeling".to_string(),
                "security".to_string(),
            ],
        ));
    }

    // Add Prompt Injection & Jailbreaks steps
    for (title, description) in ai_security::PROMPT_INJECTION_STEPS.iter() {
        steps.push(Step::new_tutorial(
            Uuid::new_v4(),
            title.to_string(),
            description.to_string(),
            vec![
                "ai".to_string(),
                "llm".to_string(),
                "prompt-injection".to_string(),
            ],
        ));
    }

    // Add Model Poisoning & Dataset Attacks steps
    for (title, description) in ai_security::MODEL_POISONING_STEPS.iter() {
        steps.push(Step::new_tutorial(
            Uuid::new_v4(),
            title.to_string(),
            description.to_string(),
            vec!["ai".to_string(), "ml".to_string(), "poisoning".to_string()],
        ));
    }

    // Add Data Exfiltration & Model Inversion steps
    for (title, description) in ai_security::DATA_EXFILTRATION_STEPS.iter() {
        steps.push(Step::new_tutorial(
            Uuid::new_v4(),
            title.to_string(),
            description.to_string(),
            vec![
                "ai".to_string(),
                "llm".to_string(),
                "data-exfiltration".to_string(),
            ],
        ));
    }

    // Add Adversarial Example Crafting steps
    for (title, description) in ai_security::ADVERSARIAL_EXAMPLES_STEPS.iter() {
        steps.push(Step::new_tutorial(
            Uuid::new_v4(),
            title.to_string(),
            description.to_string(),
            vec![
                "ai".to_string(),
                "ml".to_string(),
                "adversarial".to_string(),
            ],
        ));
    }

    // Add Guardrail Validation steps
    for (title, description) in ai_security::GUARDRAIL_VALIDATION_STEPS.iter() {
        steps.push(Step::new_tutorial(
            Uuid::new_v4(),
            title.to_string(),
            description.to_string(),
            vec![
                "ai".to_string(),
                "safety".to_string(),
                "guardrails".to_string(),
            ],
        ));
    }

    Phase {
        id: Uuid::new_v4(),
        name: "AI/ML Security Integrations".to_string(),
        steps,
        notes: String::new(),
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

    Ok(())
}

/// Validate the structure of tutorial steps
fn validate_step_structure(steps: &[Step], module_name: &str) -> Result<(), String> {
    for (index, step) in steps.iter().enumerate() {
        // Check that step has a non-empty title
        if step.title.trim().is_empty() {
            return Err(format!(
                "{}: Step {} has empty title",
                module_name, index
            ));
        }

        // Check that step has a description (tutorial steps only)
        if step.is_tutorial() {
            let description = step.get_description();
            if description.trim().is_empty() {
                return Err(format!(
                    "{}: Step '{}' has empty description",
                    module_name, step.title
                ));
            }
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
