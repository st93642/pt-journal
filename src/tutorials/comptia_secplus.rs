/// CompTIA Security+ quiz-based learning phase
///
/// This module provides 5 domains of CompTIA Security+ certification content:
/// - Domain 1.0: General Security Concepts
/// - Domain 2.0: Threats, Vulnerabilities, and Mitigations
/// - Domain 3.0: Security Architecture
/// - Domain 4.0: Security Operations
/// - Domain 5.0: Security Program Management and Oversight (Governance, Risk, Compliance)
///
/// Questions are loaded from data/comptia_secplus/ directory structure.
use crate::model::{QuizStep, Step};
use crate::quiz::parse_question_file;
use std::fs;
use std::path::Path;
use uuid::Uuid;

/// Domain 1.0: General Security Concepts
/// Subdomains: 1.1 Security Controls, 1.2 Security Concepts, 1.3 Change Management,
///             1.4 Cryptographic Solutions
pub const DOMAIN_1_GENERAL_SECURITY: &str = "1.0 General Security Concepts";

/// Domain 2.0: Threats, Vulnerabilities, and Mitigations
/// Subdomains: 2.1 Threat Actors, 2.2 Threat Vectors, 2.3 Attack Types,
///             2.4 Indicators of Compromise, 2.5 Mitigation Techniques
pub const DOMAIN_2_THREATS: &str = "2.0 Threats, Vulnerabilities, and Mitigations";

/// Domain 3.0: Security Architecture
/// Subdomains: 3.1 Security Design, 3.2 Security Infrastructure, 3.3 Secure Protocols,
///             3.4 Network Appliances
pub const DOMAIN_3_ARCHITECTURE: &str = "3.0 Security Architecture";

/// Domain 4.0: Security Operations
/// Subdomains: 4.1 Security Techniques, 4.2 Incident Response, 4.3 Digital Forensics,
///             4.4 Automation and Orchestration
pub const DOMAIN_4_OPERATIONS: &str = "4.0 Security Operations";

/// Domain 5.0: Security Program Management and Oversight
/// Subdomains: 5.1 Governance, 5.2 Risk Management, 5.3 Third-Party Risk,
///             5.4 Compliance and Audits, 5.5 Security Awareness
pub const DOMAIN_5_GOVERNANCE: &str = "5.0 Security Program Management and Oversight";

/// Load questions from a file in the data directory
fn load_questions_from_file(
    relative_path: &str,
) -> Result<Vec<crate::model::QuizQuestion>, String> {
    let base_path = Path::new("data/comptia_secplus");
    let full_path = base_path.join(relative_path);

    // Check if file exists
    if !full_path.exists() {
        return Err(format!("Question file not found: {}", full_path.display()));
    }

    // Read file content
    let content = fs::read_to_string(&full_path).map_err(|e| {
        format!(
            "Failed to read question file {}: {}",
            full_path.display(),
            e
        )
    })?;

    // Parse questions
    parse_question_file(&content).map_err(|e| {
        format!(
            "Failed to parse questions from {}: {}",
            full_path.display(),
            e
        )
    })
}

/// Create a quiz step from a question file
fn create_quiz_step_from_file(
    title: String,
    domain: String,
    file_path: &str,
) -> Result<Step, String> {
    let questions = load_questions_from_file(file_path)?;

    if questions.is_empty() {
        return Err(format!("No questions loaded from {}", file_path));
    }

    let quiz_step = QuizStep::new(Uuid::new_v4(), title.clone(), domain, questions);

    Ok(Step::new_quiz(
        Uuid::new_v4(),
        title,
        vec![
            "quiz".to_string(),
            "comptia".to_string(),
            "secplus".to_string(),
        ],
        quiz_step,
    ))
}

/// Get all quiz steps for Domain 1.0 (General Security Concepts)
pub fn get_domain_1_steps() -> Vec<Step> {
    let mut steps = Vec::new();

    // 1.1 Security Controls
    match create_quiz_step_from_file(
        "1.1 Security Controls".to_string(),
        DOMAIN_1_GENERAL_SECURITY.to_string(),
        "1.0-general-security/1.1-security-controls.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 1.1 Security Controls: {}", e),
    }

    // 1.2 Security Concepts
    match create_quiz_step_from_file(
        "1.2 Fundamental Security Concepts".to_string(),
        DOMAIN_1_GENERAL_SECURITY.to_string(),
        "1.0-general-security/1.2-security-concepts.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 1.2 Security Concepts: {}", e),
    }

    // 1.3 Change Management
    match create_quiz_step_from_file(
        "1.3 Change Management".to_string(),
        DOMAIN_1_GENERAL_SECURITY.to_string(),
        "1.0-general-security/1.3-change-management.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 1.3 Change Management: {}", e),
    }

    // 1.4 Cryptographic Solutions
    match create_quiz_step_from_file(
        "1.4 Cryptographic Solutions".to_string(),
        DOMAIN_1_GENERAL_SECURITY.to_string(),
        "1.0-general-security/1.4-cryptographic-solutions.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 1.4 Cryptographic Solutions: {}", e),
    }

    steps
}

/// Get all quiz steps for Domain 2.0 (Threats, Vulnerabilities, and Mitigations)
pub fn get_domain_2_steps() -> Vec<Step> {
    let mut steps = Vec::new();

    // 2.1 Threat Actors and Motivations
    match create_quiz_step_from_file(
        "2.1 Threat Actors and Motivations".to_string(),
        DOMAIN_2_THREATS.to_string(),
        "2.0-threats-vulnerabilities/2.1-threat-actors.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 2.1 Threat Actors: {}", e),
    }

    // 2.2 Threat Vectors
    match create_quiz_step_from_file(
        "2.2 Threat Vectors and Attack Surfaces".to_string(),
        DOMAIN_2_THREATS.to_string(),
        "2.0-threats-vulnerabilities/2.2-threat-vectors.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 2.2 Threat Vectors: {}", e),
    }

    // 2.3 Vulnerabilities
    match create_quiz_step_from_file(
        "2.3 Vulnerability Types".to_string(),
        DOMAIN_2_THREATS.to_string(),
        "2.0-threats-vulnerabilities/2.3-vulnerabilities.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 2.3 Vulnerabilities: {}", e),
    }

    // 2.4 Indicators of Malicious Activity
    match create_quiz_step_from_file(
        "2.4 Indicators of Malicious Activity".to_string(),
        DOMAIN_2_THREATS.to_string(),
        "2.0-threats-vulnerabilities/2.4-indicators-malicious-activity.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 2.4 Indicators: {}", e),
    }

    // 2.5 Mitigation Techniques
    match create_quiz_step_from_file(
        "2.5 Mitigation Techniques".to_string(),
        DOMAIN_2_THREATS.to_string(),
        "2.0-threats-vulnerabilities/2.5-mitigation-techniques.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 2.5 Mitigation Techniques: {}", e),
    }

    steps
}

/// Get all quiz steps for Domain 3.0 (Security Architecture)
pub fn get_domain_3_steps() -> Vec<Step> {
    let mut steps = Vec::new();

    // 3.1 Architecture Models
    match create_quiz_step_from_file(
        "3.1 Architecture Models".to_string(),
        DOMAIN_3_ARCHITECTURE.to_string(),
        "3.0-security-architecture/3.1-architecture-models.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 3.1 Architecture Models: {}", e),
    }

    // 3.2 Security Infrastructure
    match create_quiz_step_from_file(
        "3.2 Security Infrastructure".to_string(),
        DOMAIN_3_ARCHITECTURE.to_string(),
        "3.0-security-architecture/3.2-security-infrastructure.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 3.2 Security Infrastructure: {}", e),
    }

    // 3.3 Data Protection
    match create_quiz_step_from_file(
        "3.3 Data Protection".to_string(),
        DOMAIN_3_ARCHITECTURE.to_string(),
        "3.0-security-architecture/3.3-data-protection.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 3.3 Data Protection: {}", e),
    }

    // 3.4 Resilience and Recovery
    match create_quiz_step_from_file(
        "3.4 Resilience and Recovery".to_string(),
        DOMAIN_3_ARCHITECTURE.to_string(),
        "3.0-security-architecture/3.4-resilience-recovery.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 3.4 Resilience and Recovery: {}", e),
    }

    steps
}

/// Get all quiz steps for Domain 4.0 (Security Operations)
pub fn get_domain_4_steps() -> Vec<Step> {
    let mut steps = Vec::new();

    // 4.1 Security Techniques
    match create_quiz_step_from_file(
        "4.1 Security Techniques".to_string(),
        DOMAIN_4_OPERATIONS.to_string(),
        "4.0-security-operations/4.1-security-techniques.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 4.1 Security Techniques: {}", e),
    }

    // 4.2 Asset Management
    match create_quiz_step_from_file(
        "4.2 Asset Management".to_string(),
        DOMAIN_4_OPERATIONS.to_string(),
        "4.0-security-operations/4.2-asset-management.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 4.2 Asset Management: {}", e),
    }

    // 4.3 Vulnerability Management
    match create_quiz_step_from_file(
        "4.3 Vulnerability Management".to_string(),
        DOMAIN_4_OPERATIONS.to_string(),
        "4.0-security-operations/4.3-vulnerability-management.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!(
            "Warning: Failed to load 4.3 Vulnerability Management: {}",
            e
        ),
    }

    // 4.4 Monitoring Concepts
    match create_quiz_step_from_file(
        "4.4 Monitoring Concepts and Tools".to_string(),
        DOMAIN_4_OPERATIONS.to_string(),
        "4.0-security-operations/4.4-monitoring-concepts.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 4.4 Monitoring Concepts: {}", e),
    }

    // 4.5 Enterprise Capabilities
    match create_quiz_step_from_file(
        "4.5 Enhancing Enterprise Capabilities".to_string(),
        DOMAIN_4_OPERATIONS.to_string(),
        "4.0-security-operations/4.5-enterprise-capabilities.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 4.5 Enterprise Capabilities: {}", e),
    }

    steps
}

/// Get all quiz steps for Domain 5.0 (Governance, Risk, Compliance)
pub fn get_domain_5_steps() -> Vec<Step> {
    let mut steps = Vec::new();

    // 5.1 Governance Elements
    match create_quiz_step_from_file(
        "5.1 Governance and Compliance Elements".to_string(),
        DOMAIN_5_GOVERNANCE.to_string(),
        "5.0-governance-risk-compliance/5.1-governance-elements.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 5.1 Governance Elements: {}", e),
    }

    // 5.2 Risk Management
    match create_quiz_step_from_file(
        "5.2 Risk Management Processes".to_string(),
        DOMAIN_5_GOVERNANCE.to_string(),
        "5.0-governance-risk-compliance/5.2-risk-management.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 5.2 Risk Management: {}", e),
    }

    // 5.3 Third-Party Risk
    match create_quiz_step_from_file(
        "5.3 Third-Party Risk and Compliance".to_string(),
        DOMAIN_5_GOVERNANCE.to_string(),
        "5.0-governance-risk-compliance/5.3-third-party-risk.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 5.3 Third-Party Risk: {}", e),
    }

    // 5.4 Compliance and Auditing
    match create_quiz_step_from_file(
        "5.4 Compliance and Auditing".to_string(),
        DOMAIN_5_GOVERNANCE.to_string(),
        "5.0-governance-risk-compliance/5.4-compliance-auditing.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 5.4 Compliance: {}", e),
    }

    // 5.5 Security Awareness and Incident Response
    match create_quiz_step_from_file(
        "5.5 Security Awareness and Incident Response".to_string(),
        DOMAIN_5_GOVERNANCE.to_string(),
        "5.0-governance-risk-compliance/5.5-security-awareness-ir.txt",
    ) {
        Ok(step) => {
            steps.push(step);
        }
        Err(e) => eprintln!("Warning: Failed to load 5.5 Security Awareness: {}", e),
    }

    steps
}

/// Get all CompTIA Security+ quiz steps across all domains
pub fn get_all_comptia_steps() -> Vec<Step> {
    let mut all_steps = Vec::new();

    all_steps.extend(get_domain_1_steps());
    all_steps.extend(get_domain_2_steps());
    all_steps.extend(get_domain_3_steps());
    all_steps.extend(get_domain_4_steps());
    all_steps.extend(get_domain_5_steps());

    all_steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_domain_1_steps() {
        let steps = get_domain_1_steps();
        // Should have 4 subdomains: 1.1, 1.2, 1.3, 1.4
        assert_eq!(steps.len(), 4, "Domain 1 should have 4 subdomains");

        // Verify they're all quiz steps
        for step in &steps {
            assert!(step.is_quiz(), "All Domain 1 steps should be quiz steps");
        }

        // Verify titles
        assert_eq!(steps[0].title, "1.1 Security Controls");
        assert_eq!(steps[1].title, "1.2 Fundamental Security Concepts");
        assert_eq!(steps[2].title, "1.3 Change Management");
        assert_eq!(steps[3].title, "1.4 Cryptographic Solutions");
    }

    #[test]
    fn test_load_questions_from_file_success() {
        let result = load_questions_from_file("1.0-general-security/1.1-security-controls.txt");
        assert!(result.is_ok(), "Should successfully load 1.1 questions");

        let questions = result.unwrap();
        assert_eq!(questions.len(), 50, "Should have 50 questions (expanded)");
    }

    #[test]
    fn test_load_questions_from_nonexistent_file() {
        let result = load_questions_from_file("nonexistent/file.txt");
        assert!(result.is_err(), "Should fail for nonexistent file");
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_create_quiz_step_from_file() {
        let result = create_quiz_step_from_file(
            "Test Step".to_string(),
            DOMAIN_1_GENERAL_SECURITY.to_string(),
            "1.0-general-security/1.1-security-controls.txt",
        );

        assert!(result.is_ok(), "Should create quiz step successfully");

        let step = result.unwrap();
        assert_eq!(step.title, "Test Step");
        assert!(step.is_quiz());

        // Verify quiz content
        if let Some(quiz_step) = step.get_quiz_step() {
            assert_eq!(quiz_step.questions.len(), 50); // Expanded to 50 questions
            assert_eq!(quiz_step.domain, DOMAIN_1_GENERAL_SECURITY);
        } else {
            panic!("Step should contain quiz data");
        }
    }

    #[test]
    fn test_get_all_comptia_steps() {
        let all_steps = get_all_comptia_steps();
        // Should have at least 1 step from domain 1
        assert!(
            !all_steps.is_empty(),
            "Should have at least one CompTIA step"
        );
    }
}
