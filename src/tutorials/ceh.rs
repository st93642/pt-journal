/// Certified Ethical Hacker (CEH) v12 quiz-based learning phase
/// 
/// This module provides 24 modules of CEH v12 certification content covering the full
/// EC-Council ethical hacking curriculum plus advanced topics:
/// 
/// - Module 01: Introduction to Ethical Hacking
/// - Module 02: Footprinting and Reconnaissance  
/// - Module 03: Scanning Networks
/// - Module 04: Enumeration
/// - Module 05: Vulnerability Analysis
/// - Module 06: System Hacking
/// - Module 07: Malware Threats
/// - Module 08: Sniffing
/// - Module 09: Social Engineering
/// - Module 10: Denial of Service
/// - Module 11: Session Hijacking
/// - Module 12: Evading IDSs, Firewalls, and Honeypots
/// - Module 13: Hacking Web Servers
/// - Module 14: Hacking Web Applications
/// - Module 15: SQL Injection
/// - Module 16: Hacking Wireless Networks
/// - Module 17: Hacking Mobile Platforms
/// - Module 18: IoT and OT Hacking
/// - Module 19: Cloud Computing
/// - Module 20: Cryptography
/// - Module 21: AI and Machine Learning Security
/// - Module 22: Kubernetes and Container Security
/// - Module 23: DevSecOps and CI/CD Pipeline Security
/// - Module 24: Blockchain and Web3 Security
///
/// Questions are loaded from data/ceh/ directory structure.

use crate::model::{Step, QuizStep};
use crate::quiz::parse_question_file;
use uuid::Uuid;
use std::fs;
use std::path::Path;

/// Module 01: Introduction to Ethical Hacking
pub const MODULE_01: &str = "01. Introduction to Ethical Hacking";

/// Module 02: Footprinting and Reconnaissance
pub const MODULE_02: &str = "02. Footprinting and Reconnaissance";

/// Module 03: Scanning Networks
pub const MODULE_03: &str = "03. Scanning Networks";

/// Module 04: Enumeration
pub const MODULE_04: &str = "04. Enumeration";

/// Module 05: Vulnerability Analysis
pub const MODULE_05: &str = "05. Vulnerability Analysis";

/// Module 06: System Hacking
pub const MODULE_06: &str = "06. System Hacking";

/// Module 07: Malware Threats
pub const MODULE_07: &str = "07. Malware Threats";

/// Module 08: Sniffing
pub const MODULE_08: &str = "08. Sniffing";

/// Module 09: Social Engineering
pub const MODULE_09: &str = "09. Social Engineering";

/// Module 10: Denial of Service
pub const MODULE_10: &str = "10. Denial of Service";

/// Module 11: Session Hijacking
pub const MODULE_11: &str = "11. Session Hijacking";

/// Module 12: Evading IDSs, Firewalls, and Honeypots
pub const MODULE_12: &str = "12. Evading IDSs, Firewalls, and Honeypots";

/// Module 13: Hacking Web Servers
pub const MODULE_13: &str = "13. Hacking Web Servers";

/// Module 14: Hacking Web Applications
pub const MODULE_14: &str = "14. Hacking Web Applications";

/// Module 15: SQL Injection
pub const MODULE_15: &str = "15. SQL Injection";

/// Module 16: Hacking Wireless Networks
pub const MODULE_16: &str = "16. Hacking Wireless Networks";

/// Module 17: Hacking Mobile Platforms
pub const MODULE_17: &str = "17. Hacking Mobile Platforms";

/// Module 18: IoT and OT Hacking
pub const MODULE_18: &str = "18. IoT and OT Hacking";

/// Module 19: Cloud Computing
pub const MODULE_19: &str = "19. Cloud Computing";

/// Module 20: Cryptography
pub const MODULE_20: &str = "20. Cryptography";

/// Module 21: AI and Machine Learning Security
pub const MODULE_21: &str = "21. AI and Machine Learning Security";

/// Module 22: Kubernetes and Container Security
pub const MODULE_22: &str = "22. Kubernetes and Container Security";

/// Module 23: DevSecOps and CI/CD Pipeline Security
pub const MODULE_23: &str = "23. DevSecOps and CI/CD Pipeline Security";

/// Module 24: Blockchain and Web3 Security
pub const MODULE_24: &str = "24. Blockchain and Web3 Security";

/// Load questions from a file in the data directory
fn load_questions_from_file(relative_path: &str) -> Result<Vec<crate::model::QuizQuestion>, String> {
    let base_path = Path::new("data/ceh");
    let full_path = base_path.join(relative_path);
    
    // Check if file exists
    if !full_path.exists() {
        return Err(format!("Question file not found: {}", full_path.display()));
    }
    
    // Read file content
    let content = fs::read_to_string(&full_path)
        .map_err(|e| format!("Failed to read question file {}: {}", full_path.display(), e))?;
    
    // Parse questions
    parse_question_file(&content)
        .map_err(|e| format!("Failed to parse questions from {}: {}", full_path.display(), e))
}

/// Create a quiz step from a question file
fn create_quiz_step_from_file(
    title: String,
    module: String,
    file_path: &str,
) -> Result<Step, String> {
    let questions = load_questions_from_file(file_path)?;
    
    if questions.is_empty() {
        return Err(format!("No questions loaded from {}", file_path));
    }
    
    let quiz_step = QuizStep::new(
        Uuid::new_v4(),
        title.clone(),
        module,
        questions,
    );
    
    Ok(Step::new_quiz(
        Uuid::new_v4(),
        title,
        vec!["quiz".to_string(), "ceh".to_string(), "ethical-hacker".to_string()],
        quiz_step,
    ))
}

/// Get all quiz steps for Module 01 (Introduction to Ethical Hacking)
pub fn get_module_01_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "1.1 Ethical Hacking Fundamentals".to_string(),
        MODULE_01.to_string(),
        "01-ethical-hacking/1.1-fundamentals.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 01: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 02 (Footprinting and Reconnaissance)
pub fn get_module_02_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "2.1 Footprinting and OSINT".to_string(),
        MODULE_02.to_string(),
        "02-footprinting-reconnaissance/2.1-footprinting.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 02: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 03 (Scanning Networks)
pub fn get_module_03_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "3.1 Network Scanning Techniques".to_string(),
        MODULE_03.to_string(),
        "03-scanning-networks/3.1-scanning.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 03: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 04 (Enumeration)
pub fn get_module_04_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "4.1 Service Enumeration".to_string(),
        MODULE_04.to_string(),
        "04-enumeration/4.1-enumeration.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 04: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 05 (Vulnerability Analysis)
pub fn get_module_05_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "5.1 Vulnerability Assessment".to_string(),
        MODULE_05.to_string(),
        "05-vulnerability-analysis/5.1-vulnerability.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 05: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 06 (System Hacking)
pub fn get_module_06_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "6.1 System Hacking Techniques".to_string(),
        MODULE_06.to_string(),
        "06-system-hacking/6.1-system-hacking.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 06: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 07 (Malware Threats)
pub fn get_module_07_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "7.1 Malware and Trojans".to_string(),
        MODULE_07.to_string(),
        "07-malware-threats/7.1-malware.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 07: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 08 (Sniffing)
pub fn get_module_08_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "8.1 Network Sniffing".to_string(),
        MODULE_08.to_string(),
        "08-sniffing/8.1-sniffing.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 08: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 09 (Social Engineering)
pub fn get_module_09_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "9.1 Social Engineering Attacks".to_string(),
        MODULE_09.to_string(),
        "09-social-engineering/9.1-social-engineering.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 09: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 10 (Denial of Service)
pub fn get_module_10_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "10.1 DoS and DDoS Attacks".to_string(),
        MODULE_10.to_string(),
        "10-denial-of-service/10.1-dos-ddos.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 10: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 11 (Session Hijacking)
pub fn get_module_11_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "11.1 Session Hijacking Techniques".to_string(),
        MODULE_11.to_string(),
        "11-session-hijacking/11.1-session-hijacking.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 11: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 12 (Evading IDSs, Firewalls, and Honeypots)
pub fn get_module_12_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "12.1 IDS/IPS Evasion".to_string(),
        MODULE_12.to_string(),
        "12-evading-ids-firewalls-honeypots/12.1-evasion.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 12: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 13 (Hacking Web Servers)
pub fn get_module_13_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "13.1 Web Server Attacks".to_string(),
        MODULE_13.to_string(),
        "13-hacking-web-servers/13.1-web-servers.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 13: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 14 (Hacking Web Applications)
pub fn get_module_14_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "14.1 Web Application Attacks".to_string(),
        MODULE_14.to_string(),
        "14-web-applications/14.1-web-apps.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 14: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 15 (SQL Injection)
pub fn get_module_15_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "15.1 SQL Injection Techniques".to_string(),
        MODULE_15.to_string(),
        "15-sql-injection/15.1-sql-injection.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 15: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 16 (Hacking Wireless Networks)
pub fn get_module_16_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "16.1 Wireless Network Attacks".to_string(),
        MODULE_16.to_string(),
        "16-wireless-networks/16.1-wireless.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 16: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 17 (Hacking Mobile Platforms)
pub fn get_module_17_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "17.1 Mobile Platform Attacks".to_string(),
        MODULE_17.to_string(),
        "17-mobile-platforms/17.1-mobile.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 17: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 18 (IoT and OT Hacking)
pub fn get_module_18_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "18.1 IoT and OT Security".to_string(),
        MODULE_18.to_string(),
        "18-iot-ot-hacking/18.1-iot-ot.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 18: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 19 (Cloud Computing)
pub fn get_module_19_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "19.1 Cloud Security".to_string(),
        MODULE_19.to_string(),
        "19-cloud-computing/19.1-cloud.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 19: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 20 (Cryptography)
pub fn get_module_20_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "20.1 Cryptographic Systems".to_string(),
        MODULE_20.to_string(),
        "20-cryptography/20.1-cryptography.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 20: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 21 (AI and Machine Learning Security)
pub fn get_module_21_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "21.1 AI/ML Security".to_string(),
        MODULE_21.to_string(),
        "21-ai-ml-security/21.1-ai-ml-security.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 21: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 22 (Kubernetes and Container Security)
pub fn get_module_22_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "22.1 Kubernetes & Containers".to_string(),
        MODULE_22.to_string(),
        "22-kubernetes-container-security/22.1-kubernetes-containers.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 22: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 23 (DevSecOps and CI/CD Pipeline Security)
pub fn get_module_23_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "23.1 DevSecOps & CI/CD".to_string(),
        MODULE_23.to_string(),
        "23-devsecops-cicd-security/23.1-devsecops-cicd.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 23: {}", e),
    }
    
    steps
}

/// Get all quiz steps for Module 24 (Blockchain and Web3 Security)
pub fn get_module_24_steps() -> Vec<Step> {
    let mut steps = Vec::new();
    
    match create_quiz_step_from_file(
        "24.1 Blockchain & Web3".to_string(),
        MODULE_24.to_string(),
        "24-blockchain-web3-security/24.1-blockchain-web3.txt",
    ) {
        Ok(step) => steps.push(step),
        Err(e) => eprintln!("Warning: Failed to load Module 24: {}", e),
    }
    
    steps
}

/// Get all CEH v12 quiz steps across all 24 modules
pub fn get_all_ceh_steps() -> Vec<Step> {
    let mut all_steps = Vec::new();
    
    all_steps.extend(get_module_01_steps());
    all_steps.extend(get_module_02_steps());
    all_steps.extend(get_module_03_steps());
    all_steps.extend(get_module_04_steps());
    all_steps.extend(get_module_05_steps());
    all_steps.extend(get_module_06_steps());
    all_steps.extend(get_module_07_steps());
    all_steps.extend(get_module_08_steps());
    all_steps.extend(get_module_09_steps());
    all_steps.extend(get_module_10_steps());
    all_steps.extend(get_module_11_steps());
    all_steps.extend(get_module_12_steps());
    all_steps.extend(get_module_13_steps());
    all_steps.extend(get_module_14_steps());
    all_steps.extend(get_module_15_steps());
    all_steps.extend(get_module_16_steps());
    all_steps.extend(get_module_17_steps());
    all_steps.extend(get_module_18_steps());
    all_steps.extend(get_module_19_steps());
    all_steps.extend(get_module_20_steps());
    all_steps.extend(get_module_21_steps());
    all_steps.extend(get_module_22_steps());
    all_steps.extend(get_module_23_steps());
    all_steps.extend(get_module_24_steps());
    
    all_steps
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_load_module_01_steps() {
        let steps = get_module_01_steps();
        assert_eq!(steps.len(), 1, "Module 01 should have 1 step");
        
        // Verify it's a quiz step
        for step in &steps {
            assert!(step.is_quiz(), "All Module 01 steps should be quiz steps");
        }
        
        // Verify title
        assert_eq!(steps[0].title, "1.1 Ethical Hacking Fundamentals");
    }
    
    #[test]
    fn test_load_questions_from_file_success() {
        let result = load_questions_from_file("01-ethical-hacking/1.1-fundamentals.txt");
        assert!(result.is_ok(), "Should successfully load Module 01 questions");
        
        let questions = result.unwrap();
        assert_eq!(questions.len(), 50, "Should have 50 questions");
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
            MODULE_01.to_string(),
            "01-ethical-hacking/1.1-fundamentals.txt",
        );
        
        assert!(result.is_ok(), "Should create quiz step successfully");
        
        let step = result.unwrap();
        assert_eq!(step.title, "Test Step");
        assert!(step.is_quiz());
        
        // Verify quiz content
        if let Some(quiz_step) = step.get_quiz_step() {
            assert_eq!(quiz_step.questions.len(), 50);
            assert_eq!(quiz_step.domain, MODULE_01);
        } else {
            panic!("Step should contain quiz data");
        }
    }
    
    #[test]
    fn test_get_all_ceh_steps() {
        let all_steps = get_all_ceh_steps();
        // Should have at least 1 step from module 1
        assert!(!all_steps.is_empty(), "Should have at least one CEH step");
    }
}
