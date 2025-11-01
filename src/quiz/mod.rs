use crate::model::{QuizAnswer, QuizQuestion};
use anyhow::{Context, Result, bail};
use uuid::Uuid;

/// File format: question|a|b|c|d|correct_idx|explanation|domain|subdomain
/// Example: "What is CIA triad?|Confidentiality, Integrity, Availability|Cryptography, Identity, Access|Ciphers, Integrity, Authentication|Control, Intelligence, Analysis|0|The CIA triad stands for Confidentiality, Integrity, and Availability.|1.0 General Security Concepts|1.1 Security Controls"
pub fn parse_question_line(line: &str) -> Result<QuizQuestion> {
    let line = line.trim();
    
    // Skip empty lines and comments
    if line.is_empty() || line.starts_with('#') {
        bail!("Empty line or comment");
    }
    
    let parts: Vec<&str> = line.split('|').collect();
    
    if parts.len() != 9 {
        bail!("Invalid format: expected 9 fields separated by |, got {}", parts.len());
    }
    
    let question_text = parts[0].trim().to_string();
    if question_text.is_empty() {
        bail!("Question text cannot be empty");
    }
    
    // Parse 4 answer options (a, b, c, d)
    let answer_texts: Vec<String> = parts[1..5]
        .iter()
        .map(|s| s.trim().to_string())
        .collect();
    
    // Validate all answer texts are non-empty
    for (idx, text) in answer_texts.iter().enumerate() {
        if text.is_empty() {
            bail!("Answer option {} cannot be empty", (b'A' + idx as u8) as char);
        }
    }
    
    // Parse correct answer index (0-3)
    let correct_idx: usize = parts[5].trim().parse()
        .context("Failed to parse correct answer index")?;
    
    if correct_idx > 3 {
        bail!("Correct answer index must be 0-3, got {}", correct_idx);
    }
    
    // Build answers with is_correct flag
    let answers: Vec<QuizAnswer> = answer_texts
        .into_iter()
        .enumerate()
        .map(|(idx, text)| QuizAnswer {
            text,
            is_correct: idx == correct_idx,
        })
        .collect();
    
    let explanation = parts[6].trim().to_string();
    if explanation.is_empty() {
        bail!("Explanation cannot be empty");
    }
    
    let domain = parts[7].trim().to_string();
    if domain.is_empty() {
        bail!("Domain cannot be empty");
    }
    
    let subdomain = parts[8].trim().to_string();
    if subdomain.is_empty() {
        bail!("Subdomain cannot be empty");
    }
    
    Ok(QuizQuestion {
        id: Uuid::new_v4(),
        question_text,
        answers,
        explanation,
        domain,
        subdomain,
    })
}

/// Parse an entire file of questions
pub fn parse_question_file(content: &str) -> Result<Vec<QuizQuestion>> {
    let mut questions = Vec::new();
    
    for (line_num, line) in content.lines().enumerate() {
        match parse_question_line(line) {
            Ok(question) => questions.push(question),
            Err(e) => {
                // Skip empty lines and comments silently
                if !line.trim().is_empty() && !line.trim().starts_with('#') {
                    eprintln!("Warning: Failed to parse line {}: {}", line_num + 1, e);
                }
            }
        }
    }
    
    if questions.is_empty() {
        bail!("No valid questions found in file");
    }
    
    Ok(questions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_question() {
        let line = "What is CIA triad?|Confidentiality, Integrity, Availability|Cryptography, Identity, Access|Ciphers, Integrity, Authentication|Control, Intelligence, Analysis|0|The CIA triad stands for Confidentiality, Integrity, and Availability.|1.0 General Security Concepts|1.1 Security Controls";
        
        let question = parse_question_line(line).unwrap();
        
        assert_eq!(question.question_text, "What is CIA triad?");
        assert_eq!(question.answers.len(), 4);
        assert_eq!(question.answers[0].text, "Confidentiality, Integrity, Availability");
        assert!(question.answers[0].is_correct);
        assert!(!question.answers[1].is_correct);
        assert_eq!(question.explanation, "The CIA triad stands for Confidentiality, Integrity, and Availability.");
        assert_eq!(question.domain, "1.0 General Security Concepts");
        assert_eq!(question.subdomain, "1.1 Security Controls");
    }

    #[test]
    fn test_parse_question_with_whitespace() {
        let line = "  What is AAA?  |  Authentication, Authorization, Accounting  |  Access, Audit, Availability  |  Analysis, Action, Accountability  |  Assess, Approve, Authorize  |  0  |  AAA stands for Authentication, Authorization, and Accounting.  |  1.0 General  |  1.1 Controls  ";
        
        let question = parse_question_line(line).unwrap();
        
        assert_eq!(question.question_text, "What is AAA?");
        assert_eq!(question.answers[0].text, "Authentication, Authorization, Accounting");
        assert!(question.answers[0].is_correct);
    }

    #[test]
    fn test_parse_different_correct_answer() {
        let line = "Which is strongest encryption?|DES|3DES|AES-256|RC4|2|AES-256 is currently the strongest widely-used encryption standard.|2.0 Threats|2.1 Cryptography";
        
        let question = parse_question_line(line).unwrap();
        
        assert!(!question.answers[0].is_correct);
        assert!(!question.answers[1].is_correct);
        assert!(question.answers[2].is_correct);
        assert!(!question.answers[3].is_correct);
    }

    #[test]
    fn test_parse_empty_line() {
        let result = parse_question_line("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Empty line"));
    }

    #[test]
    fn test_parse_comment_line() {
        let result = parse_question_line("# This is a comment");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_insufficient_fields() {
        let line = "What is this?|Answer A|Answer B|Answer C";
        let result = parse_question_line(line);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected 9 fields"));
    }

    #[test]
    fn test_parse_too_many_fields() {
        let line = "Q?|A|B|C|D|0|Explanation|Domain|Subdomain|Extra";
        let result = parse_question_line(line);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected 9 fields"));
    }

    #[test]
    fn test_parse_empty_question_text() {
        let line = "|Answer A|Answer B|Answer C|Answer D|0|Explanation|Domain|Subdomain";
        let result = parse_question_line(line);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_parse_empty_answer() {
        let line = "Question?|Answer A||Answer C|Answer D|0|Explanation|Domain|Subdomain";
        let result = parse_question_line(line);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_parse_invalid_correct_index() {
        let line = "Question?|A|B|C|D|5|Explanation|Domain|Subdomain";
        let result = parse_question_line(line);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be 0-3"));
    }

    #[test]
    fn test_parse_non_numeric_correct_index() {
        let line = "Question?|A|B|C|D|abc|Explanation|Domain|Subdomain";
        let result = parse_question_line(line);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_explanation() {
        let line = "Question?|A|B|C|D|0||Domain|Subdomain";
        let result = parse_question_line(line);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Explanation cannot be empty"));
    }

    #[test]
    fn test_parse_empty_domain() {
        let line = "Question?|A|B|C|D|0|Explanation||Subdomain";
        let result = parse_question_line(line);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Domain cannot be empty"));
    }

    #[test]
    fn test_parse_empty_subdomain() {
        let line = "Question?|A|B|C|D|0|Explanation|Domain|";
        let result = parse_question_line(line);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Subdomain cannot be empty"));
    }

    #[test]
    fn test_parse_file_with_multiple_questions() {
        let content = r#"
# Domain 1.0 - General Security Concepts
What is CIA triad?|Confidentiality, Integrity, Availability|Cryptography, Identity, Access|Ciphers, Integrity, Authentication|Control, Intelligence, Analysis|0|The CIA triad stands for Confidentiality, Integrity, and Availability.|1.0 General Security Concepts|1.1 Security Controls

What is AAA?|Authentication, Authorization, Accounting|Access, Audit, Availability|Analysis, Action, Accountability|Assess, Approve, Authorize|0|AAA stands for Authentication, Authorization, and Accounting.|1.0 General Security Concepts|1.1 Security Controls
"#;
        
        let questions = parse_question_file(content).unwrap();
        assert_eq!(questions.len(), 2);
        assert_eq!(questions[0].question_text, "What is CIA triad?");
        assert_eq!(questions[1].question_text, "What is AAA?");
    }

    #[test]
    fn test_parse_file_with_invalid_lines() {
        let content = r#"
# Comment line - should be skipped

What is CIA triad?|Confidentiality, Integrity, Availability|Cryptography, Identity, Access|Ciphers, Integrity, Authentication|Control, Intelligence, Analysis|0|The CIA triad stands for Confidentiality, Integrity, and Availability.|1.0 General Security Concepts|1.1 Security Controls
Invalid line with too few fields|A|B
What is AAA?|Authentication, Authorization, Accounting|Access, Audit, Availability|Analysis, Action, Accountability|Assess, Approve, Authorize|0|AAA stands for Authentication, Authorization, and Accounting.|1.0 General Security Concepts|1.1 Security Controls
"#;
        
        let questions = parse_question_file(content).unwrap();
        // Should parse 2 valid questions despite invalid lines
        assert_eq!(questions.len(), 2);
    }

    #[test]
    fn test_parse_file_all_invalid() {
        let content = r#"
# Only comments and invalid lines
Invalid line 1|A|B
Invalid line 2|C|D
"#;
        
        let result = parse_question_file(content);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No valid questions"));
    }

    #[test]
    fn test_load_sample_file() {
        use std::fs;
        let sample_path = "data/comptia_secplus/1.0-general-security/1.1-security-controls.txt";
        
        // Skip test if file doesn't exist (e.g., in CI environment)
        if !std::path::Path::new(sample_path).exists() {
            eprintln!("Sample file not found, skipping test");
            return;
        }
        
        let content = fs::read_to_string(sample_path)
            .expect("Failed to read sample question file");
        
        let questions = parse_question_file(&content)
            .expect("Failed to parse sample questions");
        
        // We expanded to 50 questions
        assert_eq!(questions.len(), 50);
        
        // Verify first question
        assert_eq!(questions[0].question_text, "Which type of security control is a firewall?");
        assert_eq!(questions[0].answers.len(), 4);
        assert!(questions[0].answers[1].is_correct); // Answer B (index 1) is correct
        assert_eq!(questions[0].domain, "1.0 General Security Concepts");
        assert_eq!(questions[0].subdomain, "1.1 Security Controls");
    }
}
