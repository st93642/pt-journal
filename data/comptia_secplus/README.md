# CompTIA Security+ (SY0-701) Question Database

This directory contains quiz questions for the CompTIA Security+ certification exam (SY0-701) organized by domain.

## File Format

Each question file uses a pipe-delimited format with 9 fields per line:

```
question|answer_a|answer_b|answer_c|answer_d|correct_index|explanation|domain|subdomain
```

### Field Descriptions

1. **question** - The question text
2. **answer_a** - First answer option (A)
3. **answer_b** - Second answer option (B)
4. **answer_c** - Third answer option (C)
5. **answer_d** - Fourth answer option (D)
6. **correct_index** - Index of correct answer (0=A, 1=B, 2=C, 3=D)
7. **explanation** - Detailed explanation of why the answer is correct
8. **domain** - The exam domain (e.g., "1.0 General Security Concepts")
9. **subdomain** - Specific subdomain (e.g., "1.1 Compare and contrast security controls")

### Example Line

```
What is the CIA triad?|Confidentiality, Integrity, Availability|Cryptography, Identity, Access|Ciphers, Integrity, Authentication|Control, Intelligence, Analysis|0|The CIA triad stands for Confidentiality, Integrity, and Availability - the three fundamental principles of information security.|1.0 General Security Concepts|1.1 Security Controls
```

### File Naming Convention

- Files should be named after their subdomain
- Use descriptive names, e.g., `1.1-security-controls.txt`, `2.3-application-attacks.txt`
- One file per subdomain for maintainability

### Comments and Empty Lines

- Lines starting with `#` are treated as comments
- Empty lines are ignored
- Comments can be used to organize questions within a file

## Directory Structure

### 1.0-general-security/ 
Questions covering general security concepts (approximately 12% of exam)
- Security controls
- CIA triad
- Non-repudiation
- Authentication factors
- Etc.

### 2.0-threats-vulnerabilities/
Questions on threats, vulnerabilities, and attacks (approximately 22% of exam)
- Social engineering
- Malware types
- Application attacks
- Network attacks
- Vulnerability scanning
- Etc.

### 3.0-security-architecture/
Questions on security architecture and implementation (approximately 18% of exam)
- Secure network design
- Cloud security
- Secure protocols
- Endpoint security
- Etc.

### 4.0-security-operations/
Questions on security operations and monitoring (approximately 28% of exam)
- Security monitoring
- Incident response
- Digital forensics
- Disaster recovery
- Etc.

### 5.0-governance-risk-compliance/
Questions on governance, risk management, and compliance (approximately 20% of exam)
- Security policies
- Risk management
- Compliance frameworks
- Privacy
- Etc.

## Usage

The quiz system loads questions from these files using the `parse_question_file()` function in `src/quiz/mod.rs`. Questions are loaded on-demand (lazy loading) to handle large datasets efficiently.

### Adding New Questions

1. Identify the appropriate domain folder
2. Create or edit the relevant subdomain file
3. Add questions in the pipe-delimited format
4. Ensure all 9 fields are present
5. Test by running the quiz in PT Journal

### Quality Guidelines

- **Clarity**: Questions should be clear and unambiguous
- **Accuracy**: Explanations must be technically accurate
- **Relevance**: Align with SY0-701 exam objectives
- **Difficulty**: Mix of easy, medium, and hard questions
- **Uniqueness**: Avoid duplicate questions across files

## Parser Validation

The parser enforces:
- ✅ All 9 fields must be present
- ✅ Question text cannot be empty
- ✅ All 4 answer options must be non-empty
- ✅ Correct index must be 0-3
- ✅ Explanation cannot be empty
- ✅ Domain and subdomain must be specified

## Statistics

- **Target**: 1000+ questions total
- **Distribution**: Aligned with exam domain percentages
- **Current**: [To be updated as questions are added]

## Contributing

When adding questions:
1. Follow the file format exactly
2. Place questions in the correct domain folder
3. Use the appropriate subdomain file
4. Include detailed explanations
5. Reference official CompTIA objectives when possible

## Resources

- [CompTIA Security+ Exam Objectives (SY0-701)](https://www.comptia.org/certifications/security)
- Official CompTIA study materials
- Practice exam questions (converted to this format)
