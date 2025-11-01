# CompTIA Security+ Quiz System - Architectural Design

## Overview

Add a quiz-based learning phase to PT Journal supporting 1000+ CompTIA Security+ exam questions with progress tracking, scoring, and explanation viewing.

## Goals

1. Support 1000+ multiple-choice questions efficiently
2. Track user progress and scoring
3. Distinguish between tutorial phases and quiz phases
4. Maintain backward compatibility with existing sessions
5. Provide immediate feedback with explanations
6. Support CompTIA Security+ exam domain structure

## Data Model Changes

### 1. Quiz Data Structures (model.rs)

```rust
/// Multiple choice answer option
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuizAnswer {
    pub text: String,
    pub is_correct: bool,
}

/// Single quiz question
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuizQuestion {
    pub id: Uuid,
    pub question_text: String,
    pub answers: Vec<QuizAnswer>,  // 4 options (A, B, C, D)
    pub explanation: String,
    pub domain: String,  // "1.0 General Security Concepts"
    pub subdomain: String,  // "1.1 Compare and contrast..."
}

/// User's progress on a single question
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionProgress {
    pub question_id: Uuid,
    pub answered: bool,
    pub selected_answer_index: Option<usize>,
    pub is_correct: Option<bool>,
    pub explanation_viewed_before_answer: bool,
    pub first_attempt_correct: bool,  // For scoring
    pub attempts: u32,
    pub last_attempted: Option<DateTime<Utc>>,
}

/// Quiz step containing multiple questions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuizStep {
    pub id: Uuid,
    pub title: String,  // "Domain 1.1 Questions"
    pub domain: String,
    pub questions: Vec<QuizQuestion>,
    pub progress: Vec<QuestionProgress>,
}

/// Statistics for quiz performance
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuizStatistics {
    pub total_questions: usize,
    pub answered: usize,
    pub correct: usize,
    pub incorrect: usize,
    pub first_attempt_correct: usize,  // For score calculation
    pub score_percentage: f32,
}
```

### 2. Content Type System

```rust
/// Distinguish between tutorial and quiz content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepContent {
    Tutorial {
        description: String,
        notes: String,
        description_notes: String,
        evidence: Vec<Evidence>,
    },
    Quiz {
        quiz_data: QuizStep,
    },
}

/// Modified Step struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub id: Uuid,
    pub title: String,
    pub tags: Vec<String>,
    pub status: StepStatus,
    pub completed_at: Option<DateTime<Utc>>,
    pub content: StepContent,  // NEW: Either tutorial or quiz
}
```

## File Organization

### Question File Structure

```
data/
└── comptia_secplus/
    ├── 1.0-general-security/
    │   ├── 1.1-security-controls.txt
    │   ├── 1.2-security-concepts.txt
    │   ├── 1.3-change-management.txt
    │   └── 1.4-cryptography.txt
    ├── 2.0-threats-vulnerabilities/
    │   ├── 2.1-threat-actors.txt
    │   ├── 2.2-threat-vectors.txt
    │   ├── 2.3-vulnerability-types.txt
    │   ├── 2.4-attack-indicators.txt
    │   └── 2.5-vulnerability-scanning.txt
    ├── 3.0-security-architecture/
    │   ├── 3.1-secure-design.txt
    │   ├── 3.2-enterprise-infrastructure.txt
    │   ├── 3.3-secure-application.txt
    │   └── 3.4-resilience.txt
    ├── 4.0-security-operations/
    │   ├── 4.1-security-techniques.txt
    │   ├── 4.2-incident-response.txt
    │   ├── 4.3-investigation-sources.txt
    │   ├── 4.4-mitigation-techniques.txt
    │   └── 4.5-key-management.txt
    └── 5.0-governance-compliance/
        ├── 5.1-governance-elements.txt
        ├── 5.2-compliance-requirements.txt
        ├── 5.3-security-awareness.txt
        └── 5.4-security-policies.txt
```

### Question File Format (Pipe-Delimited)

```
# Lines starting with # are comments
# Format: question|answer_a|answer_b|answer_c|answer_d|correct_index|explanation|domain|subdomain

What is the primary purpose of encryption?|To compress data|To ensure confidentiality|To ensure availability|To authenticate users|1|Encryption's primary purpose is to ensure confidentiality by converting plaintext into ciphertext that cannot be read without the decryption key.|1.0 General Security Concepts|1.4 Cryptography Fundamentals

Which of the following is an example of multi-factor authentication?|Password only|Password + PIN|Password + Fingerprint|Username + Password|2|Multi-factor authentication requires credentials from two or more different categories: something you know (password), something you have (token), or something you are (biometric). Password + Fingerprint combines knowledge and biometric factors.|1.0 General Security Concepts|1.1 Security Controls
```

## UI Components

### 1. Quiz Widget (ui/quiz_widget.rs)

```rust
pub struct QuizWidget {
    question_label: Label,
    answer_radios: Vec<RadioButton>,
    check_button: Button,
    explanation_view: TextView,
    next_button: Button,
    prev_button: Button,
    stats_label: Label,
    current_question_index: usize,
    quiz_step: QuizStep,
}

impl QuizWidget {
    pub fn new() -> Self { /* ... */ }
    
    pub fn load_question(&mut self, index: usize) {
        // Display question text
        // Show 4 radio button options
        // Reset explanation visibility
        // Update navigation buttons
    }
    
    pub fn check_answer(&mut self) {
        // Compare selected radio with correct answer
        // Show explanation
        // Update progress
        // Disable further selection for this question
        // Calculate scoring impact
    }
    
    pub fn update_statistics(&mut self) {
        // Display: "25/100 answered | 20 correct (80%) | Score: 20/25"
    }
}
```

### 2. Conditional Rendering in detail_panel.rs

```rust
pub fn build_detail_panel(step: &Step) -> gtk4::Box {
    match &step.content {
        StepContent::Tutorial { description, notes, .. } => {
            // Existing tutorial UI with description, notes, canvas
            build_tutorial_panel(description, notes)
        }
        StepContent::Quiz { quiz_data } => {
            // New quiz UI with questions and answers
            build_quiz_panel(quiz_data)
        }
    }
}
```

## Quiz State Management

### StateManager Extensions (ui/state.rs)

```rust
impl StateManager {
    pub fn answer_question(&self, step_idx: usize, question_idx: usize, answer_idx: usize) {
        // Record answer
        // Check correctness
        // Update progress
        // Calculate if first_attempt_correct
        // Dispatch QuizAnswered event
    }
    
    pub fn view_explanation(&self, step_idx: usize, question_idx: usize) {
        // Mark explanation as viewed
        // If viewed before answering, set flag (affects scoring)
        // Dispatch ExplanationViewed event
    }
    
    pub fn get_quiz_statistics(&self, step_idx: usize) -> QuizStatistics {
        // Calculate stats for entire quiz step
        // Return answered/correct/incorrect counts
        // Calculate score percentage
    }
}
```

## Question Loading Strategy

### For 1000+ Questions: Lazy Loading

```rust
pub struct QuizLoader {
    data_dir: PathBuf,
    cache: HashMap<String, Vec<QuizQuestion>>,
}

impl QuizLoader {
    pub fn load_domain(&mut self, domain: &str) -> Result<Vec<QuizQuestion>> {
        // Check cache first
        if let Some(questions) = self.cache.get(domain) {
            return Ok(questions.clone());
        }
        
        // Load from txt files in domain folder
        let questions = self.parse_domain_files(domain)?;
        
        // Cache for future use
        self.cache.insert(domain.to_string(), questions.clone());
        
        Ok(questions)
    }
    
    fn parse_domain_files(&self, domain: &str) -> Result<Vec<QuizQuestion>> {
        // Read all .txt files in domain folder
        // Parse pipe-delimited format
        // Return Vec<QuizQuestion>
    }
}
```

### Alternative: Pagination (If Memory Constrained)

```rust
pub struct QuizPagination {
    questions_per_page: usize,  // e.g., 20
    current_page: usize,
    total_questions: usize,
}

impl QuizWidget {
    pub fn load_page(&mut self, page: usize) {
        let start = page * self.pagination.questions_per_page;
        let end = start + self.pagination.questions_per_page;
        let page_questions = &self.all_questions[start..end];
        self.display_questions(page_questions);
    }
}
```

## Scoring System

### Rules

1. **Full Points**: Answer correctly on first attempt WITHOUT viewing explanation first
2. **No Points**: View explanation before answering (learning mode)
3. **No Points**: Answer incorrectly (even if corrected later)
4. **Progress Tracking**: All answered questions tracked regardless of points

### Implementation

```rust
impl QuestionProgress {
    pub fn award_points(&self) -> bool {
        self.first_attempt_correct && !self.explanation_viewed_before_answer
    }
}

impl QuizStatistics {
    pub fn calculate_score(&self) -> f32 {
        if self.total_questions == 0 {
            return 0.0;
        }
        (self.first_attempt_correct as f32 / self.total_questions as f32) * 100.0
    }
}
```

## CompTIA Security+ Phase Structure

### Exam Domains (SY0-701)

1. **General Security Concepts (12%)** - ~120 questions
2. **Threats, Vulnerabilities, and Mitigations (22%)** - ~220 questions
3. **Security Architecture (18%)** - ~180 questions
4. **Security Operations (28%)** - ~280 questions
5. **Security Program Management and Oversight (20%)** - ~200 questions

### Phase Organization

```rust
pub fn create_comptia_secplus_phase() -> Phase {
    Phase {
        id: Uuid::new_v4(),
        name: "CompTIA Security+".to_string(),
        steps: vec![
            create_quiz_step("1.1 Security Controls", "1.0", load_questions("1.0-general-security/1.1-security-controls.txt")),
            create_quiz_step("1.2 Security Concepts", "1.0", load_questions("1.0-general-security/1.2-security-concepts.txt")),
            // ... more steps
            create_quiz_step("5.4 Security Policies", "5.0", load_questions("5.0-governance-compliance/5.4-security-policies.txt")),
        ],
        notes: String::new(),
    }
}
```

## Migration Strategy

### Backward Compatibility

```rust
// Old Step struct (existing sessions)
#[derive(Deserialize)]
struct StepV1 {
    id: Uuid,
    title: String,
    description: String,
    notes: String,
    // ... other fields
}

// New Step struct
#[derive(Deserialize)]
struct StepV2 {
    id: Uuid,
    title: String,
    content: StepContent,
    // ... other fields
}

// Migration during deserialization
impl Step {
    fn from_v1(old: StepV1) -> Self {
        Step {
            id: old.id,
            title: old.title,
            content: StepContent::Tutorial {
                description: old.description,
                notes: old.notes,
                // ... migrate other fields
            },
            // ...
        }
    }
}
```

### Serialization with #[serde(default)]

```rust
#[derive(Serialize, Deserialize)]
pub struct Step {
    pub id: Uuid,
    pub title: String,
    #[serde(default = "default_tutorial_content")]
    pub content: StepContent,
    // ...
}

fn default_tutorial_content() -> StepContent {
    StepContent::Tutorial {
        description: String::new(),
        notes: String::new(),
        description_notes: String::new(),
        evidence: Vec::new(),
    }
}
```

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_quiz_parser() {
        let line = "What is CIA triad?|Confidentiality Intelligence Availability|...|1|...";
        let question = parse_question_line(line).unwrap();
        assert_eq!(question.answers.len(), 4);
        assert!(question.answers[1].is_correct);
    }
    
    #[test]
    fn test_scoring_first_attempt() {
        let mut progress = QuestionProgress::new();
        progress.answer(1, true);  // Correct on first try
        assert!(progress.award_points());
    }
    
    #[test]
    fn test_scoring_explanation_viewed_first() {
        let mut progress = QuestionProgress::new();
        progress.view_explanation();
        progress.answer(1, true);  // Correct but explanation viewed first
        assert!(!progress.award_points());
    }
}
```

### Sample Data Files

Create `data/comptia_secplus/samples/` with 20-30 questions per domain for testing before adding full 1000+ questions.

## UI Flow

### Quiz Step Selection

1. User selects "CompTIA Security+" phase
2. User selects step (e.g., "1.1 Security Controls")
3. Detail panel shows quiz UI instead of description/notes/canvas

### Answering Flow

1. Question displayed with 4 radio button options (A, B, C, D)
2. User selects answer
3. User clicks "Check Answer" button
4. Correct/Incorrect indicator shown
5. Explanation displayed automatically
6. Navigation buttons active: "Next Question" / "Previous Question"
7. Statistics updated: "3/10 answered | 2 correct (66%)"

### Navigation

- **Next/Previous**: Move between questions in current step
- **Question List**: Sidebar showing all questions with status indicators (✓ correct, ✗ incorrect, ○ unanswered)
- **Filter**: Show only unanswered, only incorrect, or all questions
- **Jump**: Click question number to jump directly

## Performance Considerations

### Memory Management

- **Lazy Loading**: Load domain questions on-demand, not all 1000+ at startup
- **Cache Strategy**: Keep recently accessed domains in memory
- **Pagination**: Option to page through questions (20-50 per page)

### File I/O

- Parse question files once, cache in memory
- Use buffered reading for large files
- Consider binary format (bincode) for faster loading if txt parsing becomes bottleneck

### UI Responsiveness

- Async question loading with progress indicator
- Incremental UI updates during large question set loads
- Debounce statistics recalculation

## Future Enhancements (Out of Scope)

1. **Timed Quiz Mode**: Simulate exam conditions with time limits
2. **Flashcard Mode**: Quick review without scoring
3. **Export Results**: PDF report of quiz performance
4. **Spaced Repetition**: Algorithm to prioritize weak areas
5. **Question Bookmarking**: Mark questions for review
6. **Custom Quiz**: User-selected questions from multiple domains
7. **Collaborative Features**: Share custom question sets

## Implementation Phases

### Phase 1: Data Model & Parsing (Steps 1-4)

- Define quiz data structures
- Create content type system
- Implement question parser
- Set up file organization

### Phase 2: UI Components (Steps 5-6)

- Create quiz widget
- Implement conditional rendering
- Basic question display and answer selection

### Phase 3: State & Progress (Steps 7-9)

- Quiz state management
- Progress tracking
- Scoring logic

### Phase 4: CompTIA Integration (Steps 10-12)

- Create CompTIA phase module
- Load question files
- Integrate with existing phase system

### Phase 5: Advanced Features (Steps 13-14)

- Statistics display
- Navigation improvements
- Filtering and search

### Phase 6: Testing & Polish (Steps 15-18)

- Unit tests
- Sample data
- Serialization updates
- Documentation

## Conclusion

This design supports 1000+ questions efficiently through:

- Lazy loading by domain
- Clear separation of tutorial vs quiz content
- Comprehensive progress tracking
- Fair scoring system
- Backward-compatible data model changes
- Scalable file organization

Total estimated effort: 15-20 hours for full implementation.
