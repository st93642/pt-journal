// Bug Bounty Hunting - Modular Tutorial System
// Comprehensive methodology for ethical hacking programs

use crate::model::{Phase, Step};
use uuid::Uuid;

// Import all bug bounty hunting modules
mod program_selection_reconnaissance;
mod asset_enumeration_mapping;
mod vulnerability_research_testing;
mod proof_of_concept_development;
mod report_writing_submission;
mod triage_communication;
mod disclosure_reputation_building;
mod automation_efficiency;

// Re-export all module steps
pub use program_selection_reconnaissance::PROGRAM_SELECTION_RECONNAISSANCE_STEPS;
pub use asset_enumeration_mapping::ASSET_ENUMERATION_MAPPING_STEPS;
pub use vulnerability_research_testing::VULNERABILITY_RESEARCH_TESTING_STEPS;
pub use proof_of_concept_development::PROOF_OF_CONCEPT_DEVELOPMENT_STEPS;
pub use report_writing_submission::REPORT_WRITING_SUBMISSION_STEPS;
pub use triage_communication::TRIAGE_COMMUNICATION_STEPS;
pub use disclosure_reputation_building::DISCLOSURE_REPUTATION_BUILDING_STEPS;
pub use automation_efficiency::AUTOMATION_EFFICIENCY_STEPS;

// Combined bug bounty hunting steps
pub const BUG_BOUNTY_HUNTING_STEPS: &[(&str, &str)] = &[
    PROGRAM_SELECTION_RECONNAISSANCE_STEPS[0],
    ASSET_ENUMERATION_MAPPING_STEPS[0],
    VULNERABILITY_RESEARCH_TESTING_STEPS[0],
    PROOF_OF_CONCEPT_DEVELOPMENT_STEPS[0],
    REPORT_WRITING_SUBMISSION_STEPS[0],
    TRIAGE_COMMUNICATION_STEPS[0],
    DISCLOSURE_REPUTATION_BUILDING_STEPS[0],
    AUTOMATION_EFFICIENCY_STEPS[0],
];

pub fn load_phase() -> Phase {
    let steps: Vec<Step> = BUG_BOUNTY_HUNTING_STEPS
        .iter()
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec!["bugbounty".to_string()],
            )
        })
        .collect();

    Phase {
        id: Uuid::new_v4(),
        name: "Bug Bounty Hunting".to_string(),
        notes: String::new(),
        steps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bug_bounty_phase_loads() {
        let phase = load_phase();
        assert_eq!(phase.name, "Bug Bounty Hunting");
        assert_eq!(phase.steps.len(), 8);
    }

    #[test]
    fn test_step_content_structure() {
        for (title, description) in BUG_BOUNTY_HUNTING_STEPS {
            assert!(
                description.contains("OBJECTIVE:"),
                "Step '{}' missing OBJECTIVE section",
                title
            );
            assert!(
                description.contains("STEP-BY-STEP PROCESS:"),
                "Step '{}' missing STEP-BY-STEP PROCESS section",
                title
            );
            assert!(
                description.contains("WHAT TO LOOK FOR:"),
                "Step '{}' missing WHAT TO LOOK FOR section",
                title
            );
            assert!(
                description.contains("COMMON PITFALLS:"),
                "Step '{}' missing COMMON PITFALLS section",
                title
            );
        }
    }
}
