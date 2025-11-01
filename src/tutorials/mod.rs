pub mod reconnaissance;
pub mod vulnerability_analysis;
pub mod exploitation;
pub mod post_exploitation;
pub mod reporting;
pub mod bug_bounty_hunting;

use crate::model::{Phase, Step, StepStatus};
use uuid::Uuid;

/// Load all tutorial phases with their default content
pub fn load_tutorial_phases() -> Vec<Phase> {
    vec![
        create_reconnaissance_phase(),
        create_vulnerability_analysis_phase(),
        create_exploitation_phase(),
        create_post_exploitation_phase(),
        create_reporting_phase(),
        create_bug_bounty_hunting_phase(),
    ]
}

fn create_reconnaissance_phase() -> Phase {
    let steps = reconnaissance::RECONNAISSANCE_STEPS
        .iter()
        .map(|(title, description)| Step {
            id: Uuid::new_v4(),
            title: title.to_string(),
            description: description.to_string(),
            tags: vec!["recon".to_string()],
            status: StepStatus::Todo,
            completed_at: None,
            notes: String::new(),
            description_notes: String::new(),
            evidence: vec![],
        })
        .collect();

    Phase {
        id: Uuid::new_v4(),
        name: "Reconnaissance".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_vulnerability_analysis_phase() -> Phase {
    let steps = vulnerability_analysis::VULNERABILITY_ANALYSIS_STEPS
        .iter()
        .map(|(title, description)| Step {
            id: Uuid::new_v4(),
            title: title.to_string(),
            description: description.to_string(),
            tags: vec!["vuln".to_string()],
            status: StepStatus::Todo,
            completed_at: None,
            notes: String::new(),
            description_notes: String::new(),
            evidence: vec![],
        })
        .collect();

    Phase {
        id: Uuid::new_v4(),
        name: "Vulnerability Analysis".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_exploitation_phase() -> Phase {
    let steps = exploitation::EXPLOITATION_STEPS
        .iter()
        .map(|(title, description)| Step {
            id: Uuid::new_v4(),
            title: title.to_string(),
            description: description.to_string(),
            tags: vec!["exploit".to_string()],
            status: StepStatus::Todo,
            completed_at: None,
            notes: String::new(),
            description_notes: String::new(),
            evidence: vec![],
        })
        .collect();

    Phase {
        id: Uuid::new_v4(),
        name: "Exploitation".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_post_exploitation_phase() -> Phase {
    let steps = post_exploitation::POST_EXPLOITATION_STEPS
        .iter()
        .map(|(title, description)| Step {
            id: Uuid::new_v4(),
            title: title.to_string(),
            description: description.to_string(),
            tags: vec!["post".to_string()],
            status: StepStatus::Todo,
            completed_at: None,
            notes: String::new(),
            description_notes: String::new(),
            evidence: vec![],
        })
        .collect();

    Phase {
        id: Uuid::new_v4(),
        name: "Post-Exploitation".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_reporting_phase() -> Phase {
    let steps = reporting::REPORTING_STEPS
        .iter()
        .map(|(title, description)| Step {
            id: Uuid::new_v4(),
            title: title.to_string(),
            description: description.to_string(),
            tags: vec!["report".to_string()],
            status: StepStatus::Todo,
            completed_at: None,
            notes: String::new(),
            description_notes: String::new(),
            evidence: vec![],
        })
        .collect();

    Phase {
        id: Uuid::new_v4(),
        name: "Reporting".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_bug_bounty_hunting_phase() -> Phase {
    let steps = bug_bounty_hunting::STEPS
        .iter()
        .map(|(title, description)| Step {
            id: Uuid::new_v4(),
            title: title.to_string(),
            description: description.to_string(),
            tags: vec!["bugbounty".to_string()],
            status: StepStatus::Todo,
            completed_at: None,
            notes: String::new(),
            description_notes: String::new(),
            evidence: vec![],
        })
        .collect();

    Phase {
        id: Uuid::new_v4(),
        name: "Bug Bounty Hunting".to_string(),
        steps,
        notes: String::new(),
    }
}