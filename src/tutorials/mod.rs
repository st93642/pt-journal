pub mod reconnaissance;
pub mod vulnerability_analysis;
pub mod exploitation;
pub mod post_exploitation;
pub mod reporting;
pub mod bug_bounty_hunting;
pub mod comptia_secplus;
pub mod pentest_exam;
pub mod ceh;

use crate::model::{Phase, Step};
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
        create_comptia_secplus_phase(),
        create_pentest_exam_phase(),
        create_ceh_phase(),
    ]
}

fn create_reconnaissance_phase() -> Phase {
    let steps = reconnaissance::RECONNAISSANCE_STEPS
        .iter()
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec!["recon".to_string()],
            )
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
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec!["vuln".to_string()],
            )
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
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec!["exploit".to_string()],
            )
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
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec!["post".to_string()],
            )
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
        .map(|(title, description)| {
            Step::new_tutorial(
                Uuid::new_v4(),
                title.to_string(),
                description.to_string(),
                vec!["report".to_string()],
            )
        })
        .collect();

    Phase {
        id: Uuid::new_v4(),
        name: "Reporting".to_string(),
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
    let steps = bug_bounty_hunting::STEPS
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
        steps,
        notes: String::new(),
    }
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