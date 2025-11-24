pub mod bug_bounty_hunting;
pub mod ceh;
pub mod cloud_identity;
pub mod cloud_native;
pub mod comptia_secplus;
pub mod exploitation;
pub mod modern_web;
pub mod pentest_exam;
pub mod post_exploitation;
pub mod purple_team_threat_hunting;
pub mod reconnaissance;
pub mod red_team_tradecraft;
pub mod reporting;
pub mod supply_chain;
pub mod vulnerability_analysis;

use crate::model::{Phase, Step};
use uuid::Uuid;

/// Load all tutorial phases with their default content
pub fn load_tutorial_phases() -> Vec<Phase> {
    vec![
        create_reconnaissance_phase(),
        create_vulnerability_analysis_phase(),
        create_exploitation_phase(),
        create_post_exploitation_phase(),
        create_cloud_iam_phase(),
        create_practical_oauth_phase(),
        create_sso_federation_phase(),
        create_modern_api_phase(),
        create_jwt_spa_phase(),
        create_websocket_grpc_phase(),
        create_reporting_phase(),
        create_bug_bounty_hunting_phase(),
        create_comptia_secplus_phase(),
        create_pentest_exam_phase(),
        create_ceh_phase(),
        create_container_breakout_phase(),
        create_kubernetes_attacks_phase(),
        create_cicd_pipeline_attacks_phase(),
        create_sbom_analysis_phase(),
        create_dependency_confusion_phase(),
        create_artifact_integrity_phase(),
        create_red_team_tradecraft_phase(),
        create_purple_team_threat_hunting_phase(),
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

fn create_cloud_iam_phase() -> Phase {
    let steps = cloud_identity::get_cloud_iam_steps();

    Phase {
        id: Uuid::new_v4(),
        name: "Cloud IAM Abuse 101".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_practical_oauth_phase() -> Phase {
    let steps = cloud_identity::get_practical_oauth_steps();

    Phase {
        id: Uuid::new_v4(),
        name: "Practical OAuth/OIDC Abuse".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_sso_federation_phase() -> Phase {
    let steps = cloud_identity::get_sso_federation_steps();

    Phase {
        id: Uuid::new_v4(),
        name: "SSO & Federation Misconfigurations".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_modern_api_phase() -> Phase {
    let steps = modern_web::get_modern_api_steps();

    Phase {
        id: Uuid::new_v4(),
        name: "Modern API & GraphQL Testing Playbook".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_jwt_spa_phase() -> Phase {
    let steps = modern_web::get_jwt_spa_steps();

    Phase {
        id: Uuid::new_v4(),
        name: "JWT & SPA Security".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_websocket_grpc_phase() -> Phase {
    let steps = modern_web::get_websocket_grpc_steps();

    Phase {
        id: Uuid::new_v4(),
        name: "Real-Time/WebSocket Testing".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_container_breakout_phase() -> Phase {
    let steps = vec![cloud_native::container_breakout_phase()];

    Phase {
        id: Uuid::new_v4(),
        name: "Container Breakout Playbook".to_string(),
        steps,
        notes: String::new(),
    }
}

fn create_kubernetes_attacks_phase() -> Phase {
    let steps = vec![cloud_native::kubernetes_attacks_phase()];

    Phase {
        id: Uuid::new_v4(),
        name: "Kubernetes Pod-to-Cluster Attacks".to_string(),
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
