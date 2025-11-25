/*****************************************************************************/
/*                                                                           */
/*  lib.rs                                               TTTTTTTT SSSSSSS II */
/*                                                          TT    SS      II */
/*  By: st93642@students.tsi.lv                             TT    SSSSSSS II */
/*                                                          TT         SS II */
/*  Created: Nov 21 2025 23:42 st93642                      TT    SSSSSSS II */
/*  Updated: Nov 25 2025 12:58 st93642                                       */
/*                                                                           */
/*   Transport and Telecommunication Institute - Riga, Latvia                */
/*                       https://tsi.lv                                      */
/*****************************************************************************/

pub mod dispatcher;
pub mod model;
pub mod quiz;
pub mod store;
pub mod tools;
pub mod tutorials;
pub mod ui;

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use std::fs;
    use tempfile::TempDir;
    use uuid::Uuid;

    // Model Tests
    mod model_tests {
        use super::*;
        use crate::model::*;

        #[test]
        fn test_default_app_model() {
            let model = AppModel::default();
            assert_eq!(model.selected_phase, 0);
            assert_eq!(model.selected_step, Some(0));
            assert!(model.current_path.is_none());
            assert_eq!(model.session.phases.len(), 24); // 24 phases (added serverless security)
        }

        #[test]
        fn test_session_creation() {
            let session = Session::default();
            assert!(!session.name.is_empty());
            assert_eq!(session.phases.len(), 24); // 24 phases (added serverless security)
            assert!(session.notes_global.is_empty());
        }

        #[test]
        fn test_phase_structure() {
            let session = Session::default();

            // Test Reconnaissance phase
            let recon_phase = &session.phases[0];
            assert_eq!(recon_phase.name, "Reconnaissance");
            assert_eq!(recon_phase.steps.len(), 16); // 16 reconnaissance steps

            // Test Vulnerability Analysis phase
            let vuln_phase = &session.phases[1];
            assert_eq!(vuln_phase.name, "Vulnerability Analysis");
            assert_eq!(vuln_phase.steps.len(), 5); // 5 vulnerability analysis steps

            // Test Exploitation phase
            let exploit_phase = &session.phases[2];
            assert_eq!(exploit_phase.name, "Exploitation");
            assert_eq!(exploit_phase.steps.len(), 4); // 4 exploitation steps

            // Test Post-Exploitation phase
            let post_phase = &session.phases[3];
            assert_eq!(post_phase.name, "Post-Exploitation");
            assert_eq!(post_phase.steps.len(), 4); // 4 post-exploitation steps

            // Test Cloud IAM Abuse 101 phase
            let cloud_iam_phase = &session.phases[4];
            assert_eq!(cloud_iam_phase.name, "Cloud IAM Abuse 101");
            assert!(!cloud_iam_phase.steps.is_empty()); // Has tutorial and quiz steps

            // Test Reporting phase
            let report_phase = &session.phases[10];
            assert_eq!(report_phase.name, "Reporting");
            assert_eq!(report_phase.steps.len(), 4); // 4 reporting steps

            // Test Container & Kubernetes Security phase
            let container_security_phase = &session.phases[11];
            assert_eq!(
                container_security_phase.name,
                "Container & Kubernetes Security"
            );
            assert!(!container_security_phase.steps.is_empty()); // Has tutorial and quiz steps

            // Test Bug Bounty Hunting phase
            let bug_bounty_phase = &session.phases[13];
            assert_eq!(bug_bounty_phase.name, "Bug Bounty Hunting");
            assert!(!bug_bounty_phase.steps.is_empty()); // Has steps

            // Test CompTIA Security+ phase
            let comptia_phase = &session.phases[14];
            assert_eq!(comptia_phase.name, "CompTIA Security+");
            assert_eq!(comptia_phase.steps.len(), 23); // All 5 domains: D1(4) + D2(5) + D3(4) + D4(5) + D5(5)
        }

        #[test]
        fn test_step_properties() {
            let session = Session::default();
            let first_step = &session.phases[0].steps[0];

            // Test basic properties
            assert!(!first_step.title.is_empty());
            assert!(!first_step.get_description().is_empty()); // Use get_description() for StepContent
            assert!(first_step.id != Uuid::nil());
            assert_eq!(first_step.status, StepStatus::Todo);
            assert!(first_step.completed_at.is_none());
            assert!(first_step.get_notes().is_empty()); // Use get_notes() for StepContent
            assert!(first_step.get_evidence().is_empty()); // Use get_evidence() for StepContent
        }

        #[test]
        fn test_step_status_transitions() {
            let mut step = Step::new_tutorial(
                Uuid::new_v4(),
                "Test Step".to_string(),
                "Test description".to_string(),
                vec!["test".to_string()],
            );

            // Test Todo -> Done
            step.status = StepStatus::Done;
            assert_matches!(step.status, StepStatus::Done);

            // Test Done -> Todo
            step.status = StepStatus::Todo;
            assert_matches!(step.status, StepStatus::Todo);
        }

        #[test]
        fn test_step_with_content() {
            let session = Session::default();

            // Test that all tutorial steps have comprehensive content
            for phase in &session.phases {
                for step in &phase.steps {
                    // Each step should have a meaningful title
                    assert!(step.title.len() > 5, "Step title too short: {}", step.title);

                    // Only check tutorial steps for description format
                    if step.is_tutorial() {
                        let description = step.get_description();
                        // Each tutorial step should have detailed description
                        assert!(
                            description.len() > 100,
                            "Step description too short for: {}",
                            step.title
                        );

                        // Description should contain key sections
                        assert!(
                            description.contains("OBJECTIVE"),
                            "Missing OBJECTIVE in: {}",
                            step.title
                        );
                        assert!(
                            description.contains("STEP-BY-STEP PROCESS")
                                || description.contains("STEP-BY-STEP"),
                            "Missing STEP-BY-STEP in: {}",
                            step.title
                        );
                        // Most tutorials have "WHAT TO LOOK FOR" but Cloud & Identity tutorials have different sections
                        assert!(
                            description.contains("WHAT TO LOOK FOR")
                                || description.contains("DETECTION AND DEFENSE")
                                || description.contains("REMEDIATION")
                                || description.contains("TOOLS AND RESOURCES"),
                            "Missing educational sections in: {}",
                            step.title
                        );
                    } else if step.is_quiz() {
                        // Quiz steps should have questions
                        if let Some(quiz_step) = step.get_quiz_step() {
                            assert!(
                                !quiz_step.questions.is_empty(),
                                "Quiz step has no questions: {}",
                                step.title
                            );
                        }
                    }
                }
            }
        }

        #[test]
        fn test_unique_step_ids() {
            let session = Session::default();
            let mut ids = std::collections::HashSet::new();

            for phase in &session.phases {
                for step in &phase.steps {
                    assert!(ids.insert(step.id), "Duplicate step ID found: {}", step.id);
                }
            }
        }

        #[test]
        fn test_model_navigation() {
            let mut model = AppModel::default();

            // Test phase navigation
            assert_eq!(model.selected_phase, 0);
            model.selected_phase = 1;
            assert_eq!(model.selected_phase, 1);

            // Test step navigation
            assert_eq!(model.selected_step, Some(0));
            model.selected_step = Some(2);
            assert_eq!(model.selected_step, Some(2));

            // Test invalid phase bounds
            model.selected_phase = 10; // Beyond available phases
                                       // Should not panic, just store the value
            assert_eq!(model.selected_phase, 10);
        }
    }

    // Store Tests
    mod store_tests {
        use super::*;
        use crate::model::*;
        use crate::store;

        #[test]
        fn test_save_and_load_session() {
            let temp_dir = TempDir::new().unwrap();
            let session_folder = temp_dir.path().join("test_session");
            let session_file = session_folder.join("session.json");

            // Create a test session
            let mut session = Session::default();
            session.name = "Test Session".to_string();
            session.notes_global = "Test notes".to_string();

            // Modify a step
            if let Some(step) = session.phases[0].steps.get_mut(0) {
                step.status = StepStatus::Done;
                step.set_notes("Test step notes".to_string());
            }

            // Save to folder structure
            store::save_session(&session_folder, &session).unwrap();

            // Load from session.json
            let loaded_session = store::load_session(&session_file).unwrap();

            // Verify data integrity
            assert_eq!(loaded_session.name, session.name);
            assert_eq!(loaded_session.notes_global, session.notes_global);
            assert_eq!(loaded_session.phases.len(), session.phases.len());

            // Verify modified step
            if let Some(loaded_step) = loaded_session.phases[0].steps.first() {
                if let Some(original_step) = session.phases[0].steps.first() {
                    assert_eq!(loaded_step.status, original_step.status);
                    assert_eq!(loaded_step.get_notes(), original_step.get_notes());
                    assert_eq!(loaded_step.title, original_step.title);
                    assert_eq!(
                        loaded_step.get_description(),
                        original_step.get_description()
                    );
                }
            }
        }

        #[test]
        fn test_save_load_with_timestamps() {
            let temp_dir = TempDir::new().unwrap();
            let session_folder = temp_dir.path().join("timestamp_test");
            let session_path = session_folder.join("session.json");

            let session = Session::default();
            let original_time = session.created_at;

            // Save (now creates folder structure)
            store::save_session(&session_folder, &session).unwrap();

            // Load from session.json file
            let loaded_session = store::load_session(&session_path).unwrap();

            // Timestamps should be preserved
            assert_eq!(loaded_session.created_at, original_time);
        }

        #[test]
        fn test_save_to_nonexistent_directory() {
            let temp_dir = TempDir::new().unwrap();
            let session_folder = temp_dir
                .path()
                .join("nonexistent")
                .join("subdir")
                .join("my_session");
            let session_file = session_folder.join("session.json");

            let session = Session::default();

            // Should succeed when creating parent directories (now creates folder structure)
            let result = store::save_session(&session_folder, &session);
            assert!(
                result.is_ok(),
                "Saving to nonexistent directory should create directories and succeed"
            );

            // Verify the folder and file were created
            assert!(
                session_folder.exists(),
                "Session folder should exist after saving"
            );
            assert!(
                session_file.exists(),
                "Session file should exist after saving"
            );
            assert!(
                session_folder.join("evidence").exists(),
                "Evidence folder should exist after saving"
            );
        }

        #[test]
        fn test_load_nonexistent_file() {
            let temp_dir = TempDir::new().unwrap();
            let nonexistent_path = temp_dir.path().join("nonexistent.json");

            // Should fail when trying to load nonexistent file
            let result = store::load_session(&nonexistent_path);
            assert!(result.is_err());
        }

        #[test]
        fn test_load_invalid_json() {
            let temp_dir = TempDir::new().unwrap();
            let invalid_path = temp_dir.path().join("invalid.json");

            // Write invalid JSON
            fs::write(&invalid_path, "invalid json content").unwrap();

            // Should fail when trying to load invalid JSON
            let result = store::load_session(&invalid_path);
            assert!(result.is_err());
        }

        #[test]
        fn test_session_data_integrity() {
            let temp_dir = TempDir::new().unwrap();
            let session_folder = temp_dir.path().join("integrity_test");
            let session_file = session_folder.join("session.json");

            let mut session = Session::default();

            // Add some test data
            session.notes_global = "Global test notes".to_string();

            // Modify multiple steps
            for phase in &mut session.phases {
                for step in &mut phase.steps {
                    step.set_notes(format!("Notes for {}", step.title));
                    if step.title.contains("enumeration") {
                        step.status = StepStatus::Done;
                    }
                }
            }

            // Save to folder structure and load from session.json
            store::save_session(&session_folder, &session).unwrap();
            let loaded_session = store::load_session(&session_file).unwrap();

            // Verify all data is preserved
            assert_eq!(loaded_session.notes_global, session.notes_global);
            assert_eq!(loaded_session.phases.len(), session.phases.len());

            for (original_phase, loaded_phase) in session.phases.iter().zip(&loaded_session.phases)
            {
                assert_eq!(loaded_phase.name, original_phase.name);
                assert_eq!(loaded_phase.steps.len(), original_phase.steps.len());

                for (original_step, loaded_step) in
                    original_phase.steps.iter().zip(&loaded_phase.steps)
                {
                    assert_eq!(loaded_step.title, original_step.title);
                    assert_eq!(loaded_step.description, original_step.description);
                    assert_eq!(loaded_step.status, original_step.status);
                    assert_eq!(loaded_step.get_notes(), original_step.get_notes());
                    assert_eq!(loaded_step.tags, original_step.tags);
                    assert_eq!(loaded_step.evidence, original_step.evidence);
                }
            }
        }

        #[test]
        fn test_quiz_progress_persistence() {
            use crate::model::*;
            use crate::quiz::parse_question_line;
            use chrono::Utc;

            let temp_dir = TempDir::new().unwrap();
            let session_folder = temp_dir.path().join("quiz_progress_test");
            let session_file = session_folder.join("session.json");

            // Create a session with a quiz step
            let mut session = Session::default();

            // Create a simple quiz step
            let questions = vec![
                parse_question_line(
                    "What is 2+2?|4|3|5|6|0|Addition is commutative|Math|Arithmetic",
                )
                .unwrap(),
                parse_question_line("What is 3+3?|6|5|7|8|0|Simple arithmetic|Math|Arithmetic")
                    .unwrap(),
                parse_question_line("What is 4+4?|8|7|9|10|0|More addition|Math|Arithmetic")
                    .unwrap(),
            ];

            let quiz_step = QuizStep::new(
                Uuid::new_v4(),
                "Math Quiz".to_string(),
                "Basic Arithmetic".to_string(),
                questions,
            );

            let step = Step::new_quiz(
                Uuid::new_v4(),
                "Math Quiz Step".to_string(),
                vec!["quiz".to_string(), "test".to_string()],
                quiz_step,
            );

            // Replace first step with our quiz step
            session.phases[0].steps[0] = step;

            // Simulate answering questions
            if let Some(quiz_step) = session.phases[0].steps[0].quiz_mut_safe() {
                // Answer question 0 correctly
                if let Some(progress) = quiz_step.progress.get_mut(0) {
                    progress.answered = true;
                    progress.selected_answer_index = Some(0); // Correct answer
                    progress.is_correct = Some(true);
                    progress.attempts = 1;
                    progress.first_attempt_correct = true;
                    progress.last_attempted = Some(Utc::now());
                }

                // Answer question 1 incorrectly
                if let Some(progress) = quiz_step.progress.get_mut(1) {
                    progress.answered = true;
                    progress.selected_answer_index = Some(1); // Wrong answer
                    progress.is_correct = Some(false);
                    progress.attempts = 1;
                    progress.first_attempt_correct = false;
                    progress.last_attempted = Some(Utc::now());
                }

                // View explanation for question 2 without answering
                if let Some(progress) = quiz_step.progress.get_mut(2) {
                    progress.explanation_viewed_before_answer = true;
                }
            }

            // Save to folder structure
            store::save_session(&session_folder, &session).unwrap();

            // Load from session.json
            let loaded_session = store::load_session(&session_file).unwrap();

            // Verify quiz progress was preserved
            if let Some(loaded_quiz_step) = loaded_session.phases[0].steps[0].get_quiz_step() {
                assert_eq!(loaded_quiz_step.questions.len(), 3);
                assert_eq!(loaded_quiz_step.progress.len(), 3);

                // Check question 0 progress (correct answer)
                let progress_0 = &loaded_quiz_step.progress[0];
                assert!(progress_0.answered);
                assert_eq!(progress_0.selected_answer_index, Some(0));
                assert_eq!(progress_0.is_correct, Some(true));
                assert_eq!(progress_0.attempts, 1);
                assert!(progress_0.first_attempt_correct);
                assert!(!progress_0.explanation_viewed_before_answer);
                assert!(progress_0.awards_points());

                // Check question 1 progress (incorrect answer)
                let progress_1 = &loaded_quiz_step.progress[1];
                assert!(progress_1.answered);
                assert_eq!(progress_1.selected_answer_index, Some(1));
                assert_eq!(progress_1.is_correct, Some(false));
                assert_eq!(progress_1.attempts, 1);
                assert!(!progress_1.first_attempt_correct);
                assert!(!progress_1.awards_points());

                // Check question 2 progress (viewed explanation)
                let progress_2 = &loaded_quiz_step.progress[2];
                assert!(!progress_2.answered);
                assert!(progress_2.explanation_viewed_before_answer);
                assert!(!progress_2.awards_points());

                // Verify statistics calculation
                let stats = loaded_quiz_step.statistics();
                assert_eq!(stats.total_questions, 3);
                assert_eq!(stats.answered, 2);
                assert_eq!(stats.correct, 1);
                assert_eq!(stats.incorrect, 1);
                assert_eq!(stats.first_attempt_correct, 1);
                assert!((stats.score_percentage - (100.0 / 3.0)).abs() < 0.01); // Allow floating point tolerance
            } else {
                panic!("Expected quiz step, got tutorial step");
            }
        }
    }

    // Integration Tests
    mod integration_tests {
        use super::*;
        use crate::model::*;
        use crate::store;
        use crate::tutorials::container_security::CONTAINER_SECURITY_PHASE;
        use chrono::Utc;

        #[test]
        fn test_full_session_workflow() {
            let temp_dir = TempDir::new().unwrap();
            let session_folder = temp_dir.path().join("workflow_test");
            let session_file = session_folder.join("session.json");

            // Create and modify session
            let mut session = Session::default();
            session.name = "Integration Test Session".to_string();

            // Simulate user workflow: complete some reconnaissance steps
            for step in &mut session.phases[0].steps[0..3] {
                // First 3 recon steps
                step.status = StepStatus::Done;
                step.set_notes(format!("Completed: {}", step.title));
            }

            // Add phase notes
            session.phases[0].notes = "Reconnaissance phase completed".to_string();

            // Save to folder structure
            store::save_session(&session_folder, &session).unwrap();

            // Simulate app restart - load from session.json
            let loaded_session = store::load_session(&session_file).unwrap();

            // Verify workflow state is preserved
            assert_eq!(loaded_session.name, "Integration Test Session");
            assert_eq!(
                loaded_session.phases[0].notes,
                "Reconnaissance phase completed"
            );

            // Verify completed steps
            for i in 0..3 {
                assert_matches!(loaded_session.phases[0].steps[i].status, StepStatus::Done);
                assert!(loaded_session.phases[0].steps[i]
                    .get_notes()
                    .starts_with("Completed:"));
            }

            // Verify other steps remain todo
            for i in 3..loaded_session.phases[0].steps.len() {
                assert_matches!(loaded_session.phases[0].steps[i].status, StepStatus::Todo);
            }
        }

        #[test]
        fn test_phase_progression_workflow() {
            let session = Session::default();

            // Verify logical phase progression (first 10 phases are pentesting methodology, next are specialized)
            let phase_names = [
                "Reconnaissance",
                "Vulnerability Analysis",
                "Exploitation",
                "Post-Exploitation",
                "Cloud IAM Abuse 101",
                "Practical OAuth/OIDC Abuse",
                "SSO & Federation Misconfigurations",
                "Modern API & GraphQL Testing Playbook",
                "JWT & SPA Security",
                "Real-Time/WebSocket Testing",
                "Reporting",
                "Container & Kubernetes Security",
                "Serverless Security",
                "Bug Bounty Hunting",
                "CompTIA Security+",
                "CompTIA PenTest+",
                "Certified Ethical Hacker (CEH)",
                "CI-CD Pipeline Attacks",
                "SBOM Generation & Analysis",
                "Dependency Confusion & Typosquatting",
                "Artifact Integrity Checks",
                "Red Team Tradecraft",
                "Purple Team/Threat Hunting",
                "AI & LLM Security",
            ];
            for (idx, expected_name) in phase_names.iter().enumerate() {
                assert_eq!(session.phases[idx].name, *expected_name);
            }

            // Verify step counts are reasonable for the core pentesting phases
            let expected_step_counts = [
                16, 5, 4, 4, 2, 1, 1, 3, 3, 3, 4, 6, 7, 8, 23, 32, 24, 1, 1, 1, 1, 10, 10, 7,
            ]; // Updated for all phases including serverless security (24 total phases)
            for (idx, &expected_count) in expected_step_counts.iter().enumerate() {
                assert_eq!(session.phases[idx].steps.len(), expected_count);
            }

            // Cloud IAM Abuse 101 phase should include tutorial + quiz steps
            assert!(session.phases[4].steps.len() >= 2);

            // Container & Kubernetes Security phase should have steps
            assert!(!session.phases[11].steps.is_empty());

            // Bug Bounty Hunting phase should have steps
            assert!(!session.phases[13].steps.is_empty());

            // CompTIA Security+ phase should have quiz steps
            assert_eq!(session.phases[14].steps.len(), 23); // All 5 domains: D1(4) + D2(5) + D3(4) + D4(5) + D5(5)
        }

        #[test]
        fn test_step_content_completeness() {
            let session = Session::default();

            // Cloud Identity Security tutorials have a different structure
            const CLOUD_IDENTITY_PHASES: [&str; 7] = [
                "Cloud IAM Abuse 101",
                "Practical OAuth/OIDC Abuse",
                "SSO & Federation Misconfigurations",
                "Modern API & GraphQL Testing Playbook",
                "JWT & SPA Security",
                "Real-Time/WebSocket Testing",
                "AI & LLM Security",
            ];

            for phase in &session.phases {
                for step in &phase.steps {
                    // Only check tutorial steps
                    if step.is_tutorial() {
                        let description = step.get_description();

                        // All tutorials must have OBJECTIVE
                        assert!(
                            description.contains("OBJECTIVE"),
                            "Step '{}' missing OBJECTIVE",
                            step.title
                        );

                        // All tutorials must have procedural content
                        assert!(
                            description.contains("STEP-BY-STEP"),
                            "Step '{}' missing STEP-BY-STEP",
                            step.title
                        );

                        // Cloud Identity tutorials have different structure
                        if CLOUD_IDENTITY_PHASES.contains(&phase.name.as_str()) {
                            // Cloud tutorials should have detection, remediation, or resources sections
                            assert!(
                                description.contains("DETECTION")
                                    || description.contains("REMEDIATION")
                                    || description.contains("TOOLS AND RESOURCES"),
                                "Step '{}' missing educational sections",
                                step.title
                            );
                        } else if phase.name.as_str() == CONTAINER_SECURITY_PHASE {
                            // Container security tutorials should have WHAT TO LOOK FOR or COMMON PITFALLS
                            assert!(
                                description.contains("WHAT TO LOOK FOR")
                                    || description.contains("COMMON PITFALLS")
                                    || description.contains("DETECTION")
                                    || description.contains("REMEDIATION"),
                                "Step '{}' missing analysis sections",
                                step.title
                            );
                        }

                        // Verify step has reasonable content length
                        assert!(
                            description.len() > 200,
                            "Step '{}' description too short",
                            step.title
                        );
                    }
                }
            }
        }

        #[test]
        fn test_methodology_coverage() {
            let session = Session::default();

            // Test that all major pentesting areas are covered
            let expected_recon_techniques = [
                "subdomain",
                "dns",
                "nmap",
                "service",
                "web technologies",
                "tls",
                "whois",
                "cloud",
                "email",
                "screenshot",
                "javascript",
            ];

            let recon_descriptions: Vec<String> = session.phases[0]
                .steps
                .iter()
                .map(|s| s.get_description())
                .collect();

            for technique in &expected_recon_techniques {
                assert!(
                    recon_descriptions
                        .iter()
                        .any(|desc| desc.to_lowercase().contains(technique)),
                    "Missing {} coverage in reconnaissance",
                    technique
                );
            }
        }

        #[test]
        fn test_comprehensive_session_workflow() {
            let temp_dir = TempDir::new().unwrap();
            let session_folder = temp_dir.path().join("comprehensive_workflow");
            let session_file = session_folder.join("session.json");

            // Create a fully populated session
            let mut session = Session::default();
            session.name = "Comprehensive Test Session".to_string();
            session.notes_global =
                "This is a comprehensive test of all session features.".to_string();

            // Modify all phases
            for (phase_idx, phase) in session.phases.iter_mut().enumerate() {
                phase.notes = format!("Notes for phase {}", phase_idx);

                // Modify some steps in each phase
                for (step_idx, step) in phase.steps.iter_mut().enumerate() {
                    if step_idx % 3 == 0 {
                        // Every third step
                        step.status = StepStatus::Done;
                        step.set_notes(format!(
                            "Completed step {} in phase {}",
                            step_idx, phase_idx
                        ));
                        step.completed_at = Some(Utc::now());

                        // Add some evidence (only for tutorial steps)
                        if step.is_tutorial() {
                            step.add_evidence(Evidence {
                                id: Uuid::new_v4(),
                                path: format!("/evidence/phase{}_step{}.png", phase_idx, step_idx),
                                created_at: Utc::now(),
                                kind: "screenshot".to_string(),
                                x: 0.0,
                                y: 0.0,
                            });
                        }
                    } else if step_idx % 3 == 1 {
                        // Every other third step
                        step.status = StepStatus::InProgress;
                        step.set_notes(format!(
                            "In progress: step {} in phase {}",
                            step_idx, phase_idx
                        ));
                    }
                    // Leave some as Todo
                }
            }

            // Save to folder structure
            store::save_session(&session_folder, &session).unwrap();

            // Load from session.json and verify
            let loaded = store::load_session(&session_file).unwrap();

            assert_eq!(loaded.name, session.name);
            assert_eq!(loaded.notes_global, session.notes_global);
            assert_eq!(loaded.phases.len(), session.phases.len());

            // Verify each phase
            for (original_phase, loaded_phase) in session.phases.iter().zip(&loaded.phases) {
                assert_eq!(loaded_phase.name, original_phase.name);
                assert_eq!(loaded_phase.notes, original_phase.notes);
                assert_eq!(loaded_phase.steps.len(), original_phase.steps.len());

                // Verify each step
                for (original_step, loaded_step) in
                    original_phase.steps.iter().zip(&loaded_phase.steps)
                {
                    assert_eq!(loaded_step.title, original_step.title);
                    assert_eq!(
                        loaded_step.get_description(),
                        original_step.get_description()
                    );
                    assert_eq!(loaded_step.status, original_step.status);
                    assert_eq!(loaded_step.get_notes(), original_step.get_notes());
                    assert_eq!(loaded_step.tags, original_step.tags);
                    assert_eq!(
                        loaded_step.get_evidence().len(),
                        original_step.get_evidence().len()
                    );

                    // Verify evidence (only for tutorial steps)
                    if loaded_step.is_tutorial() {
                        for (orig_ev, loaded_ev) in original_step
                            .get_evidence()
                            .iter()
                            .zip(loaded_step.get_evidence())
                        {
                            assert_eq!(loaded_ev.path, orig_ev.path);
                            assert_eq!(loaded_ev.kind, orig_ev.kind);
                            assert_eq!(loaded_ev.created_at, orig_ev.created_at);
                        }
                    }
                }
            }
        }

        #[test]
        fn test_session_data_validation() {
            let session = Session::default();

            // Cloud Identity Security tutorials have a different structure
            const CLOUD_IDENTITY_PHASES: [&str; 7] = [
                "Cloud IAM Abuse 101",
                "Practical OAuth/OIDC Abuse",
                "SSO & Federation Misconfigurations",
                "Modern API & GraphQL Testing Playbook",
                "JWT & SPA Security",
                "Real-Time/WebSocket Testing",
                "AI & LLM Security",
            ];

            // Test that all required fields are present
            assert!(!session.name.is_empty());
            assert!(session.id != Uuid::nil());
            assert!(session.created_at <= Utc::now());
            assert!(!session.phases.is_empty());

            // Test phase structure
            for phase in &session.phases {
                assert!(!phase.name.is_empty());
                assert!(phase.id != Uuid::nil());
                assert!(!phase.steps.is_empty());

                // Test step structure
                for step in &phase.steps {
                    assert!(!step.title.is_empty());
                    // Tutorial steps have descriptions, quiz steps have questions
                    if step.is_tutorial() {
                        assert!(!step.get_description().is_empty());
                    } else if step.is_quiz() {
                        assert!(!step.get_quiz_step().unwrap().questions.is_empty());
                    }
                    assert!(step.id != Uuid::nil());
                    assert!(!step.tags.is_empty()); // All steps should have at least one tag

                    // Test that tutorial steps contain required sections
                    if step.is_tutorial() {
                        let description = step.get_description();
                        assert!(description.contains("OBJECTIVE"));
                        assert!(description.contains("STEP-BY-STEP"));
                        if CLOUD_IDENTITY_PHASES.contains(&phase.name.as_str()) {
                            assert!(
                                description.contains("DETECTION")
                                    || description.contains("REMEDIATION")
                                    || description.contains("TOOLS AND RESOURCES")
                            );
                        } else {
                            assert!(
                                description.contains("WHAT TO LOOK FOR")
                                    || description.contains("COMMON PITFALLS")
                                    || description.contains("DETECTION")
                                    || description.contains("REMEDIATION")
                            );
                        }
                    }
                }
            }
        }

        #[test]
        fn test_session_size_limits() {
            // Test with very large content
            let mut session = Session::default();
            session.name = "A".repeat(10000); // Very long name
            session.notes_global = "B".repeat(50000); // Very long notes

            for phase in &mut session.phases {
                phase.notes = "C".repeat(10000);
                for step in &mut phase.steps {
                    step.set_notes("D".repeat(5000));
                    // Add many evidence items
                    for i in 0..10 {
                        step.add_evidence(Evidence {
                            id: Uuid::new_v4(),
                            path: format!("evidence_{}.png", i),
                            created_at: Utc::now(),
                            kind: "test".to_string(),
                            x: 0.0,
                            y: 0.0,
                        });
                    }
                }
            }

            let temp_dir = TempDir::new().unwrap();
            let session_folder = temp_dir.path().join("large_session");
            let session_file = session_folder.join("session.json");

            // Should handle large sessions
            store::save_session(&session_folder, &session).unwrap();
            let loaded = store::load_session(&session_file).unwrap();

            assert_eq!(loaded.name, session.name);
            assert_eq!(loaded.notes_global, session.notes_global);
        }

        #[test]
        fn test_session_isolation() {
            // Test that sessions don't interfere with each other
            let temp_dir = TempDir::new().unwrap();

            let mut session1 = Session::default();
            session1.name = "Session One".to_string();
            session1.notes_global = "First session".to_string();

            let mut session2 = Session::default();
            session2.name = "Session Two".to_string();
            session2.notes_global = "Second session".to_string();

            let folder1 = temp_dir.path().join("session1");
            let folder2 = temp_dir.path().join("session2");
            let path1 = folder1.join("session.json");
            let path2 = folder2.join("session.json");

            // Save both sessions
            store::save_session(&folder1, &session1).unwrap();
            store::save_session(&folder2, &session2).unwrap();

            // Load and verify they remain separate
            let loaded1 = store::load_session(&path1).unwrap();
            let loaded2 = store::load_session(&path2).unwrap();

            assert_eq!(loaded1.name, "Session One");
            assert_eq!(loaded1.notes_global, "First session");
            assert_eq!(loaded2.name, "Session Two");
            assert_eq!(loaded2.notes_global, "Second session");
        }
    }

    // Edge Cases and Error Handling Tests
    mod edge_case_tests {
        use super::*;
        use crate::model::*;

        #[test]
        fn test_empty_session_handling() {
            // This would require modifying the Session::default() implementation
            // to test edge cases, but for now we'll test with the current implementation
            let session = Session::default();
            assert!(!session.phases.is_empty());
        }

        #[test]
        fn test_step_note_updates() {
            let mut step = Step::new_tutorial(
                Uuid::new_v4(),
                "Test Step".to_string(),
                "Test description".to_string(),
                vec![],
            );

            // Test note updates
            if let StepContent::Tutorial { notes, .. } = &mut step.content {
                *notes = "Initial notes".to_string();
                assert_eq!(*notes, "Initial notes");

                *notes = "Updated notes with more content".to_string();
                assert_eq!(*notes, "Updated notes with more content");

                // Test clearing notes
                notes.clear();
                assert!(notes.is_empty());
            }
        }

        #[test]
        fn test_session_metadata() {
            let session = Session::default();

            // Test session has valid creation time
            assert!(session.created_at <= chrono::Utc::now());

            // Test session has reasonable name
            assert!(!session.name.is_empty());
            assert!(session.name.len() > 3);
        }

        #[test]
        fn test_phase_isolation() {
            let mut session = Session::default();

            // Modify one phase's notes
            session.phases[0].notes = "Phase 0 notes".to_string();
            session.phases[1].notes = "Phase 1 notes".to_string();

            // Verify phases maintain separate state
            assert_eq!(session.phases[0].notes, "Phase 0 notes");
            assert_eq!(session.phases[1].notes, "Phase 1 notes");
            assert!(session.phases[2].notes.is_empty());
        }
    }

    // Performance Tests
    mod performance_tests {
        use super::*;
        use crate::model::*;
        use crate::store;
        use std::time::Instant;

        #[test]
        fn test_session_creation_performance() {
            let start = Instant::now();
            let _session = Session::default();
            let duration = start.elapsed();

            // Session creation should be fast (< 100ms)
            assert!(
                duration.as_millis() < 100,
                "Session creation took too long: {:?}",
                duration
            );
        }

        #[test]
        fn test_serialization_performance() {
            let temp_dir = TempDir::new().unwrap();
            let session_folder = temp_dir.path().join("perf_test");
            let session_file = session_folder.join("session.json");
            let session = Session::default();

            // Test save performance (increased timeout for larger quiz content with PenTest+)
            let save_start = Instant::now();
            store::save_session(&session_folder, &session).unwrap();
            let save_duration = save_start.elapsed();
            assert!(
                save_duration.as_millis() < 500,
                "Save took too long: {:?}",
                save_duration
            );

            // Test load performance (increased timeout for larger quiz content with PenTest+)
            let load_start = Instant::now();
            let _loaded = store::load_session(&session_file).unwrap();
            let load_duration = load_start.elapsed();
            assert!(
                load_duration.as_millis() < 500,
                "Load took too long: {:?}",
                load_duration
            );
        }

        #[test]
        fn test_memory_usage_estimate() {
            let session = Session::default();

            // Count total content size
            let mut total_chars = 0;
            for phase in &session.phases {
                total_chars += phase.name.len();
                total_chars += phase.notes.len();
                for step in &phase.steps {
                    total_chars += step.title.len();
                    total_chars += step.description.len();
                    total_chars += step.notes.len();
                    for tag in &step.tags {
                        total_chars += tag.len();
                    }
                }
            }

            // Should be reasonable size (< 1MB of text)
            assert!(
                total_chars < 1_000_000,
                "Content too large: {} chars",
                total_chars
            );
        }
    }

    // Property-based tests
    mod property_tests {
        use super::*;
        use crate::model::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn test_session_name_preservation(name in ".*") {
                let temp_dir = TempDir::new().unwrap();
                let session_folder = temp_dir.path().join("prop_test");
                let session_file = session_folder.join("session.json");

                let mut session = Session::default();
                session.name = name.clone();

                store::save_session(&session_folder, &session).unwrap();
                let loaded = store::load_session(&session_file).unwrap();

                prop_assert_eq!(loaded.name, name);
            }

            #[test]
            fn test_notes_preservation(notes in ".*") {
                let temp_dir = TempDir::new().unwrap();
                let session_folder = temp_dir.path().join("prop_notes_test");
                let session_file = session_folder.join("session.json");

                let mut session = Session::default();
                session.notes_global = notes.clone();

                store::save_session(&session_folder, &session).unwrap();
                let loaded = store::load_session(&session_file).unwrap();

                prop_assert_eq!(loaded.notes_global, notes);
            }

            #[test]
            fn test_step_notes_preservation(notes in ".*") {
                let temp_dir = TempDir::new().unwrap();
                let session_folder = temp_dir.path().join("prop_step_notes_test");
                let session_file = session_folder.join("session.json");

                let mut session = Session::default();
                if let Some(step) = session.phases[0].steps.get_mut(0) {
                    step.set_notes(notes.clone());
                }

                store::save_session(&session_folder, &session).unwrap();
                let loaded = store::load_session(&session_file).unwrap();

                prop_assert_eq!(&loaded.phases[0].steps[0].get_notes(), &notes);
            }
        }
    }
}
