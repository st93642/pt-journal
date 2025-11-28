use assert_matches::assert_matches;
use chrono::Utc;
use std::fs;
use std::time::Instant;
use tempfile::TempDir;
use uuid::Uuid;

use pt_journal::model::*;
use pt_journal::store;

#[cfg(test)]
mod tests {
    use super::*;

    // Model Tests
    mod model_tests {
        use super::*;

        #[test]
        fn test_default_app_model() {
            let model = AppModel::default();
            assert_eq!(model.selected_phase(), 0);
            assert_eq!(model.selected_step(), Some(0));
            assert!(model.current_path().is_none());
            assert_eq!(model.session().phases.len(), 23); // 23 phases loaded from JSON
                                                          // Config should be loaded (or default)
            assert_eq!(
                model.config().chatbot.ollama.endpoint,
                "http://localhost:11434"
            );
            assert_eq!(model.config().chatbot.default_model_id, "llama3.2:latest");
        }

        #[test]
        fn test_session_creation() {
            let session = Session::default();
            assert!(!session.name.is_empty());
            assert_eq!(session.phases.len(), 23); // 23 phases loaded from JSON
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

            // Test Linux CTF phase
            let linux_ctf_phase = &session.phases[4];
            assert_eq!(linux_ctf_phase.name, "Linux CTF");
            assert!(!linux_ctf_phase.steps.is_empty()); // Has tutorial steps

            // Test Windows CTF phase
            let windows_ctf_phase = &session.phases[5];
            assert_eq!(windows_ctf_phase.name, "Windows CTF");
            assert!(!windows_ctf_phase.steps.is_empty()); // Has tutorial steps

            // Test Cloud IAM Abuse 101 phase
            let cloud_iam_phase = &session.phases[6];
            assert_eq!(cloud_iam_phase.name, "Cloud IAM Abuse 101");
            assert!(!cloud_iam_phase.steps.is_empty()); // Has tutorial and quiz steps

            // Test Container & Kubernetes Security phase
            let container_security_phase = &session.phases[11];
            assert_eq!(
                container_security_phase.name,
                "Container & Kubernetes Security"
            );
            assert!(!container_security_phase.steps.is_empty()); // Has tutorial and quiz steps

            // Test Bug Bounty Hunting phase
            let bug_bounty_phase = &session.phases[18];
            assert_eq!(bug_bounty_phase.name, "Bug Bounty Hunting");
            assert!(!bug_bounty_phase.steps.is_empty()); // Has steps

            // Test Reporting phase (moved to position 19)
            let report_phase = &session.phases[19];
            assert_eq!(report_phase.name, "Reporting");
            assert_eq!(report_phase.steps.len(), 4); // 4 reporting steps

            // Test CompTIA Security+ phase (moved to position 20)
            let comptia_phase = &session.phases[20];
            assert_eq!(comptia_phase.name, "CompTIA Security+");
            assert_eq!(comptia_phase.steps.len(), 23); // All 5 domains: D1(4) + D2(5) + D3(4) + D4(5) + D5(5)
        }

        #[test]
        fn test_step_properties() {
            let session = Session::default();
            let first_step = &session.phases[0].steps[0];

            // Test basic properties
            assert!(!first_step.title.is_empty());
            assert!(!first_step.description.is_empty()); // Use description for StepContent
            assert!(first_step.id != Uuid::nil());
            assert_eq!(first_step.status, StepStatus::Todo);
            assert!(first_step.completed_at.is_none());
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
                        let description = step.description.clone();
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
                        if let Some(quiz_step) = step.quiz_data.as_ref() {
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
            assert_eq!(model.selected_phase(), 0);
            model.set_selected_phase(1);
            assert_eq!(model.selected_phase(), 1);

            // Test step navigation
            assert_eq!(model.selected_step(), Some(0));
            model.set_selected_step(Some(2));
            assert_eq!(model.selected_step(), Some(2));

            // Test invalid phase bounds
            model.set_selected_phase(10); // Beyond available phases
                                          // Should not panic, just store the value
            assert_eq!(model.selected_phase(), 10);
        }
    }

    // Store Tests
    mod store_tests {
        use super::*;

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
    }

    // Integration Tests
    mod integration_tests {
        use super::*;

        #[test]
        fn test_phase_progression_workflow() {
            let session = Session::default();

            // Verify logical phase progression (reordered to reflect real-world workflow)
            // Phases are ordered: recon first, core pentesting, modern topics, advanced topics, reporting, quizzes last
            let phase_names = [
                "Reconnaissance",
                "Vulnerability Analysis",
                "Exploitation",
                "Post-Exploitation",
                "Linux CTF",
                "Windows CTF",
                "Cloud IAM Abuse 101",
                "Practical OAuth/OIDC Abuse",
                "SSO & Federation Misconfigurations",
                "API Security",
                "Modern Web Application Security",
                "Container & Kubernetes Security",
                "Serverless Security",
                "Cloud Native Security",
                "Supply Chain Security",
                "AI/ML Security",
                "Red Team Tradecraft",
                "Purple Team/Threat Hunting",
                "Bug Bounty Hunting",
                "Reporting",
                "CompTIA Security+",
                "CompTIA PenTest+",
                "Certified Ethical Hacker (CEH)",
            ];
            for (idx, expected_name) in phase_names.iter().enumerate() {
                assert_eq!(session.phases[idx].name, *expected_name);
            }

            // Verify step counts are reasonable for all phases
            let expected_step_counts = [
                16, 5, 4, 4, 15, 2, 2, 1, 1, 7, 7, 6, 7, 15, 15, 13, 10, 10, 8, 4, 23, 32, 24,
            ]; // 23 phases loaded from JSON
            for (idx, &expected_count) in expected_step_counts.iter().enumerate() {
                assert_eq!(session.phases[idx].steps.len(), expected_count);
            }

            // Cloud IAM Abuse 101 phase should include tutorial + quiz steps
            assert!(session.phases[6].steps.len() >= 2);

            // Container & Kubernetes Security phase should have steps
            assert!(!session.phases[11].steps.is_empty());

            // Bug Bounty Hunting phase should have steps
            assert!(!session.phases[18].steps.is_empty());

            // CompTIA Security+ phase should have quiz steps (now at position 20)
            assert_eq!(session.phases[20].steps.len(), 23); // All 5 domains: D1(4) + D2(5) + D3(4) + D4(5) + D5(5)
        }

        #[test]
        fn test_step_content_completeness() {
            let session = Session::default();

            // Cloud Identity Security tutorials have a different structure
            const CLOUD_IDENTITY_PHASES: [&str; 6] = [
                "Cloud IAM Abuse 101",
                "Practical OAuth/OIDC Abuse",
                "SSO & Federation Misconfigurations",
                "API Security",
                "Reporting",
                "AI/ML Security Integrations",
            ];

            for phase in &session.phases {
                for step in &phase.steps {
                    // Only check tutorial steps
                    if step.is_tutorial() {
                        let description = step.description.clone();

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
                        } else if phase.name.as_str() == "Container & Kubernetes Security" {
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
                .map(|s| s.description.clone())
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
        fn test_session_data_validation() {
            let session = Session::default();

            // Cloud Identity Security tutorials have a different structure
            const CLOUD_IDENTITY_PHASES: [&str; 6] = [
                "Cloud IAM Abuse 101",
                "Practical OAuth/OIDC Abuse",
                "SSO & Federation Misconfigurations",
                "API Security",
                "Reporting",
                "AI/ML Security Integrations",
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
                        assert!(!step.description.is_empty());
                    } else if step.is_quiz() {
                        assert!(!step.quiz_data.as_ref().unwrap().questions.is_empty());
                    }
                    assert!(step.id != Uuid::nil());
                    assert!(!step.tags.is_empty()); // All steps should have at least one tag

                    // Test that tutorial steps contain required sections
                    if step.is_tutorial() {
                        let description = step.description.clone();
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
    }

    // Edge Cases and Error Handling Tests
    mod edge_case_tests {
        use super::*;

        #[test]
        fn test_empty_session_handling() {
            // This would require modifying the Session::default() implementation
            // to test edge cases, but for now we'll test with the current implementation
            let session = Session::default();
            assert!(!session.phases.is_empty());
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
    }

    // Performance Tests
    mod performance_tests {
        use super::*;

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
            // Performance test for session serialization (without actual save/load)
            let session = Session::default();

            let start = Instant::now();
            let serialized = serde_json::to_string(&session).unwrap();
            let serialize_duration = start.elapsed();

            assert!(
                serialize_duration.as_millis() < 500,
                "Serialization took too long: {:?}",
                serialize_duration
            );

            let deserialize_start = Instant::now();
            let _deserialized: Session = serde_json::from_str(&serialized).unwrap();
            let deserialize_duration = deserialize_start.elapsed();

            assert!(
                deserialize_duration.as_millis() < 500,
                "Deserialization took too long: {:?}",
                deserialize_duration
            );
        }

        #[test]
        fn test_memory_usage_estimate() {
            let session = Session::default();

            // Count total content size
            let mut total_chars = 0;
            for phase in &session.phases {
                total_chars += phase.name.len();
                for step in &phase.steps {
                    total_chars += step.title.len();
                    total_chars += step.description.len();
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
}
