/// Supply Chain Security tutorial phases
///
/// This module provides comprehensive tutorials for software supply chain security:
/// - SBOM Generation & Analysis: Creating and analyzing software bills of materials
/// - Dependency Confusion & Typosquatting: Attacking package management systems
/// - Artifact Integrity Checks: Ensuring software artifact authenticity
///
/// Each phase follows the OBJECTIVE/PROCESS/LOOK-FOR format for structured learning.
use crate::model::Step;
use uuid::Uuid;

/// SBOM Generation & Analysis phase
pub fn sbom_analysis_phase() -> Step {
    let tags = vec![
        "tutorial".to_string(),
        "supply-chain".to_string(),
        "sbom".to_string(),
        "analysis".to_string(),
    ];

    let parts = vec![
        ("SBOM Fundamentals".to_string(),
         "OBJECTIVE: Learn SBOM concepts and generation techniques\n\nSTEP-BY-STEP PROCESS:\n1. Install Syft: 'curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh'\n2. Generate SBOM for a container: 'syft alpine:latest'\n3. Analyze package dependencies\n4. Check for vulnerable components\n5. Export in multiple formats (JSON, SPDX, CycloneDX)\n\nWHAT TO LOOK FOR:\n- Package inventory completeness\n- Version information accuracy\n- License compliance data\n- Vulnerability correlations\n- Dependency tree depth".to_string()),
        ("SBOM-Based Vulnerability Scanning".to_string(),
         "OBJECTIVE: Use SBOM data for comprehensive vulnerability assessment\n\nSTEP-BY-STEP PROCESS:\n1. Install Grype: 'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh'\n2. Scan SBOM with Grype: 'grype sbom:./sbom.json'\n3. Analyze vulnerability matches\n4. Check CVSS scores and exploitability\n5. Generate remediation reports\n\nWHAT TO LOOK FOR:\n- Known vulnerability matches\n- Severity classifications\n- Exploit availability\n- Patch availability\n- False positive identification".to_string()),
        ("License Compliance Checking".to_string(),
         "OBJECTIVE: Analyze software licenses using SBOM data\n\nSTEP-BY-STEP PROCESS:\n1. Extract license information from SBOM\n2. Identify license conflicts\n3. Check for copyleft licenses\n4. Analyze license compatibility\n5. Generate compliance reports\n\nWHAT TO LOOK FOR:\n- GPL/LGPL usage\n- License compatibility issues\n- Attribution requirements\n- Commercial license restrictions\n- Open source compliance gaps".to_string()),
        ("SBOM Quality Validation".to_string(),
         "OBJECTIVE: Evaluate SBOM completeness and accuracy\n\nSTEP-BY-STEP PROCESS:\n1. Check SBOM metadata completeness\n2. Validate package information\n3. Assess relationship mappings\n4. Test SBOM parsing tools\n5. Compare against known good SBOMs\n\nWHAT TO LOOK FOR:\n- Missing package data\n- Incomplete version info\n- Broken relationship links\n- Format validation errors\n- Tool compatibility issues".to_string()),
        ("SBOM Automation & Monitoring".to_string(),
         "OBJECTIVE: Integrate SBOM generation into CI/CD pipelines\n\nSTEP-BY-STEP PROCESS:\n1. Create automated SBOM generation scripts\n2. Integrate with build pipelines\n3. Set up SBOM storage and versioning\n4. Implement continuous monitoring\n5. Configure alerting for issues\n\nWHAT TO LOOK FOR:\n- Pipeline integration points\n- Automation script reliability\n- Storage security measures\n- Monitoring effectiveness\n- Alert threshold tuning".to_string()),
    ];

    let description = parts
        .iter()
        .map(|(title, body)| format!("{}\n{}", title, body))
        .collect::<Vec<String>>()
        .join("\n\n---\n\n");

    Step::new_tutorial(
        Uuid::new_v4(),
        "SBOM Generation & Analysis".to_string(),
        description,
        tags,
    )
}

/// Dependency Confusion & Typosquatting phase
pub fn dependency_confusion_phase() -> Step {
    let tags = vec![
        "tutorial".to_string(),
        "supply-chain".to_string(),
        "dependency".to_string(),
        "confusion".to_string(),
    ];

    let parts = vec![
        ("Dependency Resolution Mechanics".to_string(),
         "OBJECTIVE: Learn how package managers resolve dependencies\n\nSTEP-BY-STEP PROCESS:\n1. Examine npm package resolution: 'npm install lodash'\n2. Check Python pip resolution process\n3. Analyze Maven dependency resolution\n4. Test package registry precedence\n5. Understand version resolution algorithms\n\nWHAT TO LOOK FOR:\n- Registry search order\n- Version matching rules\n- Cache poisoning vectors\n- Namespace conflicts\n- Resolution algorithm weaknesses".to_string()),
        ("Dependency Confusion Exploitation".to_string(),
         "OBJECTIVE: Execute dependency confusion attacks against package managers\n\nSTEP-BY-STEP PROCESS:\n1. Register malicious package with internal name\n2. Publish to public registry with higher version\n3. Trick internal systems into downloading malicious package\n4. Execute payload in compromised environment\n5. Maintain persistence through updates\n\nWHAT TO LOOK FOR:\n- Internal package name leaks\n- Registry precedence exploitation\n- Version manipulation\n- Payload execution\n- Update mechanism abuse".to_string()),
        ("Typosquatting Package Creation".to_string(),
         "OBJECTIVE: Create and deploy typosquatting packages\n\nSTEP-BY-STEP PROCESS:\n1. Identify popular package names\n2. Generate similar-sounding names (lodash → loadsh)\n3. Create malicious packages with typos\n4. Publish to public registries\n5. Monitor for installation attempts\n\nWHAT TO LOOK FOR:\n- Common typos in package names\n- Similar character substitutions\n- Package name variations\n- Installation telemetry\n- Attack success rates".to_string()),
        ("Registry Poisoning Methods".to_string(),
         "OBJECTIVE: Poison package registries with malicious content\n\nSTEP-BY-STEP PROCESS:\n1. Compromise maintainer accounts\n2. Inject malicious code into legitimate packages\n3. Create fake package updates\n4. Abuse registry APIs\n5. Exploit CI/CD publishing workflows\n\nWHAT TO LOOK FOR:\n- Weak authentication mechanisms\n- API abuse opportunities\n- Publishing workflow vulnerabilities\n- Update notification exploitation\n- Social engineering vectors".to_string()),
        ("Supply Chain Attack Mitigation".to_string(),
         "OBJECTIVE: Implement defenses against dependency attacks\n\nSTEP-BY-STEP PROCESS:\n1. Set up private package registries\n2. Implement package signing\n3. Use dependency locking (package-lock.json)\n4. Deploy integrity checking\n5. Monitor for anomalous packages\n\nWHAT TO LOOK FOR:\n- Registry isolation effectiveness\n- Signature validation\n- Lockfile integrity\n- Anomaly detection accuracy\n- Response time improvements".to_string()),
    ];

    let description = parts
        .iter()
        .map(|(title, body)| format!("{}\n{}", title, body))
        .collect::<Vec<String>>()
        .join("\n\n---\n\n");

    Step::new_tutorial(
        Uuid::new_v4(),
        "Dependency Confusion & Typosquatting".to_string(),
        description,
        tags,
    )
}

/// Artifact Integrity Checks phase
pub fn artifact_integrity_phase() -> Step {
    let tags = vec![
        "tutorial".to_string(),
        "supply-chain".to_string(),
        "artifact".to_string(),
        "integrity".to_string(),
    ];

    let parts = vec![
        ("Digital Signature Basics".to_string(),
         "OBJECTIVE: Understand digital signatures for software artifacts\n\nSTEP-BY-STEP PROCESS:\n1. Generate GPG keypair: 'gpg --gen-key'\n2. Sign a file: 'gpg --sign --armor file.txt'\n3. Verify signature: 'gpg --verify file.txt.asc'\n4. Check key trust levels\n5. Understand certificate chains\n\nWHAT TO LOOK FOR:\n- Key generation best practices\n- Signature verification process\n- Trust model understanding\n- Certificate validation\n- Key management procedures".to_string()),
        ("Package Signing Workflows".to_string(),
         "OBJECTIVE: Implement signing for different package types\n\nSTEP-BY-STEP PROCESS:\n1. Sign npm packages: 'npm publish --sign'\n2. Sign Python wheels: 'python -m twine upload --sign dist/*'\n3. Sign container images: 'cosign sign image:tag'\n4. Verify signed packages\n5. Set up automated signing\n\nWHAT TO LOOK FOR:\n- Package type support\n- Signing workflow integration\n- Verification procedures\n- Automation reliability\n- Key security measures".to_string()),
        ("Cryptographic Hash Verification".to_string(),
         "OBJECTIVE: Use cryptographic hashes for integrity verification\n\nSTEP-BY-STEP PROCESS:\n1. Generate file hashes: 'sha256sum file.txt'\n2. Create hash files for distributions\n3. Implement hash verification in downloads\n4. Use Merkle trees for large datasets\n5. Automate integrity checking\n\nWHAT TO LOOK FOR:\n- Hash algorithm selection\n- Collision resistance\n- Verification speed\n- Storage efficiency\n- Automation integration".to_string()),
        ("Provenance Tracking".to_string(),
         "OBJECTIVE: Track artifact provenance through the supply chain\n\nSTEP-BY-STEP PROCESS:\n1. Implement SLSA framework\n2. Track build provenance\n3. Verify build environments\n4. Check dependency provenance\n5. Generate provenance attestations\n\nWHAT TO LOOK FOR:\n- Build environment isolation\n- Dependency chain tracking\n- Attestation formats\n- Verification procedures\n- Compliance requirements".to_string()),
        ("Continuous Integrity Assurance".to_string(),
         "OBJECTIVE: Set up continuous integrity monitoring systems\n\nSTEP-BY-STEP PROCESS:\n1. Deploy integrity scanners\n2. Monitor artifact registries\n3. Set up alerting for tampering\n4. Implement automated remediation\n5. Generate integrity reports\n\nWHAT TO LOOK FOR:\n- Detection accuracy\n- False positive rates\n- Response automation\n- Reporting comprehensiveness\n- System performance impact".to_string()),
    ];

    let description = parts
        .iter()
        .map(|(title, body)| format!("{}\n{}", title, body))
        .collect::<Vec<String>>()
        .join("\n\n---\n\n");

    Step::new_tutorial(
        Uuid::new_v4(),
        "Artifact Integrity Checks".to_string(),
        description,
        tags,
    )
}

/// Get all supply chain security tutorial phases
pub fn get_supply_chain_phases() -> Vec<Step> {
    vec![
        sbom_analysis_phase(),
        dependency_confusion_phase(),
        artifact_integrity_phase(),
    ]
}
