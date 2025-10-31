pub const REPORTING_STEPS: &[(&str, &str)] = &[
    (
        "Evidence consolidation",
        "OBJECTIVE: Gather and organize all evidence collected during the penetration test.

STEP-BY-STEP PROCESS:
1. Evidence inventory:
   - Catalog all screenshots, logs, and captured data
   - Organize evidence by phase and finding
   - Verify evidence authenticity and timestamps

2. Finding correlation:
   - Link related findings across phases
   - Identify root causes and attack chains
   - Remove duplicate or redundant evidence

3. Evidence validation:
   - Verify all findings have supporting evidence
   - Check evidence quality and clarity
   - Ensure evidence tells a complete story

4. Documentation structure:
   - Create evidence folders by finding type
   - Implement consistent naming conventions
   - Prepare evidence for report inclusion

5. Chain of custody:
   - Document evidence collection methods
   - Maintain evidence integrity
   - Prepare evidence for potential legal review

WHAT TO LOOK FOR:
- Clear, unambiguous evidence of vulnerabilities
- Complete attack chains from discovery to exploitation
- High-quality screenshots and logs
- Evidence that supports risk assessments

COMMON PITFALLS:
- Some evidence may be time-sensitive
- Evidence quality varies by collection method
- Some findings may not have visual evidence
- Evidence may need to be sanitized for sharing"
    ),
    (
        "Risk rating",
        "OBJECTIVE: Assign risk scores to identified vulnerabilities and findings.

STEP-BY-STEP PROCESS:
1. Risk methodology selection:
   - Choose appropriate risk scoring system (CVSS, DREAD, etc.)
   - Define risk criteria and thresholds
   - Establish risk rating scale

2. Vulnerability assessment:
   - Score each finding individually
   - Consider exploitability, impact, and detection
   - Factor in business context and environment

3. Risk calculation:
   - Combine likelihood and impact scores
   - Apply environmental modifiers
   - Consider compensating controls

4. Risk prioritization:
   - Rank findings by overall risk level
   - Group similar vulnerabilities
   - Identify critical findings requiring immediate attention

5. Risk communication:
   - Explain risk scores and methodology
   - Provide context for risk ratings
   - Document assumptions and limitations

WHAT TO LOOK FOR:
- Critical vulnerabilities requiring immediate remediation
- High-risk findings with broad impact
- Vulnerabilities with reliable exploits available
- Findings affecting sensitive data or systems

COMMON PITFALLS:
- Risk scores are subjective and context-dependent
- Some vulnerabilities may be mitigated in production
- Risk perception varies by stakeholder
- Quantitative risk models may not capture all factors"
    ),
    (
        "Remediation guidance",
        "OBJECTIVE: Provide actionable recommendations for addressing identified vulnerabilities.

STEP-BY-STEP PROCESS:
1. Vulnerability analysis:
   - Understand root causes of each finding
   - Research appropriate remediation steps
   - Identify vendor patches and updates

2. Remediation prioritization:
   - Order fixes by risk level and ease of implementation
   - Consider dependencies between fixes
   - Balance security with operational impact

3. Detailed remediation steps:
   - Provide specific, actionable instructions
   - Include commands, configuration changes, and code fixes
   - Specify testing procedures for verification

4. Compensating controls:
   - Suggest temporary mitigations for complex fixes
   - Identify monitoring and detection improvements
   - Recommend process improvements

5. Timeline and resource requirements:
   - Estimate time and effort for each remediation
   - Identify required skills and resources
   - Suggest implementation phases

WHAT TO LOOK FOR:
- Specific, actionable remediation steps
- Vendor patches and security updates
- Configuration changes and hardening measures
- Process improvements and training needs

COMMON PITFALLS:
- Some remediations require application changes
- Patches may break functionality
- Some fixes require vendor coordination
- Remediation may require downtime or testing"
    ),
    (
        "Executive summaries",
        "OBJECTIVE: Create high-level summaries for executive and management audiences.

STEP-BY-STEP PROCESS:
1. Audience analysis:
   - Understand executive information needs
   - Focus on business impact over technical details
   - Identify key decision points and concerns

2. Executive summary structure:
   - Overview of assessment scope and objectives
   - High-level findings and risk assessment
   - Critical vulnerabilities requiring attention
   - Strategic recommendations and roadmap

3. Risk communication:
   - Use business terminology over technical jargon
   - Focus on impact rather than technical details
   - Include concrete examples and analogies

4. Strategic recommendations:
   - Provide high-level remediation strategies
   - Include cost-benefit analysis where possible
   - Recommend resource allocation priorities

5. Call to action:
   - Clear next steps with timelines
   - Identify responsible parties
   - Suggest metrics for measuring progress

WHAT TO LOOK FOR:
- Clear risk levels and business impact
- Actionable recommendations with priorities
- Realistic timelines and resource requirements
- Measurable success criteria

COMMON PITFALLS:
- Executives may want more technical detail
- Business context varies by organization
- Risk tolerance differs between stakeholders
- Some recommendations may be politically sensitive"
    ),
];