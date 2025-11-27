// Triage & Communication - Bug Bounty Hunting Module
// Professional communication with security teams during triage


pub const TRIAGE_COMMUNICATION_STEPS: &[(&str, &str)] = &[
    (
        "Triage & communication",
        "OBJECTIVE: Effectively communicate with security teams during the triage process, provide additional information when requested, and maintain professional relationships that lead to successful vulnerability resolution.

ACADEMIC BACKGROUND:
ISO 29147 Section 7.3 describes vulnerability information handling procedures. NIST SP 800-40 Rev. 4 covers patch management timelines. HackerOne State Guide explains triage workflow. Bugcrowd Response SLA defines expected communication timelines.

STEP-BY-STEP PROCESS:

1. Understanding Triage States:

HackerOne States:
```text
NEW → TRIAGED → RESOLVED → INFORMATIVE/DUPLICATE/NOT APPLICABLE

NEW: Report submitted, awaiting initial review (24-48 hours typical)
TRIAGED: Confirmed as valid vulnerability, accepted by team
NEEDS MORE INFO: Team requests additional details or clarification
RESOLVED: Vulnerability fixed and verified
INFORMATIVE: Valid observation but not security issue
DUPLICATE: Already reported by another researcher
NOT APPLICABLE: Out-of-scope or not a vulnerability
SPAM: Invalid report (can impact reputation)
```

Bugcrowd States:
```text
UNRESOLVED → TRIAGED → RESOLVED

UNRESOLVED: Initial submission
TRIAGED: Validated and prioritized
RESOLVED: Fixed and bounty awarded
WON'T FIX: Valid but team chooses not fix (still may get bounty)
INFORMATIVE: Not a security issue
DUPLICATE: Previously reported
OUT-OF-SCOPE: Asset/vuln type not covered
```

2. Response to \"Needs More Information\":

Good Responses:
```text
TEAM REQUEST: \"Can you provide steps to reproduce in Firefox?\"

YOUR RESPONSE:
\"Hi [Security Team],

I've tested in Firefox 119.0.1 and can confirm the vulnerability reproduces identically:

1. Firefox 119.0.1 on Ubuntu 22.04
2. Navigate to https://example.com/search
3. Enter payload: test' OR '1'='1'--
4. SQL error appears in response

[Attached: firefox_screenshot.png showing error]

The vulnerability reproduces consistently across browsers. Let me know if you need any additional information!

Best regards,
[Your Name]\"
```

Bad Responses:
```text
✗ \"I already explained this in my report\"
✗ \"Just try it yourself\"
✗ [No response for 2 weeks]
```

3. Handling Duplicate Reports:

Professional Duplicate Response:
```text
TEAM: \"This was already reported by another researcher on Oct 15th.\"

YOUR RESPONSE:
\"Thank you for the update. I understand this is a duplicate.

For future reference, could you share:
1. Was the original report already disclosed? (I couldn't find it in hacktivity)
2. Any suggestions on improving my reconnaissance to catch duplicates earlier?

I appreciate the feedback and will be more thorough in checking for existing reports.

Best regards,
[Your Name]\"

KEY POINTS:
✓ Professional and understanding
✓ Request constructive feedback
✓ Show willingness to improve
✓ Don't argue or demand payment
```

4. Escalation Procedures:

When to Escalate (HackerOne):
```text
ESCALATE IF:
- No response after 7+ days (program SLA)
- Report marked informative but clearly valid
- Unfair duplicate classification
- Bounty significantly below guidelines
- Security team unresponsive to critical vulnerability

HOW TO ESCALATE:
1. HackerOne: Request mediation
   Click \"Request Mediation\" button
   Explain situation professionally
   Provide supporting evidence

2. Bugcrowd: Contact support
   Email: support@bugcrowd.com
   Reference report # and program
   Explain concern clearly
```

Professional Escalation Message:
```text
\"Hi HackerOne Mediation Team,

I'm requesting mediation for report #XXXXX submitted to [Program] on Oct 15th.

Situation:
- Report submitted 14 days ago
- Status: NEW (no triage response)
- Severity: Critical (CVSS 9.8)
- Program SLA: First response within 5 business days

I've sent two follow-up comments (Oct 20th, Oct 27th) with no response.

Request:
Could you please help facilitate communication with the security team?

Thank you for your assistance.

Best regards,
[Your Name]\"
```

5. Communication Best Practices:

Tone and Professionalism:
```text
✓ DO:
- Be patient and respectful
- Provide requested information promptly
- Thank team for their time
- Offer to test fixes
- Accept decisions gracefully

✗ DON'T:
- Use aggressive or demanding language
- Threaten public disclosure
- Spam comments asking for updates
- Argue with triage decisions
- Insult security team
- Compare yourself to other researchers
```
[File content truncated at line 2000. Use read_file with offset/limit parameters to view more.]

Example Professional Messages:
```text
FIX VERIFICATION OFFER:
\"Hi Team,

I see the vulnerability has been marked as resolved. I'd be happy to verify the fix if you'd like me to retest.

Please let me know if verification testing would be helpful.

Best regards\"

CLARIFICATION REQUEST:
\"Hi Team,

Thanks for triaging this report. I want to ensure I understand the concern you've raised.

Are you asking about [specific clarification]? If so, I can provide [additional info].

Please let me know if I've understood correctly.

Best regards\"

THANK YOU MESSAGE:
\"Hi Team,

Thank you for the $X,XXX bounty and quick resolution!

I enjoyed working on this program and look forward to future findings.

Best regards\"
```

6. Timeline Management:

Typical Timelines:
```text
FIRST RESPONSE: 24-72 hours (good programs)
TRIAGE: 3-7 days
FIX: 30-90 days (varies by severity and complexity)
BOUNTY PAYMENT: 7-30 days after resolution

CRITICAL VULNERABILITIES:
First response: <24 hours
Fix: 1-7 days (emergency patching)
Payment: Expedited

LOW SEVERITY:
Triage: 5-14 days
Fix: 90-180 days or \"won't fix\"
```

Following Up:
```text
✓ GOOD TIMING:
- Day 7: Polite check-in if no response
- Day 14: Second check-in or mediation request
- After fix: Offer to verify

✗ BAD TIMING:
- Day 1: \"Any updates?\"
- Multiple times per day
- Impatient demands for bounty
```

7. Handling Disagreements:

Severity Disagreements:
```text
TEAM: \"We're downgrading this from High to Medium\"

PROFESSIONAL RESPONSE:
\"Thank you for the update. I appreciate you taking time to review the severity.

I'd like to respectfully discuss the rating:

My Assessment (High):
- Vulnerability allows [specific impact]
- Affects [number/type of users]
- CVSS 7.5: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

Could you help me understand the Medium classification? This would help me better assess severity in future reports.

If the decision stands, I completely understand and accept it.

Thank you!\"
```

Won't Fix Decisions:
```text
TEAM: \"This is valid but we won't fix it due to [business reason]\"

PROFESSIONAL RESPONSE:
\"Thank you for explaining the decision.

I understand the business considerations. Would you still like me to:
1. Submit similar findings in other areas?
2. Focus on different vulnerability types?

I want to ensure my future reports align with program priorities.

Appreciate your guidance!\"
```

WHAT TO LOOK FOR:
- **Timely Responses**: Security teams respecting SLA commitments (first response <48h for quality programs)
- **Clear Communication**: Triage decisions explained with reasoning
- **Fair Treatment**: Consistent duplicate handling, severity assessment
- **Professional Relationship**: Mutual respect, constructive feedback

SECURITY IMPLICATIONS:
- **Disclosure Ethics**: Never threaten premature disclosure if unhappy with triage
- **Reputation**: Professional communication builds trust and invitations to private programs
- **Legal Protection**: Bug bounty safe harbor only applies when following program rules and timelines

COMMON PITFALLS:
- **Impatience**: Spamming \"any updates?\" every day instead of respecting triage timelines
- **Aggression**: Demanding bounties, threatening disclosure, insulting security teams
- **Poor Communication**: Not responding to \"Needs More Info\" requests promptly
- **Arguing**: Fighting every triage decision instead of learning and improving
- **Unprofessionalism**: Using slang, all-caps, exclamation marks excessively
- **Ghosting**: Submitting reports then disappearing when team needs clarification
- **Comparison**: \"Other researchers got $5K for this, I should too!\"

TOOLS REFERENCE:
- **HackerOne Inbox**: https://hackerone.com/bugs (manage reports and communication)
- **Bugcrowd Dashboard**: https://bugcrowd.com/researcher/programs (track submissions)
- **Discord/Slack**: Many programs have dedicated researcher channels

FURTHER READING:
- HackerOne Triage Process: https://docs.hackerone.com/hackers/triaging.html
- Bugcrowd Response SLA: https://www.bugcrowd.com/resources/reports/state-of-bug-bounty/
- ISO 29147 Disclosure: https://www.iso.org/standard/72311.html"
    ),
];