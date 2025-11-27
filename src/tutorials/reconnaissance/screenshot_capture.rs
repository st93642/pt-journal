pub const SCREENSHOT_CAPTURE_STEPS: &[(&str, &str)] = &[
    (
        "Screenshot capture",
        "OBJECTIVE: Create visual documentation of all discovered web assets for evidence collection, visual comparison, and identification of interesting pages requiring further investigation.

STEP-BY-STEP PROCESS:

1. AUTOMATED SCREENSHOT TOOLS:
   ```bash
   # EyeWitness (comprehensive with report)
   python3 EyeWitness.py -f urls.txt --web --timeout 10 -d screenshots

   # Gowitness (fast Go-based)
   gowitness scan file -f urls.txt --threads 10 --timeout 10

   # Aquatone (pipeline-friendly)
   cat urls.txt | aquatone -out aquatone_report

   # HTTPScreenshot (Nmap integration)
   nmap -p 80,443,8080,8443 target.com --script http-screenshot

   # Webscreenshot (Python simple)
   python webscreenshot.py -i urls.txt -o screenshots/
   ```

2. RESPONSIVE DESIGN CAPTURE:
   ```bash
   # Multiple viewport sizes
   gowitness scan single --url https://target.com --resolution 1920x1080
   gowitness scan single --url https://target.com --resolution 768x1024  # Tablet
   gowitness scan single --url https://target.com --resolution 375x667   # Mobile
   ```

3. AUTHENTICATED SCREENSHOTS:
   ```bash
   # EyeWitness with cookies
   python3 EyeWitness.py -f urls.txt --web --cookie \"session=abc123\"

   # Aquatone with headers
   cat urls.txt | aquatone -H \"Authorization: Bearer token123\"
   ```

WHAT TO LOOK FOR:
- Default error pages revealing software versions
- Admin/login interfaces
- Exposed development/staging environments
- Unusual or legacy applications
- Custom applications worth investigating

COMMON PITFALLS:
- Screenshots may not capture dynamic JavaScript content
- Authentication states can expire during capture
- Some pages require specific user-agents or cookies
- AJAX-loaded content may be missed
- Rate limiting can slow down bulk screenshot capture

TOOLS REFERENCE:
- EyeWitness: https://github.com/FortyNorthSecurity/EyeWitness
- Gowitness: https://github.com/sensepost/gowitness
- Aquatone: https://github.com/michenriksen/aquatone"
    ),
];