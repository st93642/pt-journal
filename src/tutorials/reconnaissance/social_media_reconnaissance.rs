pub const SOCIAL_MEDIA_RECONNAISSANCE_STEPS: &[(&str, &str)] = &[
    (
        "Social media reconnaissance",
        "OBJECTIVE: Gather intelligence from social media platforms about target organization and personnel for social engineering preparation.

STEP-BY-STEP PROCESS:

1. LINKEDIN RECONNAISSANCE:
   ```bash
   # CrossLinked (LinkedIn employee scraping)
   python3 CrossLinked.py -f '{first}.{last}@target.com' \"Target Company\"

   # linkedin2username (username generation)
   python3 linkedin2username.py -c \"Target Company\" -n 100
   ```

2. TWITTER/X INTELLIGENCE:
   ```bash
   # Twint (Twitter scraping without API)
   twint -s \"target.com OR @targetcompany\" --email

   # Search for employee tweets
   twint -s \"from:employeehandle\" -o tweets.txt
   ```

3. GITHUB/GITLAB RECON:
   ```bash
   # Search for organization repos
   curl \"https://api.github.com/orgs/targetcompany/repos\" | jq

   # Find employee accounts
   curl \"https://api.github.com/search/users?q=@target.com\" | jq

   # GitDorker (GitHub secrets scanning)
   python3 GitDorker.py -tf tokens.txt -q target.com -d dorks/
   ```

WHAT TO LOOK FOR:
- Employee names and job titles
- Technology stack mentions
- Organizational structure
- Security awareness levels
- Potential social engineering vectors

SECURITY IMPLICATIONS:
- Employee information enables targeted phishing
- Technology mentions reveal infrastructure
- Loose security awareness indicates vulnerability
- Personal information aids pretexting attacks

COMMON PITFALLS:
- Social media data may be outdated
- Privacy settings limit information access
- Information may not be accurate or current
- Privacy laws restrict data collection activities
- Social media scraping may violate terms of service

TOOLS REFERENCE:
- CrossLinked: https://github.com/m8r0wn/CrossLinked
- Twint: https://github.com/twintproject/twint
- GitDorker: https://github.com/obheda12/GitDorker"
    ),
];