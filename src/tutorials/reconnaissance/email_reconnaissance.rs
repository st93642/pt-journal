pub const EMAIL_RECONNAISSANCE_STEPS: &[(&str, &str)] = &[
    (
        "Email reconnaissance",
        "OBJECTIVE: Gather email addresses, identify email infrastructure, and collect personnel information for social engineering preparation and authentication attack targeting.

STEP-BY-STEP PROCESS:

1. EMAIL ADDRESS HARVESTING:
   ```bash
   # theHarvester (comprehensive OSINT)
   theHarvester -d target.com -l 500 -b all -f results.html

   # Hunter.io API
   curl \"https://api.hunter.io/v2/domain-search?domain=target.com&api_key=YOUR_KEY\"

   # LinkedIn scraping for emails
   python3 linkedin2username.py -c \"Target Company\" -n 100

   # Email pattern recognition
   # Common patterns: firstname.lastname@, first.last@, flast@
   ```

2. EMAIL SERVER ENUMERATION:
   ```bash
   # Check MX records
   dig target.com MX

   # Identify email provider
   nslookup $(dig target.com MX +short | head -1 | awk '{print $2}')

   # SMTP banner grabbing
   nc target.com 25

   # Test for VRFY/EXPN commands
   telnet target.com 25
   VRFY admin
   EXPN postmaster

   # Check email security (SPF, DMARC, DKIM)
   dig target.com TXT | grep -E '(spf|dmarc)'
   dig _dmarc.target.com TXT
   ```

WHAT TO LOOK FOR:
- Email addresses of executives and IT staff
- Email naming conventions and patterns
- Weak SPF/DMARC configurations (email spoofing risk)
- Open relay misconfiguration
- VRFY/EXPN enabled (user enumeration)
- Employee LinkedIn profiles with contact info

SECURITY IMPLICATIONS:
- Email addresses enable targeted phishing
- Weak email security allows spoofing
- Personnel information aids social engineering
- VRFY command leaks valid usernames
- Email patterns enable credential stuffing

COMMON PITFALLS:
- Some email addresses are role-based not personal
- Privacy laws limit data collection
- Email harvesting tools may be rate-limited
- Organizations may use email aliases
- SMTP enumeration may trigger security alerts

TOOLS REFERENCE:
- theHarvester: https://github.com/laramies/theHarvester
- Hunter.io: https://hunter.io/ (Email finder API)
- CrossLinked: https://github.com/m8r0wn/CrossLinked (LinkedIn scraper)"
    ),
];