pub const WHOIS_DOMAIN_ANALYSIS_STEPS: &[(&str, &str)] = &[
    (
        "WHOIS domain analysis",
        "OBJECTIVE: Extract domain registration information including ownership, contacts, registration dates, and name servers to understand organizational structure and identify additional assets.

STEP-BY-STEP PROCESS:

1. BASIC WHOIS QUERIES:
   ```bash
   # Standard WHOIS lookup
   whois target.com

   # Specific WHOIS server
   whois -h whois.verisign-grs.com target.com

   # RDAP (modern alternative)
   curl https://rdap.org/domain/target.com | jq
   ```

2. EXTRACT KEY INFORMATION:
   ```bash
   # Registrar information
   whois target.com | grep -i registrar

   # Name servers
   whois target.com | grep -i \"name server\"

   # Registration dates
   whois target.com | grep -iE \"(creation|expir|updated) date\"
   ```

WHAT TO LOOK FOR:
- Registrant organization and contacts
- WHOIS privacy protection status
- Recent registration or transfer dates
- Domain expiration date
- Related domains with same registrant

COMMON PITFALLS:
- WHOIS privacy services hide real owner information
- Some TLDs have restricted WHOIS data
- Historical data may not be available
- Contact information may be outdated
- Rate limiting affects bulk WHOIS queries

TOOLS REFERENCE:
- whois: Built-in command
- WhoisXML API: https://www.whoisxmlapi.com/
- DomainTools: https://www.domaintools.com/"
    ),
];