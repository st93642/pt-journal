pub const PARAMETER_DISCOVERY_STEPS: &[(&str, &str)] = &[
    (
        "Parameter discovery",
        "OBJECTIVE: Identify all input parameters including GET/POST parameters, API parameters, and hidden form fields to establish complete attack surface for injection testing and fuzzing.

STEP-BY-STEP PROCESS:

1. URL PARAMETER EXTRACTION:
   ```bash
   # ParamSpider (URL parameter collection from archives)
   python3 paramspider.py -d target.com -o params.txt

   # Extract unique parameter names
   cat params.txt | grep -oP '(?<=[?&])[^=&]+' | sort -u > unique_params.txt

   # GAU (Get All URLs from archives)
   echo target.com | gau | grep \"=\" > urls_with_params.txt
   ```

2. HIDDEN PARAMETER DISCOVERY (FUZZING):
   ```bash
   # Arjun (HTTP parameter discovery)
   arjun -u https://target.com/api/users -m GET
   arjun -u https://target.com/api/users -m POST

   # x8 (hidden parameter discovery)
   x8 -u \"https://target.com/api/users\" -w params.txt

   # Param Miner (Burp extension)
   # Install via Burp Extender, right-click request → \"Guess params\"
   ```

3. API PARAMETER ENUMERATION:
   ```bash
   # GraphQL introspection
   python3 graphql-introspection.py https://target.com/graphql

   # REST API parameter extraction
   curl -s https://target.com/api/swagger.json | jq '.paths[][].parameters[].name' | sort -u

   # Test parameter variations
   ffuf -u https://target.com/api/users?FUZZ=test -w params.txt -mc 200
   ```

4. FORM PARAMETER IDENTIFICATION:
   ```bash
   # Extract forms and inputs
   curl -s https://target.com | grep -Eo '<(input|select|textarea)[^>]*' | grep -Eo 'name=\"[^\"]*\"'

   # Find hidden inputs
   curl -s https://target.com | grep -Eo '<input[^>]*type=\"hidden\"[^>]*>'
   ```

WHAT TO LOOK FOR:
- Parameters controlling application logic
- File upload parameters
- Sorting/filtering parameters (SQL injection risk)
- Callback/redirect parameters (open redirect risk)
- Template parameters (SSTI risk)
- Command parameters (command injection risk)
- Debug/admin parameters
- API versioning parameters

SECURITY IMPLICATIONS:
- Hidden parameters may bypass security controls
- Undocumented parameters often lack input validation
- Debug parameters may expose sensitive information
- Admin parameters may grant elevated privileges

COMMON PITFALLS:
- Some parameters only available after authentication
- AJAX requests may use different parameter formats
- Parameters may be encoded or encrypted
- Rate limiting can slow parameter fuzzing
- GraphQL and REST APIs use different parameter structures

TOOLS REFERENCE:
- Arjun: https://github.com/s0md3v/Arjun
- ParamSpider: https://github.com/devanshbatham/ParamSpider
- x8: https://github.com/Sh1Yo/x8
- GAU: https://github.com/lc/gau"
    ),
];