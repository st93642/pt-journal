pub const JAVASCRIPT_ANALYSIS_STEPS: &[(&str, &str)] = &[
    (
        "JavaScript analysis",
        "OBJECTIVE: Extract and analyze JavaScript files to discover hidden API endpoints, exposed secrets, client-side logic vulnerabilities, and sensitive information hardcoded in frontend code.

STEP-BY-STEP PROCESS:

1. JAVASCRIPT FILE COLLECTION:
   ```bash
   # Extract all JS files from target
   echo \"https://target.com\" | hakrawler | grep -E '\\.js($|\\?)' > js_files.txt

   # Using getJS
   getJS --url https://target.com --output jsfiles.txt

   # Download all JS files
   wget -i js_files.txt -P js_downloads/
   ```

2. ENDPOINT EXTRACTION FROM JS:
   ```bash
   # LinkFinder (regex-based endpoint extraction)
   python3 linkfinder.py -i https://target.com/app.js -o cli

   # Extract API endpoints
   grep -rEo \"(https?://|/)(api|v[0-9])[^'\\\"\\s]*\" js_downloads/ | sort -u

   # Find internal URLs
   grep -rEo \"(https?://)?(www\\.)?target\\.com[^'\\\"\\s]*\" js_downloads/ | sort -u
   ```

3. SECRET AND API KEY HUNTING:
   ```bash
   # Search for common secret patterns
   grep -rEi \"(api[_-]?key|apikey|api_secret|access[_-]?token|auth[_-]?token|client[_-]?secret)\" js_downloads/

   # AWS keys
   grep -rE \"AKIA[0-9A-Z]{16}\" js_downloads/

   # Private keys
   grep -rE \"BEGIN.*PRIVATE KEY\" js_downloads/

   # Passwords and credentials
   grep -rEi \"(password|passwd|pwd)\\s*[:=]\\s*['\\\"][^'\\\"]{6,}\" js_downloads/

   # Nuclei secret scanning
   nuclei -t exposures/ -l js_files.txt
   ```

4. SOURCE MAP ANALYSIS:
   ```bash
   # Find .map files
   grep -rE '\\.js\\.map' js_downloads/ > source_maps.txt

   # Download source maps
   cat source_maps.txt | while read map; do wget \"$map\"; done

   # Extract original source from maps
   python3 sourcemapper.py -u https://target.com/app.js.map
   ```

5. WEBPACK AND BUILD ANALYSIS:
   ```bash
   # Identify webpack bundles
   grep -l \"webpackJsonp\" js_downloads/*.js

   # Extract webpack module paths
   grep -oP '/\\*.*?\\*/' js_downloads/bundle.js | sort -u
   ```

WHAT TO LOOK FOR:
- Hardcoded API keys and tokens
- Internal API endpoints not in documentation
- AWS/GCP/Azure credentials
- Database connection strings
- Admin panel URLs
- Debug/development endpoints
- OAuth secrets and client IDs
- Encryption keys and salts

SECURITY IMPLICATIONS:
- Exposed API keys grant unauthorized access
- Hardcoded credentials enable authentication bypass
- Hidden endpoints may lack security controls
- Source maps reveal original unobfuscated code
- Client-side validation can be bypassed

COMMON PITFALLS:
- Minified code requires de-obfuscation tools
- Some API keys are intentionally public (analytics)
- Dynamic JavaScript loading may be missed
- Source maps may not be available for all files
- Obfuscated code can hide analysis-resistant techniques

TOOLS REFERENCE:
- LinkFinder: https://github.com/GerbenJavado/LinkFinder
- getJS: https://github.com/003random/getJS
- SecretFinder: https://github.com/m4ll0k/SecretFinder
- JSParser: https://github.com/nahamsec/JSParser"
    ),
];