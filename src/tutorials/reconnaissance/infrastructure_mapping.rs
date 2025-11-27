pub const INFRASTRUCTURE_MAPPING_STEPS: &[(&str, &str)] = &[
    (
        "Infrastructure mapping",
        "OBJECTIVE: Map the complete network infrastructure, topology, and architecture to understand organizational structure, identify key network assets, and discover potential attack paths through infrastructure relationships.

STEP-BY-STEP PROCESS:

1. AUTONOMOUS SYSTEM (AS) AND BGP ANALYSIS:
   ```bash
   # Find organization's AS number
   whois -h whois.radb.net target.com | grep -i origin

   # Get all IP ranges for an AS
   whois -h whois.radb.net -- '-i origin AS12345' | grep -E \"^route:\"

   # BGP toolkit queries
   curl \"https://bgp.he.net/AS12345\" -s | grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+'

   # Check peering relationships
   whois -h whois.radb.net -- '-i origin AS12345' | grep -i \"import\\|export\"
   ```

2. NETWORK TOPOLOGY MAPPING:
   ```bash
   # Traceroute analysis
   traceroute -I target.com
   mtr --report target.com  # Better than traceroute

   # Paris traceroute (avoids load balancing issues)
   paris-traceroute target.com

   # TCP traceroute (when ICMP blocked)
   tcptraceroute target.com 443
   ```

3. CDN AND WAF DETECTION:
   ```bash
   # Check for CDN via headers and DNS
   curl -I https://target.com | grep -iE '(cf-ray|x-amz|x-cache|server)'

   # WAF detection with wafw00f
   wafw00f https://target.com

   # Identify CDN provider
   dig target.com | grep -A2 'ANSWER SECTION'
   ```

WHAT TO LOOK FOR:
- Network boundaries and segmentation
- Cloud vs on-premise infrastructure
- CDN and load balancer configurations
- Redundancy and failover mechanisms
- Third-party service dependencies

COMMON PITFALLS:
- Traceroute may be blocked by firewalls
- Cloud infrastructure uses dynamic IPs
- CDN masks origin server details
- Virtual networks complicate topology mapping
- Infrastructure documentation may be outdated"
    ),
];