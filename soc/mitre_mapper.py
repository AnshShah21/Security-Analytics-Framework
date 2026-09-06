# soc/mitre_mapper.py
"""
MITRE ATT&CK Dynamic Mapper
=============================
Scores all rules against each incident and picks the best match.

Scoring:
  +1  per keyword matched in reason string
  +3/2/1 for confidence High/Medium/Low
  +3  bonus if protocol matches exactly

Fix in this version:
  - Added TLS deprecated/ssl version/weak cipher/expired cert keywords
  - Added CONN beaconing short-connection keywords
  - Added HTTP suspicious content-type / octet-stream keywords
  - All previously unmapped N/A cases now have a fallback
"""

import json
import os

INPUT_FILE  = os.path.join("alerts", "final_incidents.json")
OUTPUT_FILE = os.path.join("alerts", "final_incidents.json")


# ─────────────────────────────────────────────────────────────────────────────
# Rule engine
# ─────────────────────────────────────────────────────────────────────────────

RULES = [

    # ══════════════════════════════════════════════════════════════════════
    # RECONNAISSANCE
    # ══════════════════════════════════════════════════════════════════════
    {
        "protocols": ["CONN", "TCP", "UDP"],
        "keywords": ["port scan", "scanning", "sweep", "nmap", "masscan", "service discovery"],
        "tactic": "Reconnaissance",
        "technique_id": "T1046",
        "technique": "Network Service Scanning",
        "confidence": "High"
    },
    {
        "protocols": ["DNS"],
        "keywords": ["reverse dns", "ptr lookup", "dns enumeration", "zone transfer", "axfr"],
        "tactic": "Reconnaissance",
        "technique_id": "T1590.002",
        "technique": "Gather Victim Network Information: DNS",
        "confidence": "High"
    },
    {
        "protocols": ["HTTP", "HTTPS"],
        "keywords": ["directory brute", "gobuster", "dirb", "nikto", "web scan", "crawler"],
        "tactic": "Reconnaissance",
        "technique_id": "T1595.003",
        "technique": "Active Scanning: Wordlist Scanning",
        "confidence": "High"
    },

    # ══════════════════════════════════════════════════════════════════════
    # INITIAL ACCESS
    # ══════════════════════════════════════════════════════════════════════
    {
        "protocols": ["SMTP", "IMAP", "POP3"],
        "keywords": ["phishing", "spearphish", "malicious attachment", "suspicious email",
                     "spoofed sender", "dkim fail", "spf fail"],
        "tactic": "Initial Access",
        "technique_id": "T1566",
        "technique": "Phishing",
        "confidence": "High"
    },
    {
        "protocols": ["SMTP"],
        "keywords": ["suspicious header", "forged", "relay", "open relay"],
        "tactic": "Initial Access",
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "confidence": "Medium"
    },
    {
        "protocols": ["HTTP", "HTTPS"],
        "keywords": ["exploit kit", "drive-by", "malicious redirect", "iframe injection"],
        "tactic": "Initial Access",
        "technique_id": "T1189",
        "technique": "Drive-by Compromise",
        "confidence": "High"
    },
    {
        "protocols": ["HTTP", "HTTPS", "FTP", "SMB"],
        "keywords": ["brute force", "password spray", "credential stuffing",
                     "login attempt", "failed login", "repeated auth"],
        "tactic": "Initial Access",
        "technique_id": "T1110",
        "technique": "Brute Force",
        "confidence": "High"
    },
    {
        "protocols": [],
        "keywords": ["vpn", "external remote", "rdp", "remote desktop", "ssh login",
                     "remote access"],
        "tactic": "Initial Access",
        "technique_id": "T1133",
        "technique": "External Remote Services",
        "confidence": "Medium"
    },

    # ══════════════════════════════════════════════════════════════════════
    # EXECUTION
    # ══════════════════════════════════════════════════════════════════════
    {
        "protocols": ["HTTP", "HTTPS"],
        "keywords": ["powershell", "cmd.exe", "wscript", "cscript", "mshta",
                     "script execution", "base64 encoded command"],
        "tactic": "Execution",
        "technique_id": "T1059.001",
        "technique": "Command and Scripting Interpreter: PowerShell",
        "confidence": "High"
    },
    {
        "protocols": ["HTTP", "HTTPS", "DNS"],
        "keywords": ["download cradle", "invoke-expression", "iex", "wget", "curl payload",
                     "dropper", "stager"],
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "confidence": "Medium"
    },
    {
        "protocols": ["HTTP", "HTTPS"],
        "keywords": ["sql injection", "sqli", "union select", "blind sql", "error based",
                     "time based"],
        "tactic": "Execution",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "confidence": "High"
    },
    {
        "protocols": ["HTTP", "HTTPS"],
        "keywords": ["xss", "cross-site scripting", "javascript injection", "dom injection"],
        "tactic": "Execution",
        "technique_id": "T1059.007",
        "technique": "Command and Scripting Interpreter: JavaScript",
        "confidence": "High"
    },

    # ══════════════════════════════════════════════════════════════════════
    # PERSISTENCE
    # ══════════════════════════════════════════════════════════════════════
    {
        "protocols": ["HTTP", "HTTPS"],
        "keywords": ["webshell", "web shell", "c99", "r57", "php shell", "jsp shell"],
        "tactic": "Persistence",
        "technique_id": "T1505.003",
        "technique": "Server Software Component: Web Shell",
        "confidence": "High"
    },
    {
        "protocols": [],
        "keywords": ["scheduled task", "cron job", "at.exe", "schtasks", "launchd",
                     "startup entry"],
        "tactic": "Persistence",
        "technique_id": "T1053",
        "technique": "Scheduled Task/Job",
        "confidence": "High"
    },

    # ══════════════════════════════════════════════════════════════════════
    # PRIVILEGE ESCALATION
    # ══════════════════════════════════════════════════════════════════════
    {
        "protocols": [],
        "keywords": ["privilege escalation", "privesc", "sudo", "setuid",
                     "token impersonation", "uac bypass"],
        "tactic": "Privilege Escalation",
        "technique_id": "T1548",
        "technique": "Abuse Elevation Control Mechanism",
        "confidence": "High"
    },

    # ══════════════════════════════════════════════════════════════════════
    # DEFENSE EVASION
    # ══════════════════════════════════════════════════════════════════════

    # ── TLS / SSL weak config — THIS is what was causing N/A ─────────────
    {
        "protocols": ["TLS", "HTTPS", "SSL"],
        "keywords": ["deprecated tls", "tls 1.0", "tls 1.1", "ssl 2.0", "ssl 3.0",
                     "weak cipher", "null cipher", "export cipher", "rc4",
                     "insecure protocol", "deprecated ssl", "tls version",
                     "weak tls", "obsolete tls", "legacy tls", "outdated tls"],
        "tactic": "Defense Evasion",
        "technique_id": "T1573.002",
        "technique": "Encrypted Channel: Asymmetric Cryptography (Weak TLS)",
        "confidence": "High"
    },
    {
        "protocols": ["TLS", "HTTPS"],
        "keywords": ["self-signed cert", "invalid certificate", "certificate mismatch",
                     "expired cert", "untrusted ca", "cert error", "bad certificate"],
        "tactic": "Defense Evasion",
        "technique_id": "T1553.004",
        "technique": "Subvert Trust Controls: Install Root Certificate",
        "confidence": "Medium"
    },
    {
        "protocols": ["HTTP", "HTTPS", "DNS"],
        "keywords": ["obfuscated", "encoded payload", "base64", "hex encoded",
                     "encrypted payload", "packed"],
        "tactic": "Defense Evasion",
        "technique_id": "T1027",
        "technique": "Obfuscated Files or Information",
        "confidence": "Medium"
    },
    {
        "protocols": ["HTTP", "HTTPS"],
        "keywords": ["missing user-agent", "missing http user-agent", "empty user-agent",
                     "no user-agent", "blank user-agent"],
        "tactic": "Defense Evasion",
        "technique_id": "T1036",
        "technique": "Masquerading",
        "confidence": "Medium"
    },
    {
        "protocols": ["TLS", "HTTPS"],
        "keywords": ["domain fronting", "cdn fronting", "host header mismatch"],
        "tactic": "Defense Evasion",
        "technique_id": "T1090.004",
        "technique": "Proxy: Domain Fronting",
        "confidence": "High"
    },

    # ══════════════════════════════════════════════════════════════════════
    # CREDENTIAL ACCESS
    # ══════════════════════════════════════════════════════════════════════
    {
        "protocols": ["FTP", "TELNET", "HTTP", "SMTP", "POP3", "IMAP"],
        "keywords": ["cleartext", "plain text credential", "unencrypted login",
                     "plaintext password", "clear text auth"],
        "tactic": "Credential Access",
        "technique_id": "T1552.001",
        "technique": "Unsecured Credentials: Credentials in Files",
        "confidence": "High"
    },
    {
        "protocols": [],
        "keywords": ["credential dump", "mimikatz", "lsass", "ntlm hash", "kerberoast",
                     "golden ticket", "pass the hash", "pass the ticket"],
        "tactic": "Credential Access",
        "technique_id": "T1003",
        "technique": "OS Credential Dumping",
        "confidence": "High"
    },
    {
        "protocols": ["HTTP", "HTTPS", "FTP", "SSH"],
        "keywords": ["brute force", "password spray", "dictionary attack",
                     "credential stuffing", "failed auth"],
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique": "Brute Force",
        "confidence": "High"
    },

    # ══════════════════════════════════════════════════════════════════════
    # DISCOVERY
    # ══════════════════════════════════════════════════════════════════════
    {
        "protocols": ["CONN", "TCP", "UDP", "ICMP"],
        "keywords": ["ping sweep", "icmp sweep", "host discovery", "arp scan",
                     "network sweep"],
        "tactic": "Discovery",
        "technique_id": "T1018",
        "technique": "Remote System Discovery",
        "confidence": "High"
    },
    {
        "protocols": ["SMB", "LDAP", "CONN"],
        "keywords": ["smb enum", "share enumeration", "ldap query", "active directory enum",
                     "ad enum", "domain enum"],
        "tactic": "Discovery",
        "technique_id": "T1087",
        "technique": "Account Discovery",
        "confidence": "High"
    },
    {
        "protocols": ["DNS"],
        "keywords": ["repeated dns", "dns query flood", "excessive dns", "dns enumeration"],
        "tactic": "Discovery",
        "technique_id": "T1018",
        "technique": "Remote System Discovery via DNS",
        "confidence": "Medium"
    },

    # ══════════════════════════════════════════════════════════════════════
    # LATERAL MOVEMENT
    # ══════════════════════════════════════════════════════════════════════
    {
        "protocols": ["SMB", "CONN"],
        "keywords": ["smb", "psexec", "wmi lateral", "lateral movement",
                     "remote exec", "admin share"],
        "tactic": "Lateral Movement",
        "technique_id": "T1021.002",
        "technique": "Remote Services: SMB/Windows Admin Shares",
        "confidence": "High"
    },
    {
        "protocols": ["SSH", "CONN"],
        "keywords": ["ssh lateral", "ssh pivot", "ssh tunnel lateral", "jump host"],
        "tactic": "Lateral Movement",
        "technique_id": "T1021.004",
        "technique": "Remote Services: SSH",
        "confidence": "High"
    },
    {
        "protocols": ["CONN", "TCP"],
        "keywords": ["rdp", "remote desktop", "mstsc", "ts client"],
        "tactic": "Lateral Movement",
        "technique_id": "T1021.001",
        "technique": "Remote Services: Remote Desktop Protocol",
        "confidence": "High"
    },

    # ══════════════════════════════════════════════════════════════════════
    # COLLECTION
    # ══════════════════════════════════════════════════════════════════════
    {
        "protocols": ["HTTP", "HTTPS", "FTP", "SMB"],
        "keywords": ["large upload", "large post", "bulk transfer", "file collection",
                     "data staging", "archive transfer"],
        "tactic": "Collection",
        "technique_id": "T1074",
        "technique": "Data Staged",
        "confidence": "Medium"
    },

    # ══════════════════════════════════════════════════════════════════════
    # COMMAND AND CONTROL
    # ══════════════════════════════════════════════════════════════════════
    {
        "protocols": ["DNS"],
        "keywords": ["dns tunnel", "dns tunneling", "dnscat", "iodine", "dns exfil",
                     "long dns query", "high entropy dns"],
        "tactic": "Command and Control",
        "technique_id": "T1071.004",
        "technique": "Application Layer Protocol: DNS",
        "confidence": "High"
    },
    {
        "protocols": ["DNS"],
        "keywords": ["dga", "domain generation", "high entropy", "random domain",
                     "algorithmically generated", "high entropy dns query",
                     "possible dga"],
        "tactic": "Command and Control",
        "technique_id": "T1568.002",
        "technique": "Dynamic Resolution: Domain Generation Algorithms",
        "confidence": "High"
    },
    {
        "protocols": ["HTTP", "HTTPS"],
        "keywords": ["c2", "command and control", "beacon", "beaconing", "callback",
                     "heartbeat", "checkin", "check-in", "periodic http"],
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique": "Application Layer Protocol: Web Protocols",
        "confidence": "High"
    },
    {
        "protocols": ["TLS", "HTTPS"],
        "keywords": ["ja3", "ja3s", "tls fingerprint", "ssl fingerprint",
                     "suspicious tls", "ja3 fingerprint observed"],
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique": "Application Layer Protocol: Web Protocols (TLS)",
        "confidence": "Medium"
    },
    {
        "protocols": ["CONN", "TCP", "UDP"],
        "keywords": ["repeated short", "beaconing", "periodic connection", "c2 beacon",
                     "regular interval", "short duration repeated",
                     "possible beaconing", "repeated short connections"],
        "tactic": "Command and Control",
        "technique_id": "T1071",
        "technique": "Application Layer Protocol",
        "confidence": "High"
    },
    {
        "protocols": ["CONN"],
        "keywords": ["long duration", "persistent connection", "long lived",
                     "keep-alive abuse"],
        "tactic": "Command and Control",
        "technique_id": "T1571",
        "technique": "Non-Standard Port",
        "confidence": "Medium"
    },
    {
        "protocols": [],
        "keywords": ["tor", "onion", "i2p", "anonymiz", "proxy chain", "socks proxy",
                     "encrypted tunnel"],
        "tactic": "Command and Control",
        "technique_id": "T1090",
        "technique": "Proxy",
        "confidence": "High"
    },
    {
        "protocols": ["IRC", "CONN"],
        "keywords": ["irc", "botnet", "bot command", "bot channel"],
        "tactic": "Command and Control",
        "technique_id": "T1095",
        "technique": "Non-Application Layer Protocol",
        "confidence": "High"
    },

    # ══════════════════════════════════════════════════════════════════════
    # EXFILTRATION
    # ══════════════════════════════════════════════════════════════════════
    {
        "protocols": ["HTTP", "HTTPS", "FTP", "SFTP"],
        "keywords": ["exfiltration", "data exfil", "data leak",
                     "sensitive data outbound", "large outbound", "upload to external"],
        "tactic": "Exfiltration",
        "technique_id": "T1048",
        "technique": "Exfiltration Over Alternative Protocol",
        "confidence": "High"
    },
    {
        "protocols": ["DNS"],
        "keywords": ["dns exfil", "data in dns", "txt record exfil", "dns covert channel"],
        "tactic": "Exfiltration",
        "technique_id": "T1048.003",
        "technique": "Exfiltration Over Unencrypted Non-C2 Protocol",
        "confidence": "High"
    },
    {
        "protocols": ["HTTP", "HTTPS"],
        "keywords": ["large post payload", "large http post payload",
                     "possible data exfiltration", "high entropy uri",
                     "encoded uri", "large http post"],
        "tactic": "Exfiltration",
        "technique_id": "T1041",
        "technique": "Exfiltration Over C2 Channel",
        "confidence": "Medium"
    },
    {
        "protocols": ["ICMP", "CONN"],
        "keywords": ["icmp tunnel", "icmp exfil", "covert icmp", "ping payload"],
        "tactic": "Exfiltration",
        "technique_id": "T1048.003",
        "technique": "Exfiltration Over Unencrypted Non-C2 Protocol: ICMP",
        "confidence": "High"
    },

    # ══════════════════════════════════════════════════════════════════════
    # IMPACT
    # ══════════════════════════════════════════════════════════════════════
    {
        "protocols": ["UDP", "TCP", "CONN", "ICMP"],
        "keywords": ["ddos", "flood", "dos attack", "syn flood", "udp flood",
                     "amplification", "reflection attack", "volumetric"],
        "tactic": "Impact",
        "technique_id": "T1498",
        "technique": "Network Denial of Service",
        "confidence": "High"
    },
    {
        "protocols": [],
        "keywords": ["ransomware", "encrypted files", "ransom note", "file encryption",
                     "wiper", "disk wipe"],
        "tactic": "Impact",
        "technique_id": "T1486",
        "technique": "Data Encrypted for Impact",
        "confidence": "High"
    },
    {
        "protocols": [],
        "keywords": ["cryptominer", "mining pool", "stratum protocol", "coinhive",
                     "xmrig", "monero miner", "crypto mining"],
        "tactic": "Resource Development",
        "technique_id": "T1496",
        "technique": "Resource Hijacking",
        "confidence": "High"
    },

    # ══════════════════════════════════════════════════════════════════════
    # PROTOCOL CATCH-ALLS  (low confidence — always last resort)
    # ══════════════════════════════════════════════════════════════════════

    # TLS generic fallback — catches any TLS alert that didn't match above
    {
        "protocols": ["TLS"],
        "keywords": ["tls", "ssl", "certificate", "cipher", "handshake",
                     "fingerprint", "protocol"],
        "tactic": "Command and Control",
        "technique_id": "T1573.002",
        "technique": "Encrypted Channel: Asymmetric Cryptography",
        "confidence": "Low"
    },
    {
        "protocols": ["FTP"],
        "keywords": ["ftp", "file transfer", "anonymous ftp"],
        "tactic": "Lateral Movement",
        "technique_id": "T1021.003",
        "technique": "Remote Services: Distributed Component Object Model",
        "confidence": "Low"
    },
    {
        "protocols": ["TELNET"],
        "keywords": ["telnet"],
        "tactic": "Credential Access",
        "technique_id": "T1552.001",
        "technique": "Unsecured Credentials: Cleartext Protocol (Telnet)",
        "confidence": "Medium"
    },
    {
        "protocols": ["HTTP"],
        "keywords": ["suspicious http", "suspicious content-type", "octet-stream",
                     "xml content", "missing http"],
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique": "Application Layer Protocol: Web Protocols",
        "confidence": "Low"
    },
    # CONN generic fallback — outbound connection to external IP
    {
        "protocols": ["CONN"],
        "keywords": ["outbound connection", "external ip", "outbound to external",
                     "connection to external"],
        "tactic": "Command and Control",
        "technique_id": "T1071",
        "technique": "Application Layer Protocol",
        "confidence": "Low"
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Scoring engine
# ─────────────────────────────────────────────────────────────────────────────

CONFIDENCE_SCORE = {"High": 3, "Medium": 2, "Low": 1}


def map_mitre(incident: dict) -> dict:
    protocol = incident.get("protocol", "").upper()
    reason   = incident.get("reason",   "").lower()

    best       = None
    best_score = -1

    for rule in RULES:
        proto_match = (
            not rule["protocols"] or
            protocol in [p.upper() for p in rule["protocols"]]
        )
        hits = sum(1 for kw in rule["keywords"] if kw in reason)
        if hits == 0:
            continue

        score = hits + CONFIDENCE_SCORE.get(rule["confidence"], 1)
        if proto_match:
            score += 3

        if score > best_score:
            best_score = score
            best = rule

    if best:
        return {
            "tactic":       best["tactic"],
            "technique_id": best["technique_id"],
            "technique":    best["technique"],
            "confidence":   best["confidence"],
            "match_score":  best_score
        }

    return {
        "tactic":       "Unknown",
        "technique_id": "N/A",
        "technique":    "Unmapped Technique",
        "confidence":   "None",
        "match_score":  0
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if not os.path.exists(INPUT_FILE):
        print("[-] final_incidents.json not found")
        return

    with open(INPUT_FILE, "r") as f:
        data = json.load(f)

    incidents = data.get("incidents", [])
    mapped = unmapped = 0

    for incident in incidents:
        result = map_mitre(incident)
        incident["mitre"] = result
        if result["technique_id"] != "N/A":
            mapped += 1
        else:
            unmapped += 1

    data["mitre_coverage"] = mapped
    data["mitre_unmapped"] = unmapped
    data["mitre_total"]    = len(incidents)
    data["mitre_pct"]      = round(mapped / len(incidents) * 100, 1) if incidents else 0

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[+] MITRE mapping complete — {mapped}/{len(incidents)} mapped ({data['mitre_pct']}%)")
    if unmapped:
        print(f"    Still unmapped: {unmapped} — check reason strings for those incidents")


if __name__ == "__main__":
    main()