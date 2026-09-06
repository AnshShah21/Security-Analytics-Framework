import subprocess
import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

OUTPUT_DIR = "alerts"
NMAP_BINARY = os.getenv("NMAP_BINARY", r"C:\Program Files (x86)\Nmap\nmap.exe")

# ── CVE hints by service+version keyword ──────────────────────────────────────
CVE_HINTS = {
    "apache 2.4.49": [{"cve": "CVE-2021-41773", "severity": "Critical", "desc": "Path traversal & RCE"}],
    "apache 2.4.50": [{"cve": "CVE-2021-42013", "severity": "Critical", "desc": "Path traversal bypass"}],
    "openssh 7.4":   [{"cve": "CVE-2018-15473", "severity": "Medium",   "desc": "Username enumeration"}],
    "openssh 8.0":   [{"cve": "CVE-2020-14145", "severity": "Medium",   "desc": "Observable discrepancy"}],
    "vsftpd 2.3.4":  [{"cve": "CVE-2011-2523", "severity": "Critical",  "desc": "Backdoor command execution"}],
    "proftpd 1.3.5": [{"cve": "CVE-2015-3306", "severity": "High",      "desc": "Arbitrary file read/write"}],
    "ms-wbt-server": [{"cve": "CVE-2019-0708", "severity": "Critical",  "desc": "BlueKeep RCE (RDP)"}],
    "microsoft rdp": [{"cve": "CVE-2019-0708", "severity": "Critical",  "desc": "BlueKeep RCE (RDP)"}],
    "smb":           [{"cve": "CVE-2017-0144", "severity": "Critical",  "desc": "EternalBlue MS17-010"}],
    "netbios":       [{"cve": "CVE-2017-0144", "severity": "Critical",  "desc": "EternalBlue MS17-010"}],
    "mysql 5.5":     [{"cve": "CVE-2012-2122", "severity": "High",      "desc": "Auth bypass"}],
    "mysql 5.6":     [{"cve": "CVE-2016-6662", "severity": "Critical",  "desc": "Config file injection"}],
    "redis":         [{"cve": "CVE-2022-0543", "severity": "Critical",  "desc": "Lua sandbox escape"}],
    "mongodb":       [{"cve": "CVE-2021-20328", "severity": "Medium",   "desc": "Certificate validation"}],
    "elasticsearch": [{"cve": "CVE-2021-22145", "severity": "Medium",   "desc": "Sensitive info disclosure"}],
    "nginx 1.16":    [{"cve": "CVE-2019-20372", "severity": "Medium",   "desc": "HTTP request smuggling"}],
    "iis 7.":        [{"cve": "CVE-2017-7269",  "severity": "Critical", "desc": "WebDAV buffer overflow"}],
    "iis 6.":        [{"cve": "CVE-2017-7269",  "severity": "Critical", "desc": "WebDAV buffer overflow"}],
    "php 5.":        [{"cve": "CVE-2019-11043",  "severity": "Critical", "desc": "RCE via FPM"}],
    "php 7.0":       [{"cve": "CVE-2019-11043",  "severity": "Critical", "desc": "RCE via FPM"}],
    "openssl 1.0.1": [{"cve": "CVE-2014-0160",  "severity": "High",     "desc": "Heartbleed"}],
    "openssl 1.0.2": [{"cve": "CVE-2016-0800",  "severity": "High",     "desc": "DROWN attack"}],
    "telnet":        [{"cve": "CVE-1999-0619",  "severity": "High",     "desc": "Cleartext credential transmission"}],
    "ftp":           [{"cve": "CVE-1999-0082",  "severity": "Medium",   "desc": "Anonymous FTP access"}],
    "snmp":          [{"cve": "CVE-2002-0013",  "severity": "High",     "desc": "SNMP community string guessing"}],
    "vnc":           [{"cve": "CVE-2019-15681", "severity": "Critical", "desc": "Unauthenticated access"}],
}

# ── Kill chain by service ──────────────────────────────────────────────────────
SERVICE_KILL_CHAIN = {
    "smtp": "Delivery", "submission": "Delivery", "smtps": "Delivery",
    "http": "Exploitation", "https": "Exploitation", "http-alt": "Exploitation",
    "iis":  "Exploitation", "nginx": "Exploitation", "apache": "Exploitation",
    "ssh":  "Exploitation", "telnet": "Exploitation", "ftp": "Exploitation",
    "rdp":  "Exploitation", "ms-wbt-server": "Exploitation", "vnc": "Exploitation",
    "smb":  "Exploitation", "netbios": "Exploitation", "microsoft-ds": "Exploitation",
    "mysql": "Actions on Objectives", "redis": "Actions on Objectives",
    "mongodb": "Actions on Objectives", "postgresql": "Actions on Objectives",
    "elasticsearch": "Actions on Objectives", "memcache": "Actions on Objectives",
    "docker": "Installation", "kubernetes": "Installation",
    "snmp":   "Reconnaissance", "dns": "Reconnaissance",
}

PORT_KILL_CHAIN = {
    25: "Delivery", 465: "Delivery", 587: "Delivery",
    80: "Exploitation", 443: "Exploitation", 8080: "Exploitation", 8443: "Exploitation",
    22: "Exploitation", 23: "Exploitation", 21: "Exploitation",
    3389: "Exploitation", 5900: "Exploitation", 445: "Exploitation", 139: "Exploitation",
    3306: "Actions on Objectives", 6379: "Actions on Objectives",
    27017: "Actions on Objectives", 5432: "Actions on Objectives",
    9200: "Actions on Objectives", 9300: "Actions on Objectives",
    2375: "Installation", 2376: "Installation",
    161: "Reconnaissance", 53: "Reconnaissance",
}

# ── Risky service flag messages ────────────────────────────────────────────────
RISK_FLAGS = {
    "telnet": "Cleartext protocol — credentials transmitted in plaintext",
    "ftp":    "Cleartext FTP — check for anonymous login and sniff risk",
    "rdp":    "RDP exposed — check for BlueKeep (CVE-2019-0708), enable NLA",
    "vnc":    "VNC exposed — verify authentication is required",
    "smb":    "SMB exposed — check MS17-010 / EternalBlue patch status",
    "netbios":"NetBIOS exposed — lateral movement and enumeration risk",
    "mysql":  "Database exposed to network — restrict to localhost only",
    "redis":  "Redis exposed — commonly unauthenticated, RCE risk",
    "mongodb":"MongoDB exposed — verify authentication is enabled",
    "elasticsearch": "Elasticsearch exposed — no auth by default, data leak risk",
    "snmp":  "SNMP exposed — community strings may allow full device control",
    "docker":"Docker API exposed — full host access if unauthenticated",
}


def get_cves(service_name: str, version_str: str) -> list:
    combined = f"{service_name} {version_str}".lower()
    for keyword, cves in CVE_HINTS.items():
        if keyword in combined:
            return cves
    return []


def get_kill_chain(service_name: str, port: int) -> str:
    svc = service_name.lower()
    for key, stage in SERVICE_KILL_CHAIN.items():
        if key in svc:
            return stage
    return PORT_KILL_CHAIN.get(port, "Exploitation")


def get_severity(cves: list, nse_output: str, service_name: str) -> str:
    # Priority 1: CVE severity
    if cves:
        order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        return max(cves, key=lambda c: order.get(c["severity"], 0))["severity"]
    # Priority 2: NSE vuln script confirmed vulnerable
    nse_lower = (nse_output or "").lower()
    if any(k in nse_lower for k in ["vulnerable", "exploit", "cve-", "state: vulnerable"]):
        return "High"
    # Priority 3: inherently risky service
    svc = service_name.lower()
    if any(r in svc for r in ["telnet", "ftp", "rdp", "vnc", "smb", "netbios", "redis", "mongodb", "elasticsearch", "snmp", "docker"]):
        return "Medium"
    return "Info"


def get_risk_flag(service_name: str, cves: list, version: str) -> str:
    svc = service_name.lower()
    for key, flag in RISK_FLAGS.items():
        if key in svc:
            return flag
    if cves:
        return f"Known CVE: {cves[0]['cve']} — {cves[0]['desc']}"
    return ""


def run_nmap(target: str, flags: list = None) -> dict:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    xml_out = os.path.join(OUTPUT_DIR, "nmap_output.xml")

    if flags is None:
        flags = ["-sT", "-sV", "--version-intensity", "5", "-Pn", "-T4", "--top-ports", "1000"]

    # Ensure -sT is always present (no root needed on Windows)
    scan_types = {"-sT", "-sS", "-sU", "-sN", "-sF", "-sX"}
    if not any(f in scan_types for f in flags):
        flags = ["-sT"] + flags

    cmd = [NMAP_BINARY] + flags + ["-oX", xml_out, target]

    print("=" * 60)
    print(f"[NMAP] Target  : {target}")
    print(f"[NMAP] Command : {' '.join(cmd)}")
    print(f"[NMAP] XML out : {xml_out}")
    print("=" * 60)

    # Delete stale XML before every scan
    if os.path.exists(xml_out):
        os.remove(xml_out)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=300)
        print(f"[NMAP] Return code : {result.returncode}")
        if result.stdout.strip():
            print(f"[NMAP] stdout:\n{result.stdout.strip()[:600]}")
        if result.stderr.strip():
            print(f"[NMAP] stderr:\n{result.stderr.strip()[:200]}")
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Nmap scan timed out (300s). Try fewer ports or a faster target."}
    except Exception as e:
        return {"status": "error", "message": f"Nmap launch failed: {str(e)}"}

    if not os.path.exists(xml_out):
        return {"status": "error", "message": f"Nmap produced no XML output at {xml_out}"}

    file_size = os.path.getsize(xml_out)
    print(f"[NMAP] XML file size: {file_size} bytes")

    findings = parse_nmap_xml(xml_out)
    print(f"[NMAP] Parsed {len(findings)} findings")
    for f in findings:
        print(f"[NMAP]   port={f['port']}  svc={f['service']}  ver={f['version']}  sev={f['severity']}")

    output_file = os.path.join(OUTPUT_DIR, "nmap_findings.json")
    with open(output_file, "w") as fh:
        json.dump({"generated_at": datetime.utcnow().isoformat(), "findings": findings}, fh, indent=4)

    print(f"[+] Saved {len(findings)} nmap findings → {output_file}")

    return {"status": "success", "findings": findings, "count": len(findings)}


def parse_nmap_xml(xml_file: str) -> list:
    findings = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[NMAP] XML parse error: {e}")
        return []

    open_count = 0
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr", "unknown") if addr is not None else "unknown"

        for port in host.findall(".//port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            open_count += 1
            portid   = int(port.get("portid", 0))
            protocol = port.get("protocol", "tcp")

            service = port.find("service")
            svc_name = service.get("name", "unknown") if service is not None else "unknown"
            product  = service.get("product", "") if service is not None else ""
            version  = service.get("version", "") if service is not None else ""
            os_type  = service.get("ostype", "Unknown") if service is not None else "Unknown"
            full_ver = f"{product} {version}".strip() or "unknown"

            # Collect NSE script output
            nse_output = ""
            nse_findings = []
            for script in port.findall(".//script"):
                script_id  = script.get("id", "")
                script_out = script.get("output", "")
                nse_output += f"\n{script_id}: {script_out}"
                if any(k in script_out.lower() for k in ["vulnerable", "exploit", "cve-", "state: vulnerable"]):
                    nse_findings.append({"script": script_id, "output": script_out})

            cves       = get_cves(svc_name, full_ver)
            severity   = get_severity(cves, nse_output, svc_name)
            kill_chain = get_kill_chain(svc_name, portid)
            risk_flag  = get_risk_flag(svc_name, cves, full_ver)

            findings.append({
                "host":             ip,
                "port":             portid,
                "protocol":         protocol,
                "service":          svc_name,
                "version":          full_ver,
                "os":               os_type,
                "severity":         severity,
                "risk_flag":        risk_flag,
                "kill_chain_stage": kill_chain,
                "cves":             cves,
                "nse_findings":     nse_findings,
                "remediation_hints": build_remediation(svc_name, portid, cves, risk_flag, full_ver),
            })

    print(f"[+] Parsed {open_count} open port findings from Nmap XML")
    return findings


def build_remediation(service: str, port: int, cves: list, risk_flag: str, version: str) -> list:
    hints = []
    svc = service.lower()

    if port == 3389 or "rdp" in svc or "ms-wbt-server" in svc:
        hints.append({"priority": "Critical", "action": "Apply BlueKeep patch (KB4499175). Enable NLA. Restrict RDP to VPN only.", "effort": "Medium", "reference": "CVE-2019-0708 / MS-KB4499175"})
        hints.append({"priority": "High",     "action": "Move RDP behind VPN gateway — never expose port 3389 to internet.", "effort": "Low", "reference": "CIS Control 9.2"})

    elif port in (445, 139) or "smb" in svc or "netbios" in svc or "microsoft-ds" in svc:
        hints.append({"priority": "Critical", "action": "Apply MS17-010 patch (KB4012212). Disable SMBv1 immediately.", "effort": "Low", "reference": "CVE-2017-0144 / MS17-010"})
        hints.append({"priority": "High",     "action": "Block TCP 445/139 at perimeter firewall — no public SMB exposure.", "effort": "Low", "reference": "NIST SP 800-77"})

    elif port == 22 or "ssh" in svc:
        hints.append({"priority": "High",   "action": "Enforce key-based authentication — disable password login (PasswordAuthentication no).", "effort": "Low",    "reference": "CIS Benchmark SSH"})
        hints.append({"priority": "Medium", "action": "Upgrade to OpenSSH 8.x+. Restrict SSH to admin VLAN/IP allowlist.", "effort": "Medium", "reference": "CVE-2018-15473"})

    elif port == 23 or "telnet" in svc:
        hints.append({"priority": "Critical", "action": "Disable Telnet immediately — replace with SSH. Telnet sends credentials in plaintext.", "effort": "Low", "reference": "NIST SP 800-115"})

    elif port == 21 or "ftp" in svc:
        hints.append({"priority": "High",   "action": "Disable FTP — migrate to SFTP or FTPS. Check for anonymous login (ftp/ftp).", "effort": "Medium", "reference": "CIS Control 9.4"})
        hints.append({"priority": "Medium", "action": "If FTP required: enable TLS (FTPS), restrict to allowlisted IPs.", "effort": "Medium", "reference": "RFC 4217"})

    elif port == 6379 or "redis" in svc:
        hints.append({"priority": "Critical", "action": "Bind Redis to 127.0.0.1 only. Enable requirepass authentication.", "effort": "Low", "reference": "CVE-2022-0543"})
        hints.append({"priority": "High",     "action": "Add firewall rule to block port 6379 from all external IPs.", "effort": "Low", "reference": "Redis Security Guide"})

    elif port == 27017 or "mongodb" in svc:
        hints.append({"priority": "Critical", "action": "Enable MongoDB authentication (--auth). Bind to localhost unless replication needed.", "effort": "Low", "reference": "MongoDB Security Checklist"})

    elif port in (9200, 9300) or "elasticsearch" in svc:
        hints.append({"priority": "Critical", "action": "Enable X-Pack security. Bind to localhost. Never expose 9200/9300 publicly.", "effort": "Medium", "reference": "CVE-2021-22145"})

    elif port in (3306, 5432) or "mysql" in svc or "postgresql" in svc:
        hints.append({"priority": "High",   "action": "Bind database to 127.0.0.1. Firewall block external access to port.", "effort": "Low", "reference": "CIS MySQL Benchmark"})
        hints.append({"priority": "Medium", "action": "Audit database user permissions — apply principle of least privilege.", "effort": "Medium", "reference": "NIST SP 800-53"})

    elif port in (2375, 2376) or "docker" in svc:
        hints.append({"priority": "Critical", "action": "Never expose Docker daemon TCP socket — use Unix socket only. This allows full host takeover.", "effort": "Low", "reference": "Docker Security Docs"})

    elif port == 161 or "snmp" in svc:
        hints.append({"priority": "High",   "action": "Replace SNMPv1/v2 with SNMPv3 with authPriv. Change default community strings.", "effort": "Medium", "reference": "CVE-2002-0013"})
        hints.append({"priority": "Medium", "action": "Restrict SNMP access to network management station IPs only.", "effort": "Low", "reference": "CIS Control 12.9"})

    elif port == 5900 or "vnc" in svc:
        hints.append({"priority": "High",   "action": "Tunnel VNC over SSH. Add password authentication. Restrict to LAN only.", "effort": "Low", "reference": "CVE-2019-15681"})

    elif cves:
        for cve in cves[:2]:
            hints.append({"priority": cve["severity"], "action": f"Apply vendor patch for {cve['cve']}: {cve['desc']}", "effort": "Medium", "reference": cve["cve"]})

    elif risk_flag:
        hints.append({"priority": "Medium", "action": f"Review exposure: {risk_flag}", "effort": "Low", "reference": "CIS Control 9"})

    if not hints:
        hints.append({"priority": "Low", "action": "Restrict port access at firewall. Review service hardening guide.", "effort": "Low", "reference": ""})

    return hints