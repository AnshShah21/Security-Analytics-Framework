# vapt/risk_correlation.py
"""
Risk Correlation Engine — Upgraded
=====================================
Cross-references SOC incidents + Nmap findings + Nuclei findings + Web Recon
into a unified per-host risk report with:

  1. Combined risk scoring (SOC + VAPT + Web recon)
  2. Cyber Kill Chain stage mapping per finding
  3. Structured remediation plan (Priority / Action / Effort / Reference)
  4. IR action recommendation
  5. MITRE ATT&CK technique aggregation across all sources
"""

import json
import os
import re
from datetime import datetime, timezone

_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_HERE)

SOC_FILE      = os.path.join(PROJECT_ROOT, "alerts", "final_incidents.json")
NMAP_FILE     = os.path.join(PROJECT_ROOT, "alerts", "nmap_findings.json")
NUCLEI_FILE   = os.path.join(PROJECT_ROOT, "alerts", "nuclei_findings.json")
WEB_RECON_FILE= os.path.join(PROJECT_ROOT, "alerts", "web_recon.json")
OUTPUT_FILE   = os.path.join(PROJECT_ROOT, "alerts", "correlated_risk.json")


# ─────────────────────────────────────────────────────────────────────────────
# Scoring weights
# ─────────────────────────────────────────────────────────────────────────────

SOC_WEIGHT = {"Critical": 50, "High": 35, "Medium": 20, "Low": 8}

VAPT_WEIGHT = {"Critical": 50, "High": 30, "Medium": 15, "Low": 5, "Info": 0}

WEB_CVE_WEIGHT = {"Critical": 45, "High": 28, "Medium": 12, "Low": 4}

HEADER_PENALTY = {"High": 10, "Medium": 5, "Low": 2}   # per missing header

CORRELATION_BOOST   = 15   # both SOC + VAPT confirm same host
WEB_RECON_BOOST     = 10   # web recon finds extra issues on host
SUBDOMAIN_BOOST     = 5    # each live risky subdomain


# ─────────────────────────────────────────────────────────────────────────────
# Cyber Kill Chain
# ─────────────────────────────────────────────────────────────────────────────
# Lockheed Martin 7-stage model

KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command & Control",
    "Actions on Objectives",
]

# Maps finding characteristics → kill chain stage
def map_kill_chain_stage(finding: dict, source: str) -> str:
    """
    Determine the kill chain stage for a single finding.
    Uses reason text, service name, port, Nuclei template tags, MITRE ID.
    """
    reason  = (finding.get("reason", "") or finding.get("name", "") or "").lower()
    service = (finding.get("service", "")).lower()
    mitre_field = finding.get("mitre", "")
    mitre   = (mitre_field.get("technique_id", "") if isinstance(mitre_field, dict) else mitre_field).upper()
    tags    = [t.lower() for t in (finding.get("tags", []) or [])]
    port    = finding.get("port", 0)

    # Reconnaissance indicators
    if any(k in reason for k in ["scan", "enum", "discovery", "recon", "probe",
                                  "port scan", "dns enum", "subdomain"]):
        return "Reconnaissance"
    if any(t in tags for t in ["recon", "network", "dns"]):
        return "Reconnaissance"
    if mitre in ("T1046", "T1595", "T1590", "T1018"):
        return "Reconnaissance"

    # Delivery indicators
    if any(k in reason for k in ["phish", "smtp", "email", "spear", "attachment",
                                  "malicious link", "drive-by"]):
        return "Delivery"
    if service in ("smtp", "imap", "pop3") or port in (25, 143, 110, 465, 587):
        return "Delivery"
    if mitre in ("T1566", "T1189", "T1203"):
        return "Delivery"

    # Exploitation indicators
    if any(k in reason for k in ["rce", "exploit", "injection", "sqli", "xss",
                                  "lfi", "rfi", "ssrf", "xxe", "overflow",
                                  "traversal", "heartbleed", "log4shell",
                                  "vulnerability", "cve"]):
        return "Exploitation"
    if any(t in tags for t in ["cve", "rce", "sqli", "xss", "lfi", "ssrf"]):
        return "Exploitation"
    if mitre.startswith("T1190") or mitre.startswith("T1203"):
        return "Exploitation"
    if finding.get("cves"):
        return "Exploitation"

    # Installation indicators
    if any(k in reason for k in ["webshell", "backdoor", "persistence", "rootkit",
                                  "malware", "implant", "dropper", "stager",
                                  "scheduled task", "startup"]):
        return "Installation"
    if any(t in tags for t in ["webshell", "backdoor"]):
        return "Installation"
    if mitre.startswith("T1505") or mitre.startswith("T1053"):
        return "Installation"

    # Command & Control indicators
    if any(k in reason for k in ["beacon", "beaconing", "c2", "command and control",
                                  "tunnel", "dga", "covert", "callback",
                                  "repeated short", "periodic", "ja3"]):
        return "Command & Control"
    if mitre.startswith("T1071") or mitre.startswith("T1095") or mitre.startswith("T1090"):
        return "Command & Control"

    # Actions on Objectives indicators
    if any(k in reason for k in ["exfiltration", "exfil", "data leak", "large post",
                                  "large payload", "ddos", "ransomware",
                                  "lateral", "privilege", "credential dump"]):
        return "Actions on Objectives"
    if mitre.startswith("T1048") or mitre.startswith("T1041") or mitre.startswith("T1498"):
        return "Actions on Objectives"

    # Default by source
    if source == "soc":
        return "Command & Control"
    if source in ("nmap", "nuclei"):
        return "Exploitation"
    if source == "web_recon":
        return "Reconnaissance"

    return "Exploitation"


# ─────────────────────────────────────────────────────────────────────────────
# Remediation Plan Builder
# ─────────────────────────────────────────────────────────────────────────────

def build_remediation_plan(
    soc_alerts: list,
    vapt_vulns: list,
    web_data:   dict,
    combined_risk: str
) -> list:
    """
    Build a structured, prioritized remediation plan for a host.

    Each item:
      priority    : 1 (immediate) → 4 (low)
      action      : what to do
      effort      : Low / Medium / High
      category    : Patch | Config | Network | Monitor | Process
      reference   : CVE ID, MITRE ID, or standard name
      deadline    : recommended fix window
    """
    plan = []
    seen = set()

    def add(priority, action, effort, category, reference="", deadline=""):
        key = action[:60]
        if key not in seen:
            seen.add(key)
            plan.append({
                "priority":  priority,
                "action":    action,
                "effort":    effort,
                "category":  category,
                "reference": reference,
                "deadline":  deadline,
            })

    # ── Priority 1 — Immediate (Critical findings) ────────────────────────────

    if combined_risk == "Critical":
        add(1, "Isolate host from network immediately — contain active threat",
            "Low", "Network", deadline="Now")

    # CVE-based remediations
    all_cves = []
    for v in vapt_vulns:
        for c in (v.get("cves") or []):
            all_cves.append((c, v))
    for c in (web_data.get("all_cves") or []):
        all_cves.append((c, {}))

    for cve_obj, finding in all_cves:
        cve_id  = cve_obj.get("cve", "")
        sev     = cve_obj.get("severity", "Low")
        desc    = cve_obj.get("desc", "")
        service = finding.get("service", "")
        port    = finding.get("port", "")
        priority = 1 if sev == "Critical" else 2 if sev == "High" else 3

        add(priority,
            f"Patch {service or 'service'} on port {port or '?'} — {desc}",
            "Medium", "Patch", cve_id,
            deadline="24h" if priority == 1 else "72h" if priority == 2 else "7d")

    # SOC-based remediations
    for alert in soc_alerts:
        reason = alert.get("reason", "").lower()
        risk   = alert.get("final_risk", "Low")
        ind    = alert.get("indicator", "")
        mitre  = (alert.get("mitre") or {}).get("technique_id", "")
        priority = 1 if risk == "Critical" else 2 if risk == "High" else 3

        if "beacon" in reason or "c2" in reason:
            add(priority,
                f"Block outbound traffic to {ind} — suspected C2 beaconing",
                "Low", "Network", mitre, deadline="1h")
        if "exfil" in reason or "large post" in reason or "large payload" in reason:
            add(1,
                f"Block outbound large data transfers from this host — possible exfiltration",
                "Low", "Network", "T1048", deadline="Now")
        if "brute" in reason or "password spray" in reason:
            add(priority,
                "Enable account lockout policy and MFA — brute force detected",
                "Medium", "Config", "T1110", deadline="4h")
        if "tunnel" in reason or "dga" in reason:
            add(1,
                "Block suspicious DNS queries — possible DNS tunneling or DGA activity",
                "Low", "Network", "T1071.004", deadline="1h")
        if "credential" in reason or "cleartext" in reason:
            add(priority,
                "Rotate all credentials for this host — plaintext credential exposure detected",
                "High", "Process", "T1552", deadline="2h")

    # ── Priority 2 — VAPT service hardening ──────────────────────────────────
    for v in vapt_vulns:
        risk_flag = v.get("risk_flag", "")
        service   = v.get("service", "")
        port      = v.get("port", "")

        if "telnet" in risk_flag.lower() or service == "telnet":
            add(2, f"Disable Telnet on port {port} — replace with SSH",
                "Low", "Config", "T1552.001", deadline="24h")
        if "ftp" in risk_flag.lower() and service != "sftp":
            add(2, f"Disable plain FTP on port {port} — migrate to SFTP/FTPS",
                "Low", "Config", "T1552.001", deadline="48h")
        if "rdp" in risk_flag.lower():
            add(2, "Restrict RDP access via VPN/jump host — enable NLA, disable if unused",
                "Medium", "Network", "CVE-2019-0708", deadline="24h")
        if "smb" in risk_flag.lower():
            add(2, "Disable SMBv1, apply MS17-010 patch — EternalBlue risk",
                "Medium", "Patch", "CVE-2017-0144", deadline="24h")
        if "redis" in risk_flag.lower() or service == "redis":
            add(1, f"Bind Redis port {port} to localhost, enable AUTH — critical exposure",
                "Low", "Config", deadline="2h")
        if "mongodb" in risk_flag.lower() or service == "mongodb":
            add(1, f"Enable MongoDB authentication on port {port} — unauthenticated by default",
                "Low", "Config", deadline="2h")
        if "elasticsearch" in risk_flag.lower() or service == "elasticsearch":
            add(2, f"Enable Elasticsearch security (X-Pack) on port {port}",
                "Medium", "Config", "CVE-2021-22145", deadline="24h")
        if "mysql" in service or "postgresql" in service:
            add(2, f"Restrict {service} port {port} to localhost — database exposed externally",
                "Low", "Config", deadline="24h")
        if "docker" in risk_flag.lower():
            add(1, f"Secure Docker daemon on port {port} — full host compromise possible",
                "Low", "Config", deadline="1h")
        if "ssh" in risk_flag.lower():
            add(3, "Enforce SSH key-based auth — disable PasswordAuthentication in sshd_config",
                "Low", "Config", deadline="7d")

    # ── Priority 3 — Web security headers ────────────────────────────────────
    missing_headers = (web_data.get("missing_headers") or
                       (web_data.get("main_probe") or {}).get("missing_headers") or [])
    for h in missing_headers:
        impact   = h.get("impact", "Low")
        priority = 2 if impact == "High" else 3 if impact == "Medium" else 4
        add(priority,
            f"Add missing HTTP header: {h['header']} — {h['desc']}",
            "Low", "Config", h.get("fix", ""), deadline="7d")

    leaky = (web_data.get("leaky_headers") or
             (web_data.get("main_probe") or {}).get("leaky_headers") or [])
    for h in leaky:
        add(3,
            f"Remove leaky header '{h['header']}' (exposes: {h['value'][:40]}) — info disclosure",
            "Low", "Config", deadline="7d")

    # ── Priority 4 — General best practices ──────────────────────────────────
    if web_data.get("waf_detected") is False and web_data.get("domain"):
        add(4, "Deploy a Web Application Firewall (WAF) — no WAF detected on this domain",
            "High", "Network", deadline="30d")

    add(4, "Enable comprehensive logging and SIEM alerting for this host",
        "Medium", "Monitor", deadline="14d")

    add(4, "Schedule a full penetration test for this host after patching",
        "High", "Process", deadline="30d")

    # Sort by priority
    plan.sort(key=lambda x: x["priority"])
    return plan


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def clamp(score: int) -> int:
    return max(0, min(score, 100))


def load_json(path: str, key: str = None):
    if not os.path.exists(path):
        print(f"[!] File not found: {path}")
        return [] if key else {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get(key, []) if key else data


def extract_ips(text: str) -> list:
    return re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", str(text))


def score_to_risk(score: int) -> str:
    if score >= 85: return "Critical"
    if score >= 65: return "High"
    if score >= 40: return "Medium"
    return "Low"


IR_ACTIONS = {
    (True,  True,  "Critical"): "IMMEDIATE ISOLATION — Active threat + exploitable vuln confirmed on same host",
    (True,  True,  "High"):     "URGENT — Patch + EDR investigation within 4 hours",
    (True,  True,  "Medium"):   "Patch within 48h + monitor — correlated medium-risk activity",
    (True,  False, "Critical"): "Investigate SOC alert — block outbound, capture memory image",
    (False, True,  "Critical"): "Emergency patch — critical CVE with no current SOC alert yet",
    (True,  False, "High"):     "Investigate and isolate — high-severity SOC alert",
    (False, True,  "High"):     "Patch within 24h — high CVE, no active incident yet",
    (True,  False, "Medium"):   "Log review + TI correlation recommended",
    (False, True,  "Medium"):   "Schedule patch in next maintenance window",
    (True,  False, "Low"):      "Low-priority review — SOC alert with low risk score",
    (False, True,  "Low"):      "Low-priority patch — minor finding, no active threat",
}


# ─────────────────────────────────────────────────────────────────────────────
# Main correlation engine
# ─────────────────────────────────────────────────────────────────────────────

def correlate() -> list:
    soc_incidents   = load_json(SOC_FILE,    "incidents")
    nmap_findings   = load_json(NMAP_FILE,   "findings")
    nuclei_findings = load_json(NUCLEI_FILE, "findings")
    web_recon       = load_json(WEB_RECON_FILE) or {}

    # ── Index VAPT findings by host IP ────────────────────────────────────────
    vapt_by_host: dict = {}
    for f in nmap_findings:
        ip = f.get("host", "").strip()
        if ip:
            vapt_by_host.setdefault(ip, []).append({**f, "source": "nmap"})

    for f in nuclei_findings:
        for ip in extract_ips(f.get("host", "")):
            vapt_by_host.setdefault(ip, []).append({**f, "source": "nuclei"})

    # ── Index web recon results by IP ─────────────────────────────────────────
    web_by_host: dict = {}
    main_ip = web_recon.get("main_ip", "")
    if main_ip:
        web_by_host[main_ip] = web_recon

    for sub in web_recon.get("subdomains", []):
        sub_ip = sub.get("resolved_ip", "")
        if sub_ip:
            web_by_host.setdefault(sub_ip, {
                "domain": sub.get("subdomain", ""),
                "main_probe": sub,
                "all_cves": sub.get("cves", []),
                "missing_headers": sub.get("missing_headers", []),
                "leaky_headers": sub.get("leaky_headers", []),
                "waf_detected": sub.get("waf_detected", False),
            })

    # ── Index SOC incidents by IP ─────────────────────────────────────────────
    soc_by_host: dict = {}
    for incident in soc_incidents:
        for ip in extract_ips(incident.get("indicator", "")):
            soc_by_host.setdefault(ip, []).append(incident)

    all_hosts = set(vapt_by_host.keys()) | set(soc_by_host.keys()) | set(web_by_host.keys())

    results = []

    for host in all_hosts:
        soc_alerts  = soc_by_host.get(host, [])
        vapt_vulns  = vapt_by_host.get(host, [])
        web_data    = web_by_host.get(host, {})

        has_soc    = bool(soc_alerts)
        has_vapt   = bool(vapt_vulns)
        has_web    = bool(web_data)

        # ── Scoring ───────────────────────────────────────────────────────────
        soc_score  = clamp(sum(SOC_WEIGHT.get(a.get("final_risk", "Low"), 0) for a in soc_alerts))
        vapt_score = clamp(sum(VAPT_WEIGHT.get(v.get("severity", "Info"), 0) for v in vapt_vulns))

        # Web recon score — CVEs found + header penalties
        web_cve_score = 0
        for c in (web_data.get("all_cves") or []):
            web_cve_score += WEB_CVE_WEIGHT.get(c.get("severity", "Low"), 0)
        web_cve_score = clamp(web_cve_score)

        missing_headers = (web_data.get("missing_headers") or
                           (web_data.get("main_probe") or {}).get("missing_headers") or [])
        header_penalty = sum(HEADER_PENALTY.get(h.get("impact", "Low"), 0) for h in missing_headers)

        # Boosts
        corr_boost  = CORRELATION_BOOST if has_soc and has_vapt else 0
        web_boost   = WEB_RECON_BOOST   if has_web and web_cve_score > 0 else 0
        sub_boost   = min(
            SUBDOMAIN_BOOST * len([s for s in web_data.get("subdomains", [])
                                   if s.get("cves")]),
            20
        ) if has_web else 0

        combined = clamp(soc_score + vapt_score + web_cve_score
                         + header_penalty + corr_boost + web_boost + sub_boost)
        combined_risk = score_to_risk(combined)

        # ── IR action ─────────────────────────────────────────────────────────
        action_key = (has_soc, has_vapt or has_web, combined_risk)
        ir_action  = IR_ACTIONS.get(action_key, "Monitor and review")

        # ── Kill chain mapping for every finding ──────────────────────────────
        kill_chain_hits = {}   # stage → list of finding names
        all_findings_tagged = []

        for alert in soc_alerts:
            stage = map_kill_chain_stage(alert, "soc")
            kill_chain_hits.setdefault(stage, []).append(
                alert.get("reason", "SOC alert")[:60]
            )
            all_findings_tagged.append({"source": "SOC", "stage": stage,
                                         "detail": alert.get("reason", "")[:80]})

        for v in vapt_vulns:
            stage = map_kill_chain_stage(v, v.get("source", "nmap"))
            kill_chain_hits.setdefault(stage, []).append(
                v.get("name", v.get("service", "VAPT finding"))[:60]
            )
            all_findings_tagged.append({"source": v.get("source","VAPT").upper(),
                                         "stage": stage,
                                         "detail": v.get("name", v.get("service", ""))[:80]})

        for c in (web_data.get("all_cves") or []):
            stage = "Exploitation"
            kill_chain_hits.setdefault(stage, []).append(c.get("cve", "")+" "+c.get("desc","")[:40])

        for h in missing_headers:
            stage = "Reconnaissance"  # missing headers aid attacker recon
            kill_chain_hits.setdefault(stage, []).append(f"Missing: {h['header']}")

        # Build ordered kill chain summary
        kill_chain_summary = [
            {
                "stage":   stage,
                "hit":     stage in kill_chain_hits,
                "count":   len(kill_chain_hits.get(stage, [])),
                "details": kill_chain_hits.get(stage, [])[:3],
            }
            for stage in KILL_CHAIN_STAGES
        ]

        stages_hit = [s for s in KILL_CHAIN_STAGES if s in kill_chain_hits]

        # ── Remediation plan ──────────────────────────────────────────────────
        remediation = build_remediation_plan(soc_alerts, vapt_vulns, web_data, combined_risk)

        # ── CVE aggregation ───────────────────────────────────────────────────
        top_cves = []
        seen_cve_ids = set()
        for v in vapt_vulns:
            for c in (v.get("cves") or []):
                cve_id = c.get("cve", "") if isinstance(c, dict) else str(c)
                if cve_id and cve_id not in seen_cve_ids:
                    top_cves.append(cve_id)
                    seen_cve_ids.add(cve_id)
        for c in (web_data.get("all_cves") or []):
            cid = c.get("cve", "")
            if cid and cid not in seen_cve_ids:
                top_cves.append(cid)
                seen_cve_ids.add(cid)
        top_cves = top_cves[:8]

        # ── MITRE aggregation ─────────────────────────────────────────────────
        mitre_techniques = list(dict.fromkeys(
            [v.get("mitre", "") for v in vapt_vulns if v.get("mitre")]
            + [(a.get("mitre") or {}).get("technique_id", "") for a in soc_alerts]
        ))
        mitre_techniques = [m for m in mitre_techniques if m][:6]

        results.append({
            "host":              host,
            "domain":            web_data.get("domain", ""),

            # Counts
            "soc_alerts":        len(soc_alerts),
            "vapt_findings":     len(vapt_vulns),
            "web_cve_count":     len(web_data.get("all_cves") or []),
            "subdomain_count":   web_data.get("subdomain_count", 0),
            "live_subdomains":   web_data.get("live_subdomains", 0),

            # Scores
            "soc_score":         soc_score,
            "vapt_score":        vapt_score,
            "web_cve_score":     web_cve_score,
            "header_penalty":    header_penalty,
            "correlation_boost": corr_boost,
            "combined_score":    combined,
            "combined_risk":     combined_risk,

            # Flags
            "has_active_soc":    has_soc,
            "has_vapt_vuln":     has_vapt,
            "has_web_issues":    has_web,
            "waf_detected":      web_data.get("waf_detected", False),
            "waf_name":          web_data.get("waf_name", ""),
            "technologies":      web_data.get("technologies", []),

            # Intelligence
            "top_cves":          top_cves,
            "mitre":             mitre_techniques,
            "ir_action":         ir_action,

            # Kill chain
            "kill_chain":        kill_chain_summary,
            "kill_chain_stages_hit": stages_hit,
            "kill_chain_depth":  len(stages_hit),  # 1-7, higher = more advanced threat

            # Remediation
            "remediation_plan":  remediation,
            "remediation_count": len(remediation),

            # Brief summaries for dashboard
            "soc_summary": [
                {
                    "indicator": a.get("indicator"),
                    "risk":      a.get("final_risk"),
                    "reason":    a.get("reason"),
                    "score":     a.get("final_score"),
                    "mitre":     (a.get("mitre") or {}).get("technique_id", ""),
                    "kill_chain_stage": map_kill_chain_stage(a, "soc"),
                }
                for a in soc_alerts[:4]
            ],
            "vapt_summary": [
                {
                    "name":     v.get("name", v.get("service", "?")),
                    "severity": v.get("severity"),
                    "source":   v.get("source"),
                    "port":     v.get("port", ""),
                    "kill_chain_stage": map_kill_chain_stage(v, v.get("source", "nmap")),
                }
                for v in vapt_vulns[:4]
            ],
            "web_summary": {
                "main_url":         web_data.get("target", ""),
                "technologies":     web_data.get("technologies", []),
                "missing_critical": [h["header"] for h in missing_headers if h.get("impact") == "High"],
                "leaky_headers":    [h["header"] for h in (web_data.get("leaky_headers") or [])],
                "top_cves":         [(c.get("cve"), c.get("severity")) for c in
                                     (web_data.get("all_cves") or [])[:3]],
                "subdomains_with_issues": [
                    s.get("subdomain") for s in web_data.get("subdomains", [])
                    if s.get("cves") or s.get("missing_headers")
                ][:5],
            } if has_web else {},
        })

    results.sort(key=lambda x: x["combined_score"], reverse=True)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    results = correlate()

    critical = [r for r in results if r["combined_risk"] == "Critical"]
    high     = [r for r in results if r["combined_risk"] == "High"]

    with open(OUTPUT_FILE, "w") as f:
        json.dump({
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "host_count":     len(results),
            "critical_hosts": len(critical),
            "high_hosts":     len(high),
            "correlations":   results
        }, f, indent=4)

    print(f"\n[+] Risk correlation complete — {len(results)} hosts assessed")
    print(f"    Kill chain coverage: up to {len(KILL_CHAIN_STAGES)} stages mapped per host")
    print(f"    Remediation items generated: {sum(r['remediation_count'] for r in results)}")

    if critical:
        print(f"\n[!!!] {len(critical)} CRITICAL host(s) — IMMEDIATE ACTION REQUIRED:")
        for h in critical:
            print(f"      {h['host']:20s}  score={h['combined_score']}  "
                  f"kill_chain_depth={h['kill_chain_depth']}/7")
            print(f"      → {h['ir_action']}")
            if h["remediation_plan"]:
                print(f"      Top fix: {h['remediation_plan'][0]['action'][:70]}")

    if high:
        print(f"\n[!] {len(high)} HIGH risk host(s):")
        for h in high:
            print(f"    {h['host']:20s}  score={h['combined_score']}  "
                  f"remediations={h['remediation_count']}")


if __name__ == "__main__":
    main()