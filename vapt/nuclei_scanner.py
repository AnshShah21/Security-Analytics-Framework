"""
nuclei_scanner.py — Windows-native Nuclei (no WSL)
====================================================
Scans all web targets found by Nmap in ONE parallel nuclei call.
Uses -list flag so all targets run simultaneously — not sequentially.

Key changes:
  1. -list flag: scans all targets in one call (parallel) instead of looping
  2. -bulk-size 25: 25 templates per host at once
  3. 300s total timeout for all targets combined
  4. -jsonl -o file: correct output method for nuclei 3.x
  5. Fallback to -tags when NUCLEI_TEMPLATES not set
"""

import os
import subprocess
import json
import re
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

HERE         = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
ALERTS_DIR   = os.path.join(PROJECT_ROOT, "alerts")

NUCLEI_BIN   = os.getenv("NUCLEI_BINARY", r"C:\Program Files\nuclei\nuclei.exe")
TEMPLATES    = os.getenv("NUCLEI_TEMPLATES", "")

SEV_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

MITRE_MAP = {
    "cve": "T1190", "rce": "T1190", "sqli": "T1190", "xss": "T1190",
    "lfi": "T1083", "ssrf": "T1190", "default-login": "T1078.001",
    "exposed-panel": "T1083", "misconfig": "T1595", "ssl": "T1600",
    "tls": "T1600", "network": "T1046", "dns": "T1071.004",
    "http": "T1071.001", "file": "T1105", "backdoor": "T1543",
    "info-disclosure": "T1592", "tech": "T1592",
}

KILL_CHAIN_MAP = {
    "cve": "Exploitation", "rce": "Exploitation", "sqli": "Exploitation",
    "xss": "Exploitation", "lfi": "Exploitation", "ssrf": "Exploitation",
    "default-login": "Exploitation", "exposed-panel": "Reconnaissance",
    "misconfig": "Reconnaissance", "exposures": "Reconnaissance",
    "technologies": "Reconnaissance", "ssl": "Reconnaissance",
    "network": "Reconnaissance", "takeovers": "Actions on Objectives",
    "backdoor": "Installation", "dns": "Reconnaissance",
}


def get_web_targets_from_nmap() -> list:
    path = os.path.join(ALERTS_DIR, "nmap_findings.json")
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        data = json.load(f)
    targets = set()
    for finding in data.get("findings", []):
        host    = finding.get("host", "")
        port    = int(finding.get("port", 0))
        service = finding.get("service", "").lower()
        is_web  = "http" in service or port in {80, 443, 8080, 8000, 8443, 5000, 3000, 8888, 9090, 9443}
        if is_web and host:
            proto = "https" if port in {443, 8443} else "http"
            targets.add(f"{proto}://{host}:{port}")
    return list(targets)


def resolve_mitre(tags: list, template_id: str) -> str:
    combined = " ".join(tags + [template_id]).lower()
    for kw, tech in MITRE_MAP.items():
        if kw in combined:
            return tech
    return "T1190"


def resolve_kill_chain(tags: list, template_id: str) -> str:
    for tag in [t.lower() for t in tags]:
        if tag in KILL_CHAIN_MAP:
            return KILL_CHAIN_MAP[tag]
    for kw, stage in KILL_CHAIN_MAP.items():
        if kw in template_id.lower():
            return stage
    return "Exploitation"


def build_remediation(tags: list, template_id: str, severity: str, name: str) -> list:
    hints = []
    tags_l = [t.lower() for t in tags]
    tid = template_id.lower()
    if "cve" in tags_l or re.search(r"cve-\d{4}-\d+", tid):
        hints.append({"priority": severity, "action": f"Apply vendor patch for {template_id.upper()}", "effort": "Medium"})
    if "default-login" in tags_l:
        hints.append({"priority": "Critical", "action": "Change default credentials immediately", "effort": "Low"})
    if "exposed-panel" in tags_l:
        hints.append({"priority": "High", "action": "Restrict admin panel to trusted IPs via firewall", "effort": "Low"})
    if "misconfig" in tags_l:
        hints.append({"priority": "High", "action": f"Fix misconfiguration: {name}", "effort": "Medium"})
    if "ssl" in tags_l or "tls" in tags_l:
        hints.append({"priority": "High", "action": "Disable TLS 1.0/1.1, enable TLS 1.2+ only", "effort": "Medium"})
    if "xss" in tags_l:
        hints.append({"priority": "High", "action": "Add CSP header, sanitize all user input", "effort": "High"})
    if "sqli" in tags_l:
        hints.append({"priority": "Critical", "action": "Use parameterized queries — eliminate SQL injection", "effort": "High"})
    if any(t in tags_l for t in ["exposures", "exposure"]):
        hints.append({"priority": "Medium", "action": f"Remove or restrict: {name}", "effort": "Low"})
    if "technologies" in tags_l:
        hints.append({"priority": "Info", "action": "Update software, remove version disclosure headers", "effort": "Low"})
    if not hints:
        hints.append({"priority": severity, "action": f"Review and remediate: {name}", "effort": "Medium"})
    return hints


def parse_jsonl(jsonl_path: str) -> list:
    findings = []
    if not os.path.exists(jsonl_path):
        return findings
    size = os.path.getsize(jsonl_path)
    print(f"[NUCLEI] JSONL size: {size} bytes")
    if size == 0:
        return findings
    with open(jsonl_path, "r", encoding="utf-8", errors="replace") as fh:
        for line_num, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, list):
                    item = item[0] if item else {}
                if not isinstance(item, dict):
                    continue

                info     = item.get("info", {}) or {}
                template = item.get("template-id") or item.get("templateID") or "unknown"
                name     = info.get("name") or template
                severity = str(info.get("severity", "info")).lower()

                raw_tags = info.get("tags", [])
                if isinstance(raw_tags, str):
                    tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
                elif isinstance(raw_tags, list):
                    tags = [str(x).strip() for x in raw_tags if x]
                else:
                    tags = []

                host      = str(item.get("host", "") or "")
                matched   = str(item.get("matched-at", "") or item.get("matched", "") or "")
                extracted = item.get("extracted-results", []) or []
                desc      = info.get("description", "") or ""
                ref       = info.get("reference", [])
                if isinstance(ref, str):
                    ref = [ref]

                cve_list = [tg.upper() for tg in tags if re.match(r"cve-\d{4}-\d+", tg.lower())]

                findings.append({
                    "template_id":       template,
                    "name":              name,
                    "severity":          severity.capitalize(),
                    "host":              host,
                    "matched_at":        matched,
                    "tags":              tags,
                    "cves":              cve_list,
                    "extracted":         extracted,
                    "mitre":             resolve_mitre(tags, template),
                    "kill_chain_stage":  resolve_kill_chain(tags, template),
                    "description":       desc,
                    "reference":         ref,
                    "remediation_hints": build_remediation(tags, template, severity.capitalize(), name),
                })
            except Exception as e:
                print(f"[NUCLEI] Line {line_num} parse error: {e}")
    return findings


def run_nuclei(target: str = None, template_tags: list = None, severity_filter: list = None) -> dict:
    os.makedirs(ALERTS_DIR, exist_ok=True)
    output_json   = os.path.join(ALERTS_DIR, "nuclei_findings.json")
    jsonl_out     = os.path.join(ALERTS_DIR, "nuclei_raw.jsonl")
    targets_file  = os.path.join(ALERTS_DIR, "nuclei_targets.txt")

    # Clear old output
    for p in [jsonl_out]:
        if os.path.exists(p):
            os.remove(p)

    # Determine targets
    web_targets = get_web_targets_from_nmap()
    if web_targets:
        targets = web_targets
        print(f"[NUCLEI] Auto-targets from Nmap ({len(targets)}): {targets}")
    elif target:
        targets = [target]
        print(f"[NUCLEI] Manual target: {targets}")
    else:
        print("[NUCLEI] No targets — skipping")
        return {"status": "success", "count": 0, "findings": []}

    # Write targets list file
    with open(targets_file, "w") as fh:
        fh.write("\n".join(targets))

    # Template argument
    template_arg = []
    if TEMPLATES and os.path.isdir(TEMPLATES):
        subdirs = [
            "http/misconfiguration", "http/exposed-panels",
            "http/technologies",    "http/exposures",
            "http/default-logins",  "ssl", "network",
        ]
        for sd in subdirs:
            full = os.path.join(TEMPLATES, sd)
            if os.path.isdir(full):
                template_arg += ["-t", full]
        if not template_arg:
            template_arg = ["-t", TEMPLATES]
    else:
        print("[NUCLEI] NUCLEI_TEMPLATES not set — using built-in tags")
        template_arg = ["-tags", "misconfig,exposed-panel,technologies,ssl,network,default-login,exposures"]

    if severity_filter is None:
        severity_filter = ["critical", "high", "medium", "low", "info"]

    # ── Single parallel scan with -list ──────────────────────────────────────
    cmd = [
        NUCLEI_BIN,
        "-list", targets_file,      # all targets scanned in parallel
    ] + template_arg + [
        "-severity",    ",".join(severity_filter),
        "-jsonl",                   # JSONL line-delimited output
        "-o",           jsonl_out,  # write results to file
        "-silent",
        "-timeout",     "10",       # per-request HTTP timeout (seconds)
        "-retries",     "0",        # no retries
        "-rate-limit",  "100",      # global requests/sec
        "-concurrency", "25",       # parallel template runs
        "-bulk-size",   "25",       # templates per host in parallel
        "-no-color",
    ]

    print(f"\n[NUCLEI] Running parallel scan — {len(targets)} target(s)")
    print(f"[NUCLEI] Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        print(f"[NUCLEI] Return code: {result.returncode}")
        if result.stdout.strip():
            print(f"[NUCLEI] stdout: {result.stdout.strip()[:300]}")
        if result.stderr.strip():
            print(f"[NUCLEI] stderr: {result.stderr.strip()[:300]}")
        if result.returncode not in (0, 1):
            print(f"[NUCLEI] Unexpected exit code: {result.returncode}")

    except subprocess.TimeoutExpired:
        print("[NUCLEI] 300s timeout reached — parsing partial results from JSONL")
    except FileNotFoundError:
        return {"status": "error", "message": f"Nuclei binary not found: {NUCLEI_BIN}. Check NUCLEI_BINARY in .env"}
    except Exception as e:
        return {"status": "error", "message": f"Nuclei error: {str(e)}"}

    findings = parse_jsonl(jsonl_out)
    findings.sort(key=lambda x: SEV_ORDER.get(x["severity"].lower(), 0), reverse=True)

    with open(output_json, "w") as fh:
        json.dump({
            "generated_at":  datetime.utcnow().isoformat(),
            "finding_count": len(findings),
            "findings":      findings,
        }, fh, indent=2)

    print(f"[+] Nuclei completed → {len(findings)} findings → {output_json}")
    return {"status": "success", "count": len(findings), "findings": findings}