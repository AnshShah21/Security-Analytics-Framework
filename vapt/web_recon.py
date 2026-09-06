# vapt/web_recon.py
"""
Web Reconnaissance Module
==========================
Triggered automatically when a URL/domain is passed as the VAPT target.

Capabilities
------------
1. Subdomain enumeration     — subfinder (fast, passive) via WSL
2. DNS resolution            — resolves each subdomain to IPs
3. HTTP probing              — checks which subdomains are alive (httpx via WSL)
4. Tech fingerprinting       — reads HTTP headers to detect CMS, framework, server, WAF
5. Security headers audit    — checks for missing security headers
6. Web-specific CVE hints    — maps detected tech to known CVEs

Output → alerts/web_recon.json
"""

import os
import re
import json
import socket
import subprocess
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
from dotenv import load_dotenv

# ── Setup ─────────────────────────────────────────────────────────────────────
_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_HERE)
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

OUTPUT_DIR  = os.path.join(PROJECT_ROOT, "alerts")
WSL_DISTRO  = os.getenv("WSL_DISTRO", "Ubuntu-22.04")
WSL_USER    = os.getenv("WSL_USER",   "mahi")

# Tools inside WSL (install via: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)
SUBFINDER_BIN = f"/home/{WSL_USER}/go/bin/subfinder"
HTTPX_BIN     = f"/home/{WSL_USER}/go/bin/httpx"


# ─────────────────────────────────────────────────────────────────────────────
# Tech → CVE hint table
# ─────────────────────────────────────────────────────────────────────────────
TECH_CVE_HINTS = {
    "wordpress": [
        {"cve": "CVE-2022-21661", "severity": "High",     "desc": "WordPress SQL injection via WP_Query"},
        {"cve": "CVE-2019-8943",  "severity": "Medium",   "desc": "WordPress path traversal in media upload"},
    ],
    "drupal": [
        {"cve": "CVE-2018-7600",  "severity": "Critical", "desc": "Drupalgeddon2 — unauthenticated RCE"},
        {"cve": "CVE-2019-6340",  "severity": "Critical", "desc": "Drupal REST API RCE"},
    ],
    "joomla": [
        {"cve": "CVE-2023-23752", "severity": "High",     "desc": "Joomla unauthenticated info disclosure"},
    ],
    "laravel": [
        {"cve": "CVE-2021-3129",  "severity": "Critical", "desc": "Laravel ignition RCE via log poisoning"},
    ],
    "django": [
        {"cve": "CVE-2021-35042", "severity": "Critical", "desc": "Django SQL injection via QuerySet.order_by"},
    ],
    "apache":  [
        {"cve": "CVE-2021-41773", "severity": "Critical", "desc": "Apache path traversal & RCE"},
        {"cve": "CVE-2021-42013", "severity": "Critical", "desc": "Apache mod_cgi RCE"},
    ],
    "nginx": [
        {"cve": "CVE-2019-9511",  "severity": "High",     "desc": "HTTP/2 DoS — Data Dribble"},
    ],
    "iis": [
        {"cve": "CVE-2017-7269",  "severity": "Critical", "desc": "IIS WebDAV buffer overflow"},
    ],
    "tomcat": [
        {"cve": "CVE-2020-1938",  "severity": "Critical", "desc": "Ghostcat — Tomcat AJP file read/RCE"},
        {"cve": "CVE-2017-12617", "severity": "Critical", "desc": "Tomcat PUT method JSP upload"},
    ],
    "spring": [
        {"cve": "CVE-2022-22965", "severity": "Critical", "desc": "Spring4Shell — RCE via data binding"},
        {"cve": "CVE-2022-22963", "severity": "Critical", "desc": "Spring Cloud Function SpEL injection"},
    ],
    "struts": [
        {"cve": "CVE-2017-5638",  "severity": "Critical", "desc": "Apache Struts RCE — Equifax breach vector"},
    ],
    "jenkins": [
        {"cve": "CVE-2024-23897", "severity": "Critical", "desc": "Jenkins arbitrary file read via CLI"},
        {"cve": "CVE-2019-1003000","severity":"Critical", "desc": "Jenkins sandbox bypass Script Security"},
    ],
    "gitlab": [
        {"cve": "CVE-2021-22205", "severity": "Critical", "desc": "GitLab ExifTool RCE — unauthenticated"},
    ],
    "grafana": [
        {"cve": "CVE-2021-43798", "severity": "High",     "desc": "Grafana path traversal plugin files"},
    ],
    "elasticsearch": [
        {"cve": "CVE-2021-22145", "severity": "Medium",   "desc": "Elasticsearch unauthenticated exposure"},
    ],
    "phpmyadmin": [
        {"cve": "CVE-2020-26935", "severity": "Critical", "desc": "phpMyAdmin SQL injection"},
    ],
    "openssl": [
        {"cve": "CVE-2014-0160",  "severity": "Critical", "desc": "Heartbleed memory disclosure"},
        {"cve": "CVE-2022-0778",  "severity": "High",     "desc": "OpenSSL infinite loop DoS"},
    ],
}

# Security headers that MUST be present on every web app
REQUIRED_HEADERS = {
    "strict-transport-security": {
        "desc":   "HSTS — forces HTTPS, prevents downgrade attacks",
        "impact": "High",
        "fix":    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "content-security-policy": {
        "desc":   "CSP — mitigates XSS and data injection attacks",
        "impact": "High",
        "fix":    "Define a strict CSP policy. Start with: Content-Security-Policy: default-src 'self'"
    },
    "x-content-type-options": {
        "desc":   "Prevents MIME-type sniffing",
        "impact": "Medium",
        "fix":    "Add: X-Content-Type-Options: nosniff"
    },
    "x-frame-options": {
        "desc":   "Prevents clickjacking via iframes",
        "impact": "Medium",
        "fix":    "Add: X-Frame-Options: DENY  (or SAMEORIGIN)"
    },
    "referrer-policy": {
        "desc":   "Controls referrer information leakage",
        "impact": "Low",
        "fix":    "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "permissions-policy": {
        "desc":   "Restricts browser features (camera, mic, geolocation)",
        "impact": "Low",
        "fix":    "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
    },
    "x-xss-protection": {
        "desc":   "Legacy XSS filter (older browsers)",
        "impact": "Low",
        "fix":    "Add: X-XSS-Protection: 1; mode=block"
    },
}

# Headers that reveal too much server info
LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                 "x-generator", "x-drupal-cache", "x-wordpress-cache"]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def windows_to_wsl_path(win_path: str) -> str:
    if win_path.startswith("/"):
        return win_path
    drive, rest = win_path.split(":", 1)
    return f"/mnt/{drive.lower()}{rest.replace(chr(92), '/')}"


def extract_domain(target: str) -> str:
    """Extract bare domain from URL or raw domain string."""
    if target.startswith("http"):
        return urlparse(target).netloc.split(":")[0]
    return target.split("/")[0].split(":")[0]


def resolve_ip(domain: str) -> str:
    """DNS A record lookup. Returns IP or empty string."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return ""


def is_web_target(target: str) -> bool:
    """Return True if the target looks like a URL or domain (not a raw IP)."""
    if target.startswith("http"):
        return True
    # bare domain has at least one dot and isn't all digits
    parts = target.split(".")
    return len(parts) >= 2 and not target.replace(".", "").isdigit()


# ─────────────────────────────────────────────────────────────────────────────
# Subdomain Enumeration (subfinder via WSL)
# ─────────────────────────────────────────────────────────────────────────────

def enumerate_subdomains(domain: str) -> list:
    """
    Run subfinder inside WSL to passively enumerate subdomains.
    Falls back to a small manual wordlist probe if subfinder is not installed.
    Returns list of subdomain strings.
    """
    subdomains = set()

    # ── Try subfinder ────────────────────────────────────────────────────────
    try:
        cmd = [
            "wsl", "-d", WSL_DISTRO,
            SUBFINDER_BIN,
            "-d", domain,
            "-silent",
            "-timeout", "30"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                sub = line.strip().lower()
                if sub and domain in sub:
                    subdomains.add(sub)
            print(f"[+] subfinder found {len(subdomains)} subdomains for {domain}")
        else:
            print(f"[!] subfinder not available or no results — using wordlist fallback")
            subdomains.update(_wordlist_probe(domain))
    except Exception as e:
        print(f"[!] subfinder error: {e} — using wordlist fallback")
        subdomains.update(_wordlist_probe(domain))

    return sorted(subdomains)


def _wordlist_probe(domain: str) -> set:
    """
    Lightweight fallback: probe common subdomain prefixes via DNS.
    No external tool required.
    """
    COMMON = [
        "www", "mail", "smtp", "pop", "imap", "ftp", "sftp",
        "admin", "portal", "api", "dev", "staging", "test", "uat",
        "vpn", "remote", "citrix", "webmail", "autodiscover",
        "cpanel", "whm", "plesk", "phpmyadmin", "mysql", "db",
        "blog", "shop", "store", "cdn", "static", "assets",
        "beta", "demo", "old", "backup", "git", "gitlab", "jenkins",
        "jira", "confluence", "grafana", "kibana", "elastic",
        "ns1", "ns2", "mx", "mx1", "mx2",
    ]
    found = set()
    for prefix in COMMON:
        fqdn = f"{prefix}.{domain}"
        if resolve_ip(fqdn):
            found.add(fqdn)
    print(f"[+] Wordlist probe found {len(found)} live subdomains for {domain}")
    return found


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Probing + Header Fingerprinting
# ─────────────────────────────────────────────────────────────────────────────

def probe_host(url: str, timeout: int = 8) -> dict:
    """
    Fetch HTTP headers from a URL and extract:
    - Status code
    - Server / tech stack
    - Security header audit
    - Detected technologies
    - Potential CVEs based on detected tech
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    result = {
        "url":              url,
        "status_code":      None,
        "server":           "",
        "technologies":     [],
        "missing_headers":  [],
        "leaky_headers":    [],
        "cves":             [],
        "waf_detected":     False,
        "waf_name":         "",
        "redirect_to":      "",
        "error":            "",
    }

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        result["status_code"] = resp.status

        # ── Server + powered-by ───────────────────────────────────────────────
        server = headers.get("server", "")
        result["server"] = server

        # ── Tech fingerprinting from headers ──────────────────────────────────
        techs = _fingerprint_tech(headers, server)
        result["technologies"] = techs

        # ── CVE hints from detected technologies ──────────────────────────────
        cves = []
        for tech in techs:
            for keyword, hits in TECH_CVE_HINTS.items():
                if keyword in tech.lower():
                    for h in hits:
                        if h not in cves:
                            cves.append(h)
        result["cves"] = cves

        # ── Missing security headers ──────────────────────────────────────────
        missing = []
        for header, meta in REQUIRED_HEADERS.items():
            if header not in headers:
                missing.append({
                    "header":  header,
                    "desc":    meta["desc"],
                    "impact":  meta["impact"],
                    "fix":     meta["fix"],
                })
        result["missing_headers"] = missing

        # ── Leaky headers ─────────────────────────────────────────────────────
        leaky = []
        for h in LEAKY_HEADERS:
            if h in headers:
                leaky.append({"header": h, "value": headers[h]})
        result["leaky_headers"] = leaky

        # ── WAF detection ─────────────────────────────────────────────────────
        waf, waf_name = _detect_waf(headers)
        result["waf_detected"] = waf
        result["waf_name"]     = waf_name

    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["error"]       = str(e)
    except urllib.error.URLError as e:
        result["error"] = str(e.reason)
    except Exception as e:
        result["error"] = str(e)

    return result


def _fingerprint_tech(headers: dict, server: str) -> list:
    """Extract technology names from HTTP response headers."""
    techs = set()

    combined = " ".join([
        server,
        headers.get("x-powered-by", ""),
        headers.get("x-generator", ""),
        headers.get("x-drupal-cache", ""),
        headers.get("x-wordpress-cache", ""),
        headers.get("x-aspnet-version", ""),
        headers.get("via", ""),
        headers.get("x-varnish", ""),
        headers.get("x-cache", ""),
    ]).lower()

    TECH_SIGNATURES = {
        "WordPress":     ["wordpress", "wp-content", "wp-json"],
        "Drupal":        ["drupal", "x-drupal"],
        "Joomla":        ["joomla"],
        "Laravel":       ["laravel", "x-laravel"],
        "Django":        ["django", "csrftoken"],
        "Ruby on Rails": ["x-runtime", "x-request-id"],
        "ASP.NET":       ["asp.net", "x-aspnet", "aspxerrorpath"],
        "PHP":           ["php", "x-powered-by: php"],
        "Apache":        ["apache"],
        "Nginx":         ["nginx"],
        "IIS":           ["iis", "microsoft-iis"],
        "Tomcat":        ["tomcat", "coyote"],
        "Cloudflare":    ["cloudflare", "cf-ray"],
        "Varnish":       ["varnish", "x-varnish"],
        "Squid":         ["squid"],
        "Fastly":        ["fastly"],
        "Spring":        ["spring"],
        "Express.js":    ["express"],
        "Node.js":       ["node"],
        "Jenkins":       ["jenkins", "x-jenkins"],
        "Grafana":       ["grafana"],
        "GitLab":        ["gitlab"],
        "Elasticsearch": ["elasticsearch", "x-elastic"],
    }

    for tech, sigs in TECH_SIGNATURES.items():
        for sig in sigs:
            if sig in combined:
                techs.add(tech)
                break

    return sorted(techs)


def _detect_waf(headers: dict) -> tuple:
    """Returns (bool, waf_name) based on response headers."""
    WAF_SIGNATURES = {
        "Cloudflare":        ["cf-ray", "cf-cache-status"],
        "AWS WAF":           ["x-amzn-requestid", "x-amz-cf-id"],
        "Akamai":            ["x-akamai-transformed", "akamai-grn"],
        "Imperva/Incapsula": ["x-iinfo", "x-cdn"],
        "Sucuri":            ["x-sucuri-id", "x-sucuri-cache"],
        "F5 BIG-IP":         ["x-wa-info", "bigipserver"],
        "Barracuda":         ["barra_counter_session"],
        "ModSecurity":       ["mod_security", "modsecurity"],
    }
    h_lower = {k.lower(): v.lower() for k, v in headers.items()}
    for waf, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig in h_lower:
                return True, waf
    return False, ""


# ─────────────────────────────────────────────────────────────────────────────
# Main recon runner
# ─────────────────────────────────────────────────────────────────────────────

def run_web_recon(target: str) -> dict:
    """
    Full web recon pipeline for a given URL or domain.

    Steps:
      1. Extract domain from URL
      2. Probe main domain (headers, tech, CVEs, security headers)
      3. Enumerate subdomains (subfinder → wordlist fallback)
      4. Resolve each subdomain to IP
      5. Probe each live subdomain (HTTPS first, then HTTP)
      6. Save consolidated results to alerts/web_recon.json

    Returns structured dict with all findings.
    """
    if not is_web_target(target):
        return {"status": "skipped", "message": "Target is a raw IP — web recon not applicable"}

    domain = extract_domain(target)
    main_url = target if target.startswith("http") else f"https://{domain}"

    print(f"\n[+] Starting web recon for: {domain}")
    print(f"    Main URL: {main_url}")

    # ── Step 1: Probe main domain ─────────────────────────────────────────────
    print(f"[+] Probing main domain…")
    main_probe = probe_host(main_url)
    main_ip    = resolve_ip(domain)

    # ── Step 2: Subdomain enumeration ─────────────────────────────────────────
    print(f"[+] Enumerating subdomains for {domain}…")
    subdomains = enumerate_subdomains(domain)
    print(f"[+] Found {len(subdomains)} subdomains")

    # ── Step 3: Probe each subdomain ──────────────────────────────────────────
    subdomain_results = []
    for sub in subdomains:
        ip = resolve_ip(sub)
        if not ip:
            continue  # skip dead subdomains

        # Try HTTPS first, fallback to HTTP
        for scheme in ("https", "http"):
            probe = probe_host(f"{scheme}://{sub}", timeout=6)
            if probe["status_code"] and not probe["error"]:
                probe["resolved_ip"] = ip
                probe["subdomain"]   = sub
                subdomain_results.append(probe)
                break

    print(f"[+] {len(subdomain_results)} live subdomains probed")

    # ── Step 4: Aggregate all CVEs found across subdomains ────────────────────
    all_cves = []
    seen_cves = set()
    for r in [main_probe] + subdomain_results:
        for c in r.get("cves", []):
            cve_id = c.get("cve", "")
            if cve_id and cve_id not in seen_cves:
                all_cves.append({**c, "found_on": r.get("url", "")})
                seen_cves.add(cve_id)

    # ── Step 5: Summary severity ──────────────────────────────────────────────
    SEV_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    max_sev = "Info"
    for c in all_cves:
        s = c.get("severity", "Info")
        if SEV_ORDER.get(s, 0) > SEV_ORDER.get(max_sev, 0):
            max_sev = s

    # missing header impact
    critical_missing = [
        h for h in main_probe.get("missing_headers", [])
        if h["impact"] == "High"
    ]

    result = {
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "target":            target,
        "domain":            domain,
        "main_ip":           main_ip,
        "main_probe":        main_probe,
        "subdomain_count":   len(subdomains),
        "live_subdomains":   len(subdomain_results),
        "subdomains":        subdomain_results,
        "all_cves":          all_cves,
        "cve_count":         len(all_cves),
        "overall_severity":  max_sev,
        "waf_detected":      main_probe.get("waf_detected", False),
        "waf_name":          main_probe.get("waf_name", ""),
        "technologies":      main_probe.get("technologies", []),
        "missing_critical_headers": critical_missing,
        "leaky_headers":     main_probe.get("leaky_headers", []),
    }

    # ── Save ──────────────────────────────────────────────────────────────────
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "web_recon.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[+] Web recon complete → {out_path}")
    print(f"    CVEs found: {len(all_cves)} | Severity: {max_sev} | Subdomains: {len(subdomains)}")

    return {"status": "success", **result}


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = run_web_recon(target)
    print(json.dumps({
        "domain":           result.get("domain"),
        "subdomain_count":  result.get("subdomain_count"),
        "live_subdomains":  result.get("live_subdomains"),
        "cve_count":        result.get("cve_count"),
        "overall_severity": result.get("overall_severity"),
        "technologies":     result.get("technologies"),
        "waf":              result.get("waf_name") or "None detected",
    }, indent=2))