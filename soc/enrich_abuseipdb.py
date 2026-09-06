# soc/enrich_abuseipdb.py
#
# ROUTING RULE: IPs only
# ─────────────────────────────────────────────────────────────────────────────
#  SKIP  if skip_enrichment = True  (local feed already matched)
#  SKIP  if indicator is not a public IPv4
#  QUERY AbuseIPDB for all other IPs (Medium/High severity or count >= 3)
#
#  If AbuseIPDB confirms (confidence >= 25%):
#    → sets ti_confirmed   = True       (tells VT to skip this alert)
#    → sets threat_verdict = "Malicious" (fixes UNKNOWN verdict on dashboard)
#    → sets threat_source  = "AbuseIPDB" (shows correct source badge)
# ─────────────────────────────────────────────────────────────────────────────

import os
import json
import time
import requests
import re
from dotenv import load_dotenv

_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_HERE)
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

INPUT_FILE  = os.path.join(PROJECT_ROOT, "alerts", "threat_enriched.json")
OUTPUT_FILE = INPUT_FILE
CACHE_FILE  = os.path.join(PROJECT_ROOT, "cache",  "abuseipdb_cache.json")

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
API_URL = "https://api.abuseipdb.com/api/v2/check"

abuse_cache = {}
if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, "r") as f:
        abuse_cache = json.load(f)


def is_ip(value):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(value)))


def is_private_ip(ip):
    return ip.startswith(("10.", "192.168.", "172.", "127."))


def should_enrich(alert):
    return (
        alert.get("severity_hint", "").lower() in ["medium", "high"]
        or alert.get("count", 1) >= 3
    )


def mark_confirmed(alert, confidence, reports):
    """
    Called when AbuseIPDB confidence >= 25%.
    Sets three fields so the dashboard shows the correct verdict and source,
    and so VirusTotal knows to skip this alert entirely.
    """
    alert["ti_confirmed"]   = True
    alert["threat_verdict"] = "Malicious"
    alert["threat_source"]  = f"AbuseIPDB ({confidence}% confidence, {reports} reports)"


def main():
    if not API_KEY:
        print("[!] ABUSEIPDB_API_KEY not set — skipping")
        return

    with open(INPUT_FILE, "r") as f:
        data = json.load(f)

    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)

    queried       = 0
    confirmed     = 0
    skipped_local = 0
    skipped_type  = 0
    skipped_low   = 0

    for alert in data["alerts"]:
        indicator = alert.get("indicator", "")

        # ── Gate 1: local feed already confirmed → skip ──────────────────────
        if alert.get("skip_enrichment", False):
            skipped_local += 1
            continue

        # ── Gate 2: only public IPv4 ─────────────────────────────────────────
        if not is_ip(indicator) or is_private_ip(indicator):
            skipped_type += 1
            continue

        # ── Gate 3: only medium/high severity or repeated ────────────────────
        if not should_enrich(alert):
            skipped_low += 1
            continue

        # ── Cache hit ────────────────────────────────────────────────────────
        if indicator in abuse_cache:
            cached = abuse_cache[indicator]
            alert["abuseipdb"] = cached
            if cached.get("confidence", 0) >= 25:
                mark_confirmed(alert, cached["confidence"], cached.get("total_reports", 0))
                confirmed += 1
            continue

        # ── Live API call ────────────────────────────────────────────────────
        try:
            r = requests.get(
                API_URL,
                headers={"Key": API_KEY, "Accept": "application/json"},
                params={"ipAddress": indicator, "maxAgeInDays": 90},
                timeout=10
            )
            result_data = r.json().get("data", {})
            result = {
                "confidence":    result_data.get("abuseConfidenceScore", 0),
                "total_reports": result_data.get("totalReports", 0),
            }
            alert["abuseipdb"]   = result
            abuse_cache[indicator] = result
            queried += 1

            if result["confidence"] >= 25:
                mark_confirmed(alert, result["confidence"], result["total_reports"])
                confirmed += 1

            time.sleep(1)

        except Exception:
            continue

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=4)

    with open(CACHE_FILE, "w") as f:
        json.dump(abuse_cache, f, indent=2)

    print(f"[+] AbuseIPDB enrichment complete (IPs only)")
    print(f"    Live queries : {queried}   Confirmed (>=25%) : {confirmed}")
    print(f"    Skipped      : {skipped_local} local-matched   {skipped_type} non-IP   {skipped_low} low-severity")


if __name__ == "__main__":
    main()