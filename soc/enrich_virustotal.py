# soc/enrich_virustotal.py
#
# ROUTING RULE: Fallback for everything not yet confirmed
# ─────────────────────────────────────────────────────────────────────────────
#  SKIP  if skip_enrichment = True  (local feed already matched)
#  SKIP  if ti_confirmed    = True  (AbuseIPDB or OTX already confirmed it)
#  SKIP  if virustotal data already present (cache from previous run)
#
#  Handles:  IPs not confirmed by AbuseIPDB
#            URLs  (AbuseIPDB/OTX don't handle URLs)
#            Hashes (MD5/SHA1/SHA256 — AbuseIPDB/OTX don't handle these)
#            Domains not confirmed by OTX
#
#  If VT confirms (malicious >= 1):
#    → sets ti_confirmed   = True
#    → sets threat_verdict = "Malicious"  (fixes UNKNOWN verdict on dashboard)
#    → sets threat_source  = "VirusTotal" (shows correct source badge)
#
#  VT is most expensive (2s sleep, 500 req/day free tier) so runs LAST
#  and only on indicators that neither local feeds nor primary APIs resolved.
# ─────────────────────────────────────────────────────────────────────────────

import os
import json
import time
import requests
import base64
from dotenv import load_dotenv

_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_HERE)
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

INPUT_FILE  = os.path.join(PROJECT_ROOT, "alerts", "threat_enriched.json")
OUTPUT_FILE = INPUT_FILE
CACHE_FILE  = os.path.join(PROJECT_ROOT, "cache",  "vt_cache.json")

VT_KEY  = os.getenv("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"

vt_cache = {}
if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, "r") as f:
        vt_cache = json.load(f)


def should_enrich(alert):
    if alert.get("skip_enrichment", False):
        return False
    if alert.get("ti_confirmed", False):
        return False
    if alert.get("virustotal"):
        return False
    return (
        alert.get("severity_hint", "").lower() in ["medium", "high"]
        or alert.get("count", 1) >= 3
    )


def mark_confirmed(alert, malicious, suspicious):
    """
    Called when VT malicious engines >= 1.
    Sets three fields so the dashboard shows the correct verdict and source,
    and prevents any future duplicate enrichment of this indicator.
    """
    alert["ti_confirmed"]   = True
    alert["threat_verdict"] = "Malicious"
    alert["threat_source"]  = f"VirusTotal ({malicious} malicious engine{'s' if malicious != 1 else ''})"


def main():
    if not VT_KEY:
        print("[!] VT_API_KEY not set — skipping")
        return

    with open(INPUT_FILE, "r") as f:
        data = json.load(f)

    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)

    queried           = 0
    confirmed         = 0
    skipped_local     = 0
    skipped_confirmed = 0
    skipped_cached    = 0
    skipped_low       = 0

    for alert in data["alerts"]:

        # ── Count skip reasons before the should_enrich gate ─────────────────
        if alert.get("skip_enrichment", False):
            skipped_local += 1
            continue
        if alert.get("ti_confirmed", False):
            skipped_confirmed += 1
            continue
        if alert.get("virustotal"):
            skipped_cached += 1
            continue
        if not should_enrich(alert):
            skipped_low += 1
            continue

        indicator = alert.get("indicator", "")

        # ── Cache hit ────────────────────────────────────────────────────────
        if indicator in vt_cache:
            cached = vt_cache[indicator]
            alert["virustotal"] = cached
            if cached.get("malicious", 0) >= 1:
                mark_confirmed(alert, cached["malicious"], cached.get("suspicious", 0))
                confirmed += 1
            continue

        # ── Live API call ────────────────────────────────────────────────────
        try:
            if indicator.startswith("http"):
                # URL
                encoded = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
                r = requests.get(
                    f"{VT_BASE}/urls/{encoded}",
                    headers={"x-apikey": VT_KEY},
                    timeout=10
                )
            elif len(indicator) in (32, 40, 64) and indicator.isalnum():
                # Hash (MD5=32, SHA1=40, SHA256=64)
                r = requests.get(
                    f"{VT_BASE}/files/{indicator}",
                    headers={"x-apikey": VT_KEY},
                    timeout=10
                )
            else:
                # Domain or IP fallback
                r = requests.get(
                    f"{VT_BASE}/domains/{indicator}",
                    headers={"x-apikey": VT_KEY},
                    timeout=10
                )

            stats  = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result = {
                "malicious":  stats.get("malicious",  0),
                "suspicious": stats.get("suspicious", 0),
            }
            alert["virustotal"]  = result
            vt_cache[indicator]  = result
            queried += 1

            if result["malicious"] >= 1:
                mark_confirmed(alert, result["malicious"], result["suspicious"])
                confirmed += 1

            time.sleep(2)   # VT free tier: 4 req/min

        except Exception:
            continue

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=4)

    with open(CACHE_FILE, "w") as f:
        json.dump(vt_cache, f, indent=2)

    print(f"[+] VirusTotal enrichment complete (fallback only)")
    print(f"    Live queries : {queried}   Confirmed (>=1 engine) : {confirmed}")
    print(f"    Skipped      : {skipped_local} local-matched   {skipped_confirmed} already-confirmed-by-AbuseIPDB/OTX   {skipped_low} low-severity")


if __name__ == "__main__":
    main()