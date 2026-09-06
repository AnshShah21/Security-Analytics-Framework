# soc/enrich_otx.py
#
# ROUTING RULE: Domains only
# ─────────────────────────────────────────────────────────────────────────────
#  SKIP  if skip_enrichment = True  (local feed already matched)
#  SKIP  if indicator is not a domain  (IPs → AbuseIPDB, hashes → VT)
#  QUERY OTX for all other domains (Medium/High severity or count >= 3)
#
#  If OTX confirms (pulse_count >= 1):
#    → sets ti_confirmed   = True       (tells VT to skip this alert)
#    → sets threat_verdict = "Malicious" (fixes UNKNOWN verdict on dashboard)
#    → sets threat_source  = "AlienVault OTX" (shows correct source badge)
# ─────────────────────────────────────────────────────────────────────────────

import os
import json
import time
import requests
from dotenv import load_dotenv

_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_HERE)
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

INPUT_FILE  = os.path.join(PROJECT_ROOT, "alerts", "threat_enriched.json")
OUTPUT_FILE = INPUT_FILE
CACHE_FILE  = os.path.join(PROJECT_ROOT, "cache",  "otx_cache.json")

OTX_KEY  = os.getenv("OTX_API_KEY")
OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"

otx_cache = {}
if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, "r") as f:
        otx_cache = json.load(f)


def is_domain(ind):
    """True only for plain domains — not IPs, not URLs, not hashes."""
    return (
        "." in ind
        and not ind.replace(".", "").isdigit()   # exclude IPs
        and not ind.startswith("http")            # exclude URLs (VT handles these)
        and len(ind) < 253                        # valid domain max length
        and " " not in ind                        # exclude JA3 hashes / garbage
    )


def should_enrich(alert):
    return (
        alert.get("severity_hint", "").lower() in ["medium", "high"]
        or alert.get("count", 1) >= 3
    )


def mark_confirmed(alert, pulse_count):
    """
    Called when OTX pulse_count >= 1.
    Sets three fields so the dashboard shows the correct verdict and source,
    and so VirusTotal knows to skip this alert entirely.
    """
    alert["ti_confirmed"]   = True
    alert["threat_verdict"] = "Malicious"
    alert["threat_source"]  = f"AlienVault OTX ({pulse_count} pulse{'s' if pulse_count != 1 else ''})"


def main():
    if not OTX_KEY:
        print("[!] OTX_API_KEY not set — skipping")
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

        # ── Gate 2: only domains ─────────────────────────────────────────────
        if not is_domain(indicator):
            skipped_type += 1
            continue

        # ── Gate 3: only medium/high severity or repeated ────────────────────
        if not should_enrich(alert):
            skipped_low += 1
            continue

        # ── Cache hit ────────────────────────────────────────────────────────
        if indicator in otx_cache:
            cached = otx_cache[indicator]
            alert["otx"] = cached
            if cached.get("pulse_count", 0) >= 1:
                mark_confirmed(alert, cached["pulse_count"])
                confirmed += 1
            continue

        # ── Live API call ────────────────────────────────────────────────────
        try:
            r = requests.get(
                f"{OTX_BASE}/domain/{indicator}/general",
                headers={"X-OTX-API-KEY": OTX_KEY},
                timeout=10
            )
            pulses = r.json().get("pulse_info", {}).get("pulses", [])
            result = {"pulse_count": len(pulses)}

            alert["otx"]          = result
            otx_cache[indicator]  = result
            queried += 1

            if result["pulse_count"] >= 1:
                mark_confirmed(alert, result["pulse_count"])
                confirmed += 1

            time.sleep(1)

        except Exception:
            continue

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=4)

    with open(CACHE_FILE, "w") as f:
        json.dump(otx_cache, f, indent=2)

    print(f"[+] OTX enrichment complete (domains only)")
    print(f"    Live queries : {queried}   Confirmed (>=1 pulse) : {confirmed}")
    print(f"    Skipped      : {skipped_local} local-matched   {skipped_type} non-domain   {skipped_low} low-severity")


if __name__ == "__main__":
    main()