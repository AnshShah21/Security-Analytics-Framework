# soc/match_threats.py

import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_HERE)

INPUT_FILE  = os.path.join(PROJECT_ROOT, "alerts", "correlated_alerts.json")
OUTPUT_FILE = os.path.join(PROJECT_ROOT, "alerts", "threat_enriched.json")
FEED_DIR    = os.path.join(PROJECT_ROOT, "threat_feeds")


def load_feed(filename):
    path = os.path.join(FEED_DIR, filename)
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return set(
            line.strip().lower()
            for line in f
            if line.strip() and not line.startswith("#")
        )


def load_all_feeds():
    print("[*] Loading local threat feeds...")

    ip_feed      = load_feed("malicious_ips.csv")
    domain_feed  = load_feed("malicious_domains.csv")
    hash_feed    = load_feed("malicious_hashes.csv")
    ja3_feed     = load_feed("malicious_tls_fingerprints.csv")

    # URL feeds — merge malicious_urls + urlhaus_clean (skip urlhaus_urls, duplicate)
    url_feed     = load_feed("malicious_urls.csv")
    url_feed    |= load_feed("urlhaus_clean.csv")
    url_feed    |= load_feed("openphish_urls.txt")

    print(f"    IPs      : {len(ip_feed):,}")
    print(f"    Domains  : {len(domain_feed):,}")
    print(f"    URLs     : {len(url_feed):,}  (malicious_urls + urlhaus_clean + openphish)")
    print(f"    Hashes   : {len(hash_feed):,}")
    print(f"    JA3/TLS  : {len(ja3_feed):,}")

    return {
        "ip":     ip_feed,
        "domain": domain_feed,
        "url":    url_feed,
        "hash":   hash_feed,
        "ja3":    ja3_feed,
    }


def normalize_indicator(ind):
    ind = ind.lower().strip()
    if ind.startswith("http"):
        parsed = urlparse(ind)
        return ind, parsed.netloc   # (full_url, domain)
    return ind, ind


def classify_indicator(indicator, feeds):
    raw, domain = normalize_indicator(indicator)

    # ── IP ───────────────────────────────────────────────────────────────────
    if raw in feeds["ip"]:
        return "Malicious", "Local IP feed match"

    # ── Domain ───────────────────────────────────────────────────────────────
    if domain in feeds["domain"]:
        return "Malicious", "Local domain feed match"

    # ── URL (full match first, then domain extracted from URL) ────────────────
    if raw in feeds["url"]:
        return "Malicious", "Local URL feed match"
    if domain and domain in feeds["domain"]:
        return "Malicious", "Local domain feed match (from URL)"

    # ── Hash ─────────────────────────────────────────────────────────────────
    if raw in feeds["hash"]:
        return "Malicious", "Local hash feed match"

    # ── JA3 / TLS fingerprint ─────────────────────────────────────────────────
    if raw in feeds["ja3"]:
        return "Malicious", "Local JA3 fingerprint match"

    return "Unknown", "No local feed match"


def main():
    if not os.path.exists(INPUT_FILE):
        print("[-] correlated_alerts.json not found")
        return

    feeds = load_all_feeds()

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    matched = 0
    total   = len(data.get("alerts", []))

    # Track match breakdown
    match_types = {"IP": 0, "Domain": 0, "URL": 0, "Hash": 0, "JA3": 0}

    for alert in data.get("alerts", []):
        verdict, reason = classify_indicator(alert.get("indicator", ""), feeds)

        alert["threat_verdict"] = verdict
        alert["threat_reason"]  = reason
        alert["threat_source"]  = "Local Feed"

        if verdict == "Malicious":
            alert["skip_enrichment"] = True
            matched += 1
            # Track type
            if "IP"   in reason: match_types["IP"]     += 1
            elif "JA3" in reason: match_types["JA3"]   += 1
            elif "URL" in reason: match_types["URL"]    += 1
            elif "hash" in reason.lower(): match_types["Hash"] += 1
            else:                 match_types["Domain"] += 1
        else:
            alert["skip_enrichment"] = False

    with open(OUTPUT_FILE, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "alerts":       data["alerts"]
        }, f, indent=4)

    print(f"\n[+] Local threat matching completed")
    print(f"    Total alerts  : {total}")
    print(f"    Malicious     : {matched}  →  skip_enrichment = True")
    print(f"    Unknown       : {total - matched}  →  APIs will check these")
    print(f"    Breakdown     : IP={match_types['IP']}  Domain={match_types['Domain']}  URL={match_types['URL']}  Hash={match_types['Hash']}  JA3={match_types['JA3']}")


if __name__ == "__main__":
    main()