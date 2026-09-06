# soc/tip_engine.py

import json
import os
from datetime import datetime, timezone

_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_HERE)

INPUT_FILE  = os.path.join(PROJECT_ROOT, "alerts", "threat_enriched.json")
OUTPUT_FILE = os.path.join(PROJECT_ROOT, "alerts", "tip_enriched.json")

WEIGHTS = {
    "local_feed":       35,
    "virustotal":       30,
    "otx":              15,
    "abuseipdb":        20,
    "ti_confirmed":     25,   # AbuseIPDB or OTX confirmed it (any pulse/confidence)
    "behavior_high":    20,
    "behavior_medium":  10,
    "behavior_low":      5,
}


def clamp(score):
    return max(0, min(score, 100))


def evaluate_tip(alert):
    score   = 0
    signals = []

    # ── Local feed match ─────────────────────────────────────────────────────
    if alert.get("threat_verdict") == "Malicious":
        score += WEIGHTS["local_feed"]
        signals.append("Local Feed Match")

    # ── VirusTotal ───────────────────────────────────────────────────────────
    vt = alert.get("virustotal", {})
    if vt.get("malicious", 0) >= 5:
        score += WEIGHTS["virustotal"]
        signals.append("VirusTotal Hit")
    elif vt.get("malicious", 0) >= 1:
        # Partial VT hit — fewer engines flagged it
        score += 10
        signals.append("VirusTotal Partial Hit")

    # ── OTX ─────────────────────────────────────────────────────────────────
    otx = alert.get("otx", {})
    if otx.get("pulse_count", 0) >= 3:
        score += WEIGHTS["otx"]
        signals.append("OTX Pulse Match (strong)")
    elif otx.get("pulse_count", 0) >= 1:
        # Any OTX pulse is meaningful — lower threshold
        score += 10
        signals.append("OTX Pulse Match")

    # ── AbuseIPDB ────────────────────────────────────────────────────────────
    abuse = alert.get("abuseipdb", {})
    if abuse.get("confidence", 0) >= 50:
        score += WEIGHTS["abuseipdb"]
        signals.append("AbuseIPDB Reputation (strong)")
    elif abuse.get("confidence", 0) >= 25:
        # Partial confidence still meaningful
        score += 10
        signals.append("AbuseIPDB Reputation")

    # ── ti_confirmed bonus ───────────────────────────────────────────────────
    # If AbuseIPDB or OTX confirmed the indicator (any level), give a base bonus
    # This ensures VT being skipped doesn't lose the score entirely
    if alert.get("ti_confirmed", False) and "Local Feed Match" not in signals:
        score += WEIGHTS["ti_confirmed"]
        signals.append("TI Confirmed (AbuseIPDB/OTX)")

    # ── Behavioral risk ──────────────────────────────────────────────────────
    bh = alert.get("severity_hint", "Low").lower()
    if bh == "high":
        score += WEIGHTS["behavior_high"]
        signals.append("High Behavioral Risk")
    elif bh == "medium":
        score += WEIGHTS["behavior_medium"]
        signals.append("Medium Behavioral Risk")
    else:
        score += WEIGHTS["behavior_low"]

    # ── Multi-signal bonus ───────────────────────────────────────────────────
    # 3+ independent sources agree → extra confidence boost
    if len(signals) >= 3:
        score += 10
        signals.append("Multi-signal correlation bonus")

    return {"score": clamp(score), "signals": signals}


def main():
    if not os.path.exists(INPUT_FILE):
        print("[-] threat_enriched.json not found")
        return

    with open(INPUT_FILE, "r") as f:
        data = json.load(f)

    for alert in data.get("alerts", []):
        alert["tip"] = evaluate_tip(alert)

    with open(OUTPUT_FILE, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "alerts":       data["alerts"]
        }, f, indent=4)

    print("[+] TIP scoring completed")


if __name__ == "__main__":
    main()