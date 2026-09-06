# soc/tag_severity.py
"""
Behavioral Tagging Module (BASELINE SEVERITY ENABLED)
----------------------------------------------------
• Converts raw alerts into behavioral risk
• Assigns baseline severity before TIP enrichment
• Keeps severity for later correlation
"""

import json
import os

INPUT_FILE = "alerts/alerts.json"
OUTPUT_FILE = "alerts/tagged_alerts.json"


def calculate_behavioral_risk(alert):
    protocol = alert.get("protocol", "")
    reason = alert.get("reason", "").lower()

    # Trust extraction hint if provided
    if "severity_hint" in alert:
        return alert["severity_hint"].lower()

    # High risk patterns
    if "credential" in reason:
        return "high"

    if protocol in ["FTP", "SMTP"] and "clear" in reason:
        return "high"

    if protocol == "DNS" and ("tunnel" in reason or "exfiltration" in reason):
        return "high"

    # Medium risk
    if protocol == "DNS" and ("long dns" in reason or "suspicious dns" in reason):
        return "medium"

    if protocol in ["HTTP", "TLS"]:
        return "medium"

    # Low risk
    if protocol == "CONN":
        return "low"

    return "low"


def behavioral_to_severity(risk):
    mapping = {
        "high": "High",
        "medium": "Medium",
        "low": "Low"
    }
    return mapping.get(risk, "Low")


def main():
    if not os.path.exists(INPUT_FILE):
        print("[!] alerts.json not found")
        return

    with open(INPUT_FILE, "r") as f:
        data = json.load(f)

    for alert in data.get("alerts", []):
        behavioral = calculate_behavioral_risk(alert)
        alert["behavioral_risk"] = behavioral

        # 🔥 Baseline severity preserved
        alert["severity"] = behavioral_to_severity(behavioral)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=4)

    print("[+] Behavioral tagging complete (baseline severity assigned)")


if __name__ == "__main__":
    main()