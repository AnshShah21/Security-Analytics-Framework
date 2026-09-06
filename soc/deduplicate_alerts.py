# soc/deduplicate_alerts.py

import json
import os
from collections import defaultdict
from datetime import datetime

INPUT_FILE = "alerts/tagged_alerts.json"
OUTPUT_FILE = "alerts/correlated_alerts.json"


def severity_rank(sev):
    return {"Low":1, "Medium":2, "High":3, "Critical":4}.get(sev, 1)


def correlate_alerts(alerts):
    grouped = defaultdict(list)

    for alert in alerts:
        key = (
            alert.get("protocol"),
            alert.get("indicator"),
            alert.get("reason")
        )
        grouped[key].append(alert)

    correlated = []

    for (protocol, indicator, reason), items in grouped.items():
        highest_sev = max(
            [i.get("severity", "Low") for i in items],
            key=severity_rank
        )

        correlated.append({
            "protocol": protocol,
            "indicator": indicator,
            "reason": reason,
            "severity": highest_sev,
            "severity_hint": highest_sev,
            "count": len(items),
            "first_seen": min(i["timestamp"] for i in items),
            "last_seen": max(i["timestamp"] for i in items),

            # Enrichment placeholders
            "virustotal": {},
            "otx": {},
            "abuseipdb": {},
            "threat_source": "Local Feed",
            "details": items[0].get("details", {})
        })

    return correlated


def main():
    if not os.path.exists(INPUT_FILE):
        print("tagged_alerts.json not found")
        return

    with open(INPUT_FILE, "r") as f:
        alerts = json.load(f).get("alerts", [])

    correlated = correlate_alerts(alerts)

    with open(OUTPUT_FILE, "w") as f:
        json.dump({
            "generated_at": datetime.utcnow().isoformat(),
            "alerts": correlated
        }, f, indent=4)

    print(f"[+] Reduced {len(alerts)} alerts -> {len(correlated)} incidents")


if __name__ == "__main__":
    main()
