# soc/risk_fusion.py

import json
import os
from datetime import datetime, timezone

INPUT_FILE  = "alerts/tip_enriched.json"
OUTPUT_FILE = "alerts/final_incidents.json"

# Ollama AI analysis — optional, gracefully skipped if unavailable
OLLAMA_ENABLED = os.getenv("OLLAMA_ENABLED", "1") == "1"


# =====================================================
# Severity Mapping
# =====================================================

def severity_from_score(score):
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def clamp(score):
    return max(0, min(score, 100))


# =====================================================
# Main Risk Fusion Engine
# =====================================================

def main():

    if not os.path.exists(INPUT_FILE):
        print("tip_enriched.json missing")
        return

    with open(INPUT_FILE, "r") as f:
        alerts = json.load(f).get("alerts", [])

    for alert in alerts:

        base_score    = alert.get("tip", {}).get("score", 0)
        score         = base_score
        count         = alert.get("count", 1)
        severity_hint = alert.get("severity_hint", "Low").lower()

        vt      = alert.get("virustotal", {})
        otx     = alert.get("otx", {})
        abuse   = alert.get("abuseipdb", {})
        signals = alert.get("tip", {}).get("signals", [])

        # =====================================================
        # 1. Frequency Boost
        # =====================================================
        if count >= 3:
            score += 10
        if count >= 5:
            score += 15
        if count >= 10:
            score += 20

        # =====================================================
        # 2. Behavioral Escalation
        # =====================================================
        if severity_hint == "high":
            score += 15
        elif severity_hint == "medium":
            score += 8

        # =====================================================
        # 3. Strong TI Confirmation Boost
        # =====================================================
        if vt.get("malicious", 0) >= 10:
            score += 20
        if abuse.get("confidence", 0) >= 75:
            score += 15
        if otx.get("pulse_count", 0) >= 5:
            score += 10

        # =====================================================
        # 4. Multi-Signal Boost
        # =====================================================
        if len(signals) >= 3:
            score += 10

        score      = clamp(score)
        final_risk = severity_from_score(score)

        alert["final_score"] = score
        alert["final_risk"]  = final_risk
        alert["risk_explanation"] = (
            f"Base TIP score: {base_score}. "
            f"Frequency ({count}), behavioral hint ({severity_hint}), "
            f"and threat intelligence signals were fused to compute final score {score}."
        )

    # =====================================================
    # 5. Ollama AI Analysis (per-incident reasoning)
    # =====================================================
    if OLLAMA_ENABLED:
        try:
            # Import here so the module loads fine even if ollama_analyst
            # has a missing dependency
            from soc.ollama_analyst import enrich_all
            alerts = enrich_all(alerts)
        except ImportError:
            print("[risk_fusion] ollama_analyst not found — skipping AI analysis")
        except Exception as e:
            print(f"[risk_fusion] Ollama enrichment error: {e} — continuing without AI analysis")
    else:
        print("[risk_fusion] OLLAMA_ENABLED=0 — skipping AI analysis")
        for alert in alerts:
            alert["ai_analysis"] = {
                "threat_summary":     "AI analysis disabled (set OLLAMA_ENABLED=1 in .env to enable).",
                "attack_hypothesis":  "N/A",
                "recommended_action": "Enable Ollama in .env | Run: ollama serve",
                "confidence":         "Low",
                "skipped":            True
            }

    # =====================================================
    # Write output
    # =====================================================
    with open(OUTPUT_FILE, "w") as f:
        json.dump({
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "incident_count": len(alerts),
            "incidents":      alerts
        }, f, indent=4)

    print("[+] Advanced risk fusion completed")


if __name__ == "__main__":
    main()