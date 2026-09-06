# soc/ollama_analyst.py
"""
Groq AI Analyst  (drop-in replacement for the Ollama version)
==============================================================
Uses the Groq API to generate per-incident AI reasoning.
Groq runs llama3-8b-8192 at ~500 tokens/sec on their cloud hardware —
~100x faster than running llama3 on a CPU locally.

Setup (one-time):
  1. Get a FREE API key at https://console.groq.com
  2. Add to your .env file:
       GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxx
       GROQ_MODEL=llama3-8b-8192        (optional, this is the default)

Public API (unchanged from Ollama version):
  enrich_all(incidents)          -> list   called by risk_fusion.py
  analyse_incident(inc, cache)   -> dict
  should_analyse(incident)       -> bool

What it adds to each incident:
  ai_analysis:
    threat_summary     : 1-2 sentences explaining why this is suspicious
    attack_hypothesis  : what attacker technique/goal this suggests
    recommended_action : 3 specific SOC response steps (| separated)
    confidence         : High / Medium / Low

Performance:
  - Groq free tier: 30 req/min, 14,400 req/day — plenty for SOC use
  - Results cached in cache/groq_cache.json (re-upload = instant, no API calls)
  - Only Critical/High/Malicious incidents are sent to Groq (skips Low/Medium clean)
  - Rate limit handled with automatic retry + backoff
  - Full pipeline for 146 incidents: ~60-90 seconds (vs hours with local CPU)
"""

import os
import json
import time
import hashlib
import requests
from dotenv import dotenv_values

# ---------------------------------------------------------------------------
# Config — reads .env directly to avoid system env conflicts
# ---------------------------------------------------------------------------

_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_HERE)
_ENV_PATH    = os.path.join(PROJECT_ROOT, ".env")
_ENV         = dotenv_values(_ENV_PATH)

GROQ_API_KEY = _ENV.get("GROQ_API_KEY") or os.getenv("GROQ_API_KEY", "")
GROQ_MODEL   = _ENV.get("GROQ_MODEL")   or os.getenv("GROQ_MODEL",   "llama3-8b-8192")
GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"

CACHE_FILE   = os.path.join(PROJECT_ROOT, "cache", "groq_cache.json")

# Groq free tier: 30 requests/minute → wait 2.1s between calls to stay safe
_REQUEST_DELAY = 2.1


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _load_cache() -> dict:
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(cache: dict):
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


def _cache_key(incident: dict) -> str:
    raw = (
        f"{incident.get('indicator','')}"
        f"__{incident.get('reason','')}"
        f"__{incident.get('protocol','')}"
        f"__{incident.get('final_risk','')}"
    )
    return hashlib.md5(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Eligibility — only send worthwhile incidents to Groq
# ---------------------------------------------------------------------------

def should_analyse(incident: dict) -> bool:
    risk    = incident.get("final_risk",     "Low")
    verdict = incident.get("threat_verdict", "Unknown")
    count   = incident.get("count", 1)
    score   = incident.get("final_score",    0)

    if risk in ("Critical", "High"):
        return True
    if risk == "Medium" and (verdict == "Malicious" or count >= 3 or score >= 50):
        return True
    if verdict == "Malicious":
        return True
    return False


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def _build_prompt(incident: dict) -> str:
    mitre = incident.get("mitre", {})
    tip   = incident.get("tip",   {})
    vt    = incident.get("virustotal",  {})
    abuse = incident.get("abuseipdb",   {})
    otx   = incident.get("otx",         {})

    return f"""You are a senior SOC analyst. Analyse this network security incident and respond ONLY with a JSON object — no markdown, no explanation, just the JSON.

INCIDENT:
- Indicator  : {incident.get('indicator', 'unknown')}
- Protocol   : {incident.get('protocol',  'unknown')}
- Reason     : {incident.get('reason',    'unknown')}
- Risk       : {incident.get('final_risk','unknown')} (score {incident.get('final_score', 0)}/100)
- Count      : {incident.get('count', 1)} events
- TI Verdict : {incident.get('threat_verdict', 'Unknown')}
- MITRE      : {mitre.get('technique_id','N/A')} {mitre.get('technique','')} [{mitre.get('tactic','Unknown')}]
- Signals    : {', '.join(tip.get('signals', [])) or 'None'}
- VirusTotal : {vt.get('malicious', 0)} malicious engines
- AbuseIPDB  : {abuse.get('confidence', 0)}% confidence
- OTX Pulses : {otx.get('pulse_count', 0)}

Required JSON (respond with ONLY this, nothing else):
{{"threat_summary":"1-2 sentences: why suspicious and what it indicates","attack_hypothesis":"specific attacker goal or campaign this represents","recommended_action":"step 1 | step 2 | step 3","confidence":"High or Medium or Low"}}"""


# ---------------------------------------------------------------------------
# Groq API call
# ---------------------------------------------------------------------------

def _call_groq(prompt: str, retry: int = 0) -> dict | None:
    """
    Call Groq API using OpenAI-compatible chat completions endpoint.
    Handles rate limits with exponential backoff (max 2 retries).
    """
    if not GROQ_API_KEY:
        print("[groq] ERROR: GROQ_API_KEY not set in .env")
        return None

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type":  "application/json",
    }

    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {
                "role":    "system",
                "content": "You are a senior SOC analyst. Always respond with valid JSON only. No markdown, no code blocks, no explanation."
            },
            {
                "role":    "user",
                "content": prompt
            }
        ],
        "temperature":  0.2,
        "max_tokens":   350,
        "stream":       False,
    }

    try:
        resp = requests.post(GROQ_URL, headers=headers, json=payload, timeout=20)

        # Rate limit — wait and retry
        if resp.status_code == 429:
            if retry < 2:
                wait = (retry + 1) * 15   # 15s, 30s
                print(f"[groq] Rate limited — waiting {wait}s then retrying...")
                time.sleep(wait)
                return _call_groq(prompt, retry + 1)
            else:
                print("[groq] Rate limit retries exhausted")
                return None

        if resp.status_code != 200:
            print(f"[groq] HTTP {resp.status_code}: {resp.text[:300]}")
            return None

        raw_text = resp.json()["choices"][0]["message"]["content"].strip()

        # Strip markdown fences if model added them despite instructions
        if "```" in raw_text:
            lines    = raw_text.split("\n")
            raw_text = "\n".join(l for l in lines if not l.strip().startswith("```"))

        # Extract JSON object
        start = raw_text.find("{")
        end   = raw_text.rfind("}") + 1
        if start == -1 or end == 0:
            print(f"[groq] No JSON in response: {raw_text[:200]}")
            return None

        parsed = json.loads(raw_text[start:end])

        required = {"threat_summary", "attack_hypothesis", "recommended_action", "confidence"}
        if not required.issubset(parsed.keys()):
            print(f"[groq] Missing keys: {set(parsed.keys())}")
            return None

        # Normalise confidence value
        conf = parsed.get("confidence", "Low").strip().capitalize()
        if conf not in ("High", "Medium", "Low"):
            conf = "Medium"
        parsed["confidence"] = conf

        return parsed

    except requests.exceptions.Timeout:
        print(f"[groq] Request timed out after 20s")
        return None
    except requests.exceptions.ConnectionError:
        print(f"[groq] Cannot connect to Groq API — check internet connection")
        return None
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[groq] Parse error: {e}")
        return None
    except Exception as e:
        print(f"[groq] Unexpected error: {e}")
        return None


# ---------------------------------------------------------------------------
# Connectivity / key check
# ---------------------------------------------------------------------------

def check_groq_available() -> bool:
    """Verify Groq API key is set and endpoint is reachable."""
    if not GROQ_API_KEY:
        print("[groq] GROQ_API_KEY not found in .env")
        print("[groq] Get a free key at https://console.groq.com → API Keys")
        return False
    try:
        resp = requests.get(
            "https://api.groq.com/openai/v1/models",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
            timeout=8
        )
        if resp.status_code == 200:
            return True
        print(f"[groq] Key check failed: HTTP {resp.status_code}")
        return False
    except Exception as e:
        print(f"[groq] Cannot reach Groq API: {e}")
        return False


# ---------------------------------------------------------------------------
# Single incident analysis
# ---------------------------------------------------------------------------

def analyse_incident(incident: dict, cache: dict) -> dict:
    """
    Add ai_analysis to one incident. Uses cache to avoid duplicate API calls.
    Called by enrich_all() — also callable standalone.
    """
    key = _cache_key(incident)

    if key in cache:
        incident["ai_analysis"] = cache[key]
        return cache[key]

    if not should_analyse(incident):
        result = {
            "threat_summary":     "Low severity — AI analysis skipped.",
            "attack_hypothesis":  "Monitor for escalation.",
            "recommended_action": "Log | Monitor | No immediate action required",
            "confidence":         "Low",
            "skipped":            True
        }
        incident["ai_analysis"] = result
        return result

    result = _call_groq(_build_prompt(incident))

    if result is None:
        result = {
            "threat_summary":     "AI analysis failed — check GROQ_API_KEY and internet connection.",
            "attack_hypothesis":  "Manual review required.",
            "recommended_action": "Review indicator manually | Escalate if high risk | Check Groq API key",
            "confidence":         "Low",
            "error":              True
        }

    incident["ai_analysis"] = result
    cache[key]              = result
    return result


# ---------------------------------------------------------------------------
# Batch enrichment — called from risk_fusion.py
# ---------------------------------------------------------------------------

def enrich_all(incidents: list) -> list:
    """
    Add ai_analysis to all incidents in the list.
    Modifies in-place and returns the list.
    Called automatically by risk_fusion.py after scoring.
    """
    # ── Pre-flight check ──────────────────────────────────────────────────
    if not check_groq_available():
        print("[groq] Skipping AI analysis — fix GROQ_API_KEY and re-upload PCAP")
        for inc in incidents:
            inc["ai_analysis"] = {
                "threat_summary":     "Groq API unavailable. Add GROQ_API_KEY to .env to enable AI analysis.",
                "attack_hypothesis":  "N/A",
                "recommended_action": "Get free key at console.groq.com | Add GROQ_API_KEY to .env | Re-upload PCAP",
                "confidence":         "Low",
                "error":              True
            }
        return incidents

    print(f"[groq] Connected — model: {GROQ_MODEL}")

    cache      = _load_cache()
    analysed   = 0
    cached_hit = 0
    skipped    = 0
    errors     = 0

    # Count how many will actually need API calls
    to_analyse = [
        inc for inc in incidents
        if _cache_key(inc) not in cache and should_analyse(inc)
    ]
    print(f"[groq] {len(to_analyse)} incidents need analysis  "
          f"({len(incidents) - len(to_analyse)} cached/skipped)")

    for i, inc in enumerate(incidents):
        key = _cache_key(inc)

        # Cache hit — instant
        if key in cache:
            inc["ai_analysis"] = cache[key]
            cached_hit += 1
            continue

        # Not worth analysing
        if not should_analyse(inc):
            inc["ai_analysis"] = {
                "threat_summary":     "Low severity — AI analysis skipped.",
                "attack_hypothesis":  "Monitor for escalation.",
                "recommended_action": "Log | Monitor | No immediate action required",
                "confidence":         "Low",
                "skipped":            True
            }
            skipped += 1
            continue

        # Live API call
        print(f"[groq] Analysing {analysed + 1}/{len(to_analyse)}: "
              f"{inc.get('protocol','?')} | {str(inc.get('indicator',''))[:50]} "
              f"| {inc.get('final_risk','?')}")

        result = _call_groq(_build_prompt(inc))

        if result is None:
            result = {
                "threat_summary":     "AI analysis failed for this incident.",
                "attack_hypothesis":  "Manual review required.",
                "recommended_action": "Escalate to senior analyst | Manual IOC review | Check Groq API status",
                "confidence":         "Low",
                "error":              True
            }
            errors += 1
        else:
            analysed += 1

        inc["ai_analysis"] = result
        cache[key]         = result

        # Save cache after every call — no work lost if pipeline interrupted
        _save_cache(cache)

        # Respect Groq free tier rate limit (30 req/min)
        if analysed + errors < len(to_analyse):
            time.sleep(_REQUEST_DELAY)

    _save_cache(cache)

    print(f"[groq] AI analysis complete — "
          f"analysed: {analysed}  cached: {cached_hit}  skipped: {skipped}  errors: {errors}")
    if errors:
        print(f"[groq] {errors} errors — those incidents show fallback message on dashboard")

    return incidents