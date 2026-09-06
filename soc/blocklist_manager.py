# soc/blocklist_manager.py
"""
Blocklist Manager
-----------------
Handles saving, loading, and querying the persistent block list.
All firewall block/unblock actions are recorded here.

File: alerts/blocklist.json
"""

import json
import os
from datetime import datetime

BLOCKLIST_FILE = os.path.join("alerts", "blocklist.json")


def _load() -> dict:
    """Load the raw blocklist dict from disk. Returns empty structure if missing."""
    if not os.path.exists(BLOCKLIST_FILE):
        return {"blocked": {}}
    with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data: dict):
    """Persist the blocklist dict to disk."""
    os.makedirs("alerts", exist_ok=True)
    with open(BLOCKLIST_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def add_block(indicator: str, indicator_type: str, reason: str, severity: str) -> dict:
    """
    Record a new block entry.

    Parameters
    ----------
    indicator      : IP address or domain string
    indicator_type : 'ip' or 'domain'
    reason         : human-readable reason (e.g. 'Malicious - VT hit')
    severity       : final_risk value from the incident

    Returns the new block record.
    """
    data = _load()

    record = {
        "indicator":      indicator,
        "type":           indicator_type,
        "reason":         reason,
        "severity":       severity,
        "blocked_at":     datetime.utcnow().isoformat(),
        "status":         "active",
        "firewall_alias": f"SOC_BLOCK_{indicator.replace('.', '_').replace('-', '_')}"
    }

    data["blocked"][indicator] = record
    _save(data)
    return record


def remove_block(indicator: str) -> bool:
    """
    Mark an indicator as unblocked (soft delete — keeps the audit trail).
    Returns True if the indicator was found, False otherwise.
    """
    data = _load()

    if indicator not in data["blocked"]:
        return False

    data["blocked"][indicator]["status"]       = "unblocked"
    data["blocked"][indicator]["unblocked_at"] = datetime.utcnow().isoformat()
    _save(data)
    return True


def is_blocked(indicator: str) -> bool:
    """Return True if the indicator is currently actively blocked."""
    data = _load()
    entry = data["blocked"].get(indicator)
    return entry is not None and entry.get("status") == "active"


def get_all_blocks() -> list:
    """Return all block records (both active and unblocked) as a list."""
    data = _load()
    return list(data["blocked"].values())


def get_active_blocks() -> list:
    """Return only currently active (not yet unblocked) records."""
    return [r for r in get_all_blocks() if r.get("status") == "active"]


def get_block_record(indicator: str) -> dict | None:
    """Return the full record for a single indicator, or None if not found."""
    data = _load()
    return data["blocked"].get(indicator)