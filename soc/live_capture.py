# soc/live_capture.py
"""
Live Traffic Capture Module -- Live Zeek on WSL Interface
=========================================================
KEY FIX vs previous version:
  Zeek writes logs to /tmp/zeek_live_logs/ inside WSL (pure Linux path).
  Every pipeline cycle, those logs are copied to Windows zeek_logs/.
  This avoids ALL Windows path / cd issues that caused 0 alerts.

HOW TO GENERATE ALERTS (WSL2 eth0 limitation):
  eth0 in WSL2 is virtual -- it only sees traffic FROM WSL processes.
  While capture is running, open a WSL terminal and run:
    cd ~
    curl http://1.14.157.231 --max-time 5
    nslookup xk3mz9q2p1r7v8s.xyz
    nslookup xk3mz9q2p2r7v8s.xyz
    nslookup xk3mz9q2p3r7v8s.xyz
    nslookup xk3mz9q2p4r7v8s.xyz
    nslookup xk3mz9q2p5r7v8s.xyz
    nslookup xk3mz9q2p6r7v8s.xyz
  Wait 30s for pipeline run. Alerts will appear on dashboard.

  For real Windows traffic: add networkingMode=mirrored to .wslconfig

Environment variables (.env)
-----------------------------
  ZEEK_BINARY    = /opt/zeek/bin/zeek  (default)
  WSL_DISTRO     = Ubuntu-22.04         (default)
  LIVE_INTERVAL  = 30                   (pipeline re-run cadence, seconds)
  LIVE_MAX_ALERTS= 500                  (cap on rolling alert window)
"""

import os
import sys
import subprocess
import threading
import time
import json
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_HERE)

ZEEK_LOG_DIR      = os.path.join(PROJECT_ROOT, "zeek_logs")
ALERTS_DIR        = os.path.join(PROJECT_ROOT, "alerts")
STATE_FILE        = os.path.join(ALERTS_DIR, "live_state.json")
OFFSET_FILE       = os.path.join(ALERTS_DIR, "live_offsets.json")

ZEEK_BINARY       = os.getenv("ZEEK_BINARY",  "/opt/zeek/bin/zeek")
WSL_DISTRO        = os.getenv("WSL_DISTRO",   "Ubuntu-22.04")
PIPELINE_INTERVAL = int(os.getenv("LIVE_INTERVAL",    "30"))
MAX_ALERTS        = int(os.getenv("LIVE_MAX_ALERTS",  "500"))

# Zeek writes here inside WSL (pure Linux path — no Windows path issues)
WSL_ZEEK_TMP = "/tmp/zeek_live_logs"

_lock           = threading.Lock()
_zeek_proc      = None
_worker_thread  = None
_capture_iface  = None
_start_time     = None
_pipeline_count = 0
_last_run_ts    = None
_stop_event     = threading.Event()


# ==============================================================================
# WSL helpers
# ==============================================================================

def _windows_to_wsl_path(win_path: str) -> str:
    """Convert D:\\foo\\bar  ->  /mnt/d/foo/bar"""
    drive, rest = win_path.split(":", 1)
    return f"/mnt/{drive.lower()}{rest.replace(chr(92), '/')}"


def list_wsl_interfaces() -> list:
    """Return all WSL network interfaces."""
    try:
        result = subprocess.run(
            ["wsl", "-d", WSL_DISTRO, "ip", "-o", "link", "show"],
            capture_output=True, text=True, timeout=10
        )
        ifaces = []
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                name = parts[1].strip().split("@")[0].strip()
                if name and name != "lo":
                    ifaces.append(name)
        if not ifaces:
            return ["eth0"]
        # Put eth0 first
        if "eth0" in ifaces:
            ifaces.remove("eth0")
            ifaces.insert(0, "eth0")
        return ifaces
    except Exception:
        return ["eth0"]


def reset_offsets():
    """Clear byte offsets so incremental reader starts fresh."""
    if os.path.exists(OFFSET_FILE):
        os.remove(OFFSET_FILE)


def _sync_logs_to_windows():
    """
    Copy logs from /tmp/zeek_live_logs/ (WSL) to zeek_logs/ (Windows).
    This is the key fix -- Zeek writes to a pure Linux path, we copy
    to Windows so the Python pipeline can read them.
    """
    wsl_win_path = _windows_to_wsl_path(os.path.abspath(ZEEK_LOG_DIR))

    bash_cmd = (
        f"if [ -d '{WSL_ZEEK_TMP}' ] && ls '{WSL_ZEEK_TMP}'/*.log 2>/dev/null; then "
        f"  cp -f '{WSL_ZEEK_TMP}'/*.log '{wsl_win_path}/' && echo 'SYNCED'; "
        f"else "
        f"  echo 'NO_LOGS_YET'; "
        f"fi"
    )
    try:
        result = subprocess.run(
            ["wsl", "-d", WSL_DISTRO, "bash", "-c", bash_cmd],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout.strip()
        print(f"[live_capture] log sync: {output}")
        return "SYNCED" in output
    except Exception as e:
        print(f"[live_capture] log sync error: {e}")
        return False


def _check_wsl_logs():
    """Print what Zeek has written inside WSL -- shown in Flask console."""
    bash_cmd = (
        f"if [ -d '{WSL_ZEEK_TMP}' ]; then "
        f"  echo '--- WSL zeek logs ---'; "
        f"  ls -lh '{WSL_ZEEK_TMP}'/*.log 2>/dev/null || echo 'No .log files yet'; "
        f"else "
        f"  echo 'Dir {WSL_ZEEK_TMP} does not exist -- Zeek may not have started'; "
        f"fi"
    )
    try:
        result = subprocess.run(
            ["wsl", "-d", WSL_DISTRO, "bash", "-c", bash_cmd],
            capture_output=True, text=True, timeout=10
        )
        print(result.stdout.strip())
    except Exception as e:
        print(f"[live_capture] wsl log check error: {e}")


# ==============================================================================
# Pipeline runner
# ==============================================================================

def _run_module(module_name: str, env_extra: dict = None):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    subprocess.run(
        [sys.executable, "-m", module_name],
        check=True, cwd=PROJECT_ROOT, env=env, timeout=120
    )


def run_pipeline_once():
    """
    1. Check what Zeek wrote inside WSL
    2. Copy logs from WSL -> Windows zeek_logs/
    3. Run full SOC pipeline
    """
    global _pipeline_count, _last_run_ts

    # Show WSL log status in Flask console
    _check_wsl_logs()

    # Copy logs from WSL to Windows
    _sync_logs_to_windows()

    # Run the pipeline
    modules = [
        ("soc.extract_indicators", {"LIVE_MODE": "1"}),
        ("soc.tag_severity",       {}),
        ("soc.deduplicate_alerts", {}),
        ("soc.match_threats",      {}),
        ("soc.enrich_virustotal",  {}),
        ("soc.enrich_otx",         {}),
        ("soc.enrich_abuseipdb",   {}),
        ("soc.tip_engine",         {}),
        ("soc.risk_fusion",        {}),
        ("soc.mitre_mapper",       {}),
    ]

    for mod, env_extra in modules:
        try:
            _run_module(mod, env_extra=env_extra)
        except subprocess.CalledProcessError:
            print(f"[live_capture] module {mod} failed -- continuing")
        except Exception as exc:
            print(f"[live_capture] error in {mod}: {exc}")

    _pipeline_count += 1
    _last_run_ts = datetime.now(timezone.utc).isoformat()
    _save_state()
    print(f"[live_capture] pipeline run #{_pipeline_count} complete at {_last_run_ts}")


# ==============================================================================
# Background worker thread
# ==============================================================================

class _PipelineWorker(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="live-pipeline-worker")

    def run(self):
        # Give Zeek 10s to start writing
        _stop_event.wait(timeout=10)

        while not _stop_event.is_set():
            try:
                run_pipeline_once()
            except Exception as exc:
                print(f"[live_capture] worker exception: {exc}")

            # Sleep in 0.5s ticks so stop wakes us fast
            for _ in range(PIPELINE_INTERVAL * 2):
                if _stop_event.is_set():
                    break
                time.sleep(0.5)

        print("[live_capture] pipeline worker stopped")


# ==============================================================================
# State persistence
# ==============================================================================

def _save_state():
    os.makedirs(ALERTS_DIR, exist_ok=True)
    state = {
        "running":       _zeek_proc is not None and _zeek_proc.poll() is None,
        "interface":     _capture_iface,
        "start_time":    _start_time,
        "pipeline_runs": _pipeline_count,
        "last_run":      _last_run_ts,
        "interval_sec":  PIPELINE_INTERVAL,
    }
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ==============================================================================
# Public API
# ==============================================================================

def start_live_capture(interface: str) -> dict:
    global _zeek_proc, _worker_thread, _capture_iface
    global _start_time, _pipeline_count, _last_run_ts

    with _lock:
        if _zeek_proc is not None and _zeek_proc.poll() is None:
            return {
                "status":  "already_running",
                "message": f"Live capture already active on {_capture_iface}"
            }

        if not interface:
            return {"status": "error", "message": "No interface specified"}

        os.makedirs(ZEEK_LOG_DIR, exist_ok=True)
        os.makedirs(ALERTS_DIR,   exist_ok=True)

        # Clean Windows zeek_logs/
        for fname in os.listdir(ZEEK_LOG_DIR):
            fpath = os.path.join(ZEEK_LOG_DIR, fname)
            if os.path.isfile(fpath):
                os.remove(fpath)

        reset_offsets()

        # ── KEY FIX: Zeek writes to pure Linux /tmp path ──────────────────
        # Steps:
        #   1. Remove old temp logs
        #   2. Create fresh temp dir
        #   3. cd into it  (100% reliable -- pure Linux path)
        #   4. Run zeek -i <interface>
        # We then cp these logs to Windows zeek_logs/ each pipeline cycle.
        bash_cmd = (
            f"rm -rf '{WSL_ZEEK_TMP}' && "
            f"mkdir -p '{WSL_ZEEK_TMP}' && "
            f"cd '{WSL_ZEEK_TMP}' && "
            f"sudo '{ZEEK_BINARY}' -i {interface} --no-checksums"
        )

        zeek_cmd = ["wsl", "-d", WSL_DISTRO, "bash", "-c", bash_cmd]

        print(f"[live_capture] ========================================")
        print(f"[live_capture] Starting Zeek on interface: {interface}")
        print(f"[live_capture] Zeek log dir (WSL): {WSL_ZEEK_TMP}")
        print(f"[live_capture] Pipeline log dir  : {ZEEK_LOG_DIR}")
        print(f"[live_capture] Command: {bash_cmd}")
        print(f"[live_capture] ========================================")
        print(f"[live_capture] NOTE: eth0 only sees WSL-generated traffic.")
        print(f"[live_capture] To test: open WSL terminal and run:")
        print(f"[live_capture]   cd ~ && curl http://1.14.157.231 --max-time 5")
        print(f"[live_capture]   nslookup xk3mz9q2p1r7v8s.xyz")
        print(f"[live_capture] ========================================")

        try:
            _zeek_proc = subprocess.Popen(
                zeek_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        except Exception as exc:
            return {"status": "error", "message": f"Failed to launch Zeek: {exc}"}

        _capture_iface  = interface
        _start_time     = datetime.now(timezone.utc).isoformat()
        _pipeline_count = 0
        _last_run_ts    = None
        _stop_event.clear()

        _worker_thread = _PipelineWorker()
        _worker_thread.start()
        _save_state()

        print(f"[live_capture] Zeek started (PID {_zeek_proc.pid})")
        return {
            "status":    "started",
            "message":   f"Live capture started on '{interface}'",
            "interface": interface,
            "pid":       _zeek_proc.pid,
            "interval":  PIPELINE_INTERVAL,
        }


def stop_live_capture() -> dict:
    global _zeek_proc, _worker_thread, _capture_iface

    with _lock:
        if _zeek_proc is None or _zeek_proc.poll() is not None:
            return {"status": "not_running", "message": "No active live capture"}

        _stop_event.set()

        try:
            _zeek_proc.terminate()
            _zeek_proc.wait(timeout=10)
        except Exception:
            try:
                _zeek_proc.kill()
            except Exception:
                pass

        iface = _capture_iface

        if _worker_thread and _worker_thread.is_alive():
            _worker_thread.join(timeout=15)

        # Final sync + pipeline run
        _sync_logs_to_windows()
        try:
            run_pipeline_once()
        except Exception as exc:
            print(f"[live_capture] final pipeline run error: {exc}")

        _zeek_proc     = None
        _worker_thread = None
        _capture_iface = None
        _save_state()

        print(f"[live_capture] stopped (was on {iface})")
        return {
            "status":              "stopped",
            "message":             f"Live capture on '{iface}' stopped",
            "total_pipeline_runs": _pipeline_count,
        }


def get_live_status() -> dict:
    with _lock:
        zeek_alive = _zeek_proc is not None and _zeek_proc.poll() is None
        return {
            "running":       zeek_alive,
            "interface":     _capture_iface,
            "start_time":    _start_time,
            "pipeline_runs": _pipeline_count,
            "last_run":      _last_run_ts,
            "interval_sec":  PIPELINE_INTERVAL,
            "zeek_alive":    zeek_alive,
        }