import os
import subprocess
from dotenv import load_dotenv

load_dotenv()

_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_HERE)

ZEEK_LOG_DIR = os.path.join(PROJECT_ROOT, "zeek_logs")
ZEEK_BINARY  = os.getenv("ZEEK_BINARY", "/opt/zeek/bin/zeek")
WSL_DISTRO   = os.getenv("WSL_DISTRO",  "Ubuntu-22.04")


def windows_to_wsl_path(win_path: str) -> str:
    """Convert a Windows absolute path to its WSL /mnt/<drive>/... equivalent."""
    drive, rest = win_path.split(":", 1)
    return f"/mnt/{drive.lower()}{rest.replace(chr(92), '/')}"


def run_zeek_on_pcap(pcap_path: str) -> dict:
    """
    Run Zeek on a PCAP file inside WSL and write logs to ZEEK_LOG_DIR.

    Key fix vs original:
      Instead of  wsl --cd <log_dir> zeek -r <pcap>
      We now use  wsl bash -c "cd <log_dir> && zeek -r <pcap>"

    The --cd flag is unreliable on some WSL versions and may silently fail,
    causing Zeek to write logs to the WSL home directory (~/) instead of
    our zeek_logs/ folder — resulting in zero alerts every time.

    Returns
    -------
    dict with keys: status ('success' | 'error'), message, [stderr], [log_directory]
    """

    if not os.path.exists(pcap_path):
        return {"status": "error", "message": "PCAP file not found"}

    os.makedirs(ZEEK_LOG_DIR, exist_ok=True)

    # ── Clean old logs so we don't mix runs ──────────────────────────────────
    for f in os.listdir(ZEEK_LOG_DIR):
        fp = os.path.join(ZEEK_LOG_DIR, f)
        if os.path.isfile(fp):
            os.remove(fp)

    wsl_pcap    = windows_to_wsl_path(os.path.abspath(pcap_path))
    wsl_log_dir = windows_to_wsl_path(os.path.abspath(ZEEK_LOG_DIR))

    # ── Use bash -c "cd <log_dir> && zeek -r <pcap>" ─────────────────────────
    # This guarantees Zeek writes its logs into our zeek_logs/ directory.
    # Quoting: wrap paths in single quotes inside the bash -c string to handle
    # spaces and special characters in Windows paths.
    bash_cmd = f"cd '{wsl_log_dir}' && '{ZEEK_BINARY}' -r '{wsl_pcap}'"

    zeek_cmd = [
        "wsl", "-d", WSL_DISTRO,
        "bash", "-c", bash_cmd,
    ]

    print(f"[zeek_runner] WSL log dir : {wsl_log_dir}")
    print(f"[zeek_runner] WSL pcap    : {wsl_pcap}")
    print(f"[zeek_runner] Command     : {bash_cmd}")

    try:
        result = subprocess.run(
            zeek_cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        # ── Print stderr always — Zeek writes progress/warnings there ────────
        if result.stderr.strip():
            print(f"[zeek_runner] Zeek stderr:\n{result.stderr.strip()}")
        if result.stdout.strip():
            print(f"[zeek_runner] Zeek stdout:\n{result.stdout.strip()}")

        if result.returncode != 0:
            return {
                "status":  "error",
                "message": "Zeek execution failed",
                "stderr":  result.stderr.strip()
            }

        # ── Verify that Zeek actually wrote logs ──────────────────────────────
        logs_written = [
            f for f in os.listdir(ZEEK_LOG_DIR)
            if os.path.isfile(os.path.join(ZEEK_LOG_DIR, f))
        ]

        if not logs_written:
            return {
                "status":  "error",
                "message": (
                    "Zeek returned success but wrote NO log files. "
                    f"Expected logs in: {ZEEK_LOG_DIR}. "
                    "Check that the WSL path conversion is correct and "
                    "that Zeek has write permission to that directory."
                ),
                "wsl_log_dir": wsl_log_dir,
                "stderr":      result.stderr.strip()
            }

        print(f"[zeek_runner] Zeek wrote {len(logs_written)} log file(s): "
              f"{', '.join(sorted(logs_written))}")

        return {
            "status":        "success",
            "message":       "Zeek logs generated successfully",
            "log_directory": ZEEK_LOG_DIR,
            "logs_written":  sorted(logs_written),
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Zeek execution timed out (>180s)"}

    except FileNotFoundError:
        return {
            "status":  "error",
            "message": "WSL not found. Ensure WSL is installed and 'wsl' is on PATH."
        }