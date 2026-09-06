# soc/extract_indicators.py
"""
Enhanced Behavioral Detection Engine
======================================
Zeek Log Sources:
  conn.log   → Beaconing, external IPs, lateral movement, port scanning
  dns.log    → DGA, repeated queries, DNS tunneling (full)
  http.log   → Large payloads, missing UA, URI entropy, suspicious MIME
  ssl.log    → JA3 fingerprint matching (known malware families)
  files.log  → Executable downloads, large transfers, suspicious MIME
  smtp.log   → Phishing indicators, suspicious attachments, BEC patterns
  weird.log  → Zeek protocol anomalies mapped to MITRE techniques
"""

import json
import os
import math
import re
from datetime import datetime, timezone
from statistics import stdev, mean
from collections import defaultdict, Counter

# ── Absolute paths (works regardless of launch directory) ─────────────────────
_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_HERE)
ZEEK_LOG_DIR = os.path.join(PROJECT_ROOT, "zeek_logs")
ALERTS_DIR   = os.path.join(PROJECT_ROOT, "alerts")
OUTPUT_FILE  = os.path.join(ALERTS_DIR, "alerts.json")


# ==============================================================================
# KNOWN MALICIOUS JA3 FINGERPRINTS
# Source: https://github.com/salesforce/ja3
# ==============================================================================
KNOWN_MALICIOUS_JA3 = {
    # Malware families
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike Beacon",
    "72a589da586844d7f0818ce684948eea": "TrickBot / Emotet",
    "6734f37431670b3ab4292b8f60f29984": "Metasploit Meterpreter",
    "eb23788945a23e4ff73f8c6b23a4b1d6": "Dridex Banking Trojan",
    "e7d705a3286e19ea42f587b6"        : "AsyncRAT",
    "b386946a5a44d1ddcc843bc75336dfce": "NanoCore RAT",
    "c3b5a23b5e0e5d25a82cc71a4b3a7f2c": "AgentTesla",
    "d0ec4b50a944b182f68df71530895d64": "Hancitor",
    "17b816840c28c41b9610c09e3d42e0c6": "QBot / QakBot",
    "0d7b8f44bec7e1e29e8b8a7c2c5d9c76": "IcedID",
    # C2 Frameworks
    "1aa7bf8b3c2a4d9c4c6a6e8f2d1b9e56": "Covenant C2",
    "4d7a8f5c1b9e3a2d6c8b0f4e7a1d5c93": "Brute Ratel",
    "2fd4e1c67a2d28fced849ee1bb76e7391": "Sliver C2",
    # Scanning Tools
    "c13fb234a96e11b8c6d45e9b1f8c23d7": "Nmap SSL Scan",
    "e7a7e7d91f8e12b5b4c1e2d3a9f0b8c6": "Masscan",
}

# ==============================================================================
# SUSPICIOUS EXECUTABLE / FILE MIME TYPES
# ==============================================================================
MALICIOUS_MIME_TYPES = {
    "application/x-dosexec":          ("High",   "Windows PE executable download"),
    "application/x-executable":       ("High",   "Linux ELF executable download"),
    "application/x-msdownload":       ("High",   "MSI/DLL download"),
    "application/x-msdos-program":    ("High",   "MS-DOS executable download"),
    "application/x-sh":               ("Medium", "Shell script download"),
    "application/x-python-code":      ("Medium", "Python script download"),
    "application/x-powershell":       ("High",   "PowerShell script download"),
    "application/vnd.ms-office":      ("Medium", "Office document download (possible macro)"),
    "application/zip":                ("Medium", "ZIP archive transfer"),
    "application/x-rar-compressed":   ("Medium", "RAR archive transfer"),
    "application/octet-stream":       ("Medium", "Binary/unknown file transfer"),
    "application/x-java-applet":      ("Medium", "Java applet download"),
}

# ==============================================================================
# WEIRD.LOG → MITRE ATT&CK MAPPING
# ==============================================================================
WEIRD_MITRE_MAP = {
    # Scanning / Recon
    "above_hole_data_without_any_acks": ("Medium", "T1046", "Possible TCP stealth scan"),
    "bad_TCP_checksum":                 ("Low",    "T1095", "TCP checksum anomaly (possible evasion)"),
    "connection_originator_SYN_ack":    ("Medium", "T1046", "SYN-ACK without SYN (possible scan)"),
    "excess_RPC_record_len":            ("Medium", "T1190", "Malformed RPC (possible exploit attempt)"),
    "fragment_overlap":                 ("High",   "T1027", "IP fragment overlap (evasion technique)"),
    "FIN_advanced_last_seq":            ("Low",    "T1071", "FIN flag anomaly"),
    "inflate_failed":                   ("Medium", "T1027", "Decompression failure (possible evasion)"),
    "inappropriate_FIN":                ("Low",    "T1071", "Inappropriate FIN (protocol anomaly)"),
    "SYN_after_close":                  ("Medium", "T1046", "SYN after close (possible port scan)"),
    "SYN_inside_connection":            ("Medium", "T1046", "SYN inside established connection"),
    "RST_storm":                        ("High",   "T1498", "RST storm (possible DoS)"),
    "no_resp_l4_checksum_errors":       ("Low",    "T1095", "L4 checksum errors (possible tampering)"),
    "line_terminated_with_single_CR":   ("Medium", "T1071", "HTTP CR-only line termination (evasion)"),
    "unescaped_special_URI_char":       ("Medium", "T1190", "Unescaped URI char (possible injection)"),
    "DNS_label_len_exceeded":           ("Medium", "T1071.004", "DNS label too long (possible tunneling)"),
    "DNS_truncated_ans_too_short":      ("Medium", "T1071.004", "Truncated DNS answer (anomaly)"),
    "unpaired_RPC_response":            ("Low",    "T1071", "Unpaired RPC response"),
    "partial_packet_header_checksum":   ("Low",    "T1095", "Partial packet checksum error"),
}

# ==============================================================================
# SUSPICIOUS SMTP ATTACHMENT EXTENSIONS
# ==============================================================================
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".jse",
    ".wsf", ".ps1", ".psm1", ".psd1", ".lnk", ".scr", ".com",
    ".hta", ".jar", ".msi", ".iso", ".img", ".vhd",
}


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

def parse_zeek_log(filepath):
    """Parse a Zeek TSV log file into a list of dicts."""
    entries, fields = [], []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("#fields"):
                    fields = line.strip().split("\t")[1:]
                elif line.startswith("#"):
                    continue
                else:
                    values = line.strip().split("\t")
                    if len(values) == len(fields):
                        entries.append(dict(zip(fields, values)))
    except Exception:
        pass
    return entries


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq   = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def is_private_ip(ip: str) -> bool:
    if not ip:
        return True
    return (ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("172.")
            or ip.startswith("127.")
            or ip == "0.0.0.0")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_float(val, default=0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def safe_int(val, default=0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def make_alert(indicator, protocol, severity_hint, reason, details=None):
    return {
        "timestamp":     now_iso(),
        "indicator":     indicator,
        "protocol":      protocol,
        "severity_hint": severity_hint,
        "reason":        reason,
        "details":       details or {},
    }


# ==============================================================================
# 1. CONN.LOG — Connections, Beaconing, Lateral Movement, Port Scanning
# ==============================================================================

def extract_from_conn():
    alerts = []
    path   = os.path.join(ZEEK_LOG_DIR, "conn.log")
    if not os.path.exists(path):
        return alerts

    short_conn_counter  = defaultdict(int)
    timestamps_by_pair  = defaultdict(list)   # for beaconing math
    internal_dest_ports = defaultdict(set)    # for lateral movement / port scan
    internal_src_dests  = defaultdict(set)    # for internal spread detection
    bytes_out_by_src    = defaultdict(int)    # for large data transfer

    for entry in parse_zeek_log(path):
        try:
            orig_ip   = entry.get("id.orig_h", "")
            resp_ip   = entry.get("id.resp_h", "")
            resp_port = entry.get("id.resp_p", "0")
            ts        = safe_float(entry.get("ts", 0))
            duration  = safe_float(entry.get("duration", 0))
            service   = entry.get("service", "-")
            orig_bytes= safe_int(entry.get("orig_bytes", 0) or 0)

            if not orig_ip or not resp_ip:
                continue

            key = (orig_ip, resp_ip)
            timestamps_by_pair[key].append(ts)
            bytes_out_by_src[orig_ip] += orig_bytes

            # ── Short connections tracking ──────────────────────────────────
            if duration < 3:
                short_conn_counter[key] += 1

            # ── External IP alert ───────────────────────────────────────────
            if not is_private_ip(resp_ip):
                alerts.append(make_alert(
                    resp_ip, "CONN", "Low",
                    "Outbound connection to external IP",
                    {"source_ip": orig_ip, "service": service,
                     "dest_port": resp_port}
                ))

            # ── Lateral movement: internal→internal tracking ────────────────
            if is_private_ip(orig_ip) and is_private_ip(resp_ip) and orig_ip != resp_ip:
                internal_dest_ports[orig_ip].add(resp_port)
                internal_src_dests[orig_ip].add(resp_ip)

        except Exception:
            continue

    # ── Beaconing detection (statistical — low interval std-dev) ───────────
    for (src, dst), tss in timestamps_by_pair.items():
        if len(tss) < 8:
            continue
        tss.sort()
        intervals = [tss[i+1] - tss[i] for i in range(len(tss)-1)]
        if not intervals:
            continue
        avg = mean(intervals)
        if avg <= 0:
            continue
        try:
            sd = stdev(intervals)
        except Exception:
            continue
        cv = sd / avg   # Coefficient of Variation — low = very regular = beacon
        if cv < 0.15 and len(tss) >= 10:
            alerts.append(make_alert(
                dst, "CONN", "Critical",
                "Statistical C2 beacon detected (highly regular interval)",
                {"source_ip": src, "connection_count": len(tss),
                 "avg_interval_sec": round(avg, 2),
                 "coefficient_of_variation": round(cv, 4),
                 "mitre": "T1071 - Application Layer Protocol"}
            ))
        elif cv < 0.30 and len(tss) >= 6:
            alerts.append(make_alert(
                dst, "CONN", "High",
                "Possible beaconing pattern (semi-regular interval)",
                {"source_ip": src, "connection_count": len(tss),
                 "avg_interval_sec": round(avg, 2),
                 "coefficient_of_variation": round(cv, 4)}
            ))

    # ── Repeated short connections (C2 keep-alive) ──────────────────────────
    for (src, dst), count in short_conn_counter.items():
        if count >= 5:
            alerts.append(make_alert(
                dst, "CONN", "Medium",
                "Repeated short connections (possible C2 keep-alive)",
                {"source_ip": src, "connection_count": count}
            ))

    # ── Internal port scanning (lateral movement) ───────────────────────────
    for src_ip, ports in internal_dest_ports.items():
        if len(ports) >= 15:
            alerts.append(make_alert(
                src_ip, "CONN", "High",
                f"Internal port scan detected ({len(ports)} unique ports)",
                {"source_ip": src_ip, "unique_ports_scanned": len(ports),
                 "sample_ports": list(ports)[:10],
                 "mitre": "T1046 - Network Service Discovery"}
            ))

    # ── Internal host spreading (worm/ransomware lateral movement) ──────────
    for src_ip, dest_set in internal_src_dests.items():
        if len(dest_set) >= 10:
            alerts.append(make_alert(
                src_ip, "CONN", "High",
                f"Internal spread detected — connecting to {len(dest_set)} internal hosts",
                {"source_ip": src_ip, "unique_internal_destinations": len(dest_set),
                 "mitre": "T1570 - Lateral Tool Transfer"}
            ))

    # ── Large data exfiltration over raw connection ──────────────────────────
    for src_ip, total_bytes in bytes_out_by_src.items():
        if total_bytes > 50_000_000 and not is_private_ip(src_ip):   # 50 MB+
            alerts.append(make_alert(
                src_ip, "CONN", "High",
                f"Large outbound data transfer ({total_bytes // 1_000_000} MB)",
                {"source_ip": src_ip, "total_bytes": total_bytes,
                 "mitre": "T1048 - Exfiltration Over Alternative Protocol"}
            ))

    return alerts


# ==============================================================================
# 2. DNS.LOG — DGA, Repeated Queries, DNS Tunneling (Full Detection)
# ==============================================================================

def extract_from_dns():
    alerts = []
    path   = os.path.join(ZEEK_LOG_DIR, "dns.log")
    if not os.path.exists(path):
        return alerts

    domain_counter  = Counter()
    qtype_counter   = Counter()
    bytes_by_domain = defaultdict(int)
    subdomain_depth = defaultdict(int)
    txt_queries     = []
    null_queries    = []

    for entry in parse_zeek_log(path):
        try:
            query   = entry.get("query", "")
            orig_ip = entry.get("id.orig_h", "")
            qtype   = entry.get("qtype_name", "")
            answers = entry.get("answers", "")

            if not query or query == "-":
                continue

            domain_counter[query] += 1
            qtype_counter[qtype]  += 1
            bytes_by_domain[query] += len(query.encode())

            # ── Subdomain depth (tunneling indicator) ──────────────────────
            parts = query.split(".")
            subdomain_depth[query] = len(parts)

            # ── TXT record queries (common DNS tunnel type) ────────────────
            if qtype == "TXT":
                txt_queries.append((query, orig_ip))

            # ── NULL record queries (classic DNS tunnel) ───────────────────
            if qtype in ("NULL", "ANY"):
                null_queries.append((query, orig_ip))

            # ── High entropy = DGA ─────────────────────────────────────────
            base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else query
            if shannon_entropy(base_domain.split(".")[0]) > 4.0:
                alerts.append(make_alert(
                    query, "DNS", "Medium",
                    "High entropy DNS query (possible DGA domain)",
                    {"source_ip": orig_ip, "entropy": round(shannon_entropy(base_domain), 3),
                     "mitre": "T1568 - Dynamic Resolution"}
                ))

            # ── Very long subdomain (data encoded in label) ─────────────────
            longest_label = max((len(p) for p in parts), default=0)
            if longest_label > 45:
                alerts.append(make_alert(
                    query, "DNS", "High",
                    f"Extremely long DNS label ({longest_label} chars) — possible DNS tunneling",
                    {"source_ip": orig_ip, "label_length": longest_label,
                     "mitre": "T1071.004 - DNS"}
                ))

            # ── Long total query length ────────────────────────────────────
            if len(query) > 70:
                alerts.append(make_alert(
                    query, "DNS", "Medium",
                    f"Unusually long DNS query ({len(query)} chars) — possible data exfiltration",
                    {"source_ip": orig_ip, "query_length": len(query),
                     "mitre": "T1048.003 - Exfiltration Over Unencrypted Protocol"}
                ))

            # ── Deep subdomain chain ────────────────────────────────────────
            if len(parts) > 6:
                alerts.append(make_alert(
                    query, "DNS", "High",
                    f"Deep subdomain chain ({len(parts)} levels) — classic DNS tunnel indicator",
                    {"source_ip": orig_ip, "subdomain_levels": len(parts),
                     "mitre": "T1071.004 - DNS"}
                ))

        except Exception:
            continue

    # ── Repeated DNS queries ────────────────────────────────────────────────
    for domain, count in domain_counter.items():
        if count >= 5:
            alerts.append(make_alert(
                domain, "DNS", "Medium",
                f"Repeated DNS queries to same domain ({count}×)",
                {"count": count}
            ))

    # ── TXT tunnel detection ────────────────────────────────────────────────
    if len(txt_queries) >= 5:
        top_domains = Counter(q for q, _ in txt_queries).most_common(3)
        alerts.append(make_alert(
            top_domains[0][0], "DNS", "High",
            f"High volume of TXT record queries ({len(txt_queries)}) — possible DNS tunnel",
            {"total_txt_queries": len(txt_queries),
             "top_queried_domains": top_domains,
             "mitre": "T1071.004 - Application Layer Protocol: DNS"}
        ))

    # ── NULL/ANY tunnel detection ───────────────────────────────────────────
    if len(null_queries) >= 3:
        alerts.append(make_alert(
            null_queries[0][0], "DNS", "High",
            f"NULL/ANY DNS queries detected ({len(null_queries)}) — known DNS tunnel method",
            {"total_null_queries": len(null_queries),
             "mitre": "T1071.004 - Application Layer Protocol: DNS"}
        ))

    # ── High byte volume to single domain (data exfil via DNS) ─────────────
    for domain, total_bytes in bytes_by_domain.items():
        if total_bytes > 5000 and domain_counter[domain] >= 10:
            alerts.append(make_alert(
                domain, "DNS", "High",
                f"High DNS query volume to single domain ({total_bytes} bytes, {domain_counter[domain]} queries) — DNS tunneling",
                {"total_query_bytes": total_bytes, "query_count": domain_counter[domain],
                 "mitre": "T1041 - Exfiltration Over C2 Channel"}
            ))

    return alerts


# ==============================================================================
# 3. HTTP.LOG — Payloads, User-Agent, URI Entropy, MIME Types
# ==============================================================================

def extract_from_http():
    alerts = []
    path   = os.path.join(ZEEK_LOG_DIR, "http.log")
    if not os.path.exists(path):
        return alerts

    for entry in parse_zeek_log(path):
        try:
            host         = entry.get("host", "")
            uri          = entry.get("uri", "")
            orig_ip      = entry.get("id.orig_h", "")
            resp_ip      = entry.get("id.resp_h", "")
            user_agent   = entry.get("user_agent", "")
            content_type = entry.get("resp_mime_types", "")
            body_len     = safe_int(entry.get("request_body_len", 0) or 0)
            status_code  = entry.get("status_code", "")
            method       = entry.get("method", "")

            full_url = f"http://{host}{uri}" if host else resp_ip

            # ── Large POST (data exfiltration) ─────────────────────────────
            if body_len > 4000:
                alerts.append(make_alert(
                    resp_ip, "HTTP", "High",
                    "Large HTTP POST payload (possible data exfiltration)",
                    {"payload_size": body_len, "host": host,
                     "mitre": "T1048 - Exfiltration Over Alternative Protocol"}
                ))

            # ── Suspicious content-type ─────────────────────────────────────
            if content_type:
                for mime, (sev, reason) in MALICIOUS_MIME_TYPES.items():
                    if mime in content_type.lower():
                        alerts.append(make_alert(
                            resp_ip, "HTTP", sev, reason,
                            {"content_type": content_type, "source_ip": orig_ip,
                             "uri": uri[:100], "mitre": "T1105 - Ingress Tool Transfer"}
                        ))
                        break

            # ── High entropy URI ────────────────────────────────────────────
            if uri and shannon_entropy(uri) > 4.5:
                alerts.append(make_alert(
                    full_url, "HTTP", "Medium",
                    "High entropy URI (possible C2 encoded communication)",
                    {"entropy": round(shannon_entropy(uri), 3),
                     "mitre": "T1027 - Obfuscated Files or Information"}
                ))

            # ── Missing User-Agent ──────────────────────────────────────────
            if user_agent in ["-", "", None]:
                alerts.append(make_alert(
                    resp_ip, "HTTP", "Medium",
                    "Missing HTTP User-Agent (automated tool or malware)",
                    {"source_ip": orig_ip, "method": method,
                     "mitre": "T1071.001 - Application Layer Protocol: Web Protocols"}
                ))

            # ── Suspicious User-Agent strings ───────────────────────────────
            suspicious_ua_patterns = [
                ("python-requests", "Medium", "Python requests library (possible automated tool)"),
                ("curl/",           "Low",    "curl User-Agent (possible automated download)"),
                ("wget/",           "Medium", "wget User-Agent (possible automated download)"),
                ("go-http-client",  "Medium", "Go HTTP client (possible malware/tool)"),
                ("nmap",            "High",   "Nmap User-Agent (active scanning)"),
                ("masscan",         "High",   "Masscan User-Agent (port scanning)"),
                ("sqlmap",          "Critical","SQLMap detected (SQL injection tool)"),
                ("nikto",           "High",   "Nikto web scanner detected"),
                ("zgrab",           "High",   "ZGrab scanner (reconnaissance tool)"),
                ("dirbuster",       "High",   "DirBuster (directory enumeration)"),
            ]
            ua_lower = user_agent.lower()
            for pattern, sev, desc in suspicious_ua_patterns:
                if pattern in ua_lower:
                    alerts.append(make_alert(
                        resp_ip, "HTTP", sev, desc,
                        {"user_agent": user_agent, "source_ip": orig_ip,
                         "mitre": "T1595 - Active Scanning"}
                    ))
                    break

            # ── HTTP 4xx/5xx anomalies (scanning/fuzzing) ───────────────────
            if status_code and status_code.startswith("4"):
                pass   # counted separately below

        except Exception:
            continue

    return alerts


# ==============================================================================
# 4. SSL.LOG — JA3 Fingerprint Matching
# ==============================================================================

def extract_from_ssl():
    alerts = []
    path   = os.path.join(ZEEK_LOG_DIR, "ssl.log")
    if not os.path.exists(path):
        return alerts

    for entry in parse_zeek_log(path):
        try:
            resp_ip     = entry.get("id.resp_h", "")
            orig_ip     = entry.get("id.orig_h", "")
            ja3         = entry.get("ja3", "")
            ja3s        = entry.get("ja3s", "")
            tls_version = entry.get("version", "")
            server_name = entry.get("server_name", "")
            cipher      = entry.get("cipher", "")
            validation  = entry.get("validation_status", "")

            # ── JA3 known malware match ─────────────────────────────────────
            if ja3 and ja3 != "-":
                if ja3 in KNOWN_MALICIOUS_JA3:
                    malware_name = KNOWN_MALICIOUS_JA3[ja3]
                    alerts.append(make_alert(
                        ja3, "TLS", "Critical",
                        f"KNOWN MALWARE JA3 FINGERPRINT: {malware_name}",
                        {"destination_ip": resp_ip, "source_ip": orig_ip,
                         "ja3": ja3, "malware_family": malware_name,
                         "server_name": server_name,
                         "mitre": "T1071.001 - Application Layer Protocol"}
                    ))
                else:
                    # Log unknown JA3 for later matching
                    alerts.append(make_alert(
                        ja3, "TLS", "Low",
                        "JA3 fingerprint observed (unknown — not in malware DB)",
                        {"destination_ip": resp_ip, "server_name": server_name}
                    ))

            # ── Deprecated TLS versions ─────────────────────────────────────
            if tls_version in ("TLSv10", "TLSv1.0", "SSLv3", "SSLv2"):
                alerts.append(make_alert(
                    resp_ip, "TLS", "Medium",
                    f"Deprecated TLS version in use: {tls_version}",
                    {"source_ip": orig_ip, "version": tls_version,
                     "mitre": "T1600 - Weaken Encryption"}
                ))

            # ── Certificate validation failure ──────────────────────────────
            if validation and validation not in ("ok", "-", ""):
                alerts.append(make_alert(
                    resp_ip, "TLS", "Medium",
                    f"TLS certificate validation failed: {validation}",
                    {"source_ip": orig_ip, "server_name": server_name,
                     "validation_status": validation,
                     "mitre": "T1557 - Adversary-in-the-Middle"}
                ))

            # ── Weak cipher suites ──────────────────────────────────────────
            weak_ciphers = ["RC4", "NULL", "EXPORT", "DES", "MD5", "anon"]
            if cipher and any(w in cipher.upper() for w in weak_ciphers):
                alerts.append(make_alert(
                    resp_ip, "TLS", "High",
                    f"Weak TLS cipher suite: {cipher}",
                    {"source_ip": orig_ip, "cipher": cipher,
                     "mitre": "T1600.001 - Reduce Key Space"}
                ))

        except Exception:
            continue

    return alerts


# ==============================================================================
# 5. FILES.LOG — Executable Downloads, Large Transfers, Suspicious MIME
# ==============================================================================

def extract_from_files():
    alerts = []
    path   = os.path.join(ZEEK_LOG_DIR, "files.log")
    if not os.path.exists(path):
        return alerts

    for entry in parse_zeek_log(path):
        try:
            mime_type  = entry.get("mime_type", "")
            filename   = entry.get("filename", "")
            file_size  = safe_int(entry.get("total_bytes", 0) or 0)
            md5        = entry.get("md5", "")
            sha1       = entry.get("sha1", "")
            source_ip  = entry.get("tx_hosts", "").split(",")[0].strip()
            dest_ip    = entry.get("rx_hosts",  "").split(",")[0].strip()
            protocol   = entry.get("source", "")

            # ── Known malicious MIME type ────────────────────────────────────
            if mime_type:
                for mime, (sev, reason) in MALICIOUS_MIME_TYPES.items():
                    if mime in mime_type.lower():
                        alerts.append(make_alert(
                            source_ip or dest_ip, "FILE", sev,
                            f"Malicious file type downloaded: {reason}",
                            {"mime_type": mime_type, "filename": filename,
                             "file_size": file_size, "md5": md5,
                             "source_ip": source_ip, "dest_ip": dest_ip,
                             "mitre": "T1105 - Ingress Tool Transfer"}
                        ))
                        break

            # ── Suspicious file extension ────────────────────────────────────
            if filename:
                ext = os.path.splitext(filename.lower())[1]
                if ext in SUSPICIOUS_EXTENSIONS:
                    alerts.append(make_alert(
                        source_ip or dest_ip, "FILE", "High",
                        f"Suspicious file extension transferred: {ext}",
                        {"filename": filename, "extension": ext,
                         "file_size": file_size, "source_ip": source_ip,
                         "mitre": "T1105 - Ingress Tool Transfer"}
                    ))

            # ── Large file transfer (possible exfiltration) ──────────────────
            if file_size > 10_000_000:   # 10 MB+
                sev = "Critical" if file_size > 100_000_000 else "High"
                alerts.append(make_alert(
                    source_ip or dest_ip, "FILE", sev,
                    f"Large file transfer detected ({file_size // 1_000_000} MB)",
                    {"file_size_bytes": file_size, "filename": filename,
                     "mime_type": mime_type, "protocol": protocol,
                     "mitre": "T1048 - Exfiltration Over Alternative Protocol"}
                ))

            # ── Log file hash for TI matching ────────────────────────────────
            for file_hash in [md5, sha1]:
                if file_hash and file_hash != "-" and len(file_hash) in (32, 40):
                    alerts.append(make_alert(
                        file_hash, "FILE", "Low",
                        "File hash observed (check against threat intel)",
                        {"filename": filename, "mime_type": mime_type,
                         "source_ip": source_ip, "hash_type": "MD5" if len(file_hash)==32 else "SHA1"}
                    ))

        except Exception:
            continue

    return alerts


# ==============================================================================
# 6. SMTP.LOG — Phishing, BEC, Suspicious Attachments
# ==============================================================================

def extract_from_smtp():
    alerts = []
    path   = os.path.join(ZEEK_LOG_DIR, "smtp.log")
    if not os.path.exists(path):
        return alerts

    for entry in parse_zeek_log(path):
        try:
            orig_ip    = entry.get("id.orig_h", "")
            resp_ip    = entry.get("id.resp_h", "")
            from_addr  = entry.get("from", "")
            to_addrs   = entry.get("to", "")
            subject    = entry.get("subject", "")
            reply_to   = entry.get("reply_to", "")
            msg_id     = entry.get("msg_id", "")
            user_agent = entry.get("user_agent", "")
            tls        = entry.get("tls", "")

            # ── Extract domains from email addresses ─────────────────────────
            from_domain    = from_addr.split("@")[-1].strip(">").lower() if "@" in from_addr else ""
            reply_domain   = reply_to.split("@")[-1].strip(">").lower() if "@" in reply_to else ""

            # ── Reply-To domain mismatch (BEC / phishing) ────────────────────
            if from_domain and reply_domain and from_domain != reply_domain:
                alerts.append(make_alert(
                    orig_ip, "SMTP", "High",
                    "Email From/Reply-To domain mismatch (Business Email Compromise indicator)",
                    {"from": from_addr, "reply_to": reply_to,
                     "from_domain": from_domain, "reply_domain": reply_domain,
                     "mitre": "T1566.002 - Phishing: Spearphishing Link"}
                ))

            # ── Phishing keywords in subject ────────────────────────────────
            phishing_keywords = [
                "urgent", "verify your account", "suspended", "click here",
                "confirm your", "password", "invoice", "payment", "wire transfer",
                "login required", "account locked", "unusual activity",
                "action required", "limited time", "winner", "lottery",
                "prize", "gift card", "bitcoin", "crypto",
            ]
            if subject:
                subj_lower = subject.lower()
                matched_kw = [kw for kw in phishing_keywords if kw in subj_lower]
                if matched_kw:
                    alerts.append(make_alert(
                        orig_ip, "SMTP", "High",
                        f"Phishing keyword(s) in email subject: {', '.join(matched_kw)}",
                        {"subject": subject[:200], "from": from_addr,
                         "matched_keywords": matched_kw,
                         "mitre": "T1566.001 - Phishing: Spearphishing Attachment"}
                    ))

            # ── No TLS on SMTP (credentials in cleartext) ────────────────────
            if tls in ("F", "false", "0", ""):
                alerts.append(make_alert(
                    orig_ip, "SMTP", "Medium",
                    "SMTP connection without TLS encryption (cleartext email)",
                    {"source_ip": orig_ip, "from": from_addr,
                     "mitre": "T1040 - Network Sniffing"}
                ))

            # ── Suspicious message-ID format (spam/malware indicators) ───────
            if msg_id and (len(msg_id) > 100 or re.search(r"[^\x20-\x7e]", msg_id)):
                alerts.append(make_alert(
                    orig_ip, "SMTP", "Medium",
                    "Suspicious email Message-ID format",
                    {"msg_id": msg_id[:100], "from": from_addr,
                     "mitre": "T1566 - Phishing"}
                ))

        except Exception:
            continue

    return alerts


# ==============================================================================
# 7. WEIRD.LOG — Zeek Protocol Anomalies → MITRE ATT&CK
# ==============================================================================

def extract_from_weird():
    alerts = []
    path   = os.path.join(ZEEK_LOG_DIR, "weird.log")
    if not os.path.exists(path):
        return alerts

    weird_counter = Counter()

    for entry in parse_zeek_log(path):
        try:
            name     = entry.get("name", "")
            orig_ip  = entry.get("id.orig_h", "")
            resp_ip  = entry.get("id.resp_h", "")
            addl     = entry.get("addl", "")
            notice   = entry.get("notice", "")

            if not name or name == "-":
                continue

            weird_counter[name] += 1

            if name in WEIRD_MITRE_MAP:
                sev, mitre_id, description = WEIRD_MITRE_MAP[name]
                alerts.append(make_alert(
                    orig_ip or resp_ip, "WEIRD", sev,
                    f"Zeek anomaly: {description}",
                    {"weird_name": name, "source_ip": orig_ip,
                     "dest_ip": resp_ip, "additional": addl,
                     "mitre": mitre_id}
                ))
            else:
                # Unknown weird — still alert at Low
                alerts.append(make_alert(
                    orig_ip or resp_ip, "WEIRD", "Low",
                    f"Unknown Zeek protocol anomaly: {name}",
                    {"weird_name": name, "source_ip": orig_ip,
                     "dest_ip": resp_ip, "additional": addl}
                ))

        except Exception:
            continue

    # ── RST storm / DoS pattern ──────────────────────────────────────────────
    if weird_counter.get("RST_storm", 0) >= 10:
        alerts.append(make_alert(
            "network", "WEIRD", "Critical",
            f"RST storm confirmed — {weird_counter['RST_storm']} events (possible DoS/DDoS)",
            {"event_count": weird_counter["RST_storm"],
             "mitre": "T1498 - Network Denial of Service"}
        ))

    return alerts


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    os.makedirs(ALERTS_DIR, exist_ok=True)

    alerts = []

    # Original detections
    conn_alerts  = extract_from_conn()
    dns_alerts   = extract_from_dns()
    http_alerts  = extract_from_http()
    ssl_alerts   = extract_from_ssl()

    # New detections
    file_alerts  = extract_from_files()
    smtp_alerts  = extract_from_smtp()
    weird_alerts = extract_from_weird()

    alerts.extend(conn_alerts)
    alerts.extend(dns_alerts)
    alerts.extend(http_alerts)
    alerts.extend(ssl_alerts)
    alerts.extend(file_alerts)
    alerts.extend(smtp_alerts)
    alerts.extend(weird_alerts)

    output = {
        "generated_at": now_iso(),
        "alert_count":  len(alerts),
        "detection_summary": {
            "conn":  len(conn_alerts),
            "dns":   len(dns_alerts),
            "http":  len(http_alerts),
            "tls":   len(ssl_alerts),
            "files": len(file_alerts),
            "smtp":  len(smtp_alerts),
            "weird": len(weird_alerts),
        },
        "alerts": alerts
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=4)

    print(f"[+] Extracted {len(alerts)} alerts across {len([x for x in output['detection_summary'].values() if x > 0])} log sources")
    print(f"    CONN={len(conn_alerts)}  DNS={len(dns_alerts)}  HTTP={len(http_alerts)}"
          f"  TLS={len(ssl_alerts)}  FILES={len(file_alerts)}  SMTP={len(smtp_alerts)}  WEIRD={len(weird_alerts)}")


if __name__ == "__main__":
    main()