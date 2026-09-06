import { useState, useEffect, useRef } from "react";

// ─── MOCK DATA ────────────────────────────────────────────────────────────────
const MOCK_SOC_INCIDENTS = [
  { id: 1, protocol: "TLS", indicator: "2236a2c51e9a607e2e7f628e102b8263", risk: "Critical", score: 97, count: 16, mitre: "T1071.001", tactic: "C&C", reason: "Uncommon TLS fingerprint matched threat intel feed (confidence: High)", threat_verdict: "Malicious", vt: { malicious: 18, suspicious: 3 }, abuse: { confidence: 92 }, otx: { pulse_count: 9 }, first_seen: "2025-11-26T08:12:04", last_seen: "2025-11-26T14:33:11" },
  { id: 2, protocol: "TLS", indicator: "885b00c361007f8d9446b4b48a14", risk: "Critical", score: 94, count: 12, mitre: "T1071.001", tactic: "C&C", reason: "Legacy TLS client fingerprint – TLS fingerprint matched threat intel feed (confidence: High)", threat_verdict: "Malicious", vt: { malicious: 14, suspicious: 2 }, abuse: { confidence: 88 }, otx: { pulse_count: 7 }, first_seen: "2025-11-26T09:01:22", last_seen: "2025-11-26T15:44:09" },
  { id: 3, protocol: "TLS", indicator: "61f6c5269f8a19f9654d3b4dc6606f", risk: "High", score: 81, count: 12, mitre: "T1071.001", tactic: "C&C", reason: "TLS fingerprint matched threat intel feed (confidence: High)", threat_verdict: "Malicious", vt: { malicious: 9, suspicious: 1 }, abuse: { confidence: 76 }, otx: { pulse_count: 5 }, first_seen: "2025-11-26T07:55:44", last_seen: "2025-11-26T13:10:55" },
  { id: 4, protocol: "HTTP", indicator: "f8cMVe0TPM02wt02A-BgJX0jMC0gUAb8Ng", risk: "Medium", score: 55, count: 1, mitre: "N/A", tactic: "Unknown", reason: "Suspicious encoded or random-looking HTTP URI – Suspicious HTTP behavior", threat_verdict: "Unknown", vt: { malicious: 2, suspicious: 4 }, abuse: { confidence: 0 }, otx: { pulse_count: 1 }, first_seen: "2025-11-26T10:22:33", last_seen: "2025-11-26T10:22:33" },
  { id: 5, protocol: "HTTP", indicator: "focalbronx.asp", risk: "Medium", score: 52, count: 1, mitre: "T1071.001", tactic: "C&C", reason: "Missing HTTP User-Agent header – Suspicious HTTP behavior", threat_verdict: "Unknown", vt: { malicious: 3, suspicious: 2 }, abuse: { confidence: 15 }, otx: { pulse_count: 0 }, first_seen: "2025-11-26T11:05:14", last_seen: "2025-11-26T11:05:14" },
  { id: 6, protocol: "DNS", indicator: "_ldap._tcp.default-first-site-name._sites.dc._msc", risk: "Low", score: 18, count: 3, mitre: "T1041", tactic: "Exfiltration", reason: "Suspicious long DNS query detected (length>40) – Enterprise AD DNS traffic", threat_verdict: "Unknown", vt: { malicious: 0, suspicious: 0 }, abuse: { confidence: 0 }, otx: { pulse_count: 0 }, first_seen: "2025-11-26T08:00:11", last_seen: "2025-11-26T08:45:22" },
  { id: 7, protocol: "CONN", indicator: "194.160.191.64", risk: "Medium", score: 48, count: 1, mitre: "T1071", tactic: "C&C", reason: "Long duration connection (2909.7s, isolated long-lived connection)", threat_verdict: "Unknown", vt: { malicious: 1, suspicious: 0 }, abuse: { confidence: 22 }, otx: { pulse_count: 0 }, first_seen: "2025-11-26T06:14:09", last_seen: "2025-11-26T07:02:38" },
  { id: 8, protocol: "CONN", indicator: "20.7.2.167", risk: "Medium", score: 46, count: 1, mitre: "T1071", tactic: "C&C", reason: "Long duration connection (3164.7s, isolated long-lived connection)", threat_verdict: "Unknown", vt: { malicious: 0, suspicious: 1 }, abuse: { confidence: 10 }, otx: { pulse_count: 0 }, first_seen: "2025-11-26T06:20:44", last_seen: "2025-11-26T07:14:28" },
];

const MOCK_VAPT_RESULTS = {
  nmap: [
    { host: "192.168.1.1", port: 22, service: "SSH", version: "OpenSSH 7.4", state: "open", cve: "CVE-2018-15473", severity: "Medium", description: "OpenSSH Username Enumeration Vulnerability" },
    { host: "192.168.1.1", port: 80, service: "HTTP", version: "Apache 2.4.29", state: "open", cve: "CVE-2021-41773", severity: "Critical", description: "Apache HTTP Server Path Traversal & RCE" },
    { host: "192.168.1.1", port: 443, service: "HTTPS", version: "Apache 2.4.29", state: "open", cve: "CVE-2021-42013", severity: "Critical", description: "Apache HTTP Server RCE (mod_cgi)" },
    { host: "192.168.1.15", port: 3389, service: "RDP", version: "Microsoft RDP", state: "open", cve: "CVE-2019-0708", severity: "Critical", description: "BlueKeep – Remote Code Execution via RDP" },
    { host: "192.168.1.15", port: 445, service: "SMB", version: "Windows SMB", state: "open", cve: "CVE-2017-0144", severity: "Critical", description: "EternalBlue – SMB Remote Code Execution" },
    { host: "192.168.1.22", port: 3306, service: "MySQL", version: "MySQL 5.7.32", state: "open", cve: "CVE-2021-2307", severity: "High", description: "MySQL Unauthorized Access via weak auth" },
    { host: "192.168.1.22", port: 21, service: "FTP", version: "vsftpd 2.3.4", state: "open", cve: "CVE-2011-2523", severity: "Critical", description: "vsftpd 2.3.4 Backdoor Command Execution" },
  ],
  nuclei: [
    { template: "CVE-2021-44228", name: "Log4Shell", host: "192.168.1.1:8080", severity: "Critical", tags: ["rce", "log4j", "owasp"], matched: "http://192.168.1.1:8080/api/v1/endpoint", mitre: "T1190" },
    { template: "CVE-2022-22965", name: "Spring4Shell", host: "192.168.1.1:8080", severity: "Critical", tags: ["rce", "spring", "java"], matched: "http://192.168.1.1:8080/spring/classname", mitre: "T1190" },
    { template: "CVE-2021-41773", name: "Apache Path Traversal", host: "192.168.1.1:80", severity: "Critical", tags: ["lfi", "apache"], matched: "/cgi-bin/.%2e/.%2e/bin/sh", mitre: "T1083" },
    { template: "CVE-2020-14882", name: "Oracle WebLogic RCE", host: "192.168.1.33:7001", severity: "Critical", tags: ["rce", "weblogic"], matched: "/console/images/%252E%252E", mitre: "T1190" },
    { template: "CVE-2019-0708", name: "BlueKeep RDP", host: "192.168.1.15:3389", severity: "Critical", tags: ["rdp", "rce"], matched: "192.168.1.15:3389", mitre: "T1210" },
    { template: "default-credentials-ftp", name: "Default FTP Credentials", host: "192.168.1.22:21", severity: "High", tags: ["ftp", "default-login"], matched: "anonymous:anonymous", mitre: "T1078.001" },
    { template: "ssl-tls-version", name: "Deprecated TLS 1.0 Detected", host: "192.168.1.1:443", severity: "Medium", tags: ["tls", "ssl"], matched: "TLSv1.0", mitre: "T1600" },
  ],
  riskCorrelation: [
    { soc_alert: "TLS C2 Fingerprint (Critical)", vapt_finding: "Log4Shell RCE on 192.168.1.1:8080", combined_risk: "Critical", host: "192.168.1.1", action: "Immediate Isolation Required", score: 99 },
    { soc_alert: "Long-lived CONN to 194.160.191.64", vapt_finding: "BlueKeep RDP on 192.168.1.15", combined_risk: "Critical", host: "192.168.1.15", action: "Block Outbound + Patch RDP", score: 95 },
    { soc_alert: "Malicious TLS JA3 Hash", vapt_finding: "EternalBlue SMB on 192.168.1.15", combined_risk: "Critical", host: "192.168.1.15", action: "Emergency Patch Required", score: 97 },
    { soc_alert: "Suspicious HTTP URI", vapt_finding: "Apache Path Traversal on :80", combined_risk: "High", host: "192.168.1.1", action: "WAF Rule + Apache Patch", score: 78 },
    { soc_alert: "Missing User-Agent (HTTP)", vapt_finding: "Default FTP Credentials", combined_risk: "High", host: "192.168.1.22", action: "Credential Rotation Required", score: 72 },
  ]
};

const RISK_COLORS = { Critical: "#ff2d55", High: "#ff6b35", Medium: "#ffd60a", Low: "#30d158", Unknown: "#636366" };
const RISK_BG = { Critical: "rgba(255,45,85,0.15)", High: "rgba(255,107,53,0.15)", Medium: "rgba(255,214,10,0.15)", Low: "rgba(48,209,88,0.15)", Unknown: "rgba(99,99,102,0.15)" };

// ─── COMPONENTS ───────────────────────────────────────────────────────────────

function MatrixRain() {
  const canvasRef = useRef(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    const cols = Math.floor(canvas.width / 16);
    const drops = Array(cols).fill(1);
    const chars = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモ";
    const interval = setInterval(() => {
      ctx.fillStyle = "rgba(0,5,10,0.05)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "#00ff9d";
      ctx.font = "12px monospace";
      drops.forEach((y, i) => {
        const char = chars[Math.floor(Math.random() * chars.length)];
        ctx.fillStyle = i % 3 === 0 ? "#00ffcc" : "#006633";
        ctx.fillText(char, i * 16, y * 16);
        if (y * 16 > canvas.height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      });
    }, 50);
    return () => clearInterval(interval);
  }, []);
  return <canvas ref={canvasRef} style={{ position: "absolute", inset: 0, width: "100%", height: "100%", opacity: 0.15, pointerEvents: "none" }} />;
}

function GlowBadge({ label, color, bg }) {
  return (
    <span style={{
      display: "inline-block", padding: "2px 10px", borderRadius: 4,
      background: bg || "rgba(0,255,157,0.1)", color: color || "#00ff9d",
      border: `1px solid ${color || "#00ff9d"}`, fontSize: 11, fontFamily: "monospace",
      fontWeight: 700, letterSpacing: 1, textTransform: "uppercase",
      boxShadow: `0 0 8px ${color || "#00ff9d"}44`
    }}>{label}</span>
  );
}

function RiskBadge({ risk }) {
  const c = RISK_COLORS[risk] || "#636366";
  const bg = RISK_BG[risk] || "rgba(99,99,102,0.15)";
  return <GlowBadge label={risk} color={c} bg={bg} />;
}

function StatCard({ label, value, color, icon }) {
  return (
    <div style={{
      background: "rgba(0,20,35,0.85)", border: `1px solid ${color}44`,
      borderRadius: 8, padding: "16px 20px", position: "relative", overflow: "hidden",
      boxShadow: `0 0 20px ${color}22`
    }}>
      <div style={{ fontSize: 22, marginBottom: 4 }}>{icon}</div>
      <div style={{ color, fontSize: 28, fontWeight: 800, fontFamily: "monospace", lineHeight: 1 }}>{value}</div>
      <div style={{ color: "#8a9bb0", fontSize: 11, letterSpacing: 1, textTransform: "uppercase", marginTop: 4 }}>{label}</div>
      <div style={{ position: "absolute", right: -10, top: -10, width: 60, height: 60, borderRadius: "50%", background: `${color}11`, border: `1px solid ${color}22` }} />
    </div>
  );
}

function MiniBar({ value, max, color }) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div style={{ background: "rgba(255,255,255,0.05)", borderRadius: 2, height: 4, width: "100%", overflow: "hidden" }}>
      <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 2, transition: "width 0.6s ease", boxShadow: `0 0 6px ${color}` }} />
    </div>
  );
}

function ThreatScore({ score }) {
  const c = score >= 90 ? "#ff2d55" : score >= 70 ? "#ff6b35" : score >= 40 ? "#ffd60a" : "#30d158";
  const label = score >= 90 ? "CRITICAL" : score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{
        width: 36, height: 36, borderRadius: "50%", background: `${c}22`,
        border: `2px solid ${c}`, display: "flex", alignItems: "center", justifyContent: "center",
        fontFamily: "monospace", fontWeight: 800, fontSize: 12, color: c,
        boxShadow: `0 0 10px ${c}66`
      }}>{score}</div>
      <RiskBadge risk={label} />
    </div>
  );
}

// ─── PAGE: SOC MODULE ─────────────────────────────────────────────────────────

function SOCModule() {
  const [uploadState, setUploadState] = useState("idle"); // idle | uploading | processing | done
  const [progress, setProgress] = useState(0);
  const [stepIdx, setStepIdx] = useState(-1);
  const [filter, setFilter] = useState("All");
  const [search, setSearch] = useState("");
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [dragging, setDragging] = useState(false);

  const steps = [
    { label: "PCAP Validation & SHA-256 Hash", icon: "🔐" },
    { label: "Zeek Log Generation (WSL)", icon: "🔬" },
    { label: "Multi-Protocol Alert Extraction (NBAD/NABD Engine)", icon: "🕵️" },
    { label: "Behavioral Severity Tagging", icon: "🏷️" },
    { label: "Alert Deduplication & Correlation", icon: "🔗" },
    { label: "Local Feed Matching (IP/Domain/URL/Hash)", icon: "📋" },
    { label: "VirusTotal Enrichment (IPs + Domains)", icon: "🦠" },
    { label: "AlienVault OTX Enrichment (Domains)", icon: "👾" },
    { label: "AbuseIPDB Enrichment (IPs)", icon: "🚨" },
    { label: "TIP Scoring & Risk Fusion", icon: "⚡" },
    { label: "MITRE ATT&CK Mapping", icon: "🎯" },
  ];

  const simulate = () => {
    setUploadState("processing");
    setProgress(0);
    setStepIdx(0);
    let step = 0;
    const interval = setInterval(() => {
      step++;
      setStepIdx(step);
      setProgress(Math.round((step / steps.length) * 100));
      if (step >= steps.length) {
        clearInterval(interval);
        setTimeout(() => setUploadState("done"), 400);
      }
    }, 500);
  };

  const incidents = MOCK_SOC_INCIDENTS.filter(i => {
    if (filter !== "All" && i.risk !== filter) return false;
    if (search && !i.indicator.toLowerCase().includes(search.toLowerCase()) && !i.protocol.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const counts = { Critical: MOCK_SOC_INCIDENTS.filter(x=>x.risk==="Critical").length, High: MOCK_SOC_INCIDENTS.filter(x=>x.risk==="High").length, Medium: MOCK_SOC_INCIDENTS.filter(x=>x.risk==="Medium").length, Low: MOCK_SOC_INCIDENTS.filter(x=>x.risk==="Low").length };

  return (
    <div style={{ padding: "0 0 40px" }}>
      {/* Stats */}
      {uploadState === "done" && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 24 }}>
          <StatCard label="Critical" value={counts.Critical} color="#ff2d55" icon="🔴" />
          <StatCard label="High" value={counts.High} color="#ff6b35" icon="🟠" />
          <StatCard label="Medium" value={counts.Medium} color="#ffd60a" icon="🟡" />
          <StatCard label="Low" value={counts.Low} color="#30d158" icon="🟢" />
        </div>
      )}

      {/* Upload Zone */}
      {uploadState === "idle" && (
        <div
          onDragOver={e => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={e => { e.preventDefault(); setDragging(false); simulate(); }}
          style={{
            border: `2px dashed ${dragging ? "#00ff9d" : "#1a3a4a"}`,
            borderRadius: 12, padding: "60px 40px", textAlign: "center",
            background: dragging ? "rgba(0,255,157,0.05)" : "rgba(0,15,25,0.6)",
            cursor: "pointer", transition: "all 0.3s",
            boxShadow: dragging ? "0 0 30px rgba(0,255,157,0.2)" : "none"
          }}
          onClick={simulate}
        >
          <div style={{ fontSize: 48, marginBottom: 12 }}>📦</div>
          <div style={{ color: "#00ff9d", fontSize: 18, fontFamily: "monospace", fontWeight: 700 }}>DROP PCAP FILE HERE</div>
          <div style={{ color: "#8a9bb0", fontSize: 13, marginTop: 8 }}>Supports .pcap / .pcapng — Max 100MB</div>
          <div style={{ marginTop: 20, display: "inline-block", padding: "10px 28px", background: "rgba(0,255,157,0.1)", border: "1px solid #00ff9d", borderRadius: 6, color: "#00ff9d", fontFamily: "monospace", fontSize: 13, fontWeight: 700, letterSpacing: 1 }}>
            BROWSE FILES
          </div>
          <div style={{ marginTop: 16, color: "#4a6a7a", fontSize: 12 }}>or click to select a PCAP file for analysis</div>
        </div>
      )}

      {/* Processing */}
      {uploadState === "processing" && (
        <div style={{ background: "rgba(0,15,25,0.8)", border: "1px solid #0a3a4a", borderRadius: 12, padding: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
            <div style={{ color: "#00ff9d", fontFamily: "monospace", fontWeight: 700, fontSize: 14 }}>
              ⚡ ANALYZING PCAP — SOC PIPELINE
            </div>
            <div style={{ color: "#00ff9d", fontFamily: "monospace", fontSize: 14 }}>{progress}%</div>
          </div>
          <div style={{ background: "#0a1a22", borderRadius: 4, height: 6, marginBottom: 20, overflow: "hidden" }}>
            <div style={{ width: `${progress}%`, height: "100%", background: "linear-gradient(90deg,#00ff9d,#00ccff)", transition: "width 0.4s ease", boxShadow: "0 0 10px #00ff9d" }} />
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {steps.map((s, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, opacity: i <= stepIdx ? 1 : 0.3, transition: "opacity 0.3s" }}>
                <div style={{ width: 18, height: 18, borderRadius: "50%", background: i < stepIdx ? "#00ff9d" : i === stepIdx ? "#ffd60a" : "#1a3a4a", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, flexShrink: 0, transition: "background 0.3s" }}>
                  {i < stepIdx ? "✓" : i === stepIdx ? "⟳" : "○"}
                </div>
                <span style={{ fontSize: 9, color: i === stepIdx ? "#00ff9d" : i < stepIdx ? "#8a9bb0" : "#4a6a7a", fontFamily: "monospace", letterSpacing: 0.5 }}>{s.icon} {s.label}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Results */}
      {uploadState === "done" && (
        <>
          {/* NBAD/NABD Detection Badges */}
          <div style={{ background: "rgba(0,255,157,0.05)", border: "1px solid #00ff9d33", borderRadius: 8, padding: "10px 16px", marginBottom: 16, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <span style={{ color: "#8a9bb0", fontSize: 11, fontFamily: "monospace" }}>DETECTION ENGINE:</span>
            {["NBAD-11 C2 Beacon", "NBAD-14 DNS C2", "NBAD-16 DGA", "NBAD-13 HTTP C2", "NABD-44 Header Covert", "NABD-55 High Entropy Payload", "NBAD-147 Deprecated TLS"].map(t => (
              <span key={t} style={{ background: "rgba(0,204,255,0.1)", border: "1px solid #00ccff44", borderRadius: 3, padding: "2px 8px", fontSize: 10, color: "#00ccff", fontFamily: "monospace" }}>{t}</span>
            ))}
          </div>

          {/* Filters */}
          <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap", alignItems: "center" }}>
            {["All","Critical","High","Medium","Low"].map(f => (
              <button key={f} onClick={() => setFilter(f)} style={{
                padding: "5px 14px", borderRadius: 4, border: `1px solid ${filter===f ? RISK_COLORS[f]||"#00ff9d" : "#1a3a4a"}`,
                background: filter===f ? `${RISK_COLORS[f]||"#00ff9d"}22` : "transparent",
                color: filter===f ? RISK_COLORS[f]||"#00ff9d" : "#8a9bb0", cursor: "pointer",
                fontFamily: "monospace", fontSize: 11, fontWeight: 700, letterSpacing: 1,
                transition: "all 0.2s"
              }}>{f}</button>
            ))}
            <input
              placeholder="Search IP / Domain / Hash..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{ flex: 1, minWidth: 200, background: "rgba(0,15,25,0.6)", border: "1px solid #1a3a4a", borderRadius: 4, padding: "6px 12px", color: "#e0e8f0", fontFamily: "monospace", fontSize: 12, outline: "none" }}
            />
          </div>

          {/* Incidents Table */}
          <div style={{ background: "rgba(0,10,18,0.9)", border: "1px solid #0a2a35", borderRadius: 8, overflow: "hidden" }}>
            <div style={{ display: "grid", gridTemplateColumns: "80px 1fr 90px 60px 110px 110px 80px", gap: 0, background: "rgba(0,30,45,0.8)", padding: "8px 14px", borderBottom: "1px solid #0a2a35" }}>
              {["Protocol","Indicator","Risk","Count","MITRE","Verdict","TI Score"].map(h => (
                <div key={h} style={{ color: "#4a7a8a", fontSize: 10, fontFamily: "monospace", letterSpacing: 1, textTransform: "uppercase" }}>{h}</div>
              ))}
            </div>
            {incidents.map((inc) => (
              <div key={inc.id} onClick={() => setSelectedAlert(selectedAlert?.id === inc.id ? null : inc)}
                style={{ display: "grid", gridTemplateColumns: "80px 1fr 90px 60px 110px 110px 80px", gap: 0, padding: "10px 14px", borderBottom: "1px solid #081822", cursor: "pointer", background: selectedAlert?.id === inc.id ? "rgba(0,255,157,0.05)" : "transparent", transition: "background 0.2s" }}
              >
                <div style={{ color: "#00ccff", fontFamily: "monospace", fontSize: 11, fontWeight: 700 }}>{inc.protocol}</div>
                <div style={{ color: "#c0d8e8", fontFamily: "monospace", fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", paddingRight: 8 }} title={inc.indicator}>{inc.indicator}</div>
                <div><RiskBadge risk={inc.risk} /></div>
                <div style={{ color: "#8a9bb0", fontFamily: "monospace", fontSize: 12 }}>{inc.count}×</div>
                <div style={{ color: "#ffd60a", fontFamily: "monospace", fontSize: 10 }}>{inc.mitre}</div>
                <div>
                  <GlowBadge label={inc.threat_verdict} color={inc.threat_verdict === "Malicious" ? "#ff2d55" : "#636366"} bg={inc.threat_verdict === "Malicious" ? "rgba(255,45,85,0.15)" : "rgba(99,99,102,0.1)"} />
                </div>
                <div>
                  <ThreatScore score={inc.score} />
                </div>
              </div>
            ))}
          </div>

          {/* Alert Detail Panel */}
          {selectedAlert && (
            <div style={{ marginTop: 16, background: "rgba(0,15,25,0.95)", border: "1px solid #00ff9d33", borderRadius: 8, padding: 20 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
                <div>
                  <div style={{ color: "#00ff9d", fontFamily: "monospace", fontWeight: 800, fontSize: 14 }}>INCIDENT DETAIL</div>
                  <div style={{ color: "#8a9bb0", fontFamily: "monospace", fontSize: 11, marginTop: 2 }}>{selectedAlert.indicator}</div>
                </div>
                <RiskBadge risk={selectedAlert.risk} />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 16 }}>
                <div style={{ background: "rgba(0,30,45,0.8)", borderRadius: 6, padding: 12 }}>
                  <div style={{ color: "#4a7a8a", fontSize: 10, fontFamily: "monospace", letterSpacing: 1 }}>VIRUSTOTAL</div>
                  <div style={{ color: "#ff2d55", fontFamily: "monospace", fontWeight: 700, fontSize: 16, marginTop: 4 }}>{selectedAlert.vt.malicious} <span style={{ fontSize: 10, color: "#8a9bb0" }}>malicious</span></div>
                  <MiniBar value={selectedAlert.vt.malicious} max={20} color="#ff2d55" />
                </div>
                <div style={{ background: "rgba(0,30,45,0.8)", borderRadius: 6, padding: 12 }}>
                  <div style={{ color: "#4a7a8a", fontSize: 10, fontFamily: "monospace", letterSpacing: 1 }}>ABUSEIPDB</div>
                  <div style={{ color: "#ff6b35", fontFamily: "monospace", fontWeight: 700, fontSize: 16, marginTop: 4 }}>{selectedAlert.abuse.confidence}% <span style={{ fontSize: 10, color: "#8a9bb0" }}>confidence</span></div>
                  <MiniBar value={selectedAlert.abuse.confidence} max={100} color="#ff6b35" />
                </div>
                <div style={{ background: "rgba(0,30,45,0.8)", borderRadius: 6, padding: 12 }}>
                  <div style={{ color: "#4a7a8a", fontSize: 10, fontFamily: "monospace", letterSpacing: 1 }}>OTX PULSES</div>
                  <div style={{ color: "#ffd60a", fontFamily: "monospace", fontWeight: 700, fontSize: 16, marginTop: 4 }}>{selectedAlert.otx.pulse_count} <span style={{ fontSize: 10, color: "#8a9bb0" }}>matches</span></div>
                  <MiniBar value={selectedAlert.otx.pulse_count} max={15} color="#ffd60a" />
                </div>
              </div>
              <div style={{ background: "rgba(0,30,45,0.6)", borderRadius: 6, padding: 12 }}>
                <div style={{ color: "#4a7a8a", fontSize: 10, fontFamily: "monospace", letterSpacing: 1, marginBottom: 6 }}>DETECTION REASON</div>
                <div style={{ color: "#c0d8e8", fontSize: 12, fontFamily: "monospace" }}>{selectedAlert.reason}</div>
                <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <GlowBadge label={`MITRE: ${selectedAlert.mitre}`} color="#ffd60a" bg="rgba(255,214,10,0.1)" />
                  <GlowBadge label={`Tactic: ${selectedAlert.tactic}`} color="#00ccff" bg="rgba(0,204,255,0.1)" />
                  <GlowBadge label={`Count: ${selectedAlert.count}×`} color="#8a9bb0" bg="rgba(138,155,176,0.1)" />
                  <GlowBadge label={`Protocol: ${selectedAlert.protocol}`} color="#00ff9d" bg="rgba(0,255,157,0.1)" />
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ─── PAGE: VAPT MODULE ────────────────────────────────────────────────────────

function VAPTModule() {
  const [activeTab, setActiveTab] = useState("nmap");
  const [scanState, setScanState] = useState("idle");
  const [target, setTarget] = useState("192.168.1.0/24");
  const [progress, setProgress] = useState(0);
  const [stepLabel, setStepLabel] = useState("");

  const nmapSteps = ["Initializing Nmap scanner...", "Host discovery (ping sweep)...", "Port scanning (SYN scan)...", "Service/version detection...", "OS fingerprinting...", "NSE vulnerability scripts...", "CVE correlation lookup...", "Generating findings..."];
  const nucleiSteps = ["Loading CVE templates (7,200+)...", "HTTP probe on all open ports...", "Log4Shell detection (T1190)...", "Spring4Shell probe...", "Default credential checks...", "SSL/TLS version audit...", "Correlating with MITRE ATT&CK...", "Risk scoring complete..."];

  const runScan = (type) => {
    setScanState("scanning");
    setProgress(0);
    const steps = type === "nmap" ? nmapSteps : type === "nuclei" ? nucleiSteps : ["Importing SOC alerts...", "Extracting VAPT findings...", "Correlating by host IP...", "Calculating combined risk scores...", "Generating IR recommendations..."];
    let i = 0;
    const iv = setInterval(() => {
      setStepLabel(steps[i] || "");
      setProgress(Math.round(((i + 1) / steps.length) * 100));
      i++;
      if (i >= steps.length) { clearInterval(iv); setTimeout(() => setScanState("done"), 400); }
    }, 400);
  };

  const sevColors = { Critical: "#ff2d55", High: "#ff6b35", Medium: "#ffd60a", Low: "#30d158", Info: "#636366" };

  return (
    <div style={{ padding: "0 0 40px" }}>
      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 20, background: "rgba(0,10,18,0.6)", borderRadius: 8, padding: 4 }}>
        {[
          { key: "nmap", label: "🔍 NMAP VULN SCAN", desc: "Port + CVE Discovery" },
          { key: "nuclei", label: "☢️ NUCLEI CVE SCAN", desc: "Template-Based Probing" },
          { key: "correlation", label: "🔗 RISK CORRELATION", desc: "SOC × VAPT Fusion" },
        ].map(t => (
          <button key={t.key} onClick={() => { setActiveTab(t.key); setScanState("idle"); setProgress(0); }} style={{
            flex: 1, padding: "10px 8px", borderRadius: 6, cursor: "pointer",
            background: activeTab === t.key ? "rgba(0,255,157,0.1)" : "transparent",
            border: activeTab === t.key ? "1px solid #00ff9d44" : "1px solid transparent",
            color: activeTab === t.key ? "#00ff9d" : "#8a9bb0",
            fontFamily: "monospace", fontWeight: 700, fontSize: 11, letterSpacing: 0.5,
            transition: "all 0.2s", textAlign: "center"
          }}>
            <div>{t.label}</div>
            <div style={{ fontSize: 9, opacity: 0.7, marginTop: 2 }}>{t.desc}</div>
          </button>
        ))}
      </div>

      {/* Scan Controls */}
      {(activeTab === "nmap" || activeTab === "nuclei") && scanState === "idle" && (
        <div style={{ background: "rgba(0,15,25,0.8)", border: "1px solid #0a2a35", borderRadius: 8, padding: 20, marginBottom: 20 }}>
          <div style={{ display: "flex", gap: 10, marginBottom: 12, alignItems: "center" }}>
            <div style={{ color: "#4a7a8a", fontFamily: "monospace", fontSize: 11, letterSpacing: 1, whiteSpace: "nowrap" }}>TARGET:</div>
            <input value={target} onChange={e => setTarget(e.target.value)} style={{
              flex: 1, background: "rgba(0,5,10,0.8)", border: "1px solid #0a3a4a", borderRadius: 4, padding: "8px 12px",
              color: "#00ff9d", fontFamily: "monospace", fontSize: 13, outline: "none"
            }} />
          </div>
          {activeTab === "nmap" && (
            <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
              {["-sV (Version)", "-sC (Scripts)", "-O (OS Detect)", "--script vuln", "-p- (All Ports)"].map(f => (
                <label key={f} style={{ display: "flex", alignItems: "center", gap: 4, cursor: "pointer" }}>
                  <input type="checkbox" defaultChecked style={{ accentColor: "#00ff9d" }} />
                  <span style={{ color: "#8a9bb0", fontFamily: "monospace", fontSize: 10 }}>{f}</span>
                </label>
              ))}
            </div>
          )}
          {activeTab === "nuclei" && (
            <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
              {["CVEs (7,200+)", "Default-Login", "Exposed-Panels", "Misconfigs", "SSL-TLS", "OWASP Top 10"].map(f => (
                <label key={f} style={{ display: "flex", alignItems: "center", gap: 4, cursor: "pointer" }}>
                  <input type="checkbox" defaultChecked style={{ accentColor: "#00ff9d" }} />
                  <span style={{ color: "#8a9bb0", fontFamily: "monospace", fontSize: 10 }}>{f}</span>
                </label>
              ))}
            </div>
          )}
          <button onClick={() => runScan(activeTab)} style={{
            padding: "10px 28px", background: "rgba(0,255,157,0.1)", border: "1px solid #00ff9d",
            borderRadius: 6, color: "#00ff9d", fontFamily: "monospace", fontWeight: 700, fontSize: 12,
            cursor: "pointer", letterSpacing: 1, boxShadow: "0 0 15px rgba(0,255,157,0.15)"
          }}>
            ▶ LAUNCH {activeTab.toUpperCase()} SCAN
          </button>
        </div>
      )}

      {/* Scanning Progress */}
      {scanState === "scanning" && (
        <div style={{ background: "rgba(0,15,25,0.8)", border: "1px solid #ffd60a33", borderRadius: 8, padding: 20, marginBottom: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
            <div style={{ color: "#ffd60a", fontFamily: "monospace", fontWeight: 700, fontSize: 13 }}>⟳ SCANNING {target}</div>
            <div style={{ color: "#ffd60a", fontFamily: "monospace" }}>{progress}%</div>
          </div>
          <div style={{ background: "#0a1a22", borderRadius: 4, height: 6, marginBottom: 12, overflow: "hidden" }}>
            <div style={{ width: `${progress}%`, height: "100%", background: "linear-gradient(90deg,#ffd60a,#ff6b35)", transition: "width 0.35s ease", boxShadow: "0 0 10px #ffd60a" }} />
          </div>
          <div style={{ color: "#8a9bb0", fontFamily: "monospace", fontSize: 11 }}>{stepLabel}</div>
        </div>
      )}

      {/* Correlation auto-shows */}
      {activeTab === "correlation" && scanState === "idle" && (
        <div style={{ background: "rgba(0,15,25,0.8)", border: "1px solid #0a2a35", borderRadius: 8, padding: 20, marginBottom: 20, textAlign: "center" }}>
          <div style={{ fontSize: 40, marginBottom: 12 }}>⚡</div>
          <div style={{ color: "#00ccff", fontFamily: "monospace", fontWeight: 700 }}>SOC × VAPT RISK CORRELATION ENGINE</div>
          <div style={{ color: "#8a9bb0", fontSize: 12, marginTop: 8, marginBottom: 20 }}>Correlates active SOC incidents with VAPT vulnerabilities by host IP to produce combined risk scores and prioritized IR actions.</div>
          <button onClick={() => runScan("correlation")} style={{
            padding: "10px 28px", background: "rgba(0,204,255,0.1)", border: "1px solid #00ccff",
            borderRadius: 6, color: "#00ccff", fontFamily: "monospace", fontWeight: 700, fontSize: 12,
            cursor: "pointer", letterSpacing: 1
          }}>▶ RUN RISK CORRELATION</button>
        </div>
      )}

      {/* Results */}
      {scanState === "done" && activeTab === "nmap" && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 10, marginBottom: 16 }}>
            {["Critical","High","Medium","Low"].map(s => {
              const cnt = MOCK_VAPT_RESULTS.nmap.filter(x=>x.severity===s).length;
              return <StatCard key={s} label={`${s} CVEs`} value={cnt} color={sevColors[s]} icon={s==="Critical"?"💀":s==="High"?"🔴":s==="Medium"?"🟡":"🟢"} />;
            })}
          </div>
          <div style={{ background: "rgba(0,10,18,0.9)", border: "1px solid #0a2a35", borderRadius: 8, overflow: "hidden" }}>
            <div style={{ display: "grid", gridTemplateColumns: "110px 60px 80px 1fr 120px 90px", padding: "8px 14px", background: "rgba(0,30,45,0.8)", borderBottom: "1px solid #0a2a35" }}>
              {["Host","Port","Service","CVE / Description","Version","Severity"].map(h => (
                <div key={h} style={{ color: "#4a7a8a", fontSize: 10, fontFamily: "monospace", letterSpacing: 1 }}>{h}</div>
              ))}
            </div>
            {MOCK_VAPT_RESULTS.nmap.map((r, i) => (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "110px 60px 80px 1fr 120px 90px", padding: "10px 14px", borderBottom: "1px solid #081822" }}>
                <div style={{ color: "#00ccff", fontFamily: "monospace", fontSize: 11 }}>{r.host}</div>
                <div style={{ color: "#8a9bb0", fontFamily: "monospace", fontSize: 11 }}>{r.port}</div>
                <div style={{ color: "#c0d8e8", fontFamily: "monospace", fontSize: 11 }}>{r.service}</div>
                <div>
                  <div style={{ color: "#ffd60a", fontFamily: "monospace", fontSize: 10 }}>{r.cve}</div>
                  <div style={{ color: "#8a9bb0", fontSize: 10 }}>{r.description}</div>
                </div>
                <div style={{ color: "#8a9bb0", fontFamily: "monospace", fontSize: 10 }}>{r.version}</div>
                <div><GlowBadge label={r.severity} color={sevColors[r.severity]} bg={`${sevColors[r.severity]}22`} /></div>
              </div>
            ))}
          </div>
        </div>
      )}

      {scanState === "done" && activeTab === "nuclei" && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 10, marginBottom: 16 }}>
            {["Critical","High","Medium","Low"].map(s => {
              const cnt = MOCK_VAPT_RESULTS.nuclei.filter(x=>x.severity===s).length;
              return <StatCard key={s} label={`${s} Findings`} value={cnt} color={sevColors[s]} icon={s==="Critical"?"💀":s==="High"?"🔴":s==="Medium"?"🟡":"🟢"} />;
            })}
          </div>
          <div style={{ background: "rgba(0,10,18,0.9)", border: "1px solid #0a2a35", borderRadius: 8, overflow: "hidden" }}>
            <div style={{ display: "grid", gridTemplateColumns: "130px 1fr 130px 80px 90px 80px", padding: "8px 14px", background: "rgba(0,30,45,0.8)", borderBottom: "1px solid #0a2a35" }}>
              {["Template","Finding","Host","MITRE","Severity","Tags"].map(h => (
                <div key={h} style={{ color: "#4a7a8a", fontSize: 10, fontFamily: "monospace", letterSpacing: 1 }}>{h}</div>
              ))}
            </div>
            {MOCK_VAPT_RESULTS.nuclei.map((r, i) => (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "130px 1fr 130px 80px 90px 80px", padding: "10px 14px", borderBottom: "1px solid #081822" }}>
                <div style={{ color: "#ffd60a", fontFamily: "monospace", fontSize: 10 }}>{r.template}</div>
                <div>
                  <div style={{ color: "#c0d8e8", fontSize: 12 }}>{r.name}</div>
                  <div style={{ color: "#4a7a8a", fontFamily: "monospace", fontSize: 9, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.matched}</div>
                </div>
                <div style={{ color: "#00ccff", fontFamily: "monospace", fontSize: 11 }}>{r.host}</div>
                <div style={{ color: "#ffd60a", fontFamily: "monospace", fontSize: 10 }}>{r.mitre}</div>
                <div><GlowBadge label={r.severity} color={sevColors[r.severity]} bg={`${sevColors[r.severity]}22`} /></div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 2 }}>
                  {r.tags.slice(0,2).map(t => <span key={t} style={{ background: "rgba(0,204,255,0.1)", color: "#00ccff", fontSize: 8, padding: "1px 4px", borderRadius: 2, fontFamily: "monospace" }}>{t}</span>)}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {scanState === "done" && activeTab === "correlation" && (
        <div>
          <div style={{ background: "rgba(255,45,85,0.05)", border: "1px solid #ff2d5533", borderRadius: 8, padding: 14, marginBottom: 16, display: "flex", gap: 12, alignItems: "center" }}>
            <div style={{ fontSize: 24 }}>🔴</div>
            <div>
              <div style={{ color: "#ff2d55", fontFamily: "monospace", fontWeight: 700, fontSize: 13 }}>5 CORRELATED HIGH-RISK HOSTS IDENTIFIED</div>
              <div style={{ color: "#8a9bb0", fontSize: 11, marginTop: 2 }}>Active SOC alerts matched with exploitable vulnerabilities — immediate action required</div>
            </div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {MOCK_VAPT_RESULTS.riskCorrelation.map((r, i) => (
              <div key={i} style={{ background: "rgba(0,10,18,0.9)", border: `1px solid ${sevColors[r.combined_risk]}33`, borderRadius: 8, padding: 16, borderLeft: `4px solid ${sevColors[r.combined_risk]}` }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                  <div>
                    <div style={{ color: "#c0d8e8", fontFamily: "monospace", fontWeight: 700, fontSize: 13 }}>{r.host}</div>
                    <div style={{ color: "#4a7a8a", fontSize: 10, fontFamily: "monospace", marginTop: 2 }}>Combined Risk Assessment</div>
                  </div>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <div style={{ color: sevColors[r.combined_risk], fontFamily: "monospace", fontWeight: 800, fontSize: 20 }}>{r.score}</div>
                    <GlowBadge label={r.combined_risk} color={sevColors[r.combined_risk]} bg={`${sevColors[r.combined_risk]}22`} />
                  </div>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 10 }}>
                  <div style={{ background: "rgba(255,45,85,0.08)", borderRadius: 5, padding: 8 }}>
                    <div style={{ color: "#ff2d55", fontSize: 9, fontFamily: "monospace", letterSpacing: 1, marginBottom: 3 }}>SOC ALERT</div>
                    <div style={{ color: "#c0d8e8", fontSize: 11 }}>{r.soc_alert}</div>
                  </div>
                  <div style={{ background: "rgba(255,107,53,0.08)", borderRadius: 5, padding: 8 }}>
                    <div style={{ color: "#ff6b35", fontSize: 9, fontFamily: "monospace", letterSpacing: 1, marginBottom: 3 }}>VAPT FINDING</div>
                    <div style={{ color: "#c0d8e8", fontSize: 11 }}>{r.vapt_finding}</div>
                  </div>
                </div>
                <div style={{ background: "rgba(0,255,157,0.05)", border: "1px solid #00ff9d22", borderRadius: 4, padding: 8, display: "flex", gap: 8, alignItems: "center" }}>
                  <span style={{ fontSize: 14 }}>⚡</span>
                  <div>
                    <span style={{ color: "#00ff9d", fontFamily: "monospace", fontSize: 9, letterSpacing: 1 }}>RECOMMENDED ACTION: </span>
                    <span style={{ color: "#c0d8e8", fontSize: 11 }}>{r.action}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── MAIN APP ─────────────────────────────────────────────────────────────────

export default function App() {
  const [page, setPage] = useState("soc");
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <div style={{
      minHeight: "100vh", background: "#000a12", color: "#e0e8f0",
      fontFamily: "'Courier New', monospace", position: "relative",
      backgroundImage: "radial-gradient(ellipse at 20% 20%, rgba(0,80,60,0.08) 0%, transparent 50%), radial-gradient(ellipse at 80% 80%, rgba(0,30,80,0.12) 0%, transparent 50%)"
    }}>
      <MatrixRain />

      {/* Header */}
      <div style={{
        position: "relative", zIndex: 10,
        background: "rgba(0,8,15,0.95)", borderBottom: "1px solid #0a2a35",
        padding: "0 24px", backdropFilter: "blur(10px)"
      }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", height: 56 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ position: "relative" }}>
              <div style={{ width: 36, height: 36, borderRadius: "50%", background: "rgba(0,255,157,0.1)", border: "2px solid #00ff9d", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16, boxShadow: "0 0 20px rgba(0,255,157,0.4)" }}>🛡️</div>
              <div style={{ position: "absolute", top: 2, right: 2, width: 8, height: 8, background: "#00ff9d", borderRadius: "50%", boxShadow: "0 0 6px #00ff9d", animation: "pulse 2s infinite" }} />
            </div>
            <div>
              <div style={{ color: "#00ff9d", fontWeight: 800, fontSize: 14, letterSpacing: 2, textTransform: "uppercase" }}>SOC–VAPT Framework</div>
              <div style={{ color: "#4a7a8a", fontSize: 9, letterSpacing: 1 }}>PCAP-BASED THREAT DETECTION & SECURITY ASSESSMENT</div>
            </div>
          </div>

          <div style={{ display: "flex", gap: 4 }}>
            {[
              { key: "soc", label: "SOC MODULE", icon: "🕵️", sub: "PCAP Analysis + TIP" },
              { key: "vapt", label: "VAPT MODULE", icon: "🔬", sub: "Nmap + Nuclei + Correlation" },
            ].map(p => (
              <button key={p.key} onClick={() => setPage(p.key)} style={{
                padding: "8px 18px", borderRadius: 6, border: `1px solid ${page===p.key?"#00ff9d44":"#0a2a35"}`,
                background: page===p.key ? "rgba(0,255,157,0.08)" : "transparent",
                color: page===p.key ? "#00ff9d" : "#8a9bb0", cursor: "pointer",
                fontFamily: "monospace", fontWeight: 700, fontSize: 11, letterSpacing: 1,
                transition: "all 0.2s", textAlign: "center"
              }}>
                <div>{p.icon} {p.label}</div>
                <div style={{ fontSize: 8, opacity: 0.6, marginTop: 1 }}>{p.sub}</div>
              </button>
            ))}
          </div>

          <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
            <div style={{ textAlign: "right" }}>
              <div style={{ color: "#00ff9d", fontFamily: "monospace", fontSize: 12, fontWeight: 700 }}>{time.toLocaleTimeString()}</div>
              <div style={{ color: "#4a7a8a", fontSize: 9, letterSpacing: 1 }}>{time.toLocaleDateString()} UTC</div>
            </div>
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#00ff9d", boxShadow: "0 0 8px #00ff9d" }} />
              <span style={{ color: "#4a7a8a", fontSize: 9, letterSpacing: 1 }}>SYSTEM ONLINE</span>
            </div>
          </div>
        </div>

        {/* Sub header */}
        <div style={{ display: "flex", gap: 16, paddingBottom: 8, borderTop: "1px solid #061420", paddingTop: 8 }}>
          {page === "soc" ? (
            <>
              <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <span style={{ color: "#4a7a8a", fontSize: 9, fontFamily: "monospace", letterSpacing: 1 }}>DETECTION:</span>
                {["NBAD-11 C2","NBAD-14 DNS","NBAD-16 DGA","NBAD-13 HTTP","NABD-55 Entropy","NBAD-147 TLS"].map(t => (
                  <span key={t} style={{ background: "rgba(0,204,255,0.08)", border: "1px solid #00ccff22", borderRadius: 2, padding: "1px 5px", fontSize: 8, color: "#00ccff", fontFamily: "monospace" }}>{t}</span>
                ))}
              </div>
              <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
                {["VirusTotal", "AbuseIPDB", "AlienVault OTX", "Local Feeds", "MITRE ATT&CK"].map(ti => (
                  <span key={ti} style={{ background: "rgba(0,255,157,0.06)", border: "1px solid #00ff9d22", borderRadius: 2, padding: "1px 6px", fontSize: 8, color: "#00ff9d66", fontFamily: "monospace" }}>{ti}</span>
                ))}
              </div>
            </>
          ) : (
            <>
              <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <span style={{ color: "#4a7a8a", fontSize: 9, fontFamily: "monospace", letterSpacing: 1 }}>VAPT TOOLS:</span>
                {["Nmap -sV -sC --script vuln", "Nuclei v3 (7,200+ CVE templates)", "SOC×VAPT Risk Fusion Engine"].map(t => (
                  <span key={t} style={{ background: "rgba(255,214,10,0.08)", border: "1px solid #ffd60a22", borderRadius: 2, padding: "1px 5px", fontSize: 8, color: "#ffd60a", fontFamily: "monospace" }}>{t}</span>
                ))}
              </div>
              <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
                {["CVE Mapping", "MITRE T1190", "Exploit Validation", "IR Playbook"].map(ti => (
                  <span key={ti} style={{ background: "rgba(255,107,53,0.06)", border: "1px solid #ff6b3522", borderRadius: 2, padding: "1px 6px", fontSize: 8, color: "#ff6b3566", fontFamily: "monospace" }}>{ti}</span>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Main Content */}
      <div style={{ position: "relative", zIndex: 5, maxWidth: 1200, margin: "0 auto", padding: "24px 24px 0" }}>
        {/* Section Title */}
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
          <div style={{ width: 3, height: 28, background: page === "soc" ? "#00ff9d" : "#ffd60a", borderRadius: 2, boxShadow: `0 0 10px ${page==="soc"?"#00ff9d":"#ffd60a"}` }} />
          <div>
            <div style={{ color: page === "soc" ? "#00ff9d" : "#ffd60a", fontWeight: 800, fontSize: 16, letterSpacing: 2, textTransform: "uppercase" }}>
              {page === "soc" ? "🕵️ SOC Threat Detection Module" : "🔬 VAPT Security Assessment Module"}
            </div>
            <div style={{ color: "#4a7a8a", fontSize: 10, letterSpacing: 1 }}>
              {page === "soc"
                ? "PCAP Upload → Zeek → NBAD/NABD Detection → TIP → MITRE ATT&CK Mapping"
                : "Nmap Vulnerability Scan → Nuclei CVE Detection → SOC×VAPT Risk Correlation"}
            </div>
          </div>
        </div>

        {page === "soc" ? <SOCModule /> : <VAPTModule />}
      </div>

      {/* Footer */}
      <div style={{ position: "relative", zIndex: 5, borderTop: "1px solid #0a1a22", padding: "12px 24px", background: "rgba(0,5,10,0.8)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ color: "#2a4a5a", fontSize: 9, fontFamily: "monospace", letterSpacing: 1 }}>
          PCAP-BASED SOC & VAPT FRAMEWORK v2.0 — FOR AUTHORIZED USE ONLY
        </div>
        <div style={{ display: "flex", gap: 12 }}>
          {["SHA-256 Integrity", "WSL-Zeek Integration", "104 NBAD/NABD Rules", "MITRE ATT&CK Mapped"].map(f => (
            <span key={f} style={{ color: "#1a3a4a", fontSize: 8, fontFamily: "monospace", letterSpacing: 0.5 }}>{f}</span>
          ))}
        </div>
      </div>

      <style>{`
        @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.5;transform:scale(1.3)} }
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: #000a12; }
        ::-webkit-scrollbar-thumb { background: #0a3a4a; border-radius: 2px; }
      `}</style>
    </div>
  );
}
