# soc/soc_dashboard.py

import os, json, csv
from flask import Blueprint, render_template, send_file
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

soc_dashboard = Blueprint(
    "soc_dashboard",
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates")
)

ALERT_FILE = "alerts/final_incidents.json"
REPORT_DIR = "reports"


def load_incidents():
    if not os.path.exists(ALERT_FILE):
        return []
    with open(ALERT_FILE, "r", encoding="utf-8") as f:
        return json.load(f).get("incidents", [])


@soc_dashboard.route("/dashboard")
def dashboard():
    incidents = load_incidents()

    severity_counts = {"Critical":0, "High":0, "Medium":0, "Low":0}
    protocol_counts = {}

    for i in incidents:
        severity_counts[i.get("final_risk","Low")] += 1
        proto = i.get("protocol","UNKNOWN")
        protocol_counts[proto] = protocol_counts.get(proto,0) + 1

    return render_template(
        "dashboard.html",
        incidents=incidents,
        incident_count=len(incidents),
        severity_counts=severity_counts,
        protocol_counts=protocol_counts
    )


@soc_dashboard.route("/export/csv")
def export_csv():
    os.makedirs(REPORT_DIR, exist_ok=True)
    incidents = load_incidents()

    path = os.path.join(REPORT_DIR, "soc_report.csv")
    with open(path,"w",newline="",encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Protocol","Indicator","Risk","Count","Threat Source","Reason"])
        for i in incidents:
            w.writerow([
                i.get("protocol"),
                i.get("indicator"),
                i.get("final_risk"),
                i.get("count"),
                i.get("threat_source","Local"),
                i.get("reason")
            ])

    return send_file(path, as_attachment=True)


@soc_dashboard.route("/export/pdf")
def export_pdf():
    os.makedirs(REPORT_DIR, exist_ok=True)
    incidents = load_incidents()

    path = os.path.join(REPORT_DIR, "soc_report.pdf")
    c = canvas.Canvas(path, pagesize=A4)

    y = 800
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "PCAP-Based SOC Incident Report")
    y -= 30
    c.setFont("Helvetica", 9)

    for i in incidents:
        if y < 50:
            c.showPage()
            y = 800
        c.drawString(
            40, y,
            f"{i.get('protocol')} | {i.get('indicator')} | {i.get('final_risk')} | {i.get('threat_source')}"
        )
        y -= 14

    c.save()
    return send_file(path, as_attachment=True)
