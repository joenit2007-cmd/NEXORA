"""PDF (ReportLab) and CSV report generation service for NEXORA."""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models import (
    LogAnalysis,
    NetworkScan,
    PhishingAnalysis,
    SecurityAlert,
    SecurityEvent,
    VulnerabilityAssessment,
    VulnerabilityFinding,
)
from app.utils.helpers import generate_unique_id, utc_now

REPORT_TYPES = {
    "overall_summary": "NEXORA Overall Security Summary Report",
    "log_analysis": "NEXORA Log Analysis Security Report",
    "network_assessment": "NEXORA Network Monitoring & Scan Report",
    "vulnerability_assessment": "NEXORA Vulnerability Assessment Report",
    "phishing_analysis": "NEXORA Phishing Threat Analysis Report",
}

NAVY = colors.HexColor("#0B132B")
SLATE = colors.HexColor("#1C2541")
CYAN = colors.HexColor("#00D4FF")
TEXT_DARK = colors.HexColor("#1E293B")
MUTED = colors.HexColor("#475569")
LIGHT_BG = colors.HexColor("#F1F5F9")
BORDER = colors.HexColor("#CBD5E1")


def _xml_escape(text: Any) -> str:
    s = str(text if text is not None else "")
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _collect_report_data(user_id: int, report_type: str, is_admin: bool = False) -> dict[str, Any]:
    """Gather actual persisted database records for the selected report type."""
    def scoped(model):
        q = model.query
        if not is_admin:
            q = q.filter_by(user_id=user_id)
        return q

    events = scoped(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(100).all()
    log_jobs = scoped(LogAnalysis).order_by(LogAnalysis.created_at.desc()).limit(25).all()
    net_scans = scoped(NetworkScan).order_by(NetworkScan.created_at.desc()).limit(25).all()
    vuln_assessments = scoped(VulnerabilityAssessment).order_by(VulnerabilityAssessment.created_at.desc()).limit(25).all()
    vuln_findings = scoped(VulnerabilityFinding).order_by(VulnerabilityFinding.created_at.desc()).limit(100).all()
    phishing_items = scoped(PhishingAnalysis).order_by(PhishingAnalysis.created_at.desc()).limit(50).all()
    alerts = scoped(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(100).all()

    alert_sev = Counter(a.severity for a in alerts)
    vuln_sev = Counter(f.severity for f in vuln_findings)
    phish_risk = Counter(p.risk_level for p in phishing_items)

    return {
        "report_type": report_type,
        "title": REPORT_TYPES.get(report_type, "NEXORA Security Report"),
        "generated_at": utc_now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "events": events,
        "log_jobs": log_jobs,
        "net_scans": net_scans,
        "vuln_assessments": vuln_assessments,
        "vuln_findings": vuln_findings,
        "phishing_items": phishing_items,
        "alerts": alerts,
        "metrics": {
            "total_events": len(events),
            "total_log_analyses": len(log_jobs),
            "total_network_scans": len(net_scans),
            "total_vuln_assessments": len(vuln_assessments),
            "total_vuln_findings": len(vuln_findings),
            "total_phishing_analyses": len(phishing_items),
            "high_risk_phishing": phish_risk.get("High Risk", 0),
            "suspicious_phishing": phish_risk.get("Suspicious", 0),
            "total_alerts": len(alerts),
            "open_alerts": sum(1 for a in alerts if a.status == "Open"),
            "alert_severity": {
                "Critical": alert_sev.get("Critical", 0),
                "High": alert_sev.get("High", 0),
                "Medium": alert_sev.get("Medium", 0),
                "Low": alert_sev.get("Low", 0),
            },
            "vuln_severity": {
                "Critical": vuln_sev.get("Critical", 0),
                "High": vuln_sev.get("High", 0),
                "Medium": vuln_sev.get("Medium", 0),
                "Low": vuln_sev.get("Low", 0),
                "Informational": vuln_sev.get("Informational", 0),
            },
        },
    }


def _styled_table(rows: list[list[Any]], col_widths: list[float] | None = None) -> Table:
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), SLATE),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 8.5),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return tbl


def _build_pdf(output_path: Path, data: dict[str, Any], generated_by: str) -> str:
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "NexoraTitle",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=colors.white,
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "NexoraSub",
        parent=styles["Normal"],
        fontSize=9,
        textColor=CYAN,
    )
    h2_style = ParagraphStyle(
        "NexoraH2",
        parent=styles["Heading2"],
        fontSize=12,
        textColor=NAVY,
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "NexoraBody",
        parent=styles["Normal"],
        fontSize=9,
        textColor=TEXT_DARK,
        leading=13,
    )
    cell_style = ParagraphStyle(
        "NexoraCell",
        parent=styles["Normal"],
        fontSize=7.8,
        textColor=TEXT_DARK,
        leading=10,
    )

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=0.6 * inch,
        leftMargin=0.6 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        title=data["title"],
        author="NEXORA Security Platform",
    )

    story = []

    # Branded header banner
    banner_data = [
        [
            Paragraph(f"<b>NEXORA</b> &nbsp;|&nbsp; {_xml_escape(data['title'])}", title_style),
        ],
        [
            Paragraph(
                f"DETECT. ANALYZE. SECURE. &nbsp;&bull;&nbsp; Generated: {_xml_escape(data['generated_at'])} "
                f"&nbsp;&bull;&nbsp; Analyst: {_xml_escape(generated_by)}",
                subtitle_style,
            ),
        ],
    ]
    banner = Table(banner_data, colWidths=[7.0 * inch])
    banner.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), NAVY),
                ("LEFTPADDING", (0, 0), (-1, -1), 14),
                ("RIGHTPADDING", (0, 0), (-1, -1), 14),
                ("TOPPADDING", (0, 0), (0, 0), 12),
                ("BOTTOMPADDING", (0, 1), (0, 1), 12),
            ]
        )
    )
    story.append(banner)
    story.append(Spacer(1, 14))

    metrics = data["metrics"]
    report_type = data["report_type"]

    # 1. Assessment Overview
    story.append(Paragraph("1. Assessment Overview & Severity Distribution", h2_style))
    overview_rows = [
        ["Metric", "Recorded Count", "Severity Category", "Alert Count", "Vulnerability Count"],
        ["Security Events", str(metrics["total_events"]), "Critical", str(metrics["alert_severity"]["Critical"]), str(metrics["vuln_severity"]["Critical"])],
        ["Log Analyses", str(metrics["total_log_analyses"]), "High", str(metrics["alert_severity"]["High"]), str(metrics["vuln_severity"]["High"])],
        ["Network Scans", str(metrics["total_network_scans"]), "Medium", str(metrics["alert_severity"]["Medium"]), str(metrics["vuln_severity"]["Medium"])],
        ["Vulnerability Findings", str(metrics["total_vuln_findings"]), "Low", str(metrics["alert_severity"]["Low"]), str(metrics["vuln_severity"]["Low"])],
        ["Phishing Analyses", str(metrics["total_phishing_analyses"]), "Informational", "—", str(metrics["vuln_severity"]["Informational"])],
    ]
    story.append(_styled_table(overview_rows, [1.6 * inch, 1.1 * inch, 1.4 * inch, 1.3 * inch, 1.6 * inch]))
    story.append(Spacer(1, 10))

    # 2. Module-specific sections
    if report_type in {"overall_summary", "log_analysis"}:
        story.append(Paragraph("2. Log Analysis & Security Events", h2_style))
        if data["log_jobs"]:
            log_rows = [["File", "Events", "Failed Logins", "Brute-Force", "Suspicious IPs", "Analyzed At"]]
            for job in data["log_jobs"][:12]:
                log_rows.append(
                    [
                        Paragraph(_xml_escape(job.original_filename), cell_style),
                        str(job.parsed_events),
                        str(job.failed_logins),
                        str(job.brute_force_count),
                        str(len(job.suspicious_ips)),
                        job.created_at.strftime("%Y-%m-%d %H:%M"),
                    ]
                )
            story.append(_styled_table(log_rows, [2.0 * inch, 0.7 * inch, 0.95 * inch, 0.9 * inch, 1.05 * inch, 1.4 * inch]))
            story.append(Spacer(1, 8))
        else:
            story.append(Paragraph("No log analysis jobs have been executed yet.", body_style))

        if data["events"]:
            ev_rows = [["Timestamp", "IP Address", "User", "Event Type", "Severity", "Reason"]]
            for ev in data["events"][:20]:
                ev_rows.append(
                    [
                        ev.timestamp.strftime("%Y-%m-%d %H:%M"),
                        _xml_escape(ev.source_ip or "N/A"),
                        _xml_escape(ev.username or "N/A"),
                        Paragraph(_xml_escape(ev.event_type), cell_style),
                        _xml_escape(ev.severity),
                        Paragraph(_xml_escape((ev.detection_reason or "")[:120]), cell_style),
                    ]
                )
            story.append(_styled_table(ev_rows, [1.05 * inch, 0.95 * inch, 0.8 * inch, 1.35 * inch, 0.75 * inch, 2.1 * inch]))

    if report_type in {"overall_summary", "network_assessment"}:
        story.append(Paragraph("3. Authorized Network Assessment Results", h2_style))
        if data["net_scans"]:
            net_rows = [["Target", "Scan Type", "Engine", "Open Ports", "Summary", "Timestamp"]]
            for scan in data["net_scans"][:15]:
                ports_str = ", ".join(f"{p['port']}/{p.get('service', 'tcp')}" for p in scan.open_ports[:6]) or "None"
                net_rows.append(
                    [
                        _xml_escape(scan.target),
                        _xml_escape(scan.scan_type),
                        _xml_escape(scan.tool_used),
                        Paragraph(_xml_escape(ports_str), cell_style),
                        Paragraph(_xml_escape((scan.summary or "")[:110]), cell_style),
                        scan.created_at.strftime("%Y-%m-%d %H:%M"),
                    ]
                )
            story.append(_styled_table(net_rows, [0.95 * inch, 0.95 * inch, 0.9 * inch, 1.3 * inch, 1.85 * inch, 1.05 * inch]))
        else:
            story.append(Paragraph("No authorized network scans are recorded in the database.", body_style))

    if report_type in {"overall_summary", "vulnerability_assessment"}:
        story.append(Paragraph("4. Vulnerability Findings & Recommended Remediation", h2_style))
        if data["vuln_findings"]:
            vf_rows = [["Host & Service", "Severity", "Finding", "Evidence", "Remediation"]]
            for f in data["vuln_findings"][:20]:
                vf_rows.append(
                    [
                        Paragraph(_xml_escape(f"{f.affected_host}\n{f.port_service}"), cell_style),
                        _xml_escape(f.severity),
                        Paragraph(_xml_escape(f.title), cell_style),
                        Paragraph(_xml_escape(f.evidence[:130]), cell_style),
                        Paragraph(_xml_escape(f.recommended_remediation[:140]), cell_style),
                    ]
                )
            story.append(_styled_table(vf_rows, [1.15 * inch, 0.75 * inch, 1.55 * inch, 1.75 * inch, 1.8 * inch]))
        else:
            story.append(Paragraph("No vulnerability findings have been recorded yet.", body_style))

    if report_type in {"overall_summary", "phishing_analysis"}:
        story.append(Paragraph("5. Phishing Email Threat Analyses", h2_style))
        if data["phishing_items"]:
            ph_rows = [["Sender", "Subject", "Risk Level", "Score", "Method", "Explanation"]]
            for item in data["phishing_items"][:15]:
                ph_rows.append(
                    [
                        Paragraph(_xml_escape((item.sender or "N/A")[:40]), cell_style),
                        Paragraph(_xml_escape((item.subject or "(No subject)")[:45]), cell_style),
                        _xml_escape(item.risk_level),
                        f"{item.risk_score:.1f}",
                        _xml_escape(item.detection_method),
                        Paragraph(_xml_escape((item.explanation or "")[:130]), cell_style),
                    ]
                )
            story.append(_styled_table(ph_rows, [1.2 * inch, 1.2 * inch, 0.8 * inch, 0.55 * inch, 1.0 * inch, 2.25 * inch]))
        else:
            story.append(Paragraph("No phishing analyses have been performed yet.", body_style))

    # Alerts summary
    story.append(Paragraph("6. Centralized Security Alerts", h2_style))
    if data["alerts"]:
        al_rows = [["Alert ID", "Severity", "Status", "Module", "Title", "Recommended Action"]]
        for a in data["alerts"][:18]:
            al_rows.append(
                [
                    _xml_escape(a.alert_uid),
                    _xml_escape(a.severity),
                    _xml_escape(a.status),
                    _xml_escape(a.source_module),
                    Paragraph(_xml_escape(a.title), cell_style),
                    Paragraph(_xml_escape((a.recommended_action or "")[:110]), cell_style),
                ]
            )
        story.append(_styled_table(al_rows, [1.1 * inch, 0.7 * inch, 0.7 * inch, 1.0 * inch, 1.65 * inch, 1.85 * inch]))
    else:
        story.append(Paragraph("No security alerts have been triggered.", body_style))

    # Conclusion
    story.append(Paragraph("7. Analysis Summary & Conclusion", h2_style))
    summary_text = (
        f"This report compiles live telemetry stored in the NEXORA platform: {metrics['total_events']} security event(s), "
        f"{metrics['total_alerts']} centralized alert(s) ({metrics['open_alerts']} currently Open), "
        f"{metrics['total_vuln_findings']} vulnerability finding(s), and {metrics['total_phishing_analyses']} phishing "
        f"assessment(s) ({metrics['high_risk_phishing']} High Risk). Prioritize remediation of Critical and High severity "
        "findings, enforce least-privilege authentication and TLS encryption, and review all open security alerts."
    )
    story.append(Paragraph(_xml_escape(summary_text), body_style))

    doc.build(story)
    return summary_text


def _build_csv(output_path: Path, data: dict[str, Any]) -> str:
    report_type = data["report_type"]
    rows_written = 0

    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)

        if report_type == "log_analysis":
            writer.writerow(["Timestamp", "Source IP", "Username", "Event Type", "Severity", "Detection Reason", "Recommended Action"])
            for ev in data["events"]:
                writer.writerow([
                    ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    ev.source_ip or "N/A",
                    ev.username or "N/A",
                    ev.event_type,
                    ev.severity,
                    ev.detection_reason or "",
                    ev.recommended_action or "",
                ])
                rows_written += 1

        elif report_type == "network_assessment":
            writer.writerow(["Timestamp", "Target", "Scan Type", "Tool Used", "Host Status", "Open Ports Count", "Open Ports", "Summary"])
            for scan in data["net_scans"]:
                ports_str = "; ".join(f"{p['port']}/{p.get('protocol', 'tcp')} ({p.get('service', 'unknown')})" for p in scan.open_ports)
                writer.writerow([
                    scan.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    scan.target,
                    scan.scan_type,
                    scan.tool_used,
                    scan.host_status,
                    scan.open_ports_count,
                    ports_str,
                    scan.summary or "",
                ])
                rows_written += 1

        elif report_type == "vulnerability_assessment":
            writer.writerow(["Timestamp", "Affected Host", "Port/Service", "Severity", "Title", "Description", "Evidence", "Potential Impact", "Recommended Remediation"])
            for f in data["vuln_findings"]:
                writer.writerow([
                    f.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    f.affected_host,
                    f.port_service,
                    f.severity,
                    f.title,
                    f.description,
                    f.evidence,
                    f.potential_impact,
                    f.recommended_remediation,
                ])
                rows_written += 1

        elif report_type == "phishing_analysis":
            writer.writerow(["Timestamp", "Sender", "Subject", "Risk Level", "Risk Score", "Detection Method", "ML Probability", "URLs", "Explanation", "Recommended Action"])
            for p in data["phishing_items"]:
                writer.writerow([
                    p.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    p.sender or "",
                    p.subject or "",
                    p.risk_level,
                    p.risk_score,
                    p.detection_method,
                    p.ml_probability if p.ml_probability is not None else "",
                    "; ".join(p.urls),
                    p.explanation or "",
                    p.recommended_action or "",
                ])
                rows_written += 1

        else:  # overall_summary
            writer.writerow(["Record Type", "Timestamp", "Severity/Risk", "Status", "Target/Source", "Title/Event", "Details/Remediation"])
            for a in data["alerts"]:
                writer.writerow(["Security Alert", a.created_at.strftime("%Y-%m-%d %H:%M:%S"), a.severity, a.status, a.source_ip or a.target or "N/A", a.title, a.recommended_action or a.description])
                rows_written += 1
            for f in data["vuln_findings"]:
                writer.writerow(["Vulnerability Finding", f.created_at.strftime("%Y-%m-%d %H:%M:%S"), f.severity, "Detected", f"{f.affected_host} ({f.port_service})", f.title, f.recommended_remediation])
                rows_written += 1
            for p in data["phishing_items"]:
                writer.writerow(["Phishing Analysis", p.created_at.strftime("%Y-%m-%d %H:%M:%S"), p.risk_level, f"Score {p.risk_score}", p.sender or "N/A", p.subject or "Email", p.explanation or ""])
                rows_written += 1
            for ev in data["events"][:50]:
                writer.writerow(["Security Event", ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"), ev.severity, ev.source_module, ev.source_ip or "N/A", ev.event_type, ev.detection_reason or ""])
                rows_written += 1

    return f"Exported {rows_written} actual platform record(s) for '{data['title']}' as CSV."


def generate_security_report(
    *,
    reports_dir: Path,
    user_id: int,
    generated_by: str,
    report_type: str,
    report_format: str,
    is_admin: bool = False,
) -> dict[str, Any]:
    """Generate a PDF or CSV report from live database records and save to reports_dir."""
    if report_type not in REPORT_TYPES:
        return {"success": False, "error": f"Unsupported report type '{report_type}'."}

    fmt = (report_format or "pdf").lower().strip()
    if fmt not in {"pdf", "csv"}:
        return {"success": False, "error": "Report format must be 'pdf' or 'csv'."}

    reports_dir.mkdir(parents=True, exist_ok=True)
    report_uid = generate_unique_id("RPT")
    filename = f"{report_uid}_{report_type}.{fmt}"
    output_path = reports_dir / filename

    data = _collect_report_data(user_id=user_id, report_type=report_type, is_admin=is_admin)

    if fmt == "pdf":
        summary = _build_pdf(output_path, data, generated_by=generated_by)
    else:
        summary = _build_csv(output_path, data)

    file_size = output_path.stat().st_size if output_path.is_file() else 0
    return {
        "success": True,
        "report_uid": report_uid,
        "report_type": report_type,
        "report_format": fmt,
        "title": data["title"],
        "filename": filename,
        "file_size": file_size,
        "summary": summary,
    }
