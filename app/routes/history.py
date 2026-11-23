"""Unified Scan & Analysis History route."""

from __future__ import annotations

from flask import Blueprint, render_template, request, url_for
from flask_login import current_user, login_required

from app.models import LogAnalysis, NetworkScan, PhishingAnalysis, VulnerabilityAssessment

history_bp = Blueprint("history", __name__, url_prefix="/history")


@history_bp.route("", methods=["GET"])
@login_required
def index():
    module_filter = request.args.get("module", "").strip()
    search = request.args.get("q", "").strip().lower()

    def scoped(model):
        q = model.query
        if not current_user.is_admin:
            q = q.filter_by(user_id=current_user.id)
        return q

    timeline: list[dict] = []

    if module_filter in {"", "Log Analyzer"}:
        for item in scoped(LogAnalysis).order_by(LogAnalysis.created_at.desc()).limit(50).all():
            timeline.append(
                {
                    "timestamp": item.created_at,
                    "module": "Log Analyzer",
                    "target": item.original_filename,
                    "status": item.status,
                    "summary": f"{item.parsed_events} events, {item.failed_logins} failed logins, {item.brute_force_count} brute-force",
                    "severity": "High" if item.brute_force_count > 0 else ("Medium" if item.failed_logins > 0 else "Low"),
                    "url": url_for("logs.detail", analysis_id=item.id),
                    "is_demo": item.is_demo,
                }
            )

    if module_filter in {"", "Network Monitor"}:
        for item in scoped(NetworkScan).order_by(NetworkScan.created_at.desc()).limit(50).all():
            timeline.append(
                {
                    "timestamp": item.created_at,
                    "module": "Network Monitor",
                    "target": item.target,
                    "status": item.status,
                    "summary": f"{item.scan_type} via {item.tool_used} — {item.open_ports_count} open port(s)",
                    "severity": "Medium" if item.open_ports_count > 0 else "Low",
                    "url": url_for("network.index", scan_id=item.id),
                    "is_demo": item.is_demo,
                }
            )

    if module_filter in {"", "Vulnerability Assessment"}:
        for item in scoped(VulnerabilityAssessment).order_by(VulnerabilityAssessment.created_at.desc()).limit(50).all():
            sev = (
                "Critical"
                if item.critical_count > 0
                else ("High" if item.high_count > 0 else ("Medium" if item.medium_count > 0 else "Low"))
            )
            timeline.append(
                {
                    "timestamp": item.created_at,
                    "module": "Vulnerability Assessment",
                    "target": item.target,
                    "status": item.status,
                    "summary": f"{item.findings_count} finding(s) (C:{item.critical_count} H:{item.high_count} M:{item.medium_count} L:{item.low_count})",
                    "severity": sev,
                    "url": url_for("vulnerabilities.index", assessment_id=item.id),
                    "is_demo": item.is_demo,
                }
            )

    if module_filter in {"", "Phishing Analyzer"}:
        for item in scoped(PhishingAnalysis).order_by(PhishingAnalysis.created_at.desc()).limit(50).all():
            sev = "High" if item.risk_level == "High Risk" else ("Medium" if item.risk_level == "Suspicious" else "Low")
            timeline.append(
                {
                    "timestamp": item.created_at,
                    "module": "Phishing Analyzer",
                    "target": item.sender or item.subject or "Email",
                    "status": item.risk_level,
                    "summary": f"Score {item.risk_score:.1f}/100 ({item.detection_method})",
                    "severity": sev,
                    "url": url_for("phishing.index", analysis_id=item.id),
                    "is_demo": item.is_demo,
                }
            )

    if search:
        timeline = [
            row
            for row in timeline
            if search in row["target"].lower()
            or search in row["summary"].lower()
            or search in row["module"].lower()
        ]

    timeline.sort(key=lambda r: r["timestamp"], reverse=True)
    return render_template(
        "history.html",
        timeline=timeline,
        module_filter=module_filter,
        search_q=search,
    )
