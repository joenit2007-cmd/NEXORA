"""Security Dashboard routes and live statistics API."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.models import (
    LogAnalysis,
    NetworkScan,
    PhishingAnalysis,
    SecurityAlert,
    SecurityEvent,
    VulnerabilityAssessment,
    VulnerabilityFinding,
)
from app.services.sample_seeder import clear_demo_sample_data, load_demo_sample_data
from app.utils.helpers import utc_now

dashboard_bp = Blueprint("dashboard", __name__)


def _parse_date_range(days_param: str, start_str: str, end_str: str) -> tuple[datetime | None, datetime | None, str]:
    now = utc_now()
    if start_str or end_str:
        start_dt = None
        end_dt = None
        try:
            if start_str:
                start_dt = datetime.strptime(start_str, "%Y-%m-%d")
            if end_str:
                end_dt = datetime.strptime(end_str, "%Y-%m-%d") + timedelta(days=1) - timedelta(seconds=1)
            return start_dt, end_dt, "custom"
        except ValueError:
            pass

    if days_param in {"1", "7", "30", "90"}:
        d = int(days_param)
        return now - timedelta(days=d), now, days_param

    return None, None, "all"


def _compute_dashboard_stats(start_dt: datetime | None, end_dt: datetime | None) -> dict:
    is_admin = current_user.is_admin
    uid = current_user.id

    def scoped(model, ts_col):
        q = model.query
        if not is_admin:
            q = q.filter_by(user_id=uid)
        if start_dt:
            q = q.filter(ts_col >= start_dt)
        if end_dt:
            q = q.filter(ts_col <= end_dt)
        return q

    events = scoped(SecurityEvent, SecurityEvent.timestamp).order_by(SecurityEvent.timestamp.desc()).all()
    alerts = scoped(SecurityAlert, SecurityAlert.created_at).order_by(SecurityAlert.created_at.desc()).all()
    scans = scoped(NetworkScan, NetworkScan.created_at).order_by(NetworkScan.created_at.desc()).all()
    findings = scoped(VulnerabilityFinding, VulnerabilityFinding.created_at).order_by(VulnerabilityFinding.created_at.desc()).all()
    phishing_list = scoped(PhishingAnalysis, PhishingAnalysis.created_at).order_by(PhishingAnalysis.created_at.desc()).all()
    log_jobs = scoped(LogAnalysis, LogAnalysis.created_at).order_by(LogAnalysis.created_at.desc()).all()

    alert_sev = Counter(a.severity for a in alerts)
    vuln_sev = Counter(f.severity for f in findings)

    failed_logins = sum(
        1
        for e in events
        if any(k in (e.event_type or "").lower() for k in ("failed", "invalid user", "brute-force"))
    )

    suspicious_ip_set = set()
    for job in log_jobs:
        for ip_entry in job.suspicious_ips:
            if ip_entry.get("ip"):
                suspicious_ip_set.add(ip_entry["ip"])
    for a in alerts:
        if a.source_ip and a.source_ip not in {"Local", "N/A", "Unknown"}:
            suspicious_ip_set.add(a.source_ip)

    phishing_attempts = sum(1 for p in phishing_list if p.risk_level in {"High Risk", "Suspicious"})
    total_open_ports_observed = sum(s.open_ports_count for s in scans)

    # Activity timeline grouped by date (last 10 distinct active dates or last 7 days)
    date_counter = Counter()
    for e in events:
        date_counter[e.timestamp.strftime("%Y-%m-%d")] += 1
    for a in alerts:
        date_counter[a.created_at.strftime("%Y-%m-%d")] += 1
    for s in scans:
        date_counter[s.created_at.strftime("%Y-%m-%d")] += 1
    for p in phishing_list:
        date_counter[p.created_at.strftime("%Y-%m-%d")] += 1

    if date_counter:
        sorted_dates = sorted(date_counter.keys())[-10:]
        timeline_labels = sorted_dates
        timeline_values = [date_counter[d] for d in sorted_dates]
    else:
        today = utc_now().date()
        timeline_labels = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
        timeline_values = [0] * 7

    has_demo_data = any(a.is_demo for a in alerts) or any(e.is_demo for e in events) or any(s.is_demo for s in scans)

    return {
        "kpis": {
            "total_events": len(events),
            "critical_alerts": alert_sev.get("Critical", 0),
            "high_alerts": alert_sev.get("High", 0),
            "medium_alerts": alert_sev.get("Medium", 0),
            "low_alerts": alert_sev.get("Low", 0),
            "open_alerts": sum(1 for a in alerts if a.status == "Open"),
            "failed_logins": failed_logins,
            "suspicious_ips": len(suspicious_ip_set),
            "detected_vulnerabilities": len(findings),
            "phishing_attempts": phishing_attempts,
            "network_scans": len(scans),
            "open_ports_observed": total_open_ports_observed,
        },
        "charts": {
            "timeline_labels": timeline_labels,
            "timeline_values": timeline_values,
            "severity_distribution": {
                "Critical": alert_sev.get("Critical", 0) + vuln_sev.get("Critical", 0),
                "High": alert_sev.get("High", 0) + vuln_sev.get("High", 0),
                "Medium": alert_sev.get("Medium", 0) + vuln_sev.get("Medium", 0),
                "Low": alert_sev.get("Low", 0) + vuln_sev.get("Low", 0),
                "Informational": vuln_sev.get("Informational", 0),
            },
            "vuln_breakdown": {
                "Critical": vuln_sev.get("Critical", 0),
                "High": vuln_sev.get("High", 0),
                "Medium": vuln_sev.get("Medium", 0),
                "Low": vuln_sev.get("Low", 0),
                "Informational": vuln_sev.get("Informational", 0),
            },
        },
        "recent_events": events[:10],
        "latest_alerts": alerts[:8],
        "recent_scans": scans[:6],
        "recent_findings": findings[:6],
        "has_demo_data": has_demo_data,
    }


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    days_param = request.args.get("days", "all")
    start_str = request.args.get("start_date", "").strip()
    end_str = request.args.get("end_date", "").strip()

    start_dt, end_dt, active_range = _parse_date_range(days_param, start_str, end_str)
    stats = _compute_dashboard_stats(start_dt, end_dt)

    return render_template(
        "dashboard.html",
        stats=stats,
        active_range=active_range,
        start_date=start_str,
        end_date=end_str,
    )


@dashboard_bp.route("/api/dashboard/stats")
@login_required
def api_stats():
    days_param = request.args.get("days", "all")
    start_str = request.args.get("start_date", "").strip()
    end_str = request.args.get("end_date", "").strip()

    start_dt, end_dt, active_range = _parse_date_range(days_param, start_str, end_str)
    stats = _compute_dashboard_stats(start_dt, end_dt)
    return jsonify(
        {
            "active_range": active_range,
            "kpis": stats["kpis"],
            "charts": stats["charts"],
            "has_demo_data": stats["has_demo_data"],
        }
    )


@dashboard_bp.route("/dashboard/load-demo", methods=["POST"])
@login_required
def load_demo():
    counts = load_demo_sample_data(current_user.id, current_app.config["SAMPLE_DATA_DIR"])
    flash(
        f"Loaded clearly marked [DEMO] dataset via live NEXORA analyzers: "
        f"{counts['events']} events, {counts['alerts']} alerts, {counts['findings']} findings, {counts['phishing']} phishing analyses.",
        "success",
    )
    return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/dashboard/clear-demo", methods=["POST"])
@login_required
def clear_demo():
    removed = clear_demo_sample_data(current_user.id)
    flash(f"Cleared {removed} demonstration record(s) from your workspace.", "info")
    return redirect(url_for("dashboard.index"))
