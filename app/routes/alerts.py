"""Centralized Security Alert Management routes."""

from __future__ import annotations

import csv
import io
from flask import Blueprint, Response, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import SecurityAlert
from app.services.alert_service import update_alert_status

alerts_bp = Blueprint("alerts", __name__, url_prefix="/alerts")


def _filtered_alerts_query():
    q = SecurityAlert.query
    if not current_user.is_admin:
        q = q.filter_by(user_id=current_user.id)

    severity = request.args.get("severity", "").strip()
    status = request.args.get("status", "").strip()
    module = request.args.get("module", "").strip()
    search = request.args.get("q", "").strip()

    if severity:
        q = q.filter(SecurityAlert.severity == severity)
    if status:
        q = q.filter(SecurityAlert.status == status)
    if module:
        q = q.filter(SecurityAlert.source_module == module)
    if search:
        like_term = f"%{search}%"
        q = q.filter(
            (SecurityAlert.alert_uid.ilike(like_term))
            | (SecurityAlert.title.ilike(like_term))
            | (SecurityAlert.description.ilike(like_term))
            | (SecurityAlert.source_ip.ilike(like_term))
            | (SecurityAlert.category.ilike(like_term))
        )
    return q, {"severity": severity, "status": status, "module": module, "q": search}


@alerts_bp.route("", methods=["GET"])
@login_required
def index():
    q, filters = _filtered_alerts_query()
    alerts = q.order_by(SecurityAlert.created_at.desc()).limit(200).all()

    base_q = SecurityAlert.query if current_user.is_admin else SecurityAlert.query.filter_by(user_id=current_user.id)
    summary = {
        "total": base_q.count(),
        "open": base_q.filter_by(status="Open").count(),
        "reviewed": base_q.filter_by(status="Reviewed").count(),
        "resolved": base_q.filter_by(status="Resolved").count(),
        "critical": base_q.filter_by(severity="Critical").count(),
        "high": base_q.filter_by(severity="High").count(),
    }

    return render_template(
        "alerts.html",
        alerts=alerts,
        filters=filters,
        summary=summary,
    )


@alerts_bp.route("/<int:alert_id>/status", methods=["POST"])
@login_required
def change_status(alert_id: int):
    alert = db.session.get(SecurityAlert, alert_id)
    if not alert:
        abort(404)
    if not current_user.is_admin and alert.user_id != current_user.id:
        abort(403)

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        new_status = (payload.get("status") or "").strip()
        notes = payload.get("notes")
    else:
        new_status = (request.form.get("status") or "").strip()
        notes = request.form.get("notes")

    ok, msg = update_alert_status(alert, new_status, current_user.id, notes=notes)
    if request.is_json:
        return jsonify({"success": ok, "message": msg, "alert": alert.to_dict()}), (200 if ok else 400)

    flash(msg, "success" if ok else "danger")
    return redirect(request.referrer or url_for("alerts.index"))


@alerts_bp.route("/export", methods=["GET"])
@login_required
def export_csv():
    q, _ = _filtered_alerts_query()
    alerts = q.order_by(SecurityAlert.created_at.desc()).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "Alert ID",
            "Timestamp",
            "Severity",
            "Status",
            "Category",
            "Source Module",
            "Source IP",
            "Target",
            "Title",
            "Description",
            "Recommended Action",
        ]
    )
    for a in alerts:
        writer.writerow(
            [
                a.alert_uid,
                a.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                a.severity,
                a.status,
                a.category,
                a.source_module,
                a.source_ip or "N/A",
                a.target or "N/A",
                a.title,
                a.description,
                a.recommended_action or "",
            ]
        )

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="nexora_security_alerts.csv"'},
    )
