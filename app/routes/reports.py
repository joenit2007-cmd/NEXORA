"""Downloadable PDF & CSV Security Reports routes."""

from __future__ import annotations

from pathlib import Path
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import Report
from app.security.validators import is_safe_path
from app.services.report_service import REPORT_TYPES, generate_security_report

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("", methods=["GET"])
@login_required
def index():
    q = Report.query
    if not current_user.is_admin:
        q = q.filter_by(user_id=current_user.id)
    reports = q.order_by(Report.created_at.desc()).limit(50).all()
    return render_template("reports.html", reports=reports, report_types=REPORT_TYPES)


@reports_bp.route("/generate", methods=["POST"])
@login_required
def generate():
    report_type = (request.form.get("report_type", "overall_summary") or "overall_summary").strip()
    report_format = (request.form.get("report_format", "pdf") or "pdf").strip().lower()

    reports_dir = Path(current_app.config["REPORTS_FOLDER"])
    result = generate_security_report(
        reports_dir=reports_dir,
        user_id=current_user.id,
        generated_by=current_user.username,
        report_type=report_type,
        report_format=report_format,
        is_admin=current_user.is_admin,
    )

    if not result.get("success"):
        flash(result.get("error", "Report generation failed."), "danger")
        return redirect(url_for("reports.index")), 400

    record = Report(
        report_uid=result["report_uid"],
        user_id=current_user.id,
        report_type=result["report_type"],
        report_format=result["report_format"],
        title=result["title"],
        filename=result["filename"],
        file_size=result["file_size"],
        summary=result["summary"],
    )
    db.session.add(record)
    db.session.commit()

    flash(f"Generated {result['report_format'].upper()} report '{result['title']}' ({result['report_uid']}).", "success")
    return redirect(url_for("reports.index"))


@reports_bp.route("/<int:report_id>/download", methods=["GET"])
@login_required
def download(report_id: int):
    record = db.session.get(Report, report_id)
    if not record:
        abort(404)
    if not current_user.is_admin and record.user_id != current_user.id:
        abort(403)

    reports_dir = Path(current_app.config["REPORTS_FOLDER"])
    file_path = reports_dir / record.filename
    if not is_safe_path(reports_dir, file_path) or not file_path.is_file():
        flash("Report file could not be located on disk.", "danger")
        return redirect(url_for("reports.index"))

    mimetype = "application/pdf" if record.report_format == "pdf" else "text/csv"
    return send_file(file_path, mimetype=mimetype, as_attachment=True, download_name=record.filename)


@reports_bp.route("/<int:report_id>/delete", methods=["POST"])
@login_required
def delete(report_id: int):
    record = db.session.get(Report, report_id)
    if not record:
        abort(404)
    if not current_user.is_admin and record.user_id != current_user.id:
        abort(403)

    reports_dir = Path(current_app.config["REPORTS_FOLDER"])
    file_path = reports_dir / record.filename
    if is_safe_path(reports_dir, file_path) and file_path.is_file():
        try:
            file_path.unlink()
        except OSError:
            pass

    db.session.delete(record)
    db.session.commit()
    flash(f"Deleted report {record.report_uid}.", "info")
    return redirect(url_for("reports.index"))
