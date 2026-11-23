"""Intelligent Log Analyzer routes."""

from __future__ import annotations

from pathlib import Path
from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import LogAnalysis, SecurityEvent
from app.security.validators import is_safe_path, validate_log_upload
from app.services.alert_service import create_alert
from app.services.log_analyzer import analyze_log_content, export_events_to_csv
from app.utils.helpers import build_safe_upload_name, safe_json_dumps

logs_bp = Blueprint("logs", __name__, url_prefix="/logs")

SAMPLE_FILES = {
    "auth_sample.log": "SSH & Linux Authentication Log (Brute-Force + Privilege Escalation)",
    "security_events_sample.csv": "Structured CSV Security Events (Failed Logins + Web Probes)",
    "system_sample.txt": "Mixed System & Application Log (Errors + Unauthorized Access)",
}


def _persist_log_analysis(
    raw_bytes: bytes,
    original_filename: str,
    stored_filename: str,
    threshold: int,
    window: int,
    is_demo: bool = False,
) -> LogAnalysis:
    result = analyze_log_content(
        raw_bytes,
        original_filename,
        brute_force_threshold=threshold,
        window_minutes=window,
    )

    ext = Path(original_filename).suffix.lower().lstrip(".") or "log"
    analysis = LogAnalysis(
        user_id=current_user.id,
        original_filename=original_filename,
        stored_filename=stored_filename,
        file_size=len(raw_bytes),
        file_format=ext,
        total_lines=result["summary"]["total_lines"],
        parsed_events=result["summary"]["parsed_events"],
        failed_logins=result["summary"]["failed_logins"],
        brute_force_count=result["summary"]["brute_force_count"],
        unusual_activity_count=result["summary"]["unusual_activity_count"],
        suspicious_ips_json=safe_json_dumps(result["suspicious_ips"]),
        threshold_config_json=safe_json_dumps(result["threshold_config"]),
        summary_json=safe_json_dumps(result["summary"]),
        status="Completed",
        is_demo=is_demo,
    )
    db.session.add(analysis)
    db.session.flush()

    for ev in result["events"]:
        db.session.add(
            SecurityEvent(
                user_id=current_user.id,
                log_analysis_id=analysis.id,
                timestamp=ev["timestamp"],
                source_ip=ev["source_ip"],
                username=ev["username"],
                event_type=ev["event_type"],
                severity=ev["severity"],
                source_module="Log Analyzer",
                raw_message=ev["raw_message"],
                detection_reason=ev["detection_reason"],
                recommended_action=ev["recommended_action"],
                is_demo=is_demo,
            )
        )

    for alert_data in result["alerts"]:
        create_alert(
            user_id=current_user.id,
            title=alert_data["title"],
            category=alert_data["category"],
            severity=alert_data["severity"],
            source_module="Log Analyzer",
            source_ip=alert_data["source_ip"],
            target=alert_data["target"],
            description=alert_data["description"],
            recommended_action=alert_data["recommended_action"],
            is_demo=is_demo,
        )

    db.session.commit()
    return analysis


@logs_bp.route("", methods=["GET"])
@login_required
def index():
    q = LogAnalysis.query
    if not current_user.is_admin:
        q = q.filter_by(user_id=current_user.id)
    analyses = q.order_by(LogAnalysis.created_at.desc()).limit(30).all()

    latest = analyses[0] if analyses else None
    latest_events = (
        latest.events.order_by(SecurityEvent.timestamp.desc()).limit(100).all() if latest else []
    )
    return render_template(
        "logs.html",
        analyses=analyses,
        latest=latest,
        latest_events=latest_events,
        sample_files=SAMPLE_FILES,
    )


@logs_bp.route("/upload", methods=["POST"])
@login_required
def upload():
    file_obj = request.files.get("log_file")
    if not file_obj or not file_obj.filename:
        flash("Please choose a .log, .txt, or .csv file to analyze.", "danger")
        return redirect(url_for("logs.index")), 400

    try:
        threshold = int(request.form.get("brute_force_threshold", current_user.brute_force_threshold))
        window = int(request.form.get("window_minutes", current_user.brute_force_window_minutes))
    except ValueError:
        threshold = current_user.brute_force_threshold
        window = current_user.brute_force_window_minutes

    raw_bytes = file_obj.read()
    max_bytes = current_app.config["MAX_CONTENT_LENGTH"]
    valid, err = validate_log_upload(file_obj.filename, raw_bytes, max_bytes)
    if not valid:
        flash(err, "danger")
        return redirect(url_for("logs.index")), 400

    upload_dir: Path = Path(current_app.config["UPLOAD_FOLDER"])
    upload_dir.mkdir(parents=True, exist_ok=True)
    stored_name = build_safe_upload_name(file_obj.filename)
    dest_path = upload_dir / stored_name
    if not is_safe_path(upload_dir, dest_path):
        flash("Invalid file path detected.", "danger")
        return redirect(url_for("logs.index")), 400

    # Save passively as read-only data; never execute uploaded files
    dest_path.write_bytes(raw_bytes)

    analysis = _persist_log_analysis(
        raw_bytes=raw_bytes,
        original_filename=Path(file_obj.filename).name[:255],
        stored_filename=stored_name,
        threshold=threshold,
        window=window,
        is_demo=False,
    )

    flash(
        f"Log analysis complete: parsed {analysis.parsed_events} events, "
        f"{analysis.failed_logins} failed logins, {analysis.brute_force_count} brute-force pattern(s).",
        "success",
    )
    return redirect(url_for("logs.detail", analysis_id=analysis.id))


@logs_bp.route("/run-sample/<sample_name>", methods=["POST"])
@login_required
def run_sample(sample_name: str):
    if sample_name not in SAMPLE_FILES:
        abort(404)

    sample_dir = Path(current_app.config["SAMPLE_DATA_DIR"])
    sample_path = sample_dir / sample_name
    if not sample_path.is_file() or not is_safe_path(sample_dir, sample_path):
        flash("Sample log file is unavailable.", "danger")
        return redirect(url_for("logs.index"))

    raw_bytes = sample_path.read_bytes()
    analysis = _persist_log_analysis(
        raw_bytes=raw_bytes,
        original_filename=f"[SAMPLE] {sample_name}",
        stored_filename=f"sample_{sample_name}",
        threshold=current_user.brute_force_threshold,
        window=current_user.brute_force_window_minutes,
        is_demo=True,
    )
    flash(f"Analyzed bundled sample file '{sample_name}' ({analysis.parsed_events} events parsed).", "success")
    return redirect(url_for("logs.detail", analysis_id=analysis.id))


@logs_bp.route("/<int:analysis_id>", methods=["GET"])
@login_required
def detail(analysis_id: int):
    analysis = db.session.get(LogAnalysis, analysis_id)
    if not analysis:
        abort(404)
    if not current_user.is_admin and analysis.user_id != current_user.id:
        abort(403)

    severity_filter = request.args.get("severity", "").strip()
    search_q = request.args.get("q", "").strip().lower()

    ev_query = analysis.events.order_by(SecurityEvent.timestamp.desc())
    if severity_filter:
        ev_query = ev_query.filter_by(severity=severity_filter)
    events = ev_query.all()

    if search_q:
        events = [
            e
            for e in events
            if search_q in (e.source_ip or "").lower()
            or search_q in (e.username or "").lower()
            or search_q in (e.event_type or "").lower()
            or search_q in (e.detection_reason or "").lower()
        ]

    return render_template(
        "log_detail.html",
        analysis=analysis,
        events=events,
        severity_filter=severity_filter,
        search_q=search_q,
    )


@logs_bp.route("/<int:analysis_id>/export", methods=["GET"])
@login_required
def export_csv(analysis_id: int):
    analysis = db.session.get(LogAnalysis, analysis_id)
    if not analysis:
        abort(404)
    if not current_user.is_admin and analysis.user_id != current_user.id:
        abort(403)

    events = [e.to_dict() for e in analysis.events.order_by(SecurityEvent.timestamp.desc()).all()]
    csv_body = export_events_to_csv(events)
    filename = f"nexora_log_analysis_{analysis.id}.csv"
    return Response(
        csv_body,
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
