"""Phishing Email Analyzer routes."""

from __future__ import annotations

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import PhishingAnalysis, SecurityEvent
from app.services.alert_service import create_alert
from app.services.phishing_detector import analyze_phishing_email, get_phishing_engine
from app.utils.helpers import safe_json_dumps

phishing_bp = Blueprint("phishing", __name__, url_prefix="/phishing")


@phishing_bp.route("", methods=["GET"])
@login_required
def index():
    q = PhishingAnalysis.query
    if not current_user.is_admin:
        q = q.filter_by(user_id=current_user.id)
    analyses = q.order_by(PhishingAnalysis.created_at.desc()).limit(30).all()

    selected_id = request.args.get("analysis_id", type=int)
    selected = None
    if selected_id:
        cand = db.session.get(PhishingAnalysis, selected_id)
        if cand and (current_user.is_admin or cand.user_id == current_user.id):
            selected = cand
    if not selected and analyses:
        selected = analyses[0]

    engine = get_phishing_engine()
    return render_template(
        "phishing.html",
        analyses=analyses,
        selected=selected,
        model_metrics=engine.metrics,
    )


@phishing_bp.route("/analyze", methods=["POST"])
@login_required
def analyze():
    sender = (request.form.get("sender", "") or "").strip()
    subject = (request.form.get("subject", "") or "").strip()
    urls = (request.form.get("urls", "") or "").strip()
    content = (request.form.get("content", "") or "").strip()

    result = analyze_phishing_email(
        content=content,
        sender=sender,
        subject=subject,
        extra_urls=urls,
    )

    if not result.get("success"):
        flash(result.get("error", "Please enter email details or URLs to analyze."), "danger")
        return redirect(url_for("phishing.index")), 400

    record = PhishingAnalysis(
        user_id=current_user.id,
        sender=result["sender"][:255],
        subject=result["subject"][:255],
        urls_json=safe_json_dumps(result["urls"]),
        content_preview=result["content_preview"],
        risk_level=result["risk_level"],
        risk_score=result["risk_score"],
        detection_method=result["detection_method"],
        ml_probability=result["ml_probability"],
        rule_score=result["rule_score"],
        indicators_json=safe_json_dumps(result["indicators"]),
        explanation=result["explanation"],
        recommended_action=result["recommended_action"],
    )
    db.session.add(record)

    sev_map = {"High Risk": "High", "Suspicious": "Medium", "Low Risk": "Low"}
    db.session.add(
        SecurityEvent(
            user_id=current_user.id,
            source_ip="Email",
            username=result["sender"][:120],
            event_type=f"Phishing Analysis ({result['risk_level']})",
            severity=sev_map.get(result["risk_level"], "Low"),
            source_module="Phishing Analyzer",
            detection_reason=result["explanation"],
            recommended_action=result["recommended_action"],
        )
    )

    if result["risk_level"] in {"High Risk", "Suspicious"}:
        create_alert(
            user_id=current_user.id,
            title=f"{result['risk_level']} Phishing Email: {result['subject'][:90]}",
            category="Phishing Attempt",
            severity="High" if result["risk_level"] == "High Risk" else "Medium",
            source_module="Phishing Analyzer",
            target=result["sender"][:120],
            description=result["explanation"],
            recommended_action=result["recommended_action"],
        )

    db.session.commit()
    flash(
        f"Phishing assessment complete: {result['risk_level']} (Score: {result['risk_score']:.1f}/100).",
        "danger" if result["risk_level"] == "High Risk" else ("warning" if result["risk_level"] == "Suspicious" else "success"),
    )
    return redirect(url_for("phishing.index", analysis_id=record.id))


@phishing_bp.route("/model-info", methods=["GET"])
@login_required
def model_info():
    engine = get_phishing_engine()
    return jsonify(engine.metrics)


@phishing_bp.route("/<int:analysis_id>", methods=["GET"])
@login_required
def detail(analysis_id: int):
    record = db.session.get(PhishingAnalysis, analysis_id)
    if not record:
        abort(404)
    if not current_user.is_admin and record.user_id != current_user.id:
        abort(403)
    return redirect(url_for("phishing.index", analysis_id=record.id))
