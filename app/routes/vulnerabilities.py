"""Vulnerability Assessment routes."""

from __future__ import annotations

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import SecurityEvent, VulnerabilityAssessment, VulnerabilityFinding
from app.services.alert_service import create_alert
from app.services.network_monitor import get_nmap_status
from app.services.vuln_assessor import run_vulnerability_assessment
from app.utils.helpers import safe_json_dumps

vuln_bp = Blueprint("vulnerabilities", __name__, url_prefix="/vulnerabilities")


@vuln_bp.route("", methods=["GET"])
@login_required
def index():
    q = VulnerabilityAssessment.query
    if not current_user.is_admin:
        q = q.filter_by(user_id=current_user.id)
    assessments = q.order_by(VulnerabilityAssessment.created_at.desc()).limit(25).all()

    selected_id = request.args.get("assessment_id", type=int)
    selected = None
    if selected_id:
        cand = db.session.get(VulnerabilityAssessment, selected_id)
        if cand and (current_user.is_admin or cand.user_id == current_user.id):
            selected = cand
    if not selected and assessments:
        selected = assessments[0]

    selected_findings = (
        selected.findings.order_by(VulnerabilityFinding.id.asc()).all() if selected else []
    )
    nmap_status = get_nmap_status(current_app.config.get("NMAP_PATH", ""))

    return render_template(
        "vulnerabilities.html",
        assessments=assessments,
        selected=selected,
        selected_findings=selected_findings,
        nmap_status=nmap_status,
    )


@vuln_bp.route("/assess", methods=["POST"])
@login_required
def assess():
    target = (request.form.get("target", "") or "").strip()
    port_spec = (request.form.get("port_spec", "") or "").strip()
    authorized_confirmed = request.form.get("authorized_confirmed") in {"on", "true", "1", "yes"}

    result = run_vulnerability_assessment(
        target=target,
        port_spec=port_spec,
        authorized_confirmed=authorized_confirmed,
        configured_nmap_path=current_app.config.get("NMAP_PATH", ""),
    )

    if not result.get("success"):
        flash(result.get("error", "Vulnerability assessment failed validation."), "danger")
        return redirect(url_for("vulnerabilities.index")), 400

    sev = result["severity_counts"]
    assessment = VulnerabilityAssessment(
        user_id=current_user.id,
        target=result["target"],
        port_spec=result["port_spec"],
        tool_used=result["tool_used"],
        authorized_confirmed=True,
        open_ports_count=result["open_ports_count"],
        findings_count=result["findings_count"],
        critical_count=sev["Critical"],
        high_count=sev["High"],
        medium_count=sev["Medium"],
        low_count=sev["Low"],
        info_count=sev["Informational"],
        services_json=safe_json_dumps(result["open_ports"]),
        summary=result["summary"],
        status="Completed",
    )
    db.session.add(assessment)
    db.session.flush()

    for f in result["findings"]:
        db.session.add(
            VulnerabilityFinding(
                assessment_id=assessment.id,
                user_id=current_user.id,
                title=f["title"],
                affected_host=f["affected_host"],
                port_service=f["port_service"],
                severity=f["severity"],
                description=f["description"],
                evidence=f["evidence"],
                potential_impact=f["potential_impact"],
                recommended_remediation=f["recommended_remediation"],
            )
        )
        if f["severity"] in {"Critical", "High", "Medium"}:
            create_alert(
                user_id=current_user.id,
                title=f"{f['title']} ({f['affected_host']})",
                category="Vulnerability Finding",
                severity=f["severity"],
                source_module="Vulnerability Assessment",
                source_ip=f["affected_host"],
                target=f["port_service"],
                description=f"{f['description']} Evidence: {f['evidence']}",
                recommended_action=f["recommended_remediation"],
            )

    db.session.add(
        SecurityEvent(
            user_id=current_user.id,
            source_ip=result["target"],
            username=current_user.username,
            event_type="Vulnerability Assessment Completed",
            severity="High" if (sev["Critical"] or sev["High"]) else "Low",
            source_module="Vulnerability Assessment",
            detection_reason=result["summary"],
            recommended_action="Review prioritized findings and apply recommended security hardening.",
        )
    )

    db.session.commit()
    flash(result["summary"], "success")
    return redirect(url_for("vulnerabilities.index", assessment_id=assessment.id))


@vuln_bp.route("/<int:assessment_id>", methods=["GET"])
@login_required
def detail(assessment_id: int):
    assessment = db.session.get(VulnerabilityAssessment, assessment_id)
    if not assessment:
        abort(404)
    if not current_user.is_admin and assessment.user_id != current_user.id:
        abort(403)
    return redirect(url_for("vulnerabilities.index", assessment_id=assessment.id))
