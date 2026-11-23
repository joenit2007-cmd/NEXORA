"""Network Monitor and authorized Nmap scanning routes."""

from __future__ import annotations

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import NetworkScan, SecurityEvent
from app.services.alert_service import create_alert
from app.services.network_monitor import (
    get_active_connections,
    get_local_network_info,
    get_nmap_status,
    run_authorized_scan,
)
from app.utils.helpers import safe_json_dumps

network_bp = Blueprint("network", __name__, url_prefix="/network")


@network_bp.route("", methods=["GET"])
@login_required
def index():
    local_info = get_local_network_info()
    conn_info = get_active_connections(limit=60)
    nmap_status = get_nmap_status(current_app.config.get("NMAP_PATH", ""))

    q = NetworkScan.query
    if not current_user.is_admin:
        q = q.filter_by(user_id=current_user.id)
    scans = q.order_by(NetworkScan.created_at.desc()).limit(25).all()

    selected_id = request.args.get("scan_id", type=int)
    selected_scan = None
    if selected_id:
        cand = db.session.get(NetworkScan, selected_id)
        if cand and (current_user.is_admin or cand.user_id == current_user.id):
            selected_scan = cand
    if not selected_scan and scans:
        selected_scan = scans[0]

    return render_template(
        "network.html",
        local_info=local_info,
        conn_info=conn_info,
        nmap_status=nmap_status,
        scans=scans,
        selected_scan=selected_scan,
    )


@network_bp.route("/scan", methods=["POST"])
@login_required
def scan():
    target = (request.form.get("target", "") or "").strip()
    scan_type = (request.form.get("scan_type", "quick_ports") or "quick_ports").strip()
    port_spec = (request.form.get("port_spec", "") or "").strip()
    authorized_confirmed = request.form.get("authorized_confirmed") in {"on", "true", "1", "yes"}

    if scan_type not in {"quick_ports", "service_version"}:
        scan_type = "quick_ports"

    result = run_authorized_scan(
        target=target,
        scan_type=scan_type,
        port_spec=port_spec,
        authorized_confirmed=authorized_confirmed,
        configured_nmap_path=current_app.config.get("NMAP_PATH", ""),
    )

    if not result.get("success"):
        flash(result.get("error", "Scan validation failed."), "danger")
        return redirect(url_for("network.index")), 400

    record = NetworkScan(
        user_id=current_user.id,
        target=result["target"],
        scan_type=result["scan_type"],
        port_spec=result["port_spec"],
        tool_used=result["tool_used"],
        nmap_available=result["nmap_available"],
        authorized_confirmed=True,
        host_status=result["host_status"],
        open_ports_count=result["open_ports_count"],
        open_ports_json=safe_json_dumps(result["open_ports"]),
        summary=result["summary"],
        raw_output=result["raw_output"],
        status="Completed",
    )
    db.session.add(record)

    db.session.add(
        SecurityEvent(
            user_id=current_user.id,
            source_ip=result["target"],
            username=current_user.username,
            event_type="Authorized Network Scan",
            severity="Low",
            source_module="Network Monitor",
            detection_reason=result["summary"],
            recommended_action="Review discovered open ports and verify only authorized services are listening.",
        )
    )

    # Alert automatically if high-risk legacy ports (Telnet 23, FTP 21, SMB 445, RDP 3389) are open
    risky_ports = [p for p in result["open_ports"] if p["port"] in {21, 23, 445, 3389, 5900, 6379}]
    if risky_ports:
        port_str = ", ".join(f"{p['port']}/{p['service']}" for p in risky_ports)
        create_alert(
            user_id=current_user.id,
            title=f"Sensitive Listening Service(s) Discovered on {result['target']}",
            category="Network Exposure",
            severity="High" if any(p["port"] == 23 for p in risky_ports) else "Medium",
            source_module="Network Monitor",
            source_ip=result["target"],
            target=port_str,
            description=f"Authorized scan of {result['target']} identified sensitive listening port(s): {port_str}.",
            recommended_action="Verify firewall restrictions, disable cleartext protocols, and run a Vulnerability Assessment.",
        )

    db.session.commit()
    flash(result["summary"], "success")
    return redirect(url_for("network.index", scan_id=record.id))


@network_bp.route("/api/live", methods=["GET"])
@login_required
def api_live():
    return jsonify(
        {
            "local_info": get_local_network_info(),
            "connections": get_active_connections(limit=60),
            "nmap_status": get_nmap_status(current_app.config.get("NMAP_PATH", "")),
        }
    )


@network_bp.route("/<int:scan_id>", methods=["GET"])
@login_required
def detail_json(scan_id: int):
    record = db.session.get(NetworkScan, scan_id)
    if not record:
        abort(404)
    if not current_user.is_admin and record.user_id != current_user.id:
        abort(403)
    return jsonify(
        {
            "id": record.id,
            "target": record.target,
            "scan_type": record.scan_type,
            "tool_used": record.tool_used,
            "host_status": record.host_status,
            "open_ports": record.open_ports,
            "summary": record.summary,
            "created_at": record.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }
    )
