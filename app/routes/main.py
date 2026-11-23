"""About NEXORA and production Health Check routes."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template
from flask_login import login_required
from sqlalchemy import text

from app.extensions import db
from app.services.network_monitor import get_nmap_status
from app.services.phishing_detector import get_phishing_engine
from app.utils.helpers import utc_now

main_bp = Blueprint("main", __name__)


@main_bp.route("/about", methods=["GET"])
@login_required
def about():
    nmap_status = get_nmap_status(current_app.config.get("NMAP_PATH", ""))
    ml_metrics = get_phishing_engine().metrics
    return render_template("about.html", nmap_status=nmap_status, ml_metrics=ml_metrics)


@main_bp.route("/health", methods=["GET"])
def health():
    """Lightweight health check endpoint for container orchestration and Render."""
    db_ok = True
    try:
        db.session.execute(text("SELECT 1"))
    except Exception:
        db_ok = False

    status_code = 200 if db_ok else 503
    return (
        jsonify(
            {
                "status": "healthy" if db_ok else "degraded",
                "application": current_app.config.get("APP_NAME", "NEXORA"),
                "version": current_app.config.get("APP_VERSION", "1.0.0"),
                "database": "connected" if db_ok else "error",
                "timestamp": utc_now().isoformat() + "Z",
            }
        ),
        status_code,
    )
