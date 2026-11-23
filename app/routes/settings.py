"""User Settings, Detection Thresholds, and Admin Role Management routes."""

from __future__ import annotations

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import User
from app.security.decorators import role_required
from app.security.validators import validate_password
from app.services.network_monitor import get_nmap_status

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


@settings_bp.route("", methods=["GET"])
@login_required
def index():
    users = User.query.order_by(User.created_at.asc()).all() if current_user.is_admin else []
    nmap_status = get_nmap_status(current_app.config.get("NMAP_PATH", ""))
    return render_template("settings.html", users=users, nmap_status=nmap_status)


@settings_bp.route("/thresholds", methods=["POST"])
@login_required
def update_thresholds():
    try:
        threshold = int(request.form.get("brute_force_threshold", current_user.brute_force_threshold))
        window = int(request.form.get("brute_force_window_minutes", current_user.brute_force_window_minutes))
    except ValueError:
        flash("Thresholds must be valid integers.", "danger")
        return redirect(url_for("settings.index")), 400

    if not (2 <= threshold <= 100):
        flash("Brute-force threshold must be between 2 and 100 failed attempts.", "danger")
        return redirect(url_for("settings.index")), 400

    if not (1 <= window <= 1440):
        flash("Time window must be between 1 and 1440 minutes.", "danger")
        return redirect(url_for("settings.index")), 400

    current_user.brute_force_threshold = threshold
    current_user.brute_force_window_minutes = window
    db.session.commit()
    flash(f"Updated detection settings: {threshold} failed logins within {window} minute(s).", "success")
    return redirect(url_for("settings.index"))


@settings_bp.route("/password", methods=["POST"])
@login_required
def update_password():
    current_pwd = request.form.get("current_password", "")
    new_pwd = request.form.get("new_password", "")
    confirm_pwd = request.form.get("confirm_password", "")

    if not current_user.check_password(current_pwd):
        flash("Current password is incorrect.", "danger")
        return redirect(url_for("settings.index")), 400

    ok, err = validate_password(new_pwd)
    if not ok:
        flash(err, "danger")
        return redirect(url_for("settings.index")), 400

    if new_pwd != confirm_pwd:
        flash("New passwords do not match.", "danger")
        return redirect(url_for("settings.index")), 400

    current_user.set_password(new_pwd)
    db.session.commit()
    flash("Password updated securely.", "success")
    return redirect(url_for("settings.index"))


@settings_bp.route("/users/<int:user_id>/role", methods=["POST"])
@login_required
@role_required("admin")
def update_user_role(user_id: int):
    target_user = db.session.get(User, user_id)
    if not target_user:
        abort(404)

    new_role = (request.form.get("role", "analyst") or "analyst").strip().lower()
    if new_role not in {"admin", "analyst"}:
        flash("Invalid role specified.", "danger")
        return redirect(url_for("settings.index")), 400

    if target_user.id == current_user.id and new_role != "admin":
        flash("You cannot demote your own active admin account.", "warning")
        return redirect(url_for("settings.index")), 400

    target_user.role = new_role
    db.session.commit()
    flash(f"Updated role for '{target_user.username}' to {new_role.title()}.", "success")
    return redirect(url_for("settings.index"))
