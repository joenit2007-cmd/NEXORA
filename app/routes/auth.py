"""Authentication routes: registration, login, and logout."""

from __future__ import annotations

from urllib.parse import urlparse
from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.extensions import db
from app.models import SecurityEvent, User
from app.security.validators import validate_email, validate_password, validate_username
from app.services.alert_service import create_alert
from app.utils.helpers import utc_now

auth_bp = Blueprint("auth", __name__)


def _is_safe_redirect(target: str | None) -> bool:
    if not target:
        return False
    parsed = urlparse(target)
    return not parsed.scheme and not parsed.netloc and target.startswith("/")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username_raw = request.form.get("username", "")
        email_raw = request.form.get("email", "")
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        ok_u, username = validate_username(username_raw)
        if not ok_u:
            flash(username, "danger")
            return render_template("auth/register.html", username=username_raw, email=email_raw), 400

        ok_e, email = validate_email(email_raw)
        if not ok_e:
            flash(email, "danger")
            return render_template("auth/register.html", username=username_raw, email=email_raw), 400

        ok_p, pwd_err = validate_password(password)
        if not ok_p:
            flash(pwd_err, "danger")
            return render_template("auth/register.html", username=username_raw, email=email_raw), 400

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("auth/register.html", username=username_raw, email=email_raw), 400

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("An account with that username or email already exists.", "danger")
            return render_template("auth/register.html", username=username_raw, email=email_raw), 409

        # First registered account receives admin privileges; subsequent accounts default to analyst
        assigned_role = "admin" if User.query.count() == 0 else "analyst"

        user = User(username=username, email=email, role=assigned_role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash(f"Account created successfully ({assigned_role.title()} role). Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        identifier = (request.form.get("username", "") or "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        if not identifier or not password:
            flash("Please enter both username/email and password.", "danger")
            return render_template("auth/login.html", username=identifier), 400

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if user and user.check_password(password) and user.is_active:
            user.last_login = utc_now()
            db.session.add(
                SecurityEvent(
                    user_id=user.id,
                    source_ip=request.remote_addr or "127.0.0.1",
                    username=user.username,
                    event_type="Platform Login Success",
                    severity="Low",
                    source_module="Authentication",
                    detection_reason="Successful user authentication to NEXORA SOC platform.",
                    recommended_action="Retained for session audit logging.",
                )
            )
            db.session.commit()

            login_user(user, remember=remember)
            flash(f"Welcome back, {user.username}.", "success")
            next_url = request.args.get("next")
            if _is_safe_redirect(next_url):
                return redirect(next_url)
            return redirect(url_for("dashboard.index"))

        # Record failed login event if account exists (for genuine platform telemetry)
        if user:
            client_ip = request.remote_addr or "127.0.0.1"
            db.session.add(
                SecurityEvent(
                    user_id=user.id,
                    source_ip=client_ip,
                    username=user.username,
                    event_type="Failed Login",
                    severity="Medium",
                    source_module="Authentication",
                    detection_reason="Invalid password submitted to NEXORA authentication endpoint.",
                    recommended_action="Verify whether repeated failed login attempts indicate credential guessing.",
                )
            )
            recent_fails = SecurityEvent.query.filter_by(
                user_id=user.id,
                event_type="Failed Login",
                source_module="Authentication",
            ).count()
            if recent_fails >= user.brute_force_threshold:
                create_alert(
                    user_id=user.id,
                    title=f"Repeated Failed NEXORA Logins for '{user.username}'",
                    category="Authentication Abuse",
                    severity="High",
                    source_module="Authentication",
                    source_ip=client_ip,
                    target=user.username,
                    description=f"Account '{user.username}' has accumulated {recent_fails} failed platform login attempts.",
                    recommended_action="Review source IP activity and reset credentials if unauthorized.",
                )
            db.session.commit()

        flash("Invalid username/email or password.", "danger")
        return render_template("auth/login.html", username=identifier), 401

    return render_template("auth/login.html")


@auth_bp.route("/logout", methods=["POST", "GET"])
@login_required
def logout():
    logout_user()
    flash("You have been signed out securely.", "info")
    return redirect(url_for("auth.login"))
