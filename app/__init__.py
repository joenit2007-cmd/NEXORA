"""NEXORA Flask Application Factory."""

from __future__ import annotations

import os
from pathlib import Path
from flask import Flask, render_template

from app.config import CONFIG_MAP
from app.extensions import csrf, db, login_manager
from app.security.headers import register_security_headers
from app.utils.helpers import SEVERITY_BADGE_CLASS, format_bytes, truncate_text


def create_app(config_name: str | None = None) -> Flask:
    env_name = (config_name or os.environ.get("FLASK_ENV") or "development").lower()
    config_cls = CONFIG_MAP.get(env_name, CONFIG_MAP["development"])

    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder="templates",
        static_folder="static",
    )
    app.config.from_object(config_cls)

    # Ensure required runtime directories exist
    for dir_key in ("INSTANCE_DIR", "UPLOAD_FOLDER", "REPORTS_FOLDER"):
        Path(app.config[dir_key]).mkdir(parents=True, exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Register defensive HTTP response headers
    register_security_headers(app)

    # Register blueprints
    from app.routes.alerts import alerts_bp
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.history import history_bp
    from app.routes.logs import logs_bp
    from app.routes.main import main_bp
    from app.routes.network import network_bp
    from app.routes.phishing import phishing_bp
    from app.routes.reports import reports_bp
    from app.routes.settings import settings_bp
    from app.routes.vulnerabilities import vuln_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(network_bp)
    app.register_blueprint(vuln_bp)
    app.register_blueprint(phishing_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(main_bp)

    # Template globals & filters
    app.jinja_env.filters["format_bytes"] = format_bytes
    app.jinja_env.filters["truncate_text"] = truncate_text
    app.jinja_env.globals["severity_badge"] = lambda sev: SEVERITY_BADGE_CLASS.get(sev, "severity-info")

    @app.context_processor
    def inject_nav_context():
        from flask_login import current_user
        from app.models import SecurityAlert

        open_alerts_count = 0
        if current_user.is_authenticated:
            q = SecurityAlert.query.filter_by(status="Open")
            if not current_user.is_admin:
                q = q.filter_by(user_id=current_user.id)
            open_alerts_count = q.count()

        return {
            "app_name": app.config["APP_NAME"],
            "app_tagline": app.config["APP_TAGLINE"],
            "app_version": app.config["APP_VERSION"],
            "open_alerts_badge": open_alerts_count,
        }

    # Custom error handlers (safe error disclosure)
    @app.errorhandler(400)
    def bad_request(error):
        return render_template("errors/400.html"), 400

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(413)
    def file_too_large(error):
        return render_template("errors/400.html", custom_message="Uploaded file exceeds the 5 MB security limit."), 413

    @app.errorhandler(500)
    def server_error(error):
        db.session.rollback()
        return render_template("errors/500.html"), 500

    # Initialize database tables automatically
    with app.app_context():
        from app import models as _models  # noqa: F401
        db.create_all()

    # Register Flask CLI utility commands
    @app.cli.command("init-db")
    def init_db_command():
        """Create all NEXORA database tables."""
        db.create_all()
        print("NEXORA database initialized.")

    @app.cli.command("seed-admin")
    def seed_admin_command():
        """Bootstrap an initial admin account using environment variables."""
        from app.models import User

        username = os.environ.get("NEXORA_ADMIN_USERNAME", "admin").strip()
        email = os.environ.get("NEXORA_ADMIN_EMAIL", "admin@nexora.local").strip().lower()
        password = os.environ.get("NEXORA_ADMIN_PASSWORD", "").strip()
        if not password:
            print("Error: Set NEXORA_ADMIN_PASSWORD in your environment before running seed-admin.")
            return
        if User.query.filter((User.username == username) | (User.email == email)).first():
            print(f"Admin user '{username}' already exists.")
            return
        user = User(username=username, email=email, role="admin")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print(f"Created NEXORA admin account '{username}'.")

    return app
