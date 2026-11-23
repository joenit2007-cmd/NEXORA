"""User authentication and role model."""

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from app.extensions import db, login_manager
from app.utils.helpers import utc_now


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="analyst")  # 'admin' or 'analyst'
    is_active_account = db.Column(db.Boolean, nullable=False, default=True)

    # User-configurable detection thresholds
    brute_force_threshold = db.Column(db.Integer, nullable=False, default=5)
    brute_force_window_minutes = db.Column(db.Integer, nullable=False, default=10)

    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    last_login = db.Column(db.DateTime, nullable=True)

    # Relationships
    log_analyses = db.relationship("LogAnalysis", back_populates="user", lazy="dynamic", cascade="all, delete-orphan")
    security_events = db.relationship("SecurityEvent", back_populates="user", lazy="dynamic", cascade="all, delete-orphan")
    network_scans = db.relationship("NetworkScan", back_populates="user", lazy="dynamic", cascade="all, delete-orphan")
    vuln_assessments = db.relationship("VulnerabilityAssessment", back_populates="user", lazy="dynamic", cascade="all, delete-orphan")
    phishing_analyses = db.relationship("PhishingAnalysis", back_populates="user", lazy="dynamic", cascade="all, delete-orphan")
    alerts = db.relationship("SecurityAlert", back_populates="user", lazy="dynamic", foreign_keys="SecurityAlert.user_id")
    reports = db.relationship("Report", back_populates="user", lazy="dynamic", cascade="all, delete-orphan")

    @property
    def is_active(self) -> bool:
        return bool(self.is_active_account)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def set_password(self, raw_password: str) -> None:
        self.password_hash = generate_password_hash(raw_password, method="pbkdf2:sha256:600000")

    def check_password(self, raw_password: str) -> bool:
        if not self.password_hash or not raw_password:
            return False
        return check_password_hash(self.password_hash, raw_password)

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role})>"


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None
