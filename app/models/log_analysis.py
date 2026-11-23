"""Log analysis job record model."""

from app.extensions import db
from app.utils.helpers import safe_json_loads, utc_now


class LogAnalysis(db.Model):
    __tablename__ = "log_analyses"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False, default=0)
    file_format = db.Column(db.String(20), nullable=False, default="log")

    total_lines = db.Column(db.Integer, nullable=False, default=0)
    parsed_events = db.Column(db.Integer, nullable=False, default=0)
    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    brute_force_count = db.Column(db.Integer, nullable=False, default=0)
    unusual_activity_count = db.Column(db.Integer, nullable=False, default=0)

    suspicious_ips_json = db.Column(db.Text, nullable=True, default="[]")
    threshold_config_json = db.Column(db.Text, nullable=True, default="{}")
    summary_json = db.Column(db.Text, nullable=True, default="{}")
    status = db.Column(db.String(30), nullable=False, default="Completed")
    is_demo = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(db.DateTime, nullable=False, default=utc_now, index=True)

    user = db.relationship("User", back_populates="log_analyses")
    events = db.relationship("SecurityEvent", back_populates="log_analysis", lazy="dynamic", cascade="all, delete-orphan")

    @property
    def suspicious_ips(self) -> list:
        return safe_json_loads(self.suspicious_ips_json, [])

    @property
    def threshold_config(self) -> dict:
        return safe_json_loads(self.threshold_config_json, {})

    @property
    def summary(self) -> dict:
        return safe_json_loads(self.summary_json, {})
