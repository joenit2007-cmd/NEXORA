"""Security event model representing parsed log and platform telemetry."""

from app.extensions import db
from app.utils.helpers import utc_now


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    log_analysis_id = db.Column(db.Integer, db.ForeignKey("log_analyses.id"), nullable=True, index=True)

    timestamp = db.Column(db.DateTime, nullable=False, default=utc_now, index=True)
    source_ip = db.Column(db.String(64), nullable=True, index=True)
    username = db.Column(db.String(120), nullable=True)
    event_type = db.Column(db.String(80), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, default="Low", index=True)
    source_module = db.Column(db.String(40), nullable=False, default="Log Analyzer")
    raw_message = db.Column(db.Text, nullable=True)
    detection_reason = db.Column(db.Text, nullable=True)
    recommended_action = db.Column(db.Text, nullable=True)
    is_demo = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    user = db.relationship("User", back_populates="security_events")
    log_analysis = db.relationship("LogAnalysis", back_populates="events")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "",
            "source_ip": self.source_ip or "N/A",
            "username": self.username or "N/A",
            "event_type": self.event_type,
            "severity": self.severity,
            "source_module": self.source_module,
            "detection_reason": self.detection_reason or "",
            "recommended_action": self.recommended_action or "",
            "is_demo": self.is_demo,
        }
