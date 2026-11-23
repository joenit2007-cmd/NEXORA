"""Centralized security alert management model."""

from app.extensions import db
from app.utils.helpers import generate_unique_id, utc_now


class SecurityAlert(db.Model):
    __tablename__ = "security_alerts"

    id = db.Column(db.Integer, primary_key=True)
    alert_uid = db.Column(db.String(32), unique=True, nullable=False, index=True, default=lambda: generate_unique_id("NEX"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(60), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)  # Critical, High, Medium, Low
    status = db.Column(db.String(20), nullable=False, default="Open", index=True)  # Open, Reviewed, Resolved

    source_module = db.Column(db.String(50), nullable=False)
    source_ip = db.Column(db.String(64), nullable=True)
    target = db.Column(db.String(120), nullable=True)
    description = db.Column(db.Text, nullable=False)
    recommended_action = db.Column(db.Text, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    is_demo = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(db.DateTime, nullable=False, default=utc_now, index=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    user = db.relationship("User", back_populates="alerts", foreign_keys=[user_id])
    reviewed_by = db.relationship("User", foreign_keys=[reviewed_by_id])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "alert_uid": self.alert_uid,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "source_module": self.source_module,
            "source_ip": self.source_ip or "N/A",
            "target": self.target or "N/A",
            "description": self.description,
            "recommended_action": self.recommended_action or "",
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else "",
            "reviewed_at": self.reviewed_at.strftime("%Y-%m-%d %H:%M:%S") if self.reviewed_at else None,
            "resolved_at": self.resolved_at.strftime("%Y-%m-%d %H:%M:%S") if self.resolved_at else None,
        }
