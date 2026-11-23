"""Phishing email analysis record model."""

from app.extensions import db
from app.utils.helpers import safe_json_loads, utc_now


class PhishingAnalysis(db.Model):
    __tablename__ = "phishing_analyses"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    sender = db.Column(db.String(255), nullable=True)
    subject = db.Column(db.String(255), nullable=True)
    urls_json = db.Column(db.Text, nullable=True, default="[]")
    content_preview = db.Column(db.Text, nullable=False)

    risk_level = db.Column(db.String(20), nullable=False, index=True)  # Low Risk, Suspicious, High Risk
    risk_score = db.Column(db.Float, nullable=False, default=0.0)  # 0 to 100
    detection_method = db.Column(db.String(50), nullable=False, default="Hybrid ML + Rules")
    ml_probability = db.Column(db.Float, nullable=True)  # 0.0 to 1.0 when ML used
    rule_score = db.Column(db.Float, nullable=False, default=0.0)

    indicators_json = db.Column(db.Text, nullable=True, default="[]")
    explanation = db.Column(db.Text, nullable=True)
    recommended_action = db.Column(db.Text, nullable=True)
    is_demo = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(db.DateTime, nullable=False, default=utc_now, index=True)

    user = db.relationship("User", back_populates="phishing_analyses")

    @property
    def urls(self) -> list:
        return safe_json_loads(self.urls_json, [])

    @property
    def indicators(self) -> list:
        return safe_json_loads(self.indicators_json, [])
