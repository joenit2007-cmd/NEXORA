"""Generated security report metadata model."""

from app.extensions import db
from app.utils.helpers import generate_unique_id, utc_now


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    report_uid = db.Column(db.String(32), unique=True, nullable=False, index=True, default=lambda: generate_unique_id("RPT"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    report_type = db.Column(db.String(40), nullable=False)  # overall, log_analysis, network_assessment, vulnerability_assessment, phishing_analysis
    report_format = db.Column(db.String(10), nullable=False)  # pdf, csv
    title = db.Column(db.String(200), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False, default=0)
    summary = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=utc_now, index=True)

    user = db.relationship("User", back_populates="reports")
