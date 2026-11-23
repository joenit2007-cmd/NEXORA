"""Authorized network scan record model."""

from app.extensions import db
from app.utils.helpers import safe_json_loads, utc_now


class NetworkScan(db.Model):
    __tablename__ = "network_scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    target = db.Column(db.String(64), nullable=False, index=True)
    scan_type = db.Column(db.String(40), nullable=False, default="quick_ports")
    port_spec = db.Column(db.String(120), nullable=True)
    tool_used = db.Column(db.String(40), nullable=False, default="nmap")
    nmap_available = db.Column(db.Boolean, nullable=False, default=False)
    authorized_confirmed = db.Column(db.Boolean, nullable=False, default=False)

    host_status = db.Column(db.String(30), nullable=False, default="up")
    open_ports_count = db.Column(db.Integer, nullable=False, default=0)
    open_ports_json = db.Column(db.Text, nullable=True, default="[]")
    summary = db.Column(db.Text, nullable=True)
    raw_output = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(30), nullable=False, default="Completed")
    is_demo = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(db.DateTime, nullable=False, default=utc_now, index=True)

    user = db.relationship("User", back_populates="network_scans")

    @property
    def open_ports(self) -> list:
        return safe_json_loads(self.open_ports_json, [])
