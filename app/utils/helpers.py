"""Shared utility helpers for NEXORA."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from werkzeug.utils import secure_filename

SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1,
    "Info": 1,
}

SEVERITY_BADGE_CLASS = {
    "Critical": "severity-critical",
    "High": "severity-high",
    "Medium": "severity-medium",
    "Low": "severity-low",
    "Informational": "severity-info",
    "Info": "severity-info",
}


def utc_now() -> datetime:
    """Return timezone-naive UTC datetime compatible with SQLite storage."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def safe_json_dumps(data: Any) -> str:
    return json.dumps(data, default=str, ensure_ascii=False)


def safe_json_loads(raw: str | None, default: Any = None) -> Any:
    if not raw:
        return default if default is not None else {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else {}


def generate_unique_id(prefix: str) -> str:
    stamp = utc_now().strftime("%Y%m%d")
    token = uuid.uuid4().hex[:6].upper()
    return f"{prefix}-{stamp}-{token}"


def build_safe_upload_name(original_filename: str) -> str:
    """Sanitize filename and attach UUID prefix to avoid collisions and traversal."""
    cleaned = secure_filename(original_filename or "upload.log")
    if not cleaned:
        cleaned = "upload.log"
    stem = Path(cleaned).stem[:40]
    suffix = Path(cleaned).suffix.lower()
    return f"{uuid.uuid4().hex[:12]}_{stem}{suffix}"


def format_bytes(size_bytes: int | None) -> str:
    if not size_bytes or size_bytes < 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB"]
    value = float(size_bytes)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024.0
    return f"{int(size_bytes)} B"


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, 0)


def truncate_text(text: str | None, max_len: int = 160) -> str:
    if not text:
        return ""
    clean = re.sub(r"\s+", " ", text).strip()
    if len(clean) <= max_len:
        return clean
    return clean[: max_len - 3] + "..."
