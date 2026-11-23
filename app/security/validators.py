"""Input, target, upload, and credential validation for NEXORA."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Tuple

ALLOWED_LOG_EXTENSIONS = {".log", ".txt", ".csv"}
PORT_SPEC_RE = re.compile(r"^[0-9,\-\s]+$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,32}$")
SHELL_META_RE = re.compile(r"[;&|`$><\\()\n\r\t]")


def validate_username(username: str) -> Tuple[bool, str]:
    value = (username or "").strip()
    if not USERNAME_RE.match(value):
        return False, "Username must be 3-32 characters (letters, numbers, _, ., -)."
    return True, value


def validate_email(email: str) -> Tuple[bool, str]:
    value = (email or "").strip().lower()
    if not EMAIL_RE.match(value) or len(value) > 120:
        return False, "Enter a valid email address."
    return True, value


def validate_password(password: str) -> Tuple[bool, str]:
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return False, "Password must contain at least one letter and one number."
    return True, ""


def validate_authorized_target(target: str) -> Tuple[bool, str, str]:
    """Validate that a scan target is localhost or an RFC1918 private lab IP.

    Returns (is_valid, normalized_target, error_message).
    Public IPs, external domains, and shell metacharacters are strictly rejected.
    """
    raw = (target or "").strip().lower()
    if not raw:
        return False, "", "Target host or IP address is required."

    if len(raw) > 64 or SHELL_META_RE.search(raw):
        return False, "", "Invalid characters detected in target specification."

    if raw == "localhost":
        return True, "127.0.0.1", ""

    # Reject CIDR blocks or ranges to prevent broad sweep scanning
    if "/" in raw or "*" in raw or "-" in raw:
        return (
            False,
            "",
            "Only single authorized host targets (localhost or single private RFC1918 IP) are permitted.",
        )

    try:
        ip_obj = ipaddress.ip_address(raw)
    except ValueError:
        return (
            False,
            "",
            "Unauthorized or invalid target. Only 'localhost', 127.0.0.1, ::1, or private lab IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are allowed.",
        )

    if ip_obj.is_loopback:
        return True, str(ip_obj), ""

    if ip_obj.is_private and not ip_obj.is_link_local and not ip_obj.is_multicast and not ip_obj.is_unspecified:
        return True, str(ip_obj), ""

    return (
        False,
        "",
        f"Target {ip_obj} is outside authorized local/private lab boundaries. Public network scanning is prohibited.",
    )


def validate_port_range(port_spec: str) -> Tuple[bool, list[int], str]:
    """Parse and validate a bounded list of TCP ports (max 100 ports per scan)."""
    spec = (port_spec or "").strip()
    if not spec:
        default_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5000, 5432, 6379, 8000, 8080, 8443]
        return True, default_ports, ""

    if not PORT_SPEC_RE.match(spec):
        return False, [], "Port specification may only contain digits, commas, and hyphens (e.g., '22,80,443,8000-8010')."

    ports: set[int] = set()
    for part in spec.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            bounds = token.split("-")
            if len(bounds) != 2 or not bounds[0].isdigit() or not bounds[1].isdigit():
                return False, [], f"Invalid port range '{token}'."
            start, end = int(bounds[0]), int(bounds[1])
            if start < 1 or end > 65535 or start > end:
                return False, [], f"Port range '{token}' must be within 1-65535."
            if end - start > 100:
                return False, [], "Port range span cannot exceed 100 ports per assessment."
            ports.update(range(start, end + 1))
        else:
            if not token.isdigit():
                return False, [], f"Invalid port '{token}'."
            p = int(token)
            if p < 1 or p > 65535:
                return False, [], f"Port {p} must be between 1 and 65535."
            ports.add(p)

    if not ports:
        return False, [], "No valid ports were specified."
    if len(ports) > 100:
        return False, [], "A maximum of 100 ports can be assessed in a single scan."

    return True, sorted(ports), ""


def validate_log_upload(filename: str, content_bytes: bytes, max_bytes: int) -> Tuple[bool, str]:
    """Validate uploaded log filename, extension, size, and text safety."""
    if not filename:
        return False, "No file selected."

    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_LOG_EXTENSIONS:
        return False, f"Unsupported file type '{ext or 'none'}'. Allowed types: .log, .txt, .csv."

    if not content_bytes or len(content_bytes.strip()) == 0:
        return False, "Uploaded file is empty."

    if len(content_bytes) > max_bytes:
        return False, f"File exceeds maximum allowed size of {max_bytes // (1024 * 1024)} MB."

    # Reject binary/executable payloads (null bytes or MZ/ELF headers)
    if b"\x00" in content_bytes[:4096] or content_bytes[:2] == b"MZ" or content_bytes[:4] == b"\x7fELF":
        return False, "Binary or executable files are rejected for security reasons."

    return True, ""


def is_safe_path(base_dir: Path, target_path: Path) -> bool:
    """Prevent path traversal outside a designated directory."""
    try:
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        return resolved_target == resolved_base or resolved_base in resolved_target.parents
    except OSError:
        return False
