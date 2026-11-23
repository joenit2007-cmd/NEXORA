"""Intelligent log analysis engine supporting .log, .txt, and .csv files."""

from __future__ import annotations

import csv
import io
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd

from app.utils.helpers import utc_now

# Regex patterns for common authentication, system, and web logs
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ISO_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")
SYSLOG_TS_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

SSH_FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>[\w.\-]+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)
SSH_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>[\w.\-]+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>[\w.\-]+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)
PAM_AUTH_FAIL_RE = re.compile(
    r"authentication failure.*?(?:rhost=(?P<ip>(?:\d{1,3}\.){3}\d{1,3}))?.*?(?:user=(?P<user>[\w.\-]*))?",
    re.IGNORECASE,
)
SUDO_RE = re.compile(r"sudo:\s*(?P<user>[\w.\-]+)\s*:.*COMMAND=(?P<cmd>.+)$", re.IGNORECASE)
WIN_FAIL_RE = re.compile(
    r"(?:4625|Logon Failure|Failed Login).*?(?:user|account)[:=\s]+(?P<user>[\w.\-\\]+).*?(?:ip|from|src)[:=\s]+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)
WEB_ATTACK_RE = re.compile(
    r"(?:'\s*OR\s*'1'='1|UNION\s+SELECT|<script>|%3Cscript%3E|\.\./\.\./|/etc/passwd|cmd\.exe|sqlmap|nikto)",
    re.IGNORECASE,
)
GENERIC_USER_RE = re.compile(r"(?:user(?:name)?|account|for)\s*[=:]?\s*['\"]?(?P<user>[A-Za-z0-9_.\-]{2,40})['\"]?", re.IGNORECASE)


def _parse_timestamp(line: str, fallback: datetime) -> datetime:
    iso_match = ISO_TS_RE.search(line)
    if iso_match:
        raw = iso_match.group(1).replace("T", " ")
        try:
            return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    syslog_match = SYSLOG_TS_RE.search(line)
    if syslog_match:
        raw = f"{fallback.year} {syslog_match.group(1)}"
        try:
            return datetime.strptime(raw, "%Y %b %d %H:%M:%S")
        except ValueError:
            pass

    return fallback


def _extract_ip(line: str) -> str | None:
    match = IPV4_RE.search(line)
    return match.group(0) if match else None


def _classify_line(line: str, fallback_ts: datetime) -> dict[str, Any] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    ts = _parse_timestamp(stripped, fallback_ts)
    ip = _extract_ip(stripped)
    lower = stripped.lower()

    # 1. SSH Failed password
    m = SSH_FAILED_RE.search(stripped)
    if m:
        is_invalid = "invalid user" in lower
        return {
            "timestamp": ts,
            "source_ip": m.group("ip"),
            "username": m.group("user"),
            "event_type": "Invalid User Login Attempt" if is_invalid else "Failed Login",
            "severity": "Medium",
            "detection_reason": "SSH authentication failure detected in authentication log.",
            "recommended_action": "Monitor source IP for repeated attempts and enforce SSH key-based authentication.",
            "raw_message": stripped[:500],
            "is_failed_login": True,
            "is_unusual": is_invalid,
        }

    # 2. SSH Invalid user
    m = SSH_INVALID_USER_RE.search(stripped)
    if m:
        return {
            "timestamp": ts,
            "source_ip": m.group("ip"),
            "username": m.group("user"),
            "event_type": "Invalid User Enumeration",
            "severity": "Medium",
            "detection_reason": f"Login attempted for non-existent user '{m.group('user')}'.",
            "recommended_action": "Verify whether IP is conducting account enumeration and restrict SSH exposure.",
            "raw_message": stripped[:500],
            "is_failed_login": True,
            "is_unusual": True,
        }

    # 3. Web attack probe
    if WEB_ATTACK_RE.search(stripped):
        return {
            "timestamp": ts,
            "source_ip": ip or "Unknown",
            "username": "web-client",
            "event_type": "Suspicious Web Attack Pattern",
            "severity": "High",
            "detection_reason": "Potential injection, XSS, path traversal, or automated scanner signature observed in log entry.",
            "recommended_action": "Inspect web application logs, validate input sanitization, and block hostile source IP.",
            "raw_message": stripped[:500],
            "is_failed_login": False,
            "is_unusual": True,
        }

    # 4. Windows / generic failed login
    m = WIN_FAIL_RE.search(stripped)
    if m:
        return {
            "timestamp": ts,
            "source_ip": m.group("ip"),
            "username": m.group("user"),
            "event_type": "Failed Login",
            "severity": "Medium",
            "detection_reason": "Windows/system logon failure event identified.",
            "recommended_action": "Review account lockout policies and confirm source host legitimacy.",
            "raw_message": stripped[:500],
            "is_failed_login": True,
            "is_unusual": False,
        }

    # 5. PAM authentication failure
    if "authentication failure" in lower or "failed login" in lower or "login failed" in lower or "auth failed" in lower:
        pm = PAM_AUTH_FAIL_RE.search(stripped)
        user_val = (pm.group("user") if pm and pm.group("user") else None)
        if not user_val:
            um = GENERIC_USER_RE.search(stripped)
            user_val = um.group("user") if um else "unknown"
        return {
            "timestamp": ts,
            "source_ip": (pm.group("ip") if pm and pm.group("ip") else ip) or "Local",
            "username": user_val,
            "event_type": "Failed Login",
            "severity": "Medium",
            "detection_reason": "Authentication failure keyword matched in system log.",
            "recommended_action": "Check user account activity and correlate with other authentication events.",
            "raw_message": stripped[:500],
            "is_failed_login": True,
            "is_unusual": False,
        }

    # 6. Sudo / privilege escalation
    m = SUDO_RE.search(stripped)
    if m:
        cmd = m.group("cmd").strip()
        suspicious_cmd = any(k in cmd.lower() for k in ("/etc/shadow", "chmod 777", "nc ", "bash -i", "useradd", "passwd"))
        return {
            "timestamp": ts,
            "source_ip": ip or "Local",
            "username": m.group("user"),
            "event_type": "Suspicious Privilege Escalation" if suspicious_cmd else "Privilege Escalation (sudo)",
            "severity": "High" if suspicious_cmd else "Low",
            "detection_reason": (
                f"Sensitive privileged command executed via sudo: {cmd[:100]}"
                if suspicious_cmd
                else f"Administrative command executed via sudo by {m.group('user')}."
            ),
            "recommended_action": "Confirm authorized change ticket and review sudoers least-privilege rules.",
            "raw_message": stripped[:500],
            "is_failed_login": False,
            "is_unusual": suspicious_cmd,
        }

    # 7. SSH Accepted login
    m = SSH_ACCEPTED_RE.search(stripped)
    if m:
        user_val = m.group("user")
        off_hours = ts.hour < 6 or ts.hour >= 22
        is_root = user_val.lower() in {"root", "administrator", "admin"}
        unusual = is_root or off_hours
        severity = "Medium" if is_root else ("Low" if not off_hours else "Medium")
        reason = "Direct privileged account SSH login detected." if is_root else (
            "Successful authentication observed during off-hours window." if off_hours else "Successful SSH authentication."
        )
        return {
            "timestamp": ts,
            "source_ip": m.group("ip"),
            "username": user_val,
            "event_type": "Privileged Login" if is_root else "Successful Login",
            "severity": severity,
            "detection_reason": reason,
            "recommended_action": "Disable direct root SSH login (PermitRootLogin no) and verify session legitimacy." if is_root else "No immediate action required; retain for audit trail.",
            "raw_message": stripped[:500],
            "is_failed_login": False,
            "is_unusual": unusual,
        }

    # 8. Critical/Error/Denied system events
    if any(k in lower for k in ("possible break-in", "unauthorized", "access denied", "permission denied", "firewall block", "blocked connection")):
        um = GENERIC_USER_RE.search(stripped)
        return {
            "timestamp": ts,
            "source_ip": ip or "Local",
            "username": um.group("user") if um else "system",
            "event_type": "Access Denied / Unauthorized Attempt",
            "severity": "High" if "break-in" in lower or "unauthorized" in lower else "Medium",
            "detection_reason": "Access restriction or unauthorized activity indicator found in system log.",
            "recommended_action": "Investigate access control logs and confirm whether activity originates from a trusted host.",
            "raw_message": stripped[:500],
            "is_failed_login": False,
            "is_unusual": True,
        }

    if any(k in lower for k in ("critical", "fatal", "panic", "segfault", "error")):
        return {
            "timestamp": ts,
            "source_ip": ip or "Local",
            "username": "system",
            "event_type": "System Error Event",
            "severity": "High" if any(k in lower for k in ("critical", "fatal", "panic")) else "Low",
            "detection_reason": "System error or critical fault recorded in log.",
            "recommended_action": "Inspect host service stability and correlate with security telemetry.",
            "raw_message": stripped[:500],
            "is_failed_login": False,
            "is_unusual": "critical" in lower or "fatal" in lower,
        }

    # Generic informational line with IP or timestamp
    if ip or ISO_TS_RE.search(stripped) or SYSLOG_TS_RE.search(stripped):
        return {
            "timestamp": ts,
            "source_ip": ip or "Local",
            "username": "system",
            "event_type": "System Activity",
            "severity": "Low",
            "detection_reason": "Standard log telemetry entry parsed.",
            "recommended_action": "Retain for baseline correlation.",
            "raw_message": stripped[:500],
            "is_failed_login": False,
            "is_unusual": False,
        }

    return None


def _parse_csv_content(text: str, fallback_ts: datetime) -> tuple[int, list[dict[str, Any]]]:
    """Parse structured CSV security logs using pandas with graceful column mapping."""
    events: list[dict[str, Any]] = []
    try:
        df = pd.read_csv(io.StringIO(text), dtype=str).fillna("")
    except Exception:
        # Fallback to line-by-line parsing if malformed CSV
        lines = text.splitlines()
        for line in lines:
            ev = _classify_line(line, fallback_ts)
            if ev:
                events.append(ev)
        return len(lines), events

    total_rows = len(df)
    if total_rows == 0:
        return 0, []

    cols = {c.strip().lower(): c for c in df.columns}

    def get_val(row: pd.Series, candidates: list[str], default: str = "") -> str:
        for cand in candidates:
            if cand in cols:
                val = str(row[cols[cand]]).strip()
                if val:
                    return val
        return default

    for _, row in df.iterrows():
        raw_ts = get_val(row, ["timestamp", "time", "date", "datetime", "event_time"])
        ts = _parse_timestamp(raw_ts, fallback_ts) if raw_ts else fallback_ts
        ip = get_val(row, ["ip", "ip_address", "source_ip", "src_ip", "client_ip", "host"], "")
        user = get_val(row, ["username", "user", "account", "actor"], "unknown")
        ev_type = get_val(row, ["event_type", "event", "action", "status", "category"], "")
        message = get_val(row, ["message", "details", "description", "raw_message", "log"], "")
        sev_raw = get_val(row, ["severity", "level", "priority"], "")

        combined = f"{ev_type} {message}".strip()
        lower = combined.lower()

        is_failed = any(k in lower for k in ("fail", "invalid", "denied", "rejected", "401", "403", "4625"))
        is_web_attack = bool(WEB_ATTACK_RE.search(combined))
        is_priv = any(k in lower for k in ("sudo", "privilege", "escalation", "root"))

        if is_web_attack:
            severity = "High"
            event_type = ev_type or "Suspicious Web Attack Pattern"
            reason = "Malicious web payload pattern identified in CSV log record."
            action = "Inspect endpoint logs, verify input validation, and block offending IP."
            unusual = True
        elif is_failed:
            severity = "Medium"
            event_type = ev_type or "Failed Login"
            reason = "Authentication or access failure recorded in structured CSV log."
            action = "Correlate failed authentication attempts by IP and username."
            unusual = "invalid" in lower
        elif is_priv:
            severity = "Medium"
            event_type = ev_type or "Privilege Escalation"
            reason = "Privileged account or administrative operation detected in CSV log."
            action = "Verify administrative authorization and review audit logs."
            unusual = True
        else:
            severity = sev_raw.title() if sev_raw.title() in {"Critical", "High", "Medium", "Low"} else "Low"
            event_type = ev_type or "Log Event"
            reason = message[:220] if message else "Structured CSV security event parsed."
            action = "Monitor and retain for baseline auditing."
            unusual = severity in {"Critical", "High"}

        if not ip:
            ip = _extract_ip(combined) or "Local"

        events.append(
            {
                "timestamp": ts,
                "source_ip": ip,
                "username": user,
                "event_type": event_type[:80],
                "severity": severity,
                "detection_reason": reason,
                "recommended_action": action,
                "raw_message": combined[:500] or f"CSV row: {user}@{ip}",
                "is_failed_login": is_failed,
                "is_unusual": unusual,
            }
        )

    return total_rows, events


def analyze_log_content(
    content_bytes: bytes,
    filename: str,
    brute_force_threshold: int = 5,
    window_minutes: int = 10,
) -> dict[str, Any]:
    """Analyze raw uploaded log bytes safely without executing file contents.

    Returns parsed events, brute-force detections, suspicious IP summary,
    timestamp distribution, and generated alert payloads.
    """
    threshold = max(2, min(int(brute_force_threshold), 100))
    window = max(1, min(int(window_minutes), 1440))

    text = content_bytes.decode("utf-8", errors="replace")
    ext = Path(filename).suffix.lower()
    fallback_ts = utc_now()

    if ext == ".csv":
        total_lines, parsed_events = _parse_csv_content(text, fallback_ts)
    else:
        lines = text.splitlines()
        total_lines = len(lines)
        parsed_events = []
        for line in lines:
            ev = _classify_line(line, fallback_ts)
            if ev:
                parsed_events.append(ev)

    # Sort events chronologically for sliding-window brute-force analysis
    parsed_events.sort(key=lambda e: e["timestamp"])

    failed_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    users_by_ip: dict[str, set[str]] = defaultdict(set)
    failed_logins = 0
    unusual_count = 0

    for ev in parsed_events:
        if ev.get("is_failed_login"):
            failed_logins += 1
            ip = ev.get("source_ip") or "Unknown"
            if ip not in {"Local", "Unknown", "N/A"}:
                failed_by_ip[ip].append(ev)
                if ev.get("username"):
                    users_by_ip[ip].add(ev["username"])
        if ev.get("is_unusual"):
            unusual_count += 1

    # Sliding window brute-force & password-spraying detection
    brute_force_events: list[dict[str, Any]] = []
    suspicious_ips: list[dict[str, Any]] = []
    alerts_to_create: list[dict[str, Any]] = []
    window_delta = timedelta(minutes=window)

    for ip, fails in failed_by_ip.items():
        fails_sorted = sorted(fails, key=lambda x: x["timestamp"])
        max_in_window = 0
        peak_start = fails_sorted[0]["timestamp"]
        peak_end = fails_sorted[0]["timestamp"]

        left = 0
        for right in range(len(fails_sorted)):
            while fails_sorted[right]["timestamp"] - fails_sorted[left]["timestamp"] > window_delta:
                left += 1
            count_in_win = right - left + 1
            if count_in_win > max_in_window:
                max_in_window = count_in_win
                peak_start = fails_sorted[left]["timestamp"]
                peak_end = fails_sorted[right]["timestamp"]

        distinct_users = sorted(users_by_ip[ip])
        total_ip_fails = len(fails_sorted)
        is_brute = max_in_window >= threshold
        is_spray = len(distinct_users) >= max(3, threshold - 1)

        if is_brute:
            sev = "Critical" if max_in_window >= threshold * 2 else "High"
            reason = (
                f"Detected {max_in_window} failed authentication attempts from {ip} within "
                f"{window} minute(s) (threshold: {threshold}). Targeted accounts: {', '.join(distinct_users[:5])}."
            )
            action = (
                f"Block or rate-limit {ip} at firewall/fail2ban, audit targeted accounts "
                f"({', '.join(distinct_users[:3])}), and enforce MFA/SSH key authentication."
            )
            bf_ev = {
                "timestamp": peak_end,
                "source_ip": ip,
                "username": ", ".join(distinct_users[:4]) or "multiple",
                "event_type": "Brute-Force Attack Detected",
                "severity": sev,
                "detection_reason": reason,
                "recommended_action": action,
                "raw_message": f"Aggregated {total_ip_fails} failed logins ({max_in_window} in {window}m window) from {ip}.",
                "is_failed_login": False,
                "is_unusual": True,
            }
            brute_force_events.append(bf_ev)
            alerts_to_create.append(
                {
                    "title": f"Brute-Force Authentication Pattern from {ip}",
                    "category": "Brute-Force Attack",
                    "severity": sev,
                    "source_ip": ip,
                    "target": ", ".join(distinct_users[:3]) or "Authentication Service",
                    "description": reason,
                    "recommended_action": action,
                }
            )
        elif is_spray:
            reason = f"Password-spraying indicator: {ip} failed logins across {len(distinct_users)} distinct usernames."
            action = f"Investigate {ip} for credential stuffing / account enumeration and tighten lockout controls."
            alerts_to_create.append(
                {
                    "title": f"Multi-Account Authentication Probing from {ip}",
                    "category": "Account Enumeration",
                    "severity": "High",
                    "source_ip": ip,
                    "target": ", ".join(distinct_users[:3]),
                    "description": reason,
                    "recommended_action": action,
                }
            )
        elif total_ip_fails >= 3:
            alerts_to_create.append(
                {
                    "title": f"Repeated Authentication Failures from {ip}",
                    "category": "Repeated Failed Logins",
                    "severity": "Medium",
                    "source_ip": ip,
                    "target": ", ".join(distinct_users[:3]) or "Authentication Service",
                    "description": f"{total_ip_fails} failed login attempts recorded from {ip}.",
                    "recommended_action": "Verify whether user experienced credential issues or unauthorized access attempt.",
                }
            )

        if is_brute or is_spray or total_ip_fails >= 2:
            risk_label = "Critical" if max_in_window >= threshold * 2 else (
                "High" if is_brute or is_spray else "Medium"
            )
            suspicious_ips.append(
                {
                    "ip": ip,
                    "failed_attempts": total_ip_fails,
                    "peak_in_window": max_in_window,
                    "targeted_users": distinct_users[:10],
                    "first_seen": fails_sorted[0]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen": fails_sorted[-1]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    "classification": "Brute-Force Source" if is_brute else ("Password Spraying" if is_spray else "Repeated Failures"),
                    "severity": risk_label,
                }
            )

    # Also generate alerts for High severity web attacks or suspicious privilege escalation
    for ev in parsed_events:
        if ev["event_type"] == "Suspicious Web Attack Pattern":
            alerts_to_create.append(
                {
                    "title": f"Web Attack Signature Detected from {ev['source_ip']}",
                    "category": "Web Attack Probe",
                    "severity": "High",
                    "source_ip": ev["source_ip"],
                    "target": "Web Application",
                    "description": f"{ev['detection_reason']} Raw sample: {ev['raw_message'][:180]}",
                    "recommended_action": ev["recommended_action"],
                }
            )
        elif ev["event_type"] == "Suspicious Privilege Escalation":
            alerts_to_create.append(
                {
                    "title": f"Sensitive Sudo Command by {ev['username']}",
                    "category": "Privilege Escalation",
                    "severity": "High",
                    "source_ip": ev["source_ip"],
                    "target": ev["username"],
                    "description": ev["detection_reason"],
                    "recommended_action": ev["recommended_action"],
                }
            )

    all_events = parsed_events + brute_force_events
    all_events.sort(key=lambda e: e["timestamp"], reverse=True)

    # Timestamp & severity breakdown
    severity_counts = Counter(e["severity"] for e in all_events)
    hourly_counts = Counter(e["timestamp"].strftime("%H:00") for e in all_events)
    timestamps = [e["timestamp"] for e in all_events]

    summary = {
        "total_lines": total_lines,
        "parsed_events": len(all_events),
        "failed_logins": failed_logins,
        "brute_force_count": len(brute_force_events),
        "unusual_activity_count": unusual_count + len(brute_force_events),
        "unique_suspicious_ips": len(suspicious_ips),
        "severity_breakdown": dict(severity_counts),
        "hourly_distribution": dict(sorted(hourly_counts.items())),
        "time_range": {
            "start": min(timestamps).strftime("%Y-%m-%d %H:%M:%S") if timestamps else "N/A",
            "end": max(timestamps).strftime("%Y-%m-%d %H:%M:%S") if timestamps else "N/A",
        },
    }

    suspicious_ips.sort(key=lambda x: x["failed_attempts"], reverse=True)

    return {
        "events": all_events,
        "suspicious_ips": suspicious_ips,
        "summary": summary,
        "alerts": alerts_to_create[:25],
        "threshold_config": {
            "brute_force_threshold": threshold,
            "window_minutes": window,
        },
    }


def export_events_to_csv(events: list[dict[str, Any]]) -> str:
    """Serialize log analysis events to CSV text."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "Timestamp",
            "IP Address",
            "Username",
            "Event Type",
            "Severity",
            "Detection Reason",
            "Recommended Action",
        ]
    )
    for ev in events:
        writer.writerow(
            [
                ev.get("timestamp", ""),
                ev.get("source_ip", "N/A"),
                ev.get("username", "N/A"),
                ev.get("event_type", ""),
                ev.get("severity", "Low"),
                ev.get("detection_reason", ""),
                ev.get("recommended_action", ""),
            ]
        )
    return buf.getvalue()
