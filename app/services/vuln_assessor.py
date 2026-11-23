"""Practical, evidence-based vulnerability assessment engine.

Strictly adheres to authorized target boundaries (localhost / RFC1918 private lab),
uses transparent detection logic, never fabricates CVEs, and never marks a port
vulnerable merely because it is open.
"""

from __future__ import annotations

import http.client
import ipaddress
import ssl
from collections import Counter
from typing import Any

from app.security.validators import validate_authorized_target, validate_port_range
from app.services.network_monitor import run_authorized_scan
from app.utils.helpers import severity_rank

HTTP_PORTS = {80, 5000, 8000, 8080, 8888, 3000}
HTTPS_PORTS = {443, 8443}


def _is_loopback_target(target: str) -> bool:
    if target == "localhost":
        return True
    try:
        return ipaddress.ip_address(target).is_loopback
    except ValueError:
        return False


def _inspect_http_security_headers(target: str, port: int, use_https: bool) -> list[dict[str, Any]]:
    """Perform non-intrusive HTTP HEAD/GET inspection on an authorized web service."""
    findings: list[dict[str, Any]] = []
    scheme = "https" if use_https else "http"
    conn = None

    try:
        if use_https:
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(target, port, timeout=3.0, context=ctx)
        else:
            conn = http.client.HTTPConnection(target, port, timeout=3.0)

        conn.request("GET", "/", headers={"User-Agent": "NEXORA-Security-Assessor/1.0"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        status_code = resp.status
        location = headers.get("location", "")

        # 1. Check plaintext HTTP without HTTPS redirect
        if not use_https and not location.lower().startswith("https://"):
            sev = "Low" if _is_loopback_target(target) else "Medium"
            findings.append(
                {
                    "title": "Unencrypted HTTP Service Without HTTPS Redirection",
                    "affected_host": target,
                    "port_service": f"{port}/tcp ({scheme})",
                    "severity": sev,
                    "description": (
                        f"The web service on {target}:{port} responded over plaintext HTTP (status {status_code}) "
                        "without redirecting clients to HTTPS."
                    ),
                    "evidence": f"GET http://{target}:{port}/ returned HTTP {status_code}; Location header: '{location or 'none'}'.",
                    "potential_impact": (
                        "Session cookies, credentials, and application data transmitted over plaintext HTTP on a "
                        "shared network can be intercepted or modified in transit."
                    ),
                    "recommended_remediation": (
                        "Enable TLS/HTTPS with a valid certificate, enforce HTTP-to-HTTPS 301 redirects, "
                        "and configure Strict-Transport-Security (HSTS)."
                    ),
                }
            )

        # 2. Check missing security headers
        required_headers = [
            ("x-content-type-options", "X-Content-Type-Options"),
            ("x-frame-options", "X-Frame-Options"),
            ("content-security-policy", "Content-Security-Policy"),
        ]
        if use_https:
            required_headers.append(("strict-transport-security", "Strict-Transport-Security"))

        missing = [label for key, label in required_headers if key not in headers]
        if missing:
            findings.append(
                {
                    "title": "Missing Recommended HTTP Security Headers",
                    "affected_host": target,
                    "port_service": f"{port}/tcp ({scheme})",
                    "severity": "Low" if len(missing) <= 2 else "Medium",
                    "description": (
                        f"The HTTP response from {target}:{port} omits {len(missing)} standard browser defense "
                        f"header(s): {', '.join(missing)}."
                    ),
                    "evidence": f"HTTP {status_code} response headers observed: {', '.join(sorted(headers.keys())) or 'none'}. Missing: {', '.join(missing)}.",
                    "potential_impact": (
                        "Absence of defensive response headers weakens client-side protections against clickjacking, "
                        "MIME-sniffing, and cross-site scripting (XSS)."
                    ),
                    "recommended_remediation": (
                        "Configure the web server or application middleware to emit Content-Security-Policy, "
                        "X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and HSTS (over HTTPS)."
                    ),
                }
            )

        # 3. Check verbose Server / X-Powered-By version disclosure
        server_hdr = headers.get("server", "")
        powered_hdr = headers.get("x-powered-by", "")
        disclosed = []
        if server_hdr and any(ch.isdigit() for ch in server_hdr):
            disclosed.append(f"Server: {server_hdr}")
        if powered_hdr:
            disclosed.append(f"X-Powered-By: {powered_hdr}")

        if disclosed:
            findings.append(
                {
                    "title": "Web Server Technology/Version Header Disclosure",
                    "affected_host": target,
                    "port_service": f"{port}/tcp ({scheme})",
                    "severity": "Informational",
                    "description": (
                        "The web server discloses specific software stack or version identifiers in HTTP response headers."
                    ),
                    "evidence": "Observed response header(s): " + "; ".join(disclosed),
                    "potential_impact": (
                        "Version disclosure assists reconnaissance by helping attackers identify exact server "
                        "components without probing."
                    ),
                    "recommended_remediation": (
                        "Suppress or generalize Server and X-Powered-By headers in reverse proxy or web server configuration."
                    ),
                }
            )
    except Exception:
        # Do not fabricate findings if service did not speak HTTP or refused connection
        return []
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    return findings


def evaluate_discovered_services(
    target: str,
    open_ports: list[dict[str, Any]],
    perform_http_checks: bool = True,
) -> list[dict[str, Any]]:
    """Evaluate discovered open ports/services using transparent, evidence-backed rules."""
    findings: list[dict[str, Any]] = []
    loopback = _is_loopback_target(target)
    exposure_scope = "localhost loopback interface" if loopback else "private network interface"

    for item in open_ports:
        port = int(item.get("port", 0))
        proto = item.get("protocol", "tcp")
        service = (item.get("service") or "unknown").lower()
        version = item.get("version") or "Version not disclosed"
        banner = item.get("banner") or ""
        port_svc_label = f"{port}/{proto} ({service})"

        matched_rule = False

        # Rule 1: Cleartext Telnet (Port 23 or telnet service)
        if port == 23 or "telnet" in service:
            matched_rule = True
            findings.append(
                {
                    "title": "Cleartext Remote Administration Protocol (Telnet) Enabled",
                    "affected_host": target,
                    "port_service": port_svc_label,
                    "severity": "High" if loopback else "Critical",
                    "description": (
                        "Telnet transmits authentication credentials and interactive session traffic completely unencrypted."
                    ),
                    "evidence": f"Open port {port}/{proto} identified as service '{service}' ({version}) on {exposure_scope}.",
                    "potential_impact": (
                        "Any network observer on the local segment can capture administrative usernames, passwords, "
                        "and session commands in plaintext."
                    ),
                    "recommended_remediation": (
                        "Disable the Telnet daemon immediately and migrate remote management to SSHv2 with key-based authentication."
                    ),
                }
            )

        # Rule 2: Unencrypted FTP (Port 21 or ftp service)
        elif port == 21 or service == "ftp":
            matched_rule = True
            findings.append(
                {
                    "title": "Unencrypted File Transfer Protocol (FTP) Exposed",
                    "affected_host": target,
                    "port_service": port_svc_label,
                    "severity": "Medium" if loopback else "High",
                    "description": (
                        "Standard FTP transfers authentication credentials and file contents without transport encryption unless FTPS is enforced."
                    ),
                    "evidence": f"Open port {port}/{proto} running '{service}' ({version}) detected on {exposure_scope}.",
                    "potential_impact": (
                        "Credentials and sensitive files can be intercepted via network sniffing or modified in transit."
                    ),
                    "recommended_remediation": (
                        "Replace plaintext FTP with SFTP (over SSH) or enforce explicit FTPS (TLS 1.2+), and disable anonymous login."
                    ),
                }
            )

        # Rule 3: SMB / NetBIOS exposure (Ports 139, 445)
        elif port in {139, 445} or service in {"microsoft-ds", "netbios-ssn", "smb"}:
            matched_rule = True
            findings.append(
                {
                    "title": "SMB / NetBIOS File Sharing Service Exposed",
                    "affected_host": target,
                    "port_service": port_svc_label,
                    "severity": "Medium" if loopback else "High",
                    "description": (
                        f"Windows/Samba file sharing service is listening on port {port}/{proto}. Exposed SMB endpoints "
                        "are high-value targets for lateral movement, NTLM relay, and weak share permissions."
                    ),
                    "evidence": f"Port {port}/{proto} ({service}) responded open on {target} ({exposure_scope}).",
                    "potential_impact": (
                        "Misconfigured shares, disabled SMB signing, or SMBv1 support can allow unauthorized file access "
                        "or credential relay across the local network."
                    ),
                    "recommended_remediation": (
                        "Disable SMBv1, enforce SMB signing and encryption (SMBv3), restrict port 445/139 via host firewall "
                        "to trusted subnets, and audit share ACLs."
                    ),
                }
            )

        # Rule 4: Remote Desktop Protocol (Port 3389) or VNC (Port 5900)
        elif port in {3389, 5900} or service in {"ms-wbt-server", "rdp", "vnc"}:
            matched_rule = True
            proto_name = "RDP" if port == 3389 or "rdp" in service or "wbt" in service else "VNC"
            findings.append(
                {
                    "title": f"Remote Graphical Administration Service ({proto_name}) Reachable",
                    "affected_host": target,
                    "port_service": port_svc_label,
                    "severity": "Medium" if loopback else "High",
                    "description": (
                        f"{proto_name} remote desktop interface is reachable on {target}:{port}. Remote graphical "
                        "endpoints are frequent targets for credential stuffing and brute-force attacks."
                    ),
                    "evidence": f"Open port {port}/{proto} identified as '{service}' ({version}) on {exposure_scope}.",
                    "potential_impact": (
                        "Weak credentials or lack of Network Level Authentication (NLA) / encryption could allow "
                        "unauthorized interactive system control."
                    ),
                    "recommended_remediation": (
                        f"Restrict {proto_name} access via VPN or firewall allowlists, enforce NLA/TLS encryption, "
                        "enable account lockout policies, and require strong MFA."
                    ),
                }
            )

        # Rule 5: Direct Database / In-Memory Cache Exposure (Redis, MongoDB, MySQL, PostgreSQL, MSSQL)
        elif port in {1433, 3306, 5432, 6379, 27017} or service in {"mysql", "postgresql", "redis", "mongodb", "ms-sql-s"}:
            matched_rule = True
            is_nosql_cache = port in {6379, 27017} or service in {"redis", "mongodb"}
            sev = "Low" if loopback else ("High" if is_nosql_cache else "Medium")
            findings.append(
                {
                    "title": f"Database / Data Store Service Reachable ({service.upper()})",
                    "affected_host": target,
                    "port_service": port_svc_label,
                    "severity": sev,
                    "description": (
                        f"Data store service '{service}' is listening on {target}:{port} ({exposure_scope}). "
                        "Direct network exposure increases the risk of unauthorized data access if authentication or TLS is misconfigured."
                    ),
                    "evidence": f"TCP port {port} open; service identified as '{service}' ({version}).",
                    "potential_impact": (
                        "Unauthenticated access, weak credentials, or unencrypted database connections may lead to "
                        "sensitive data exfiltration or tampering."
                    ),
                    "recommended_remediation": (
                        "Bind database services to loopback (127.0.0.1) unless remote access is strictly required, "
                        "enforce strong authentication and TLS, and apply firewall rules restricting client IPs."
                    ),
                }
            )

        # Rule 6: Microsoft RPC (135)
        elif port == 135 or service == "msrpc":
            matched_rule = True
            findings.append(
                {
                    "title": "Microsoft RPC Endpoint Mapper Accessible",
                    "affected_host": target,
                    "port_service": port_svc_label,
                    "severity": "Low" if loopback else "Medium",
                    "description": (
                        "The Microsoft RPC Endpoint Mapper (port 135) exposes service binding information to querying hosts."
                    ),
                    "evidence": f"Open TCP port 135 ({service}) confirmed on {target} ({exposure_scope}).",
                    "potential_impact": (
                        "Exposes internal Windows RPC service mappings that can aid host reconnaissance on untrusted LANs."
                    ),
                    "recommended_remediation": (
                        "Restrict TCP port 135 to trusted management networks via Windows Defender Firewall."
                    ),
                }
            )

        # Rule 7: SSH (Port 22) hardening check
        elif port == 22 or service == "ssh":
            matched_rule = True
            findings.append(
                {
                    "title": "SSH Service Hardening Review Recommended",
                    "affected_host": target,
                    "port_service": port_svc_label,
                    "severity": "Low",
                    "description": (
                        "Secure Shell (SSH) is active on the target host. While SSH is encrypted, configuration "
                        "hardening should be verified to prevent brute-force and weak-cipher risks."
                    ),
                    "evidence": f"Open port {port}/{proto} identified as SSH ({version or banner or 'banner not disclosed'}).",
                    "potential_impact": (
                        "Permitting password authentication or root login increases susceptibility to automated brute-force attacks."
                    ),
                    "recommended_remediation": (
                        "Disable root SSH login (PermitRootLogin no), prefer Ed25519 key authentication, disable password "
                        "authentication where feasible, and apply rate-limiting (e.g., fail2ban)."
                    ),
                }
            )

        # Rule 8: Web Services (HTTP / HTTPS) - perform real non-intrusive header inspection
        if port in HTTP_PORTS or port in HTTPS_PORTS or "http" in service:
            is_https = port in HTTPS_PORTS or "https" in service or "ssl" in service
            if perform_http_checks:
                http_findings = _inspect_http_security_headers(target, port, is_https)
                if http_findings:
                    matched_rule = True
                    findings.extend(http_findings)

        # Transparent non-alarmist inventory record if open port has no confirmed misconfiguration
        if not matched_rule:
            findings.append(
                {
                    "title": f"Open Network Service Inventory: {service.upper()} on Port {port}",
                    "affected_host": target,
                    "port_service": port_svc_label,
                    "severity": "Informational",
                    "description": (
                        f"Port {port}/{proto} ({service}) is open on {target}. An open port alone does not confirm a "
                        "vulnerability; verify that this service is intentionally exposed and patched."
                    ),
                    "evidence": f"Confirmed open TCP port {port} ({service}; {version}) during authorized assessment.",
                    "potential_impact": (
                        "Unnecessary listening services expand the host attack surface if left unmaintained."
                    ),
                    "recommended_remediation": (
                        "Validate business need for this service, restrict access via host firewall if unused externally, "
                        "and maintain vendor security updates."
                    ),
                }
            )

    findings.sort(key=lambda f: severity_rank(f["severity"]), reverse=True)
    return findings


def run_vulnerability_assessment(
    target: str,
    port_spec: str = "",
    authorized_confirmed: bool = False,
    configured_nmap_path: str = "",
    force_fallback: bool = False,
    perform_http_checks: bool = True,
) -> dict[str, Any]:
    """Run safe authorized port/service enumeration followed by evidence-based checks."""
    if not authorized_confirmed:
        return {
            "success": False,
            "error": "Explicit target authorization confirmation is required before running a vulnerability assessment.",
        }

    valid_target, normalized_target, target_err = validate_authorized_target(target)
    if not valid_target:
        return {"success": False, "error": target_err}

    valid_ports, _, ports_err = validate_port_range(port_spec)
    if not valid_ports:
        return {"success": False, "error": ports_err}

    scan_result = run_authorized_scan(
        target=normalized_target,
        scan_type="service_version",
        port_spec=port_spec,
        authorized_confirmed=True,
        configured_nmap_path=configured_nmap_path,
        force_fallback=force_fallback,
    )
    if not scan_result.get("success"):
        return scan_result

    open_ports = scan_result["open_ports"]
    findings = evaluate_discovered_services(
        target=normalized_target,
        open_ports=open_ports,
        perform_http_checks=perform_http_checks,
    )

    counts = Counter(f["severity"] for f in findings)
    summary = (
        f"Assessed {normalized_target} using {scan_result['tool_used']}: "
        f"{len(open_ports)} open port(s) analyzed, producing {len(findings)} finding(s) "
        f"({counts.get('Critical', 0)} Critical, {counts.get('High', 0)} High, "
        f"{counts.get('Medium', 0)} Medium, {counts.get('Low', 0)} Low, "
        f"{counts.get('Informational', 0)} Informational)."
    )

    return {
        "success": True,
        "target": normalized_target,
        "port_spec": scan_result["port_spec"],
        "tool_used": scan_result["tool_used"],
        "open_ports": open_ports,
        "open_ports_count": len(open_ports),
        "findings": findings,
        "findings_count": len(findings),
        "severity_counts": {
            "Critical": counts.get("Critical", 0),
            "High": counts.get("High", 0),
            "Medium": counts.get("Medium", 0),
            "Low": counts.get("Low", 0),
            "Informational": counts.get("Informational", 0),
        },
        "summary": summary,
    }
