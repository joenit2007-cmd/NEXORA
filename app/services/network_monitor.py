"""Network monitoring and authorized Nmap scanning service."""

from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import psutil

from app.security.validators import validate_authorized_target, validate_port_range

COMMON_SERVICES = {
    21: ("ftp", "File Transfer Protocol"),
    22: ("ssh", "Secure Shell"),
    23: ("telnet", "Telnet (Cleartext)"),
    25: ("smtp", "Simple Mail Transfer Protocol"),
    53: ("dns", "Domain Name System"),
    80: ("http", "Hypertext Transfer Protocol"),
    110: ("pop3", "Post Office Protocol v3"),
    135: ("msrpc", "Microsoft RPC"),
    139: ("netbios-ssn", "NetBIOS Session Service"),
    143: ("imap", "Internet Message Access Protocol"),
    443: ("https", "HTTP Secure (TLS)"),
    445: ("microsoft-ds", "SMB / File Sharing"),
    1433: ("ms-sql-s", "Microsoft SQL Server"),
    3306: ("mysql", "MySQL Database"),
    3389: ("ms-wbt-server", "Remote Desktop Protocol (RDP)"),
    5000: ("http", "Web / Flask Application Service"),
    5432: ("postgresql", "PostgreSQL Database"),
    5900: ("vnc", "Virtual Network Computing"),
    6379: ("redis", "Redis In-Memory Store"),
    8000: ("http-alt", "HTTP Alternate"),
    8080: ("http-proxy", "HTTP Alternate / Proxy"),
    8443: ("https-alt", "HTTPS Alternate"),
    27017: ("mongodb", "MongoDB Database"),
}


def find_nmap_binary(configured_path: str = "") -> str | None:
    """Locate Nmap executable safely across Windows, Linux, and macOS."""
    candidates = []
    if configured_path:
        candidates.append(configured_path)
    which_path = shutil.which("nmap")
    if which_path:
        candidates.append(which_path)

    if platform.system().lower() == "windows":
        candidates.extend(
            [
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
            ]
        )
    else:
        candidates.extend(["/usr/bin/nmap", "/usr/local/bin/nmap"])

    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def get_nmap_status(configured_path: str = "") -> dict[str, Any]:
    """Return Nmap availability and version details."""
    binary = find_nmap_binary(configured_path)
    if not binary:
        return {
            "available": False,
            "path": None,
            "version": None,
            "message": (
                "Nmap was not detected on this system. NEXORA will automatically use its safe "
                "built-in Python TCP socket scanner for authorized localhost/private lab targets."
            ),
        }

    version_line = "Detected"
    try:
        proc = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,
            check=False,
        )
        if proc.stdout:
            version_line = proc.stdout.splitlines()[0].strip()
    except Exception:
        version_line = "Installed (version query unavailable)"

    return {
        "available": True,
        "path": binary,
        "version": version_line,
        "message": f"Nmap is available ({version_line}). Authorized scans will use Nmap.",
    }


def get_local_network_info() -> dict[str, Any]:
    """Collect local hostname, primary IP, and available network interfaces safely."""
    hostname = socket.gethostname()
    primary_ip = "127.0.0.1"
    try:
        # Determine preferred outbound interface IP without transmitting packets
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.connect(("10.255.255.255", 1))
            primary_ip = s.getsockname()[0]
    except Exception:
        try:
            primary_ip = socket.gethostbyname(hostname)
        except Exception:
            primary_ip = "127.0.0.1"

    interfaces: list[dict[str, Any]] = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for iface_name, addr_list in addrs.items():
            ipv4_list = []
            ipv6_list = []
            mac_addr = "N/A"
            netmask = "N/A"
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ipv4_list.append(addr.address)
                    if addr.netmask:
                        netmask = addr.netmask
                elif addr.family == socket.AF_INET6:
                    ipv6_list.append(addr.address.split("%")[0])
                elif getattr(psutil, "AF_LINK", None) and addr.family == psutil.AF_LINK:
                    mac_addr = addr.address

            st = stats.get(iface_name)
            interfaces.append(
                {
                    "name": iface_name,
                    "is_up": bool(st.isup) if st else False,
                    "speed_mbps": st.speed if st else 0,
                    "ipv4": ", ".join(ipv4_list) if ipv4_list else "—",
                    "ipv6": ipv6_list[0] if ipv6_list else "—",
                    "netmask": netmask,
                    "mac": mac_addr,
                }
            )
    except Exception:
        interfaces.append(
            {
                "name": "loopback",
                "is_up": True,
                "speed_mbps": 0,
                "ipv4": "127.0.0.1",
                "ipv6": "::1",
                "netmask": "255.0.0.0",
                "mac": "N/A",
            }
        )

    return {
        "hostname": hostname,
        "primary_ip": primary_ip,
        "os": f"{platform.system()} {platform.release()}",
        "interfaces": interfaces,
    }


def get_active_connections(limit: int = 80) -> dict[str, Any]:
    """Inspect active network connections and listening sockets where permitted."""
    connections: list[dict[str, Any]] = []
    listening: list[dict[str, Any]] = []
    permission_note = ""

    try:
        raw_conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        raw_conns = []
        permission_note = "Elevated OS privileges are required to enumerate all system sockets; showing permitted connections only."
    except Exception as exc:
        raw_conns = []
        permission_note = f"Connection telemetry partially restricted: {exc}"

    proc_cache: dict[int, str] = {}

    for conn in raw_conns:
        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        laddr_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
        laddr_port = conn.laddr.port if conn.laddr else 0
        raddr_ip = conn.raddr.ip if conn.raddr else "—"
        raddr_port = conn.raddr.port if conn.raddr else "—"
        state = conn.status or ("LISTENING" if proto == "UDP" and not conn.raddr else "UNKNOWN")

        proc_name = "Restricted"
        if conn.pid:
            if conn.pid in proc_cache:
                proc_name = proc_cache[conn.pid]
            else:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except Exception:
                    proc_name = f"PID {conn.pid}"
                proc_cache[conn.pid] = proc_name

        entry = {
            "protocol": proto,
            "local_ip": laddr_ip,
            "local_port": laddr_port,
            "remote_ip": raddr_ip,
            "remote_port": raddr_port,
            "state": state,
            "pid": conn.pid or "—",
            "process": proc_name,
        }
        if state == "LISTEN":
            listening.append(entry)
        else:
            connections.append(entry)

    listening.sort(key=lambda x: x["local_port"])
    connections.sort(key=lambda x: (x["state"] != "ESTABLISHED", x["local_port"]))

    return {
        "active": connections[:limit],
        "listening": listening[:limit],
        "active_count": len(connections),
        "listening_count": len(listening),
        "permission_note": permission_note,
    }


def parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    """Parse Nmap XML output into structured host and open port records."""
    open_ports: list[dict[str, Any]] = []
    host_status = "unknown"
    os_guess = ""

    if not xml_text or not xml_text.strip().startswith("<"):
        return {"host_status": host_status, "open_ports": open_ports, "os_guess": os_guess}

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {"host_status": "parse_error", "open_ports": open_ports, "os_guess": os_guess}

    host_el = root.find("host")
    if host_el is None:
        return {"host_status": "down_or_filtered", "open_ports": open_ports, "os_guess": os_guess}

    status_el = host_el.find("status")
    if status_el is not None:
        host_status = status_el.attrib.get("state", "up")

    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            state_val = state_el.attrib.get("state", "") if state_el is not None else ""
            if state_val != "open":
                continue

            port_num = int(port_el.attrib.get("portid", 0))
            proto = port_el.attrib.get("protocol", "tcp")
            svc_el = port_el.find("service")
            svc_name = svc_el.attrib.get("name", "unknown") if svc_el is not None else "unknown"
            product = svc_el.attrib.get("product", "") if svc_el is not None else ""
            version = svc_el.attrib.get("version", "") if svc_el is not None else ""
            extra = svc_el.attrib.get("extrainfo", "") if svc_el is not None else ""
            version_str = " ".join(p for p in [product, version, extra] if p).strip()

            open_ports.append(
                {
                    "port": port_num,
                    "protocol": proto,
                    "state": state_val,
                    "service": svc_name,
                    "version": version_str or "Version not disclosed",
                    "banner": version_str,
                }
            )

    open_ports.sort(key=lambda x: x["port"])
    return {"host_status": host_status, "open_ports": open_ports, "os_guess": os_guess}


def _probe_single_port(target: str, port: int, timeout: float = 0.45) -> dict[str, Any] | None:
    """Safely check whether a single TCP port is open on an authorized target."""
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result != 0:
                return None

            banner = ""
            try:
                if port in {80, 5000, 8000, 8080}:
                    sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode("ascii", errors="ignore"))
                banner_bytes = sock.recv(256)
                banner = banner_bytes.decode("utf-8", errors="replace").splitlines()[0].strip()[:120]
            except Exception:
                banner = ""

            svc_name, svc_desc = COMMON_SERVICES.get(port, ("unknown", "Unclassified TCP Service"))
            return {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": svc_name,
                "version": banner if banner else svc_desc,
                "banner": banner,
            }
    except OSError:
        return None


def _socket_fallback_scan(target: str, ports: list[int]) -> dict[str, Any]:
    """Safe Python TCP connect scan fallback when Nmap is not installed."""
    open_ports: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(20, max(1, len(ports)))) as executor:
        futures = [executor.submit(_probe_single_port, target, port) for port in ports]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                open_ports.append(res)

    open_ports.sort(key=lambda x: x["port"])
    return {
        "host_status": "up" if open_ports or target in {"127.0.0.1", "::1"} else "up_or_no_open_ports",
        "open_ports": open_ports,
    }


def run_authorized_scan(
    target: str,
    scan_type: str = "quick_ports",
    port_spec: str = "",
    authorized_confirmed: bool = False,
    configured_nmap_path: str = "",
    force_fallback: bool = False,
) -> dict[str, Any]:
    """Execute an authorized network scan against localhost or a private lab IP."""
    if not authorized_confirmed:
        return {
            "success": False,
            "error": "Explicit target authorization confirmation is required before scanning.",
        }

    valid_target, normalized_target, target_err = validate_authorized_target(target)
    if not valid_target:
        return {"success": False, "error": target_err}

    valid_ports, ports_list, ports_err = validate_port_range(port_spec)
    if not valid_ports:
        return {"success": False, "error": ports_err}

    nmap_bin = None if force_fallback else find_nmap_binary(configured_nmap_path)
    ports_arg = ",".join(str(p) for p in ports_list)

    if nmap_bin:
        cmd = [nmap_bin, "-sT", "-Pn", "-T4", "-p", ports_arg]
        if scan_type == "service_version":
            cmd.extend(["-sV", "--version-light"])
        if ":" in normalized_target:
            cmd.append("-6")
        cmd.extend(["-oX", "-", normalized_target])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=45,
                shell=False,
                check=False,
            )
            parsed = parse_nmap_xml(proc.stdout)
            if parsed["host_status"] != "parse_error":
                open_ports = parsed["open_ports"]
                return {
                    "success": True,
                    "target": normalized_target,
                    "scan_type": scan_type,
                    "port_spec": port_spec or f"{len(ports_list)} common ports",
                    "tool_used": "nmap",
                    "nmap_available": True,
                    "host_status": parsed["host_status"],
                    "open_ports": open_ports,
                    "open_ports_count": len(open_ports),
                    "summary": (
                        f"Authorized Nmap ({scan_type}) scan of {normalized_target} completed: "
                        f"{len(open_ports)} open port(s) discovered across {len(ports_list)} probed ports."
                    ),
                    "raw_output": proc.stdout[:8000],
                }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Nmap scan of {normalized_target} timed out after 45 seconds. Try narrowing the port range.",
            }
        except Exception:
            # Fall through to safe socket fallback if Nmap invocation fails unexpectedly
            pass

    # Safe documented fallback when Nmap is absent or unavailable
    fallback_res = _socket_fallback_scan(normalized_target, ports_list)
    open_ports = fallback_res["open_ports"]
    return {
        "success": True,
        "target": normalized_target,
        "scan_type": scan_type,
        "port_spec": port_spec or f"{len(ports_list)} common ports",
        "tool_used": "python_socket_fallback",
        "nmap_available": bool(nmap_bin),
        "host_status": fallback_res["host_status"],
        "open_ports": open_ports,
        "open_ports_count": len(open_ports),
        "summary": (
            f"Authorized TCP socket fallback scan of {normalized_target} completed "
            f"(Nmap unavailable or bypassed): {len(open_ports)} open port(s) discovered across {len(ports_list)} probed ports."
        ),
        "raw_output": "Executed via NEXORA safe Python TCP socket fallback (Nmap unavailable).",
    }
