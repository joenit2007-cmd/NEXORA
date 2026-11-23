"""Network Monitor, Nmap integration, validation, and fallback tests."""

import socket
from app.security.validators import validate_authorized_target
from app.services.network_monitor import (
    get_local_network_info,
    get_nmap_status,
    parse_nmap_xml,
    run_authorized_scan,
)


def test_authorized_target_validation():
    for valid_t in ["localhost", "127.0.0.1", "::1", "10.0.0.5", "172.16.10.2", "192.168.1.50"]:
        ok, norm, err = validate_authorized_target(valid_t)
        assert ok is True, f"Expected {valid_t} to be valid, got: {err}"
        assert norm != ""

    for invalid_t in ["8.8.8.8", "1.1.1.1", "example.com", "192.168.1.0/24", "127.0.0.1; whoami", "169.254.169.254"]:
        ok, _, err = validate_authorized_target(invalid_t)
        assert ok is False, f"Expected {invalid_t} to be rejected"
        assert err != ""


def test_nmap_availability_check_and_xml_parsing():
    status = get_nmap_status()
    assert "available" in status
    assert "message" in status

    sample_xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up" />
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open" />
            <service name="ssh" product="OpenSSH" version="9.0" />
          </port>
          <port protocol="tcp" portid="80">
            <state state="closed" />
            <service name="http" />
          </port>
        </ports>
      </host>
    </nmaprun>"""
    parsed = parse_nmap_xml(sample_xml)
    assert parsed["host_status"] == "up"
    assert len(parsed["open_ports"]) == 1
    assert parsed["open_ports"][0]["port"] == 22
    assert parsed["open_ports"][0]["service"] == "ssh"
    assert "OpenSSH 9.0" in parsed["open_ports"][0]["version"]


def test_missing_nmap_safe_socket_fallback_discovers_local_port():
    # Spin up an ephemeral localhost TCP server so we verify genuine open port detection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        ephemeral_port = srv.getsockname()[1]

        res = run_authorized_scan(
            target="127.0.0.1",
            scan_type="quick_ports",
            port_spec=str(ephemeral_port),
            authorized_confirmed=True,
            force_fallback=True,
        )
        assert res["success"] is True
        assert res["tool_used"] == "python_socket_fallback"
        assert res["open_ports_count"] == 1
        assert res["open_ports"][0]["port"] == ephemeral_port


def test_scan_requires_confirmation_and_rejects_public_target(auth_client):
    # Missing confirmation
    no_confirm = auth_client.post(
        "/network/scan",
        data={"target": "127.0.0.1", "scan_type": "quick_ports", "port_spec": "80"},
    )
    assert no_confirm.status_code == 400

    # Public IP rejected even if confirmed
    pub_target = auth_client.post(
        "/network/scan",
        data={
            "target": "8.8.8.8",
            "scan_type": "quick_ports",
            "port_spec": "80",
            "authorized_confirmed": "on",
        },
    )
    assert pub_target.status_code == 400


def test_local_network_info_structure():
    info = get_local_network_info()
    assert "hostname" in info
    assert "primary_ip" in info
    assert isinstance(info["interfaces"], list)
    assert len(info["interfaces"]) >= 1
