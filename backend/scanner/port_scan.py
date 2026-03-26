"""
port_scan.py
Scans common ports on the target host and reports open ports with severity.
"""

import socket
from urllib.parse import urlparse

# Ports to check and their associated severity / service name
PORT_INFO = {
    21:   {"service": "FTP",        "severity": "High",   "description": "FTP port is open. FTP transmits data in cleartext and is a common attack vector."},
    22:   {"service": "SSH",        "severity": "Low",    "description": "SSH port is open. Ensure strong authentication is enforced and root login is disabled."},
    23:   {"service": "Telnet",     "severity": "High",   "description": "Telnet port is open. Telnet is unencrypted and highly insecure."},
    25:   {"service": "SMTP",       "severity": "Medium", "description": "SMTP port is open. Verify this is intentional and properly secured."},
    80:   {"service": "HTTP",       "severity": "Low",    "description": "HTTP port is open. Ensure traffic is redirected to HTTPS."},
    443:  {"service": "HTTPS",      "severity": "Low",    "description": "HTTPS port is open — expected for web services."},
    3306: {"service": "MySQL",      "severity": "High",   "description": "MySQL database port is exposed to the internet."},
    3389: {"service": "RDP",        "severity": "High",   "description": "RDP port is open. Remote Desktop is a frequent ransomware target."},
    5432: {"service": "PostgreSQL", "severity": "High",   "description": "PostgreSQL database port is exposed to the internet."},
    6379: {"service": "Redis",      "severity": "High",   "description": "Redis port is open without authentication by default."},
    8080: {"service": "HTTP-Alt",   "severity": "Medium", "description": "Alternative HTTP port is open. May expose dev/admin interfaces."},
    8443: {"service": "HTTPS-Alt",  "severity": "Medium", "description": "Alternative HTTPS port is open."},
    27017:{"service": "MongoDB",    "severity": "High",   "description": "MongoDB port is exposed — historically misconfigured with no auth."},
}

TIMEOUT = 1.5  # seconds per port


def _extract_host(target: str) -> str:
    """Extract the hostname/IP from a full URL."""
    parsed = urlparse(target)
    return parsed.hostname or target


def scan_ports(target: str) -> list:
    """
    Scan the target host for open ports.
    Returns a list of issue dicts for each open port.
    """
    host = _extract_host(target)
    issues = []

    for port, info in PORT_INFO.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:  # Port is open
                issues.append({
                    "title": f"Open Port: {info['service']} ({port})",
                    "severity": info["severity"],
                    "description": info["description"],
                    "category": "Port Exposure",
                })
        except (socket.gaierror, OSError):
            # Host not reachable or DNS failure — skip silently
            pass

    return issues
