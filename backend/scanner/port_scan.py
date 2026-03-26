import socket
from urllib.parse import urlparse

PORT_INFO = {
    21:    {"service": "FTP",        "severity": "High",   "description": "FTP transmits data in cleartext and is a common attack vector."},
    22:    {"service": "SSH",        "severity": "Low",    "description": "SSH port open. Ensure strong auth and no root login."},
    23:    {"service": "Telnet",     "severity": "High",   "description": "Telnet is unencrypted and highly insecure."},
    25:    {"service": "SMTP",       "severity": "Medium", "description": "SMTP port open. Verify it is intentional and secured."},
    80:    {"service": "HTTP",       "severity": "Low",    "description": "HTTP open. Ensure traffic is redirected to HTTPS."},
    443:   {"service": "HTTPS",      "severity": "Low",    "description": "HTTPS open — expected for web services."},
    3306:  {"service": "MySQL",      "severity": "High",   "description": "MySQL database port exposed to the internet."},
    3389:  {"service": "RDP",        "severity": "High",   "description": "RDP open. Frequent ransomware target."},
    5432:  {"service": "PostgreSQL", "severity": "High",   "description": "PostgreSQL database port exposed to the internet."},
    6379:  {"service": "Redis",      "severity": "High",   "description": "Redis open — unauthenticated by default."},
    8080:  {"service": "HTTP-Alt",   "severity": "Medium", "description": "Alternative HTTP port. May expose dev/admin interfaces."},
    8443:  {"service": "HTTPS-Alt",  "severity": "Medium", "description": "Alternative HTTPS port open."},
    27017: {"service": "MongoDB",    "severity": "High",   "description": "MongoDB port exposed — historically no-auth by default."},
}

CONNECT_TIMEOUT = 1.5
BANNER_TIMEOUT  = 2.0


def _extract_host(target: str) -> str:
    return urlparse(target).hostname or target


def _grab_banner(host: str, port: int) -> str:
    """Try to grab a service banner for evidence/fingerprinting."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(BANNER_TIMEOUT)
        sock.connect((host, port))
        # Some services send a banner immediately; others need a probe
        sock.sendall(b"\r\n")
        banner = sock.recv(256).decode("utf-8", errors="replace").strip()
        sock.close()
        return banner[:200] if banner else ""
    except Exception:
        return ""


def scan_ports(target: str) -> list:
    """Scan common ports and return normalized issue dicts."""
    host = _extract_host(target)
    issues = []

    for port, info in PORT_INFO.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(CONNECT_TIMEOUT)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                banner = _grab_banner(host, port)
                evidence = f"Port {port}/tcp open"
                if banner:
                    evidence += f" — Banner: {banner}"

                issues.append({
                    "title":       f"Open Port: {info['service']} ({port})",
                    "severity":    info["severity"],
                    "description": info["description"],
                    "category":    "Port Exposure",
                    "confidence":  95,
                    "evidence":    evidence,
                    "status":      "COMPLETED",
                })
        except (socket.gaierror, OSError):
            pass

    return issues
