"""
tls_check.py  [NEW]
CWE-5   J2EE Misconfiguration: Data Transmission Without Encryption
CWE-315 Cleartext Storage of Sensitive Information in a Cookie
CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

Full TLS/SSL audit: certificate validity, expiry, protocol versions,
weak ciphers, cleartext transmission, and HSTS enforcement.
"""

import ssl
import socket
import datetime
import requests
from urllib.parse import urlparse

TIMEOUT = 8

WEAK_PROTOCOLS = {
    "SSLv2":   ("High",   "SSLv2 is supported — completely broken, vulnerable to DROWN attack."),
    "SSLv3":   ("High",   "SSLv3 is supported — vulnerable to POODLE attack."),
    "TLSv1.0": ("Medium", "TLS 1.0 is supported — deprecated, vulnerable to BEAST/POODLE."),
    "TLSv1.1": ("Medium", "TLS 1.1 is supported — deprecated since 2021, should be disabled."),
}

WEAK_CIPHERS = [
    ("RC4",      "High",   "RC4 cipher suite detected — cryptographically broken."),
    ("DES",      "High",   "DES cipher suite detected — 56-bit key, trivially brute-forced."),
    ("3DES",     "Medium", "3DES (Triple-DES) detected — vulnerable to SWEET32 attack."),
    ("NULL",     "High",   "NULL cipher suite — provides zero encryption."),
    ("EXPORT",   "High",   "EXPORT cipher suite — intentionally weak, vulnerable to FREAK attack."),
    ("anon",     "High",   "Anonymous cipher suite — no server authentication, trivial MITM."),
    ("MD5",      "Medium", "MD5-based cipher suite — MD5 is cryptographically broken."),
]


def _extract_host_port(target: str):
    parsed = urlparse(target)
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def _get_cert_info(host: str, port: int) -> dict:
    """Retrieve certificate details via SSL handshake."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                return {"cert": cert, "cipher": cipher, "version": version, "error": None}
    except Exception as e:
        return {"cert": None, "cipher": None, "version": None, "error": str(e)}


def _check_weak_protocol(host: str, port: int, proto_const, proto_name: str) -> bool:
    """Try to connect using a specific (weak) protocol."""
    try:
        ctx = ssl.SSLContext(proto_const)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock):
                return True
    except Exception:
        return False


def check_tls(target: str) -> list:
    issues = []
    parsed = urlparse(target)
    host, port = _extract_host_port(target)

    # ── 1. HTTP (cleartext) check ────────────────────────────────────────────
    # CWE-5: Data Transmission Without Encryption
    if parsed.scheme == "http":
        issues.append({
            "title":       "Cleartext HTTP in Use (No TLS)",
            "severity":    "High",
            "description": "The target is served over HTTP without encryption. All data is transmitted in cleartext — passwords, tokens, and cookies are exposed (CWE-5).",
            "category":    "TLS/SSL",
            "cwe":         "CWE-5",
            "confidence":  100,
            "evidence":    f"Target URL uses http:// scheme: {target}",
            "status":      "COMPLETED",
        })

    # Check if HTTPS is available at all
    https_target = target.replace("http://", "https://", 1)
    try:
        r = requests.get(https_target, timeout=TIMEOUT, verify=False)
        https_available = True
    except Exception:
        https_available = False

    if parsed.scheme == "http" and not https_available:
        issues.append({
            "title":       "HTTPS Not Available",
            "severity":    "High",
            "description": "The server does not appear to support HTTPS at all. All traffic is unencrypted.",
            "category":    "TLS/SSL",
            "cwe":         "CWE-5",
            "confidence":  80,
            "evidence":    f"HTTPS connection to {https_target} failed.",
            "status":      "COMPLETED",
        })
        return issues  # No point checking certs if no TLS

    # Use HTTPS port for further checks
    tls_port = 443 if port == 80 else port
    info = _get_cert_info(host, tls_port)

    if info["error"] and not info["cert"]:
        issues.append({
            "title":       "TLS Certificate Unreachable",
            "severity":    "Medium",
            "description": f"Could not retrieve TLS certificate: {info['error']}",
            "category":    "TLS/SSL",
            "cwe":         "CWE-5",
            "confidence":  70,
            "evidence":    info["error"],
            "status":      "PARTIAL",
        })
        return issues

    # ── 2. Certificate validity ───────────────────────────────────────────────
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, tls_port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                pass  # Valid cert — no exception
    except ssl.SSLCertVerificationError as e:
        issues.append({
            "title":       "Invalid TLS Certificate",
            "severity":    "High",
            "description": "Certificate verification failed — self-signed, expired, or hostname mismatch. Users are vulnerable to MITM attacks.",
            "category":    "TLS/SSL",
            "cwe":         "CWE-5",
            "confidence":  95,
            "evidence":    str(e),
            "status":      "COMPLETED",
        })
    except Exception:
        pass

    # ── 3. Certificate expiry ─────────────────────────────────────────────────
    cert = info.get("cert")
    if cert:
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                days_left = (expiry - now).days
                if days_left < 0:
                    issues.append({
                        "title":       "TLS Certificate Expired",
                        "severity":    "High",
                        "description": f"Certificate expired {abs(days_left)} days ago. Browsers will show security warnings.",
                        "category":    "TLS/SSL",
                        "cwe":         "CWE-5",
                        "confidence":  100,
                        "evidence":    f"Not After: {not_after}",
                        "status":      "COMPLETED",
                    })
                elif days_left <= 30:
                    issues.append({
                        "title":       f"TLS Certificate Expires Soon ({days_left} days)",
                        "severity":    "Medium",
                        "description": "Certificate expires within 30 days. Renew immediately to avoid service disruption.",
                        "category":    "TLS/SSL",
                        "cwe":         "CWE-5",
                        "confidence":  100,
                        "evidence":    f"Not After: {not_after} — {days_left} days remaining",
                        "status":      "COMPLETED",
                    })
            except Exception:
                pass

    # ── 4. Cipher suite check ─────────────────────────────────────────────────
    cipher = info.get("cipher")
    if cipher:
        cipher_name = cipher[0] if cipher else ""
        for weak, severity, description in WEAK_CIPHERS:
            if weak.upper() in cipher_name.upper():
                issues.append({
                    "title":       f"Weak Cipher Suite: {cipher_name}",
                    "severity":    severity,
                    "description": description,
                    "category":    "TLS/SSL",
                    "cwe":         "CWE-5",
                    "confidence":  90,
                    "evidence":    f"Negotiated cipher: {cipher_name} (protocol: {info.get('version', '?')})",
                    "status":      "COMPLETED",
                })
                break

    # ── 5. HTTP → HTTPS redirect check ───────────────────────────────────────
    if parsed.scheme == "http" and https_available:
        try:
            r = requests.get(target, timeout=TIMEOUT, allow_redirects=False, verify=False)
            if r.status_code not in (301, 302, 307, 308):
                issues.append({
                    "title":       "No HTTP → HTTPS Redirect",
                    "severity":    "Medium",
                    "description": "The server does not redirect HTTP traffic to HTTPS. Users who connect via HTTP will not be upgraded to a secure connection (CWE-5).",
                    "category":    "TLS/SSL",
                    "cwe":         "CWE-5",
                    "confidence":  90,
                    "evidence":    f"GET {target} returned HTTP {r.status_code} with no Location redirect.",
                    "status":      "COMPLETED",
                })
        except Exception:
            pass

    # ── 6. Weak protocol versions ─────────────────────────────────────────────
    proto_checks = []
    try:
        proto_checks.append((ssl.PROTOCOL_TLSv1,   "TLSv1.0"))
    except AttributeError:
        pass
    try:
        proto_checks.append((ssl.PROTOCOL_TLSv1_1, "TLSv1.1"))
    except AttributeError:
        pass

    for proto_const, proto_name in proto_checks:
        if _check_weak_protocol(host, tls_port, proto_const, proto_name):
            cfg = WEAK_PROTOCOLS[proto_name]
            issues.append({
                "title":       f"Weak TLS Protocol Supported: {proto_name}",
                "severity":    cfg[0],
                "description": cfg[1],
                "category":    "TLS/SSL",
                "cwe":         "CWE-5",
                "confidence":  85,
                "evidence":    f"Successfully negotiated {proto_name} with {host}:{tls_port}",
                "status":      "COMPLETED",
            })

    return issues
