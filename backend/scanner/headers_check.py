"""
headers_check.py
Checks HTTP security headers. Normalized output: confidence, evidence, status.
"""

import requests

SECURITY_HEADERS = {
    "Content-Security-Policy":   ("High",   "CSP header missing. Prevents XSS and data injection attacks."),
    "X-Frame-Options":           ("Medium", "X-Frame-Options missing. Site may be vulnerable to clickjacking."),
    "X-Content-Type-Options":    ("Medium", "X-Content-Type-Options missing. Browsers may MIME-sniff responses."),
    "Strict-Transport-Security": ("High",   "HSTS missing. Users may connect over insecure HTTP."),
    "Referrer-Policy":           ("Low",    "Referrer-Policy missing. Sensitive URL data may leak to third parties."),
    "Permissions-Policy":        ("Low",    "Permissions-Policy missing. Browser features may not be restricted."),
    "X-XSS-Protection":          ("Low",    "X-XSS-Protection missing. Older browsers lack reflected XSS protection."),
}

INFO_DISCLOSURE = {
    "Server":           ("Low",    "Server header exposes software/version, aiding fingerprinting."),
    "X-Powered-By":     ("Low",    "X-Powered-By reveals the technology stack."),
    "X-AspNet-Version": ("Medium", "X-AspNet-Version reveals the .NET version in use."),
}

TIMEOUT = 8


def check_headers(target: str) -> list:
    issues = []
    try:
        resp = requests.get(target, timeout=TIMEOUT, allow_redirects=True, verify=False)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # Missing security headers
        for header, (severity, description) in SECURITY_HEADERS.items():
            if header.lower() not in headers_lower:
                issues.append({
                    "title":       f"Missing Header: {header}",
                    "severity":    severity,
                    "description": description,
                    "category":    "Security Headers",
                    "confidence":  100,
                    "evidence":    f"Header '{header}' absent in HTTP response from {target}",
                    "status":      "COMPLETED",
                })

        # Information disclosure headers
        for header, (severity, description) in INFO_DISCLOSURE.items():
            if header.lower() in headers_lower:
                val = headers_lower[header.lower()]
                issues.append({
                    "title":       f"Information Disclosure: {header}",
                    "severity":    severity,
                    "description": description,
                    "category":    "Information Disclosure",
                    "confidence":  100,
                    "evidence":    f"{header}: {val}",
                    "status":      "COMPLETED",
                })

        # Cookie security flags
        raw_cookie = resp.headers.get("Set-Cookie", "")
        if raw_cookie:
            if "httponly" not in raw_cookie.lower():
                issues.append({
                    "title":       "Cookie Missing HttpOnly Flag",
                    "severity":    "Medium",
                    "description": "Cookies lack HttpOnly — accessible via JavaScript (XSS risk).",
                    "category":    "Cookie Security",
                    "confidence":  90,
                    "evidence":    f"Set-Cookie: {raw_cookie[:120]}",
                    "status":      "COMPLETED",
                })
            if "secure" not in raw_cookie.lower():
                issues.append({
                    "title":       "Cookie Missing Secure Flag",
                    "severity":    "Medium",
                    "description": "Cookies lack Secure flag — may transmit over unencrypted HTTP.",
                    "category":    "Cookie Security",
                    "confidence":  90,
                    "evidence":    f"Set-Cookie: {raw_cookie[:120]}",
                    "status":      "COMPLETED",
                })

    except requests.exceptions.SSLError:
        issues.append({"title": "SSL/TLS Certificate Error", "severity": "High",
                        "description": "Invalid or self-signed SSL certificate — MITM risk.",
                        "category": "TLS/SSL", "confidence": 95, "evidence": "SSLError on connect", "status": "COMPLETED"})
    except requests.exceptions.ConnectionError:
        issues.append({"title": "Connection Failed", "severity": "High",
                        "description": f"Could not connect to {target}.",
                        "category": "Connectivity", "confidence": 100, "evidence": "ConnectionError", "status": "ERROR"})
    except requests.exceptions.Timeout:
        issues.append({"title": "Request Timed Out", "severity": "Low",
                        "description": f"Target took >{TIMEOUT}s to respond.",
                        "category": "Connectivity", "confidence": 80, "evidence": "Timeout", "status": "PARTIAL"})

    return issues
