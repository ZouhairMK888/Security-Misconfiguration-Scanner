"""
headers_check.py
Checks HTTP response headers for missing or misconfigured security headers.
"""

import requests

# Headers to check: header name → (severity, description)
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "High",
        "Content-Security-Policy (CSP) header is missing. CSP prevents XSS and data injection attacks."
    ),
    "X-Frame-Options": (
        "Medium",
        "X-Frame-Options header is missing. The site may be vulnerable to clickjacking attacks."
    ),
    "X-Content-Type-Options": (
        "Medium",
        "X-Content-Type-Options header is missing. Browsers may MIME-sniff responses, enabling attacks."
    ),
    "Strict-Transport-Security": (
        "High",
        "Strict-Transport-Security (HSTS) header is missing. Users may connect over insecure HTTP."
    ),
    "Referrer-Policy": (
        "Low",
        "Referrer-Policy header is missing. Sensitive URL data may leak to third parties."
    ),
    "Permissions-Policy": (
        "Low",
        "Permissions-Policy header is missing. Browser features (camera, mic) may not be restricted."
    ),
    "X-XSS-Protection": (
        "Low",
        "X-XSS-Protection header is missing. Older browsers lack reflected XSS protection."
    ),
}

# Headers that reveal server/technology info
INFORMATION_DISCLOSURE = {
    "Server": (
        "Low",
        "The 'Server' header exposes server software and version, aiding fingerprinting."
    ),
    "X-Powered-By": (
        "Low",
        "The 'X-Powered-By' header reveals the technology stack (e.g., PHP/7.4), aiding attackers."
    ),
    "X-AspNet-Version": (
        "Medium",
        "The 'X-AspNet-Version' header reveals the .NET version in use."
    ),
}

REQUEST_TIMEOUT = 8


def check_headers(target: str) -> list:
    """
    Perform an HTTP GET and inspect response headers.
    Returns a list of issue dicts.
    """
    issues = []

    try:
        response = requests.get(
            target,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=False,  # Allow self-signed certs during scan
        )
        headers = {k.lower(): v for k, v in response.headers.items()}

        # Check missing security headers
        for header, (severity, description) in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                issues.append({
                    "title": f"Missing Header: {header}",
                    "severity": severity,
                    "description": description,
                    "category": "Security Headers",
                })

        # Check for information disclosure headers
        for header, (severity, description) in INFORMATION_DISCLOSURE.items():
            if header.lower() in headers:
                value = headers[header.lower()]
                issues.append({
                    "title": f"Information Disclosure: {header}",
                    "severity": severity,
                    "description": f"{description} Current value: '{value}'",
                    "category": "Information Disclosure",
                })

        # Check for insecure cookie flags
        set_cookie = response.headers.get("Set-Cookie", "")
        if set_cookie:
            if "httponly" not in set_cookie.lower():
                issues.append({
                    "title": "Cookie Missing HttpOnly Flag",
                    "severity": "Medium",
                    "description": "Session cookies lack the HttpOnly flag, making them accessible via JavaScript (XSS risk).",
                    "category": "Cookie Security",
                })
            if "secure" not in set_cookie.lower():
                issues.append({
                    "title": "Cookie Missing Secure Flag",
                    "severity": "Medium",
                    "description": "Session cookies lack the Secure flag, allowing transmission over unencrypted HTTP.",
                    "category": "Cookie Security",
                })

    except requests.exceptions.SSLError:
        issues.append({
            "title": "SSL/TLS Certificate Error",
            "severity": "High",
            "description": "The target has an invalid or self-signed SSL certificate, which exposes users to MITM attacks.",
            "category": "TLS/SSL",
        })
    except requests.exceptions.ConnectionError:
        issues.append({
            "title": "Connection Failed",
            "severity": "High",
            "description": f"Could not connect to {target}. The host may be unreachable.",
            "category": "Connectivity",
        })
    except requests.exceptions.Timeout:
        issues.append({
            "title": "Request Timed Out",
            "severity": "Low",
            "description": f"The target took too long to respond (>{REQUEST_TIMEOUT}s).",
            "category": "Connectivity",
        })

    return issues
