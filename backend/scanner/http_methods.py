"""
http_methods.py
Checks which HTTP methods are allowed on the target.
Flags dangerous methods like PUT, DELETE, TRACE, CONNECT.
"""

import requests

# Methods considered dangerous if enabled
DANGEROUS_METHODS = {
    "PUT":     ("High",   "PUT method is enabled. Attackers may upload malicious files to the server."),
    "DELETE":  ("High",   "DELETE method is enabled. Attackers may delete server resources."),
    "TRACE":   ("Medium", "TRACE method is enabled. It can be used in Cross-Site Tracing (XST) attacks."),
    "CONNECT": ("Medium", "CONNECT method is enabled. It may allow proxying through the server."),
    "PATCH":   ("Low",    "PATCH method is enabled. Verify it is intentional and properly authenticated."),
    "OPTIONS": ("Low",    "OPTIONS method reveals all allowed HTTP methods to potential attackers."),
}

REQUEST_TIMEOUT = 8


def check_http_methods(target: str) -> list:
    """
    Send an OPTIONS request to discover allowed HTTP methods.
    Returns a list of issue dicts for each dangerous method found.
    """
    issues = []

    try:
        response = requests.options(
            target,
            timeout=REQUEST_TIMEOUT,
            verify=False,
        )

        allow_header = response.headers.get("Allow", "")
        
        if not allow_header:
            # Some servers don't return Allow; try individual probes
            allowed_methods = _probe_methods(target)
        else:
            allowed_methods = [m.strip().upper() for m in allow_header.split(",")]

        for method in allowed_methods:
            if method in DANGEROUS_METHODS:
                severity, description = DANGEROUS_METHODS[method]
                issues.append({
                    "title": f"Dangerous HTTP Method Enabled: {method}",
                    "severity": severity,
                    "description": description,
                    "category": "HTTP Methods",
                })

    except requests.exceptions.RequestException:
        pass  # Connectivity issues are caught by headers_check

    return issues


def _probe_methods(target: str) -> list:
    """
    Manually probe for dangerous methods when OPTIONS doesn't return Allow header.
    """
    found = []
    probe_methods = ["PUT", "DELETE", "TRACE", "PATCH"]

    for method in probe_methods:
        try:
            resp = requests.request(
                method,
                target,
                timeout=REQUEST_TIMEOUT,
                verify=False,
            )
            # A non-405 response suggests the method may be accepted
            if resp.status_code not in (405, 501, 403):
                found.append(method)
        except requests.exceptions.RequestException:
            pass

    return found
