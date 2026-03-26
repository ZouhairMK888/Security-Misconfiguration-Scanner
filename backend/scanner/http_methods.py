"""
http_methods.py
Detects dangerous HTTP methods. Normalized output: confidence, evidence, status.
"""

import requests

DANGEROUS_METHODS = {
    "PUT":     ("High",   "PUT enabled — attackers may upload malicious files."),
    "DELETE":  ("High",   "DELETE enabled — attackers may delete server resources."),
    "TRACE":   ("Medium", "TRACE enabled — Cross-Site Tracing (XST) attack vector."),
    "CONNECT": ("Medium", "CONNECT enabled — may allow proxying through the server."),
    "PATCH":   ("Low",    "PATCH enabled — verify it is properly authenticated."),
    "OPTIONS": ("Low",    "OPTIONS reveals all allowed HTTP methods to attackers."),
}

TIMEOUT = 8


def check_http_methods(target: str) -> list:
    issues = []
    try:
        resp = requests.options(target, timeout=TIMEOUT, verify=False)
        allow = resp.headers.get("Allow", "")
        allowed = [m.strip().upper() for m in allow.split(",")] if allow else _probe_methods(target)

        for method in allowed:
            if method in DANGEROUS_METHODS:
                severity, description = DANGEROUS_METHODS[method]
                issues.append({
                    "title":       f"Dangerous HTTP Method Enabled: {method}",
                    "severity":    severity,
                    "description": description,
                    "category":    "HTTP Methods",
                    "confidence":  90 if allow else 70,
                    "evidence":    f"Allow: {allow}" if allow else f"{method} probe returned non-405",
                    "status":      "COMPLETED",
                })
    except requests.exceptions.RequestException:
        pass

    return issues


def _probe_methods(target: str) -> list:
    found = []
    for method in ["PUT", "DELETE", "TRACE", "PATCH"]:
        try:
            r = requests.request(method, target, timeout=TIMEOUT, verify=False)
            if r.status_code not in (405, 501, 403):
                found.append(method)
        except requests.exceptions.RequestException:
            pass
    return found
