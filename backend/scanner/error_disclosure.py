"""
error_disclosure.py  [NEW MODULE]
Detects verbose error pages and application stack trace leakage.
OWASP A02 — misconfigured debug/error modes expose internal details.
"""

import requests

# Probe paths likely to trigger errors
ERROR_PROBE_PATHS = [
    "/nonexistent_mk8scan_probe",
    "/index.php?id=",
    "/?debug=true",
    "/?test=<script>",
    "/api/nonexistent",
]

# Signatures indicating verbose error disclosure
ERROR_SIGNATURES = [
    # Stack traces
    ("Traceback (most recent call last)", "Python stack trace leaked in response.",   "High"),
    ("at com.",                           "Java stack trace leaked in response.",      "High"),
    ("System.Exception",                  ".NET exception details leaked.",            "High"),
    ("Fatal error:",                      "PHP fatal error message exposed.",          "High"),
    ("Warning:",                          "PHP warning message exposed.",              "Medium"),
    ("Parse error:",                      "PHP parse error exposed.",                  "High"),
    # Debug info
    ("debug=true",                        "Debug mode indicator found in response.",   "Medium"),
    ("APP_DEBUG",                         "APP_DEBUG flag referenced in response.",    "Medium"),
    ("SQL syntax",                        "SQL error leaked — possible SQLi surface.", "High"),
    ("ORA-",                              "Oracle DB error message exposed.",          "High"),
    ("MySQL server version",              "MySQL version disclosed via error.",        "Medium"),
    ("SQLSTATE",                          "Database SQLSTATE error code leaked.",      "Medium"),
    # Framework debug pages
    ("Whoa! You broke something!",        "Laravel debug page exposed.",               "High"),
    ("Application Error",                 "Generic application error page exposed.",   "Low"),
    ("werkzeug",                          "Werkzeug/Flask debugger may be active.",    "High"),
    ("Interactive Console",               "Werkzeug interactive debugger is ACTIVE.",  "High"),
    ("Django Version",                    "Django debug page with version info.",      "High"),
]

TIMEOUT = 8


def check_error_disclosure(target: str) -> list:
    """
    Probe the target with paths/params likely to trigger error pages.
    Inspect responses for stack traces and verbose error signatures.
    """
    issues = []
    base = target.rstrip("/")
    seen_signatures = set()  # Avoid duplicate findings

    for path in ERROR_PROBE_PATHS:
        url = base + path
        try:
            resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
            body = resp.text

            for signature, description, severity in ERROR_SIGNATURES:
                if signature.lower() in body.lower() and signature not in seen_signatures:
                    seen_signatures.add(signature)

                    # Extract a snippet of evidence around the signature
                    idx = body.lower().find(signature.lower())
                    snippet = body[max(0, idx - 40): idx + len(signature) + 80].strip()
                    snippet = snippet.replace("\n", " ")[:200]

                    issues.append({
                        "title":       f"Verbose Error Disclosure: {signature[:40]}",
                        "severity":    severity,
                        "description": description,
                        "category":    "Error Disclosure",
                        "confidence":  90,
                        "evidence":    f"Found in response to GET {url} — ...{snippet}...",
                        "status":      "COMPLETED",
                    })

        except requests.exceptions.RequestException:
            pass

    return issues
