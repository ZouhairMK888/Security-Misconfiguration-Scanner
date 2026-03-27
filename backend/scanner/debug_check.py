"""
debug_check.py  [NEW]
CWE-11  ASP.NET Misconfiguration: Creating Debug Binary
CWE-489 Active Debug Code
CWE-526 Exposure of Sensitive Information Through Environmental Variables

Detects active debug modes, debug headers, test/diagnostic endpoints,
ASP.NET debug compilation, and exposed environment variable endpoints.
"""

import requests

TIMEOUT = 8

# Paths that expose debug / diagnostic / environment information
DEBUG_PATHS = {
    # CWE-489 / CWE-526 — Active debug or env exposure
    "/?XDEBUG_SESSION_START=1":    ("Medium", "PHP XDebug session trigger detected — debug mode may be active (CWE-489).", "CWE-489"),
    "/?debug=1":                   ("Medium", "Debug parameter accepted — may activate verbose output (CWE-489).", "CWE-489"),
    "/?debug=true":                ("Medium", "Debug mode activated via query parameter (CWE-489).", "CWE-489"),
    "/?env=true":                  ("Medium", "Env parameter accepted — may expose environment variables (CWE-526).", "CWE-526"),
    "/actuator/env":               ("High",   "Spring Boot /actuator/env exposes environment variables including secrets (CWE-526).", "CWE-526"),
    "/actuator/configprops":       ("High",   "Spring Boot config properties endpoint exposed — may contain passwords (CWE-526).", "CWE-526"),
    "/actuator/heapdump":          ("High",   "Spring Boot heap dump endpoint exposed — full memory dump downloadable (CWE-526).", "CWE-526"),
    "/actuator/threaddump":        ("Medium", "Spring Boot thread dump exposed — reveals internal app state (CWE-526).", "CWE-526"),
    "/actuator/mappings":          ("Medium", "Spring Boot route mappings exposed — reveals full API surface (CWE-489).", "CWE-489"),
    "/actuator/beans":             ("Medium", "Spring Boot beans endpoint exposed — reveals internal component list (CWE-489).", "CWE-489"),
    "/env":                        ("High",   "Environment variables endpoint exposed (CWE-526).", "CWE-526"),
    "/debug/vars":                 ("High",   "Go expvar debug endpoint exposed — reveals runtime metrics and vars (CWE-489).", "CWE-489"),
    "/debug/pprof":                ("Medium", "Go pprof profiling endpoint exposed (CWE-489).", "CWE-489"),
    "/__debug__":                  ("Medium", "Debug endpoint discovered (CWE-489).", "CWE-489"),
    "/console":                    ("High",   "Web console exposed — may allow remote code execution (CWE-489).", "CWE-489"),
    "/rails/info/properties":      ("High",   "Rails info/properties page exposed — reveals Ruby/Rails versions and env (CWE-489).", "CWE-489"),
    "/rails/info/routes":          ("Medium", "Rails routes exposed — reveals full application routing (CWE-489).", "CWE-489"),
    "/_profiler":                  ("Medium", "Symfony profiler exposed — full request/response debug data visible (CWE-489).", "CWE-489"),
    "/_profiler/phpinfo":          ("High",   "Symfony phpinfo page exposed — full PHP configuration visible (CWE-489).", "CWE-489"),
    "/phpinfo.php":                ("High",   "phpinfo() page exposed — reveals PHP config, env vars, loaded modules (CWE-489).", "CWE-489"),
    "/info.php":                   ("High",   "phpinfo() page exposed — reveals full PHP environment (CWE-489).", "CWE-489"),
    "/test.php":                   ("Low",    "test.php accessible — may contain debug code (CWE-489).", "CWE-489"),
    # CWE-11 — ASP.NET debug binary / compilation
    "/elmah.axd":                  ("High",   "ELMAH error log handler exposed — full ASP.NET error history visible (CWE-11).", "CWE-11"),
    "/trace.axd":                  ("High",   "ASP.NET trace.axd exposed — reveals request/response debug data (CWE-11).", "CWE-11"),
    "/WebResource.axd":            ("Low",    "ASP.NET WebResource.axd accessible — check for debug build artifacts (CWE-11).", "CWE-11"),
    "/ScriptResource.axd":         ("Low",    "ASP.NET ScriptResource.axd accessible.", "CWE-11"),
    "/web.config":                 ("High",   "ASP.NET web.config accessible — may contain DB passwords and debug settings (CWE-11/CWE-260).", "CWE-11"),
    "/app_offline.htm":            ("Low",    "app_offline.htm present — reveals ASP.NET maintenance mode.", "CWE-11"),
}

# Response headers that indicate debug mode
DEBUG_HEADERS = {
    "X-Debug-Token":              ("Medium", "Symfony X-Debug-Token header present — profiler is active (CWE-489).", "CWE-489"),
    "X-Debug-Token-Link":         ("Medium", "Symfony X-Debug-Token-Link exposes profiler URL (CWE-489).", "CWE-489"),
    "X-Powered-By":               ("Low",    "X-Powered-By reveals technology stack (CWE-489).", "CWE-489"),
    "X-AspNet-Version":           ("Medium", "X-AspNet-Version reveals .NET version — check for known CVEs (CWE-11).", "CWE-11"),
    "X-AspNetMvc-Version":        ("Medium", "X-AspNetMvc-Version reveals MVC version (CWE-11).", "CWE-11"),
    "X-SourceFiles":              ("High",   "X-SourceFiles header present — ASP.NET debug mode is active (CWE-11).", "CWE-11"),
    "Server":                     ("Low",    "Server header reveals web server software/version (CWE-489).", "CWE-489"),
}

# Body signatures indicating debug/env exposure in response
BODY_SIGNATURES = [
    ("XDEBUG",             "High",   "XDebug output detected in response — PHP debug mode active (CWE-489).", "CWE-489"),
    ("APP_ENV",            "High",   "APP_ENV variable exposed in response body (CWE-526).", "CWE-526"),
    ("DATABASE_URL",       "High",   "DATABASE_URL environment variable leaked in response (CWE-526).", "CWE-526"),
    ("SECRET_KEY",         "High",   "SECRET_KEY environment variable leaked in response (CWE-526).", "CWE-526"),
    ("AWS_ACCESS_KEY",     "High",   "AWS access key leaked in response body (CWE-526).", "CWE-526"),
    ("debug: true",        "Medium", "debug: true found in response body — debug mode active (CWE-489).", "CWE-489"),
    ("compilation debug",  "High",   "ASP.NET debug compilation attribute detected (CWE-11).", "CWE-11"),
    ("phpinfo()",          "High",   "phpinfo() output detected — full PHP config exposed (CWE-489).", "CWE-489"),
    ("Server Variables",   "High",   "Server Variables table detected — PHP server variables exposed (CWE-526).", "CWE-526"),
    ("_SERVER",            "Medium", "$_SERVER array contents exposed in response (CWE-526).", "CWE-526"),
    ("System.Diagnostics", "Medium", "ASP.NET System.Diagnostics namespace referenced in response (CWE-11).", "CWE-11"),
]


def check_debug(target: str) -> list:
    issues = []
    base = target.rstrip("/")

    # ── 1. Check debug response headers on base URL ───────────────────────────
    try:
        resp = requests.get(target, timeout=TIMEOUT, verify=False)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header, (severity, description, cwe) in DEBUG_HEADERS.items():
            if header.lower() in headers_lower:
                val = headers_lower[header.lower()]
                issues.append({
                    "title":       f"Debug/Info Header Present: {header}",
                    "severity":    severity,
                    "description": description,
                    "category":    "Debug & Configuration Exposure",
                    "cwe":         cwe,
                    "confidence":  100,
                    "evidence":    f"{header}: {val}",
                    "status":      "COMPLETED",
                })

        # Check body of base response for debug signatures
        body = resp.text
        for sig, severity, description, cwe in BODY_SIGNATURES:
            if sig.lower() in body.lower():
                idx = body.lower().find(sig.lower())
                snippet = body[max(0, idx - 20): idx + len(sig) + 60].strip().replace("\n", " ")[:150]
                issues.append({
                    "title":       f"Sensitive Data in Response: {sig[:40]}",
                    "severity":    severity,
                    "description": description,
                    "category":    "Debug & Configuration Exposure",
                    "cwe":         cwe,
                    "confidence":  85,
                    "evidence":    f"Found at base URL — ...{snippet}...",
                    "status":      "COMPLETED",
                })

    except requests.exceptions.RequestException:
        pass

    # ── 2. Probe debug/env paths ──────────────────────────────────────────────
    seen = set()
    for path, (severity, description, cwe) in DEBUG_PATHS.items():
        url = base + path
        try:
            resp = requests.get(url, timeout=TIMEOUT, allow_redirects=False, verify=False)
            code = resp.status_code

            if code == 200 and path not in seen:
                seen.add(path)
                body_snippet = resp.text[:300].replace("\n", " ").strip()
                issues.append({
                    "title":       f"Debug/Env Endpoint Exposed: {path}",
                    "severity":    severity,
                    "description": description,
                    "category":    "Debug & Configuration Exposure",
                    "cwe":         cwe,
                    "confidence":  92,
                    "evidence":    f"GET {url} → HTTP {code} ({len(resp.content)} bytes) — {body_snippet[:100]}...",
                    "status":      "COMPLETED",
                })
        except requests.exceptions.RequestException:
            pass

    return issues
