"""
paths_check.py
Checks for exposed sensitive paths. Normalized: confidence, evidence, status.
"""

import requests

SENSITIVE_PATHS = {
    "/admin":              ("High",   "Admin panel publicly accessible."),
    "/administrator":      ("High",   "Administrator panel accessible without auth."),
    "/backup":             ("High",   "Backup directory exposed. May contain source code/data."),
    "/backup.zip":         ("High",   "Backup archive publicly downloadable."),
    "/backup.sql":         ("High",   "SQL backup file publicly accessible."),
    "/config":             ("High",   "Config directory exposed. May contain secrets/API keys."),
    "/.env":               ("High",   ".env file accessible. May contain credentials and secrets."),
    "/.git":               ("High",   "Git repo exposed. Source code and history extractable."),
    "/.git/config":        ("High",   "Git config accessible — exposes repository metadata."),
    "/wp-admin":           ("High",   "WordPress admin panel accessible."),
    "/wp-config.php":      ("High",   "WordPress config exposed. Contains DB credentials."),
    "/phpmyadmin":         ("High",   "phpMyAdmin interface publicly accessible."),
    "/database":           ("High",   "Database directory publicly accessible."),
    "/logs":               ("High",   "Log directory accessible. May expose sensitive app data."),
    "/error_log":          ("Medium", "Error log publicly accessible."),
    "/server-status":      ("Medium", "Apache server-status page exposed."),
    "/server-info":        ("Medium", "Apache server-info page exposed."),
    "/.htaccess":          ("Medium", "Apache .htaccess readable."),
    "/debug":              ("Medium", "Debug endpoint accessible. May expose stack traces."),
    "/swagger":            ("Medium", "Swagger API docs publicly exposed."),
    "/swagger-ui.html":    ("Medium", "Swagger UI accessible — reveals full API schema."),
    "/actuator":           ("High",   "Spring Boot Actuator exposed. May leak env vars."),
    "/actuator/env":       ("High",   "/actuator/env exposes environment variables."),
    "/robots.txt":         ("Low",    "robots.txt accessible — hints at hidden paths."),
    "/sitemap.xml":        ("Low",    "Sitemap accessible — reveals internal URL structure."),
    "/test":               ("Low",    "Test directory accessible. May contain debug code."),
    "/health":             ("Low",    "Health check endpoint publicly accessible."),
    "/.DS_Store":          ("Low",    ".DS_Store reveals macOS directory structure."),
}

TIMEOUT = 6


def check_paths(target: str) -> list:
    issues = []
    base = target.rstrip("/")

    for path, (severity, description) in SENSITIVE_PATHS.items():
        url = base + path
        try:
            resp = requests.get(url, timeout=TIMEOUT, allow_redirects=False, verify=False)
            status = resp.status_code

            if status == 200:
                issues.append({
                    "title":       f"Exposed Path: {path}",
                    "severity":    severity,
                    "description": description,
                    "category":    "Exposed Paths",
                    "confidence":  95,
                    "evidence":    f"GET {url} → HTTP {status} ({len(resp.content)} bytes)",
                    "status":      "COMPLETED",
                })
            elif status in (401, 403):
                issues.append({
                    "title":       f"Restricted Path Detected: {path}",
                    "severity":    "Low",
                    "description": f"Path exists but is access-controlled (HTTP {status}). Verify bypass is not possible.",
                    "category":    "Exposed Paths",
                    "confidence":  80,
                    "evidence":    f"GET {url} → HTTP {status}",
                    "status":      "COMPLETED",
                })
        except requests.exceptions.RequestException:
            pass

    return issues
