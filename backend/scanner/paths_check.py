"""
paths_check.py
Checks for exposed sensitive paths/endpoints that should not be publicly accessible.
"""

import requests
from urllib.parse import urljoin

# Sensitive paths: path → (severity, description)
SENSITIVE_PATHS = {
    "/admin":               ("High",   "Admin panel is publicly accessible. This may expose administrative functions."),
    "/admin/":              ("High",   "Admin directory is publicly accessible."),
    "/administrator":       ("High",   "Administrator panel is accessible without authentication."),
    "/backup":              ("High",   "Backup directory is exposed. May contain sensitive data or source code."),
    "/backup.zip":          ("High",   "Backup archive is publicly downloadable."),
    "/backup.sql":          ("High",   "SQL backup file is publicly accessible."),
    "/config":              ("High",   "Configuration directory is exposed. May contain secrets, credentials, or API keys."),
    "/config.php":          ("High",   "PHP configuration file may be accessible."),
    "/.env":                ("High",   ".env file is publicly accessible. May contain API keys, DB credentials, and secrets."),
    "/.git":                ("High",   "Git repository is publicly exposed. Full source code and history may be extractable."),
    "/.git/config":         ("High",   "Git config file is accessible — exposes repository metadata."),
    "/wp-admin":            ("High",   "WordPress admin panel is accessible. Common target for brute-force attacks."),
    "/wp-config.php":       ("High",   "WordPress config file is exposed. Contains database credentials."),
    "/phpmyadmin":          ("High",   "phpMyAdmin interface is publicly accessible."),
    "/database":            ("High",   "Database directory is publicly accessible."),
    "/db":                  ("High",   "Database endpoint is exposed."),
    "/logs":                ("High",   "Log directory is accessible. May expose sensitive application data and errors."),
    "/log":                 ("Medium", "Log file is accessible. May reveal server internals and errors."),
    "/error_log":           ("Medium", "Error log is publicly accessible."),
    "/server-status":       ("Medium", "Apache server-status page is enabled and exposed."),
    "/server-info":         ("Medium", "Apache server-info page is exposed."),
    "/.htaccess":           ("Medium", "Apache .htaccess file is publicly readable."),
    "/robots.txt":          ("Low",    "robots.txt is accessible — may hint at hidden or sensitive paths."),
    "/sitemap.xml":         ("Low",    "Sitemap is publicly accessible — may reveal internal URL structure."),
    "/test":                ("Low",    "Test directory is accessible. May contain debug code or unprotected endpoints."),
    "/debug":               ("Medium", "Debug endpoint is accessible. May expose stack traces and internal state."),
    "/api/v1":              ("Low",    "API root is publicly discoverable."),
    "/swagger":             ("Medium", "Swagger API documentation is publicly exposed."),
    "/swagger-ui.html":     ("Medium", "Swagger UI is publicly accessible — reveals full API schema."),
    "/actuator":            ("High",   "Spring Boot Actuator is exposed. May leak environment variables and metrics."),
    "/actuator/env":        ("High",   "Spring Boot /actuator/env endpoint exposes environment variables."),
    "/health":              ("Low",    "Health check endpoint is publicly accessible."),
    "/.DS_Store":           ("Low",    ".DS_Store file is accessible — reveals macOS directory structure."),
}

REQUEST_TIMEOUT = 6


def check_paths(target: str) -> list:
    """
    Probe each sensitive path and report any that return accessible HTTP responses.
    Returns a list of issue dicts.
    """
    issues = []

    # Normalize base URL (remove trailing slash)
    base_url = target.rstrip("/")

    for path, (severity, description) in SENSITIVE_PATHS.items():
        url = base_url + path
        try:
            response = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,  # Don't follow — a redirect is still noteworthy
                verify=False,
            )

            status = response.status_code

            # 200 = fully accessible; 401/403 = exists but protected (still worth noting)
            if status == 200:
                issues.append({
                    "title": f"Exposed Path: {path}",
                    "severity": severity,
                    "description": f"{description} (HTTP {status})",
                    "category": "Exposed Paths",
                })
            elif status in (401, 403):
                # Exists but gated — lower severity, still informational
                issues.append({
                    "title": f"Restricted Path Detected: {path}",
                    "severity": "Low",
                    "description": f"The path {path} exists but is access-controlled (HTTP {status}). Verify it cannot be bypassed.",
                    "category": "Exposed Paths",
                })

        except requests.exceptions.RequestException:
            pass  # Unreachable path — skip silently

    return issues
