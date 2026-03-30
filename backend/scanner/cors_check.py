"""
cors_check.py  [NEW]
CWE-942 Permissive Cross-domain Policy with Untrusted Domains

Tests CORS configuration by sending Origin headers with malicious/wildcard
values and inspecting Access-Control-* response headers.
"""

import requests

TIMEOUT = 8

TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
    "https://trusted.com.evil.com",
]


def check_cors(target: str) -> list:
    issues = []

    for origin in TEST_ORIGINS:
        try:
            resp = requests.get(
                target,
                headers={"Origin": origin},
                timeout=TIMEOUT,
                verify=False,
            )

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            acam = resp.headers.get("Access-Control-Allow-Methods", "")

            # ── Wildcard CORS ──────────────────────────────────────────────
            if acao == "*":
                issues.append({
                    "title":       "CORS Wildcard Origin Allowed (*)",
                    "severity":    "Medium",
                    "description": "Access-Control-Allow-Origin: * permits any domain to make cross-origin requests. Sensitive API endpoints should restrict allowed origins (CWE-942).",
                    "category":    "CORS Misconfiguration",
                    "cwe":         "CWE-942",
                    "confidence":  100,
                    "evidence":    f"Request Origin: {origin} → Access-Control-Allow-Origin: {acao}",
                    "status":      "COMPLETED",
                })
                break  # Wildcard supersedes other checks

            # ── Origin reflected back ──────────────────────────────────────
            if acao == origin and origin != "null":
                base_msg = f"Server reflects arbitrary Origin '{origin}' in Access-Control-Allow-Origin."

                if acac == "true":
                    # Critical: reflected origin + credentials = cross-site requests with cookies
                    issues.append({
                        "title":       "CORS: Arbitrary Origin Reflected + Credentials Allowed",
                        "severity":    "High",
                        "description": f"{base_msg} Combined with Access-Control-Allow-Credentials: true, this allows a malicious site to make authenticated requests on behalf of a victim (CWE-942).",
                        "category":    "CORS Misconfiguration",
                        "cwe":         "CWE-942",
                        "confidence":  95,
                        "evidence":    f"Origin: {origin} → ACAO: {acao}, ACAC: {acac}",
                        "status":      "COMPLETED",
                    })
                else:
                    issues.append({
                        "title":       "CORS: Arbitrary Origin Reflected",
                        "severity":    "Medium",
                        "description": f"{base_msg} Any domain can read responses from this server (CWE-942).",
                        "category":    "CORS Misconfiguration",
                        "cwe":         "CWE-942",
                        "confidence":  90,
                        "evidence":    f"Origin: {origin} → ACAO: {acao}",
                        "status":      "COMPLETED",
                    })
                break

            # ── Null origin accepted ───────────────────────────────────────
            if acao == "null" and origin == "null":
                issues.append({
                    "title":       "CORS: Null Origin Accepted",
                    "severity":    "Medium",
                    "description": "Server accepts 'null' as a trusted origin. Attackers can send requests with Origin: null from sandboxed iframes or local files (CWE-942).",
                    "category":    "CORS Misconfiguration",
                    "cwe":         "CWE-942",
                    "confidence":  90,
                    "evidence":    f"Origin: null → ACAO: null",
                    "status":      "COMPLETED",
                })
                break

        except requests.exceptions.RequestException:
            pass

    # ── Check for CORS on preflight (OPTIONS) ────────────────────────────────
    try:
        preflight = requests.options(
            target,
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type, Authorization",
            },
            timeout=TIMEOUT,
            verify=False,
        )
        acao = preflight.headers.get("Access-Control-Allow-Origin", "")
        acam = preflight.headers.get("Access-Control-Allow-Methods", "")
        acah = preflight.headers.get("Access-Control-Allow-Headers", "")

        if acao and "evil.com" in acao:
            issues.append({
                "title":       "CORS Preflight Allows Untrusted Origin",
                "severity":    "High",
                "description": "The CORS preflight (OPTIONS) response allows requests from untrusted origins including Authorization headers (CWE-942).",
                "category":    "CORS Misconfiguration",
                "cwe":         "CWE-942",
                "confidence":  90,
                "evidence":    f"OPTIONS preflight → ACAO: {acao}, Methods: {acam}, Headers: {acah}",
                "status":      "COMPLETED",
            })
    except requests.exceptions.RequestException:
        pass

    return issues
