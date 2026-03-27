"""
config_files.py  [NEW]
CWE-13  ASP.NET Misconfiguration: Password in Configuration File
CWE-260 Password in Configuration File
CWE-547 Use of Hard-coded, Security-relevant Constants (partial)

Probes for exposed configuration files across all major frameworks,
and analyzes their content for embedded credentials and secrets.
"""

import re
import requests

TIMEOUT = 7

# Config files to probe: path → (severity, description, cwe)
CONFIG_PATHS = {
    # Generic config files
    "/.env":                      ("High",   "Root .env file exposed — may contain DB_PASSWORD, API keys, JWT secrets.", "CWE-260"),
    "/.env.local":                ("High",   ".env.local exposed — local override env with credentials.", "CWE-260"),
    "/.env.production":           ("High",   ".env.production exposed — production secrets accessible.", "CWE-260"),
    "/.env.development":          ("Medium", ".env.development exposed — development credentials leaked.", "CWE-260"),
    "/.env.backup":               ("High",   ".env backup file exposed.", "CWE-260"),
    "/.env.example":              ("Low",    ".env.example exposed — reveals expected credential key names.", "CWE-260"),

    # ASP.NET / .NET (CWE-13)
    "/web.config":                ("High",   "ASP.NET web.config exposed — may contain DB connection strings and passwords.", "CWE-13"),
    "/Web.config":                ("High",   "ASP.NET Web.config exposed (case variant).", "CWE-13"),
    "/appsettings.json":          ("High",   "ASP.NET Core appsettings.json exposed — may contain ConnectionStrings and secrets.", "CWE-13"),
    "/appsettings.Production.json": ("High", "ASP.NET Core production settings exposed.", "CWE-13"),
    "/appsettings.Development.json": ("Medium", "ASP.NET Core dev settings exposed.", "CWE-13"),

    # Java / Spring
    "/application.properties":   ("High",   "Spring application.properties exposed — may contain datasource passwords.", "CWE-260"),
    "/application.yml":           ("High",   "Spring application.yml exposed — may contain DB credentials.", "CWE-260"),
    "/application-prod.properties": ("High", "Spring production properties exposed.", "CWE-260"),
    "/config/application.yml":   ("High",   "Spring config/application.yml exposed.", "CWE-260"),
    "/src/main/resources/application.properties": ("High", "Spring source config exposed.", "CWE-260"),

    # PHP
    "/config.php":                ("High",   "PHP config.php exposed — may contain DB credentials.", "CWE-260"),
    "/configuration.php":         ("High",   "PHP configuration.php exposed.", "CWE-260"),
    "/wp-config.php":             ("High",   "WordPress wp-config.php exposed — contains DB_USER and DB_PASSWORD.", "CWE-260"),
    "/config/database.php":       ("High",   "Laravel database config exposed — contains DB credentials.", "CWE-260"),
    "/config/app.php":            ("Medium", "Laravel app config exposed — may contain APP_KEY.", "CWE-260"),

    # Ruby on Rails
    "/config/database.yml":       ("High",   "Rails database.yml exposed — contains DB username and password.", "CWE-260"),
    "/config/secrets.yml":        ("High",   "Rails secrets.yml exposed — contains secret_key_base.", "CWE-547"),
    "/config/credentials.yml.enc": ("Low",   "Rails encrypted credentials file accessible (encrypted but notable).", "CWE-260"),
    "/config/master.key":         ("High",   "Rails master.key exposed — decrypts all Rails credentials!", "CWE-547"),

    # Node.js
    "/.npmrc":                    ("High",   ".npmrc exposed — may contain NPM_TOKEN with registry access.", "CWE-547"),
    "/.yarnrc":                   ("Medium", ".yarnrc exposed — may contain registry tokens.", "CWE-547"),
    "/config/config.json":        ("Medium", "config.json exposed.", "CWE-260"),
    "/config/default.json":       ("Medium", "Node config default.json exposed.", "CWE-260"),
    "/config/production.json":    ("High",   "Node production config exposed.", "CWE-260"),

    # Docker / CI-CD
    "/docker-compose.yml":        ("High",   "docker-compose.yml exposed — may contain service passwords and env vars.", "CWE-260"),
    "/docker-compose.yaml":       ("High",   "docker-compose.yaml exposed.", "CWE-260"),
    "/.dockerenv":                ("Low",    ".dockerenv file accessible — confirms Docker container environment.", "CWE-489"),
    "/.github/workflows/ci.yml":  ("Medium", "GitHub Actions workflow exposed — may reveal CI secrets.", "CWE-547"),
    "/.travis.yml":               ("Medium", ".travis.yml CI config exposed — may contain env vars.", "CWE-547"),
    "/Jenkinsfile":               ("Medium", "Jenkinsfile exposed — may reveal pipeline credentials.", "CWE-547"),

    # Cloud / Infrastructure
    "/.aws/credentials":          ("High",   "AWS credentials file exposed — AWS_ACCESS_KEY_ID and SECRET.", "CWE-547"),
    "/terraform.tfvars":          ("High",   "Terraform variables file exposed — may contain cloud provider secrets.", "CWE-547"),
    "/terraform.tfstate":         ("High",   "Terraform state file exposed — contains full infrastructure config.", "CWE-547"),
    "/ansible/vault_pass.txt":    ("High",   "Ansible vault password file exposed.", "CWE-547"),
    "/kubeconfig":                ("High",   "Kubeconfig exposed — Kubernetes cluster access credentials.", "CWE-547"),

    # Database dumps
    "/dump.sql":                  ("High",   "SQL dump file exposed — full database backup accessible.", "CWE-260"),
    "/db.sql":                    ("High",   "SQL database file accessible.", "CWE-260"),
    "/database.sql":              ("High",   "Database SQL dump accessible.", "CWE-260"),

    # SSH / Crypto keys
    "/id_rsa":                    ("High",   "Private SSH key exposed — full server access possible.", "CWE-547"),
    "/.ssh/id_rsa":               ("High",   "SSH private key in .ssh directory exposed.", "CWE-547"),
    "/server.key":                ("High",   "Private TLS key exposed — can decrypt all HTTPS traffic.", "CWE-547"),
    "/private.key":               ("High",   "Private key file exposed.", "CWE-547"),
}

# Regex patterns to detect credentials in exposed file content (CWE-260, CWE-547)
CREDENTIAL_PATTERNS = [
    (r"password\s*[=:]\s*['\"]?[^\s'\"]{4,}", "High",   "Password/credential value detected in file content.", "CWE-260"),
    (r"passwd\s*[=:]\s*['\"]?[^\s'\"]{4,}",   "High",   "passwd value detected in file content.", "CWE-260"),
    (r"db_pass\w*\s*[=:]\s*['\"]?[^\s'\"]{4,}","High",  "Database password detected in config file.", "CWE-260"),
    (r"secret\s*[=:]\s*['\"]?[^\s'\"]{8,}",   "High",   "Secret value detected in file content.", "CWE-547"),
    (r"api_key\s*[=:]\s*['\"]?[^\s'\"]{8,}",  "High",   "API key detected in file content.", "CWE-547"),
    (r"aws_access_key_id\s*[=:]\s*[A-Z0-9]{20}","High", "AWS Access Key ID detected.", "CWE-547"),
    (r"aws_secret_access_key\s*[=:]\s*[^\s]{30,}","High","AWS Secret Access Key detected.", "CWE-547"),
    (r"private_key\s*[=:]\s*['\"]?[^\s'\"]{8,}","High", "Private key value detected.", "CWE-547"),
    (r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----","High","Private key block detected in response.", "CWE-547"),
    (r"token\s*[=:]\s*['\"]?[a-zA-Z0-9_\-\.]{20,}","High","Token value detected in file.", "CWE-547"),
    (r"connection.?string.*password",          "High",   "Connection string with password detected.", "CWE-13"),
]


def _scan_content_for_credentials(content: str, source_url: str) -> list:
    """Scan file content for embedded credential patterns."""
    findings = []
    for pattern, severity, description, cwe in CREDENTIAL_PATTERNS:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            snippet = match.group(0)[:80]
            findings.append({
                "title":       f"Credential Pattern in Exposed File",
                "severity":    severity,
                "description": description,
                "category":    "Exposed Configuration",
                "cwe":         cwe,
                "confidence":  85,
                "evidence":    f"In {source_url} — matched: {snippet}",
                "status":      "COMPLETED",
            })
    return findings


def check_config_files(target: str) -> list:
    issues = []
    base = target.rstrip("/")

    for path, (severity, description, cwe) in CONFIG_PATHS.items():
        url = base + path
        try:
            resp = requests.get(url, timeout=TIMEOUT, allow_redirects=False, verify=False)
            code = resp.status_code

            if code == 200:
                content = resp.text
                content_len = len(resp.content)

                issues.append({
                    "title":       f"Exposed Config File: {path}",
                    "severity":    severity,
                    "description": description,
                    "category":    "Exposed Configuration",
                    "cwe":         cwe,
                    "confidence":  95,
                    "evidence":    f"GET {url} → HTTP {code} ({content_len} bytes)",
                    "status":      "COMPLETED",
                })

                # Scan content for credentials
                if content_len < 50000:  # Only scan reasonably sized files
                    cred_findings = _scan_content_for_credentials(content, url)
                    issues.extend(cred_findings)

            elif code in (401, 403):
                issues.append({
                    "title":       f"Config File Exists (Access Restricted): {path}",
                    "severity":    "Low",
                    "description": f"Config file detected but access-controlled (HTTP {code}). Verify authentication cannot be bypassed.",
                    "category":    "Exposed Configuration",
                    "cwe":         cwe,
                    "confidence":  75,
                    "evidence":    f"GET {url} → HTTP {code}",
                    "status":      "COMPLETED",
                })

        except requests.exceptions.RequestException:
            pass

    return issues
