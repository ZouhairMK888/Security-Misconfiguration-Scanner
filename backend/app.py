"""
Web Security Scanner - Flask Backend
OWASP Top 10: A02 - Security Misconfiguration
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from scanner.port_scan import scan_ports
from scanner.headers_check import check_headers
from scanner.http_methods import check_http_methods
from scanner.paths_check import check_paths

app = Flask(__name__)
CORS(app)  # Allow all origins for development


def calculate_score(issues: list) -> int:
    """
    Compute a security score out of 100.
    High   => -20 points
    Medium => -10 points
    Low    =>  -5 points
    """
    score = 100
    deductions = {"High": 20, "Medium": 10, "Low": 5}
    for issue in issues:
        severity = issue.get("severity", "Low")
        score -= deductions.get(severity, 0)
    return max(score, 0)  # Never go below 0


@app.route("/scan", methods=["POST"])
def scan():
    """
    POST /scan
    Body: { "target": "http://example.com" }
    Returns all discovered issues and a global security score.
    """
    data = request.get_json()

    if not data or "target" not in data:
        return jsonify({"error": "Missing 'target' field"}), 400

    target = data["target"].strip()
    if not target:
        return jsonify({"error": "Target cannot be empty"}), 400

    # Normalize: add http:// if missing scheme
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    issues = []

    # Run all scanner modules
    issues += scan_ports(target)
    issues += check_headers(target)
    issues += check_http_methods(target)
    issues += check_paths(target)

    score = calculate_score(issues)

    return jsonify({
        "target": target,
        "issues": issues,
        "score": score,
        "total": len(issues)
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
