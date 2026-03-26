import time
from flask import Flask, request, jsonify
from flask_cors import CORS
from scanner.port_scan import scan_ports
from scanner.headers_check import check_headers
from scanner.http_methods import check_http_methods
from scanner.paths_check import check_paths
from scanner.error_disclosure import check_error_disclosure

app = Flask(__name__)
CORS(app)

# ── Scoring ──────────────────────────────────────────────────────────────────
DEDUCTIONS = {"High": 20, "Medium": 10, "Low": 5}

def calculate_score(issues: list) -> int:
    score = 100
    for issue in issues:
        score -= DEDUCTIONS.get(issue.get("severity", "Low"), 0)
    return max(score, 0)


# ── Module registry ──────────────────────────────────────────────────────────
MODULES = {
    "port_scan":        scan_ports,
    "headers_check":    check_headers,
    "http_methods":     check_http_methods,
    "paths_check":      check_paths,
    "error_disclosure": check_error_disclosure,
}

# Per-module timebox in seconds (adaptive strategy)
MODULE_TIMEBOXES = {
    "port_scan":        20,
    "headers_check":    10,
    "http_methods":     10,
    "paths_check":      30,
    "error_disclosure": 10,
}


def run_module(name: str, fn, target: str) -> dict:
    """
    Run a single scanner module with timebox enforcement.
    Returns a normalized module result with status, issues, duration.
    """
    timebox = MODULE_TIMEBOXES.get(name, 15)
    start = time.time()
    status = "COMPLETED"
    issues = []

    try:
        issues = fn(target)
        elapsed = time.time() - start
        if elapsed >= timebox * 0.9:
            status = "PARTIAL"
    except Exception as e:
        status = "ERROR"
        issues = [{
            "title": f"Module Error: {name}",
            "severity": "Low",
            "description": str(e),
            "category": "Scanner Error",
            "confidence": 0,
            "evidence": "",
            "status": "ERROR",
        }]

    elapsed = round(time.time() - start, 2)
    return {
        "module": name,
        "status": status,
        "duration_s": elapsed,
        "issues": issues,
    }


def normalize_target(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "http://" + t
    return t


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.route("/scan", methods=["POST"])
def full_scan():
    """POST /scan — runs ALL modules."""
    data = request.get_json()
    if not data or not data.get("target", "").strip():
        return jsonify({"error": "Missing or empty 'target' field"}), 400

    target = normalize_target(data["target"])
    scan_start = time.time()

    module_results = []
    all_issues = []

    for name, fn in MODULES.items():
        result = run_module(name, fn, target)
        module_results.append(result)
        all_issues.extend(result["issues"])

    total_duration = round(time.time() - scan_start, 2)
    overall_status = (
        "ERROR"   if all(r["status"] == "ERROR" for r in module_results) else
        "PARTIAL" if any(r["status"] in ("ERROR", "PARTIAL") for r in module_results) else
        "COMPLETED"
    )

    return jsonify({
        "target": target,
        "status": overall_status,
        "score": calculate_score(all_issues),
        "total": len(all_issues),
        "duration_s": total_duration,
        "modules": module_results,
        "issues": all_issues,
    })


@app.route("/scan/single", methods=["POST"])
def single_scan():
    """POST /scan/single — runs ONE specific module."""
    data = request.get_json()
    if not data or not data.get("target", "").strip():
        return jsonify({"error": "Missing or empty 'target' field"}), 400

    module_name = data.get("module", "").strip()
    if not module_name:
        return jsonify({"error": f"Missing 'module'. Available: {list(MODULES.keys())}"}), 400
    if module_name not in MODULES:
        return jsonify({"error": f"Unknown module '{module_name}'. Available: {list(MODULES.keys())}"}), 400

    target = normalize_target(data["target"])
    result = run_module(module_name, MODULES[module_name], target)
    issues = result["issues"]

    return jsonify({
        "target": target,
        "status": result["status"],
        "module": module_name,
        "score": calculate_score(issues),
        "total": len(issues),
        "duration_s": result["duration_s"],
        "issues": issues,
    })


@app.route("/modules", methods=["GET"])
def list_modules():
    return jsonify({"modules": list(MODULES.keys())})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "2.0"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
