# 🛡 OWASPScan — Security Misconfiguration Scanner

> Automated OWASP A02:2021 (Security Misconfiguration) detection tool.  
> Python/Flask backend · React frontend · Modular scanner architecture

---

## 📁 Project Structure

```
project/
├── backend/
│   ├── app.py                  # Flask application & API routes
│   ├── requirements.txt        # Python dependencies
│   └── scanner/
│       ├── __init__.py
│       ├── port_scan.py        # TCP port scanner (21 common ports)
│       ├── headers_check.py    # HTTP security header analysis
│       ├── http_methods.py     # Dangerous HTTP method detection
│       └── paths_check.py      # Sensitive path/endpoint discovery
├── frontend/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── main.jsx
│       └── App.jsx             # Full React UI (single file)
└── README.md
```

---

## ⚡ Quickstart

### 1 · Backend (Flask)

```bash
cd backend

# Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the API server
python app.py
```

The API will be available at **http://localhost:5000**

---

### 2 · Frontend (React + Vite)

```bash
cd frontend

# Install Node dependencies
npm install

# Start the dev server
npm run dev
```

Open **http://localhost:3000** in your browser.

---

## 🔌 API Reference

### `POST /scan`

Runs all scanner modules against the provided target.

**Request:**
```json
{ "target": "https://example.com" }
```

**Response:**
```json
{
  "target": "https://example.com",
  "score": 55,
  "total": 7,
  "issues": [
    {
      "title": "Missing Header: Content-Security-Policy",
      "severity": "High",
      "description": "Content-Security-Policy (CSP) header is missing...",
      "category": "Security Headers"
    }
  ]
}
```

### `GET /health`
Returns `{ "status": "ok" }` — used to verify the backend is running.

---

## 🧠 Scanner Modules

| Module | What it checks |
|--------|---------------|
| `port_scan.py` | 21 common ports — FTP, SSH, Telnet, MySQL, Redis, MongoDB, RDP, etc. |
| `headers_check.py` | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, cookie flags, info disclosure headers |
| `http_methods.py` | PUT, DELETE, TRACE, PATCH, CONNECT via OPTIONS + active probing |
| `paths_check.py` | 30+ sensitive paths: /.env, /.git, /admin, /backup, /actuator, /phpmyadmin, etc. |

---

## 🧮 Scoring Algorithm

```
Score = 100
  - 20 per High severity issue
  - 10 per Medium severity issue
  -  5 per Low severity issue
  (minimum: 0)
```

| Range | Label    |
|-------|----------|
| 80–100 | 🟢 Secure  |
| 50–79  | 🟡 At Risk |
| 0–49   | 🔴 Critical |

---

## ✨ Features

- **Modular scanner** — each check is an independent, pluggable module
- **Real-time UI** — animated scanning state with module labels
- **Severity badges** — color-coded High / Medium / Low
- **Score ring** — animated SVG ring with color-coded score
- **Category grouping** — issues grouped by type (Headers, Ports, Paths…)
- **Severity filter** — filter results by severity level
- **Download report** — saves a self-contained HTML report to disk
- **Expandable cards** — click any issue to reveal full description

---

## ⚠️ Legal Notice

This tool is intended for **authorized security testing only**.  
Only scan systems you own or have explicit written permission to test.  
Unauthorized scanning may violate computer fraud laws.

---

## 🚀 Production Notes

- Set `FLASK_ENV=production` and use a WSGI server (gunicorn) for production
- Add rate limiting (Flask-Limiter) to prevent abuse
- Consider adding authentication to the `/scan` endpoint
- The port scanner timeout is 1.5s per port — adjust in `port_scan.py` for speed vs accuracy trade-off
