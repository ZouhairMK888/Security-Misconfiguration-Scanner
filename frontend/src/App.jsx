import { useState, useEffect, useRef } from "react";

const API_BASE = "http://localhost:5000";

// ── Severity config ─────────────────────────────────────────────────────────
const SEVERITY = {
  High:   { color: "#ff4d4d", bg: "rgba(255,77,77,0.12)",   glow: "rgba(255,77,77,0.35)",   icon: "⬆" },
  Medium: { color: "#ffaa00", bg: "rgba(255,170,0,0.12)",   glow: "rgba(255,170,0,0.35)",   icon: "➔" },
  Low:    { color: "#00cfff", bg: "rgba(0,207,255,0.10)",   glow: "rgba(0,207,255,0.25)",   icon: "⬇" },
};

const SCORE_COLOR = (s) =>
  s >= 80 ? "#00e676" : s >= 50 ? "#ffaa00" : "#ff4d4d";

// ── Utility ─────────────────────────────────────────────────────────────────
function groupByCategory(issues) {
  return issues.reduce((acc, issue) => {
    const cat = issue.category || "General";
    acc[cat] = acc[cat] ? [...acc[cat], issue] : [issue];
    return acc;
  }, {});
}

// ── Sub-components ───────────────────────────────────────────────────────────

function ScannerLogo() {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
      <div style={{
        width: 42, height: 42, borderRadius: 10,
        background: "linear-gradient(135deg, #00cfff 0%, #7b61ff 100%)",
        display: "flex", alignItems: "center", justifyContent: "center",
        fontSize: 22, boxShadow: "0 0 18px rgba(0,207,255,0.4)",
      }}>🛡</div>
      <div>
        <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 18, fontWeight: 700, letterSpacing: 1, color: "#e8f4ff" }}>
          MK8<span style={{ color: "#00cfff" }}>Scan</span>
        </div>
        <div style={{ fontSize: 10, color: "#6a8faa", letterSpacing: 2, fontFamily: "'Space Mono', monospace" }}>
          SECURITY MISCONFIGURATION SCANNER
        </div>
      </div>
    </div>
  );
}

function ScoreRing({ score }) {
  const r = 54, cx = 70, cy = 70;
  const circ = 2 * Math.PI * r;
  const dash = circ - (score / 100) * circ;
  const color = SCORE_COLOR(score);
  const label = score >= 80 ? "SECURE" : score >= 50 ? "AT RISK" : "CRITICAL";

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
      <svg width={140} height={140} style={{ filter: `drop-shadow(0 0 14px ${color}55)` }}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={10} />
        <circle
          cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth={10}
          strokeDasharray={circ} strokeDashoffset={dash}
          strokeLinecap="round"
          transform={`rotate(-90 ${cx} ${cy})`}
          style={{ transition: "stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1)" }}
        />
        <text x={cx} y={cy - 8} textAnchor="middle" fill={color}
          style={{ fontFamily: "'Space Mono', monospace", fontSize: 28, fontWeight: 700 }}>
          {score}
        </text>
        <text x={cx} y={cy + 14} textAnchor="middle" fill="rgba(255,255,255,0.4)"
          style={{ fontFamily: "'Space Mono', monospace", fontSize: 9, letterSpacing: 2 }}>
          / 100
        </text>
      </svg>
      <span style={{
        fontFamily: "'Space Mono', monospace", fontSize: 11, letterSpacing: 3,
        color, padding: "3px 10px",
        border: `1px solid ${color}55`, borderRadius: 4,
      }}>{label}</span>
    </div>
  );
}

function SeverityBadge({ severity }) {
  const cfg = SEVERITY[severity] || SEVERITY.Low;
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, letterSpacing: 1.5,
      fontFamily: "'Space Mono', monospace",
      color: cfg.color, background: cfg.bg,
      border: `1px solid ${cfg.color}55`,
      borderRadius: 4, padding: "3px 8px",
      whiteSpace: "nowrap",
    }}>
      {cfg.icon} {severity.toUpperCase()}
    </span>
  );
}

function IssueCard({ issue, index }) {
  const [open, setOpen] = useState(false);
  const cfg = SEVERITY[issue.severity] || SEVERITY.Low;
  return (
    <div
      onClick={() => setOpen(!open)}
      style={{
        background: "rgba(255,255,255,0.03)",
        border: `1px solid ${open ? cfg.color + "55" : "rgba(255,255,255,0.07)"}`,
        borderLeft: `3px solid ${cfg.color}`,
        borderRadius: 8, padding: "12px 16px",
        cursor: "pointer",
        transition: "border-color 0.2s, background 0.2s",
        animation: `fadeUp 0.35s ease ${index * 0.04}s both`,
      }}
      onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.055)"}
      onMouseLeave={e => e.currentTarget.style.background = open ? "rgba(255,255,255,0.04)" : "rgba(255,255,255,0.03)"}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
        <div style={{ fontFamily: "'Space Mono', monospace", fontSize: 13, color: "#d0e8ff", fontWeight: 600 }}>
          {issue.title}
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0 }}>
          <SeverityBadge severity={issue.severity} />
          <span style={{ color: "rgba(255,255,255,0.3)", fontSize: 11 }}>{open ? "▲" : "▼"}</span>
        </div>
      </div>
      {open && (
        <div style={{
          marginTop: 10, paddingTop: 10,
          borderTop: "1px solid rgba(255,255,255,0.07)",
          fontSize: 12, color: "#8ab4d4", lineHeight: 1.7,
          fontFamily: "'IBM Plex Mono', monospace",
        }}>
          <span style={{ color: cfg.color, marginRight: 6 }}>▸</span>{issue.description}
        </div>
      )}
    </div>
  );
}

function FilterBar({ active, onChange, counts }) {
  const filters = ["All", "High", "Medium", "Low"];
  return (
    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
      {filters.map(f => {
        const isAll = f === "All";
        const cfg = SEVERITY[f] || {};
        const count = isAll ? Object.values(counts).reduce((a, b) => a + b, 0) : (counts[f] || 0);
        const isActive = active === f;
        return (
          <button key={f} onClick={() => onChange(f)} style={{
            fontFamily: "'Space Mono', monospace", fontSize: 11, letterSpacing: 1,
            padding: "5px 14px", borderRadius: 5, cursor: "pointer",
            border: `1px solid ${isActive ? (isAll ? "#00cfff" : cfg.color) : "rgba(255,255,255,0.12)"}`,
            background: isActive
              ? (isAll ? "rgba(0,207,255,0.12)" : cfg.bg)
              : "rgba(255,255,255,0.03)",
            color: isActive ? (isAll ? "#00cfff" : cfg.color) : "rgba(255,255,255,0.5)",
            transition: "all 0.2s",
          }}>
            {f} {count > 0 && <span style={{ opacity: 0.7 }}>({count})</span>}
          </button>
        );
      })}
    </div>
  );
}

function ProgressBar({ label, value, max, color }) {
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
        <span style={{ fontSize: 11, fontFamily: "'Space Mono', monospace", color: "rgba(255,255,255,0.5)" }}>{label}</span>
        <span style={{ fontSize: 11, fontFamily: "'Space Mono', monospace", color }}>{value}</span>
      </div>
      <div style={{ height: 4, background: "rgba(255,255,255,0.07)", borderRadius: 2, overflow: "hidden" }}>
        <div style={{
          height: "100%", width: `${(value / Math.max(max, 1)) * 100}%`,
          background: color, borderRadius: 2,
          transition: "width 0.8s ease",
          boxShadow: `0 0 8px ${color}`,
        }} />
      </div>
    </div>
  );
}

function ScannerAnimation() {
  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center", gap: 20,
      padding: "40px 0",
    }}>
      <div style={{ position: "relative", width: 80, height: 80 }}>
        {[0, 1, 2].map(i => (
          <div key={i} style={{
            position: "absolute", inset: 0,
            border: "2px solid rgba(0,207,255,0.6)",
            borderRadius: "50%",
            animation: `ping 1.5s ease-out ${i * 0.5}s infinite`,
          }} />
        ))}
        <div style={{
          position: "absolute", inset: "50%", transform: "translate(-50%,-50%)",
          width: 28, height: 28,
          background: "linear-gradient(135deg, #00cfff, #7b61ff)",
          borderRadius: "50%",
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 14,
        }}>🛡</div>
      </div>
      <div style={{
        fontFamily: "'Space Mono', monospace", fontSize: 12, letterSpacing: 3,
        color: "#00cfff", animation: "pulse 1.5s ease-in-out infinite",
      }}>
        SCANNING TARGET...
      </div>
      <div style={{
        display: "flex", gap: 6,
      }}>
        {["PORTS", "HEADERS", "METHODS", "PATHS"].map((step, i) => (
          <div key={step} style={{
            fontSize: 9, fontFamily: "'Space Mono', monospace", letterSpacing: 1,
            color: "rgba(0,207,255,0.6)", padding: "2px 8px",
            border: "1px solid rgba(0,207,255,0.2)", borderRadius: 3,
            animation: `blink 2s ease-in-out ${i * 0.4}s infinite`,
          }}>{step}</div>
        ))}
      </div>
    </div>
  );
}

// ── PDF Generation ───────────────────────────────────────────────────────────
function generatePDF(data) {
  const { target, score, issues } = data;
  const date = new Date().toLocaleString();
  const htmlContent = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<title>Security Scan Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap');
  body { font-family: 'Space Mono', monospace; background: #0a0f1e; color: #d0e8ff; padding: 40px; }
  h1 { color: #00cfff; font-size: 22px; margin-bottom: 4px; }
  .meta { color: #6a8faa; font-size: 11px; margin-bottom: 30px; }
  .score-box { border: 1px solid #00cfff44; background: rgba(0,207,255,0.07); padding: 16px 24px; border-radius: 8px; margin-bottom: 24px; display: inline-block; }
  .score-val { font-size: 36px; font-weight: 700; color: ${SCORE_COLOR(score)}; }
  .issue { border: 1px solid rgba(255,255,255,0.1); border-radius: 6px; padding: 12px 16px; margin-bottom: 10px; page-break-inside: avoid; }
  .issue-title { font-weight: 700; font-size: 13px; margin-bottom: 6px; }
  .badge { font-size: 10px; padding: 2px 8px; border-radius: 3px; display: inline-block; margin-right: 8px; }
  .High { background: rgba(255,77,77,0.2); color: #ff4d4d; }
  .Medium { background: rgba(255,170,0,0.2); color: #ffaa00; }
  .Low { background: rgba(0,207,255,0.2); color: #00cfff; }
  .desc { font-size: 11px; color: #8ab4d4; margin-top: 6px; line-height: 1.6; }
  .cat { font-size: 10px; color: #4a6a8a; }
</style>
</head>
<body>
<h1>🛡 MK8Scan Security Report</h1>
<div class="meta">Target: ${target} &nbsp;|&nbsp; Scanned: ${date} &nbsp;|&nbsp; OWASP A02: Security Misconfiguration</div>
<div class="score-box">
  <div style="font-size:11px;color:#6a8faa;letter-spacing:2px;margin-bottom:4px">SECURITY SCORE</div>
  <div class="score-val">${score}<span style="font-size:16px;color:#4a6a8a">/100</span></div>
</div>
<div style="margin-bottom:24px;font-size:12px;color:#6a8faa">${issues.length} issue${issues.length !== 1 ? "s" : ""} found &nbsp;|&nbsp;
High: ${issues.filter(i=>i.severity==="High").length} &nbsp;|&nbsp;
Medium: ${issues.filter(i=>i.severity==="Medium").length} &nbsp;|&nbsp;
Low: ${issues.filter(i=>i.severity==="Low").length}</div>
<hr style="border-color:rgba(255,255,255,0.08);margin-bottom:24px"/>
${issues.map(issue => `
<div class="issue">
  <div class="issue-title">
    <span class="badge ${issue.severity}">${issue.severity.toUpperCase()}</span>
    ${issue.title}
  </div>
  <div class="cat">${issue.category}</div>
  <div class="desc">${issue.description}</div>
</div>`).join("")}
</body>
</html>`;

  const blob = new Blob([htmlContent], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `security-report-${new Date().toISOString().slice(0, 10)}.html`;
  link.click();
  URL.revokeObjectURL(url);
}

// ── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState("All");
  const inputRef = useRef();

  useEffect(() => {
    // Inject Google Fonts and keyframes
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=IBM+Plex+Mono:wght@300;400;600&display=swap";
    document.head.appendChild(link);

    const style = document.createElement("style");
    style.textContent = `
      *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
      body { background: #060c1a; }
      @keyframes fadeUp { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: translateY(0); } }
      @keyframes ping { 0% { transform: scale(0.4); opacity: 0.8; } 100% { transform: scale(1.8); opacity: 0; } }
      @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
      @keyframes blink { 0%,100% { opacity: 0.3; } 50% { opacity: 1; } }
      @keyframes scanLine { 0% { top: 0; } 100% { top: 100%; } }
      @keyframes gradientShift { 0%,100% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } }
      input:-webkit-autofill { -webkit-box-shadow: 0 0 0 100px #0d1929 inset !important; -webkit-text-fill-color: #d0e8ff !important; }
      ::-webkit-scrollbar { width: 5px; } ::-webkit-scrollbar-track { background: transparent; }
      ::-webkit-scrollbar-thumb { background: rgba(0,207,255,0.2); border-radius: 3px; }
    `;
    document.head.appendChild(style);
  }, []);

  const handleScan = async () => {
    if (!target.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    setFilter("All");

    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim() }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || `Server error ${res.status}`);
      }

      const data = await res.json();
      setResult(data);
    } catch (e) {
      if (e.message === "Failed to fetch") {
        setError("Cannot reach backend. Make sure Flask is running on port 5000.");
      } else {
        setError(e.message);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleKey = (e) => { if (e.key === "Enter") handleScan(); };

  // Filter logic
  const filteredIssues = result
    ? result.issues.filter(i => filter === "All" || i.severity === filter)
    : [];

  const severityCounts = result
    ? { High: 0, Medium: 0, Low: 0, ...result.issues.reduce((a, i) => ({ ...a, [i.severity]: (a[i.severity] || 0) + 1 }), {}) }
    : { High: 0, Medium: 0, Low: 0 };

  const grouped = groupByCategory(filteredIssues);

  return (
    <div style={{
      minHeight: "100vh",
      background: "radial-gradient(ellipse at 20% 0%, rgba(0,80,120,0.3) 0%, transparent 50%), radial-gradient(ellipse at 80% 100%, rgba(100,50,200,0.2) 0%, transparent 50%), #060c1a",
      fontFamily: "'IBM Plex Mono', monospace",
      color: "#d0e8ff",
    }}>
      {/* Grid overlay */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0,
        backgroundImage: "linear-gradient(rgba(0,207,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,207,255,0.03) 1px, transparent 1px)",
        backgroundSize: "48px 48px",
      }} />

      <div style={{ position: "relative", zIndex: 1, maxWidth: 900, margin: "0 auto", padding: "0 20px" }}>

        {/* Header */}
        <header style={{
          display: "flex", justifyContent: "space-between", alignItems: "center",
          padding: "24px 0", borderBottom: "1px solid rgba(255,255,255,0.06)",
          marginBottom: 48,
          animation: "fadeUp 0.5s ease both",
        }}>
          <ScannerLogo />
          <div style={{ fontSize: 10, fontFamily: "'Space Mono', monospace", color: "#2a4a6a", letterSpacing: 2 }}>
            A02:2021
          </div>
        </header>

        {/* Hero section */}
        {!result && !loading && (
          <div style={{ textAlign: "center", marginBottom: 60, animation: "fadeUp 0.5s ease 0.1s both" }}>
            <div style={{
              fontSize: 42, fontWeight: 700, fontFamily: "'Space Mono', monospace",
              lineHeight: 1.15, marginBottom: 16, letterSpacing: -1,
              background: "linear-gradient(135deg, #ffffff 0%, #00cfff 50%, #7b61ff 100%)",
              backgroundSize: "200% 200%",
              WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
              animation: "gradientShift 6s ease infinite",
            }}>
              Security<br />Misconfiguration<br />Scanner
            </div>
            <div style={{ color: "#4a7090", fontSize: 13, maxWidth: 480, margin: "0 auto", lineHeight: 1.7 }}>
              Automated OWASP A02 detection — scan any URL or IP for exposed ports, missing headers, dangerous HTTP methods, and sensitive paths.
            </div>
          </div>
        )}

        {/* Input card */}
        <div style={{
          background: "rgba(255,255,255,0.03)",
          border: "1px solid rgba(255,255,255,0.08)",
          borderRadius: 14, padding: 28,
          marginBottom: result || loading ? 32 : 0,
          backdropFilter: "blur(10px)",
          animation: "fadeUp 0.5s ease 0.2s both",
          boxShadow: "0 4px 40px rgba(0,0,0,0.4)",
        }}>
          <div style={{ marginBottom: 16, fontSize: 11, letterSpacing: 2, color: "#4a7090", fontFamily: "'Space Mono', monospace" }}>
            TARGET URL OR IP ADDRESS
          </div>
          <div style={{ display: "flex", gap: 12 }}>
            <div style={{ flex: 1, position: "relative" }}>
              <span style={{
                position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)",
                color: "#2a5a7a", fontSize: 14, pointerEvents: "none",
              }}>⬡</span>
              <input
                ref={inputRef}
                type="text"
                value={target}
                onChange={e => setTarget(e.target.value)}
                onKeyDown={handleKey}
                placeholder="https://example.com  or  192.168.1.1"
                disabled={loading}
                style={{
                  width: "100%", padding: "13px 16px 13px 38px",
                  background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.1)",
                  borderRadius: 8, color: "#d0e8ff", fontSize: 13,
                  fontFamily: "'IBM Plex Mono', monospace",
                  outline: "none", transition: "border-color 0.2s",
                }}
                onFocus={e => e.target.style.borderColor = "rgba(0,207,255,0.5)"}
                onBlur={e => e.target.style.borderColor = "rgba(255,255,255,0.1)"}
              />
            </div>
            <button
              onClick={handleScan}
              disabled={loading || !target.trim()}
              style={{
                padding: "13px 28px", borderRadius: 8, border: "none",
                background: loading || !target.trim()
                  ? "rgba(0,207,255,0.15)"
                  : "linear-gradient(135deg, #00cfff, #7b61ff)",
                color: loading || !target.trim() ? "rgba(0,207,255,0.4)" : "#fff",
                fontFamily: "'Space Mono', monospace", fontWeight: 700, fontSize: 13,
                letterSpacing: 1, cursor: loading || !target.trim() ? "not-allowed" : "pointer",
                transition: "all 0.2s",
                boxShadow: loading || !target.trim() ? "none" : "0 0 20px rgba(0,207,255,0.3)",
                whiteSpace: "nowrap",
              }}
            >
              {loading ? "SCANNING…" : "▶ SCAN"}
            </button>
          </div>

          {error && (
            <div style={{
              marginTop: 14, padding: "10px 14px",
              background: "rgba(255,77,77,0.08)", border: "1px solid rgba(255,77,77,0.25)",
              borderRadius: 6, fontSize: 12, color: "#ff6b6b",
              fontFamily: "'Space Mono', monospace",
            }}>
              ⚠ {error}
            </div>
          )}
        </div>

        {/* Loading */}
        {loading && <ScannerAnimation />}

        {/* Results */}
        {result && !loading && (
          <div style={{ animation: "fadeUp 0.5s ease both" }}>

            {/* Stats row */}
            <div style={{
              display: "grid", gridTemplateColumns: "auto 1fr",
              gap: 24, marginBottom: 28,
              background: "rgba(255,255,255,0.02)",
              border: "1px solid rgba(255,255,255,0.07)",
              borderRadius: 14, padding: 28,
              backdropFilter: "blur(10px)",
            }}>
              <ScoreRing score={result.score} />

              <div style={{ display: "flex", flexDirection: "column", justifyContent: "center", gap: 16 }}>
                <div>
                  <div style={{ fontSize: 10, letterSpacing: 2, color: "#4a7090", marginBottom: 6, fontFamily: "'Space Mono', monospace" }}>
                    TARGET
                  </div>
                  <div style={{ fontSize: 13, color: "#00cfff", wordBreak: "break-all" }}>
                    {result.target}
                  </div>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  <ProgressBar label="HIGH" value={severityCounts.High} max={result.total} color="#ff4d4d" />
                  <ProgressBar label="MEDIUM" value={severityCounts.Medium} max={result.total} color="#ffaa00" />
                  <ProgressBar label="LOW" value={severityCounts.Low} max={result.total} color="#00cfff" />
                </div>
              </div>
            </div>

            {/* Filter + Download row */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20, flexWrap: "wrap", gap: 12 }}>
              <FilterBar active={filter} onChange={setFilter} counts={severityCounts} />
              <button
                onClick={() => generatePDF(result)}
                style={{
                  fontFamily: "'Space Mono', monospace", fontSize: 11, letterSpacing: 1,
                  padding: "6px 16px", borderRadius: 5, cursor: "pointer",
                  border: "1px solid rgba(123,97,255,0.4)",
                  background: "rgba(123,97,255,0.1)",
                  color: "#b09cff",
                  transition: "all 0.2s",
                  display: "flex", alignItems: "center", gap: 6,
                }}
                onMouseEnter={e => { e.currentTarget.style.background = "rgba(123,97,255,0.2)"; e.currentTarget.style.borderColor = "rgba(123,97,255,0.7)"; }}
                onMouseLeave={e => { e.currentTarget.style.background = "rgba(123,97,255,0.1)"; e.currentTarget.style.borderColor = "rgba(123,97,255,0.4)"; }}
              >
                ↓ DOWNLOAD REPORT
              </button>
            </div>

            {/* Issues by category */}
            {filteredIssues.length === 0 ? (
              <div style={{
                textAlign: "center", padding: "40px 20px",
                color: "#2a5a7a", fontFamily: "'Space Mono', monospace", fontSize: 13,
                border: "1px dashed rgba(255,255,255,0.06)", borderRadius: 10,
              }}>
                ✓ No {filter !== "All" ? filter.toLowerCase() : ""} issues found
              </div>
            ) : (
              Object.entries(grouped).map(([category, catIssues]) => (
                <div key={category} style={{ marginBottom: 24 }}>
                  <div style={{
                    fontSize: 10, letterSpacing: 3, color: "#4a7090",
                    fontFamily: "'Space Mono', monospace",
                    marginBottom: 12, paddingLeft: 2,
                    display: "flex", alignItems: "center", gap: 10,
                  }}>
                    <span>{category.toUpperCase()}</span>
                    <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.06)" }} />
                    <span style={{ color: "#2a4a6a" }}>{catIssues.length}</span>
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {catIssues.map((issue, i) => (
                      <IssueCard key={i} issue={issue} index={i} />
                    ))}
                  </div>
                </div>
              ))
            )}

            {/* Rescan */}
            <div style={{ textAlign: "center", padding: "28px 0 40px" }}>
              <button
                onClick={() => { setResult(null); setTarget(""); setTimeout(() => inputRef.current?.focus(), 100); }}
                style={{
                  fontFamily: "'Space Mono', monospace", fontSize: 11, letterSpacing: 2,
                  padding: "8px 24px", borderRadius: 5, cursor: "pointer",
                  border: "1px solid rgba(255,255,255,0.1)",
                  background: "transparent", color: "rgba(255,255,255,0.3)",
                  transition: "all 0.2s",
                }}
                onMouseEnter={e => { e.currentTarget.style.color = "#d0e8ff"; e.currentTarget.style.borderColor = "rgba(255,255,255,0.3)"; }}
                onMouseLeave={e => { e.currentTarget.style.color = "rgba(255,255,255,0.3)"; e.currentTarget.style.borderColor = "rgba(255,255,255,0.1)"; }}
              >
                ← NEW SCAN
              </button>
            </div>

          </div>
        )}
      </div>
    </div>
  );
}