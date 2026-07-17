import { useState, useEffect, useCallback } from "react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from "recharts";

// ── Config ───────────────────────────────────────────────────────────────────
const API = "http://localhost:8000/api";

// ── Helpers ──────────────────────────────────────────────────────────────────
const riskColor = (risk) => ({
  Low: "#22c55e", Medium: "#f59e0b", High: "#f97316", Critical: "#ef4444", Unknown: "#6b7280"
}[risk] || "#6b7280");

const riskBg = (risk) => ({
  Low: "#dcfce7", Medium: "#fef3c7", High: "#ffedd5", Critical: "#fee2e2", Unknown: "#f3f4f6"
}[risk] || "#f3f4f6");

const severityColor = (s) => ({ HIGH: "#ef4444", MEDIUM: "#f59e0b", LOW: "#3b82f6", INFO: "#6b7280" }[s] || "#6b7280");

const fmt = (ts) => ts ? new Date(ts).toLocaleString() : "Never";
const fmtDate = (ts) => ts ? new Date(ts).toLocaleDateString() : "";

async function api(path, opts = {}) {
  const res = await fetch(API + path, opts);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// ── Score Ring ────────────────────────────────────────────────────────────────
function ScoreRing({ score, risk, size = 80 }) {
  const r = (size / 2) - 8;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;
  const color = riskColor(risk);
  return (
    <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#e5e7eb" strokeWidth="7" />
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth="7"
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
        style={{ transition: "stroke-dasharray 0.6s ease" }} />
      <text x={size/2} y={size/2} textAnchor="middle" dominantBaseline="central"
        style={{ transform: "rotate(90deg)", transformOrigin: `${size/2}px ${size/2}px`,
          fontSize: size > 60 ? 18 : 13, fontWeight: 700, fill: color }}>
        {score ?? "—"}
      </text>
    </svg>
  );
}

// ── Severity Badge ─────────────────────────────────────────────────────────
function Badge({ text, color }) {
  return (
    <span style={{
      display: "inline-block", padding: "2px 8px", borderRadius: 99,
      background: color + "22", color, fontSize: 11, fontWeight: 700,
      border: `1px solid ${color}44`, letterSpacing: "0.04em"
    }}>{text}</span>
  );
}

// ── Add Host Modal ─────────────────────────────────────────────────────────
function AddHostModal({ onClose, onAdded }) {
  const [form, setForm] = useState({ hostname: "", ip: "", ssh_user: "pi", ssh_key_path: "" });
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const submit = async () => {
    setLoading(true); setErr("");
    try {
      await api("/hosts", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(form) });
      onAdded();
    } catch (e) { setErr(e.message); } finally { setLoading(false); }
  };

  const field = (label, key, placeholder = "", type = "text") => (
    <div style={{ marginBottom: 14 }}>
      <label style={{ display: "block", fontSize: 12, fontWeight: 600, color: "#374151", marginBottom: 4 }}>{label}</label>
      <input type={type} value={form[key]} onChange={e => setForm(p => ({ ...p, [key]: e.target.value }))}
        placeholder={placeholder}
        style={{ width: "100%", padding: "8px 10px", border: "1px solid #d1d5db", borderRadius: 6,
          fontSize: 14, outline: "none", boxSizing: "border-box" }} />
    </div>
  );

  return (
    <div style={{ position: "fixed", inset: 0, background: "#0007", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100 }}>
      <div style={{ background: "#fff", borderRadius: 12, padding: 28, width: 360, boxShadow: "0 20px 60px #0003" }}>
        <h3 style={{ margin: "0 0 20px", fontSize: 18 }}>Add Raspberry Pi</h3>
        {field("Hostname", "hostname", "pi1")}
        {field("IP Address", "ip", "192.168.1.10")}
        {field("SSH User", "ssh_user", "pi")}
        {field("SSH Key Path", "ssh_key_path", "/home/user/.ssh/id_rsa")}
        {err && <p style={{ color: "#ef4444", fontSize: 13, margin: "0 0 12px" }}>{err}</p>}
        <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
          <button onClick={onClose} style={{ padding: "8px 16px", borderRadius: 6, border: "1px solid #d1d5db", background: "#fff", cursor: "pointer" }}>Cancel</button>
          <button onClick={submit} disabled={loading}
            style={{ padding: "8px 16px", borderRadius: 6, border: "none", background: "#3b82f6", color: "#fff", cursor: "pointer", fontWeight: 600 }}>
            {loading ? "Adding..." : "Add Host"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Host Detail Panel ──────────────────────────────────────────────────────
function HostDetail({ hostId, onBack }) {
  const [data, setData] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [tab, setTab] = useState("findings");

  const load = useCallback(async () => {
    try { setData(await api(`/hosts/${hostId}`)); } catch {}
  }, [hostId]);

  useEffect(() => { load(); }, [load]);

  const triggerScan = async () => {
    setScanning(true);
    await api(`/hosts/${hostId}/scan`, { method: "POST" });
    setTimeout(() => { load(); setScanning(false); }, 8000);
  };

  if (!data) return <div style={{ padding: 40, textAlign: "center", color: "#6b7280" }}>Loading…</div>;

  const { host, latest_scan, findings, score_history, normalized, port_history } = data;

  const tabs = [
    { id: "findings", label: `Findings (${findings.length})` },
    { id: "ports", label: `Ports (${port_history.length})` },
    { id: "history", label: "Score History" },
    { id: "details", label: "System Details" },
  ];

  return (
    <div>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 24 }}>
        <button onClick={onBack} style={{ background: "none", border: "1px solid #d1d5db", padding: "6px 12px", borderRadius: 6, cursor: "pointer", fontSize: 13 }}>← Back</button>
        <div style={{ flex: 1 }}>
          <h2 style={{ margin: 0, fontSize: 22 }}>{host.hostname}</h2>
          <span style={{ color: "#6b7280", fontSize: 13 }}>{host.ip} · Last scan: {fmt(latest_scan?.timestamp)}</span>
        </div>
        {latest_scan && <ScoreRing score={latest_scan.score} risk={latest_scan.risk_level} size={72} />}
        <button onClick={triggerScan} disabled={scanning}
          style={{ padding: "10px 20px", borderRadius: 8, border: "none", background: scanning ? "#93c5fd" : "#3b82f6", color: "#fff", cursor: scanning ? "default" : "pointer", fontWeight: 600 }}>
          {scanning ? "Scanning…" : "Scan Now"}
        </button>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 20, borderBottom: "1px solid #e5e7eb", paddingBottom: 0 }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{ padding: "8px 16px", border: "none", background: "none", cursor: "pointer",
              borderBottom: tab === t.id ? "2px solid #3b82f6" : "2px solid transparent",
              color: tab === t.id ? "#3b82f6" : "#6b7280", fontWeight: tab === t.id ? 600 : 400, fontSize: 14 }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Findings Tab */}
      {tab === "findings" && (
        <div>
          {findings.length === 0
            ? <p style={{ color: "#6b7280", textAlign: "center", padding: 32 }}>No findings — this Pi looks clean ✓</p>
            : findings.map((f, i) => (
              <div key={i} style={{ padding: "14px 16px", marginBottom: 8, borderRadius: 8, background: "#f9fafb", border: `1px solid ${severityColor(f.severity)}44` }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
                  <Badge text={f.severity} color={severityColor(f.severity)} />
                  <Badge text={f.category} color="#6b7280" />
                  <span style={{ fontWeight: 600, fontSize: 14 }}>{f.title}</span>
                </div>
                <p style={{ margin: 0, fontSize: 13, color: "#6b7280" }}>{f.detail}</p>
              </div>
            ))}
        </div>
      )}

      {/* Ports Tab */}
      {tab === "ports" && (
        <div>
          <div style={{ marginBottom: 16 }}>
            <h4 style={{ margin: "0 0 8px", color: "#374151" }}>Currently Open Ports</h4>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {(normalized?.open_ports || []).map(p => (
                <span key={p} style={{ padding: "4px 12px", background: "#eff6ff", border: "1px solid #bfdbfe", borderRadius: 6, fontSize: 13, fontWeight: 600, color: "#1d4ed8" }}>:{p}</span>
              ))}
            </div>
          </div>
          <h4 style={{ margin: "16px 0 8px", color: "#374151" }}>Port History</h4>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead><tr style={{ background: "#f9fafb" }}>
              {["Port", "Service", "First Seen"].map(h => <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontWeight: 600, color: "#6b7280", borderBottom: "1px solid #e5e7eb" }}>{h}</th>)}
            </tr></thead>
            <tbody>
              {port_history.map((p, i) => (
                <tr key={i} style={{ borderBottom: "1px solid #f3f4f6" }}>
                  <td style={{ padding: "8px 12px", fontWeight: 600 }}>:{p.port}</td>
                  <td style={{ padding: "8px 12px", color: "#374151" }}>{p.service}</td>
                  <td style={{ padding: "8px 12px", color: "#6b7280" }}>{fmt(p.first_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* History Tab */}
      {tab === "history" && (
        <div style={{ height: 300 }}>
          {score_history.length < 2
            ? <p style={{ color: "#6b7280", textAlign: "center", paddingTop: 80 }}>Not enough scan history yet. Run more scans.</p>
            : <ResponsiveContainer width="100%" height="100%">
                <LineChart data={score_history.map(s => ({ date: fmtDate(s.timestamp), score: s.score, risk: s.risk_level }))}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
                  <XAxis dataKey="date" tick={{ fontSize: 11 }} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} />
                  <Tooltip formatter={(v, n) => [v, "Score"]} contentStyle={{ fontSize: 12 }} />
                  <Line type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={2} dot={{ r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
          }
        </div>
      )}

      {/* Details Tab */}
      {tab === "details" && normalized && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          {[
            { label: "OS", value: normalized.os_info || "Unknown" },
            { label: "Disk Usage", value: `${normalized.disk_usage_percent}%` },
            { label: "Firewall", value: normalized.firewall_enabled ? `Active (${normalized.firewall_rules_count} rules)` : "Disabled" },
            { label: "SSH Port", value: `:${normalized.ssh_port}` },
            { label: "Password Auth", value: normalized.password_auth_enabled ? "Enabled" : "Disabled" },
            { label: "Root Login", value: normalized.root_login_permitted ? "Permitted ⚠" : "Blocked ✓" },
            { label: "Pending Updates", value: normalized.pending_updates },
            { label: "Failed Logins", value: normalized.failed_login_count },
            { label: "User Accounts", value: (normalized.user_accounts || []).join(", ") || "None detected" },
            { label: "Running Services", value: (normalized.running_services || []).slice(0, 5).join(", ") },
          ].map(({ label, value }) => (
            <div key={label} style={{ padding: "12px 16px", background: "#f9fafb", borderRadius: 8, border: "1px solid #e5e7eb" }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: "#9ca3af", marginBottom: 4 }}>{label.toUpperCase()}</div>
              <div style={{ fontSize: 14, color: "#111827" }}>{value}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main Dashboard ──────────────────────────────────────────────────────────
export default function App() {
  const [hosts, setHosts] = useState([]);
  const [stats, setStats] = useState(null);
  const [selectedHost, setSelectedHost] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scheduleHours, setScheduleHours] = useState(6);

  const loadHosts = useCallback(async () => {
    try {
      const [h, s] = await Promise.all([api("/hosts"), api("/stats")]);
      setHosts(h);
      setStats(s);
    } catch {}
  }, []);

  useEffect(() => { loadHosts(); const i = setInterval(loadHosts, 30000); return () => clearInterval(i); }, [loadHosts]);

  const scanAll = async () => {
    setScanning(true);
    await api("/scan-all", { method: "POST" });
    setTimeout(() => { loadHosts(); setScanning(false); }, 10000);
  };

  const updateSchedule = async () => {
    await api("/schedule", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ interval_hours: scheduleHours }) });
  };

  if (selectedHost) {
    return (
      <div style={{ minHeight: "100vh", background: "#f8fafc", fontFamily: "system-ui, -apple-system, sans-serif" }}>
        <div style={{ maxWidth: 900, margin: "0 auto", padding: "24px 20px" }}>
          <HostDetail hostId={selectedHost} onBack={() => { setSelectedHost(null); loadHosts(); }} />
        </div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: "100vh", background: "#f8fafc", fontFamily: "system-ui, -apple-system, sans-serif" }}>
      {showAdd && <AddHostModal onClose={() => setShowAdd(false)} onAdded={() => { setShowAdd(false); loadHosts(); }} />}

      {/* Nav */}
      <div style={{ background: "#0f172a", padding: "0 24px" }}>
        <div style={{ maxWidth: 1100, margin: "0 auto", display: "flex", alignItems: "center", height: 56, gap: 12 }}>
          <span style={{ fontSize: 18, fontWeight: 700, color: "#f1f5f9", letterSpacing: "-0.02em" }}>🛡 PiScore</span>
          <span style={{ flex: 1 }} />
          <span style={{ color: "#64748b", fontSize: 13 }}>Auto-scan every</span>
          <select value={scheduleHours} onChange={e => setScheduleHours(Number(e.target.value))}
            style={{ padding: "4px 8px", borderRadius: 6, border: "1px solid #334155", background: "#1e293b", color: "#f1f5f9", fontSize: 13 }}>
            {[1, 3, 6, 12, 24].map(h => <option key={h} value={h}>{h}h</option>)}
          </select>
          <button onClick={updateSchedule} style={{ padding: "5px 12px", borderRadius: 6, border: "1px solid #475569", background: "#1e293b", color: "#94a3b8", cursor: "pointer", fontSize: 12 }}>Set</button>
        </div>
      </div>

      <div style={{ maxWidth: 1100, margin: "0 auto", padding: "28px 20px" }}>
        {/* Stats Bar */}
        {stats && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 28 }}>
            {[
              { label: "Monitored Hosts", value: stats.total_hosts, color: "#3b82f6" },
              { label: "Total Scans", value: stats.total_scans, color: "#8b5cf6" },
              { label: "Average Score", value: stats.average_score || "—", color: "#10b981" },
              { label: "Critical Hosts", value: stats.critical_hosts, color: "#ef4444" },
            ].map(({ label, value, color }) => (
              <div key={label} style={{ background: "#fff", borderRadius: 10, padding: "16px 20px", border: "1px solid #e5e7eb", boxShadow: "0 1px 3px #0001" }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: "#9ca3af", marginBottom: 6 }}>{label.toUpperCase()}</div>
                <div style={{ fontSize: 28, fontWeight: 700, color }}>{value}</div>
              </div>
            ))}
          </div>
        )}

        {/* Actions */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <h2 style={{ margin: 0, fontSize: 20, color: "#111827" }}>Hosts</h2>
          <div style={{ display: "flex", gap: 10 }}>
            <button onClick={scanAll} disabled={scanning}
              style={{ padding: "9px 18px", borderRadius: 8, border: "1px solid #d1d5db", background: "#fff", cursor: scanning ? "default" : "pointer", fontWeight: 600, fontSize: 14, color: "#374151" }}>
              {scanning ? "Scanning all…" : "⟳ Scan All"}
            </button>
            <button onClick={() => setShowAdd(true)}
              style={{ padding: "9px 18px", borderRadius: 8, border: "none", background: "#3b82f6", color: "#fff", cursor: "pointer", fontWeight: 600, fontSize: 14 }}>
              + Add Pi
            </button>
          </div>
        </div>

        {/* Host Table */}
        {hosts.length === 0 ? (
          <div style={{ textAlign: "center", padding: "60px 20px", background: "#fff", borderRadius: 12, border: "1px solid #e5e7eb" }}>
            <div style={{ fontSize: 40, marginBottom: 12 }}>🍓</div>
            <h3 style={{ color: "#374151", margin: "0 0 8px" }}>No Pis added yet</h3>
            <p style={{ color: "#6b7280", margin: "0 0 20px" }}>Add your first Raspberry Pi to start monitoring.</p>
            <button onClick={() => setShowAdd(true)}
              style={{ padding: "10px 24px", borderRadius: 8, border: "none", background: "#3b82f6", color: "#fff", cursor: "pointer", fontWeight: 600 }}>
              Add your first Pi
            </button>
          </div>
        ) : (
          <div style={{ background: "#fff", borderRadius: 12, border: "1px solid #e5e7eb", overflow: "hidden", boxShadow: "0 1px 3px #0001" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ background: "#f9fafb", borderBottom: "1px solid #e5e7eb" }}>
                  {["Host", "IP", "Score", "Risk", "Last Scan", ""].map(h => (
                    <th key={h} style={{ padding: "12px 16px", textAlign: "left", fontSize: 12, fontWeight: 600, color: "#6b7280" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {hosts.map((h, i) => (
                  <tr key={h.id} onClick={() => setSelectedHost(h.id)}
                    style={{ borderBottom: i < hosts.length-1 ? "1px solid #f3f4f6" : "none", cursor: "pointer", transition: "background 0.1s" }}
                    onMouseEnter={e => e.currentTarget.style.background = "#f9fafb"}
                    onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                    <td style={{ padding: "14px 16px", fontWeight: 600, color: "#111827" }}>{h.hostname}</td>
                    <td style={{ padding: "14px 16px", color: "#6b7280", fontFamily: "monospace", fontSize: 13 }}>{h.ip}</td>
                    <td style={{ padding: "14px 16px" }}>
                      {h.score != null ? (
                        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                          <div style={{ width: 120, height: 6, background: "#e5e7eb", borderRadius: 3, overflow: "hidden" }}>
                            <div style={{ width: `${h.score}%`, height: "100%", background: riskColor(h.risk_level), borderRadius: 3, transition: "width 0.5s" }} />
                          </div>
                          <span style={{ fontWeight: 700, fontSize: 14, color: riskColor(h.risk_level) }}>{h.score}</span>
                        </div>
                      ) : <span style={{ color: "#9ca3af" }}>Not scanned</span>}
                    </td>
                    <td style={{ padding: "14px 16px" }}>
                      {h.risk_level
                        ? <span style={{ padding: "3px 10px", borderRadius: 99, background: riskBg(h.risk_level), color: riskColor(h.risk_level), fontWeight: 600, fontSize: 12 }}>{h.risk_level}</span>
                        : <span style={{ color: "#9ca3af", fontSize: 13 }}>—</span>}
                    </td>
                    <td style={{ padding: "14px 16px", color: "#6b7280", fontSize: 13 }}>{fmt(h.last_scan)}</td>
                    <td style={{ padding: "14px 16px" }}>
                      <span style={{ color: "#3b82f6", fontSize: 13, fontWeight: 500 }}>View →</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
