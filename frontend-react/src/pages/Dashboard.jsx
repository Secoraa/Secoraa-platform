import React, { useEffect, useMemo, useState } from 'react';
import Notification from '../components/Notification';
import { getAllFindings, getDomains, getIPAddresses, getSubdomains, getUrls } from '../api/apiClient';
import './Dashboard.css';

const severityWeight = (sev) => {
  const s = String(sev || 'INFO').toUpperCase();
  return { CRITICAL: 100, HIGH: 80, MEDIUM: 55, LOW: 25, INFO: 10 }.hasOwnProperty(s) ? { CRITICAL: 100, HIGH: 80, MEDIUM: 55, LOW: 25, INFO: 10 }[s] : 10;
};

const safeArray = (v) => (Array.isArray(v) ? v : (Array.isArray(v?.data) ? v.data : []));

const monthKey = (d) => {
  const dt = d instanceof Date ? d : new Date(d);
  if (Number.isNaN(dt.getTime())) return null;
  return `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}`;
};

const Dashboard = () => {
  const [loading, setLoading] = useState(false);
  const [notification, setNotification] = useState(null);
  const [domains, setDomains] = useState([]);
  const [subdomains, setSubdomains] = useState([]);
  const [ips, setIps] = useState([]);
  const [urls, setUrls] = useState([]);
  const [findings, setFindings] = useState([]);
  const [showAssetBreakdown, setShowAssetBreakdown] = useState(false);
  const [visibleSeverities, setVisibleSeverities] = useState({
    CRITICAL: true,
    HIGH: true,
    MEDIUM: true,
    LOW: true,
    INFO: true,
  });

  const load = async () => {
    try {
      setLoading(true);
      const [d, s, ip, u, f] = await Promise.all([
        getDomains().catch(() => []),
        getSubdomains().catch(() => []),
        getIPAddresses().catch(() => []),
        getUrls().catch(() => []),
        getAllFindings().catch(() => ({ data: [] })),
      ]);
      setDomains(safeArray(d));
      setSubdomains(safeArray(s));
      setIps(safeArray(ip));
      setUrls(safeArray(u));
      setFindings(safeArray(f?.data || f));
    } catch (err) {
      setNotification({ message: err.message, type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const totals = useMemo(() => {
    const totalAssets = (domains?.length || 0) + (subdomains?.length || 0) + (ips?.length || 0) + (urls?.length || 0);
    const totalVulns = findings?.length || 0;

    const weights = (findings || []).map((f) => severityWeight(f.severity));
    const avgWeight = weights.length ? (weights.reduce((a, b) => a + b, 0) / weights.length) : 0;
    const risk10 = avgWeight / 10; // 0-10 scale like your screenshot

    return {
      totalAssets,
      totalVulns,
      avgWeight,
      risk10,
    };
  }, [domains, subdomains, ips, urls, findings]);

  const sevCounts = useMemo(() => {
    const out = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const f of findings || []) {
      const s = String(f.severity || 'INFO').toUpperCase();
      out[s] = (out[s] || 0) + 1;
    }
    return out;
  }, [findings]);

  const vulnByRiskBars = useMemo(() => {
    const keys = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    return keys.map((k) => ({ key: k, value: sevCounts[k] || 0 }));
  }, [sevCounts]);

  const recentVulns = useMemo(() => {
    const rows = [...(findings || [])];
    rows.sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime());
    return rows.slice(0, 6);
  }, [findings]);

  const topAssets = useMemo(() => {
    const map = new Map();
    for (const f of findings || []) {
      const asset = String(f.asset_url || f.asset || f.url || 'Unknown').trim() || 'Unknown';
      const prev = map.get(asset) || { asset, count: 0, maxWeight: 0 };
      const w = severityWeight(f.severity);
      map.set(asset, { asset, count: prev.count + 1, maxWeight: Math.max(prev.maxWeight, w) });
    }
    const rows = Array.from(map.values());
    rows.sort((a, b) => (b.count - a.count) || (b.maxWeight - a.maxWeight) || a.asset.localeCompare(b.asset));
    return rows.slice(0, 6);
  }, [findings]);

  const assetTrend = useMemo(() => {
    // Build a 12-month trend for the current year using created_at on assets (fallback: flat line).
    const year = new Date().getFullYear();
    const months = Array.from({ length: 12 }, (_, i) => `${year}-${String(i + 1).padStart(2, '0')}`);
    const counts = Object.fromEntries(months.map((m) => [m, 0]));

    const push = (item) => {
      const k = monthKey(item?.created_at);
      if (!k) return;
      if (String(k).startsWith(String(year))) counts[k] = (counts[k] || 0) + 1;
    };

    (domains || []).forEach(push);
    (subdomains || []).forEach(push);
    (ips || []).forEach(push);
    (urls || []).forEach(push);

    // cumulative line
    let cum = 0;
    const points = months.map((m) => {
      cum += counts[m] || 0;
      return { month: m, value: cum };
    });
    return points;
  }, [domains, subdomains, ips, urls]);

  const assetTypeCounts = useMemo(() => {
    return {
      DOMAINS: domains?.length || 0,
      SUBDOMAINS: subdomains?.length || 0,
      IPS: ips?.length || 0,
      URLS: urls?.length || 0,
    };
  }, [domains, subdomains, ips, urls]);

  const vulnTrendSeries = useMemo(() => {
    const year = new Date().getFullYear();
    const months = Array.from({ length: 12 }, (_, i) => `${year}-${String(i + 1).padStart(2, '0')}`);
    const initCounts = () => Object.fromEntries(months.map((m) => [m, 0]));
    const bySev = {
      CRITICAL: initCounts(),
      HIGH: initCounts(),
      MEDIUM: initCounts(),
      LOW: initCounts(),
      INFO: initCounts(),
    };

    for (const f of findings || []) {
      const sev = String(f.severity || 'INFO').toUpperCase();
      const k = monthKey(f.created_at);
      if (!k) continue;
      if (!String(k).startsWith(String(year))) continue;
      const bucket = bySev[sev] ? sev : 'INFO';
      bySev[bucket][k] = (bySev[bucket][k] || 0) + 1;
    }

    const colors = {
      CRITICAL: '#ef4444',
      HIGH: '#fb7185',
      MEDIUM: '#f59e0b',
      LOW: '#38bdf8',
      INFO: '#94a3b8',
    };

    return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((sev) => ({
      key: sev,
      color: colors[sev],
      points: months.map((m) => ({ month: m, value: bySev[sev][m] || 0 })),
    }));
  }, [findings]);

  const toggleSeverity = (sev) => {
    setVisibleSeverities((prev) => ({ ...prev, [sev]: !prev[sev] }));
  };

  const anySeverityVisible = useMemo(() => {
    return Object.values(visibleSeverities || {}).some(Boolean);
  }, [visibleSeverities]);

  return (
    <div className="dash-page">
      {notification && (
        <Notification
          message={notification.message}
          type={notification.type}
          onClose={() => setNotification(null)}
          duration={5000}
        />
      )}

      <div className="dash-header">
        <div className="dash-breadcrumb">ASM / <span>Dashboard</span></div>
        <button className="dash-refresh" type="button" onClick={load} disabled={loading}>
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      <div className="dash-grid-top">
        <div className="dash-card dash-card-gauge">
          <div className="dash-card-title">OVERALL RISK</div>
          <Gauge value={totals.risk10} />
          <div className="dash-card-sub">How is this calculated?</div>
        </div>

        <div className="dash-card">
          <div className="dash-card-kpi">
            <div className="dash-kpi-value">{totals.totalAssets.toLocaleString()}</div>
            <div className="dash-kpi-label">TOTAL ASSETS</div>
          </div>
          <MiniAssetDonut counts={assetTypeCounts} onClick={() => setShowAssetBreakdown(true)} />
        </div>

        <div className="dash-card">
          <div className="dash-card-kpi">
            <div className="dash-kpi-value">{totals.totalVulns.toLocaleString()}</div>
            <div className="dash-kpi-label">VULNERABILITIES</div>
          </div>
          <div className="dash-mini-note">From scans + stored findings</div>
          <StackedSeverityBar counts={sevCounts} />
        </div>

        <div className="dash-card">
          <div className="dash-card-kpi">
            <div className="dash-kpi-value">9K</div>
            <div className="dash-kpi-label">CREDENTIAL BREACH</div>
          </div>
          <div className="dash-mini-note">Coming soon</div>
        </div>
      </div>

      {showAssetBreakdown && (
        <div className="dash-modal-overlay" onMouseDown={() => setShowAssetBreakdown(false)}>
          <div className="dash-modal" onMouseDown={(e) => e.stopPropagation()}>
            <div className="dash-modal-header">
              <div className="dash-modal-title">Asset Breakdown</div>
              <button className="dash-icon-btn" type="button" onClick={() => setShowAssetBreakdown(false)}>
                ✕
              </button>
            </div>
            <div className="dash-modal-body">
              <div className="dash-breakdown-total">
                <div className="dash-breakdown-total-label">Total Assets</div>
                <div className="dash-breakdown-total-value">{totals.totalAssets.toLocaleString()}</div>
              </div>

              <div className="dash-breakdown-grid">
                <BreakdownRow label="Domains" value={assetTypeCounts.DOMAINS} color="#60a5fa" />
                <BreakdownRow label="Subdomains" value={assetTypeCounts.SUBDOMAINS} color="#38bdf8" />
                <BreakdownRow label="IP Addresses" value={assetTypeCounts.IPS} color="#22c55e" />
                <BreakdownRow label="URLs" value={assetTypeCounts.URLS} color="#f59e0b" />
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="dash-grid-mid">
        <div className="dash-card dash-card-wide">
          <div className="dash-section-title">
            Vulnerability Trend <span className="dash-muted">{new Date().getFullYear()}</span>
          </div>
          <MultiLineTrendChart
            series={vulnTrendSeries}
            visible={visibleSeverities}
            emptyLabel="No vulnerability trend data yet."
          />
          <div className="dash-legend">
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).map((sev) => {
              const cls =
                sev === 'CRITICAL' ? 'critical' :
                sev === 'HIGH' ? 'high' :
                sev === 'MEDIUM' ? 'medium' :
                sev === 'LOW' ? 'low' : 'info';
              const label = sev === 'INFO' ? 'Informational' : (sev[0] + sev.slice(1).toLowerCase());
              const isOn = !!visibleSeverities?.[sev];
              // Keep at least 1 series visible
              const canToggleOff = isOn ? (Object.values(visibleSeverities || {}).filter(Boolean).length > 1) : true;
              return (
                <button
                  key={sev}
                  type="button"
                  className={`pill pill-btn ${cls} ${isOn ? 'active' : 'inactive'}`}
                  onClick={() => (canToggleOff ? toggleSeverity(sev) : null)}
                  title={isOn ? 'Click to hide' : 'Click to show'}
                >
                  {label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="dash-card dash-card-wide">
          <div className="dash-section-title">Vulnerabilities by Risk</div>
          <BarChart bars={vulnByRiskBars} />
        </div>
      </div>

      <div className="dash-grid-bottom">
        <div className="dash-card dash-card-wide">
          <div className="dash-section-title">Top Vulnerable Assets</div>
          <table className="dash-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Findings</th>
                <th>Worst Severity</th>
              </tr>
            </thead>
            <tbody>
              {topAssets.length === 0 ? (
                <tr><td colSpan="3" className="dash-empty">No findings yet.</td></tr>
              ) : (
                topAssets.map((r) => (
                  <tr key={r.asset}>
                    <td className="dash-mono">{r.asset}</td>
                    <td>{r.count}</td>
                    <td><SeverityPill weight={r.maxWeight} /></td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="dash-card dash-card-wide">
          <div className="dash-section-title">Recent Vulnerabilities</div>
          <table className="dash-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Assets Impacted</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {recentVulns.length === 0 ? (
                <tr><td colSpan="3" className="dash-empty">No findings yet.</td></tr>
              ) : (
                recentVulns.map((f, idx) => (
                  <tr key={`${f.issue || f.name || 'f'}-${idx}`}>
                    <td>{f.issue || f.name || '-'}</td>
                    <td className="dash-mono">{(f.asset_url || '-')}</td>
                    <td><span className={`pill ${String(f.severity || 'info').toLowerCase()}`}>{String(f.severity || 'INFO').toUpperCase()}</span></td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const BreakdownRow = ({ label, value, color }) => {
  return (
    <div className="dash-breakdown-row">
      <div className="dash-breakdown-left">
        <span className="dash-breakdown-dot" style={{ background: color }} />
        <span className="dash-breakdown-label">{label}</span>
      </div>
      <div className="dash-breakdown-value">{Number(value || 0).toLocaleString()}</div>
    </div>
  );
};

const SeverityPill = ({ weight }) => {
  const sev =
    weight >= 100 ? 'critical' :
    weight >= 80 ? 'high' :
    weight >= 55 ? 'medium' :
    weight >= 25 ? 'low' : 'info';
  const label = sev.toUpperCase();
  return <span className={`pill ${sev}`}>{label}</span>;
};

const Gauge = ({ value }) => {
  const v = Math.max(0, Math.min(10, Number(value || 0)));
  const pct = v / 10;
  const start = 200;
  const end = 340;
  const ang = start + (end - start) * pct;
  const cx = 120;
  const cy = 88;
  const r = 66;
  const polar = (deg) => {
    const rad = (deg * Math.PI) / 180;
    return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
  };
  const pNeedle = polar(ang);
  return (
    <svg width="240" height="140" viewBox="0 0 240 140" className="dash-gauge">
      <path d={arcPath(cx, cy, r, 200, 235)} stroke="#22c55e" strokeWidth="10" fill="none" strokeLinecap="round" />
      <path d={arcPath(cx, cy, r, 236, 280)} stroke="#3b82f6" strokeWidth="10" fill="none" strokeLinecap="round" />
      <path d={arcPath(cx, cy, r, 281, 310)} stroke="#f59e0b" strokeWidth="10" fill="none" strokeLinecap="round" />
      <path d={arcPath(cx, cy, r, 311, 340)} stroke="#ef4444" strokeWidth="10" fill="none" strokeLinecap="round" />
      <line x1={cx} y1={cy} x2={pNeedle.x} y2={pNeedle.y} stroke="#0f172a" strokeWidth="3" />
      <circle cx={cx} cy={cy} r="6" fill="#0f172a" />
      <text x="120" y="95" textAnchor="middle" className="dash-gauge-value">{v.toFixed(1)}</text>
    </svg>
  );
};

const arcPath = (cx, cy, r, a0, a1) => {
  const toXY = (a) => {
    const rad = (a * Math.PI) / 180;
    return [cx + r * Math.cos(rad), cy + r * Math.sin(rad)];
  };
  const [x0, y0] = toXY(a0);
  const [x1, y1] = toXY(a1);
  const large = a1 - a0 > 180 ? 1 : 0;
  return `M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1}`;
};

const MiniAssetDonut = ({ counts, onClick }) => {
  const c = counts || {};
  const total =
    Number(c.DOMAINS || 0) +
    Number(c.SUBDOMAINS || 0) +
    Number(c.IPS || 0) +
    Number(c.URLS || 0);

  const size = 120;
  const stroke = 12;
  const r = (size - stroke) / 2;
  const cx = size / 2;
  const cy = size / 2;

  return (
    <button
      type="button"
      className="dash-mini-donut-wrap dash-mini-donut-btn"
      aria-label="Asset mix (click for details)"
      onClick={onClick}
    >
      <svg width="100%" height="92" viewBox={`0 0 ${size} ${size}`} className="dash-mini-donut">
        {/* track */}
        <circle cx={cx} cy={cy} r={r} stroke="rgba(148,163,184,0.22)" strokeWidth={stroke} fill="none" />
        {/* single-color ring (details are shown on click) */}
        <circle
          cx={cx}
          cy={cy}
          r={r}
          stroke={total > 0 ? '#f59e0b' : 'rgba(148,163,184,0.35)'}
          strokeWidth={stroke}
          fill="none"
          strokeLinecap="round"
          transform={`rotate(-90 ${cx} ${cy})`}
        />
      </svg>
    </button>
  );
};

const TrendChart = ({ points }) => {
  const pts = Array.isArray(points) ? points : [];
  const values = pts.map((p) => p.value);
  const max = Math.max(1, ...values);
  const w = 800;
  const h = 220;
  const padL = 42;
  const padB = 34;
  const padT = 12;
  const padR = 12;
  const xFor = (i) => padL + (i * (w - padL - padR)) / Math.max(1, pts.length - 1);
  const yFor = (v) => padT + (h - padT - padB) * (1 - v / max);
  const d = pts.map((p, i) => `${i === 0 ? 'M' : 'L'} ${xFor(i)} ${yFor(p.value)}`).join(' ');
  return (
    <svg width="100%" height="240" viewBox={`0 0 ${w} ${h}`} className="dash-trend">
      {/* grid */}
      {[0.25, 0.5, 0.75, 1].map((t) => (
        <line key={t} x1={padL} x2={w - padR} y1={yFor(max * t)} y2={yFor(max * t)} stroke="rgba(148,163,184,0.15)" />
      ))}
      <path d={d} fill="none" stroke="#60a5fa" strokeWidth="2.5" />
      {pts.map((p, i) => (
        <circle key={p.month} cx={xFor(i)} cy={yFor(p.value)} r="3.2" fill="#e2e8f0" />
      ))}
      {/* x labels */}
      {pts.map((p, i) => {
        const m = p.month.split('-')[1];
        const label = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][Number(m) - 1] || m;
        if (i % 2 !== 0) return null;
        return (
          <text key={p.month} x={xFor(i)} y={h - 10} textAnchor="middle" className="dash-axis">
            {label}
          </text>
        );
      })}
    </svg>
  );
};

const MultiLineTrendChart = ({ series, visible, emptyLabel }) => {
  const s = Array.isArray(series) ? series : [];
  const enabledKeys = Object.entries(visible || {}).filter(([, v]) => !!v).map(([k]) => k);
  const enabled = s.filter((x) => enabledKeys.includes(x.key));

  const allPoints = enabled.flatMap((x) => x.points || []);
  const values = allPoints.map((p) => Number(p.value || 0));
  const max = Math.max(1, ...values);

  const w = 800;
  const h = 220;
  const padL = 42;
  const padB = 34;
  const padT = 12;
  const padR = 12;

  // Use 12 months from the first series (all are aligned)
  const pts = (s[0]?.points || []);
  const xFor = (i) => padL + (i * (w - padL - padR)) / Math.max(1, pts.length - 1);
  const yFor = (v) => padT + (h - padT - padB) * (1 - v / max);

  const pathFor = (points) => {
    if (!Array.isArray(points) || points.length === 0) return '';
    const coords = points.map((p, i) => ({ x: xFor(i), y: yFor(Number(p.value || 0)) }));
    if (coords.length < 2) return `M ${coords[0].x} ${coords[0].y}`;
    // Straight line segments (reads more accurately for sparse / spiky data)
    return coords.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');
  };

  const hasData = values.some((v) => v > 0);

  return (
    <div className="dash-trend-wrap">
      <svg width="100%" height="240" viewBox={`0 0 ${w} ${h}`} className="dash-trend">
        {/* grid */}
        {[0.25, 0.5, 0.75, 1].map((t) => (
          <line key={t} x1={padL} x2={w - padR} y1={yFor(max * t)} y2={yFor(max * t)} stroke="rgba(148,163,184,0.15)" />
        ))}

        {!hasData ? (
          <text x={w / 2} y={h / 2} textAnchor="middle" className="dash-empty">
            {emptyLabel || 'No data yet.'}
          </text>
        ) : (
          enabled.map((line) => (
            <g key={line.key}>
              <path d={pathFor(line.points)} fill="none" stroke={line.color} strokeWidth="2.5" />
              {(line.points || []).map((p, i) => (
                <circle key={`${line.key}-${p.month}`} cx={xFor(i)} cy={yFor(Number(p.value || 0))} r="2.8" fill="#e2e8f0" />
              ))}
            </g>
          ))
        )}

        {/* x labels */}
        {(pts || []).map((p, i) => {
          const m = p.month.split('-')[1];
          const label = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][Number(m) - 1] || m;
          if (i % 2 !== 0) return null;
          return (
            <text key={p.month} x={xFor(i)} y={h - 10} textAnchor="middle" className="dash-axis">
              {label}
            </text>
          );
        })}
      </svg>
    </div>
  );
};

const BarChart = ({ bars }) => {
  const items = Array.isArray(bars) ? bars : [];
  const max = Math.max(1, ...items.map((b) => b.value));
  const w = 520;
  const h = 220;
  const padL = 42;
  const padB = 34;
  const padT = 12;
  const padR = 12;
  const bw = ((w - padL - padR) / Math.max(1, items.length)) * 0.5;
  return (
    <svg width="100%" height="240" viewBox={`0 0 ${w} ${h}`} className="dash-bars">
      {[0.25, 0.5, 0.75, 1].map((t) => (
        <line key={t} x1={padL} x2={w - padR} y1={padT + (h - padT - padB) * (1 - t)} y2={padT + (h - padT - padB) * (1 - t)} stroke="rgba(148,163,184,0.15)" />
      ))}
      {items.map((b, i) => {
        const x = padL + (i + 0.25) * ((w - padL - padR) / items.length);
        const barH = (h - padT - padB) * (b.value / max);
        const y = h - padB - barH;
        const color = b.key === 'LOW' ? '#38bdf8' : b.key === 'MEDIUM' ? '#f59e0b' : b.key === 'HIGH' ? '#ef4444' : '#fb7185';
        return (
          <g key={b.key}>
            <rect x={x} y={y} width={bw} height={barH} fill={color} rx="4" />
            <text x={x + bw / 2} y={h - 10} textAnchor="middle" className="dash-axis">{b.key}</text>
          </g>
        );
      })}
      <text x={padL} y={h - 10} textAnchor="start" className="dash-axis">RISKS</text>
    </svg>
  );
};

const StackedSeverityBar = ({ counts }) => {
  const c = counts || {};
  const parts = [
    { key: 'CRITICAL', value: Number(c.CRITICAL || 0), color: '#ef4444' },
    { key: 'HIGH', value: Number(c.HIGH || 0), color: '#fb7185' },
    { key: 'MEDIUM', value: Number(c.MEDIUM || 0), color: '#f59e0b' },
    { key: 'LOW', value: Number(c.LOW || 0), color: '#38bdf8' },
    { key: 'INFO', value: Number(c.INFO || 0), color: '#94a3b8' },
  ];
  const total = parts.reduce((a, b) => a + b.value, 0);
  return (
    <div className="dash-stacked-wrap" aria-label="Vulnerability severity distribution">
      <div className="dash-stacked">
        {total === 0 ? (
          <div className="dash-stacked-empty" />
        ) : (
          parts.filter((p) => p.value > 0).map((p) => (
            <div
              key={p.key}
              className="dash-stacked-seg"
              style={{ width: `${(p.value / total) * 100}%`, background: p.color }}
              title={`${p.key}: ${p.value}`}
            />
          ))
        )}
      </div>
      <div className="dash-stacked-legend">
        {parts.map((p) => (
          <div key={p.key} className="dash-stacked-item">
            <span className="dash-stacked-dot" style={{ background: p.color }} />
            <span className="dash-stacked-key">{p.key}</span>
            <span className="dash-stacked-val">{p.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Dashboard;

