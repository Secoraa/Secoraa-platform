import React, { useEffect, useMemo, useState } from 'react';
import Notification from '../components/Notification';
import NexVeilLoader from '../components/NexVeilLoader';
import { getAllFindings, getDomains, getIPAddresses, getSubdomains, getUrls } from '../api/apiClient';
import './Dashboard.css';

const severityWeight = (sev) => {
  const s = String(sev || 'INFORMATIONAL').toUpperCase();
  const weights = { CRITICAL: 100, HIGH: 80, MEDIUM: 55, LOW: 25, INFORMATIONAL: 10 };
  return weights[s] ?? 10;
};

const safeArray = (v) => (Array.isArray(v) ? v : (Array.isArray(v?.data) ? v.data : []));


const monthKey = (d) => {
  const dt = d instanceof Date ? d : new Date(d);
  if (Number.isNaN(dt.getTime())) return null;
  return `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}`;
};

const Dashboard = () => {
  const [loading, setLoading] = useState(true);
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
    INFORMATIONAL: true,
  });

  const load = async () => {
    try {
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
    }
    setLoading(false);
  };

  useEffect(() => {
    load();
  }, []);

  // Deduplicate findings by (vuln name + asset_url) — same vuln on same asset across scans = once
  const dedupedFindings = useMemo(() => {
    const seen = new Set();
    return (findings || []).filter((f) => {
      const key = `${String(f.issue || f.name || '').trim().toLowerCase()}|${String(f.asset_url || '').trim().toLowerCase()}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [findings]);

  const totals = useMemo(() => {
    // Exclude domains — only count subdomains, IPs, URLs as assets
    const totalAssets = (subdomains?.length || 0) + (ips?.length || 0) + (urls?.length || 0);
    const totalVulns = dedupedFindings.length;
    const weights = dedupedFindings.map((f) => severityWeight(f.severity));
    const avgWeight = weights.length ? (weights.reduce((a, b) => a + b, 0) / weights.length) : 0;
    const risk10 = avgWeight / 10;
    return { totalAssets, totalVulns, avgWeight, risk10 };
  }, [subdomains, ips, urls, dedupedFindings]);

  const sevCounts = useMemo(() => {
    const out = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 };
    for (const f of dedupedFindings) {
      const s = String(f.severity || 'INFORMATIONAL').toUpperCase();
      out[s] = (out[s] || 0) + 1;
    }
    return out;
  }, [dedupedFindings]);

  const vulnByRiskBars = useMemo(() => {
    const keys = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    return keys.map((k) => ({ key: k, value: sevCounts[k] || 0 }));
  }, [sevCounts]);

  const recentVulns = useMemo(() => {
    // Deduplicate by vulnerability name, collecting unique assets per vuln
    const map = new Map();
    for (const f of dedupedFindings) {
      const key = String(f.issue || f.name || '').trim() || 'Unknown';
      const asset = String(f.asset_url || '').trim();
      const ts = new Date(f.created_at || 0).getTime();
      if (!map.has(key)) {
        map.set(key, { ...f, _assets: new Set(asset ? [asset] : []), _latestTs: ts });
      } else {
        const ex = map.get(key);
        if (asset) ex._assets.add(asset);
        if (ts > ex._latestTs) { ex._latestTs = ts; ex.created_at = f.created_at; }
      }
    }
    const rows = Array.from(map.values()).map((r) => ({ ...r, assetCount: r._assets.size }));
    rows.sort((a, b) => b._latestTs - a._latestTs);
    return rows.slice(0, 6);
  }, [dedupedFindings]);

  const topAssets = useMemo(() => {
    const map = new Map();
    for (const f of dedupedFindings) {
      const asset = String(f.asset_url || f.asset || f.url || 'Unknown').trim() || 'Unknown';
      const vulnKey = String(f.issue || f.name || '').trim().toLowerCase();
      if (!map.has(asset)) map.set(asset, { asset, vulns: new Set(), maxWeight: 0 });
      const entry = map.get(asset);
      if (vulnKey) entry.vulns.add(vulnKey);
      entry.maxWeight = Math.max(entry.maxWeight, severityWeight(f.severity));
    }
    const rows = Array.from(map.values()).map((e) => ({ asset: e.asset, count: e.vulns.size, maxWeight: e.maxWeight }));
    rows.sort((a, b) => (b.count - a.count) || (b.maxWeight - a.maxWeight) || a.asset.localeCompare(b.asset));
    return rows.slice(0, 6);
  }, [dedupedFindings]);

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
      INFORMATIONAL: initCounts(),
    };

    for (const f of dedupedFindings) {
      const sev = String(f.severity || 'INFORMATIONAL').toUpperCase();
      const k = monthKey(f.created_at);
      if (!k) continue;
      if (!String(k).startsWith(String(year))) continue;
      const bucket = bySev[sev] ? sev : 'INFORMATIONAL';
      bySev[bucket][k] = (bySev[bucket][k] || 0) + 1;
    }

    const colors = {
      CRITICAL: '#ef4444',
      HIGH: '#fb7185',
      MEDIUM: '#f59e0b',
      LOW: '#38bdf8',
      INFORMATIONAL: '#16a34a',
    };

    return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].map((sev) => ({
      key: sev,
      color: colors[sev],
      points: months.map((m) => ({ month: m, value: bySev[sev][m] || 0 })),
    }));
  }, [dedupedFindings]);

  const toggleSeverity = (sev) => {
    setVisibleSeverities((prev) => ({ ...prev, [sev]: !prev[sev] }));
  };

  const anySeverityVisible = useMemo(() => {
    return Object.values(visibleSeverities || {}).some(Boolean);
  }, [visibleSeverities]);

  if (loading) {
    return <NexVeilLoader />;
  }

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
      </div>


      <div className="dash-grid-top">
        {(() => {
          const rv = Math.max(0, Math.min(10, Number(totals.risk10 || 0)));
          const rm = getRiskMeta(rv);
          return (
            <div className="dash-card dash-card-centered">
              <div className="dash-kpi-value dash-kpi-value--lg" style={{ color: rm.color }}>
                {rv.toFixed(1)}
              </div>
              <div className="dash-kpi-label">OVERALL RISK</div>
              <div className="dash-risk-badge" style={{ color: rm.color, background: rm.bg, border: `1px solid ${rm.color}33` }}>
                {rm.label}
              </div>
            </div>
          );
        })()}

        <div className="dash-card dash-card-centered dash-card-clickable" onClick={() => setShowAssetBreakdown(true)}>
          <div className="dash-kpi-value dash-kpi-value--lg">{totals.totalAssets.toLocaleString()}</div>
          <div className="dash-kpi-label">TOTAL ASSETS</div>
        </div>

        <div className="dash-card">
          <div className="dash-card-kpi">
            <div className="dash-kpi-value">{totals.totalVulns.toLocaleString()}</div>
            <div className="dash-kpi-label">VULNERABILITIES</div>
          </div>
          <StackedSeverityBar counts={sevCounts} />
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
                <BreakdownRow label="Subdomains" value={assetTypeCounts.SUBDOMAINS} color="#E0B12B" />
                <BreakdownRow label="IP Addresses" value={assetTypeCounts.IPS} color="#18A999" />
                <BreakdownRow label="URLs" value={assetTypeCounts.URLS} color="#9b7fe8" />
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
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']).map((sev) => {
              const cls =
                sev === 'CRITICAL' ? 'critical' :
                sev === 'HIGH' ? 'high' :
                sev === 'MEDIUM' ? 'medium' :
                sev === 'LOW' ? 'low' : 'informational';
              const label = sev === 'INFORMATIONAL' ? 'Informational' : (sev[0] + sev.slice(1).toLowerCase());
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
                <th style={{ textAlign: 'center' }}>Assets Impacted</th>
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
                    <td style={{ textAlign: 'center' }}>{f.assetCount > 0 ? f.assetCount : '-'}</td>
                    <td><span className={`pill ${String(f.severity || 'informational').toLowerCase()}`}>{String(f.severity || 'INFORMATIONAL').toUpperCase()}</span></td>
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
    weight >= 25 ? 'low' : 'informational';
  const label = sev.toUpperCase();
  return <span className={`pill ${sev}`}>{label}</span>;
};

const getRiskMeta = (v) => {
  if (v >= 9)  return { label: 'Critical', color: '#FF4C4C', bg: 'rgba(255,76,76,0.12)',  band: 4 };
  if (v >= 7)  return { label: 'High',     color: '#FF8A00', bg: 'rgba(255,138,0,0.12)',  band: 3 };
  if (v >= 4)  return { label: 'Medium',   color: '#E0B12B', bg: 'rgba(224,177,43,0.12)', band: 2 };
  if (v >= 1)  return { label: 'Low',      color: '#18A999', bg: 'rgba(24,169,153,0.12)', band: 1 };
  return             { label: 'Secure',    color: '#28C76F', bg: 'rgba(40,199,111,0.12)', band: 0 };
};


const OverallRiskCard = ({ score, counts }) => {
  const v = Math.max(0, Math.min(10, Number(score || 0)));
  const { label, color, bg } = getRiskMeta(v);

  return (
    <div className="risk-card">
      {/* Header */}
      <div className="risk-card-header">
        <span className="risk-card-label">OVERALL RISK</span>
        <span className="risk-card-badge" style={{ color, background: bg, border: `1px solid ${color}33` }}>
          {label}
        </span>
      </div>

      {/* Score number — centered */}
      <div className="risk-score-wrap">
        <span className="risk-score-number" style={{ color }}>{v.toFixed(1)}</span>
        <span className="risk-score-denom">/10</span>
      </div>
    </div>
  );
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
        <line key={t} x1={padL} x2={w - padR} y1={yFor(max * t)} y2={yFor(max * t)} stroke="rgba(107,114,128,0.15)" />
      ))}
      <path d={d} fill="none" stroke="#60a5fa" strokeWidth="2.5" />
      {pts.map((p, i) => (
        <circle key={p.month} cx={xFor(i)} cy={yFor(p.value)} r="3.2" fill="#2563eb" />
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
  const baseline = yFor(0);

  // Smooth cubic-bezier wave path between data points
  const wavePathFor = (points) => {
    if (!Array.isArray(points) || points.length === 0) return '';
    const coords = points.map((p, i) => ({ x: xFor(i), y: yFor(Number(p.value || 0)) }));
    if (coords.length === 1) return `M ${coords[0].x} ${coords[0].y}`;
    let d = `M ${coords[0].x} ${coords[0].y}`;
    for (let i = 1; i < coords.length; i++) {
      const prev = coords[i - 1];
      const curr = coords[i];
      const cpx = (prev.x + curr.x) / 2;
      d += ` C ${cpx} ${prev.y} ${cpx} ${curr.y} ${curr.x} ${curr.y}`;
    }
    return d;
  };

  const areaPathFor = (points) => {
    const line = wavePathFor(points);
    if (!line || !Array.isArray(points) || points.length === 0) return '';
    const lastX = xFor(points.length - 1);
    const firstX = xFor(0);
    return `${line} L ${lastX} ${baseline} L ${firstX} ${baseline} Z`;
  };

  const hasData = values.some((v) => v > 0);

  return (
    <div className="dash-trend-wrap">
      <svg width="100%" height="240" viewBox={`0 0 ${w} ${h}`} className="dash-trend">
        <defs>
          {enabled.map((line) => (
            <linearGradient key={`grad-${line.key}`} id={`grad-${line.key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={line.color} stopOpacity="0.22" />
              <stop offset="100%" stopColor={line.color} stopOpacity="0" />
            </linearGradient>
          ))}
        </defs>
        {/* grid lines + y-axis labels */}
        {[0.25, 0.5, 0.75, 1].map((t) => {
          const val = Math.round(max * t);
          const y = yFor(max * t);
          return (
            <g key={t}>
              <line x1={padL} x2={w - padR} y1={y} y2={y} stroke="rgba(107,114,128,0.15)" />
              <text x={padL - 6} y={y + 4} textAnchor="end" className="dash-axis">{val}</text>
            </g>
          );
        })}

        {!hasData ? (
          <text x={w / 2} y={h / 2} textAnchor="middle" className="dash-empty">
            {emptyLabel || 'No data yet.'}
          </text>
        ) : (
          enabled.map((line) => (
            <g key={line.key}>
              <path d={areaPathFor(line.points)} fill={`url(#grad-${line.key})`} />
              <path
                d={wavePathFor(line.points)}
                fill="none"
                stroke={line.color}
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              {(line.points || []).map((p, i) => (
                <circle key={`${line.key}-${p.month}`} cx={xFor(i)} cy={yFor(Number(p.value || 0))} r="2.8" fill={line.color} />
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
  // total slots = RISKS (label-only) + one per bar item
  const totalSlots = items.length + 1;
  const slotW = (w - padL - padR) / totalSlots;
  const bw = slotW * 0.5;
  const slotCenter = (slot) => padL + (slot + 0.5) * slotW;
  return (
    <svg width="100%" height="240" viewBox={`0 0 ${w} ${h}`} className="dash-bars">
      {/* grid lines + y-axis labels */}
      {[0.25, 0.5, 0.75, 1].map((t) => {
        const val = Math.round(max * t);
        const y = padT + (h - padT - padB) * (1 - t);
        return (
          <g key={t}>
            <line x1={padL} x2={w - padR} y1={y} y2={y} stroke="rgba(107,114,128,0.15)" />
            <text x={padL - 6} y={y + 4} textAnchor="end" className="dash-axis">{val}</text>
          </g>
        );
      })}
      {/* RISKS label in slot 0 */}
      <text x={slotCenter(0)} y={h - 10} textAnchor="middle" className="dash-axis">RISKS</text>
      {/* bars + labels in slots 1..n */}
      {items.map((b, i) => {
        const cx = slotCenter(i + 1);
        const barH = (h - padT - padB) * (b.value / max);
        const y = h - padB - barH;
        const color = b.key === 'LOW' ? '#38bdf8' : b.key === 'MEDIUM' ? '#f59e0b' : b.key === 'HIGH' ? '#ef4444' : '#fb7185';
        return (
          <g key={b.key}>
            <rect x={cx - bw / 2} y={y} width={bw} height={barH} fill={color} rx="4" />
            <text x={cx} y={h - 10} textAnchor="middle" className="dash-axis">{b.key}</text>
          </g>
        );
      })}
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
    { key: 'INFORMATIONAL', value: Number(c.INFORMATIONAL || 0), color: '#16a34a' },
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

