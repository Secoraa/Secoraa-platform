import React, { useEffect, useMemo, useState } from 'react';
import { getDomainById } from '../api/apiClient';
import './DomainGraph.css';

const computeNodePositions = (count, radius, cx, cy) => {
  if (count <= 0) return [];
  const step = (2 * Math.PI) / count;
  return Array.from({ length: count }, (_, i) => {
    const angle = i * step - Math.PI / 2; // start top
    return {
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
    };
  });
};

const shortenForCenter = (domainName, maxLen = 10) => {
  const s = (domainName || '').toString();
  if (!s) return '';
  const first = s.split('.')[0] || s;
  const label = first.length >= 3 ? first : s;
  if (label.length <= maxLen) return label;
  return `${label.slice(0, Math.max(0, maxLen - 1))}…`;
};

const ringCountFor = (n) => {
  if (n <= 20) return 1;
  if (n <= 60) return 2;
  if (n <= 120) return 3;
  return 4;
};

const sampleIndices = (count, maxLabels) => {
  if (count <= 0) return new Set();
  if (count <= maxLabels) return new Set(Array.from({ length: count }, (_, i) => i));
  const set = new Set();
  const step = count / maxLabels;
  for (let i = 0; i < maxLabels; i++) {
    set.add(Math.floor(i * step));
  }
  return set;
};

const DomainGraph = ({ domainId, onBack }) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [domain, setDomain] = useState(null);
  const [showLabels, setShowLabels] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        setLoading(true);
        setError(null);
        const resp = await getDomainById(domainId);
        const data = resp?.data || resp; // tolerate either shape
        if (mounted) setDomain(data);
      } catch (e) {
        if (mounted) setError(e.message);
      } finally {
        if (mounted) setLoading(false);
      }
    };
    if (domainId) load();
    return () => {
      mounted = false;
    };
  }, [domainId]);

  const subdomainNames = useMemo(() => {
    const subs = domain?.subdomains || [];
    // backend may return strings or objects; normalize to strings
    return subs
      .map((s) => (typeof s === 'string' ? s : s?.subdomain_name))
      .filter(Boolean);
  }, [domain]);

  const displayedSubdomains = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return subdomainNames;
    return subdomainNames.filter((s) => String(s).toLowerCase().includes(q));
  }, [subdomainNames, search]);

  useEffect(() => {
    // Default: hide labels when there are lots of nodes (prevents overlap)
    setShowLabels(displayedSubdomains.length <= 25);
  }, [displayedSubdomains.length]);

  const svg = useMemo(() => {
    const width = 960;
    const height = 540;
    const cx = width / 2;
    const cy = height / 2;
    const minDim = Math.min(width, height);

    const n = displayedSubdomains.length;
    const rings = ringCountFor(n);
    const outerRadius = minDim * 0.36;
    const innerRadius = minDim * 0.20;
    const ringGap = rings === 1 ? 0 : (outerRadius - innerRadius) / (rings - 1);
    const ringRadii = Array.from({ length: rings }, (_, i) => innerRadius + i * ringGap);

    // distribute nodes across rings
    const perRing = Math.ceil(n / rings);
    const nodes = [];
    for (let r = 0; r < rings; r++) {
      const start = r * perRing;
      const end = Math.min(n, start + perRing);
      const count = Math.max(0, end - start);
      const positions = computeNodePositions(count, ringRadii[r], cx, cy);
      for (let i = 0; i < count; i++) {
        nodes.push({
          idx: start + i,
          x: positions[i].x,
          y: positions[i].y,
          ring: r,
        });
      }
    }

    const centerR = n > 80 ? 30 : 28;
    const leafR = n > 120 ? 8 : n > 60 ? 10 : 14;

    return {
      width,
      height,
      cx,
      cy,
      rings,
      ringRadii,
      nodes,
      centerR,
      leafR,
      dense: n > 40,
    };
  }, [displayedSubdomains.length]);

  // Show all labels when small; otherwise sample to keep readable.
  const labelIdxSet = useMemo(
    () => sampleIndices(displayedSubdomains.length, displayedSubdomains.length <= 60 ? 9999 : 40),
    [displayedSubdomains.length]
  );

  if (!domainId) {
    return (
      <div className="domain-graph-page">
        <div className="domain-graph-header">
          <button className="btn-secondary" onClick={onBack}>← Back</button>
        </div>
        <div className="domain-graph-card">
          <div className="domain-graph-empty">No domain selected.</div>
        </div>
      </div>
    );
  }

  return (
    <div className="domain-graph-page">
      <div className="domain-graph-header">
        <button className="domain-graph-back-btn" onClick={onBack}>← Back</button>
        <div className="domain-graph-title">Domain Insight</div>
        <div />
      </div>

      <div className="domain-graph-card">
        {loading ? (
          <div className="domain-graph-empty">Loading domain...</div>
        ) : error ? (
          <div className="domain-graph-error">Error: {error}</div>
        ) : (
          <>
            <div className="domain-graph-domain-name">{domain?.domain_name}</div>

            <div className="domain-graph-controls">
              <input
                className="domain-graph-search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search subdomain…"
              />
            </div>

            <div className="domain-graph-svg-wrap">
              <svg
                className="domain-graph-svg"
                viewBox={`0 0 ${svg.width} ${svg.height}`}
                role="img"
                aria-label={`Domain graph for ${domain?.domain_name}`}
              >
                {/* rings */}
                {svg.ringRadii.map((r, i) => (
                  <circle
                    key={`ring-${i}`}
                    className={`ring ${i === svg.ringRadii.length - 1 ? 'ring-outer' : 'ring-inner'}`}
                    cx={svg.cx}
                    cy={svg.cy}
                    r={r}
                  />
                ))}

                {/* edges */}
                {svg.nodes.map((p) => (
                  <line
                    key={`edge-${p.idx}`}
                    className={`edge ${svg.dense ? 'edge-dense' : ''}`}
                    x1={svg.cx}
                    y1={svg.cy}
                    x2={p.x}
                    y2={p.y}
                  />
                ))}

                {/* center node */}
                <g>
                  <title>{domain?.domain_name}</title>
                  <circle className="node node-center" cx={svg.cx} cy={svg.cy} r={svg.centerR} />
                  <text className="node-label node-label-center" x={svg.cx} y={svg.cy + 4} textAnchor="middle">
                    {shortenForCenter(domain?.domain_name, 12)}
                  </text>
                </g>

                {/* subdomain nodes */}
                {svg.nodes.map((p) => {
                  const label = displayedSubdomains[p.idx];
                  const angle = Math.atan2(p.y - svg.cy, p.x - svg.cx);
                  const ux = Math.cos(angle);
                  const uy = Math.sin(angle);
                  const isRight = ux >= 0;
                  const labelEnabled = showLabels && labelIdxSet.has(p.idx);
                  const leaderBase = svg.leafR + 10;
                  const leaderExtra = (p.idx % 2) * 12; // alternate short/long
                  const leaderLen = leaderBase + leaderExtra;

                  const x1 = p.x + ux * svg.leafR;
                  const y1 = p.y + uy * svg.leafR;
                  const x2 = p.x + ux * leaderLen;
                  const y2 = p.y + uy * leaderLen;
                  const tx = x2 + ux * 6;
                  const ty = y2 + uy * 6;

                  return (
                    <g key={`node-${p.idx}`} className="leaf-group">
                      <title>{label}</title>
                      <circle className="node node-leaf" cx={p.x} cy={p.y} r={svg.leafR} />
                      {labelEnabled && (
                        <>
                          <line className="leader" x1={x1} y1={y1} x2={x2} y2={y2} />
                          <text
                            className="node-label node-label-leaf"
                            x={tx}
                            y={ty}
                            textAnchor={isRight ? 'start' : 'end'}
                            dominantBaseline="middle"
                          >
                            {label}
                          </text>
                        </>
                      )}
                    </g>
                  );
                })}
              </svg>
            </div>

            {displayedSubdomains.length === 0 && (
              <div className="domain-graph-empty">No subdomains found for this domain.</div>
            )}

            <div className="domain-graph-footer">
              <div className="domain-graph-footer-left">
                <label className="domain-graph-toggle">
                  <input
                    type="checkbox"
                    checked={showLabels}
                    onChange={(e) => setShowLabels(e.target.checked)}
                  />
                  Show labels
                </label>
                <div className="domain-graph-count">
                  {displayedSubdomains.length} subdomains
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default DomainGraph;

