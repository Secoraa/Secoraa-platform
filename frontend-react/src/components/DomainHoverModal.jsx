import React, { useEffect, useMemo, useRef, useState } from 'react';
import { getDomainById } from '../api/apiClient';
import './DomainHoverModal.css';

const tabs = [
  { id: 'subdomains', label: 'Subdomain' },
  { id: 'asn', label: 'ASN' },
  { id: 'vulns', label: 'Vulnerability' },
];

const DomainHoverModal = ({ domain, position, ipAddresses, findings, onClose }) => {
  const [activeTab, setActiveTab] = useState('subdomains');
  const [loading, setLoading] = useState(false);
  const [detail, setDetail] = useState(null);
  const rootRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        setLoading(true);
        const d = await getDomainById(domain.id);
        if (!cancelled) setDetail(d);
      } catch {
        if (!cancelled) setDetail(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [domain?.id]);

  const subdomains = useMemo(() => {
    const arr = detail?.subdomains || domain?.subdomains || [];
    return Array.isArray(arr) ? arr : [];
  }, [detail, domain]);

  const relatedIps = useMemo(() => {
    const all = Array.isArray(ipAddresses) ? ipAddresses : [];
    return all.filter((ip) => String(ip.domain_name || '').toLowerCase() === String(domain.domain_name || '').toLowerCase());
  }, [ipAddresses, domain]);

  const relatedFindings = useMemo(() => {
    const all = Array.isArray(findings) ? findings : [];
    const dn = String(domain.domain_name || '').toLowerCase();
    if (!dn) return [];
    return all.filter((f) => {
      const asset = String(f.asset_url || '').toLowerCase();
      return asset === dn || asset.endsWith(`.${dn}`) || asset.includes(dn);
    });
  }, [findings, domain]);

  const style = useMemo(() => {
    const x = Math.min(Math.max(10, position?.x ?? 10), window.innerWidth - 360);
    const y = Math.min(Math.max(10, position?.y ?? 10), window.innerHeight - 320);
    return { left: x, top: y };
  }, [position]);

  return (
    <div
      ref={rootRef}
      className="dhm"
      style={style}
      onMouseLeave={() => onClose && onClose()}
    >
      <div className="dhm-header">
        <div className="dhm-title">{domain.domain_name}</div>
        <button className="dhm-close" type="button" onClick={() => onClose && onClose()}>
          ✕
        </button>
      </div>

      <div className="dhm-tabs">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            className={`dhm-tab ${activeTab === t.id ? 'active' : ''}`}
            onClick={() => setActiveTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="dhm-body">
        {loading ? (
          <div className="dhm-muted">Loading…</div>
        ) : activeTab === 'subdomains' ? (
          <div className="dhm-list">
            {subdomains.length === 0 ? (
              <div className="dhm-muted">No subdomains found.</div>
            ) : (
              subdomains.slice(0, 12).map((s) => (
                <div key={s.id || s.subdomain_name || s.name} className="dhm-row">
                  {s.subdomain_name || s.name}
                </div>
              ))
            )}
            {subdomains.length > 12 && <div className="dhm-muted">Showing 12 of {subdomains.length}</div>}
          </div>
        ) : activeTab === 'asn' ? (
          <div>
            <div className="dhm-muted" style={{ marginBottom: 8 }}>
              ASN lookup is not enabled yet. Showing linked IP assets for this domain:
            </div>
            {relatedIps.length === 0 ? (
              <div className="dhm-muted">No IPs for this domain.</div>
            ) : (
              <div className="dhm-list">
                {relatedIps.slice(0, 10).map((ip) => (
                  <div key={ip.id || ip.ipaddress_name} className="dhm-row">
                    {ip.ipaddress_name}
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div className="dhm-list">
            {relatedFindings.length === 0 ? (
              <div className="dhm-muted">No vulnerabilities found for this domain.</div>
            ) : (
              relatedFindings.slice(0, 10).map((f, idx) => (
                <div key={`${f.issue || f.name}-${idx}`} className="dhm-row">
                  <div className="dhm-row-title">{f.issue || f.name}</div>
                  <div className={`dhm-sev sev-${String(f.severity || 'info').toLowerCase()}`}>
                    {String(f.severity || 'INFO').toUpperCase()}
                  </div>
                </div>
              ))
            )}
            {relatedFindings.length > 10 && <div className="dhm-muted">Showing 10 of {relatedFindings.length}</div>}
          </div>
        )}
      </div>
    </div>
  );
};

export default DomainHoverModal;

