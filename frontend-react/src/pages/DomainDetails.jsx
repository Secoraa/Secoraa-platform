import React, { useEffect, useMemo, useState } from 'react';
import { getDomainById, getIPAddresses, getAllFindings } from '../api/apiClient';
import './DomainDetails.css';

const normalizeSubdomains = (subs) => {
  const arr = Array.isArray(subs) ? subs : [];
  return arr
    .map((s) => {
      if (!s) return null;
      if (typeof s === 'string') return { id: s, name: s };
      return { id: s.id || s.subdomain_id || s.subdomain_name, name: s.subdomain_name || s.name };
    })
    .filter((x) => x && x.name);
};

const wordCount = (txt) => {
  return String(txt || '').trim().split(/\s+/).filter(Boolean).length;
};

const DomainDetails = ({ domainId, onBack }) => {
  const [activeTab, setActiveTab] = useState('subdomain');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [domain, setDomain] = useState(null);
  const [ips, setIps] = useState([]);
  const [findings, setFindings] = useState([]);

  const [expandedDesc, setExpandedDesc] = useState({});
  const [subdomainPage, setSubdomainPage] = useState(1);
  const [vulnPage, setVulnPage] = useState(1);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      if (!domainId) return;
      try {
        setLoading(true);
        setError(null);

        const [domainResp, ipResp, findingsResp] = await Promise.all([
          getDomainById(domainId),
          getIPAddresses(),
          getAllFindings(),
        ]);

        const domainData = domainResp?.data?.data || domainResp?.data || domainResp;
        const ipData = Array.isArray(ipResp) ? ipResp : [];
        const allFindings = Array.isArray(findingsResp?.data) ? findingsResp.data : Array.isArray(findingsResp) ? findingsResp : [];

        if (!mounted) return;
        setDomain(domainData);
        setIps(ipData);
        setFindings(allFindings);
      } catch (e) {
        if (!mounted) return;
        setError(e.message || 'Failed to load domain details');
      } finally {
        if (mounted) setLoading(false);
      }
    };
    load();
    return () => {
      mounted = false;
    };
  }, [domainId]);

  useEffect(() => {
    // reset pagination when switching domain
    setSubdomainPage(1);
    setVulnPage(1);
    setExpandedDesc({});
  }, [domainId]);

  const subdomains = useMemo(() => normalizeSubdomains(domain?.subdomains), [domain?.subdomains]);
  const domainIps = useMemo(() => (ips || []).filter((ip) => String(ip.domain_id) === String(domainId)), [ips, domainId]);
  const domainFindings = useMemo(
    () => (findings || []).filter((f) => String(f.domain_id || '') === String(domainId)),
    [findings, domainId]
  );

  const asnValue = domain?.asn || '-';

  const PAGE_SIZE = 20;
  const subdomainTotalPages = Math.max(1, Math.ceil(subdomains.length / PAGE_SIZE));
  const vulnTotalPages = Math.max(1, Math.ceil(domainFindings.length / PAGE_SIZE));

  const pagedSubdomains = useMemo(() => {
    const start = (subdomainPage - 1) * PAGE_SIZE;
    return subdomains.slice(start, start + PAGE_SIZE);
  }, [subdomains, subdomainPage]);

  const pagedFindings = useMemo(() => {
    const start = (vulnPage - 1) * PAGE_SIZE;
    return domainFindings.slice(start, start + PAGE_SIZE);
  }, [domainFindings, vulnPage]);

  const toggleDesc = (id) => {
    setExpandedDesc((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div className="domain-details-page">
      <div className="domain-details-header">
        <button className="domain-details-back" onClick={onBack}>← Back</button>
        <div className="domain-details-title">
          <div className="domain-details-title-top">Domain Details</div>
          <div className="domain-details-title-sub">{domain?.domain_name || '-'}</div>
        </div>
        <div />
      </div>

      <div className="domain-details-card">
        {loading ? (
          <div className="domain-details-empty">Loading domain details…</div>
        ) : error ? (
          <div className="domain-details-error">Error: {error}</div>
        ) : (
          <>
            <div className="domain-details-tabs">
              <button
                className={`domain-details-tab ${activeTab === 'subdomain' ? 'active' : ''}`}
                onClick={() => setActiveTab('subdomain')}
              >
                Subdomain <span className="pill">{subdomains.length}</span>
              </button>
              <button
                className={`domain-details-tab ${activeTab === 'asn' ? 'active' : ''}`}
                onClick={() => setActiveTab('asn')}
              >
                ASN <span className="pill">{domainIps.length}</span>
              </button>
              <button
                className={`domain-details-tab ${activeTab === 'vulnerability' ? 'active' : ''}`}
                onClick={() => setActiveTab('vulnerability')}
              >
                Vulnerability <span className="pill">{domainFindings.length}</span>
              </button>
            </div>

            {activeTab === 'subdomain' && (
              <div className="domain-details-section">
                <div className="domain-details-section-title">Subdomains</div>
                <div className="domain-details-table-wrap">
                  <table className="domain-details-table">
                    <thead>
                      <tr>
                        <th>NAME</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pagedSubdomains.length === 0 ? (
                        <tr>
                          <td className="domain-details-muted">No subdomains</td>
                        </tr>
                      ) : (
                        pagedSubdomains.map((s) => (
                          <tr key={s.id}>
                            <td className="mono">{s.name}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>

                {subdomains.length > PAGE_SIZE && (
                  <div className="domain-details-pagination">
                    <button
                      className="pg-btn"
                      onClick={() => setSubdomainPage((p) => Math.max(1, p - 1))}
                      disabled={subdomainPage === 1}
                    >
                      ←
                    </button>
                    <div className="pg-text">
                      Page {subdomainPage} / {subdomainTotalPages}
                    </div>
                    <button
                      className="pg-btn"
                      onClick={() => setSubdomainPage((p) => Math.min(subdomainTotalPages, p + 1))}
                      disabled={subdomainPage === subdomainTotalPages}
                    >
                      →
                    </button>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'asn' && (
              <div className="domain-details-section">
                <div className="domain-details-section-title">ASN</div>

                <div className="domain-details-kv">
                  <div className="kv-row">
                    <div className="kv-k">Stored ASN</div>
                    <div className="kv-v">{asnValue}</div>
                  </div>
                  <div className="kv-row">
                    <div className="kv-k">ASN lookup</div>
                    <div className="kv-v domain-details-muted">Coming soon (needs provider integration)</div>
                  </div>
                </div>

                <div className="domain-details-section-title" style={{ marginTop: 14 }}>Linked IP Assets</div>
                <div className="domain-details-table-wrap">
                  <table className="domain-details-table">
                    <thead>
                      <tr>
                        <th>IP ADDRESS</th>
                        <th>TAGS</th>
                      </tr>
                    </thead>
                    <tbody>
                      {domainIps.length === 0 ? (
                        <tr>
                          <td colSpan={2} className="domain-details-muted">No IP assets linked to this domain</td>
                        </tr>
                      ) : (
                        domainIps.map((ip) => (
                          <tr key={ip.id}>
                            <td className="mono">{ip.ipaddress_name || '-'}</td>
                            <td>{Array.isArray(ip.tags) && ip.tags.length ? ip.tags.join(', ') : '-'}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {activeTab === 'vulnerability' && (
              <div className="domain-details-section">
                <div className="domain-details-section-title">Vulnerabilities</div>
                <div className="domain-details-table-wrap">
                  <table className="domain-details-table">
                    <thead>
                      <tr>
                        <th>NAME</th>
                        <th>SEVERITY</th>
                        <th>ASSET</th>
                        <th>DESCRIPTION</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pagedFindings.length === 0 ? (
                        <tr>
                          <td colSpan={4} className="domain-details-muted">No vulnerabilities found for this domain</td>
                        </tr>
                      ) : (
                        pagedFindings.map((f) => {
                          const id = f.id || `${f.issue || f.name}-${f.asset_url || ''}-${f.endpoint || ''}`;
                          const desc = f.description || '';
                          const shouldToggle = wordCount(desc) > 15;
                          const expanded = Boolean(expandedDesc[id]);
                          const shown = expanded ? desc : desc.split(/\s+/).slice(0, 15).join(' ');
                          const name = f.issue || f.name || f.vuln_name || '-';
                          const severity = f.severity || '-';
                          const asset = f.asset_url || f.endpoint || f.subdomain || domain?.domain_name || '-';

                          return (
                            <tr key={id}>
                              <td>{name}</td>
                              <td>{severity}</td>
                              <td className="mono">{asset}</td>
                              <td>
                                <div className="desc-cell">
                                  <span>{shown}{!expanded && shouldToggle ? '…' : ''}</span>
                                  {shouldToggle && (
                                    <button className="desc-toggle" onClick={() => toggleDesc(id)}>
                                      {expanded ? 'Show less' : 'Show more'}
                                    </button>
                                  )}
                                </div>
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>

                {domainFindings.length > PAGE_SIZE && (
                  <div className="domain-details-pagination">
                    <button
                      className="pg-btn"
                      onClick={() => setVulnPage((p) => Math.max(1, p - 1))}
                      disabled={vulnPage === 1}
                    >
                      ←
                    </button>
                    <div className="pg-text">
                      Page {vulnPage} / {vulnTotalPages}
                    </div>
                    <button
                      className="pg-btn"
                      onClick={() => setVulnPage((p) => Math.min(vulnTotalPages, p + 1))}
                      disabled={vulnPage === vulnTotalPages}
                    >
                      →
                    </button>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default DomainDetails;

