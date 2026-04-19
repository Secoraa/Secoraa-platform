import React, { useState, useEffect, useMemo } from 'react';
import { getScanResults } from '../api/apiClient';
import Notification from '../components/Notification';
import { dedupeAssetsPreserveOrder } from '../utils/assets';
import NexVeilLoader from '../components/NexVeilLoader';
import './ScanResults.css';
import './Vulnerability.css';

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFORMATIONAL: 4 };
const SEVERITY_COLORS = {
  CRITICAL: '#ff4757',
  HIGH: '#ff6b35',
  MEDIUM: '#ffa502',
  LOW: '#2ed573',
  INFORMATIONAL: '#70a1ff',
};

const SEVERITY_PILL_SLUGS = new Set(['critical', 'high', 'medium', 'low', 'informational', 'info']);

/** Same pill classes as Vulnerability table (Vulnerability.css `.sev-*`). */
function severityPillClass(severity) {
  let slug = String(severity || 'INFORMATIONAL').trim().toLowerCase();
  if (slug === 'info') slug = 'informational';
  if (!SEVERITY_PILL_SLUGS.has(slug)) slug = 'informational';
  return `sev sev-${slug}`;
}

function collectUrlsFromVulnItem(item) {
  const urls = [];
  const pocs = Array.isArray(item?.pocs) ? item.pocs : [];
  for (const p of pocs) {
    if (!p || typeof p !== 'object') continue;
    if (Array.isArray(p.urls)) {
      for (const u of p.urls) {
        if (u != null && String(u).trim()) urls.push(String(u).trim());
      }
    }
  }
  return dedupeAssetsPreserveOrder(urls);
}

const SCAN_TYPE_LABELS = {
  dd: 'Domain Discovery Scan',
  subdomain: 'Web Scan',
  api: 'API Scan',
  ci_api_security: 'CI/CD API Security Scan',
  web: 'Web Scan',
  network: 'Network Scan',
  vulnerability: 'Vulnerability Scan',
};

const ScanResults = ({ scanId, onBack }) => {
  const [scanResults, setScanResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notification, setNotification] = useState(null);
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('ALL');

  useEffect(() => {
    if (scanId) {
      loadResults();
    }
  }, [scanId]);

  const loadResults = async () => {
    try {
      setLoading(true);
      const results = await getScanResults(scanId);
      setScanResults(results);
    } catch (err) {
      setNotification({
        message: `Failed to load results: ${err.message}`,
        type: 'error',
      });
    } finally {
      setLoading(false);
    }
  };

  const report = scanResults?.report || {};
  // API scans use findings: []; vulnerability scanner uses findings: { pluginName: {...} }
  const rawFindings = Array.isArray(report.findings) ? report.findings : [];

  const vulnScannerRows = useMemo(() => {
    const fd = report.findings;
    if (!fd || typeof fd !== 'object' || Array.isArray(fd)) return [];
    const byDedupeKey = new Map();
    for (const [pluginKey, item] of Object.entries(fd)) {
      if (!item || typeof item !== 'object') continue;
      const v = item.vulnerability;
      const vul = v && typeof v === 'object' ? v : {};
      const title = String(vul.name || pluginKey || 'Finding').trim();
      const sevRaw = String(vul.severity || 'INFO').toUpperCase();
      const severity = sevRaw === 'INFO' ? 'INFORMATIONAL' : sevRaw;
      const vid = vul.vid != null && String(vul.vid).trim() !== '' ? String(vul.vid).trim() : null;
      const dedupeKey = vid ? `vid:${vid}` : `title:${title.toLowerCase()}`;
      const affectedUrls = collectUrlsFromVulnItem(item);
      if (byDedupeKey.has(dedupeKey)) {
        const prev = byDedupeKey.get(dedupeKey);
        prev.affectedUrls = dedupeAssetsPreserveOrder([...prev.affectedUrls, ...affectedUrls]);
        prev.mergedPluginKeys = [...(prev.mergedPluginKeys || [prev.id]), pluginKey];
        continue;
      }
      byDedupeKey.set(dedupeKey, {
        id: pluginKey,
        title,
        severity,
        cvss_score: vul.cvss_score,
        cvss_vector: vul.cvss_vector,
        description: vul.description,
        recommendation: vul.recommendation,
        affectedUrls,
        mergedPluginKeys: [pluginKey],
      });
    }
    return Array.from(byDedupeKey.values());
  }, [report.findings]);

  const uniqueScanSubdomains = useMemo(
    () => dedupeAssetsPreserveOrder(scanResults?.subdomains || []),
    [scanResults?.subdomains],
  );

  // Deduplicate by vulnerability title — same vulnerability type shown only once
  const findings = (() => {
    const seen = new Set();
    return rawFindings.filter((f) => {
      const key = String(f.title || f.issue || '').trim().toLowerCase();
      if (!key || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  })();

  // Recompute severity counts purely from deduplicated findings
  const severityCounts = findings.reduce((acc, f) => {
    const s = String(f.severity || 'INFORMATIONAL').toUpperCase();
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 });

  const filteredFindings = severityFilter === 'ALL'
    ? findings
    : findings.filter((f) => f.severity === severityFilter);

  const toggleFinding = (id) => {
    setExpandedFinding(expandedFinding === id ? null : id);
  };

  const renderApiScanResults = () => {
    const totalFindings = findings.length;
    const duration = report.duration_seconds;
    const baseUrl = report.base_url || scanResults?.asset_url;

    return (
      <>
        {/* Summary Cards */}
        <div className="api-summary-grid">
          <div className="summary-card summary-total">
            <div className="summary-number">{totalFindings}</div>
            <div className="summary-label">Total Findings</div>
          </div>
          <div className="summary-card summary-critical">
            <div className="summary-number">{severityCounts.CRITICAL || 0}</div>
            <div className="summary-label">Critical</div>
          </div>
          <div className="summary-card summary-high">
            <div className="summary-number">{severityCounts.HIGH || 0}</div>
            <div className="summary-label">High</div>
          </div>
          <div className="summary-card summary-medium">
            <div className="summary-number">{severityCounts.MEDIUM || 0}</div>
            <div className="summary-label">Medium</div>
          </div>
          <div className="summary-card summary-low">
            <div className="summary-number">{(severityCounts.LOW || 0) + (severityCounts.INFORMATIONAL || 0)}</div>
            <div className="summary-label">Low / Info</div>
          </div>
        </div>

        {/* Scan Info */}
        <div className="results-info-section">
          <div className="info-card">
            <h3>Scan Details</h3>
            <div className="info-grid">
              <div className="info-item">
                <span className="info-label">Target</span>
                <span className="info-value">{baseUrl || 'N/A'}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Endpoints Scanned</span>
                <span className="info-value">{report.total_endpoints || 0}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Duration</span>
                <span className="info-value">{duration ? `${duration}s` : 'N/A'}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Scan Mode</span>
                <span className="info-value">{(report.scan_mode || 'active').toUpperCase()}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Severity Filter */}
        <div className="findings-section">
          <div className="findings-header">
            <h2>Findings ({filteredFindings.length})</h2>
            <div className="severity-filters">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                <button
                  key={sev}
                  className={`filter-btn ${severityFilter === sev ? 'active' : ''} filter-${sev.toLowerCase()}`}
                  onClick={() => setSeverityFilter(sev)}
                >
                  {sev === 'ALL' ? 'All' : sev}
                  {sev !== 'ALL' && (
                    <span className="filter-count">
                      {sev === 'LOW'
                        ? (severityCounts.LOW || 0) + (severityCounts.INFORMATIONAL || 0)
                        : severityCounts[sev] || 0}
                    </span>
                  )}
                </button>
              ))}
            </div>
          </div>

          {/* Findings List */}
          {filteredFindings.length === 0 ? (
            <div className="empty-state">No findings match the selected filter</div>
          ) : (
            <div className="findings-list">
              {filteredFindings.map((finding, idx) => {
                const fId = finding.finding_id || `f-${idx}`;
                const isExpanded = expandedFinding === fId;
                return (
                  <div
                    key={fId}
                    className={`finding-card ${isExpanded ? 'expanded' : ''}`}
                    style={{ borderLeftColor: SEVERITY_COLORS[finding.severity] || '#70a1ff' }}
                  >
                    <div className="finding-header" onClick={() => toggleFinding(fId)}>
                      <div className="finding-header-left">
                        <span
                          className="severity-badge"
                          style={{ backgroundColor: SEVERITY_COLORS[finding.severity] || '#70a1ff' }}
                        >
                          {finding.severity}
                        </span>
                        <span className="finding-title">{finding.title}</span>
                      </div>
                      <div className="finding-header-right">
                        <span className="finding-cvss">CVSS {finding.cvss_score}</span>
                        <span className="finding-expand">{isExpanded ? '−' : '+'}</span>
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="finding-details">
                        <div className="finding-detail-row">
                          <span className="detail-label">Endpoint</span>
                          <code className="detail-value-code">{finding.endpoint}</code>
                        </div>
                        <div className="finding-detail-row">
                          <span className="detail-label">Description</span>
                          <span className="detail-value">{finding.description}</span>
                        </div>
                        <div className="finding-detail-row">
                          <span className="detail-label">Impact</span>
                          <span className="detail-value">{finding.impact}</span>
                        </div>
                        <div className="finding-detail-row">
                          <span className="detail-label">Remediation</span>
                          <span className="detail-value">{finding.remediation}</span>
                        </div>
                        {finding.confidence && (
                          <div className="finding-detail-row">
                            <span className="detail-label">Confidence</span>
                            <span className={`confidence-badge confidence-${finding.confidence.toLowerCase()}`}>
                              {finding.confidence}
                            </span>
                          </div>
                        )}
                        {finding.owasp_category && (
                          <div className="finding-detail-row">
                            <span className="detail-label">OWASP</span>
                            <span className="detail-value">{finding.owasp_category}</span>
                          </div>
                        )}
                        {finding.cvss_vector && (
                          <div className="finding-detail-row">
                            <span className="detail-label">CVSS Vector</span>
                            <code className="detail-value-code">{finding.cvss_vector}</code>
                          </div>
                        )}
                        {finding.references && finding.references.length > 0 && (
                          <div className="finding-detail-row">
                            <span className="detail-label">References</span>
                            <div className="detail-value">
                              {finding.references.map((ref, rIdx) => (
                                <a
                                  key={rIdx}
                                  href={ref}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="ref-link"
                                >
                                  {ref}
                                </a>
                              ))}
                            </div>
                          </div>
                        )}
                        {finding.evidence && Object.keys(finding.evidence).length > 0 && (
                          <div className="finding-detail-row">
                            <span className="detail-label">Evidence</span>
                            <pre className="evidence-pre">
                              {JSON.stringify(finding.evidence, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </>
    );
  };

  return (
    <div className="scan-results-page">
      {notification && (
        <Notification
          message={notification.message}
          type={notification.type}
          onClose={() => setNotification(null)}
        />
      )}

      <div className="scan-results-header">
        <button className="btn-back" onClick={onBack}>
          ← Back to Scan History
        </button>
        <h1>{scanResults?.scan_name || 'Scan Results'}</h1>
      </div>

      {loading ? (
        <NexVeilLoader />
      ) : scanResults ? (
        <div className="scan-results-content">
          {(scanResults.scan_type === 'api' || (scanResults.scan_type && scanResults.scan_type.startsWith('ci_'))) ? (
            renderApiScanResults()
          ) : (
            <>
              <div className="results-info-section">
                <div className="info-card">
                  <h3>Scan Information</h3>
                  <div className="info-grid">
                    <div className="info-item">
                      <span className="info-label">Scan Name</span>
                      <span className="info-value">{scanResults.scan_name}</span>
                    </div>
                    <div className="info-item">
                      <span className="info-label">Scan Type</span>
                      <span className="info-value">{SCAN_TYPE_LABELS[scanResults.scan_type] || scanResults.scan_type?.toUpperCase() || 'N/A'}</span>
                    </div>
                    <div className="info-item">
                      <span className="info-label">Domain</span>
                      <span className="info-value">{scanResults.domain || report.scan?.domain || 'N/A'}</span>
                    </div>
                    <div className="info-item">
                      <span className="info-label">Total Subdomains</span>
                      <span className="info-value">{scanResults.total_subdomains || 0}</span>
                    </div>
                  </div>
                </div>
              </div>

              {scanResults.scan_type === 'vulnerability' && report.preflight_checks && (
                <div className="results-info-section">
                  <div className="info-card">
                    <h3>Reachability</h3>
                    <div className="info-grid">
                      <div className="info-item">
                        <span className="info-label">Reachable</span>
                        <span className="info-value">{report.preflight_checks.reachable ? 'Yes' : 'No'}</span>
                      </div>
                      <div className="info-item">
                        <span className="info-label">Target</span>
                        <span className="info-value">{report.scan?.asset_value || scanResults.subdomains?.[0] || 'N/A'}</span>
                      </div>
                    </div>
                    {report.messages?.infos?.length > 0 && (
                      <ul className="scan-msg-list">
                        {report.messages.infos.map((m, i) => (
                          <li key={`info-${i}`}>{m}</li>
                        ))}
                      </ul>
                    )}
                    {report.messages?.errors?.length > 0 && (
                      <ul className="scan-msg-list scan-msg-errors">
                        {report.messages.errors.map((m, i) => (
                          <li key={`err-${i}`}>{m}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              )}

              {scanResults.scan_type === 'vulnerability' && (
                <div className="subdomains-section">
                  <h2>Findings ({vulnScannerRows.length})</h2>
                  {vulnScannerRows.length === 0 ? (
                    <div className="empty-state">
                      No findings in this scan report. The target may be clean, unreachable, or plugins did not
                      detect issues. Check reachability above and backend logs if this is unexpected.
                    </div>
                  ) : (
                    <div className="findings-list">
                      {vulnScannerRows.map((row) => (
                        <div key={row.id} className="finding-card vuln-scan-finding-card">
                          <div className="finding-header">
                            <div className="finding-header-left">
                              <span className={severityPillClass(row.severity)}>{row.severity}</span>
                              <span className="finding-title">{row.title}</span>
                            </div>
                            <div className="finding-header-right">
                              {row.cvss_score != null && row.cvss_score !== '' && (
                                <span className="finding-cvss">CVSS {row.cvss_score}</span>
                              )}
                            </div>
                          </div>
                          {(row.description ||
                            row.recommendation ||
                            row.cvss_vector ||
                            (row.affectedUrls && row.affectedUrls.length > 0)) && (
                            <div className="finding-details">
                              {row.description && (
                                <div className="finding-detail-row">
                                  <span className="detail-label">Description</span>
                                  <span className="detail-value">{row.description}</span>
                                </div>
                              )}
                              {row.recommendation && (
                                <div className="finding-detail-row">
                                  <span className="detail-label">Recommendation</span>
                                  <span className="detail-value">{row.recommendation}</span>
                                </div>
                              )}
                              {row.cvss_vector && (
                                <div className="finding-detail-row">
                                  <span className="detail-label">CVSS vector</span>
                                  <code className="detail-value-code">{row.cvss_vector}</code>
                                </div>
                              )}
                              {row.affectedUrls && row.affectedUrls.length > 0 && (
                                <div className="finding-detail-row">
                                  <span className="detail-label">Affected URLs</span>
                                  <ul className="vuln-affected-url-list">
                                    {row.affectedUrls.map((u) => (
                                      <li key={u}>
                                        <code className="detail-value-code">{u}</code>
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              <div className="subdomains-section">
                <h2>Subdomains ({uniqueScanSubdomains.length || scanResults.total_subdomains || 0})</h2>
                {uniqueScanSubdomains.length > 0 ? (
                  <div className="subdomains-list">
                    {uniqueScanSubdomains.map((subdomain) => (
                      <div key={subdomain} className="subdomain-item">
                        {subdomain}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="empty-state">No subdomains found</div>
                )}
              </div>

              {scanResults.scan_type === 'subdomain' && scanResults.report?.subdomains ? (
                <div className="subdomains-section">
                  <h2>Vulnerabilities</h2>
                  <div className="vuln-results">
                    {Object.entries(scanResults.report.subdomains || {}).map(([sub, data]) => {
                      const vulns = (data && data.vulnerabilities) || {};
                      const exposure = dedupeAssetsPreserveOrder(
                        (Array.isArray(vulns.exposure) ? vulns.exposure : []).map((e) => String(e)),
                      );
                      const misconfig = vulns.misconfiguration && typeof vulns.misconfiguration === 'object' ? vulns.misconfiguration : null;
                      const takeover = vulns.takeover || null;
                      const hasAny = exposure.length || misconfig || takeover;
                      return (
                        <div key={sub} className="vuln-subdomain-card">
                          <div className="vuln-subdomain-title">{sub}</div>
                          {!hasAny ? (
                            <div className="vuln-empty">No vulnerabilities found</div>
                          ) : (
                            <div className="vuln-groups">
                              {exposure.length > 0 && (
                                <div className="vuln-group">
                                  <div className="vuln-group-title">Exposure</div>
                                  <ul className="vuln-list">
                                    {exposure.map((e, idx) => (
                                      <li key={idx}>{String(e)}</li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                              {misconfig && Object.keys(misconfig).length > 0 && (
                                <div className="vuln-group">
                                  <div className="vuln-group-title">Misconfiguration</div>
                                  <pre className="vuln-pre">{JSON.stringify(misconfig, null, 2)}</pre>
                                </div>
                              )}
                              {takeover && (
                                <div className="vuln-group">
                                  <div className="vuln-group-title">Potential Takeover</div>
                                  <div className="vuln-text">{String(takeover)}</div>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : null}
            </>
          )}
        </div>
      ) : (
        <div className="empty-state">No results available</div>
      )}
    </div>
  );
};

export default ScanResults;
