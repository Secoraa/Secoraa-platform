import React, { useState, useEffect } from 'react';
import { getScanResults } from '../api/apiClient';
import Notification from '../components/Notification';
import './ScanResults.css';

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFORMATIONAL: 4 };
const SEVERITY_COLORS = {
  CRITICAL: '#ff4757',
  HIGH: '#ff6b35',
  MEDIUM: '#ffa502',
  LOW: '#2ed573',
  INFORMATIONAL: '#70a1ff',
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
  const findings = report.findings || [];
  const severityCounts = report.severity_counts || {};

  const filteredFindings = severityFilter === 'ALL'
    ? findings
    : findings.filter((f) => f.severity === severityFilter);

  const toggleFinding = (id) => {
    setExpandedFinding(expandedFinding === id ? null : id);
  };

  const renderApiScanResults = () => {
    const totalFindings = report.total_findings || findings.length;
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
        <div className="loading-state">Loading scan results...</div>
      ) : scanResults ? (
        <div className="scan-results-content">
          {scanResults.scan_type === 'api' ? (
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
                      <span className="info-value">{scanResults.scan_type?.toUpperCase() || 'N/A'}</span>
                    </div>
                    <div className="info-item">
                      <span className="info-label">Domain</span>
                      <span className="info-value">{scanResults.domain || 'N/A'}</span>
                    </div>
                    <div className="info-item">
                      <span className="info-label">Total Subdomains</span>
                      <span className="info-value">{scanResults.total_subdomains || 0}</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="subdomains-section">
                <h2>Subdomains ({scanResults.total_subdomains || 0})</h2>
                {scanResults.subdomains && scanResults.subdomains.length > 0 ? (
                  <div className="subdomains-list">
                    {scanResults.subdomains.map((subdomain, index) => (
                      <div key={index} className="subdomain-item">
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
                      const exposure = Array.isArray(vulns.exposure) ? vulns.exposure : [];
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
