import React, { useState, useEffect } from 'react';
import { getScanResults } from '../api/apiClient';
import Notification from '../components/Notification';
import './ScanResults.css';

const ScanResults = ({ scanId, onBack }) => {
  const [scanResults, setScanResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notification, setNotification] = useState(null);

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
        <h1>Scan Results</h1>
      </div>

      {loading ? (
        <div className="loading-state">Loading scan results...</div>
      ) : scanResults ? (
        <div className="scan-results-content">
          <div className="results-info-section">
            <div className="info-card">
              <h3>Scan Information</h3>
              <div className="info-grid">
                <div className="info-item">
                  <span className="info-label">Scan Name:</span>
                  <span className="info-value">{scanResults.scan_name}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Scan Type:</span>
                  <span className="info-value">{scanResults.scan_type?.toUpperCase() || 'N/A'}</span>
                </div>
                {scanResults.scan_type === 'api' ? (
                  <div className="info-item">
                    <span className="info-label">Report:</span>
                    <span className="info-value">Available</span>
                  </div>
                ) : (
                  <>
                    <div className="info-item">
                      <span className="info-label">Domain:</span>
                      <span className="info-value">{scanResults.domain || 'N/A'}</span>
                    </div>
                    <div className="info-item">
                      <span className="info-label">Total Subdomains:</span>
                      <span className="info-value">{scanResults.total_subdomains || 0}</span>
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>

          {scanResults.scan_type === 'api' ? (
            <div className="subdomains-section">
              <h2>API Scan Report</h2>
              <pre style={{ whiteSpace: 'pre-wrap' }}>
                {JSON.stringify(scanResults.report || {}, null, 2)}
              </pre>
            </div>
          ) : (
            <>
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

