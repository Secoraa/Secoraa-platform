import React, { useEffect, useMemo, useState } from 'react';
import { createReport, downloadReportPdf, getAllScans, getDomains, getSubdomains, listReports } from '../api/apiClient';
import Notification from '../components/Notification';
import './Reporting.css';

const Reporting = () => {
  const [notification, setNotification] = useState(null);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [domains, setDomains] = useState([]);
  const [reports, setReports] = useState([]);
  const [showModal, setShowModal] = useState(false);

  const [reportName, setReportName] = useState('');
  const [reportType, setReportType] = useState('EXEC_SUMMARY');
  const [description, setDescription] = useState('');
  const [domainName, setDomainName] = useState('');
  const [assessmentType, setAssessmentType] = useState('DOMAIN');
  const [subdomains, setSubdomains] = useState([]);
  const [subdomainName, setSubdomainName] = useState('');
  const [scans, setScans] = useState([]);
  const [scanId, setScanId] = useState('');

  const getAssetHost = (value) => {
    if (!value) return '';
    try {
      const url = new URL(value);
      return url.hostname || '';
    } catch (err) {
      return String(value).replace(/^https?:\/\//i, '').split('/')[0];
    }
  };

  const apiScansForDomain = useMemo(() => {
    const apiScans = (scans || []).filter((s) => String(s.scan_type || '').toLowerCase() === 'api');
    if (!domainName) return apiScans;
    const domainLower = String(domainName).toLowerCase();
    const filtered = apiScans.filter((s) => {
      const asset = String(s.asset_url || s.asset_name || '').toLowerCase();
      const host = getAssetHost(asset).toLowerCase();
      return (
        host === domainLower ||
        host.endsWith(`.${domainLower}`) ||
        asset.includes(domainLower)
      );
    });
    return filtered.length > 0 ? filtered : apiScans;
  }, [scans, domainName]);

  useEffect(() => {
    getDomains()
      .then((data) => setDomains(Array.isArray(data) ? data : data?.data || []))
      .catch(() => setDomains([]));
  }, []);

  useEffect(() => {
    // Needed for WEBSCAN and API_TESTING selection. Safe to load once.
    getSubdomains()
      .then((data) => setSubdomains(Array.isArray(data) ? data : data?.data || []))
      .catch(() => setSubdomains([]));
    getAllScans()
      .then((res) => setScans(Array.isArray(res?.data) ? res.data : []))
      .catch(() => setScans([]));
  }, []);

  const loadReports = async () => {
    try {
      setLoading(true);
      const res = await listReports(200, 0);
      setReports(Array.isArray(res?.data) ? res.data : []);
    } catch (err) {
      setNotification({ message: err.message, type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReports();
  }, []);

  const resetModal = () => {
    setReportName('');
    setReportType('EXEC_SUMMARY');
    setDescription('');
    setDomainName('');
    setAssessmentType('DOMAIN');
    setSubdomainName('');
    setScanId('');
  };

  const canGenerate = useMemo(() => {
    if (!reportName.trim()) return false;
    if (!domainName) return false;
    if (assessmentType === 'WEBSCAN' && !subdomainName) return false;
    if (assessmentType === 'API_TESTING' && !scanId) return false;
    return true;
  }, [reportName, reportType, domainName, assessmentType, subdomainName, scanId]);

  const downloadBlob = (blob, filename) => {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  };

  const handleGenerate = async () => {
    try {
      if (!canGenerate) return;
      setGenerating(true);

      const created = await createReport({
        reportName: reportName.trim(),
        reportType,
        description: description.trim(),
        domainName,
        assessmentType,
        subdomainName,
        scanId,
      });

      const reportId = created?.id;
      if (!reportId) throw new Error('Report created but no id returned');

      const blob = await downloadReportPdf(reportId);
      downloadBlob(blob, `${reportName.trim().replace(/\s+/g, '-')}.pdf`);

      setShowModal(false);
      resetModal();
      await loadReports();
    } catch (err) {
      setNotification({ message: err.message, type: 'error' });
    } finally {
      setGenerating(false);
    }
  };

  const handleDownloadExisting = async (r) => {
    try {
      const blob = await downloadReportPdf(r.id);
      downloadBlob(blob, `${(r.report_name || 'report').toString().replace(/\s+/g, '-')}.pdf`);
    } catch (err) {
      setNotification({ message: err.message, type: 'error' });
    }
  };

  return (
    <div className="reporting-page">
      {notification && (
        <Notification
          message={notification.message}
          type={notification.type}
          onClose={() => setNotification(null)}
          duration={5000}
        />
      )}

      <div className="reporting-header">
        <h1 className="page-title">REPORTING</h1>
        <button
          className="btn-primary"
          type="button"
          onClick={() => {
            setShowModal(true);
            resetModal();
          }}
        >
          New Report
        </button>
      </div>

      <div className="reporting-card">
        <div className="reporting-table-wrap">
          <table className="reporting-table">
            <thead>
              <tr>
                <th>REPORT NAME</th>
                <th>REPORT TYPE</th>
                <th>CREATED BY</th>
                <th>CREATED AT</th>
                <th>REPORT LINK</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="5" className="empty-state">
                    Loading…
                  </td>
                </tr>
              ) : reports.length === 0 ? (
                <tr>
                  <td colSpan="5" className="empty-state">
                    No reports found.
                  </td>
                </tr>
              ) : (
                reports.map((r) => (
                  <tr key={r.id}>
                    <td className="mono">{r.report_name}</td>
                    <td>
                      {(() => {
                        const rt = String(r.report_type || '').toUpperCase();
                        const scope = r.domain_name || '-';
                        // New format: <ASSESSMENT>_<VARIANT>
                        if (rt.includes('_')) {
                          const parts = rt.split('_');
                          const assessment = parts[0] || 'DOMAIN';
                          const variant = parts.slice(1).join('_') || '';
                          const assessmentLabel =
                            assessment === 'DOMAIN' ? 'Domain' :
                            assessment === 'WEBSCAN' ? 'Webscan (Subdomain)' :
                            assessment === 'API' || assessment === 'API_TESTING' ? 'API Testing' :
                            assessment;
                          const variantLabel =
                            variant === 'EXEC_SUMMARY' ? 'Executive Summary' :
                            variant === 'DETAILS_REPORT' || variant === 'DETAILS_SUMMARY' ? 'Details Report' :
                            variant;
                          return `${variantLabel} - ${assessmentLabel} (${scope})`;
                        }
                        if (rt === 'EXEC_SUMMARY' || rt === 'EXECUTIVE_SUMMARY' || rt === 'EXPOSURE_STORIES') return `Executive Summary - Domain (${scope})`;
                        if (rt === 'DETAILS_SUMMARY' || rt === 'DETAIL_SUMMARY' || rt === 'ASM') return `Details Report - Domain (${scope})`;
                        return rt || '-';
                      })()}
                    </td>
                    <td>{r.created_by || '-'}</td>
                    <td>{r.created_at ? new Date(r.created_at).toLocaleString() : '-'}</td>
                    <td>
                      <button className="link-btn" type="button" onClick={() => handleDownloadExisting(r)}>
                        Download
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {showModal && (
        <div className="modal-overlay" onMouseDown={() => setShowModal(false)}>
          <div className="modal" onMouseDown={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">New Report</div>
              <button className="icon-btn" type="button" onClick={() => setShowModal(false)}>
                ✕
              </button>
            </div>

            <div className="modal-body">
              <div className="modal-field">
                <label>Report name</label>
                <input value={reportName} onChange={(e) => setReportName(e.target.value)} placeholder="e.g. ASM Report - Q1" />
              </div>

              <div className="modal-field">
                <label>Assessment</label>
                <select
                  value={assessmentType}
                  onChange={(e) => {
                    const next = e.target.value;
                    setAssessmentType(next);
                    setSubdomainName('');
                    setScanId('');
                  }}
                >
                  <option value="DOMAIN">Domain</option>
                  <option value="WEBSCAN">Webscan (Subdomain)</option>
                  <option value="API_TESTING">API Testing</option>
                </select>
              </div>

              <div className="modal-field">
                <label>Summary type</label>
                <select value={reportType} onChange={(e) => setReportType(e.target.value)}>
                  <option value="EXEC_SUMMARY">Executive Summary</option>
                  <option value="DETAILS_SUMMARY">Details Report</option>
                </select>
              </div>

              <div className="modal-field">
                <label>Description</label>
                <textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional" rows={3} />
              </div>

              <div className="modal-field">
                <label>Domain name</label>
                <select value={domainName} onChange={(e) => setDomainName(e.target.value)}>
                  <option value="">Select domain</option>
                  {domains.map((d) => (
                    <option key={d.id} value={d.domain_name}>
                      {d.domain_name}
                    </option>
                  ))}
                </select>
              </div>

              {assessmentType === 'WEBSCAN' && (
                <div className="modal-field">
                  <label>Subdomain</label>
                  <select value={subdomainName} onChange={(e) => setSubdomainName(e.target.value)} disabled={!domainName}>
                    <option value="">{domainName ? 'Select subdomain' : 'Select domain first'}</option>
                    {(subdomains || [])
                      .filter((s) => String(s.domain_id) === String(domains.find((d) => d.domain_name === domainName)?.id))
                      .map((s) => (
                        <option key={s.id} value={s.subdomain_name}>
                          {s.subdomain_name}
                        </option>
                      ))}
                  </select>
                </div>
              )}

              {assessmentType === 'API_TESTING' && (
                <div className="modal-field">
                  <label>API Asset</label>
                  <select value={scanId} onChange={(e) => setScanId(e.target.value)}>
                    <option value="">Select API asset</option>
                    {(apiScansForDomain || [])
                      .slice(0, 200)
                      .map((s) => (
                        <option key={s.scan_id} value={s.scan_id}>
                          {s.asset_url || s.asset_name || s.scan_name} ({s.status})
                        </option>
                      ))}
                  </select>
                  {domainName && (apiScansForDomain || []).length > 0 && (apiScansForDomain || []).every((s) => !String(s.asset_url || s.asset_name || '').toLowerCase().includes(domainName.toLowerCase())) && (
                    <div className="helper-text">No API scans matched this domain. Showing all API scans.</div>
                  )}
                </div>
              )}
            </div>

            <div className="modal-footer">
              <button
                className="btn-secondary"
                type="button"
                onClick={() => {
                  setShowModal(false);
                  resetModal();
                }}
              >
                Cancel
              </button>
              <button className="btn-primary" type="button" onClick={handleGenerate} disabled={!canGenerate || generating}>
                {generating ? 'Generating…' : 'Generate report'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Reporting;

