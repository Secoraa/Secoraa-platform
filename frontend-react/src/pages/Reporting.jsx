import React, { useEffect, useMemo, useState } from 'react';
import { createReport, downloadReportPdf, getAllScans, getDomains, getSubdomains, listReports } from '../api/apiClient';
import Notification from '../components/Notification';
import Dropdown from '../components/Dropdown';
import ScanTypeIcon from '../components/ScanTypeIcon';
import nexveilLogo from '../assets/nexveil-logo.png';
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

  const normalizeAssetUrl = (value) => {
    const raw = String(value || '').trim();
    if (!raw) return '';
    try {
      const parsed = new URL(raw);
      const normalizedPath = parsed.pathname.replace(/\/+$/, '').toLowerCase();
      return `${parsed.protocol.toLowerCase()}//${parsed.host.toLowerCase()}${normalizedPath}`;
    } catch (err) {
      return raw.replace(/\/+$/, '').toLowerCase();
    }
  };

  const apiAssetOptions = useMemo(() => {
    const uniqueByAsset = new Map();
    (apiScansForDomain || [])
      .filter((s) => s.asset_url && String(s.status).toUpperCase() === 'COMPLETED')
      .forEach((s) => {
        const key = normalizeAssetUrl(s.asset_url);
        if (!key || uniqueByAsset.has(key)) return;
        uniqueByAsset.set(key, {
          value: s.scan_id,
          label: s.asset_url,
        });
      });
    return Array.from(uniqueByAsset.values());
  }, [apiScansForDomain]);

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
                  <td colSpan="5">
                    <div className="empty-report">
                      <img src={nexveilLogo} alt="NexVeil" className="empty-report-logo" />
                      <div className="empty-report-tagline">Start your API Security Journey with NexVeil</div>
                      <button className="empty-report-btn" onClick={() => { setShowModal(true); resetModal(); }}>Create Your First Report</button>
                    </div>
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
                            assessment === 'WEBSCAN' ? 'Vulnerability Scan' :
                            assessment === 'API' || assessment === 'API_TESTING' ? 'API Scan' :
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
                <Dropdown
                  value={assessmentType}
                  onChange={(val) => {
                    setAssessmentType(val);
                    setSubdomainName('');
                    setScanId('');
                  }}
                  options={[
                    { value: 'DOMAIN', label: 'Domain', icon: <ScanTypeIcon type="dd" /> },
                    { value: 'WEBSCAN', label: 'Vulnerability Scan', icon: <ScanTypeIcon type="subdomain" /> },
                    { value: 'API_TESTING', label: 'API Scan', icon: <ScanTypeIcon type="api" /> },
                  ]}
                />
              </div>

              <div className="modal-field">
                <label>Summary type</label>
                <Dropdown
                  value={reportType}
                  onChange={(val) => setReportType(val)}
                  options={[
                    { value: 'EXEC_SUMMARY', label: 'Executive Summary' },
                    { value: 'DETAILS_SUMMARY', label: 'Details Report' },
                  ]}
                />
              </div>

              <div className="modal-field">
                <label>Description</label>
                <textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional" rows={3} />
              </div>

              <div className="modal-field">
                <label>Domain name</label>
                <Dropdown
                  value={domainName}
                  onChange={(val) => setDomainName(val)}
                  placeholder="Select domain"
                  options={domains.map((d) => ({
                    value: d.domain_name,
                    label: d.domain_name,
                  }))}
                />
              </div>

              {assessmentType === 'WEBSCAN' && (
                <div className="modal-field">
                  <label>Subdomain</label>
                  <Dropdown
                    value={subdomainName}
                    onChange={(val) => setSubdomainName(val)}
                    disabled={!domainName}
                    placeholder={domainName ? 'Select subdomain' : 'Select domain first'}
                    options={(subdomains || [])
                      .filter((s) => String(s.domain_id) === String(domains.find((d) => d.domain_name === domainName)?.id))
                      .map((s) => ({
                        value: s.subdomain_name,
                        label: s.subdomain_name,
                      }))}
                  />
                </div>
              )}

              {assessmentType === 'API_TESTING' && (
                <div className="modal-field">
                  <label>API Asset</label>
                  <Dropdown
                    value={scanId}
                    onChange={(val) => setScanId(val)}
                    placeholder="Select API asset"
                    options={apiAssetOptions}
                  />
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

