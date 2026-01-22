import React, { useEffect, useMemo, useState } from 'react';
import { createReport, downloadReportPdf, getDomains, listReports } from '../api/apiClient';
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
  const [reportType, setReportType] = useState('ASM');
  const [description, setDescription] = useState('');
  const [domainName, setDomainName] = useState('');

  useEffect(() => {
    getDomains()
      .then((data) => setDomains(Array.isArray(data) ? data : data?.data || []))
      .catch(() => setDomains([]));
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
    setReportType('ASM');
    setDescription('');
    setDomainName('');
  };

  const canGenerate = useMemo(() => {
    if (!reportName.trim()) return false;
    if (reportType !== 'ASM') return false; // only ASM for now
    if (!domainName) return false;
    return true;
  }, [reportName, reportType, domainName]);

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
                    <td>{r.report_type === 'ASM' ? `ASM report (${r.domain_name || '-'})` : r.report_type}</td>
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
                <label>Type</label>
                <select value={reportType} onChange={(e) => setReportType(e.target.value)}>
                  <option value="ASM">ASM report</option>
                  <option value="WEB">Web Report (coming soon)</option>
                  <option value="API">API Report (coming soon)</option>
                </select>
              </div>

              <div className="modal-field">
                <label>Description</label>
                <textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional" rows={3} />
              </div>

              <div className="modal-field">
                <label>Domain name</label>
                <select value={domainName} onChange={(e) => setDomainName(e.target.value)} disabled={reportType !== 'ASM'}>
                  <option value="">Select domain</option>
                  {domains.map((d) => (
                    <option key={d.id} value={d.domain_name}>
                      {d.domain_name}
                    </option>
                  ))}
                </select>
                {reportType !== 'ASM' && <div className="helper-text">Domain selection is only for ASM right now.</div>}
              </div>
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

