import React, { useEffect, useMemo, useState } from 'react';
import Dropdown from '../components/Dropdown';
import Notification from '../components/Notification';
import { createPtaasRequest, listPtaasRequests } from '../api/apiClient';
import './Ptaas.css';

const TARGET_OPTIONS = [
  { value: 'DOMAIN', label: 'Domain' },
  { value: 'SUBDOMAIN', label: 'Subdomain' },
  { value: 'IP', label: 'IP Address' },
  { value: 'URL', label: 'URL' },
  { value: 'API', label: 'API' },
];

const Ptaas = ({ initialTab = 'new-pentest' }) => {
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [notification, setNotification] = useState(null);
  const [rows, setRows] = useState([]);
  const [activeTab, setActiveTab] = useState(initialTab === 'pentest' ? 'pentest' : 'new-pentest');
  const [form, setForm] = useState({
    title: '',
    targetType: 'DOMAIN',
    targetValue: '',
    scopeNotes: '',
    timeline: '',
  });

  const canSubmit = useMemo(() => (
    String(form.title || '').trim() &&
    String(form.targetType || '').trim() &&
    String(form.targetValue || '').trim()
  ), [form]);

  const loadRequests = async () => {
    try {
      setLoading(true);
      const res = await listPtaasRequests();
      setRows(Array.isArray(res?.data) ? res.data : []);
    } catch (err) {
      setRows([]);
      setNotification({ message: err.message || 'Failed to load PTAAS requests', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRequests();
  }, []);

  useEffect(() => {
    setActiveTab(initialTab === 'pentest' ? 'pentest' : 'new-pentest');
  }, [initialTab]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!canSubmit || submitting) return;
    try {
      setSubmitting(true);
      await createPtaasRequest(form);
      setNotification({ message: 'PTAAS request submitted successfully', type: 'success' });
      setForm({
        title: '',
        targetType: 'DOMAIN',
        targetValue: '',
        scopeNotes: '',
        timeline: '',
      });
      await loadRequests();
    } catch (err) {
      setNotification({ message: err.message || 'Failed to submit PTAAS request', type: 'error' });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="ptaas-page">
      {notification && (
        <Notification
          message={notification.message}
          type={notification.type}
          onClose={() => setNotification(null)}
        />
      )}

      <div className="ptaas-header">
        <h1 className="page-title">PTAAS</h1>
      </div>

      <div className="ptaas-tabs">
        <button
          className={`ptaas-tab ${activeTab === 'new-pentest' ? 'active' : ''}`}
          onClick={() => setActiveTab('new-pentest')}
          type="button"
        >
          New Pentest
        </button>
        <button
          className={`ptaas-tab ${activeTab === 'pentest' ? 'active' : ''}`}
          onClick={() => setActiveTab('pentest')}
          type="button"
        >
          Pentest
        </button>
      </div>

      <div className="ptaas-grid">
        {activeTab === 'new-pentest' && (
          <section className="ptaas-card">
            <h2>Request Intake</h2>
            <form className="ptaas-form" onSubmit={handleSubmit}>
              <label>
                Title
                <input
                  value={form.title}
                  onChange={(e) => setForm((prev) => ({ ...prev, title: e.target.value }))}
                  placeholder="e.g. Quarterly external pentest"
                  maxLength={200}
                  required
                />
              </label>

              <label>
                Target Type
                <Dropdown
                  value={form.targetType}
                  onChange={(val) => setForm((prev) => ({ ...prev, targetType: val }))}
                  options={TARGET_OPTIONS}
                />
              </label>

              <label>
                Target Value
                <input
                  value={form.targetValue}
                  onChange={(e) => setForm((prev) => ({ ...prev, targetValue: e.target.value }))}
                  placeholder="e.g. app.example.com / 10.10.10.5 / https://api.example.com"
                  maxLength={500}
                  required
                />
              </label>

              <label>
                Scope Notes
                <textarea
                  value={form.scopeNotes}
                  onChange={(e) => setForm((prev) => ({ ...prev, scopeNotes: e.target.value }))}
                  rows={4}
                  placeholder="In-scope assets, exclusions, auth notes, special constraints"
                  maxLength={2000}
                />
              </label>

              <label>
                Timeline
                <input
                  value={form.timeline}
                  onChange={(e) => setForm((prev) => ({ ...prev, timeline: e.target.value }))}
                  placeholder="e.g. Need report by 30 Apr"
                  maxLength={200}
                />
              </label>

              <div className="ptaas-actions">
                <button type="submit" className="btn-primary" disabled={!canSubmit || submitting}>
                  {submitting ? 'Submitting…' : 'Submit Request'}
                </button>
              </div>
            </form>
          </section>
        )}

        {activeTab === 'pentest' && (
          <section className="ptaas-card">
            <h2>Submitted Requests</h2>
            {loading ? (
              <div className="ptaas-empty">Loading…</div>
            ) : rows.length === 0 ? (
              <div className="ptaas-empty">No PTAAS requests yet.</div>
            ) : (
              <div className="ptaas-table-wrap">
                <table className="ptaas-table">
                  <thead>
                    <tr>
                      <th>Title</th>
                      <th>Target</th>
                      <th>Status</th>
                      <th>Timeline</th>
                      <th>Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r) => (
                      <tr key={r.id}>
                        <td>{r.title || '-'}</td>
                        <td>{`${r.target_type || '-'}: ${r.target_value || '-'}`}</td>
                        <td>
                          <span className={`ptaas-status status-${String(r.status || '').toLowerCase()}`}>
                            {r.status || '-'}
                          </span>
                        </td>
                        <td>{r.timeline || '-'}</td>
                        <td>{r.created_at ? new Date(r.created_at).toLocaleString() : '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}
      </div>
    </div>
  );
};

export default Ptaas;
