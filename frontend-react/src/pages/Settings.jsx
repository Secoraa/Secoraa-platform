import React, { useState, useEffect, useCallback } from 'react';
import { getUserProfile, getApiKeys, createApiKey, revokeApiKey } from '../api/apiClient';
import './Settings.css';

export default function Settings() {
  const [profile, setProfile] = useState(null);
  const [apiKeys, setApiKeys] = useState([]);
  const [newKeyName, setNewKeyName] = useState('');
  const [expiryDays, setExpiryDays] = useState('');
  const [generating, setGenerating] = useState(false);
  const [newKey, setNewKey] = useState(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');
  const [confirmModal, setConfirmModal] = useState({ open: false, keyId: null });

  const loadProfile = useCallback(async () => {
    try {
      const data = await getUserProfile();
      setProfile(data);
    } catch (err) {
      console.error('Failed to load profile', err);
    }
  }, []);

  const loadKeys = useCallback(async () => {
    try {
      const data = await getApiKeys();
      setApiKeys(data);
    } catch (err) {
      console.error('Failed to load API keys', err);
    }
  }, []);

  useEffect(() => {
    loadProfile();
    loadKeys();
  }, [loadProfile, loadKeys]);

  const handleGenerate = async () => {
    if (!newKeyName.trim()) {
      setError('Enter a name for this key');
      return;
    }
    setError('');
    setGenerating(true);
    setNewKey(null);
    try {
      const body = {
        name: newKeyName.trim(),
        scopes: ['ci'],
      };
      if (expiryDays && parseInt(expiryDays) > 0) {
        body.expires_in_days = parseInt(expiryDays);
      }
      const data = await createApiKey(body);
      setNewKey(data);
      setNewKeyName('');
      setExpiryDays('');
      loadKeys();
    } catch (err) {
      setError(err.message || 'Failed to generate key');
    } finally {
      setGenerating(false);
    }
  };

  const handleRevoke = (keyId) => {
    setConfirmModal({ open: true, keyId });
  };

  const confirmRevoke = async () => {
    const keyId = confirmModal.keyId;
    setConfirmModal({ open: false, keyId: null });
    try {
      await revokeApiKey(keyId);
      loadKeys();
    } catch (err) {
      console.error('Revoke failed', err);
    }
  };

  const handleCopy = () => {
    if (newKey?.key) {
      navigator.clipboard.writeText(newKey.key);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="settings-page">
      {confirmModal.open && (
        <div className="confirm-overlay" onClick={() => setConfirmModal({ open: false, keyId: null })}>
          <div className="confirm-modal" onClick={(e) => e.stopPropagation()}>
            <p className="confirm-text">Revoke this API key? Any CI/CD pipelines using it will stop working.</p>
            <div className="confirm-actions">
              <button className="confirm-btn confirm-btn-cancel" onClick={() => setConfirmModal({ open: false, keyId: null })}>Cancel</button>
              <button className="confirm-btn confirm-btn-yes" onClick={confirmRevoke}>Confirm</button>
            </div>
          </div>
        </div>
      )}
      <h1>Settings</h1>
      <p className="subtitle">Manage your account, API keys, and integrations.</p>

      {/* ── Profile ── */}
      <div className="settings-section">
        <h2>Profile</h2>
        <p className="section-desc">Your account information</p>
        {profile ? (
          <div className="profile-grid">
            <div className="profile-item">
              <label>Email / Username</label>
              <span>{profile.username}</span>
            </div>
            <div className="profile-item">
              <label>Tenant</label>
              <span>{profile.tenant}</span>
            </div>
            <div className="profile-item">
              <label>Status</label>
              <span>{profile.is_active ? 'Active' : 'Inactive'}</span>
            </div>
            <div className="profile-item">
              <label>Member since</label>
              <span>{new Date(profile.created_at).toLocaleDateString()}</span>
            </div>
          </div>
        ) : (
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Loading profile...</p>
        )}
      </div>

      {/* ── API Keys ── */}
      <div className="settings-section">
        <h2>API Keys</h2>
        <p className="section-desc">
          Generate API keys for CI/CD integrations like GitHub Actions. Keys are shown only once at creation.
        </p>

        <div className="apikey-form">
          <div className="field">
            <label>Key Name</label>
            <input
              type="text"
              placeholder="e.g. GitHub Actions - Production"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              style={{ width: 280 }}
            />
          </div>
          <div className="field">
            <label>Expires In</label>
            <select value={expiryDays} onChange={(e) => setExpiryDays(e.target.value)}>
              <option value="">Never</option>
              <option value="30">30 days</option>
              <option value="90">90 days</option>
              <option value="180">180 days</option>
              <option value="365">1 year</option>
            </select>
          </div>
          <button className="btn-generate" onClick={handleGenerate} disabled={generating}>
            {generating ? 'Generating...' : 'Generate API Key'}
          </button>
        </div>

        {error && <p style={{ color: '#ef4444', fontSize: '0.85rem', marginBottom: '1rem' }}>{error}</p>}

        {/* Show newly created key */}
        {newKey && (
          <div className="new-key-banner">
            <p className="warning">
              Copy this key now. You won't be able to see it again.
            </p>
            <div className="key-display">
              <span className="key-value">{newKey.key}</span>
              <button className="btn-copy" onClick={handleCopy}>
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
          </div>
        )}

        {/* Key list */}
        {apiKeys.length > 0 ? (
          <table className="apikey-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Key</th>
                <th>Status</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Last Used</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {apiKeys.map((k) => (
                <tr key={k.id}>
                  <td>{k.name}</td>
                  <td><span className="key-prefix">{k.key_prefix}...</span></td>
                  <td>
                    <span className={k.is_active ? 'badge-active' : 'badge-revoked'}>
                      {k.is_active ? 'Active' : 'Revoked'}
                    </span>
                  </td>
                  <td>{new Date(k.created_at).toLocaleDateString()}</td>
                  <td>{k.expires_at ? new Date(k.expires_at).toLocaleDateString() : 'Never'}</td>
                  <td>{k.last_used_at ? new Date(k.last_used_at).toLocaleDateString() : '-'}</td>
                  <td>
                    {k.is_active && (
                      <button className="btn-revoke" onClick={() => handleRevoke(k.id)}>
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-state">No API keys yet. Generate one to use in your CI/CD pipeline.</div>
        )}
      </div>

      {/* ── Usage guide ── */}
      <div className="settings-section">
        <h2>Using API Keys in GitHub Actions</h2>
        <p className="section-desc">Add your API key as a GitHub repository secret, then reference it in your workflow.</p>
        <pre style={{
          background: 'var(--bg-primary)',
          border: '1px solid var(--border-color)',
          borderRadius: 8,
          padding: '1rem',
          fontSize: '0.8rem',
          overflow: 'auto',
          color: 'var(--text-primary)',
        }}>
{`# .github/workflows/security.yml
- name: Secoraa API Security Scan
  uses: secoraa/api-security-scan@v1
  with:
    target-url: \${{ secrets.SECORAA_TARGET_URL }}
    auth-token: \${{ secrets.SECORAA_AUTH_TOKEN }}
    severity-threshold: HIGH`}
        </pre>
      </div>
    </div>
  );
}
