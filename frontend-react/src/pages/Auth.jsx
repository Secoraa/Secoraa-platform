import React, { useMemo, useState } from 'react';
import secoraaLogo from '../assets/secoraa-logo.jpg';
import './Auth.css';
import { login, signup, setStoredToken } from '../api/apiClient';

const EyeIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
    <circle cx="12" cy="12" r="3" />
  </svg>
);

const EyeOffIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
    <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
    <line x1="1" y1="1" x2="23" y2="23" />
  </svg>
);

/* ── Service card icons ── */
const ShieldIcon = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);
const HackIcon = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" />
  </svg>
);
const BugIcon = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M8 2l1.5 1.5" /><path d="M14.5 3.5L16 2" />
    <path d="M9 7.5A3 3 0 0 1 15 7.5" />
    <path d="M6.5 10H4" /><path d="M20 10h-2.5" />
    <path d="M4.5 16H4" /><path d="M20 16h-.5" />
    <path d="M12 7v13" />
    <path d="M8 10c0 5 8 5 8 0" />
    <path d="M6 16c0 3 6 4 6 4s6-1 6-4" />
  </svg>
);
const TargetIcon = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" /><circle cx="12" cy="12" r="6" /><circle cx="12" cy="12" r="2" />
  </svg>
);

const services = [
  { icon: <ShieldIcon />, tag: 'Most Popular', title: 'Penetration Testing', desc: 'Simulate real-world attacks on your infrastructure to expose critical vulnerabilities before malicious actors do.' },
  { icon: <HackIcon />,   tag: 'Advanced',     title: 'API Testing',        desc: 'Deep inspection of REST, GraphQL, and gRPC APIs to uncover authentication flaws, injection vulnerabilities, and broken access controls.' },
  { icon: <BugIcon />,    tag: 'Fast Turnaround', title: 'Vulnerability Assessments', desc: 'Comprehensive scanning and manual analysis to identify, rank, and remediate security weaknesses.' },
  { icon: <TargetIcon />, tag: 'Enterprise',   title: 'CI/CD API Security Scanning', desc: 'Integrate automated API security scanning directly into your CI/CD pipeline to catch vulnerabilities before they reach production.' },
];

const Auth = ({ onAuthed }) => {
  const [mode, setMode] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [tenant, setTenant] = useState('');
  const [remember, setRemember] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const bannerText = useMemo(() => (mode === 'login' ? 'SIGN IN' : 'CREATE ACCOUNT'), [mode]);

  const onSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (mode === 'signup') {
        await signup(email, password, tenant);
      }
      const tokenResp = await login(email, password);
      const token = tokenResp?.access_token;
      if (!token) throw new Error('Login did not return access_token');
      setStoredToken(token, remember);
      onAuthed && onAuthed(token);
    } catch (err) {
      setError(err.message || 'Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      {/* ── Left: Auth card ── */}
      <div className="auth-left">
        <div className="auth-card">
          <div className="auth-logo-section">
            <div className="auth-logo">
              <img src={secoraaLogo} alt="Secoraa" onError={(e) => { e.target.style.display = 'none'; }} />
            </div>
            <span className="auth-brand-text">SECORAA</span>
          </div>

          <div className="auth-banner">
            <span className="auth-banner-text">{bannerText}</span>
          </div>

          <div className="auth-form-section">
            {error && <div className="auth-error">{error}</div>}

            <form onSubmit={onSubmit} className="auth-form">
              <input
                className="auth-input"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter email address"
                required
              />

              <div className="auth-input-wrap">
                <input
                  className="auth-input auth-input-pw"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password"
                  required
                />
                <button
                  type="button"
                  className="auth-pw-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                  tabIndex={-1}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOffIcon /> : <EyeIcon />}
                </button>
              </div>

              {mode === 'signup' && (
                <input
                  className="auth-input"
                  type="text"
                  value={tenant}
                  onChange={(e) => setTenant(e.target.value)}
                  placeholder="Company name (tenant)"
                />
              )}

              <div className="auth-row">
                <label className="auth-checkbox">
                  <input
                    type="checkbox"
                    checked={remember}
                    onChange={(e) => setRemember(e.target.checked)}
                  />
                  <span>Stay signed in</span>
                </label>
                <button
                  type="button"
                  className="auth-link"
                  onClick={() => alert('Forgot password: not implemented yet')}
                >
                  Forgot Password?
                </button>
              </div>

              <button className="auth-primary" type="submit" disabled={loading}>
                {loading ? 'Authenticating…' : 'Login'}
              </button>
            </form>
          </div>

          <div className="auth-footer">
            {mode === 'login' ? (
              <span>
                New to Secoraa?{' '}
                <button className="auth-link" type="button" onClick={() => setMode('signup')}>
                  Create an Account
                </button>
              </span>
            ) : (
              <span>
                Already have an account?{' '}
                <button className="auth-link" type="button" onClick={() => setMode('login')}>
                  Sign in
                </button>
              </span>
            )}
          </div>

          <div className="auth-copyright">
            &copy; Powered by Secoraa Inc. All Rights Reserved, {new Date().getFullYear()}
          </div>
        </div>
      </div>

      {/* ── Right: Marketing panel ── */}
      <div className="auth-right">
        <div className="auth-marketing">
          <div className="auth-marketing-heading">
            <h1 className="auth-marketing-title">Security Services</h1>
            <h1 className="auth-marketing-title gold">Built for Modern Threats</h1>
          </div>
          <p className="auth-marketing-sub">
            Continuously discover, monitor, and secure your entire attack surface.<br />
            From asset discovery to vulnerability scanning — all in one platform.
          </p>

          <button className="auth-demo-btn" onClick={() => alert('Demo request: coming soon!')}>
            Request Demo
          </button>

          <div className="auth-services-grid">
            {services.map((s) => (
              <div className="auth-service-card" key={s.title}>
                <div className="auth-service-top">
                  <div className="auth-service-icon">{s.icon}</div>
                  <span className="auth-service-tag">{s.tag}</span>
                </div>
                <h3 className="auth-service-title">{s.title}</h3>
                <p className="auth-service-desc">{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Auth;
