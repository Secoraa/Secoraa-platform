import React, { useMemo, useState } from 'react';
import secoraaLogo from '../assets/secoraa-logo.jpg';
import './Auth.css';
import { login, signup, setStoredToken } from '../api/apiClient';

const LockIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </svg>
);

const EyeIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
    <circle cx="12" cy="12" r="3" />
  </svg>
);

const EyeOffIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
    <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
    <line x1="1" y1="1" x2="23" y2="23" />
  </svg>
);

const SSOIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
    <circle cx="9" cy="7" r="4" />
    <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
    <path d="M16 3.13a4 4 0 0 1 0 7.75" />
  </svg>
);

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

            <div className="auth-divider">
              <span>OR</span>
            </div>

            <div className="auth-sso-row">
              <button
                type="button"
                className="auth-sso-btn auth-sso-oidc"
                onClick={() => alert('OIDC sign-in: not implemented yet')}
              >
                <SSOIcon />
                <span>Login with OIDC</span>
              </button>
              <button
                type="button"
                className="auth-sso-btn auth-sso-saml"
                onClick={() => alert('SAML sign-in: not implemented yet')}
              >
                <SSOIcon />
                <span>Login with SAML</span>
              </button>
            </div>
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
  );
};

export default Auth;
