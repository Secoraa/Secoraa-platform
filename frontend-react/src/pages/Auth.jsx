import React, { useMemo, useState } from 'react';
import './Auth.css';
import { login, signup, setStoredToken } from '../api/apiClient';

const Auth = ({ onAuthed }) => {
  const [mode, setMode] = useState('login'); // login | signup
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [tenant, setTenant] = useState('');
  const [remember, setRemember] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const title = useMemo(() => (mode === 'login' ? 'Welcome back' : 'Create your account'), [mode]);
  const subtitle = useMemo(() => (mode === 'login' ? 'Please enter your details' : 'Get started with Secoraa'), [mode]);

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
      {/* Decorative animation (kept subtle, disabled for reduce-motion users via CSS) */}
      <div className="auth-sky" aria-hidden="true">
        <div className="auth-clouds">
          <div className="auth-cloud cloud-1" />
          <div className="auth-cloud cloud-2" />
          <div className="auth-cloud cloud-3" />
          <div className="auth-cloud cloud-4" />
        </div>
        <svg className="auth-bird auth-bird1" viewBox="0 0 64 32" xmlns="http://www.w3.org/2000/svg">
          <path className="auth-wing auth-left" d="M32 16 C20 5, 5 5, 0 16" fill="none" stroke="currentColor" strokeWidth="2" />
          <path className="auth-wing auth-right" d="M32 16 C44 5, 59 5, 64 16" fill="none" stroke="currentColor" strokeWidth="2" />
        </svg>
        <svg className="auth-bird auth-bird2" viewBox="0 0 64 32" xmlns="http://www.w3.org/2000/svg">
          <path className="auth-wing auth-left" d="M32 16 C20 5, 5 5, 0 16" fill="none" stroke="currentColor" strokeWidth="2" />
          <path className="auth-wing auth-right" d="M32 16 C44 5, 59 5, 64 16" fill="none" stroke="currentColor" strokeWidth="2" />
        </svg>
        <svg className="auth-bird auth-bird3" viewBox="0 0 64 32" xmlns="http://www.w3.org/2000/svg">
          <path className="auth-wing auth-left" d="M32 16 C20 5, 5 5, 0 16" fill="none" stroke="currentColor" strokeWidth="2" />
          <path className="auth-wing auth-right" d="M32 16 C44 5, 59 5, 64 16" fill="none" stroke="currentColor" strokeWidth="2" />
        </svg>
      </div>

      <div className="auth-brand">
        <div className="auth-logo">
          <img src="/images/secoraa-logo.jpg" alt="Secoraa" onError={(e) => { e.target.style.display = 'none'; }} />
        </div>
        <div className="auth-brand-text">Secoraa</div>
      </div>

      <div className="auth-card">
        <div className="auth-card-header">
          <div className="auth-subtitle">{subtitle}</div>
          <h1 className="auth-title">{title}</h1>
        </div>

        {error && <div className="auth-error">{error}</div>}

        <form onSubmit={onSubmit} className="auth-form">
          <label className="auth-label">Email address</label>
          <input
            className="auth-input"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Email address"
            required
          />

          <label className="auth-label">Password</label>
          <input
            className="auth-input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password"
            required
          />

          {mode === 'signup' && (
            <>
              <label className="auth-label">Company name (tenant)</label>
              <input
                className="auth-input"
                type="text"
                value={tenant}
                onChange={(e) => setTenant(e.target.value)}
                placeholder="Secoraa"
              />
            </>
          )}

          <div className="auth-row">
            <label className="auth-checkbox">
              <input
                type="checkbox"
                checked={remember}
                onChange={(e) => setRemember(e.target.checked)}
              />
              <span>Remember for 30 days</span>
            </label>
            <button
              type="button"
              className="auth-link"
              onClick={() => alert('Forgot password: not implemented yet')}
            >
              Forgot password
            </button>
          </div>

          <button className="auth-primary" type="submit" disabled={loading}>
            {loading ? 'Please wait…' : (mode === 'login' ? 'Sign in' : 'Sign up')}
          </button>

          <button
            type="button"
            className="auth-google"
            onClick={() => alert('Google sign-in: not implemented yet')}
          >
            <span className="auth-google-dot">G</span>
            <span>Sign in with Google</span>
          </button>
        </form>

        <div className="auth-footer">
          {mode === 'login' ? (
            <span>
              Don&apos;t have an account?{' '}
              <button className="auth-link" type="button" onClick={() => setMode('signup')}>
                Sign up
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
      </div>
    </div>
  );
};

export default Auth;

