import React, { useEffect, useMemo, useRef, useState } from 'react';
import nexveilLogo from '../assets/nexveil-logo.png';
import './Auth.css';
import {
  login,
  signup,
  setStoredToken,
  verifySignupOtp,
  resendSignupOtp,
  forgotPassword,
  verifyResetOtp,
  resetPassword,
} from '../api/apiClient';

const OTP_LENGTH = 6;
const RESEND_COOLDOWN_SECONDS = 60;

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

  const [otpDigits, setOtpDigits] = useState(Array(OTP_LENGTH).fill(''));
  const [otpInfo, setOtpInfo] = useState('');
  const [resendCountdown, setResendCountdown] = useState(0);
  const otpRefs = useRef([]);

  const [resetToken, setResetToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [loginInfo, setLoginInfo] = useState('');

  const bannerText = useMemo(() => {
    switch (mode) {
      case 'login': return 'SIGN IN';
      case 'signup': return 'CREATE ACCOUNT';
      case 'verify': return 'VERIFY EMAIL';
      case 'forgot': return 'RESET PASSWORD';
      case 'reset-otp': return 'ENTER CODE';
      case 'reset-password': return 'NEW PASSWORD';
      default: return 'SIGN IN';
    }
  }, [mode]);

  useEffect(() => {
    if (resendCountdown <= 0) return undefined;
    const id = setInterval(() => {
      setResendCountdown((s) => (s > 0 ? s - 1 : 0));
    }, 1000);
    return () => clearInterval(id);
  }, [resendCountdown]);

  useEffect(() => {
    if ((mode === 'verify' || mode === 'reset-otp') && otpRefs.current[0]) {
      otpRefs.current[0].focus();
    }
  }, [mode]);

  const resetOtpState = () => {
    setOtpDigits(Array(OTP_LENGTH).fill(''));
    setOtpInfo('');
    setError('');
  };

  const switchMode = (next) => {
    setError('');
    setOtpInfo('');
    setLoginInfo('');
    setMode(next);
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setOtpInfo('');
    setLoading(true);
    try {
      if (mode === 'signup') {
        const resp = await signup(email, password, tenant);
        setOtpDigits(Array(OTP_LENGTH).fill(''));
        setResendCountdown(RESEND_COOLDOWN_SECONDS);
        setOtpInfo(
          resp?.otp_expires_in_minutes
            ? `We sent a ${OTP_LENGTH}-digit code to ${email}. It expires in ${resp.otp_expires_in_minutes} minutes.`
            : `We sent a ${OTP_LENGTH}-digit code to ${email}.`
        );
        setMode('verify');
      } else {
        const tokenResp = await login(email, password);
        const token = tokenResp?.access_token;
        if (!token) throw new Error('Login did not return access_token');
        setStoredToken(token, remember);
        onAuthed && onAuthed(token);
      }
    } catch (err) {
      setError(err.message || 'Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  const handleOtpChange = (idx, rawValue) => {
    const value = rawValue.replace(/\D/g, '');
    if (!value) {
      const next = [...otpDigits];
      next[idx] = '';
      setOtpDigits(next);
      return;
    }
    if (value.length > 1) {
      const chars = value.slice(0, OTP_LENGTH - idx).split('');
      const next = [...otpDigits];
      chars.forEach((c, i) => {
        next[idx + i] = c;
      });
      setOtpDigits(next);
      const focusIdx = Math.min(idx + chars.length, OTP_LENGTH - 1);
      otpRefs.current[focusIdx]?.focus();
      return;
    }
    const next = [...otpDigits];
    next[idx] = value;
    setOtpDigits(next);
    if (idx < OTP_LENGTH - 1) {
      otpRefs.current[idx + 1]?.focus();
    }
  };

  const handleOtpKeyDown = (idx, e) => {
    if (e.key === 'Backspace' && !otpDigits[idx] && idx > 0) {
      otpRefs.current[idx - 1]?.focus();
    } else if (e.key === 'ArrowLeft' && idx > 0) {
      otpRefs.current[idx - 1]?.focus();
    } else if (e.key === 'ArrowRight' && idx < OTP_LENGTH - 1) {
      otpRefs.current[idx + 1]?.focus();
    }
  };

  const onVerifyOtp = async (e) => {
    e.preventDefault();
    setError('');
    const code = otpDigits.join('');
    if (code.length !== OTP_LENGTH) {
      setError(`Enter the ${OTP_LENGTH}-digit code from your email.`);
      return;
    }
    setLoading(true);
    try {
      const resp = await verifySignupOtp(email, code);
      const token = resp?.access_token;
      if (!token) throw new Error('Verification did not return access_token');
      setStoredToken(token, remember);
      onAuthed && onAuthed(token);
    } catch (err) {
      setError(err.message || 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  const onResend = async () => {
    if (resendCountdown > 0 || loading) return;
    setError('');
    setOtpInfo('');
    setLoading(true);
    try {
      const resp = await resendSignupOtp(email);
      setResendCountdown(RESEND_COOLDOWN_SECONDS);
      setOtpDigits(Array(OTP_LENGTH).fill(''));
      otpRefs.current[0]?.focus();
      setOtpInfo(
        resp?.otp_expires_in_minutes
          ? `New code sent. It expires in ${resp.otp_expires_in_minutes} minutes.`
          : 'New code sent to your email.'
      );
    } catch (err) {
      setError(err.message || 'Could not resend code');
    } finally {
      setLoading(false);
    }
  };

  const onBackToSignup = () => {
    resetOtpState();
    setResendCountdown(0);
    setMode('signup');
  };

  const onForgotClick = () => {
    setError('');
    setOtpInfo('');
    setLoginInfo('');
    setPassword('');
    setMode('forgot');
  };

  const onBackToLogin = () => {
    setError('');
    setOtpInfo('');
    setOtpDigits(Array(OTP_LENGTH).fill(''));
    setResendCountdown(0);
    setResetToken('');
    setNewPassword('');
    setShowNewPassword(false);
    setPassword('');
    setMode('login');
  };

  const onSubmitForgot = async (e) => {
    e.preventDefault();
    setError('');
    setOtpInfo('');
    setLoading(true);
    try {
      const resp = await forgotPassword(email);
      setOtpDigits(Array(OTP_LENGTH).fill(''));
      setResendCountdown(RESEND_COOLDOWN_SECONDS);
      setOtpInfo(
        resp?.otp_expires_in_minutes
          ? `If an account exists for ${email}, we've sent a ${OTP_LENGTH}-digit code. It expires in ${resp.otp_expires_in_minutes} minutes.`
          : `If an account exists for ${email}, we've sent a ${OTP_LENGTH}-digit code.`
      );
      setMode('reset-otp');
    } catch (err) {
      setError(err.message || 'Could not start password reset');
    } finally {
      setLoading(false);
    }
  };

  const onSubmitResetOtp = async (e) => {
    e.preventDefault();
    setError('');
    const code = otpDigits.join('');
    if (code.length !== OTP_LENGTH) {
      setError(`Enter the ${OTP_LENGTH}-digit code from your email.`);
      return;
    }
    setLoading(true);
    try {
      const resp = await verifyResetOtp(email, code);
      const token = resp?.reset_token;
      if (!token) throw new Error('Server did not return a reset token');
      setResetToken(token);
      setOtpInfo('');
      setMode('reset-password');
    } catch (err) {
      setError(err.message || 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  const onResendReset = async () => {
    if (resendCountdown > 0 || loading) return;
    setError('');
    setOtpInfo('');
    setLoading(true);
    try {
      const resp = await forgotPassword(email);
      setResendCountdown(RESEND_COOLDOWN_SECONDS);
      setOtpDigits(Array(OTP_LENGTH).fill(''));
      otpRefs.current[0]?.focus();
      setOtpInfo(
        resp?.otp_expires_in_minutes
          ? `New code sent. It expires in ${resp.otp_expires_in_minutes} minutes.`
          : 'New code sent to your email.'
      );
    } catch (err) {
      setError(err.message || 'Could not resend code');
    } finally {
      setLoading(false);
    }
  };

  const onSubmitResetPassword = async (e) => {
    e.preventDefault();
    setError('');
    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }
    setLoading(true);
    try {
      await resetPassword(resetToken, newPassword);
      setResetToken('');
      setNewPassword('');
      setShowNewPassword(false);
      setPassword('');
      setOtpDigits(Array(OTP_LENGTH).fill(''));
      setResendCountdown(0);
      setLoginInfo('Password updated. Sign in with your new password.');
      setMode('login');
    } catch (err) {
      setError(err.message || 'Could not reset password');
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
              <img
                src={nexveilLogo}
                alt="NEXVEIL Security"
                onError={(e) => {
                  e.target.style.display = 'none';
                  const fb = e.target.closest('.auth-logo-section')?.querySelector('.auth-logo-fallback');
                  if (fb) fb.hidden = false;
                }}
              />
              <span className="auth-logo-fallback" hidden>NEXVEIL</span>
            </div>
          </div>

          <div className="auth-banner">
            <span className="auth-banner-text">{bannerText}</span>
          </div>

          <div className="auth-form-section">
            {error && <div className="auth-error">{error}</div>}
            {mode === 'login' && loginInfo && !error && (
              <div className="auth-info">{loginInfo}</div>
            )}
            {(mode === 'verify' || mode === 'reset-otp') && otpInfo && !error && (
              <div className="auth-info">{otpInfo}</div>
            )}

            {mode === 'forgot' ? (
              <form onSubmit={onSubmitForgot} className="auth-form">
                <p className="auth-hint">
                  Enter the email you signed up with. We'll send a {OTP_LENGTH}-digit code to reset your password.
                </p>
                <input
                  className="auth-input"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter email address"
                  required
                />
                <button className="auth-primary" type="submit" disabled={loading}>
                  {loading ? 'Sending code…' : 'Send reset code'}
                </button>
                <div className="auth-row auth-row-otp">
                  <button
                    type="button"
                    className="auth-link"
                    onClick={onBackToLogin}
                    disabled={loading}
                  >
                    ← Back to sign in
                  </button>
                </div>
              </form>
            ) : mode === 'reset-otp' ? (
              <form onSubmit={onSubmitResetOtp} className="auth-form">
                <div className="auth-otp-row">
                  {otpDigits.map((digit, idx) => (
                    <input
                      key={idx}
                      ref={(el) => { otpRefs.current[idx] = el; }}
                      className="auth-otp-input"
                      type="text"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      maxLength={OTP_LENGTH}
                      value={digit}
                      onChange={(e) => handleOtpChange(idx, e.target.value)}
                      onKeyDown={(e) => handleOtpKeyDown(idx, e)}
                      aria-label={`Digit ${idx + 1}`}
                    />
                  ))}
                </div>
                <button className="auth-primary" type="submit" disabled={loading}>
                  {loading ? 'Verifying…' : 'Verify code'}
                </button>
                <div className="auth-row auth-row-otp">
                  <button
                    type="button"
                    className="auth-link"
                    onClick={onBackToLogin}
                    disabled={loading}
                  >
                    ← Back
                  </button>
                  <button
                    type="button"
                    className="auth-link"
                    onClick={onResendReset}
                    disabled={resendCountdown > 0 || loading}
                  >
                    {resendCountdown > 0
                      ? `Resend in ${resendCountdown}s`
                      : 'Resend code'}
                  </button>
                </div>
              </form>
            ) : mode === 'reset-password' ? (
              <form onSubmit={onSubmitResetPassword} className="auth-form">
                <p className="auth-hint">Choose a new password (at least 8 characters).</p>
                <div className="auth-input-wrap">
                  <input
                    className="auth-input auth-input-pw"
                    type={showNewPassword ? 'text' : 'password'}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="New password"
                    minLength={8}
                    required
                    autoFocus
                  />
                  <button
                    type="button"
                    className="auth-pw-toggle"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                    tabIndex={-1}
                    aria-label={showNewPassword ? 'Hide password' : 'Show password'}
                  >
                    {showNewPassword ? <EyeOffIcon /> : <EyeIcon />}
                  </button>
                </div>
                <button className="auth-primary" type="submit" disabled={loading}>
                  {loading ? 'Updating…' : 'Update password'}
                </button>
                <div className="auth-row auth-row-otp">
                  <button
                    type="button"
                    className="auth-link"
                    onClick={onBackToLogin}
                    disabled={loading}
                  >
                    Cancel
                  </button>
                </div>
              </form>
            ) : mode === 'verify' ? (
              <form onSubmit={onVerifyOtp} className="auth-form">
                <div className="auth-otp-row">
                  {otpDigits.map((digit, idx) => (
                    <input
                      key={idx}
                      ref={(el) => { otpRefs.current[idx] = el; }}
                      className="auth-otp-input"
                      type="text"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      maxLength={OTP_LENGTH}
                      value={digit}
                      onChange={(e) => handleOtpChange(idx, e.target.value)}
                      onKeyDown={(e) => handleOtpKeyDown(idx, e)}
                      aria-label={`Digit ${idx + 1}`}
                    />
                  ))}
                </div>

                <button className="auth-primary" type="submit" disabled={loading}>
                  {loading ? 'Verifying…' : 'Verify & Continue'}
                </button>

                <div className="auth-row auth-row-otp">
                  <button
                    type="button"
                    className="auth-link"
                    onClick={onBackToSignup}
                    disabled={loading}
                  >
                    ← Back
                  </button>
                  <button
                    type="button"
                    className="auth-link"
                    onClick={onResend}
                    disabled={resendCountdown > 0 || loading}
                  >
                    {resendCountdown > 0
                      ? `Resend in ${resendCountdown}s`
                      : 'Resend code'}
                  </button>
                </div>
              </form>
            ) : (
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
                  {mode === 'login' && (
                    <button
                      type="button"
                      className="auth-link"
                      onClick={onForgotClick}
                    >
                      Forgot Password?
                    </button>
                  )}
                </div>

                <button className="auth-primary" type="submit" disabled={loading}>
                  {loading
                    ? (mode === 'signup' ? 'Sending code…' : 'Authenticating…')
                    : (mode === 'signup' ? 'Create Account' : 'Login')}
                </button>
              </form>
            )}
          </div>

          <div className="auth-footer">
            {mode === 'login' && (
              <span>
                New to NEXVEIL?{' '}
                <button className="auth-link" type="button" onClick={() => switchMode('signup')}>
                  Create an Account
                </button>
              </span>
            )}
            {mode === 'signup' && (
              <span>
                Already have an account?{' '}
                <button className="auth-link" type="button" onClick={() => switchMode('login')}>
                  Sign in
                </button>
              </span>
            )}
            {mode === 'verify' && (
              <span>
                Wrong email?{' '}
                <button className="auth-link" type="button" onClick={onBackToSignup}>
                  Change it
                </button>
              </span>
            )}
          </div>

          <div className="auth-copyright">
            &copy; Powered by NEXVEIL. All Rights Reserved, {new Date().getFullYear()}
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
