import React, { useEffect, useMemo, useRef, useState } from 'react';
import './Header.css';

const Header = ({ tenant, username, onLogout }) => {
  const [open, setOpen] = useState(false);
  const [showComingSoon, setShowComingSoon] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const menuRef = useRef(null);

  const initials = useMemo(() => {
    const s = String(username || '').trim();
    if (!s) return 'U';
    const base = s.includes('@') ? s.split('@')[0] : s;
    const parts = base.split(/[^a-zA-Z0-9]+/).filter(Boolean);
    const a = (parts[0] || base || 'U')[0] || 'U';
    const b = (parts[1] || '')[0] || (parts[0] || '')[1] || '';
    return (String(a) + String(b)).toUpperCase();
  }, [username]);

  const displayName = useMemo(() => {
    const s = String(username || '').trim();
    if (!s) return 'User';
    return s.includes('@') ? s.split('@')[0] : s;
  }, [username]);

  useEffect(() => {
    const onDocClick = (e) => {
      if (!open) return;
      if (menuRef.current && !menuRef.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  useEffect(() => {
    if (!open) {
      setShowComingSoon(false);
      setShowProfile(false);
    }
  }, [open]);

  return (
    <div className="header">
      <div className="header-left">
        {tenant ? <div className="header-tenant-label">{tenant}</div> : null}
      </div>

      <div className="header-center">
        <input
          type="text"
          className="header-search"
          placeholder="Q Search..."
        />
      </div>

      <div className="header-right">
        <div className="profile-menu" ref={menuRef}>
          <button
            type="button"
            className="profile-avatar-btn"
            onClick={() => setOpen((v) => !v)}
            aria-haspopup="menu"
            aria-expanded={open}
            title={username || 'Profile'}
          >
            <div className="user-avatar">{initials}</div>
          </button>

          {open && (
            <div className="profile-dropdown" role="menu">
              {/* User info section */}
              <div className="profile-dropdown-header">
                <div className="profile-dropdown-avatar">{initials}</div>
                <div className="profile-dropdown-info">
                  <div className="profile-dropdown-name">{displayName}</div>
                  <div className="profile-dropdown-email">{username || 'User'}</div>
                </div>
              </div>

              {/* Plan badge */}
              <div className="profile-dropdown-plan-section">
                <div className="profile-plan-badge free">Free Plan</div>
              </div>

              {/* Upgrade button */}
              <button
                type="button"
                className="profile-dropdown-upgrade"
                onClick={() => setShowComingSoon((v) => !v)}
              >
                Upgrade to Pro
              </button>

              {showComingSoon && (
                <div className="profile-coming-soon">
                  Coming soon!
                </div>
              )}

              {/* Divider */}
              <div className="profile-dropdown-divider"></div>

              {/* Profile */}
              <button
                type="button"
                className="profile-dropdown-item"
                onClick={() => setShowProfile((v) => !v)}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                  <circle cx="12" cy="7" r="4"></circle>
                </svg>
                Profile
              </button>

              {showProfile && (
                <div className="profile-dropdown-details">
                  <div className="profile-detail-row">
                    <span className="profile-detail-label">Username</span>
                    <span className="profile-detail-value">{displayName}</span>
                  </div>
                  <div className="profile-detail-row">
                    <span className="profile-detail-label">Email</span>
                    <span className="profile-detail-value">{username || '-'}</span>
                  </div>
                  <div className="profile-detail-row">
                    <span className="profile-detail-label">Company</span>
                    <span className="profile-detail-value">{tenant || '-'}</span>
                  </div>
                </div>
              )}

              {/* Account settings */}
              <button
                type="button"
                className="profile-dropdown-item"
                onClick={() => {
                  setOpen(false);
                  const event = new CustomEvent('navigate', { detail: 'settings' });
                  window.dispatchEvent(event);
                }}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="3"></circle>
                  <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"></path>
                </svg>
                Account Settings
              </button>

              {/* Sign out */}
              {onLogout && (
                <button
                  type="button"
                  className="profile-dropdown-logout"
                  onClick={() => {
                    setOpen(false);
                    onLogout();
                  }}
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
                    <polyline points="16 17 21 12 16 7"></polyline>
                    <line x1="21" y1="12" x2="9" y2="12"></line>
                  </svg>
                  Sign Out
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Header;

