import React, { useEffect, useMemo, useRef, useState } from 'react';
import './Header.css';

const Header = ({ tenant, username, onLogout }) => {
  const [open, setOpen] = useState(false);
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
              <div className="profile-dropdown-user">
                <div className="profile-dropdown-email">{username || 'User'}</div>
              </div>
              {onLogout && (
                <button
                  type="button"
                  className="profile-dropdown-logout"
                  onClick={() => {
                    setOpen(false);
                    onLogout();
                  }}
                >
                  Logout
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

