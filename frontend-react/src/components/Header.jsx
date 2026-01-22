import React from 'react';
import './Header.css';

const Header = ({ tenant, username, onLogout }) => {
  return (
    <div className="header">
      <div className="header-left">
        <div className="header-logo">
          <img 
            src="/images/secoraa-logo.jpg" 
            alt="Secoraa Logo" 
            className="logo-image"
            onError={(e) => {
              // Fallback to emoji if image not found
              e.target.style.display = 'none';
              if (e.target.nextSibling) {
                e.target.nextSibling.style.display = 'inline';
              }
            }}
          />
          <span className="logo-icon" style={{ display: 'none' }}>🛡️</span>
          <span className="logo-text">SECORAA</span>
        </div>
        <select className="header-org-selector">
          <option>{tenant || 'Demo Org'}</option>
        </select>
      </div>
      
      <div className="header-center">
        <input 
          type="text" 
          className="header-search" 
          placeholder="Q Search..."
        />
      </div>
      
      <div className="header-right">
        <div className="header-user">
          <div className="user-avatar">AA</div>
          <span className="user-name">{username || 'User'}</span>
        </div>
        {onLogout && (
          <button
            type="button"
            className="header-logout-btn"
            onClick={onLogout}
            title="Logout"
          >
            Logout
          </button>
        )}
      </div>
    </div>
  );
};

export default Header;

