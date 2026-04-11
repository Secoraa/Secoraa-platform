import React, { useState } from 'react';
import secoraaLogo from '../assets/secoraa-logo.jpg';
import ASMIcon from './ASMIcon';
import ScanIcon from './ScanIcon';
import BugIcon from './BugIcon';
import ReportIcon from './ReportIcon';
import SettingsIcon from './SettingsIcon';
import HelpIcon from './HelpIcon';
import DashboardIcon from './DashboardIcon';
import AssetDiscoveryIcon from './AssetDiscoveryIcon';
import './Sidebar.css';

const Sidebar = ({ activePage, setActivePage, tenant, username, collapsed, onToggle }) => {
  const [asmExpanded, setAsmExpanded] = useState(true);

  const asmItems = [
    { id: 'dashboard', label: 'Dashboard', SvgComponent: DashboardIcon },
    { id: 'asset-discovery', label: 'Asset Discovery', SvgComponent: AssetDiscoveryIcon },
    { id: 'scan', label: 'Scan', SvgComponent: ScanIcon },
    { id: 'vulnerability', label: 'Vulnerability', SvgComponent: BugIcon },
  ];

  const otherItems = [
    { id: 'reporting', label: 'Reporting', SvgComponent: ReportIcon },
    { id: 'settings', label: 'Settings', SvgComponent: SettingsIcon },
    { id: 'help', label: 'Help Center', SvgComponent: HelpIcon },
  ];

  return (
    <div className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <img
            src={secoraaLogo}
            alt="Secoraa Logo"
            className="logo-image"
            onError={(e) => {
              e.target.style.display = 'none';
              if (e.target.nextSibling) {
                e.target.nextSibling.style.display = 'inline';
              }
            }}
          />
          <span className="logo-icon" style={{ display: 'none' }}>🛡️</span>
          <span className="logo-text">SECORAA</span>
        </div>
        <button
          className="sidebar-toggle"
          onClick={onToggle}
          title={collapsed ? 'Pin sidebar open' : 'Collapse sidebar'}
        >
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            {collapsed ? (
              <polyline points="9 18 15 12 9 6" />
            ) : (
              <polyline points="15 18 9 12 15 6" />
            )}
          </svg>
        </button>
      </div>

      <div className="sidebar-section">
        {/* ASM Section */}
        <div className="asm-section">
          <button
            className="asm-header"
            onClick={() => setAsmExpanded(!asmExpanded)}
            title={asmExpanded ? 'Collapse ASM' : 'Expand ASM'}
          >
            <div className="asm-header-left">
              <span className="asm-icon">
                <ASMIcon size={20} />
              </span>
              <span className="section-label">ASM</span>
            </div>
            <span className={`asm-arrow ${asmExpanded ? 'expanded' : ''}`}>▲</span>
          </button>

          {asmExpanded && (
            <nav className="sidebar-nav asm-nav">
              {asmItems.map((item) => (
                <button
                  key={item.id}
                  className={`nav-item ${activePage === item.id ? 'active' : ''}`}
                  onClick={() => setActivePage(item.id)}
                  title={item.label}
                >
                  <span className="nav-icon">
                    <item.SvgComponent size={20} />
                  </span>
                  <span className="nav-label">{item.label}</span>
                </button>
              ))}
            </nav>
          )}
        </div>

        {/* Other menu items */}
        <nav className="sidebar-nav other-nav">
          {otherItems.map((item) => (
            <button
              key={item.id}
              className={`nav-item ${activePage === item.id ? 'active' : ''}`}
              onClick={() => setActivePage(item.id)}
              title={item.label}
            >
              <span className="nav-icon">
                <item.SvgComponent size={20} />
              </span>
              <span className="nav-label">{item.label}</span>
            </button>
          ))}
        </nav>
      </div>

      <div className="sidebar-footer">
        <div className="sidebar-copyright">
          &copy; {new Date().getFullYear()} Secoraa. All rights reserved.
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
