import React, { useState } from 'react';
import ASMIcon from './ASMIcon';
import ScanIcon from './ScanIcon';
import BugIcon from './BugIcon';
import ReportIcon from './ReportIcon';
import SettingsIcon from './SettingsIcon';
import HelpIcon from './HelpIcon';
import DashboardIcon from './DashboardIcon';
import AssetDiscoveryIcon from './AssetDiscoveryIcon';
import './Sidebar.css';

const Sidebar = ({ activePage, setActivePage, tenant, username }) => {
  const [asmExpanded, setAsmExpanded] = useState(true);

  const asmItems = [
    { id: 'dashboard', label: 'Dashboard', icon: null, isSvg: true, SvgComponent: DashboardIcon },
    { id: 'asset-discovery', label: 'Asset Discovery', icon: null, isSvg: true, SvgComponent: AssetDiscoveryIcon },
    { id: 'scan', label: 'Scan', icon: null, isSvg: true, SvgComponent: ScanIcon },
    { id: 'vulnerability', label: 'Vulnerability', icon: null, isSvg: true, SvgComponent: BugIcon },
  ];

  const otherItems = [
    { id: 'reporting', label: 'Reporting', icon: null, isSvg: true, SvgComponent: ReportIcon },
    { id: 'settings', label: 'Settings', icon: null, isSvg: true, SvgComponent: SettingsIcon },
    { id: 'help', label: 'Help Center', icon: null, isSvg: true, SvgComponent: HelpIcon },
  ];

  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">
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
      </div>

      <div className="sidebar-section">
        {/* ASM Section with expand/collapse */}
        <div className="asm-section">
          <button 
            className="asm-header"
            onClick={() => setAsmExpanded(!asmExpanded)}
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
              {asmItems.map((item) => {
                const SvgComponent = item.SvgComponent;
                return (
                  <button
                    key={item.id}
                    className={`nav-item ${activePage === item.id ? 'active' : ''}`}
                    onClick={() => setActivePage(item.id)}
                  >
                    <span className="nav-icon">
                      {item.isSvg && SvgComponent ? (
                        <SvgComponent size={20} />
                      ) : (
                        item.icon
                      )}
                    </span>
                    <span className="nav-label">{item.label}</span>
                  </button>
                );
              })}
            </nav>
          )}
        </div>

        {/* Other menu items */}
        <nav className="sidebar-nav">
          {otherItems.map((item) => {
            const SvgComponent = item.SvgComponent;
            return (
              <button
                key={item.id}
                className={`nav-item ${activePage === item.id ? 'active' : ''}`}
                onClick={() => setActivePage(item.id)}
              >
                <span className="nav-icon">
                  {item.isSvg && SvgComponent ? (
                    <SvgComponent size={item.id === 'help' ? 22 : 20} />
                  ) : (
                    item.icon
                  )}
                </span>
                <span className="nav-label">{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      <div className="sidebar-footer">
        <div className="user-info">
          <div className="user-org">{tenant || '-'}</div>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
