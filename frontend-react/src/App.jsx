import React, { useEffect, useState } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import AssetDiscovery from './pages/AssetDiscovery';
import Scan from './pages/Scan';
import ScanResults from './pages/ScanResults';
import Auth from './pages/Auth';
import Vulnerability from './pages/Vulnerability';
import Reporting from './pages/Reporting';
import Dashboard from './pages/Dashboard';
import DomainDetails from './pages/DomainDetails';
import HelpCenter from './pages/HelpCenter';
import './styles/theme.css';
import './App.css';
import { getStoredToken, setStoredToken, getTokenClaims } from './api/apiClient';

function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [selectedDomainId, setSelectedDomainId] = useState(null);
  const [token, setToken] = useState(() => getStoredToken());
  const [userClaims, setUserClaims] = useState(null);

  useEffect(() => {
    const t = getStoredToken();
    if (!t) {
      setUserClaims(null);
      return;
    }
    // Validate token and load claims for header/org display
    getTokenClaims()
      .then((claims) => setUserClaims(claims))
      .catch(() => {
        setStoredToken(null, true);
        setToken(null);
        setUserClaims(null);
      });
  }, [token]);

  useEffect(() => {
    // Support opening domain details in a NEW BROWSER TAB via query param: ?domain=<uuid>
    if (!token) return;
    try {
      const url = new URL(window.location.href);
      const domainId = url.searchParams.get('domain');
      if (domainId) {
        setSelectedDomainId(domainId);
        setActivePage('domain-details');
      }
    } catch {
      // ignore
    }
  }, [token]);

  const handleBackToScan = () => {
    setSelectedScanId(null);
    setActivePage('scan');
  };

  const handleCloseDomainDetails = () => {
    setSelectedDomainId(null);
    // Clear query param so refresh doesn't reopen domain details
    try {
      const url = new URL(window.location.href);
      url.searchParams.delete('domain');
      window.history.replaceState({}, '', url.toString());
    } catch {
      // ignore
    }
    setActivePage('asset-discovery');
  };

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard':
        return <Dashboard />;
      case 'asset-discovery':
        return <AssetDiscovery />;
      case 'domain-details':
        return <DomainDetails domainId={selectedDomainId} onBack={handleCloseDomainDetails} />;
      case 'scan':
        return <Scan onViewResults={(scanId) => {
          setSelectedScanId(scanId);
          setActivePage('scan-results');
        }} />;
      case 'scan-results':
        return <ScanResults scanId={selectedScanId} onBack={handleBackToScan} />;
      case 'vulnerability':
        return <Vulnerability />;
      case 'reporting':
        return <Reporting />;
      case 'settings':
        return (
          <div style={{ marginLeft: '260px', padding: '2rem' }}>
            <h1>SETTINGS</h1>
            <p>Settings - Coming soon</p>
          </div>
        );
      case 'help':
        return <HelpCenter />;
      default:
        return <Dashboard />;
    }
  };

  if (!token) {
    return (
      <Auth
        onAuthed={(t) => {
          setToken(t);
          setActivePage('dashboard');
        }}
      />
    );
  }

  return (
    <div className="app">
      <Sidebar 
        activePage={activePage} 
        setActivePage={setActivePage}
        tenant={userClaims?.tenant}
        username={userClaims?.sub}
      />
      <Header
        tenant={userClaims?.tenant}
        username={userClaims?.sub}
        onLogout={() => {
          setStoredToken(null, true);
          setToken(null);
          setUserClaims(null);
        }}
      />
      <main className="main-content">{renderPage()}</main>
    </div>
  );
}

export default App;

