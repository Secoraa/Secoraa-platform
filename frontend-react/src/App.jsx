import React, { useEffect, useState } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import AssetDiscovery from './pages/AssetDiscovery';
import Scan from './pages/Scan';
import ScanResults from './pages/ScanResults';
import DomainGraph from './pages/DomainGraph';
import Auth from './pages/Auth';
import Vulnerability from './pages/Vulnerability';
import Reporting from './pages/Reporting';
import Dashboard from './pages/Dashboard';
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

  const handleBackToScan = () => {
    setSelectedScanId(null);
    setActivePage('scan');
  };

  const handleOpenDomainGraph = (domainId) => {
    setSelectedDomainId(domainId);
    setActivePage('domain-graph');
  };

  const handleBackToAssetDiscovery = () => {
    setSelectedDomainId(null);
    setActivePage('asset-discovery');
  };

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard':
        return <Dashboard />;
      case 'asset-discovery':
        return <AssetDiscovery onOpenDomain={handleOpenDomainGraph} />;
      case 'domain-graph':
        return <DomainGraph domainId={selectedDomainId} onBack={handleBackToAssetDiscovery} />;
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
        return (
          <div style={{ marginLeft: '260px', padding: '2rem' }}>
            <h1>HELP CENTER</h1>
            <p>Help Center - Coming soon</p>
          </div>
        );
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

