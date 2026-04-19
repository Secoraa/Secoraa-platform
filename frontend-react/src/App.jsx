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
import Settings from './pages/Settings';
import './styles/theme.css';
import './App.css';
import { getStoredToken, setStoredToken, getTokenClaims } from './api/apiClient';

const PAGE_FALLBACKS = {
  'scan-results': 'scan',
  'domain-details': 'asset-discovery',
};

function App() {
  const [activePage, setActivePage] = useState(() => {
    const stored = sessionStorage.getItem('activePage') || 'dashboard';
    return PAGE_FALLBACKS[stored] ?? stored;
  });
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [selectedDomainId, setSelectedDomainId] = useState(null);
  const [token, setToken] = useState(() => getStoredToken());
  const [userClaims, setUserClaims] = useState(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true);

  useEffect(() => {
    sessionStorage.setItem('activePage', activePage);
  }, [activePage]);

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
    if (!token) return;
    try {
      const url = new URL(window.location.href);
      const domainParam = url.searchParams.get('domain');
      if (domainParam) {
        setSelectedDomainId(domainParam);
        setActivePage('domain-details');
        return;
      }
    } catch {
      // ignore
    }
    // Do NOT force-redirect to dashboard — sessionStorage already restored the right page
  }, [token]);

  // Listen for navigate events from Header dropdown
  useEffect(() => {
    const handler = (e) => {
      if (e.detail) setActivePage(e.detail);
    };
    window.addEventListener('navigate', handler);
    return () => window.removeEventListener('navigate', handler);
  }, []);

  const [scanInitialTab, setScanInitialTab] = useState(null);

  const handleBackToScan = () => {
    setSelectedScanId(null);
    setScanInitialTab('history');
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
        return <Scan initialTab={scanInitialTab} onViewResults={(scanId) => {
          setSelectedScanId(scanId);
          setScanInitialTab(null);
          setActivePage('scan-results');
        }} />;
      case 'scan-results':
        return <ScanResults scanId={selectedScanId} onBack={handleBackToScan} />;
      case 'vulnerability':
        return <Vulnerability />;
      case 'reporting':
        return <Reporting />;
      case 'settings':
        return <Settings />;
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
    <div className={`app ${sidebarCollapsed ? 'sidebar-collapsed' : 'sidebar-expanded'}`}>
      <Sidebar 
        activePage={activePage} 
        setActivePage={setActivePage}
        tenant={userClaims?.tenant}
        username={userClaims?.sub}
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(prev => !prev)}
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

