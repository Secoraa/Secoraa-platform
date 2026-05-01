import React, { useEffect, useState } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import NexVeilLoader from './components/NexVeilLoader';
import AssetDiscovery from './pages/AssetDiscovery';
import Scan from './pages/Scan';
import ScanResults from './pages/ScanResults';
import Auth from './pages/Auth';
import Vulnerability from './pages/Vulnerability';
import VulnerabilityDetails from './pages/VulnerabilityDetails';
import Reporting from './pages/Reporting';
import Dashboard from './pages/Dashboard';
import DomainDetails from './pages/DomainDetails';
import HelpCenter from './pages/HelpCenter';
import Settings from './pages/Settings';
import CreatePentest from './pages/CreatePentest';
import PentestScan from './pages/PentestScan';
import PentestVulnerability from './pages/PentestVulnerability';
import './styles/theme.css';
import './App.css';
import { getStoredToken, setStoredToken, getTokenClaims } from './api/apiClient';

const PAGE_FALLBACKS = {
  'scan-results': 'scan',
  'domain-details': 'asset-discovery',
  'vulnerability-details': 'vulnerability',
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
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    sessionStorage.setItem('activePage', activePage);
  }, [activePage]);

  useEffect(() => {
    const t = getStoredToken();
    if (!t) {
      setUserClaims(null);
      setIsLoading(false);
      return;
    }
    // Validate token and load claims for header/org display
    getTokenClaims()
      .then((claims) => {
        setUserClaims(claims);
        setIsLoading(false);
      })
      .catch(() => {
        setStoredToken(null, true);
        setToken(null);
        setUserClaims(null);
        setIsLoading(false);
      });
  }, [token]);

  useEffect(() => {
    if (!token) return;
    try {
      const url = new URL(window.location.href);
      const domainParam = url.searchParams.get('domain');
      const vulnParam = url.searchParams.get('vuln');
      if (domainParam) {
        setSelectedDomainId(domainParam);
        setActivePage('domain-details');
        return;
      }
      if (vulnParam) {
        setActivePage('vulnerability-details');
        return;
      }
    } catch {
      // ignore
    }
    // Do NOT force-redirect to dashboard — sessionStorage already restored the right page
  }, [token]);

  useEffect(() => {
    if (!token) return;
    try {
      const url = new URL(window.location.href);
      const current = url.searchParams.get('domain');
      const currentVuln = url.searchParams.get('vuln');
      const next = selectedDomainId ? String(selectedDomainId) : '';

      // Show ?domain only on domain-details page; remove it everywhere else.
      if (activePage === 'domain-details' && next) {
        if (current !== next) {
          url.searchParams.set('domain', next);
          window.history.replaceState({}, '', url.toString());
        }
      } else if (current) {
        url.searchParams.delete('domain');
      }

      if (activePage !== 'vulnerability-details' && currentVuln) {
        url.searchParams.delete('vuln');
      }

      if (current || currentVuln) {
        window.history.replaceState({}, '', url.toString());
      }
    } catch {
      // ignore URL sync errors
    }
  }, [token, activePage, selectedDomainId]);

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

  if (isLoading) {
    return <NexVeilLoader />;
  }

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
      case 'vulnerability-details':
        return <VulnerabilityDetails />;
      case 'reporting':
        return <Reporting />;
      case 'settings':
        return <Settings />;
      case 'help':
        return <HelpCenter />;
      case 'pentest-create':
        return <CreatePentest />;
      case 'pentest-scan':
        return <PentestScan />;
      case 'pentest-vulnerability':
        return <PentestVulnerability />;
      default:
        return <Dashboard />;
    }
  };

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

