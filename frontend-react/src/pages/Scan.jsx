import React, { useState, useEffect } from 'react';
import {
  getDomains,
  getSubdomains,
  getIPAddresses,
  createScan,
  createScanWithPayload,
  getAllScans,
  pauseScan,
  resumeScan,
  terminateScan,
  runApiTestingScan,
  getUrls,
  createScheduledScan,
  listScheduledScans,
  cancelScheduledScan,
} from '../api/apiClient';
import Notification from '../components/Notification';
import ScanIcon from '../components/ScanIcon';
import ReportIcon from '../components/ReportIcon';
import ScheduleScanIcon from '../components/ScheduleScanIcon';
import './Scan.css';

const Scan = ({ onViewResults }) => {
  const [domains, setDomains] = useState([]);
  const [urlAssets, setUrlAssets] = useState([]);
  const [urlLoading, setUrlLoading] = useState(false);
  const [ipAssets, setIpAssets] = useState([]);
  const [ipLoading, setIpLoading] = useState(false);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('run');
  const [runStep, setRunStep] = useState(1); // 1: scan details, 2: select asset/domain + run
  const [historyPage, setHistoryPage] = useState(1);
  const [historyRowsPerPage, setHistoryRowsPerPage] = useState(10);
  const [scanForm, setScanForm] = useState({
    name: '',
    type: 'dd',
    domain: '',
    assetUrl: '',
    docType: 'POSTMAN', // OPENAPI | POSTMAN | CUSTOM
    subdomainId: '',
    targetIp: '',
  });
  const [scheduleForm, setScheduleForm] = useState({
    name: '',
    type: 'dd',
    scheduledFor: '',
    domain: '',
    assetUrl: '',
    docType: 'POSTMAN',
    subdomainId: '',
    targetIp: '',
  });
  const [scheduledScans, setScheduledScans] = useState([]);
  const [scheduleLoading, setScheduleLoading] = useState(false);
  const [lastScheduledId, setLastScheduledId] = useState(null);
  const [notification, setNotification] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [apiScanResult, setApiScanResult] = useState(null);
  const [postmanFileName, setPostmanFileName] = useState('');
  const [apiEndpoints, setApiEndpoints] = useState([]);
  const [selectedEndpointKeys, setSelectedEndpointKeys] = useState(() => new Set());
  const [allSubdomains, setAllSubdomains] = useState([]);
  const [subdomainLoading, setSubdomainLoading] = useState(false);
  const [subdomainQuery, setSubdomainQuery] = useState('');
  const [subdomainPage, setSubdomainPage] = useState(1);
  const SUBDOMAIN_PAGE_SIZE = 20;

  useEffect(() => {
    if (activeTab === 'history') {
      loadScans();
      setHistoryPage(1);
    } else if (activeTab === 'schedule-history') {
      loadScheduled();
    } else {
      // Reset wizard when entering Run tab
      setRunStep(1);
    }
  }, [activeTab]);

  useEffect(() => {
    // Load domains only when user reaches Step 2
    if (activeTab === 'run' && runStep === 2 && scanForm.type === 'dd') {
      loadDomains();
    }
  }, [activeTab, runStep]);

  useEffect(() => {
    // For Schedule tab: load assets needed for selected scan type
    if (activeTab !== 'schedule') return;
    if (scheduleForm.type === 'dd') loadDomains();
    if (scheduleForm.type === 'api') loadUrlAssets();
    if (scheduleForm.type === 'subdomain') loadSubdomains();
    if (scheduleForm.type === 'network') loadIpAssets();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, scheduleForm.type]);

  useEffect(() => {
    if (activeTab === 'run' && runStep === 2 && scanForm.type === 'api') {
      loadUrlAssets();
    }
  }, [activeTab, runStep, scanForm.type]);

  useEffect(() => {
    if (activeTab === 'run' && runStep === 2 && scanForm.type === 'network') {
      loadIpAssets();
    }
  }, [activeTab, runStep, scanForm.type]);

  const allEndpointsSelected = apiEndpoints.length > 0 && selectedEndpointKeys.size === apiEndpoints.length;

  const loadSubdomains = async () => {
    try {
      setSubdomainLoading(true);
      const data = await getSubdomains();
      setAllSubdomains(Array.isArray(data) ? data : []);
    } catch (err) {
      setAllSubdomains([]);
      setNotification({ message: `Failed to load subdomains: ${err.message}`, type: 'error' });
    } finally {
      setSubdomainLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'run' && runStep === 2 && scanForm.type === 'subdomain') {
      loadSubdomains();
    }
  }, [activeTab, runStep, scanForm.type]);

  const loadScheduled = async () => {
    try {
      setScheduleLoading(true);
      const resp = await listScheduledScans(50, 0);
      setScheduledScans(resp?.data || []);

      // If a schedule we created has triggered, auto-switch to history
      if (lastScheduledId) {
        const row = (resp?.data || []).find((r) => String(r.id) === String(lastScheduledId));
        if (row && row.triggered_scan_id) {
          await loadScans();
          setActiveTab('history');
          setLastScheduledId(null);
          setNotification({ message: `Scheduled scan triggered. Redirected to scan history.`, type: 'success' });
        }
      }
    } catch (err) {
      setScheduledScans([]);
      setNotification({ message: `Failed to load scheduled scans: ${err.message}`, type: 'error' });
    } finally {
      setScheduleLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab !== 'schedule' && activeTab !== 'schedule-history') return undefined;
    loadScheduled();
    const t = setInterval(() => {
      loadScheduled();
    }, 5000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, lastScheduledId]);
  
  const filteredSubdomainData = (() => {
    const q = subdomainQuery.trim().toLowerCase();
    const list = allSubdomains.filter((s) => {
      const name = String(s.subdomain_name || s.name || '').toLowerCase();
      if (!q) return true;
      return name.includes(q);
    });
    const total = list.length;
    const totalPages = Math.max(1, Math.ceil(total / SUBDOMAIN_PAGE_SIZE));
    const page = Math.min(Math.max(1, subdomainPage), totalPages);
    const start = (page - 1) * SUBDOMAIN_PAGE_SIZE;
    const end = start + SUBDOMAIN_PAGE_SIZE;
    return {
      items: list.slice(start, end),
      total,
      totalPages,
      page,
      start,
      end: Math.min(end, total),
    };
  })();

  // Reset pagination when search changes
  useEffect(() => {
    setSubdomainPage(1);
  }, [subdomainQuery]);

  const selectedSubdomain = scanForm.subdomainId
    ? allSubdomains.find((s) => String(s.id) === String(scanForm.subdomainId))
    : null;

  const selectedScheduledSubdomain = scheduleForm.subdomainId
    ? allSubdomains.find((s) => String(s.id) === String(scheduleForm.subdomainId))
    : null;

  const loadDomains = async () => {
    try {
      const data = await getDomains();
      setDomains(Array.isArray(data) ? data : data.data || []);
    } catch (err) {
      console.error('Failed to load domains:', err);
      setDomains([]);
      setNotification({
        message: `Failed to load domains: ${err.message}. If Docker/Postgres is down, start it and refresh.`,
        type: 'error',
      });
    }
  };

  const loadScans = async () => {
    try {
      const data = await getAllScans();
      setScans(data.data || []);
    } catch (err) {
      console.error('Failed to load scans:', err);
    }
  };

  const loadUrlAssets = async () => {
    try {
      setUrlLoading(true);
      const data = await getUrls();
      setUrlAssets(Array.isArray(data) ? data : []);
    } catch (err) {
      setUrlAssets([]);
      setNotification({ message: `Failed to load URLs: ${err.message}`, type: 'error' });
    } finally {
      setUrlLoading(false);
    }
  };

  const loadIpAssets = async () => {
    try {
      setIpLoading(true);
      const data = await getIPAddresses();
      setIpAssets(Array.isArray(data) ? data : []);
    } catch (err) {
      setIpAssets([]);
      setNotification({ message: `Failed to load IP addresses: ${err.message}`, type: 'error' });
    } finally {
      setIpLoading(false);
    }
  };

  const parsePostmanEndpoints = (collection) => {
    const endpoints = [];
    const walk = (items) => {
      (items || []).forEach((item) => {
        if (item && item.request) {
          const req = item.request;
          const url = req.url || {};
          let path = '';

          // Postman url can be:
          // - string: "https://example.com/users"
          // - object: { raw, host, path: [...] }
          if (typeof url === 'string') {
            try {
              const u = new URL(url.replace('{{base_url}}', 'http://placeholder'));
              path = u.pathname || '';
            } catch {
              // best-effort: grab path-ish portion
              const idx = url.indexOf('://');
              const s = idx >= 0 ? url.slice(idx + 3) : url;
              const slash = s.indexOf('/');
              path = slash >= 0 ? s.slice(slash) : '';
            }
          } else if (url && typeof url === 'object') {
            const pathParts = Array.isArray(url.path) ? url.path : [];
            if (pathParts.length) {
              path = '/' + pathParts.join('/');
            } else if (typeof url.raw === 'string') {
              try {
                const raw = url.raw.replace('{{base_url}}', 'http://placeholder');
                const u = new URL(raw);
                path = u.pathname || '';
              } catch {
                // best-effort: trim base and query
                const raw = url.raw;
                const q = raw.indexOf('?');
                const noQuery = q >= 0 ? raw.slice(0, q) : raw;
                const slash = noQuery.indexOf('/');
                path = slash >= 0 ? noQuery.slice(slash) : noQuery;
              }
            }
          }

          if (!path) {
            // If we can't compute path, skip it.
            return;
          }
          if (!path.startsWith('/')) path = `/${path}`;
          endpoints.push({
            name: item.name,
            method: req.method,
            path: path,
          });
        } else if (item && Array.isArray(item.item)) {
          walk(item.item);
        }
      });
    };
    walk(collection?.item || []);
    return endpoints;
  };

  const parseOpenApiEndpoints = (spec) => {
    const endpoints = [];
    const paths = spec?.paths;
    if (!paths || typeof paths !== 'object') return endpoints;
    Object.entries(paths).forEach(([p, methods]) => {
      if (!methods || typeof methods !== 'object') return;
      Object.entries(methods).forEach(([m, op]) => {
        const method = String(m || '').toUpperCase();
        if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(method)) return;
        const opObj = (op && typeof op === 'object') ? op : {};
        endpoints.push({
          name: opObj.operationId || opObj.summary || opObj.description || `${method} ${p}`,
          method,
          path: String(p),
        });
      });
    });
    return endpoints;
  };

  const parseCustomExcelEndpoints = async (file) => {
    const endpoints = [];
    // Use xlsx to parse both .xls and .xlsx
    const XLSX = await import('xlsx');
    const buf = await file.arrayBuffer();
    const wb = XLSX.read(buf, { type: 'array' });
    const sheetName = wb.SheetNames?.[0];
    if (!sheetName) return endpoints;
    const sheet = wb.Sheets[sheetName];
    const rows = XLSX.utils.sheet_to_json(sheet, { defval: '' });

    const norm = (s) => String(s || '').trim().toLowerCase();
    const pick = (row, keys) => {
      for (const k of keys) {
        for (const rk of Object.keys(row)) {
          if (norm(rk) === k) return row[rk];
        }
      }
      return '';
    };

    rows.forEach((row) => {
      const method = String(pick(row, ['method', 'http_method', 'httpmethod'])).trim().toUpperCase();
      const rawPath = String(pick(row, ['path', 'endpoint', 'route', 'url'])).trim();
      const name = String(pick(row, ['name', 'title', 'operation', 'operation_id', 'operationid'])).trim();
      if (!method || !rawPath) return;
      // If rawPath is full URL, keep only pathname (scanner uses asset_url as base)
      let path = rawPath;
      try {
        const u = new URL(rawPath);
        path = u.pathname || rawPath;
      } catch {
        // not a full URL
      }
      if (!path.startsWith('/')) path = `/${path}`;
      endpoints.push({
        name: name || `${method} ${path}`,
        method,
        path,
      });
    });

    return endpoints;
  };

  const endpointKey = (ep) => `${String(ep.method || '').toUpperCase()} ${ep.path}`;

  const handleSpecUpload = async (file) => {
    if (!file) return;
    setApiScanResult(null);
    setPostmanFileName(file.name);
    try {
      let endpoints = [];
      if (scanForm.docType === 'CUSTOM') {
        endpoints = await parseCustomExcelEndpoints(file);
      } else {
        // OPENAPI / POSTMAN: JSON only
        const text = await file.text();
        const obj = JSON.parse(text);

        // Parse based on selected docType, but fall back to auto-detect if mismatch.
        if (scanForm.docType === 'POSTMAN') {
          endpoints = parsePostmanEndpoints(obj);
          if (!endpoints.length && obj?.paths && typeof obj.paths === 'object') {
            endpoints = parseOpenApiEndpoints(obj);
          }
        } else if (scanForm.docType === 'OPENAPI') {
          endpoints = parseOpenApiEndpoints(obj);
          if (!endpoints.length && Array.isArray(obj?.item)) {
            endpoints = parsePostmanEndpoints(obj);
          }
        } else {
          if (Array.isArray(obj?.item)) endpoints = parsePostmanEndpoints(obj);
          else if (obj?.paths && typeof obj.paths === 'object') endpoints = parseOpenApiEndpoints(obj);
        }
      }
      setApiEndpoints(endpoints);
      const all = new Set(endpoints.map(endpointKey));
      setSelectedEndpointKeys(new Set()); // default: none selected
      if (!endpoints.length) {
        setNotification({
          message: 'No endpoints found. If this is a Postman collection, choose Documentation Type = POSTMAN. If it is OpenAPI, choose OPENAPI.',
          type: 'error',
        });
      }
    } catch (err) {
      setApiEndpoints([]);
      setSelectedEndpointKeys(new Set());
      setNotification({ message: 'Invalid/unsupported file. For OPENAPI/POSTMAN upload JSON. For CUSTOM upload XLS/XLSX.', type: 'error' });
    }
  };

  const handleRunScan = async (e) => {
    e.preventDefault();
    setApiScanResult(null);
    if (!scanForm.name) {
      setNotification({ message: 'Please enter a scan name', type: 'error' });
      return;
    }

    try {
      setLoading(true);
      if (scanForm.type === 'dd') {
        if (!scanForm.domain) {
          setNotification({ message: 'Please select a domain', type: 'error' });
          return;
        }
        const result = await createScan(scanForm.name, scanForm.type, scanForm.domain);
        setNotification({
          message: `Scan "${result.scan_name}" started successfully! Check scan history for progress.`,
          type: 'success',
        });
        setScanForm({ name: '', type: 'dd', domain: '', assetUrl: '', docType: 'POSTMAN', subdomainId: '', targetIp: '' });
        // Load scans and redirect to history tab immediately
        await loadScans();
        setActiveTab('history');

        // Poll for status updates every 2 seconds
        const pollInterval = setInterval(async () => {
          const updatedScansData = await getAllScans();
          const updatedScans = updatedScansData.data || [];
          await loadScans(); // Update state

          // Check if scan is completed or failed, then stop polling
          const currentScan = updatedScans.find(s => s.scan_id === result.scan_id);
          if (currentScan && (currentScan.status === 'COMPLETED' || currentScan.status === 'FAILED')) {
            clearInterval(pollInterval);
            if (currentScan.status === 'COMPLETED') {
              setNotification({
                message: `Scan "${result.scan_name}" completed successfully!`,
                type: 'success',
              });
            } else {
              setNotification({
                message: `Scan "${result.scan_name}" failed. Please check the logs.`,
                type: 'error',
              });
            }
          }
        }, 2000);

        // Stop polling after 5 minutes
        setTimeout(() => clearInterval(pollInterval), 300000);
      } else if (scanForm.type === 'api') {
        if (!scanForm.assetUrl) {
          setNotification({ message: 'Please select Asset Base URL', type: 'error' });
          return;
        }
        if (!apiEndpoints.length) {
          setNotification({ message: 'Please upload documentation file first', type: 'error' });
          return;
        }
        const selected = apiEndpoints.filter((ep) => selectedEndpointKeys.has(endpointKey(ep)));
        if (!selected.length) {
          setNotification({ message: 'Please select at least one endpoint', type: 'error' });
          return;
        }
        const result = await runApiTestingScan(scanForm.name, scanForm.assetUrl, selected);
        setApiScanResult(result);
        setNotification({ message: `API Scan "${scanForm.name}" completed.`, type: 'success' });
        await loadScans();
        setActiveTab('history');
      } else if (scanForm.type === 'network') {
        if (!scanForm.targetIp) {
          setNotification({ message: 'Please select a target IP', type: 'error' });
          return;
        }
        const result = await createScanWithPayload(scanForm.name, 'network', {
          target_ip: scanForm.targetIp,
        });

        setNotification({
          message: `Network scan "${result.scan_name}" started successfully! Check scan history for progress.`,
          type: 'success',
        });

        setScanForm({ name: '', type: 'dd', domain: '', assetUrl: '', docType: 'POSTMAN', subdomainId: '', targetIp: '' });
        await loadScans();
        setActiveTab('history');

        const pollInterval = setInterval(async () => {
          const updatedScansData = await getAllScans();
          const updatedScans = updatedScansData.data || [];
          await loadScans();
          const currentScan = updatedScans.find(s => s.scan_id === result.scan_id);
          if (currentScan && (currentScan.status === 'COMPLETED' || currentScan.status === 'FAILED')) {
            clearInterval(pollInterval);
            setNotification({
              message: currentScan.status === 'COMPLETED'
                ? `Scan "${result.scan_name}" completed successfully!`
                : `Scan "${result.scan_name}" failed. Please check the logs.`,
              type: currentScan.status === 'COMPLETED' ? 'success' : 'error',
            });
          }
        }, 2000);

        setTimeout(() => clearInterval(pollInterval), 300000);
      } else if (scanForm.type === 'subdomain') {
        if (!selectedSubdomain) {
          setNotification({ message: 'Please select a subdomain', type: 'error' });
          return;
        }
        const subName = String(selectedSubdomain.subdomain_name || selectedSubdomain.name || '').trim();
        const domainName = String(selectedSubdomain.domain_name || '').trim();
        const derivedDomain = domainName || subName.split('.').slice(-2).join('.');

        const result = await createScanWithPayload(scanForm.name, 'subdomain', {
          domain: derivedDomain,
          subdomains: [subName],
        });

        setNotification({
          message: `Subdomain scan "${result.scan_name}" started successfully! Check scan history for progress.`,
          type: 'success',
        });

        setScanForm({ name: '', type: 'dd', domain: '', assetUrl: '', docType: 'POSTMAN', subdomainId: '', targetIp: '' });
        await loadScans();
        setActiveTab('history');

        // Poll for status updates every 2 seconds (same as DD)
        const pollInterval = setInterval(async () => {
          const updatedScansData = await getAllScans();
          const updatedScans = updatedScansData.data || [];
          await loadScans();

          const currentScan = updatedScans.find(s => s.scan_id === result.scan_id);
          if (currentScan && (currentScan.status === 'COMPLETED' || currentScan.status === 'FAILED')) {
            clearInterval(pollInterval);
            setNotification({
              message: currentScan.status === 'COMPLETED'
                ? `Scan "${result.scan_name}" completed successfully!`
                : `Scan "${result.scan_name}" failed. Please check the logs.`,
              type: currentScan.status === 'COMPLETED' ? 'success' : 'error',
            });
          }
        }, 2000);

        setTimeout(() => clearInterval(pollInterval), 300000);
      }
    } catch (err) {
      setNotification({
        message: `Failed to start scan: ${err.message}`,
        type: 'error',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleScheduleScan = async (e) => {
    e.preventDefault();
    if (!scheduleForm.name) {
      setNotification({ message: 'Please enter a scan name', type: 'error' });
      return;
    }
    if (!scheduleForm.scheduledFor) {
      setNotification({ message: 'Please select schedule time', type: 'error' });
      return;
    }

    try {
      setLoading(true);
      const scheduledIso = new Date(scheduleForm.scheduledFor).toISOString();
      let payload = {};

      if (scheduleForm.type === 'dd') {
        if (!scheduleForm.domain) {
          setNotification({ message: 'Please select a domain', type: 'error' });
          return;
        }
        payload = { domain: scheduleForm.domain };
      } else if (scheduleForm.type === 'subdomain') {
        if (!selectedScheduledSubdomain) {
          setNotification({ message: 'Please select a subdomain', type: 'error' });
          return;
        }
        const subName = String(selectedScheduledSubdomain.subdomain_name || selectedScheduledSubdomain.name || '').trim();
        const derivedDomain = subName.split('.').slice(-2).join('.');
        payload = { domain: derivedDomain, subdomains: [subName] };
      } else if (scheduleForm.type === 'network') {
        if (!scheduleForm.targetIp) {
          setNotification({ message: 'Please select a target IP', type: 'error' });
          return;
        }
        payload = { target_ip: scheduleForm.targetIp };
      } else if (scheduleForm.type === 'api') {
        if (!scheduleForm.assetUrl) {
          setNotification({ message: 'Please select Asset Base URL', type: 'error' });
          return;
        }
        if (!apiEndpoints.length) {
          setNotification({ message: 'Please upload documentation file first', type: 'error' });
          return;
        }
        const selected = apiEndpoints.filter((ep) => selectedEndpointKeys.has(endpointKey(ep)));
        if (!selected.length) {
          setNotification({ message: 'Please select at least one endpoint', type: 'error' });
          return;
        }
        payload = { asset_url: scheduleForm.assetUrl, endpoints: selected };
      }

      const resp = await createScheduledScan({
        scanName: scheduleForm.name,
        scanType: scheduleForm.type,
        scheduledFor: scheduledIso,
        payload,
      });

      setLastScheduledId(resp?.id);
      setNotification({ message: `Scan scheduled successfully! It will run at the selected time.`, type: 'success' });
      setScheduleForm({ name: '', type: 'dd', scheduledFor: '', domain: '', assetUrl: '', docType: 'POSTMAN', subdomainId: '', targetIp: '' });
      await loadScheduled();
      // After scheduling, go to Schedule Scan History tab
      setActiveTab('schedule-history');
    } catch (err) {
      setNotification({ message: `Failed to schedule scan: ${err.message}`, type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleNextStep = () => {
    if (!scanForm.name) {
      setNotification({
        message: 'Please enter a scan name',
        type: 'error',
      });
      return;
    }
    setRunStep(2);
  };

  const handleBackStep = () => {
    setRunStep(1);
  };

  const handleViewResults = (scanId) => {
    if (onViewResults) {
      onViewResults(scanId);
    }
  };

  const handlePauseScan = async (scanId) => {
    try {
      await pauseScan(scanId);
      setNotification({
        message: 'Scan paused successfully',
        type: 'success',
      });
      await loadScans();
    } catch (err) {
      setNotification({
        message: `Failed to pause scan: ${err.message}`,
        type: 'error',
      });
    }
  };

  const handleResumeScan = async (scanId) => {
    try {
      await resumeScan(scanId);
      setNotification({
        message: 'Scan resumed successfully',
        type: 'success',
      });
      await loadScans();
    } catch (err) {
      setNotification({
        message: `Failed to resume scan: ${err.message}`,
        type: 'error',
      });
    }
  };

  const handleTerminateScan = async (scanId) => {
    if (!window.confirm('Are you sure you want to terminate this scan? This action cannot be undone.')) {
      return;
    }
    try {
      await terminateScan(scanId);
      setNotification({
        message: 'Scan terminated successfully',
        type: 'success',
      });
      await loadScans();
    } catch (err) {
      setNotification({
        message: `Failed to terminate scan: ${err.message}`,
        type: 'error',
      });
    }
  };

  return (
    <div className="scan-page">
      {notification && (
        <Notification
          message={notification.message}
          type={notification.type}
          onClose={() => setNotification(null)}
          duration={5000}
        />
      )}
      <h1 className="page-title">SCAN</h1>

      <div className="scan-tabs">
        <button
          className={`scan-tab ${activeTab === 'run' ? 'active' : ''}`}
          onClick={() => setActiveTab('run')}
        >
          Run Scan
        </button>
        <button
          className={`scan-tab ${activeTab === 'schedule' ? 'active' : ''}`}
          onClick={() => setActiveTab('schedule')}
        >
          Schedule Scan
        </button>
        <button
          className={`scan-tab ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => setActiveTab('history')}
        >
          Scan History
        </button>
        <button
          className={`scan-tab ${activeTab === 'schedule-history' ? 'active' : ''}`}
          onClick={() => setActiveTab('schedule-history')}
        >
          Schedule Scan History
        </button>
      </div>

      {activeTab === 'run' && (
        <div className="run-scan-section">
          <h2>
            <span className="scan-icon-header">
              <ScanIcon size={24} />
            </span>
            Run New Scan
          </h2>
          <form
            onSubmit={(e) => {
              if (runStep === 2) return handleRunScan(e);
              e.preventDefault();
              return undefined;
            }}
            className="scan-form"
          >
            {runStep === 1 && (
              <>
                <div className="form-row">
                  <div className="form-group">
                    <label>Scan Name</label>
                    <input
                      type="text"
                      value={scanForm.name}
                      onChange={(e) =>
                        setScanForm({ ...scanForm, name: e.target.value })
                      }
                      placeholder="Scan Name"
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label>Scan Type</label>
                    <select
                      value={scanForm.type}
                      onChange={(e) =>
                        setScanForm({
                          ...scanForm,
                          type: e.target.value,
                          // reset step-2 fields when changing type
                          domain: '',
                          assetUrl: '',
                          subdomainId: '',
                          targetIp: '',
                        })
                      }
                    >
                      <option value="dd">Domain Discovery</option>
                      <option value="api">API Testing</option>
                      <option value="subdomain">Subdomain Scan</option>
                      <option value="network">Network Scan</option>
                    </select>
                  </div>
                </div>

                <div className="wizard-actions wizard-actions-right">
                  <button
                    type="button"
                    className="btn-primary"
                    onClick={handleNextStep}
                  >
                    Next →
                  </button>
                </div>
              </>
            )}

            {runStep === 2 && (
              <>
                {scanForm.type === 'dd' && (
                  <div className="form-group">
                    <label>Target Domain</label>
                    <select
                      value={scanForm.domain}
                      onChange={(e) =>
                        setScanForm({ ...scanForm, domain: e.target.value })
                      }
                      required
                    >
                      <option value="">Select a domain</option>
                      {domains.map((domain) => (
                        <option key={domain.id} value={domain.domain_name}>
                          {domain.domain_name}
                        </option>
                      ))}
                    </select>
                  </div>
                )}

                {scanForm.type === 'subdomain' && (
                  <>
                    <div className="form-group">
                      <label>Subdomain</label>
                      <input
                        type="text"
                        className="scan-search-input"
                        placeholder={subdomainLoading ? 'Loading subdomains...' : 'Search and select subdomain'}
                        value={subdomainQuery}
                        onChange={(e) => {
                          setSubdomainQuery(e.target.value);
                          // clear previous selection if user edits text
                          setScanForm({ ...scanForm, subdomainId: '' });
                        }}
                        disabled={subdomainLoading}
                      />
                      <div className="helper-text">
                        Showing 20 results per page. Type to search, then click a subdomain to select.
                      </div>

                      <div className="api-endpoints" style={{ marginTop: 10 }}>
                        <div className="api-endpoints-header">
                          <div>
                            Results ({filteredSubdomainData.start + 1}-{filteredSubdomainData.end} of {filteredSubdomainData.total})
                          </div>
                          <div className="api-endpoints-actions">
                            <button
                              type="button"
                              className="btn-secondary btn-small"
                              onClick={() => setSubdomainPage((p) => Math.max(1, p - 1))}
                              disabled={subdomainLoading || filteredSubdomainData.page <= 1}
                            >
                              Prev
                            </button>
                            <button
                              type="button"
                              className="btn-secondary btn-small"
                              onClick={() => setSubdomainPage((p) => Math.min(filteredSubdomainData.totalPages, p + 1))}
                              disabled={subdomainLoading || filteredSubdomainData.page >= filteredSubdomainData.totalPages}
                            >
                              Next
                            </button>
                          </div>
                        </div>
                        <div className="api-endpoints-list">
                          {filteredSubdomainData.items.length === 0 ? (
                            <div className="helper-text" style={{ padding: '8px 12px' }}>
                              {subdomainLoading ? 'Loading…' : 'No matches.'}
                            </div>
                          ) : (
                            filteredSubdomainData.items.map((s) => {
                              const id = String(s.id);
                              const name = String(s.subdomain_name || s.name || '');
                              const isSelected = String(scanForm.subdomainId) === id;
                              return (
                                <label
                                  key={id}
                                  className={`subdomain-option-row ${isSelected ? 'selected' : ''}`}
                                >
                                  <input
                                    className="subdomain-option-checkbox"
                                    type="checkbox"
                                    checked={isSelected}
                                    onChange={(e) => {
                                      const nextId = e.target.checked ? id : '';
                                      setScanForm({ ...scanForm, subdomainId: nextId });
                                      setSubdomainQuery(e.target.checked ? name : '');
                                    }}
                                  />
                                  <span className="subdomain-option-name">{name}</span>
                                  <span className="subdomain-option-domain">{s.domain_name || ''}</span>
                                </label>
                              );
                            })
                          )}
                        </div>
                      </div>
                    </div>
                  </>
                )}

                {scanForm.type === 'network' && (
                  <div className="form-group">
                    <label>Target IP</label>
                    {ipAssets.length > 0 ? (
                      <select
                        value={scanForm.targetIp}
                        onChange={(e) => setScanForm({ ...scanForm, targetIp: e.target.value })}
                        required
                        disabled={ipLoading}
                      >
                        <option value="">{ipLoading ? 'Loading IPs...' : 'Select an IP'}</option>
                        {ipAssets.map((ip) => (
                          <option key={ip.id || ip.ipaddress_name} value={ip.ipaddress_name}>
                            {ip.ipaddress_name}{ip.domain_name ? ` (${ip.domain_name})` : ''}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <input
                        type="text"
                        placeholder="e.g. 8.8.8.8"
                        value={scanForm.targetIp}
                        onChange={(e) => setScanForm({ ...scanForm, targetIp: e.target.value })}
                        required
                      />
                    )}
                  </div>
                )}

                {scanForm.type === 'api' && (
                  <>
                    <div className="form-group">
                      <label>Asset Base URL</label>
                      <select
                        value={scanForm.assetUrl}
                        onChange={(e) => setScanForm({ ...scanForm, assetUrl: e.target.value })}
                        required
                        disabled={urlLoading}
                      >
                        <option value="">{urlLoading ? 'Loading URLs...' : 'Select a URL'}</option>
                        {urlAssets.map((u) => (
                          <option key={u.id || u.url_name} value={u.url_name}>
                            {u.url_name}{u.domain_name ? ` (${u.domain_name})` : ''}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div className="form-group">
                      <label>Documentation Type</label>
                      <select
                        value={scanForm.docType}
                        onChange={(e) => {
                          const nextType = e.target.value;
                          setScanForm({ ...scanForm, docType: nextType });
                          // reset file-derived state
                          setPostmanFileName('');
                          setApiEndpoints([]);
                          setSelectedEndpointKeys(new Set());
                        }}
                      >
                        <option value="OPENAPI">OPENAPI</option>
                        <option value="POSTMAN">POSTMAN</option>
                        <option value="CUSTOM">CUSTOM</option>
                      </select>
                    </div>

                    <div className="form-group">
                      <label>
                        {scanForm.docType === 'CUSTOM'
                          ? 'Custom Documentation (Excel)'
                          : 'Documentation File (JSON)'}
                      </label>
                      <input
                        type="file"
                        accept={
                          scanForm.docType === 'CUSTOM'
                            ? '.xls,.xlsx,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                            : '.json,application/json'
                        }
                        onChange={(e) => handleSpecUpload(e.target.files?.[0])}
                      />
                      {postmanFileName && (
                        <div className="helper-text">Uploaded: {postmanFileName}</div>
                      )}
                      <div className="helper-text">
                        {scanForm.docType === 'CUSTOM'
                          ? 'Tip: Upload an .xls/.xlsx with columns like method + path (or url).'
                          : 'Tip: Upload a JSON file for the selected documentation type.'}
                      </div>
                    </div>

                    {apiEndpoints.length > 0 && (
                      <div className="api-endpoints">
                        <div className="api-endpoints-header">
                          <div>
                            Endpoints ({apiEndpoints.length})
                            <span className="scan-count" style={{ marginLeft: 10 }}>
                              Selected: {selectedEndpointKeys.size}
                            </span>
                          </div>
                          <div className="api-endpoints-actions">
                            <button
                              type="button"
                              className="btn-secondary btn-small"
                              onClick={() => {
                                if (allEndpointsSelected) {
                                  setSelectedEndpointKeys(new Set());
                                } else {
                                  setSelectedEndpointKeys(new Set(apiEndpoints.map(endpointKey)));
                                }
                              }}
                            >
                              {allEndpointsSelected ? 'Unselect all' : 'Select all'}
                            </button>
                          </div>
                        </div>

                        <div className="api-endpoints-list">
                          {apiEndpoints.map((ep) => {
                            const key = endpointKey(ep);
                            const checked = selectedEndpointKeys.has(key);
                            return (
                              <label key={key} className="api-endpoint-row">
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  onChange={(e) => {
                                    const next = new Set(selectedEndpointKeys);
                                    if (e.target.checked) next.add(key);
                                    else next.delete(key);
                                    setSelectedEndpointKeys(next);
                                  }}
                                />
                                <span className={`api-method api-method-${String(ep.method || '').toLowerCase()}`}>
                                  {String(ep.method || '').toUpperCase()}
                                </span>
                                <span className="api-path">{ep.path}</span>
                                <span className="api-name">{ep.name || ''}</span>
                              </label>
                            );
                          })}
                        </div>
                      </div>
                    )}
                  </>
                )}

                <div className="wizard-actions wizard-actions-between">
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={handleBackStep}
                    disabled={loading}
                  >
                    ← Back
                  </button>

                  <button
                    type="submit"
                    className="btn-primary"
                    disabled={loading}
                  >
                    {loading ? (
                      (scanForm.type === 'api' ? 'Running API Scan...' : 'Running Scan... This may take a few minutes')
                    ) : (
                      <>
                        <ScanIcon size={18} />
                        <span>Run Scan</span>
                      </>
                    )}
                  </button>
                </div>

                {scanForm.type === 'api' && apiScanResult && (
                  <div className="api-scan-result">
                    <div className="api-scan-result-header">
                      API Scan Result
                      <button
                        type="button"
                        className="btn-secondary btn-small"
                        onClick={() => {
                          try {
                            navigator.clipboard.writeText(JSON.stringify(apiScanResult, null, 2));
                            setNotification({ message: 'Copied result to clipboard', type: 'success' });
                          } catch {
                            setNotification({ message: 'Copy failed', type: 'error' });
                          }
                        }}
                      >
                        Copy JSON
                      </button>
                    </div>
                    <pre className="api-scan-result-pre">{JSON.stringify(apiScanResult, null, 2)}</pre>
                  </div>
                )}

                {/* Subdomain scan runs through Scan History (DD-style), so no inline result here */}
              </>
            )}
          </form>
        </div>
      )}

      {activeTab === 'schedule' && (
        <div className="run-scan-section">
          <h2>
            <span className="scan-icon-header">
              <ScheduleScanIcon size={24} />
            </span>
            Schedule Scan
          </h2>

          <form onSubmit={handleScheduleScan} className="scan-form">
            <div className="form-row">
              <div className="form-group">
                <label>Scan Name</label>
                <input
                  type="text"
                  value={scheduleForm.name}
                  onChange={(e) => setScheduleForm({ ...scheduleForm, name: e.target.value })}
                  placeholder="Scheduled Scan Name"
                  required
                />
              </div>
              <div className="form-group">
                <label>Scan Type</label>
                <select
                  value={scheduleForm.type}
                  onChange={(e) =>
                    setScheduleForm({
                      ...scheduleForm,
                      type: e.target.value,
                      domain: '',
                      subdomainId: '',
                      targetIp: '',
                    })
                  }
                >
                  <option value="dd">Domain Discovery (DD)</option>
                  <option value="subdomain">Subdomain Scan</option>
                  <option value="network">Network Scan</option>
                  <option value="api" disabled>API Scan (coming soon)</option>
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Schedule Time</label>
                <input
                  type="datetime-local"
                  value={scheduleForm.scheduledFor}
                  onChange={(e) => setScheduleForm({ ...scheduleForm, scheduledFor: e.target.value })}
                  required
                />
                <div className="helper-text">Uses your local time; it will be stored and executed in UTC on the backend.</div>
              </div>
              <div className="form-group">
                <label> </label>
                <div />
              </div>
            </div>

            {scheduleForm.type === 'dd' && (
              <div className="form-group">
                <label>Select Domain</label>
                <select
                  value={scheduleForm.domain}
                  onChange={(e) => setScheduleForm({ ...scheduleForm, domain: e.target.value })}
                  required
                >
                  <option value="">Select Domain</option>
                  {domains.map((d) => (
                    <option key={d.id} value={d.domain_name}>
                      {d.domain_name}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {scheduleForm.type === 'subdomain' && (
              <div className="form-group">
                <label>Select Subdomain</label>
                <input
                  type="text"
                  className="scan-search-input"
                  placeholder="Search subdomain..."
                  value={subdomainQuery}
                  onChange={(e) => setSubdomainQuery(e.target.value)}
                />

                {subdomainLoading ? (
                  <div className="loading">Loading subdomains...</div>
                ) : (
                  <div className="api-endpoints">
                    <div className="api-endpoints-header">
                      <span>Subdomains</span>
                      <span className="scan-count">{filteredSubdomainData.total}</span>
                    </div>
                    <div className="api-endpoints-list">
                      {filteredSubdomainData.items.map((s) => {
                        const id = String(s.id);
                        const name = String(s.subdomain_name || s.name || '');
                        const checked = String(scheduleForm.subdomainId) === id;
                        return (
                          <label
                            key={id}
                            className={`subdomain-option-row ${checked ? 'selected' : ''}`}
                          >
                            <input
                              className="subdomain-option-checkbox"
                              type="checkbox"
                              checked={checked}
                              onChange={(e) =>
                                setScheduleForm({ ...scheduleForm, subdomainId: e.target.checked ? id : '' })
                              }
                            />
                            <div className="subdomain-option-name">{name}</div>
                            <div className="subdomain-option-domain"> </div>
                          </label>
                        );
                      })}
                      {filteredSubdomainData.items.length === 0 && (
                        <div style={{ padding: '12px', color: 'var(--text-secondary)' }}>No subdomains found</div>
                      )}
                    </div>
                    <div className="scan-pagination">
                      <div className="scan-pagination-left">
                        <span>
                          {filteredSubdomainData.start + 1}-{filteredSubdomainData.end} of {filteredSubdomainData.total}
                        </span>
                      </div>
                      <div className="scan-pagination-right">
                        <div className="scan-pagination-arrows">
                          <button
                            type="button"
                            className="scan-pagination-btn"
                            onClick={() => setSubdomainPage((p) => Math.max(1, p - 1))}
                            disabled={filteredSubdomainData.page === 1}
                          >
                            ←
                          </button>
                          <button
                            type="button"
                            className="scan-pagination-btn"
                            onClick={() => setSubdomainPage((p) => Math.min(filteredSubdomainData.totalPages, p + 1))}
                            disabled={filteredSubdomainData.page === filteredSubdomainData.totalPages}
                          >
                            →
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {scheduleForm.type === 'network' && (
              <div className="form-group">
                <label>Target IP</label>
                {ipAssets.length > 0 ? (
                  <select
                    value={scheduleForm.targetIp}
                    onChange={(e) => setScheduleForm({ ...scheduleForm, targetIp: e.target.value })}
                    required
                    disabled={ipLoading}
                  >
                    <option value="">{ipLoading ? 'Loading IPs...' : 'Select an IP'}</option>
                    {ipAssets.map((ip) => (
                      <option key={ip.id || ip.ipaddress_name} value={ip.ipaddress_name}>
                        {ip.ipaddress_name}{ip.domain_name ? ` (${ip.domain_name})` : ''}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    placeholder="e.g. 8.8.8.8"
                    value={scheduleForm.targetIp}
                    onChange={(e) => setScheduleForm({ ...scheduleForm, targetIp: e.target.value })}
                    required
                  />
                )}
              </div>
            )}

            <div className="wizard-actions wizard-actions-right">
              <button type="submit" className="btn-primary" disabled={loading}>
                Schedule Scan
              </button>
            </div>
          </form>
        </div>
      )}

      {activeTab === 'history' && (
        <div className="scan-history-section">
          <h2>
            <span className="scan-icon-header">
              <ReportIcon size={24} />
            </span>
            Scan History
          </h2>
          
          {/* Search Bar */}
          <div className="scan-search-container">
            <input
              type="text"
              className="scan-search-input"
              placeholder="Q Search by scan name, type, or status..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          {/* Filter scans based on search query */}
          {(() => {
                    const filteredScans = scans.filter((scan) => {
              if (!searchQuery.trim()) return true;
              const query = searchQuery.toLowerCase();
              return (
                scan.scan_name?.toLowerCase().includes(query) ||
                scan.scan_type?.toLowerCase().includes(query) ||
                        scan.status?.toLowerCase().includes(query) ||
                        scan.asset_name?.toLowerCase().includes(query)
              );
            });

            const totalPages = Math.max(1, Math.ceil(filteredScans.length / historyRowsPerPage));
            const safePage = Math.min(historyPage, totalPages);
            const startIndex = (safePage - 1) * historyRowsPerPage;
            const endIndex = startIndex + historyRowsPerPage;
            const paginatedScans = filteredScans.slice(startIndex, endIndex);

            return filteredScans.length === 0 ? (
              <div className="empty-state">
                {scans.length === 0 ? 'No scans found' : 'No scans match your search'}
              </div>
            ) : (
              <div className="scans-table">
                <table>
                  <thead>
                    <tr>
                      <th>Scan Name</th>
                      <th>Scan Type</th>
                      <th>Asset</th>
                      <th>Status</th>
                      <th>Created At</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedScans.map((scan) => (
                    <tr key={scan.scan_id}>
                      <td>{scan.scan_name}</td>
                      <td>{scan.scan_type.toUpperCase()}</td>
                      <td>{scan.asset_name || '-'}</td>
                      <td>
                        <span
                          className={`status-badge ${
                            scan.status === 'COMPLETED' 
                              ? 'success' 
                              : scan.status === 'FAILED'
                              ? 'error'
                              : scan.status === 'TERMINATED'
                              ? 'error'
                              : scan.status === 'PAUSED'
                              ? 'pending'
                              : scan.status === 'IN_PROGRESS'
                              ? 'pending'
                              : 'pending'
                          }`}
                        >
                          {scan.status === 'IN_PROGRESS' ? 'IN PROGRESS' : scan.status}
                        </span>
                      </td>
                      <td>
                        {new Date(scan.created_at).toLocaleString()}
                      </td>
                      <td>
                        <div className="scan-actions">
                          {scan.status === 'IN_PROGRESS' && (
                            <>
                              <button
                                className="btn-small btn-pause"
                                onClick={() => handlePauseScan(scan.scan_id)}
                                title="Pause scan"
                              >
                                ⏸ Pause
                              </button>
                              <button
                                className="btn-small btn-terminate"
                                onClick={() => handleTerminateScan(scan.scan_id)}
                                title="Terminate scan"
                              >
                                ⏹ Terminate
                              </button>
                            </>
                          )}
                          {scan.status === 'PAUSED' && (
                            <>
                              <button
                                className="btn-small btn-resume"
                                onClick={() => handleResumeScan(scan.scan_id)}
                                title="Resume scan"
                              >
                                ▶ Resume
                              </button>
                              <button
                                className="btn-small btn-terminate"
                                onClick={() => handleTerminateScan(scan.scan_id)}
                                title="Terminate scan"
                              >
                                ⏹ Terminate
                              </button>
                            </>
                          )}
                          {(scan.status === 'COMPLETED' || scan.status === 'FAILED' || scan.status === 'TERMINATED') && (
                            <button
                              className="btn-small"
                              onClick={() => handleViewResults(scan.scan_id)}
                            >
                              View Results
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                    ))}
                  </tbody>
                </table>

                <div className="scan-pagination">
                  <div className="scan-pagination-left">
                    <span>Rows per page:</span>
                    <select
                      className="scan-pagination-select"
                      value={historyRowsPerPage}
                      onChange={(e) => {
                        setHistoryRowsPerPage(Number(e.target.value));
                        setHistoryPage(1);
                      }}
                    >
                      <option value={5}>5</option>
                      <option value={10}>10</option>
                      <option value={25}>25</option>
                      <option value={50}>50</option>
                    </select>
                  </div>

                  <div className="scan-pagination-right">
                    <span>
                      {filteredScans.length === 0 ? 0 : startIndex + 1}-{Math.min(endIndex, filteredScans.length)} of {filteredScans.length}
                    </span>
                    <div className="scan-pagination-arrows">
                      <button
                        className="scan-pagination-btn"
                        onClick={() => setHistoryPage((p) => Math.max(1, p - 1))}
                        disabled={safePage === 1}
                      >
                        ←
                      </button>
                      <button
                        className="scan-pagination-btn"
                        onClick={() => setHistoryPage((p) => Math.min(totalPages, p + 1))}
                        disabled={safePage === totalPages}
                      >
                        →
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {activeTab === 'schedule-history' && (
        <div className="scan-history-section">
          <h2>
            <span className="scan-icon-header">
              <ScheduleScanIcon size={24} />
            </span>
            Schedule Scan History
          </h2>

          <div className="schedule-history-header">
            <div />
            <button
              type="button"
              className="btn-secondary btn-small"
              onClick={loadScheduled}
              disabled={scheduleLoading}
            >
              {scheduleLoading ? 'Refreshing…' : 'Refresh'}
            </button>
          </div>

          {scheduleLoading ? (
            <div className="loading">Loading scheduled scans...</div>
          ) : (
            <div className="scans-table">
              <table>
                <thead>
                  <tr>
                    <th>NAME</th>
                    <th>TYPE</th>
                    <th>SCHEDULED FOR</th>
                    <th>STATUS</th>
                    <th>SCAN ID</th>
                    <th>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {scheduledScans.length === 0 ? (
                    <tr>
                      <td colSpan="6">No scheduled scans</td>
                    </tr>
                  ) : (
                    [...scheduledScans]
                      .sort((a, b) => new Date(b.created_at || b.scheduled_for || 0).getTime() - new Date(a.created_at || a.scheduled_for || 0).getTime())
                      .map((s) => (
                        <tr key={s.id}>
                          <td>{s.scan_name}</td>
                          <td>{String(s.scan_type).toUpperCase()}</td>
                          <td>{s.scheduled_for ? new Date(s.scheduled_for).toLocaleString() : '-'}</td>
                          <td>
                            <span className={`status-badge ${s.status === 'COMPLETED' ? 'success' : s.status === 'FAILED' ? 'error' : s.status === 'CANCELLED' ? 'error' : 'pending'}`}>
                              {s.status === 'IN_PROGRESS' ? 'IN PROGRESS' : s.status}
                            </span>
                          </td>
                          <td>{s.triggered_scan_id || '-'}</td>
                          <td>
                            <div className="scan-actions">
                              {s.triggered_scan_id ? (
                                <button
                                  type="button"
                                  className="btn-small"
                                  onClick={() => handleViewResults(s.triggered_scan_id)}
                                >
                                  View Results
                                </button>
                              ) : s.status === 'PENDING' ? (
                                <button
                                  type="button"
                                  className="btn-small btn-terminate"
                                  onClick={async () => {
                                    try {
                                      await cancelScheduledScan(s.id);
                                      setNotification({ message: 'Scheduled scan cancelled', type: 'success' });
                                      await loadScheduled();
                                    } catch (err) {
                                      setNotification({ message: `Failed to cancel: ${err.message}`, type: 'error' });
                                    }
                                  }}
                                >
                                  Cancel
                                </button>
                              ) : (
                                <span style={{ color: 'var(--text-secondary)' }}>-</span>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Scan;

