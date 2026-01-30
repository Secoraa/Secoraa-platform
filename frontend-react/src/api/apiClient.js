/**
 * FastAPI Client - All backend API calls
 */
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || process.env.REACT_APP_API_URL || 'https://secoraa-platform-production.up.railway.app';

const TOKEN_STORAGE_KEY = 'secoraa_access_token';
const TOKEN_STORAGE_PERSIST_KEY = 'secoraa_token_persist';

export const getStoredToken = () => {
  const persist = localStorage.getItem(TOKEN_STORAGE_PERSIST_KEY) === 'true';
  const store = persist ? localStorage : sessionStorage;
  return store.getItem(TOKEN_STORAGE_KEY);
};

export const setStoredToken = (token, persist = true) => {
  localStorage.setItem(TOKEN_STORAGE_PERSIST_KEY, persist ? 'true' : 'false');
  const store = persist ? localStorage : sessionStorage;
  const other = persist ? sessionStorage : localStorage;
  if (token) {
    store.setItem(TOKEN_STORAGE_KEY, token);
    other.removeItem(TOKEN_STORAGE_KEY);
  } else {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    sessionStorage.removeItem(TOKEN_STORAGE_KEY);
  }
};

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000, // 30 seconds for regular requests
  headers: {
    'Content-Type': 'application/json',
  },
});

// Separate client for long-running scan operations (no timeout)
const scanClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 0, // No timeout - scans can take as long as needed
  headers: {
    'Content-Type': 'application/json',
  },
});

const attachAuthInterceptor = (client) => {
  client.interceptors.request.use((config) => {
    const token = getStoredToken();
    if (token) {
      config.headers = config.headers || {};
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  });
};

attachAuthInterceptor(apiClient);
attachAuthInterceptor(scanClient);

// ==========================================
// Auth APIs
// ==========================================

export const signup = async (username, password, tenant) => {
  try {
    const response = await apiClient.post('/auth/signup', {
      username,
      password,
      tenant: tenant || undefined,
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `Signup failed: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Signup failed: ${error.message}`);
  }
};

export const login = async (username, password) => {
  try {
    const response = await apiClient.post('/auth/login', { username, password });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `Login failed: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Login failed: ${error.message}`);
  }
};

export const getTokenClaims = async () => {
  try {
    const response = await apiClient.get('/auth/token');
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `Token validation failed: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Token validation failed: ${error.message}`);
  }
};

// ==========================================
// Help Center (User Flows Q&A)
// ==========================================

export const askHelpCenter = async (question, maxSources = 3) => {
  try {
    const response = await apiClient.post('/help/qa', { question, max_sources: maxSources });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `Help Center failed: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Help Center failed: ${error.message}`);
  }
};

// ==========================================
// API Scanner
// ==========================================

export const runApiTestingScan = async (scanName, assetUrl, endpoints) => {
  try {
    const response = await scanClient.post('/scanner/api', {
      scan_name: scanName,
      asset_url: assetUrl,
      endpoints: endpoints,
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `API scan failed: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`API scan failed: ${error.message}`);
  }
};

export const getApiFindings = async () => {
  try {
    const response = await apiClient.get('/vulnerabilities/api-findings');
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `Failed to fetch findings: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to fetch findings: ${error.message}`);
  }
};

export const getAllFindings = async () => {
  try {
    const response = await apiClient.get('/vulnerabilities/findings');
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `Failed to fetch findings: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to fetch findings: ${error.message}`);
  }
};

// ==========================================
// Reports
// ==========================================

export const downloadAsmReportPdf = async (domain = null) => {
  try {
    const response = await scanClient.get('/reports/asm.pdf', {
      responseType: 'blob',
      params: domain ? { domain } : undefined,
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `Failed to download report: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to download report: ${error.message}`);
  }
};

export const listReports = async (limit = 50, offset = 0) => {
  try {
    const response = await apiClient.get('/reports', { params: { limit, offset } });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `Failed to load reports: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to load reports: ${error.message}`);
  }
};

export const createReport = async ({ reportName, reportType, description, domainName, assessmentType, subdomainName, scanId }) => {
  try {
    const response = await apiClient.post('/reports', {
      report_name: reportName,
      report_type: reportType,
      description: description || undefined,
      domain_name: domainName || undefined,
      assessment_type: assessmentType || undefined,
      subdomain_name: subdomainName || undefined,
      scan_id: scanId || undefined,
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `Failed to create report: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to create report: ${error.message}`);
  }
};

export const downloadReportPdf = async (reportId) => {
  try {
    const response = await scanClient.get(`/reports/${reportId}/download`, { responseType: 'blob' });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `Failed to download report: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to download report: ${error.message}`);
  }
};

// ==========================================
// Subdomain Scanner
// ==========================================

export const runSubdomainScan = async (domain, subdomains = null, exportJson = false, exportPdf = false) => {
  try {
    const response = await apiClient.post('/scan/subdomain/run', {
      domain,
      subdomains: Array.isArray(subdomains) ? subdomains : undefined,
      export_json: Boolean(exportJson),
      export_pdf: Boolean(exportPdf),
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `Subdomain scan failed: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Subdomain scan failed: ${error.message}`);
  }
};

// ==========================================
// Asset Discovery APIs
// ==========================================

export const getDomains = async () => {
  try {
    const response = await apiClient.get('/assets/domain');
    return response.data;
  } catch (error) {
    // Better error handling for network issues
    if (error.code === 'ERR_NETWORK' || error.message.includes('Network Error')) {
      throw new Error('Network Error: Unable to connect to backend. Please ensure the FastAPI server is running on http://localhost:8000');
    }
    if (error.response) {
      throw new Error(`Failed to fetch domains: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to fetch domains: ${error.message}`);
  }
};

export const getDomainById = async (domainId) => {
  try {
    const response = await apiClient.get(`/assets/domain/${domainId}`);
    return response.data;
  } catch (error) {
    throw new Error(`Failed to fetch domain: ${error.message}`);
  }
};

export const createDomain = async (domainName, tags = []) => {
  try {
    const response = await apiClient.post('/assets/domain', {
      domain_name: domainName,
      tags: tags,
    });
    return response.data;
  } catch (error) {
    throw new Error(`Failed to create domain: ${error.message}`);
  }
};

export const updateDomain = async (domainId, tags) => {
  try {
    const response = await apiClient.patch(`/assets/domain/${domainId}`, {
      tags: tags,
    });
    return response.data;
  } catch (error) {
    throw new Error(`Failed to update domain: ${error.message}`);
  }
};

export const getSubdomains = async () => {
  try {
    const response = await apiClient.get('/subdomain/subdomain');
    return response.data;
  } catch (error) {
    if (error.code === 'ERR_NETWORK' || error.message.includes('Network Error')) {
      throw new Error('Network Error: Unable to connect to backend. Please ensure the FastAPI server is running on http://localhost:8000');
    }
    if (error.response) {
      throw new Error(`Failed to fetch subdomains: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to fetch subdomains: ${error.message}`);
  }
};

export const getIPAddresses = async () => {
  try {
    const response = await apiClient.get('/assets/ip-addresses');
    return response.data;
  } catch (error) {
    if (error.code === 'ERR_NETWORK' || error.message.includes('Network Error')) {
      throw new Error('Network Error: Unable to connect to backend. Please ensure the FastAPI server is running on http://localhost:8000');
    }
    if (error.response) {
      throw new Error(`Failed to fetch IP addresses: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to fetch IP addresses: ${error.message}`);
  }
};

export const getUrls = async () => {
  try {
    const response = await apiClient.get('/assets/urls');
    return response.data;
  } catch (error) {
    if (error.code === 'ERR_NETWORK' || error.message.includes('Network Error')) {
      throw new Error('Network Error: Unable to connect to backend. Please ensure the FastAPI server is running on http://localhost:8000');
    }
    if (error.response) {
      throw new Error(`Failed to fetch URLs: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to fetch URLs: ${error.message}`);
  }
};

export const getAssetGroups = async () => {
  try {
    const response = await apiClient.get('/assets/asset-groups');
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(`Failed to fetch asset groups: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to fetch asset groups: ${error.message}`);
  }
};

export const createAssetGroup = async ({ name, domainId, assetType, description, assetIds }) => {
  try {
    const response = await apiClient.post('/assets/asset-groups', {
      name,
      domain_id: domainId,
      asset_type: assetType,
      asset_ids: Array.isArray(assetIds) ? assetIds : [],
      description: description || undefined,
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `Failed to create asset group: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to create asset group: ${error.message}`);
  }
};

export const createIPAddress = async (domainId, ipAddress, tags = []) => {
  try {
    const response = await apiClient.post('/assets/ip-addresses', {
      domain_id: domainId,
      ipaddress_name: ipAddress,
      tags: tags,
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(`Failed to create IP address: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to create IP address: ${error.message}`);
  }
};

export const createUrl = async (domainId, url, tags = []) => {
  try {
    const response = await apiClient.post('/assets/urls', {
      domain_id: domainId,
      url_name: url,
      tags: tags,
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(`Failed to create URL: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to create URL: ${error.message}`);
  }
};

export const createSubdomain = async (domainId, subdomainName, tags = []) => {
  try {
    const response = await apiClient.post('/subdomain/subdomain', {
      domain_id: domainId,
      subdomain_name: subdomainName,
      tags: tags,
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(`Failed to create subdomain: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to create subdomain: ${error.message}`);
  }
};

// ==========================================
// Scan APIs
// ==========================================

export const createScan = async (scanName, scanType, domain) => {
  return await createScanWithPayload(scanName, scanType, { domain });
};

export const createScanWithPayload = async (scanName, scanType, payload) => {
  try {
    // Use scanClient for long-running scan operations (no timeout)
    const response = await scanClient.post('/scans/', {
      scan_name: scanName,
      scan_type: scanType,
      payload: payload || {},
    });
    return response.data;
  } catch (error) {
    if (error.code === 'ECONNABORTED') {
      throw new Error('Scan is taking longer than expected. Please check scan history for results.');
    }
    throw new Error(`Failed to run scan: ${error.message}`);
  }
};

export const getAllScans = async () => {
  try {
    const response = await apiClient.get('/scans/scan');
    return response.data;
  } catch (error) {
    throw new Error(`Failed to fetch scans: ${error.message}`);
  }
};

export const getScanById = async (scanId) => {
  try {
    const response = await apiClient.get(`/scans/scan/${scanId}`);
    return response.data;
  } catch (error) {
    throw new Error(`Failed to fetch scan: ${error.message}`);
  }
};

export const getScanResults = async (scanId) => {
  try {
    const response = await apiClient.get(`/scans/${scanId}/results`);
    return response.data;
  } catch (error) {
    throw new Error(`Failed to fetch scan results: ${error.message}`);
  }
};

export const pauseScan = async (scanId) => {
  try {
    const response = await apiClient.post(`/scans/${scanId}/pause`);
    return response.data;
  } catch (error) {
    throw new Error(`Failed to pause scan: ${error.message}`);
  }
};

export const resumeScan = async (scanId) => {
  try {
    const response = await apiClient.post(`/scans/${scanId}/resume`);
    return response.data;
  } catch (error) {
    throw new Error(`Failed to resume scan: ${error.message}`);
  }
};

export const terminateScan = async (scanId) => {
  try {
    const response = await apiClient.post(`/scans/${scanId}/terminate`);
    return response.data;
  } catch (error) {
    throw new Error(`Failed to terminate scan: ${error.message}`);
  }
};

// ==========================================
// Scheduled Scans
// ==========================================

export const createScheduledScan = async ({ scanName, scanType, scheduledFor, payload }) => {
  try {
    const response = await apiClient.post('/scans/schedule', {
      scan_name: scanName,
      scan_type: scanType,
      scheduled_for: scheduledFor, // ISO string
      payload: payload || {},
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `Failed to schedule scan: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to schedule scan: ${error.message}`);
  }
};

export const listScheduledScans = async (limit = 50, offset = 0) => {
  try {
    const response = await apiClient.get('/scans/schedule', { params: { limit, offset } });
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `Failed to load scheduled scans: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to load scheduled scans: ${error.message}`);
  }
};

export const cancelScheduledScan = async (scheduleId) => {
  try {
    const response = await apiClient.post(`/scans/schedule/${scheduleId}/cancel`);
    return response.data;
  } catch (error) {
    if (error.response) {
      throw new Error(error.response.data?.detail || `Failed to cancel scheduled scan: ${error.response.status} ${error.response.statusText}`);
    }
    throw new Error(`Failed to cancel scheduled scan: ${error.message}`);
  }
};
