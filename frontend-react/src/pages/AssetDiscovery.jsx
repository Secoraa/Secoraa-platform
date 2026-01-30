import React, { useState, useEffect, useMemo } from 'react';
import {
  getDomains,
  createDomain,
  getSubdomains,
  createSubdomain,
  getIPAddresses,
  getUrls,
  createIPAddress,
  createUrl,
  getAssetGroups,
  createAssetGroup,
} from '../api/apiClient';
import './AssetDiscovery.css';

// TagsDisplay component to show tags with "+X" functionality
const TagsDisplay = ({ tags, itemId, expandedTags, setExpandedTags }) => {
  if (!tags || tags.length === 0) {
    return <span className="no-tags">-</span>;
  }

  const isExpanded = expandedTags[itemId] || false;
  const maxVisible = 2;
  const hasMore = tags.length > maxVisible;
  const visibleTags = isExpanded ? tags : tags.slice(0, maxVisible);
  const remainingCount = tags.length - maxVisible;

  const handleToggle = (e) => {
    e.stopPropagation();
    setExpandedTags(prev => ({
      ...prev,
      [itemId]: !prev[itemId]
    }));
  };

  return (
    <div className="tags-container">
      {visibleTags.map((tag, idx) => (
        <span key={idx} className="tag-badge">
          {tag}
        </span>
      ))}
      {hasMore && (
        <span 
          className="tag-more-link" 
          onClick={handleToggle}
          title={isExpanded ? 'Show less' : `Show ${remainingCount} more tag${remainingCount > 1 ? 's' : ''}`}
        >
          {isExpanded ? 'Show less' : `+${remainingCount}`}
        </span>
      )}
    </div>
  );
};

const AssetDiscovery = () => {
  const [domains, setDomains] = useState([]);
  const [subdomains, setSubdomains] = useState([]);
  const [ipAddresses, setIpAddresses] = useState([]);
  const [urls, setUrls] = useState([]);
  const [assetGroups, setAssetGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [subdomainLoading, setSubdomainLoading] = useState(false);
  const [ipLoading, setIpLoading] = useState(false);
  const [urlLoading, setUrlLoading] = useState(false);
  const [assetGroupLoading, setAssetGroupLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('domains');
  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState('All');
  const [labelsFilter, setLabelsFilter] = useState('All Labels');
  const [subdomainDomainFilter, setSubdomainDomainFilter] = useState('All Domains');
  const [ipDomainFilter, setIpDomainFilter] = useState('All Domains');
  const [urlDomainFilter, setUrlDomainFilter] = useState('All Domains');
  const [showAddModal, setShowAddModal] = useState(false);
  const [showAddSubdomainModal, setShowAddSubdomainModal] = useState(false);
  const [showAddIpModal, setShowAddIpModal] = useState(false);
  const [showAddUrlModal, setShowAddUrlModal] = useState(false);
  const [showAddAssetGroupModal, setShowAddAssetGroupModal] = useState(false);
  const [newDomain, setNewDomain] = useState({ name: '', tags: '' });
  const [newSubdomain, setNewSubdomain] = useState({ domainId: '', name: '', tags: '' });
  const [newIpAddress, setNewIpAddress] = useState({ domainId: '', ip: '', tags: '' });
  const [newUrl, setNewUrl] = useState({ domainId: '', url: '', tags: '' });
  const [newAssetGroup, setNewAssetGroup] = useState({ name: '', domainId: '', assetType: 'SUBDOMAIN', description: '', assetIds: [] });
  const [currentPage, setCurrentPage] = useState(1);
  const [subdomainCurrentPage, setSubdomainCurrentPage] = useState(1);
  const [ipCurrentPage, setIpCurrentPage] = useState(1);
  const [urlCurrentPage, setUrlCurrentPage] = useState(1);
  const [assetGroupCurrentPage, setAssetGroupCurrentPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [expandedTags, setExpandedTags] = useState({});

  useEffect(() => {
    // Prefetch counts so tab badges don't show 0 before user clicks into tabs
    loadDomains();
    loadIPAddresses();
    loadUrls();
    loadAssetGroups();
  }, []);

  useEffect(() => {
    if (activeTab === 'subdomains') {
      loadSubdomains();
    }
    if (activeTab === 'ip-addresses') {
      // Lazy-load fallback (in case prefetch failed)
      if (!ipAddresses || ipAddresses.length === 0) loadIPAddresses();
    }
    if (activeTab === 'url') {
      // Lazy-load fallback (in case prefetch failed)
      if (!urls || urls.length === 0) loadUrls();
    }
    if (activeTab === 'asset-groups') {
      if (!assetGroups || assetGroups.length === 0) loadAssetGroups();
    }
  }, [activeTab]);

  useEffect(() => {
    if (!showAddAssetGroupModal) return;
    if (newAssetGroup.assetType === 'SUBDOMAIN' && subdomains.length === 0) {
      loadSubdomains();
    }
    if (newAssetGroup.assetType === 'IP' && ipAddresses.length === 0) {
      loadIPAddresses();
    }
  }, [showAddAssetGroupModal, newAssetGroup.assetType]);

  const loadDomains = async () => {
    try {
      setLoading(true);
      const data = await getDomains();
      setDomains(Array.isArray(data) ? data : data.data || []);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const openDomainDetailsInNewTab = (domain) => {
    const id = domain?.id;
    if (!id) return;
    const url = `${window.location.origin}${window.location.pathname}?domain=${encodeURIComponent(id)}`;
    window.open(url, '_blank', 'noopener,noreferrer');
  };

  const loadSubdomains = async () => {
    try {
      setSubdomainLoading(true);
      const data = await getSubdomains();
      setSubdomains(Array.isArray(data) ? data : []);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setSubdomainLoading(false);
    }
  };

  const loadIPAddresses = async () => {
    try {
      setIpLoading(true);
      const data = await getIPAddresses();
      setIpAddresses(Array.isArray(data) ? data : []);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setIpLoading(false);
    }
  };

  const loadUrls = async () => {
    try {
      setUrlLoading(true);
      const data = await getUrls();
      setUrls(Array.isArray(data) ? data : []);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setUrlLoading(false);
    }
  };

  const loadAssetGroups = async () => {
    try {
      setAssetGroupLoading(true);
      const data = await getAssetGroups();
      setAssetGroups(Array.isArray(data) ? data : []);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setAssetGroupLoading(false);
    }
  };

  const domainNameOptions = useMemo(() => {
    const names = (domains || []).map((d) => d.domain_name).filter(Boolean);
    return Array.from(new Set(names)).sort((a, b) => a.localeCompare(b));
  }, [domains]);

  const handleAddDomain = async (e) => {
    e.preventDefault();
    try {
      const tags = newDomain.tags
        ? newDomain.tags.split(',').map((t) => t.trim()).filter(t => t)
        : [];
      await createDomain(newDomain.name, tags);
      setShowAddModal(false);
      setNewDomain({ name: '', tags: '' });
      loadDomains();
    } catch (err) {
      alert(`Failed to add domain: ${err.message}`);
    }
  };

  const handleAddSubdomain = async (e) => {
    e.preventDefault();
    try {
      if (!newSubdomain.domainId) {
        alert('Please select a domain');
        return;
      }
      const tags = newSubdomain.tags
        ? newSubdomain.tags.split(',').map((t) => t.trim()).filter(t => t)
        : [];
      await createSubdomain(newSubdomain.domainId, newSubdomain.name, tags);
      setShowAddSubdomainModal(false);
      setNewSubdomain({ domainId: '', name: '', tags: '' });
      loadSubdomains();
      loadDomains(); // Refresh domains to update subdomain count
    } catch (err) {
      alert(`Failed to add subdomain: ${err.message}`);
    }
  };

  const handleAddIpAddress = async (e) => {
    e.preventDefault();
    try {
      if (!newIpAddress.domainId) {
        alert('Please select a domain');
        return;
      }
      const tags = newIpAddress.tags
        ? newIpAddress.tags.split(',').map((t) => t.trim()).filter(t => t)
        : [];
      await createIPAddress(newIpAddress.domainId, newIpAddress.ip, tags);
      setShowAddIpModal(false);
      setNewIpAddress({ domainId: '', ip: '', tags: '' });
      setIpCurrentPage(1);
      loadIPAddresses();
    } catch (err) {
      alert(`Failed to add IP address: ${err.message}`);
    }
  };

  const handleAddUrl = async (e) => {
    e.preventDefault();
    try {
      if (!newUrl.domainId) {
        alert('Please select a domain');
        return;
      }
      const tags = newUrl.tags
        ? newUrl.tags.split(',').map((t) => t.trim()).filter(t => t)
        : [];
      await createUrl(newUrl.domainId, newUrl.url, tags);
      setShowAddUrlModal(false);
      setNewUrl({ domainId: '', url: '', tags: '' });
      setUrlCurrentPage(1);
      loadUrls();
    } catch (err) {
      alert(`Failed to add URL: ${err.message}`);
    }
  };

  const handleAddAssetGroup = async (e) => {
    e.preventDefault();
    try {
      if (!newAssetGroup.domainId) {
        alert('Please select a domain');
        return;
      }
      if (!newAssetGroup.assetIds || newAssetGroup.assetIds.length === 0) {
        alert('Please select at least one asset');
        return;
      }
      if (newAssetGroup.assetIds.length > 5) {
        alert('You can select up to 5 assets');
        return;
      }
      await createAssetGroup({
        name: newAssetGroup.name,
        domainId: newAssetGroup.domainId,
        assetType: newAssetGroup.assetType,
        description: newAssetGroup.description,
        assetIds: newAssetGroup.assetIds,
      });
      setShowAddAssetGroupModal(false);
      setNewAssetGroup({ name: '', domainId: '', assetType: 'SUBDOMAIN', description: '', assetIds: [] });
      setAssetGroupCurrentPage(1);
      loadAssetGroups();
    } catch (err) {
      alert(`Failed to add asset group: ${err.message}`);
    }
  };

  // Filter domains
  let filteredDomains = domains;
  if (searchQuery) {
    filteredDomains = filteredDomains.filter((domain) =>
      domain.domain_name?.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }

  // Active/Inactive filter
  if (activeFilter === 'Active') {
    filteredDomains = filteredDomains.filter((d) => (d.is_active ?? true) === true && (d.is_archived ?? false) === false);
  } else if (activeFilter === 'Inactive') {
    filteredDomains = filteredDomains.filter((d) => (d.is_active ?? true) === false || (d.is_archived ?? false) === true);
  }

  // Labels filter (maps to tags)
  if (labelsFilter && labelsFilter !== 'All Labels') {
    const label = labelsFilter.toLowerCase();
    filteredDomains = filteredDomains.filter((d) =>
      Array.isArray(d.tags) && d.tags.some((t) => String(t).toLowerCase() === label)
    );
  }

  // Pagination
  const totalPages = Math.ceil(filteredDomains.length / rowsPerPage);
  const startIndex = (currentPage - 1) * rowsPerPage;
  const endIndex = startIndex + rowsPerPage;
  const paginatedDomains = filteredDomains.slice(startIndex, endIndex);

  const totalSubdomains = domains.reduce(
    (sum, d) => sum + (d.subdomains?.length || 0),
    0
  );

  // Filter subdomains
  let filteredSubdomains = subdomains;
  if (activeTab === 'subdomains' && subdomainDomainFilter !== 'All Domains') {
    filteredSubdomains = filteredSubdomains.filter((s) => s.domain_name === subdomainDomainFilter);
  }
  if (searchQuery && activeTab === 'subdomains') {
    filteredSubdomains = subdomains.filter((subdomain) =>
      subdomain.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      subdomain.domain_name?.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }

  // Pagination for subdomains
  const subdomainTotalPages = Math.ceil(filteredSubdomains.length / rowsPerPage);
  const subdomainStartIndex = (subdomainCurrentPage - 1) * rowsPerPage;
  const subdomainEndIndex = subdomainStartIndex + rowsPerPage;
  const paginatedSubdomains = filteredSubdomains.slice(subdomainStartIndex, subdomainEndIndex);

  // Filter IP addresses
  let filteredIPs = ipAddresses;
  if (activeTab === 'ip-addresses' && ipDomainFilter !== 'All Domains') {
    filteredIPs = filteredIPs.filter((ip) => ip.domain_name === ipDomainFilter);
  }
  if (searchQuery && activeTab === 'ip-addresses') {
    const q = searchQuery.toLowerCase();
    filteredIPs = filteredIPs.filter((ip) =>
      String(ip.ipaddress_name || '').toLowerCase().includes(q) ||
      String(ip.domain_name || '').toLowerCase().includes(q)
    );
  }
  const ipTotalPages = Math.ceil(filteredIPs.length / rowsPerPage);
  const ipStartIndex = (ipCurrentPage - 1) * rowsPerPage;
  const ipEndIndex = ipStartIndex + rowsPerPage;
  const paginatedIPs = filteredIPs.slice(ipStartIndex, ipEndIndex);

  // Filter URLs
  let filteredUrls = urls;
  if (activeTab === 'url' && urlDomainFilter !== 'All Domains') {
    filteredUrls = filteredUrls.filter((u) => u.domain_name === urlDomainFilter);
  }
  if (searchQuery && activeTab === 'url') {
    const q = searchQuery.toLowerCase();
    filteredUrls = filteredUrls.filter((u) =>
      String(u.url_name || '').toLowerCase().includes(q) ||
      String(u.domain_name || '').toLowerCase().includes(q)
    );
  }
  const urlTotalPages = Math.ceil(filteredUrls.length / rowsPerPage);
  const urlStartIndex = (urlCurrentPage - 1) * rowsPerPage;
  const urlEndIndex = urlStartIndex + rowsPerPage;
  const paginatedUrls = filteredUrls.slice(urlStartIndex, urlEndIndex);

  // Filter Asset Groups
  let filteredAssetGroups = assetGroups;
  if (searchQuery && activeTab === 'asset-groups') {
    const q = searchQuery.toLowerCase();
    filteredAssetGroups = filteredAssetGroups.filter((g) =>
      String(g.name || '').toLowerCase().includes(q) ||
      String(g.domain_name || '').toLowerCase().includes(q) ||
      String(g.asset_type || '').toLowerCase().includes(q) ||
      String(g.description || '').toLowerCase().includes(q)
    );
  }
  const assetGroupTotalPages = Math.ceil(filteredAssetGroups.length / rowsPerPage);
  const assetGroupStartIndex = (assetGroupCurrentPage - 1) * rowsPerPage;
  const assetGroupEndIndex = assetGroupStartIndex + rowsPerPage;
  const paginatedAssetGroups = filteredAssetGroups.slice(assetGroupStartIndex, assetGroupEndIndex);

  const selectedDomainSubdomains = useMemo(() => {
    if (!newAssetGroup.domainId) return [];
    return (subdomains || []).filter((s) => String(s.domain_id) === String(newAssetGroup.domainId));
  }, [subdomains, newAssetGroup.domainId]);

  const selectedDomainIps = useMemo(() => {
    if (!newAssetGroup.domainId) return [];
    return (ipAddresses || []).filter((ip) => String(ip.domain_id) === String(newAssetGroup.domainId));
  }, [ipAddresses, newAssetGroup.domainId]);

  const toggleAssetSelection = (assetId) => {
    setNewAssetGroup((prev) => {
      const exists = prev.assetIds.includes(assetId);
      if (exists) {
        return { ...prev, assetIds: prev.assetIds.filter((id) => id !== assetId) };
      }
      if (prev.assetIds.length >= 5) return prev;
      return { ...prev, assetIds: [...prev.assetIds, assetId] };
    });
  };

  const tabs = [
    { id: 'domains', label: 'Domains', count: domains.length },
    { id: 'subdomains', label: 'Subdomains', count: totalSubdomains > 999 ? '999+' : totalSubdomains },
    { id: 'ip-addresses', label: 'IP Addresses', count: ipAddresses.length },
    { id: 'url', label: 'URL', count: urls.length },
    { id: 'ip-blocks', label: 'IP Blocks', count: 0 },
    { id: 'asset-groups', label: 'Asset Groups', count: assetGroups.length },
  ];

  return (
    <div className="asset-discovery">
      <div className="page-header">
        <h1 className="page-title">ASSET DISCOVERY</h1>
      </div>

      {/* Tabs */}
      <div className="asset-tabs">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            className={`asset-tab ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            <span className="tab-label">{tab.label}</span>
            <span className="tab-count">{tab.count}</span>
          </button>
        ))}
      </div>

      {activeTab === 'domains' && (
        <>
          {/* Filters */}
          <div className="filters-row">
            <input
              type="text"
              className="search-input"
              placeholder="Q Search Name"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(1);
              }}
            />
            <select 
              className="filter-select"
              value={activeFilter}
              onChange={(e) => setActiveFilter(e.target.value)}
            >
              <option>All</option>
              <option>Active</option>
              <option>Inactive</option>
            </select>
            <select 
              className="filter-select"
              value={labelsFilter}
              onChange={(e) => setLabelsFilter(e.target.value)}
            >
              <option>All Labels</option>
              <option>Production</option>
              <option>External</option>
              <option>Internal</option>
            </select>
            <button 
              className="add-domain-btn-filter"
              onClick={() => setShowAddModal(true)}
            >
              ➕ Add Domain
            </button>
          </div>

          {/* Table */}
          {loading ? (
            <div className="loading">Loading domains...</div>
          ) : error ? (
            <div className="error">Error: {error}</div>
          ) : (
            <div className="table-container">
              <div className="asset-table-wrapper">
                <table className="asset-table">
                  <thead>
                    <tr>
                      <th>NAME</th>
                      <th>ASSET LABELS</th>
                      <th>TAGS</th>
                      <th>SUBDOMAIN COUNT</th>
                      <th>ASN COUNT</th>
                      <th>VULNERABILITY COUNT</th>
                    </tr>
                  </thead>
                  <tbody>
                  {paginatedDomains.length === 0 ? (
                    <tr>
                      <td colSpan="6" className="empty-state">
                        No domains found
                      </td>
                    </tr>
                  ) : (
                    paginatedDomains.map((domain) => (
                      <tr
                        key={domain.id}
                        className="domain-row-clickable"
                        onClick={() => openDomainDetailsInNewTab(domain)}
                        title="Open domain details in a new tab"
                      >
                        <td
                          className="domain-name"
                          title="Click to open domain details in a new tab"
                        >
                          {domain.domain_name}
                        </td>
                        <td>
                          {domain.discovery_source === 'manual'
                            ? 'Manually Added'
                            : 'Auto Discovered'}
                        </td>
                        <td>
                          <TagsDisplay 
                            tags={domain.tags} 
                            itemId={domain.id}
                            expandedTags={expandedTags}
                            setExpandedTags={setExpandedTags}
                          />
                        </td>
                        <td>{domain.subdomains?.length || 0}</td>
                        <td>0</td>
                        <td>0</td>
                      </tr>
                    ))
                  )}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              <div className="pagination">
                <div className="pagination-left">
                  <span>Rows per page:</span>
                  <select 
                    className="pagination-select"
                    value={rowsPerPage}
                    onChange={(e) => {
                      setRowsPerPage(Number(e.target.value));
                      setCurrentPage(1);
                    }}
                  >
                    <option value={5}>5</option>
                    <option value={10}>10</option>
                    <option value={25}>25</option>
                    <option value={50}>50</option>
                  </select>
                </div>
                <div className="pagination-right">
                  <span>
                    {startIndex + 1}-{Math.min(endIndex, filteredDomains.length)} of {filteredDomains.length}
                  </span>
                  <div className="pagination-arrows">
                    <button
                      className="pagination-btn"
                      onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                      disabled={currentPage === 1}
                    >
                      ←
                    </button>
                    <button
                      className="pagination-btn"
                      onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                      disabled={currentPage === totalPages}
                    >
                      →
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* Subdomains Tab */}
      {activeTab === 'subdomains' && (
        <>
          {/* Filters */}
          <div className="filters-row">
            <input
              type="text"
              className="search-input"
              placeholder="Q Search Name"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setSubdomainCurrentPage(1);
              }}
            />
            <select
              className="filter-select"
              value={subdomainDomainFilter}
              onChange={(e) => {
                setSubdomainDomainFilter(e.target.value);
                setSubdomainCurrentPage(1);
              }}
            >
              <option>All Domains</option>
              {domainNameOptions.map((dn) => (
                <option key={dn} value={dn}>{dn}</option>
              ))}
            </select>
            <select 
              className="filter-select"
              value={activeFilter}
              onChange={(e) => setActiveFilter(e.target.value)}
            >
              <option>All</option>
              <option>Active</option>
              <option>Inactive</option>
            </select>
            <select 
              className="filter-select"
              value={labelsFilter}
              onChange={(e) => setLabelsFilter(e.target.value)}
            >
              <option>All Labels</option>
              <option>Production</option>
              <option>External</option>
              <option>Internal</option>
            </select>
            <button 
              className="add-domain-btn-filter"
              onClick={() => setShowAddSubdomainModal(true)}
            >
              ➕ Add Subdomain
            </button>
          </div>

          {/* Table */}
          {subdomainLoading ? (
            <div className="loading">Loading subdomains...</div>
          ) : error ? (
            <div className="error">Error: {error}</div>
          ) : (
            <div className="table-container">
              <div className="asset-table-wrapper">
                <table className="asset-table">
                  <thead>
                    <tr>
                      <th>NAME</th>
                      <th>DOMAIN NAME</th>
                      <th>TAGS</th>
                      <th>CREATED BY</th>
                      <th>UPDATED BY</th>
                      <th>CREATED AT</th>
                    </tr>
                  </thead>
                  <tbody>
                  {paginatedSubdomains.length === 0 ? (
                    <tr>
                      <td colSpan="6" className="empty-state">
                        No subdomains found
                      </td>
                    </tr>
                  ) : (
                    paginatedSubdomains.map((subdomain) => (
                      <tr key={subdomain.id}>
                        <td className="domain-name">{subdomain.name || subdomain.subdomain_name}</td>
                        <td>{subdomain.domain_name || '-'}</td>
                        <td>
                          <TagsDisplay 
                            tags={subdomain.tags} 
                            itemId={subdomain.id}
                            expandedTags={expandedTags}
                            setExpandedTags={setExpandedTags}
                          />
                        </td>
                        <td>{subdomain.created_by || '-'}</td>
                        <td>{subdomain.updated_by || '-'}</td>
                        <td>
                          {subdomain.created_at 
                            ? new Date(subdomain.created_at).toLocaleDateString()
                            : '-'}
                        </td>
                      </tr>
                    ))
                  )}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              <div className="pagination">
                <div className="pagination-left">
                  <span>Rows per page:</span>
                  <select 
                    className="pagination-select"
                    value={rowsPerPage}
                    onChange={(e) => {
                      setRowsPerPage(Number(e.target.value));
                      setSubdomainCurrentPage(1);
                    }}
                  >
                    <option value={5}>5</option>
                    <option value={10}>10</option>
                    <option value={25}>25</option>
                    <option value={50}>50</option>
                  </select>
                </div>
                <div className="pagination-right">
                  <span>
                    {subdomainStartIndex + 1}-{Math.min(subdomainEndIndex, filteredSubdomains.length)} of {filteredSubdomains.length}
                  </span>
                  <div className="pagination-arrows">
                    <button
                      className="pagination-btn"
                      onClick={() => setSubdomainCurrentPage(prev => Math.max(1, prev - 1))}
                      disabled={subdomainCurrentPage === 1}
                    >
                      ←
                    </button>
                    <button
                      className="pagination-btn"
                      onClick={() => setSubdomainCurrentPage(prev => Math.min(subdomainTotalPages, prev + 1))}
                      disabled={subdomainCurrentPage === subdomainTotalPages}
                    >
                      →
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* IP Addresses Tab */}
      {activeTab === 'ip-addresses' && (
        <>
          <div className="filters-row">
            <input
              type="text"
              className="search-input"
              placeholder="Q Search Name"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setIpCurrentPage(1);
              }}
            />
            <select
              className="filter-select"
              value={ipDomainFilter}
              onChange={(e) => {
                setIpDomainFilter(e.target.value);
                setIpCurrentPage(1);
              }}
            >
              <option>All Domains</option>
              {domainNameOptions.map((dn) => (
                <option key={dn} value={dn}>{dn}</option>
              ))}
            </select>
            <button
              className="add-domain-btn-filter"
              onClick={() => setShowAddIpModal(true)}
            >
              ➕ Add IP Address
            </button>
          </div>

          {ipLoading ? (
            <div className="loading">Loading IP addresses...</div>
          ) : error ? (
            <div className="error">Error: {error}</div>
          ) : (
            <div className="table-container">
              <div className="asset-table-wrapper">
                <table className="asset-table">
                  <thead>
                    <tr>
                      <th>IP ADDRESS</th>
                      <th>DOMAIN NAME</th>
                      <th>TAGS</th>
                      <th>CREATED BY</th>
                      <th>UPDATED BY</th>
                      <th>CREATED AT</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedIPs.length === 0 ? (
                      <tr>
                        <td colSpan="6" className="empty-state">No IP addresses found</td>
                      </tr>
                    ) : (
                      paginatedIPs.map((ip) => (
                        <tr key={ip.id}>
                          <td className="domain-name">{ip.ipaddress_name}</td>
                          <td>{ip.domain_name || '-'}</td>
                          <td>
                            <TagsDisplay
                              tags={ip.tags}
                              itemId={ip.id}
                              expandedTags={expandedTags}
                              setExpandedTags={setExpandedTags}
                            />
                          </td>
                          <td>{ip.created_by || '-'}</td>
                          <td>{ip.updated_by || '-'}</td>
                          <td>{ip.created_at ? new Date(ip.created_at).toLocaleDateString() : '-'}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>

              <div className="pagination">
                <div className="pagination-left">
                  <span>Rows per page:</span>
                  <select
                    className="pagination-select"
                    value={rowsPerPage}
                    onChange={(e) => {
                      setRowsPerPage(Number(e.target.value));
                      setIpCurrentPage(1);
                    }}
                  >
                    <option value={5}>5</option>
                    <option value={10}>10</option>
                    <option value={25}>25</option>
                    <option value={50}>50</option>
                  </select>
                </div>
                <div className="pagination-right">
                  <span>
                    {ipStartIndex + 1}-{Math.min(ipEndIndex, filteredIPs.length)} of {filteredIPs.length}
                  </span>
                  <div className="pagination-arrows">
                    <button
                      className="pagination-btn"
                      onClick={() => setIpCurrentPage(prev => Math.max(1, prev - 1))}
                      disabled={ipCurrentPage === 1}
                    >
                      ←
                    </button>
                    <button
                      className="pagination-btn"
                      onClick={() => setIpCurrentPage(prev => Math.min(ipTotalPages, prev + 1))}
                      disabled={ipCurrentPage === ipTotalPages}
                    >
                      →
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* URL Tab */}
      {activeTab === 'url' && (
        <>
          <div className="filters-row">
            <input
              type="text"
              className="search-input"
              placeholder="Q Search Name"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setUrlCurrentPage(1);
              }}
            />
            <select
              className="filter-select"
              value={urlDomainFilter}
              onChange={(e) => {
                setUrlDomainFilter(e.target.value);
                setUrlCurrentPage(1);
              }}
            >
              <option>All Domains</option>
              {domainNameOptions.map((dn) => (
                <option key={dn} value={dn}>{dn}</option>
              ))}
            </select>
            <button
              className="add-domain-btn-filter"
              onClick={() => setShowAddUrlModal(true)}
            >
              ➕ Add URL
            </button>
          </div>

          {urlLoading ? (
            <div className="loading">Loading URLs...</div>
          ) : error ? (
            <div className="error">Error: {error}</div>
          ) : (
            <div className="table-container">
              <div className="asset-table-wrapper">
                <table className="asset-table">
                  <thead>
                    <tr>
                      <th>URL</th>
                      <th>DOMAIN NAME</th>
                      <th>TAGS</th>
                      <th>CREATED BY</th>
                      <th>UPDATED BY</th>
                      <th>CREATED AT</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedUrls.length === 0 ? (
                      <tr>
                        <td colSpan="6" className="empty-state">No URLs found</td>
                      </tr>
                    ) : (
                      paginatedUrls.map((u) => (
                        <tr key={u.id}>
                          <td className="domain-name">{u.url_name}</td>
                          <td>{u.domain_name || '-'}</td>
                          <td>
                            <TagsDisplay
                              tags={u.tags}
                              itemId={u.id}
                              expandedTags={expandedTags}
                              setExpandedTags={setExpandedTags}
                            />
                          </td>
                          <td>{u.created_by || '-'}</td>
                          <td>{u.updated_by || '-'}</td>
                          <td>{u.created_at ? new Date(u.created_at).toLocaleDateString() : '-'}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>

              <div className="pagination">
                <div className="pagination-left">
                  <span>Rows per page:</span>
                  <select
                    className="pagination-select"
                    value={rowsPerPage}
                    onChange={(e) => {
                      setRowsPerPage(Number(e.target.value));
                      setUrlCurrentPage(1);
                    }}
                  >
                    <option value={5}>5</option>
                    <option value={10}>10</option>
                    <option value={25}>25</option>
                    <option value={50}>50</option>
                  </select>
                </div>
                <div className="pagination-right">
                  <span>
                    {urlStartIndex + 1}-{Math.min(urlEndIndex, filteredUrls.length)} of {filteredUrls.length}
                  </span>
                  <div className="pagination-arrows">
                    <button
                      className="pagination-btn"
                      onClick={() => setUrlCurrentPage(prev => Math.max(1, prev - 1))}
                      disabled={urlCurrentPage === 1}
                    >
                      ←
                    </button>
                    <button
                      className="pagination-btn"
                      onClick={() => setUrlCurrentPage(prev => Math.min(urlTotalPages, prev + 1))}
                      disabled={urlCurrentPage === urlTotalPages}
                    >
                      →
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* Asset Groups Tab */}
      {activeTab === 'asset-groups' && (
        <>
          <div className="filters-row">
            <input
              type="text"
              className="search-input"
              placeholder="Q Search Name"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setAssetGroupCurrentPage(1);
              }}
            />
            <button
              className="add-domain-btn-filter"
              onClick={() => setShowAddAssetGroupModal(true)}
            >
              ➕ Add Asset Group
            </button>
          </div>

          {assetGroupLoading ? (
            <div className="loading">Loading asset groups...</div>
          ) : error ? (
            <div className="error">Error: {error}</div>
          ) : (
            <div className="table-container">
              <div className="asset-table-wrapper">
                <table className="asset-table">
                  <thead>
                    <tr>
                      <th>NAME</th>
                      <th>DOMAIN</th>
                      <th>ASSET TYPE</th>
                      <th>ASSETS</th>
                      <th>DESCRIPTION</th>
                      <th>CREATED AT</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedAssetGroups.length === 0 ? (
                      <tr>
                        <td colSpan="6" className="empty-state">No asset groups found</td>
                      </tr>
                    ) : (
                      paginatedAssetGroups.map((g) => (
                        <tr key={g.id}>
                          <td>{g.name}</td>
                          <td>{g.domain_name || '-'}</td>
                          <td>{g.asset_type || '-'}</td>
                          <td>{(g.assets || []).join(', ') || '-'}</td>
                          <td>{g.description || '-'}</td>
                          <td>{g.created_at ? new Date(g.created_at).toLocaleDateString() : '-'}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>

              <div className="pagination">
                <div className="pagination-left">
                  <span>Rows per page:</span>
                  <select
                    className="pagination-select"
                    value={rowsPerPage}
                    onChange={(e) => {
                      setRowsPerPage(Number(e.target.value));
                      setAssetGroupCurrentPage(1);
                    }}
                  >
                    <option value={5}>5</option>
                    <option value={10}>10</option>
                    <option value={25}>25</option>
                    <option value={50}>50</option>
                  </select>
                </div>
                <div className="pagination-right">
                  <span>
                    {assetGroupStartIndex + 1}-{Math.min(assetGroupEndIndex, filteredAssetGroups.length)} of {filteredAssetGroups.length}
                  </span>
                  <div className="pagination-arrows">
                    <button
                      className="pagination-btn"
                      onClick={() => setAssetGroupCurrentPage(prev => Math.max(1, prev - 1))}
                      disabled={assetGroupCurrentPage === 1}
                    >
                      ←
                    </button>
                    <button
                      className="pagination-btn"
                      onClick={() => setAssetGroupCurrentPage(prev => Math.min(assetGroupTotalPages, prev + 1))}
                      disabled={assetGroupCurrentPage === assetGroupTotalPages}
                    >
                      →
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* Other tabs placeholder */}
      {activeTab !== 'domains' && activeTab !== 'subdomains' && activeTab !== 'ip-addresses' && activeTab !== 'url' && activeTab !== 'asset-groups' && (
        <div className="coming-soon">Coming soon</div>
      )}

      {/* Add Domain Modal */}
      {showAddModal && (
        <div className="modal-overlay" onClick={() => setShowAddModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Add New Domain</h2>
            <form onSubmit={handleAddDomain}>
              <div className="form-group">
                <label>Name</label>
                <input
                  type="text"
                  value={newDomain.name}
                  onChange={(e) =>
                    setNewDomain({ ...newDomain, name: e.target.value })
                  }
                  placeholder="example.com"
                  required
                />
              </div>
              <div className="form-group">
                <label>Tags</label>
                <input
                  type="text"
                  value={newDomain.tags}
                  onChange={(e) =>
                    setNewDomain({ ...newDomain, tags: e.target.value })
                  }
                  placeholder="production, external"
                />
              </div>
              <div className="form-actions">
                <button type="submit" className="btn-primary">
                  Add Domain
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setShowAddModal(false)}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Subdomain Modal */}
      {showAddSubdomainModal && (
        <div className="modal-overlay" onClick={() => setShowAddSubdomainModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Add New Subdomain</h2>
            <form onSubmit={handleAddSubdomain}>
              <div className="form-group">
                <label>Domain</label>
                <select
                  value={newSubdomain.domainId}
                  onChange={(e) =>
                    setNewSubdomain({ ...newSubdomain, domainId: e.target.value })
                  }
                  required
                >
                  <option value="">Select a domain</option>
                  {domains.map((domain) => (
                    <option key={domain.id} value={domain.id}>
                      {domain.domain_name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label>Subdomain Name</label>
                <input
                  type="text"
                  value={newSubdomain.name}
                  onChange={(e) =>
                    setNewSubdomain({ ...newSubdomain, name: e.target.value })
                  }
                  placeholder="api.example.com"
                  required
                />
              </div>
              <div className="form-group">
                <label>Tags </label>
                <input
                  type="text"
                  value={newSubdomain.tags}
                  onChange={(e) =>
                    setNewSubdomain({ ...newSubdomain, tags: e.target.value })
                  }
                  placeholder="production, external"
                />
              </div>
              <div className="form-actions">
                <button type="submit" className="btn-primary">
                  Add Subdomain
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setShowAddSubdomainModal(false)}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add IP Address Modal */}
      {showAddIpModal && (
        <div className="modal-overlay" onClick={() => setShowAddIpModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Add IP Address</h2>
            <form onSubmit={handleAddIpAddress}>
              <div className="form-group">
                <label>Domain</label>
                <select
                  value={newIpAddress.domainId}
                  onChange={(e) =>
                    setNewIpAddress({ ...newIpAddress, domainId: e.target.value })
                  }
                  required
                >
                  <option value="">Select a domain</option>
                  {domains.map((domain) => (
                    <option key={domain.id} value={domain.id}>
                      {domain.domain_name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label>IP Address</label>
                <input
                  type="text"
                  value={newIpAddress.ip}
                  onChange={(e) =>
                    setNewIpAddress({ ...newIpAddress, ip: e.target.value })
                  }
                  placeholder="93.184.216.34"
                  required
                />
              </div>
              <div className="form-group">
                <label>Tags</label>
                <input
                  type="text"
                  value={newIpAddress.tags}
                  onChange={(e) =>
                    setNewIpAddress({ ...newIpAddress, tags: e.target.value })
                  }
                  placeholder="production, external"
                />
              </div>
              <div className="form-actions">
                <button type="submit" className="btn-primary">
                  Add IP Address
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setShowAddIpModal(false)}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add URL Modal */}
      {showAddUrlModal && (
        <div className="modal-overlay" onClick={() => setShowAddUrlModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Add URL</h2>
            <form onSubmit={handleAddUrl}>
              <div className="form-group">
                <label>Domain</label>
                <select
                  value={newUrl.domainId}
                  onChange={(e) =>
                    setNewUrl({ ...newUrl, domainId: e.target.value })
                  }
                  required
                >
                  <option value="">Select a domain</option>
                  {domains.map((domain) => (
                    <option key={domain.id} value={domain.id}>
                      {domain.domain_name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label>URL</label>
                <input
                  type="text"
                  value={newUrl.url}
                  onChange={(e) =>
                    setNewUrl({ ...newUrl, url: e.target.value })
                  }
                  placeholder="https://example.com/login"
                  required
                />
              </div>
              <div className="form-group">
                <label>Tags</label>
                <input
                  type="text"
                  value={newUrl.tags}
                  onChange={(e) =>
                    setNewUrl({ ...newUrl, tags: e.target.value })
                  }
                  placeholder="login, production"
                />
              </div>
              <div className="form-actions">
                <button type="submit" className="btn-primary">
                  Add URL
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setShowAddUrlModal(false)}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Asset Group Modal */}
      {showAddAssetGroupModal && (
        <div className="modal-overlay" onClick={() => setShowAddAssetGroupModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Add Asset Group</h2>
            <form onSubmit={handleAddAssetGroup}>
              <div className="form-group">
                <label>Name</label>
                <input
                  type="text"
                  value={newAssetGroup.name}
                  onChange={(e) =>
                    setNewAssetGroup({ ...newAssetGroup, name: e.target.value })
                  }
                  placeholder="Customer APIs"
                  required
                />
              </div>
              <div className="form-group">
                <label>Domain</label>
                <select
                  value={newAssetGroup.domainId}
                  onChange={(e) =>
                    setNewAssetGroup({ ...newAssetGroup, domainId: e.target.value })
                  }
                  required
                >
                  <option value="">Select a domain</option>
                  {domains.map((domain) => (
                    <option key={domain.id} value={domain.id}>
                      {domain.domain_name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label>Asset Type</label>
                <select
                  value={newAssetGroup.assetType}
                  onChange={(e) =>
                    setNewAssetGroup({ ...newAssetGroup, assetType: e.target.value, assetIds: [] })
                  }
                  required
                >
                  <option value="SUBDOMAIN">Subdomain</option>
                  <option value="IP">IP</option>
                </select>
              </div>
              <div className="form-group">
                <label>Select Assets (max 5)</label>
                {!newAssetGroup.domainId ? (
                  <div className="helper-text">Select a domain first.</div>
                ) : (
                  <div className="asset-select-list">
                    {(newAssetGroup.assetType === 'SUBDOMAIN' ? selectedDomainSubdomains : selectedDomainIps).map((item) => {
                      const id = item.id;
                      const label = newAssetGroup.assetType === 'SUBDOMAIN' ? item.subdomain_name : item.ipaddress_name;
                      const checked = newAssetGroup.assetIds.includes(id);
                      const disabled = !checked && newAssetGroup.assetIds.length >= 5;
                      return (
                        <label key={id} className={`asset-select-item ${disabled ? 'disabled' : ''}`}>
                          <input
                            type="checkbox"
                            checked={checked}
                            disabled={disabled}
                            onChange={() => toggleAssetSelection(id)}
                          />
                          <span>{label}</span>
                        </label>
                      );
                    })}
                    {(newAssetGroup.assetType === 'SUBDOMAIN' ? selectedDomainSubdomains : selectedDomainIps).length === 0 && (
                      <div className="helper-text">No assets found for this domain.</div>
                    )}
                  </div>
                )}
                <div className="helper-text">{newAssetGroup.assetIds.length} / 5 selected</div>
              </div>
              <div className="form-group">
                <label>Description (optional)</label>
                <textarea
                  value={newAssetGroup.description}
                  onChange={(e) =>
                    setNewAssetGroup({ ...newAssetGroup, description: e.target.value })
                  }
                  placeholder="Short description of this asset group"
                  rows={3}
                />
              </div>
              <div className="form-actions">
                <button type="submit" className="btn-primary">
                  Add Asset Group
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setShowAddAssetGroupModal(false)}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default AssetDiscovery;
