import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import PhishingDetail from './PhishingDetail';

// Types
interface PhishingSite {
  id: string;
  url: string;
  domain: string;
  status: 'active' | 'monitoring' | 'taken-down';
  first_detected: string;
  last_checked: string;
  similarity_score: number;
  visual_similarity?: number;
  content_similarity?: number;
  url_similarity?: number;
  ml_confidence?: number;
  features_detected: string[];
  ip_address?: string;
  country_code?: string;
  hosting_provider?: string;
  registration_date?: string;
  has_login_form: boolean;
  has_tamm_logo: boolean;
  screenshot_path?: string;
  target_page: string;
}

interface ScanProgress {
  scan_id: string;
  status: string;
  progress: number;
  sites_found: number;
  started_at: string;
  estimated_completion?: string;
}

interface PhishingStats {
  total_sites: number;
  active_sites: number;
  taken_down_sites: number;
  average_similarity: number;
  by_target_page: Record<string, number>;
  by_country: Record<string, number>;
  by_status: Record<string, number>;
  detection_trend: Record<string, number>;
}

const PhishingDetection: React.FC = () => {
  // State variables
  const [sites, setSites] = useState<PhishingSite[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<PhishingStats | null>(null);
  const [activeTab, setActiveTab] =
  
  // Filter state
  const [timeRange, setTimeRange] = useState('30');
  const [searchQuery, setSearchQuery] = useState('');
  const [thresholdScore, setThresholdScore] = useState(60);
  const [targetFilter, setTargetFilter] = useState('all');
  const [sortBy, setSortBy] = useState('first_detected');
  const [sortOrder, setSortOrder] = useState('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const pageSize = 10;

  // Fetch phishing sites
  const fetchSites = async () => {
    try {
      setLoading(true);
      
      // Build query parameters
      let queryParams = new URLSearchParams({
        page: currentPage.toString(),
        page_size: pageSize.toString(),
        sort_by: sortBy,
        sort_order: sortOrder,
      });
      
      // Add optional filters
      if (searchQuery) queryParams.append('search', searchQuery);
      if (thresholdScore > 0) queryParams.append('min_similarity', thresholdScore.toString());
      if (targetFilter !== 'all') queryParams.append('target_page', targetFilter);
      if (timeRange !== 'all') queryParams.append('days', timeRange);
      
      // Add status filter based on active tab
      if (activeTab !== 'all') {
        if (activeTab === 'detected') {
          queryParams.append('status', 'active');
        } else if (activeTab === 'mitigated') {
          queryParams.append('status', 'taken-down');
        }
      }
      
      const response = await fetch(`/api/phishing/sites?${queryParams.toString()}`);
      
      if (!response.ok) {
        throw new Error(`Error fetching phishing sites: ${response.statusText}`);
      }
      
      const data = await response.json();
      setSites(data);
      
      // Calculate total pages
      const totalCount = parseInt(response.headers.get('X-Total-Count') || '0');
      setTotalPages(Math.ceil(totalCount / pageSize) || 1);
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
      console.error('Error fetching phishing sites:', err);
    } finally {
      setLoading(false);
    }
  };

  // Fetch phishing statistics
  const fetchStats = async () => {
    try {
      const response = await fetch('/api/phishing/stats');
      
      if (!response.ok) {
        throw new Error(`Error fetching phishing stats: ${response.statusText}`);
      }
      
      const data = await response.json();
      setStats(data);
    } catch (err) {
      console.error('Error fetching phishing stats:', err);
    }
  };

  // Start a new scan
  const startScan = async () => {
    try {
      setScanInProgress(true);
      
      // Prepare scan request
      const scanRequest = {
        check_typosquatting: true,
        depth: 1
      };
      
      // Start scan
      const response = await fetch('/api/phishing/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(scanRequest)
      });
      
      if (!response.ok) {
        throw new Error(`Error starting scan: ${response.statusText}`);
      }
      
      const scanData = await response.json();
      setScanProgress(scanData);
      
      // Start polling for scan progress
      const interval = setInterval(async () => {
        await checkScanProgress(scanData.scan_id);
      }, 3000);
      
      setScanInterval(interval);
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan');
      setScanInProgress(false);
    }
  };

  // Check scan progress
  const checkScanProgress = async (scanId: string) => {
    try {
      const response = await fetch(`/api/phishing/scan/${scanId}`);
      
      if (!response.ok) {
        throw new Error(`Error checking scan progress: ${response.statusText}`);
      }
      
      const progressData = await response.json();
      setScanProgress(progressData);
      
      // If scan is complete, stop polling and refresh data
      if (progressData.status === 'completed' || progressData.status === 'error') {
        if (scanInterval) {
          clearInterval(scanInterval);
          setScanInterval(null);
        }
        setScanInProgress(false);
        fetchSites();
        fetchStats();
      }
      
    } catch (err) {
      console.error('Error checking scan progress:', err);
      if (scanInterval) {
        clearInterval(scanInterval);
        setScanInterval(null);
      }
      setScanInProgress(false);
    }
  };

  // Handle site status change
  const updateSiteStatus = async (siteId: string, status: string) => {
    try {
      const response = await fetch(`/api/phishing/sites/${siteId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status })
      });
      
      if (!response.ok) {
        throw new Error(`Error updating site: ${response.statusText}`);
      }
      
      // Refresh data
      fetchSites();
      fetchStats();
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update site');
    }
  };

  // Report a phishing site
  const reportSite = async (siteId: string) => {
    try {
      const response = await fetch(`/api/phishing/report/${siteId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        throw new Error(`Error reporting site: ${response.statusText}`);
      }
      
      // Refresh data
      fetchSites();
      
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to report site');
    }
  };

  // Check a single URL
  const checkSingleUrl = async (url: string, targetPage: string = 'main') => {
    try {
      const formData = new FormData();
      formData.append('url', url);
      formData.append('target_page', targetPage);
      
      const response = await fetch('/api/phishing/check', {
        method: 'POST',
        body: formData
      });
      
      if (!response.ok) {
        throw new Error(`Error checking URL: ${response.statusText}`);
      }
      
      const result = await response.json();
      
      // Refresh data
      fetchSites();
      
      return result;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to check URL');
      return null;
    }
  };

  // Get status badge for a site
  const getSiteStatusBadge = (status: string) => {
    switch (status) {
      case 'active':
        return <span className="px-2 py-1 bg-red-900 text-red-100 text-xs rounded-full">Active</span>;
      case 'monitoring':
        return <span className="px-2 py-1 bg-yellow-800 text-yellow-100 text-xs rounded-full">Monitoring</span>;
      case 'taken-down':
        return <span className="px-2 py-1 bg-green-900 text-green-100 text-xs rounded-full">Taken Down</span>;
      default:
        return <span className="px-2 py-1 bg-gray-800 text-gray-100 text-xs rounded-full">Unknown</span>;
    }
  };

  // Get similarity badge
  const getSimilarityBadge = (score: number) => {
    if (score >= 90) {
      return <span className="px-2 py-1 bg-red-900 text-red-100 text-xs rounded-full">{score.toFixed(1)}%</span>;
    } else if (score >= 75) {
      return <span className="px-2 py-1 bg-orange-800 text-orange-100 text-xs rounded-full">{score.toFixed(1)}%</span>;
    } else {
      return <span className="px-2 py-1 bg-yellow-800 text-yellow-100 text-xs rounded-full">{score.toFixed(1)}%</span>;
    }
  };

  // Init effect - fetch sites and stats on component mount
  useEffect(() => {
    fetchSites();
    fetchStats();
    
    // Clean up interval on unmount
    return () => {
      if (scanInterval) {
        clearInterval(scanInterval);
      }
    };
  }, []);

  // Effect to refetch when filters change
  useEffect(() => {
    fetchSites();
  }, [
    activeTab,
    timeRange,
    searchQuery,
    thresholdScore,
    targetFilter,
    sortBy,
    sortOrder,
    currentPage
  ]);

  return (
    <div className="bg-gray-900 text-white min-h-screen">
      <div className="container mx-auto px-4 py-8">
        <header className="mb-8">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between">
            <h1 className="text-3xl font-bold text-dark-cyan mb-4 md:mb-0">Phishing Detection for Tamm Abu Dhabi</h1>
            
            <button
              onClick={startScan}
              disabled={scanInProgress}
              className={`flex items-center justify-center px-4 py-2 rounded font-medium ${
                scanInProgress
                  ? "bg-gray-700 text-gray-400 cursor-not-allowed"
                  : "bg-dark-cyan text-white hover:bg-opacity-90"
              }`}
            >
              {scanInProgress ? (
                <>
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Scanning ({scanProgress ? Math.round(scanProgress.progress) : 0}%)
                </>
              ) : (
                <>
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
                  </svg>
                  Start New Scan
                </>
              )}
            </button>
          </div>
          
          {scanProgress && scanInProgress && (
            <div className="mt-4 bg-gray-800 p-4 rounded-lg">
              <div className="flex justify-between mb-2">
                <span>Scan in progress...</span>
                <span>{scanProgress.sites_found} phishing sites found</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2.5">
                <div 
                  className="bg-dark-cyan h-2.5 rounded-full" 
                  style={{ width: `${scanProgress.progress}%` }}
                ></div>
              </div>
              {scanProgress.estimated_completion && (
                <div className="text-xs text-gray-400 mt-1 text-right">
                  Estimated completion: {new Date(scanProgress.estimated_completion).toLocaleTimeString()}
                </div>
              )}
            </div>
          )}
        </header>
        
        {/* Stats summary */}
        {stats && (
          <div className="mb-8 grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-gray-400 text-sm">Total Sites</div>
              <div className="text-2xl font-bold">{stats.total_sites}</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-gray-400 text-sm">Active Sites</div>
              <div className="text-2xl font-bold text-red-500">{stats.active_sites}</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-gray-400 text-sm">Mitigated Sites</div>
              <div className="text-2xl font-bold text-green-500">{stats.taken_down_sites}</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-gray-400 text-sm">Avg. Similarity</div>
              <div className="text-2xl font-bold">{stats.average_similarity.toFixed(1)}%</div>
            </div>
          </div>
        )}
        
        {/* Tabs */}
        <div className="flex border-b border-gray-800 mb-6">
          <button
            className={`py-2 px-4 font-medium ${
              activeTab === "detected"
                ? "text-dark-cyan border-b-2 border-dark-cyan"
                : "text-gray-400 hover:text-gray-300"
            }`}
            onClick={() => setActiveTab("detected")}
          >
            Detected Sites
          </button>
          <button
            className={`py-2 px-4 font-medium ${
              activeTab === "mitigated"
                ? "text-dark-cyan border-b-2 border-dark-cyan"
                : "text-gray-400 hover:text-gray-300"
            }`}
            onClick={() => setActiveTab("mitigated")}
          >
            Mitigated
          </button>
          <button
            className={`py-2 px-4 font-medium ${
              activeTab === "all"
                ? "text-dark-cyan border-b-2 border-dark-cyan"
                : "text-gray-400 hover:text-gray-300"
            }`}
            onClick={() => setActiveTab("all")}
          >
            All Sites
          </button>
        </div>

        {/* Filters */}
        <div className="bg-gray-900 rounded-lg p-6 mb-8 border border-dark-cyan">
          <h3 className="text-lg font-medium text-dark-cyan mb-4">Filters</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <label className="block text-gray-300 mb-2 text-sm">Time Range</label>
              <select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
                className="w-full bg-gray-800 text-white p-2 rounded border border-gray-700"
              >
                <option value="7">Last 7 days</option>
                <option value="30">Last 30 days</option>
                <option value="90">Last 3 months</option>
                <option value="all">All time</option>
              </select>
            </div>
            
            <div>
              <label className="block text-gray-300 mb-2 text-sm">Similarity Threshold</label>
              <div className="flex items-center">
                <input
                  type="range"
                  min="50"
                  max="100"
                  value={thresholdScore}
                  onChange={(e) => setThresholdScore(parseInt(e.target.value))}
                  className="w-full mr-2"
                />
                <span className="text-white">{thresholdScore}%</span>
              </div>
            </div>
            
            <div>
              <label className="block text-gray-300 mb-2 text-sm">Target Page</label>
              <select
                value={targetFilter}
                onChange={(e) => setTargetFilter(e.target.value)}
                className="w-full bg-gray-800 text-white p-2 rounded border border-gray-700"
              >
                <option value="all">All Pages</option>
                <option value="main">Main Website</option>
                <option value="login">Login Page</option>
                <option value="payments">Payments</option>
                <option value="business-services">Business Services</option>
              </select>
            </div>
            
            <div>
              <label className="block text-gray-300 mb-2 text-sm">Search URLs</label>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search for domains..."
                className="w-full bg-gray-800 text-white p-2 rounded border border-gray-700"
              />
            </div>
          </div>
          
          <div className="mt-4 flex justify-end">
            <button
              onClick={() => {
                setTimeRange('30');
                setSearchQuery('');
                setThresholdScore(60);
                setTargetFilter('all');
                setCurrentPage(1);
              }}
              className="px-4 py-2 bg-gray-800 text-gray-300 rounded hover:bg-gray-700 transition"
            >
              Reset Filters
            </button>
          </div>
        </div>

        {/* URL check form */}
        <div className="bg-gray-900 rounded-lg p-6 mb-8 border border-dark-cyan">
          <h3 className="text-lg font-medium text-dark-cyan mb-4">Check Specific URL</h3>
          <div className="flex flex-col md:flex-row gap-4">
            <input
              type="text"
              id="url-to-check"
              placeholder="Enter URL to check (e.g., https://suspicious-site.com)"
              className="flex-1 bg-gray-800 text-white p-2 rounded border border-gray-700"
            />
            
            <select
              id="target-page"
              className="md:w-48 bg-gray-800 text-white p-2 rounded border border-gray-700"
            >
              <option value="main">Main Page</option>
              <option value="login">Login Page</option>
              <option value="payments">Payments Page</option>
              <option value="business-services">Business Services</option>
            </select>
            
            <button
              onClick={() => {
                const url = (document.getElementById('url-to-check') as HTMLInputElement).value;
                const targetPage = (document.getElementById('target-page') as HTMLSelectElement).value;
                if (url) {
                  checkSingleUrl(url, targetPage);
                }
              }}
              className="px-4 py-2 bg-dark-cyan text-white rounded hover:bg-opacity-90"
            >
              Check URL
            </button>
          </div>
        </div>

        {/* Results */}
        {loading ? (
          <div className="flex justify-center items-center p-12">
            <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-dark-cyan"></div>
          </div>
        ) : error ? (
          <div className="bg-red-900 text-white p-4 rounded-lg">
            <p className="font-bold">Error</p>
            <p>{error}</p>
          </div>
        ) : sites.length === 0 ? (
          <div className="text-center p-12 bg-gray-900 rounded-lg border border-gray-800">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-16 w-16 mx-auto text-gray-600 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <h3 className="text-xl font-medium text-gray-400 mb-2">No phishing sites found</h3>
            <p className="text-gray-500 mb-4">No phishing sites match your current filter criteria.</p>
          </div>
        ) : (
          <div className="space-y-6">
            {sites.map((site) => (
              <motion.div
                key={site.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-gray-900 rounded-lg p-6 border border-dark-cyan shadow-md"
              >
                <div className="flex flex-col md:flex-row md:justify-between md:items-start gap-6">
                  <div className="flex-1">
                    <div className="flex items-start justify-between mb-2">
                      <h3 className="text-xl font-bold text-white break-all">{site.url}</h3>
                      <div className="flex items-center space-x-2 ml-4">
                        {getSiteStatusBadge(site.status)}
                        {getSimilarityBadge(site.similarity_score)}
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                      <div>
                        <h4 className="text-dark-cyan font-medium mb-2">Detection Details</h4>
                        <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                          <div>
                            <span className="text-gray-400">Detected:</span>
                            <div className="text-white">{new Date(site.first_detected).toLocaleDateString()}</div>
                          </div>
                          <div>
                            <span className="text-gray-400">ML Confidence:</span>
                            <div className="text-white">{site.ml_confidence ? (site.ml_confidence * 100).toFixed(1) : 'N/A'}%</div>
                          </div>
                          <div>
                            <span className="text-gray-400">Target Page:</span>
                            <div className="text-white capitalize">{site.target_page.replace('-', ' ')}</div>
                          </div>
                          <div>
                            <span className="text-gray-400">Last Checked:</span>
                            <div className="text-white">{new Date(site.last_checked).toLocaleDateString()}</div>
                          </div>
                        </div>
                      </div>
                      
                      <div>
                        <h4 className="text-dark-cyan font-medium mb-2">Technical Information</h4>
                        <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                          <div>
                            <span className="text-gray-400">IP Address:</span>
                            <div className="text-white">{site.ip_address || 'Unknown'}</div>
                          </div>
                          <div>
                            <span className="text-gray-400">Country:</span>
                            <div className="text-white">{site.country_code || 'Unknown'}</div>
                          </div>
                          <div className="col-span-2">
                            <span className="text-gray-400">Hosting:</span>
                            <div className="text-white">{site.hosting_provider || 'Unknown'}</div>
                          </div>
                        </div>
                      </div>
                    </div>
                    
                    <div>
                      <h4 className="text-dark-cyan font-medium mb-2">Similarity Analysis</h4>
                      <div className="grid grid-cols-3 gap-4 mb-4">
                        <div>
                          <div className="text-gray-400 text-xs mb-1">Visual Similarity</div>
                          <div className="w-full bg-gray-800 rounded-full h-4">
                            <div 
                              className="bg-dark-cyan h-4 rounded-full" 
                              style={{ width: `${site.visual_similarity || 0}%` }}
                            ></div>
                          </div>
                          <div className="text-right text-xs text-gray-400 mt-1">{site.visual_similarity?.toFixed(1) || 0}%</div>
                        </div>
                        <div>
                          <div className="text-gray-400 text-xs mb-1">Content Similarity</div>
                          <div className="w-full bg-gray-800 rounded-full h-4">
                            <div 
                              className="bg-dark-cyan h-4 rounded-full" 
                              style={{ width: `${site.content_similarity || 0}%` }}
                            ></div>
                          </div>
                          <div className="text-right text-xs text-gray-400 mt-1">{site.content_similarity?.toFixed(1) || 0}%</div>
                        </div>
                        <div>
                          <div className="text-gray-400 text-xs mb-1">URL Similarity</div>
                          <div className="w-full bg-gray-800 rounded-full h-4">
                            <div 
                              className="bg-dark-cyan h-4 rounded-full" 
                              style={{ width: `${site.url_similarity || 0}%` }}
                            ></div>
                          </div>
                          <div className="text-right text-xs text-gray-400 mt-1">{site.url_similarity?.toFixed(1) || 0}%</div>
                        </div>
                      </div>
                      
                      <div>
                        <div className="text-gray-400 text-xs mb-2">Detected Features</div>
                        <div className="flex flex-wrap gap-2">
                          {site.features_detected.map((feature, idx) => (
                            <span key={idx} className="px-2 py-1 bg-gray-800 text-gray-300 text-xs rounded">
                              {feature.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="w-full md:w-64 shrink-0">
                    <div className="bg-gray-800 rounded-lg p-3 border border-gray-700">
                      <div className="text-gray-400 text-xs mb-2 font-medium">Screenshot Preview</div>
                      <div className="aspect-video bg-gray-700 rounded flex items-center justify-center mb-2">
                        {site.screenshot_path ? (
                          <img 
                            src={site.screenshot_path} 
                            alt="Phishing site screenshot" 
                            className="w-full h-full object-cover rounded"
                          />
                        ) : (
                          <div className="text-gray-500 text-xs">Screenshot not available</div>
                        )}
                      </div>
                      <div className="flex space-x-2">
                        <button 
                          className="flex-1 bg-dark-cyan text-white py-1 px-2 rounded text-sm"
                          onClick={() => window.open(`/api/phishing/screenshot/${site.id}`, '_blank')}
                        >
                          View Full
                        </button>
                        <button className="flex-1 bg-gray-700 text-white py-1 px-2 rounded text-sm">
                          Compare
                        </button>
                      </div>
                    </div>
                    
                    <div className="mt-4 space-y-2">
                      <button 
                        className="w-full bg-red-900 hover:bg-red-800 text-white py-2 px-4 rounded text-sm flex items-center justify-center"
                        onClick={() => reportSite(site.id)}
                      >
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2" viewBox="0 0 20 20" fill="currentColor">
                          <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                        </svg>
                        Report Site
                      </button>
                      
                      {site.status !== 'taken-down' && (
                        <button 
                          className="w-full bg-green-900 hover:bg-green-800 text-white py-2 px-4 rounded text-sm flex items-center justify-center"
                          onClick={() => updateSiteStatus(site.id, 'taken-down')}
                        >
                          <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2" viewBox="0 0 20 20" fill="currentColor">
                            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                          </svg>
                          Mark as Mitigated
                        </button>
                      )}
                      
                      <button
                        className="w-full bg-gray-800 hover:bg-gray-700 text-white py-2 px-4 rounded text-sm flex items-center justify-center"
                        onClick={() => {
                          const confirmed = window.confirm(`Are you sure you want to block domain ${site.domain}?`);
                          if (confirmed) {
                            // In a real implementation, this would trigger domain blocking
                            alert(`Domain ${site.domain} has been added to block list`);
                          }
                        }}
                      >
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2" viewBox="0 0 20 20" fill="currentColor">
                          <path d="M4 3a2 2 0 100 4h12a2 2 0 100-4H4z" />
                          <path fillRule="evenodd" d="M3 8h14v7a2 2 0 01-2 2H5a2 2 0 01-2-2V8zm5 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z" clipRule="evenodd" />
                        </svg>
                        Block Domain
                      </button>
                    </div>
                  </div>
                </div>
              </motion.div>
            ))}
            
            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex justify-center mt-8">
                <nav className="flex items-center space-x-2">
                  <button
                    onClick={() => setCurrentPage(Math.max(currentPage - 1, 1))}
                    disabled={currentPage <= 1}
                    className={`px-3 py-1 rounded ${
                      currentPage <= 1
                        ? "bg-gray-800 text-gray-500 cursor-not-allowed"
                        : "bg-gray-800 text-white hover:bg-gray-700"
                    }`}
                  >
                    Previous
                  </button>
                  
                  {[...Array(totalPages).keys()].map((page) => (
                    <button
                      key={page + 1}
                      onClick={() => setCurrentPage(page + 1)}
                      className={`px-3 py-1 rounded ${
                        currentPage === page + 1
                          ? "bg-dark-cyan text-white"
                          : "bg-gray-800 text-white hover:bg-gray-700"
                      }`}
                    >
                      {page + 1}
                    </button>
                  ))}
                  
                  <button
                    onClick={() => setCurrentPage(Math.min(currentPage + 1, totalPages))}
                    disabled={currentPage >= totalPages}
                    className={`px-3 py-1 rounded ${
                      currentPage >= totalPages
                        ? "bg-gray-800 text-gray-500 cursor-not-allowed"
                        : "bg-gray-800 text-white hover:bg-gray-700"
                    }`}
                  >
                    Next
                  </button>
                </nav>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default PhishingDetection;