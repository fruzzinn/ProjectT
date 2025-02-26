'use client'
import React, { useState, useEffect } from "react";
import { motion } from "framer-motion";

// Dashboard components
const Dashboard = () => {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  return (
    <div className="bg-black text-white min-h-screen">
      {/* Header */}
      <motion.header
        initial={{ y: -50, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.8 }}
        className="bg-dark-cyan w-full py-4 text-center font-bold shadow-md sticky top-0 z-50"
      >
        <div className="container mx-auto px-4 flex justify-between items-center">
          <h1 className="text-2xl">Cyber Threat Intelligence Platform</h1>
          <nav className="hidden md:block">
            <ul className="flex space-x-6">
              <li className={`cursor-pointer ${activeTab === "dashboard" ? "text-white" : "text-gray-300 hover:text-white"}`} 
                  onClick={() => setActiveTab("dashboard")}>Dashboard</li>
              <li className={`cursor-pointer ${activeTab === "threats" ? "text-white" : "text-gray-300 hover:text-white"}`}
                  onClick={() => setActiveTab("threats")}>Threats</li>
              <li className={`cursor-pointer ${activeTab === "phishing" ? "text-white" : "text-gray-300 hover:text-white"}`}
                  onClick={() => setActiveTab("phishing")}>Phishing Detection</li>
              <li className={`cursor-pointer ${activeTab === "actors" ? "text-white" : "text-gray-300 hover:text-white"}`}
                  onClick={() => setActiveTab("actors")}>Threat Actors</li>
              <li className={`cursor-pointer ${activeTab === "indicators" ? "text-white" : "text-gray-300 hover:text-white"}`}
                  onClick={() => setActiveTab("indicators")}>IOCs</li>
            </ul>
          </nav>
          <div className="md:hidden">
            <button className="text-white">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
          </div>
        </div>
      </motion.header>

      {/* Main content */}
      <main className="container mx-auto px-4 py-8">
        {activeTab === "dashboard" && <DashboardView />}
        {activeTab === "threats" && <ThreatsView />}
        {activeTab === "phishing" && <PhishingView />}
        {activeTab === "actors" && <ActorsView />}
        {activeTab === "indicators" && <IndicatorsView />}
      </main>

      {/* Footer */}
      <footer className="bg-gray-900 text-center p-4 mt-auto">
        <div className="container mx-auto">
          <p className="text-gray-400">© {new Date().getFullYear()} Cyber Threat Intelligence Platform</p>
        </div>
      </footer>
    </div>
  );
};

// Phishing Detection View
const PhishingView = () => {
  const [phishingSites, setPhishingSites] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [timeRange, setTimeRange] = useState("30");
  const [searchQuery, setSearchQuery] = useState("");
  const [thresholdScore, setThresholdScore] = useState(60);
  const [targetFilter, setTargetFilter] = useState("all");
  const [activeTab, setActiveTab] = useState("detected");
  const [scanInProgress, setScanInProgress] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);

  // Mock data for demonstration purposes
  const mockPhishingSites = [
    {
      id: "ps-001",
      url: "https://tam-m-abudhabi.com",
      detectedDate: "2025-02-15T08:30:00Z",
      similarityScore: 92,
      status: "active",
      screenshot: "/phishing1.jpg",
      targetPage: "main",
      mlConfidence: 0.95,
      registrationDate: "2025-02-01T10:15:00Z",
      ipAddress: "203.0.113.42",
      hostingProvider: "ShadyHost LLC",
      countryCode: "RU",
      visualSimilarity: 87,
      contentSimilarity: 94,
      urlSimilarity: 89,
      featuresDetected: ["fake-login", "logo-clone", "similar-layout", "ssl-missing"]
    },
    {
      id: "ps-002",
      url: "https://tamm.service-abudhabi.net",
      detectedDate: "2025-02-18T14:45:00Z",
      similarityScore: 88,
      status: "active",
      screenshot: "/phishing2.jpg",
      targetPage: "login",
      mlConfidence: 0.92,
      registrationDate: "2025-02-10T12:20:00Z",
      ipAddress: "198.51.100.78",
      hostingProvider: "PhishyCloud Services",
      countryCode: "CN",
      visualSimilarity: 82,
      contentSimilarity: 91,
      urlSimilarity: 84,
      featuresDetected: ["fake-login", "logo-clone", "data-harvesting", "ssl-valid"]
    },
    {
      id: "ps-003",
      url: "https://tamm-abudhabi-services.org",
      detectedDate: "2025-02-20T09:10:00Z",
      similarityScore: 76,
      status: "monitoring",
      screenshot: "/phishing3.jpg",
      targetPage: "payments",
      mlConfidence: 0.86,
      registrationDate: "2025-02-12T16:40:00Z",
      ipAddress: "45.33.21.18",
      hostingProvider: "DarkHost Inc.",
      countryCode: "NG",
      visualSimilarity: 74,
      contentSimilarity: 82,
      urlSimilarity: 78,
      featuresDetected: ["payment-form", "logo-clone", "similar-layout"]
    },
    {
      id: "ps-004",
      url: "https://tammabudhabiportal.com",
      detectedDate: "2025-02-22T11:25:00Z",
      similarityScore: 85,
      status: "taken-down",
      screenshot: "/phishing4.jpg",
      targetPage: "main",
      mlConfidence: 0.91,
      registrationDate: "2025-02-05T09:30:00Z",
      ipAddress: "91.234.56.78",
      hostingProvider: "BlackHole Hosting",
      countryCode: "UA",
      visualSimilarity: 81,
      contentSimilarity: 88,
      urlSimilarity: 79,
      featuresDetected: ["fake-login", "logo-clone", "email-harvesting"]
    },
    {
      id: "ps-005",
      url: "https://abudhabi-tamm-gov.site",
      detectedDate: "2025-02-24T15:20:00Z",
      similarityScore: 65,
      status: "monitoring",
      screenshot: "/phishing5.jpg",
      targetPage: "business-services",
      mlConfidence: 0.72,
      registrationDate: "2025-02-15T14:10:00Z",
      ipAddress: "185.128.43.89",
      hostingProvider: "EvilHost Co.",
      countryCode: "RO",
      visualSimilarity: 61,
      contentSimilarity: 73,
      urlSimilarity: 68,
      featuresDetected: ["similar-layout", "business-form", "document-upload"]
    }
  ];

  useEffect(() => {
    // Simulate API fetch
    const fetchPhishingSites = async () => {
      try {
        setLoading(true);
        // In a real implementation, this would be an API call
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        // Filter mock data based on current filters
        let filtered = [...mockPhishingSites];
        
        // Apply time range filter
        if (timeRange !== "all") {
          const cutoffDate = new Date();
          cutoffDate.setDate(cutoffDate.getDate() - parseInt(timeRange));
          filtered = filtered.filter(site => new Date(site.detectedDate) >= cutoffDate);
        }
        
        // Apply search filter
        if (searchQuery) {
          const query = searchQuery.toLowerCase();
          filtered = filtered.filter(site => 
            site.url.toLowerCase().includes(query) || 
            site.targetPage.toLowerCase().includes(query)
          );
        }
        
        // Apply threshold filter
        filtered = filtered.filter(site => site.similarityScore >= thresholdScore);
        
        // Apply target filter
        if (targetFilter !== "all") {
          filtered = filtered.filter(site => site.targetPage === targetFilter);
        }
        
        // Apply status filter based on active tab
        if (activeTab !== "all") {
          if (activeTab === "detected") {
            filtered = filtered.filter(site => site.status === "active" || site.status === "monitoring");
          } else if (activeTab === "mitigated") {
            filtered = filtered.filter(site => site.status === "taken-down");
          }
        }
        
        setPhishingSites(filtered);
      } catch (err) {
        console.error("Error fetching phishing sites:", err);
        setError("Failed to load phishing detection data.");
      } finally {
        setLoading(false);
      }
    };

    fetchPhishingSites();
  }, [timeRange, searchQuery, thresholdScore, targetFilter, activeTab]);

  const startScan = () => {
    setScanInProgress(true);
    setScanProgress(0);
    
    // Simulate scan progress
    const interval = setInterval(() => {
      setScanProgress(prev => {
        const newProgress = prev + Math.random() * 15;
        if (newProgress >= 100) {
          clearInterval(interval);
          setTimeout(() => {
            setScanInProgress(false);
            // Could add new mock sites here
          }, 500);
          return 100;
        }
        return newProgress;
      });
    }, 800);
  };

  const getSiteStatusBadge = (status) => {
    switch (status) {
      case "active":
        return <span className="px-2 py-1 bg-red-900 text-red-100 text-xs rounded-full">Active</span>;
      case "monitoring":
        return <span className="px-2 py-1 bg-yellow-800 text-yellow-100 text-xs rounded-full">Monitoring</span>;
      case "taken-down":
        return <span className="px-2 py-1 bg-green-900 text-green-100 text-xs rounded-full">Taken Down</span>;
      default:
        return <span className="px-2 py-1 bg-gray-800 text-gray-100 text-xs rounded-full">Unknown</span>;
    }
  };

  const getSimilarityBadge = (score) => {
    if (score >= 90) {
      return <span className="px-2 py-1 bg-red-900 text-red-100 text-xs rounded-full">{score}%</span>;
    } else if (score >= 75) {
      return <span className="px-2 py-1 bg-orange-800 text-orange-100 text-xs rounded-full">{score}%</span>;
    } else {
      return <span className="px-2 py-1 bg-yellow-800 text-yellow-100 text-xs rounded-full">{score}%</span>;
    }
  };

  return (
    <div>
      <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-8">
        <h2 className="text-3xl font-bold text-dark-cyan mb-4 md:mb-0">Phishing Detection for Tamm Abu Dhabi</h2>
        
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
              Scanning ({Math.round(scanProgress)}%)
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
      </div>

      {/* Results */}
      {loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorMessage message={error} />
      ) : phishingSites.length === 0 ? (
        <div className="text-center p-12 bg-gray-900 rounded-lg border border-gray-800">
          <svg xmlns="http://www.w3.org/2000/svg" className="h-16 w-16 mx-auto text-gray-600 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h3 className="text-xl font-medium text-gray-400 mb-2">No phishing sites found</h3>
          <p className="text-gray-500 mb-4">No phishing sites match your current filter criteria.</p>
          <button
            onClick={() => {
              setTimeRange("30");
              setSearchQuery("");
              setThresholdScore(60);
              setTargetFilter("all");
            }}
            className="px-4 py-2 bg-gray-800 text-gray-300 rounded hover:bg-gray-700 transition"
          >
            Reset Filters
          </button>
        </div>
      ) : (
        <div className="space-y-6">
          {phishingSites.map((site) => (
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
                      {getSimilarityBadge(site.similarityScore)}
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                      <h4 className="text-dark-cyan font-medium mb-2">Detection Details</h4>
                      <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                        <div>
                          <span className="text-gray-400">Detected:</span>
                          <div className="text-white">{new Date(site.detectedDate).toLocaleDateString()}</div>
                        </div>
                        <div>
                          <span className="text-gray-400">ML Confidence:</span>
                          <div className="text-white">{(site.mlConfidence * 100).toFixed(1)}%</div>
                        </div>
                        <div>
                          <span className="text-gray-400">Target Page:</span>
                          <div className="text-white capitalize">{site.targetPage.replace('-', ' ')}</div>
                        </div>
                        <div>
                          <span className="text-gray-400">Registration:</span>
                          <div className="text-white">{new Date(site.registrationDate).toLocaleDateString()}</div>
                        </div>
                      </div>
                    </div>
                    
                    <div>
                      <h4 className="text-dark-cyan font-medium mb-2">Technical Information</h4>
                      <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                        <div>
                          <span className="text-gray-400">IP Address:</span>
                          <div className="text-white">{site.ipAddress}</div>
                        </div>
                        <div>
                          <span className="text-gray-400">Country:</span>
                          <div className="text-white">{site.countryCode}</div>
                        </div>
                        <div className="col-span-2">
                          <span className="text-gray-400">Hosting:</span>
                          <div className="text-white">{site.hostingProvider}</div>
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
                            style={{ width: `${site.visualSimilarity}%` }}
                          ></div>
                        </div>
                        <div className="text-right text-xs text-gray-400 mt-1">{site.visualSimilarity}%</div>
                      </div>
                      <div>
                        <div className="text-gray-400 text-xs mb-1">Content Similarity</div>
                        <div className="w-full bg-gray-800 rounded-full h-4">
                          <div 
                            className="bg-dark-cyan h-4 rounded-full" 
                            style={{ width: `${site.contentSimilarity}%` }}
                          ></div>
                        </div>
                        <div className="text-right text-xs text-gray-400 mt-1">{site.contentSimilarity}%</div>
                      </div>
                      <div>
                        <div className="text-gray-400 text-xs mb-1">URL Similarity</div>
                        <div className="w-full bg-gray-800 rounded-full h-4">
                          <div 
                            className="bg-dark-cyan h-4 rounded-full" 
                            style={{ width: `${site.urlSimilarity}%` }}
                          ></div>
                        </div>
                        <div className="text-right text-xs text-gray-400 mt-1">{site.urlSimilarity}%</div>
                      </div>
                    </div>
                    
                    <div>
                      <div className="text-gray-400 text-xs mb-2">Detected Features</div>
                      <div className="flex flex-wrap gap-2">
                        {site.featuresDetected.map((feature, idx) => (
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
                      <div className="text-gray-500 text-xs">Screenshot preview</div>
                    </div>
                    <div className="flex space-x-2">
                      <button className="flex-1 bg-dark-cyan text-white py-1 px-2 rounded text-sm">View Full</button>
                      <button className="flex-1 bg-gray-700 text-white py-1 px-2 rounded text-sm">Compare</button>
                    </div>
                  </div>
                  
                  <div className="mt-4 space-y-2">
                    <button className="w-full bg-red-900 hover:bg-red-800 text-white py-2 px-4 rounded text-sm flex items-center justify-center">
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                      </svg>
                      Report Site
                    </button>
                    <button className="w-full bg-gray-800 hover:bg-gray-700 text-white py-2 px-4 rounded text-sm flex items-center justify-center">
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
        </div>
      )}
    </div>
  );
};

// Existing components (DashboardView, ThreatsView, ActorsView, IndicatorsView)

// Dashboard View
const DashboardView = () => {
  const [stats, setStats] = useState(null);
  const [recentThreats, setRecentThreats] = useState([]);
  const [severeThreats, setSevereThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setLoading(true);
        
        // Fetch statistics
        const statsResponse = await fetch("http://localhost:8000/api/stats");
        
        // Fetch recent threats
        const recentResponse = await fetch("http://localhost:8000/api/threats/recent?limit=5");
        
        // Fetch severe threats
        const severeResponse = await fetch("http://localhost:8000/api/threats/severe?limit=5");
        
        if (!statsResponse.ok || !recentResponse.ok || !severeResponse.ok) {
          throw new Error("Failed to fetch dashboard data");
        }
        
        const statsData = await statsResponse.json();
        const recentData = await recentResponse.json();
        const severeData = await severeResponse.json();
        
        setStats(statsData);
        setRecentThreats(recentData);
        setSevereThreats(severeData);
      } catch (err) {
        console.error("Error fetching dashboard data:", err);
        setError("Failed to load dashboard data. Please check if the API server is running.");
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
  }, []);

  if (loading) {
    return <LoadingSpinner />;
  }

  if (error) {
    return <ErrorMessage message={error} />;
  }

  return (
    <div>
      <h2 className="text-3xl font-bold mb-8 text-dark-cyan">Threat Intelligence Dashboard</h2>
      
      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-6 mb-8">
        <StatsCard 
          title="Total Threats" 
          value={stats?.total_articles || 0} 
          icon="📊" 
        />
        <StatsCard 
          title="Critical Threats" 
          value={stats?.severity_distribution?.Critical || 0} 
          icon="🚨" 
          color="bg-red-900"
        />
        <StatsCard 
          title="High Severity" 
          value={stats?.severity_distribution?.High || 0} 
          icon="⚠️" 
          color="bg-orange-800"
        />
        <StatsCard 
          title="Active Threat Actors" 
          value={Object.keys(stats?.category_distribution || {}).length} 
          icon="👤" 
        />
        <StatsCard 
          title="Phishing Sites" 
          value="5" 
          icon="🎣" 
          color="bg-purple-900"
        />
      </div>
      
      {/* Recent & Severe Threats and Phishing */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
        <div className="bg-gray-900 rounded-lg shadow-lg p-6 border border-dark-cyan">
          <h3 className="text-xl font-bold mb-4 text-dark-cyan flex items-center">
            <span className="mr-2">⏱️</span> Recent Threats
          </h3>
          <div className="space-y-4">
            {recentThreats.map((threat, index) => (
              <ThreatListItem key={index} threat={threat} />
            ))}
          </div>
        </div>
        
        <div className="bg-gray-900 rounded-lg shadow-lg p-6 border border-dark-cyan">
          <h3 className="text-xl font-bold mb-4 text-dark-cyan flex items-center">
            <span className="mr-2">🔥</span> Critical & High Severity
          </h3>
          <div className="space-y-4">
            {severeThreats.map((threat, index) => (
              <ThreatListItem key={index} threat={threat} />
            ))}
          </div>
        </div>
        
        <div className="bg-gray-900 rounded-lg shadow-lg p-6 border border-dark-cyan">
          <h3 className="text-xl font-bold mb-4 text-dark-cyan flex items-center">
            <span className="mr-2">🎣</span> Phishing Alerts
          </h3>
          <div className="space-y-4">
            <div className="border-b border-gray-800 pb-3 last:border-0 last:pb-0">
              <div className="flex justify-between items-start mb-1">
                <h4 className="font-medium text-white">tam-m-abudhabi.com</h4>
                <span className="text-xs px-2 py-1 rounded ml-2 bg-red-900 text-red-100">92%</span>
              </div>
              <p className="text-sm text-gray-400 mb-1 line-clamp-2">Impersonating main Tamm Abu Dhabi portal with login form</p>
              <div className="flex justify-between items-center text-xs">
                <span className="text-gray-500">Feb 15, 2025</span>
                <span className="bg-red-900 text-red-100 px-2 py-1 rounded">
                  Active
                </span>
              </div>
            </div>
            
            <div className="border-b border-gray-800 pb-3 last:border-0 last:pb-0">
              <div className="flex justify-between items-start mb-1">
                <h4 className="font-medium text-white">tamm.service-abudhabi.net</h4>
                <span className="text-xs px-2 py-1 rounded ml-2 bg-orange-800 text-orange-100">88%</span>
              </div>
              <p className="text-sm text-gray-400 mb-1 line-clamp-2">Fraudulent login page targeting credentials</p>
              <div className="flex justify-between items-center text-xs">
                <span className="text-gray-500">Feb 18, 2025</span>
                <span className="bg-red-900 text-red-100 px-2 py-1 rounded">
                  Active
                </span>
              </div>
            </div>
            
            <div className="border-b border-gray-800 pb-3 last:border-0 last:pb-0">
              <div className="flex justify-between items-start mb-1">
                <h4 className="font-medium text-white">tammabudhabiportal.com</h4>
                <span className="text-xs px-2 py-1 rounded ml-2 bg-orange-800 text-orange-100">85%</span>
              </div>
              <p className="text-sm text-gray-400 mb-1 line-clamp-2">Clone of main portal collecting email addresses</p>
              <div className="flex justify-between items-center text-xs">
                <span className="text-gray-500">Feb 22, 2025</span>
                <span className="bg-green-900 text-green-100 px-2 py-1 rounded">
                  Taken Down
                </span>
              </div>
            </div>
          </div>
          <div className="mt-4">
            <button onClick={() => setActiveTab("phishing")} className="text-dark-cyan text-sm hover:underline flex items-center">
              View all phishing sites
              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 ml-1" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M12.293 5.293a1 1 0 011.414 0l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-2.293-2.293a1 1 0 010-1.414z" clipRule="evenodd" />
              </svg>
            </button>
          </div>
        </div>
      </div>
      
      {/* Category Distribution */}
      {stats && (
        <div className="bg-gray-900 rounded-lg shadow-lg p-6 border border-dark-cyan mb-8">
          <h3 className="text-xl font-bold mb-4 text-dark-cyan">Threat Categories</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Object.entries(stats.category_distribution || {}).map(([category, count]) => (
              <div key={category} className="bg-gray-800 rounded-lg p-4 text-center">
                <div className="font-bold text-2xl">{count}</div>
                <div className="text-gray-400 text-sm truncate">{category}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// Reusable components
const LoadingSpinner = () => (
  <div className="flex justify-center items-center py-12">
    <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-dark-cyan"></div>
  </div>
);

const ErrorMessage = ({ message }) => (
  <div className="bg-red-900 text-white p-4 rounded-lg">
    <p className="font-bold">Error</p>
    <p>{message}</p>
  </div>
);

const StatsCard = ({ title, value, icon, color = "bg-gray-900" }) => (
  <div className={`${color} p-6 rounded-lg shadow-lg border border-dark-cyan`}>
    <div className="flex items-center justify-between">
      <div>
        <p className="text-gray-400 text-sm">{title}</p>
        <p className="text-2xl font-bold mt-1">{value}</p>
      </div>
      <div className="text-3xl">{icon}</div>
    </div>
  </div>
);

const ThreatListItem = ({ threat }) => {
  const getSeverityColor = (severity) => {
    switch (severity) {
      case "Critical": return "bg-red-900 text-red-100";
      case "High": return "bg-orange-800 text-orange-100";
      case "Medium": return "bg-yellow-800 text-yellow-100";
      default: return "bg-green-900 text-green-100";
    }
  };

  return (
    <div className="border-b border-gray-800 pb-3 last:border-0 last:pb-0">
      <div className="flex justify-between items-start mb-1">
        <h4 className="font-medium text-white">{threat.title}</h4>
        <span className={`text-xs px-2 py-1 rounded ml-2 ${getSeverityColor(threat.severity)}`}>
          {threat.severity}
        </span>
      </div>
      <p className="text-sm text-gray-400 mb-1 line-clamp-2">{threat.summary}</p>
      <div className="flex justify-between items-center text-xs">
        <span className="text-gray-500">{new Date(threat.published_date).toLocaleDateString()}</span>
        {threat.cve && (
          <span className="bg-blue-900 text-blue-100 px-2 py-1 rounded">
            {threat.cve}
          </span>
        )}
      </div>
    </div>
  );
};

// Remaining components like ThreatsView, ActorsView, IndicatorsView, ThreatCard
// would go here but are omitted for brevity

export default Dashboard;