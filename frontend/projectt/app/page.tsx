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
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
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
      </div>
      
      {/* Recent & Severe Threats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
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
            <span className="mr-2">🔥</span> Critical & High Severity Threats
          </h3>
          <div className="space-y-4">
            {severeThreats.map((threat, index) => (
              <ThreatListItem key={index} threat={threat} />
            ))}
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

// Threats View with Advanced Filtering
const ThreatsView = () => {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  
  // Filters
  const [filters, setFilters] = useState({
    category: "",
    severity: "",
    min_severity_score: "",
    days: "30",
    cve: "",
    search: ""
  });
  
  // Categories and severities for filter options
  const categories = [
    "Ransomware", "Phishing", "Malware", "Zero-Day Exploit", 
    "Vulnerability", "Supply Chain Attack", "Advanced Persistent Threat", 
    "Data Breach", "DDoS", "Nation-State Attack", "Other"
  ];
  
  const severities = ["Critical", "High", "Medium", "Low"];
  
  useEffect(() => {
    fetchThreats();
  }, [page, filters]);
  
  const fetchThreats = async () => {
    try {
      setLoading(true);
      
      // Build query parameters
      const params = new URLSearchParams({
        page: page.toString(),
        page_size: "10",
      });
      
      // Add filters to query
      Object.entries(filters).forEach(([key, value]) => {
        if (value) {
          params.append(key, value);
        }
      });
      
      const response = await fetch(`http://localhost:8000/api/threats?${params.toString()}`);
      
      if (!response.ok) {
        throw new Error(`HTTP Error: ${response.status}`);
      }
      
      const data = await response.json();
      setThreats(data.results);
      setTotalPages(Math.ceil(data.total / 10));
    } catch (err) {
      console.error("Error fetching threats:", err);
      setError("Failed to load threats. Please check if the API server is running.");
    } finally {
      setLoading(false);
    }
  };
  
  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters(prev => ({
      ...prev,
      [name]: value
    }));
    setPage(1); // Reset to first page when filters change
  };
  
  const clearFilters = () => {
    setFilters({
      category: "",
      severity: "",
      min_severity_score: "",
      days: "30",
      cve: "",
      search: ""
    });
    setPage(1);
  };

  return (
    <div>
      <h2 className="text-3xl font-bold mb-6 text-dark-cyan">Threat Intelligence</h2>
      
      {/* Filters */}
      <div className="bg-gray-900 rounded-lg p-6 mb-8 border border-dark-cyan">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-xl font-bold text-dark-cyan">Filters</h3>
          <button 
            onClick={clearFilters}
            className="px-4 py-2 bg-gray-800 text-gray-300 rounded hover:bg-gray-700 transition"
          >
            Clear Filters
          </button>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {/* Category filter */}
          <div>
            <label className="block text-gray-300 mb-2">Category</label>
            <select
              name="category"
              value={filters.category}
              onChange={handleFilterChange}
              className="w-full bg-gray-800 text-white p-2 rounded border border-gray-700"
            >
              <option value="">All Categories</option>
              {categories.map((category) => (
                <option key={category} value={category}>{category}</option>
              ))}
            </select>
          </div>
          
          {/* Severity filter */}
          <div>
            <label className="block text-gray-300 mb-2">Severity</label>
            <select
              name="severity"
              value={filters.severity}
              onChange={handleFilterChange}
              className="w-full bg-gray-800 text-white p-2 rounded border border-gray-700"
            >
              <option value="">All Severities</option>
              {severities.map((severity) => (
                <option key={severity} value={severity}>{severity}</option>
              ))}
            </select>
          </div>
          
          {/* Min severity score filter */}
          <div>
            <label className="block text-gray-300 mb-2">Min Severity Score (0-10)</label>
            <input
              type="number"
              name="min_severity_score"
              value={filters.min_severity_score}
              onChange={handleFilterChange}
              min="0"
              max="10"
              step="0.1"
              className="w-full bg-gray-800 text-white p-2 rounded border border-gray-700"
              placeholder="Minimum score"
            />
          </div>
          
          {/* Time range filter */}
          <div>
            <label className="block text-gray-300 mb-2">Time Range (days)</label>
            <select
              name="days"
              value={filters.days}
              onChange={handleFilterChange}
              className="w-full bg-gray-800 text-white p-2 rounded border border-gray-700"
            >
              <option value="1">Last 24 Hours</option>
              <option value="7">Last Week</option>
              <option value="30">Last Month</option>
              <option value="90">Last 3 Months</option>
              <option value="365">Last Year</option>
              <option value="">All Time</option>
            </select>
          </div>
          
          {/* CVE filter */}
          <div>
            <label className="block text-gray-300 mb-2">CVE ID</label>
            <input
              type="text"
              name="cve"
              value={filters.cve}
              onChange={handleFilterChange}
              className="w-full bg-gray-800 text-white p-2 rounded border border-gray-700"
              placeholder="e.g. CVE-2023-1234"
            />
          </div>
          
          {/* Search filter */}
          <div>
            <label className="block text-gray-300 mb-2">Search</label>
            <input
              type="text"
              name="search"
              value={filters.search}
              onChange={handleFilterChange}
              className="w-full bg-gray-800 text-white p-2 rounded border border-gray-700"
              placeholder="Search in title and content"
            />
          </div>
        </div>
      </div>
      
      {/* Results */}
      {loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorMessage message={error} />
      ) : (
        <>
          {threats.length === 0 ? (
            <div className="text-center text-gray-400 py-12">
              <p className="text-xl">No threats match your filter criteria</p>
              <button 
                onClick={clearFilters}
                className="mt-4 px-4 py-2 bg-dark-cyan text-white rounded"
              >
                Clear Filters
              </button>
            </div>
          ) : (
            <div className="space-y-6">
              {threats.map((threat, index) => (
                <ThreatCard key={index} threat={threat} />
              ))}
            </div>
          )}
          
          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex justify-center mt-8">
              <nav className="flex items-center space-x-2">
                <button
                  onClick={() => setPage(prev => Math.max(prev - 1, 1))}
                  disabled={page === 1}
                  className={`px-4 py-2 rounded ${
                    page === 1 
                      ? "bg-gray-800 text-gray-500 cursor-not-allowed" 
                      : "bg-gray-800 text-white hover:bg-gray-700"
                  }`}
                >
                  Previous
                </button>
                
                <span className="text-gray-400">
                  Page {page} of {totalPages}
                </span>
                
                <button
                  onClick={() => setPage(prev => Math.min(prev + 1, totalPages))}
                  disabled={page === totalPages}
                  className={`px-4 py-2 rounded ${
                    page === totalPages 
                      ? "bg-gray-800 text-gray-500 cursor-not-allowed" 
                      : "bg-gray-800 text-white hover:bg-gray-700"
                  }`}
                >
                  Next
                </button>
              </nav>
            </div>
          )}
        </>
      )}
    </div>
  );
};

// Threat Actors View
const ActorsView = () => {
  const [actors, setActors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchActors = async () => {
      try {
        setLoading(true);
        const response = await fetch("http://localhost:8000/api/actors");
        
        if (!response.ok) {
          throw new Error(`HTTP Error: ${response.status}`);
        }
        
        const data = await response.json();
        setActors(data);
      } catch (err) {
        console.error("Error fetching threat actors:", err);
        setError("Failed to load threat actors. Please check if the API server is running.");
      } finally {
        setLoading(false);
      }
    };

    fetchActors();
  }, []);

  if (loading) {
    return <LoadingSpinner />;
  }

  if (error) {
    return <ErrorMessage message={error} />;
  }

  return (
    <div>
      <h2 className="text-3xl font-bold mb-8 text-dark-cyan">Threat Actors</h2>
      
      {actors.length === 0 ? (
        <div className="text-center text-gray-400 py-12">
          <p className="text-xl">No threat actors information available</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {actors.map((actor, index) => (
            <div key={index} className="bg-gray-900 rounded-lg shadow-lg p-6 border border-dark-cyan">
              <h3 className="text-xl font-bold mb-2 text-dark-cyan">{actor.name}</h3>
              
              {actor.aliases && actor.aliases.length > 0 && (
                <div className="mb-2">
                  <span className="text-gray-400">Also known as: </span>
                  <span className="text-gray-300">{actor.aliases.join(", ")}</span>
                </div>
              )}
              
              <div className="mb-4 text-gray-300">{actor.description}</div>
              
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div>
                  <span className="text-gray-400">Motivation: </span>
                  <span className="text-gray-300">{actor.motivation || "Unknown"}</span>
                </div>
                <div>
                  <span className="text-gray-400">Sophistication: </span>
                  <span className="text-gray-300">{actor.sophistication || "Unknown"}</span>
                </div>
                <div>
                  <span className="text-gray-400">First seen: </span>
                  <span className="text-gray-300">
                    {actor.first_seen ? new Date(actor.first_seen).toLocaleDateString() : "Unknown"}
                  </span>
                </div>
                <div>
                  <span className="text-gray-400">Last seen: </span>
                  <span className="text-gray-300">
                    {actor.last_seen ? new Date(actor.last_seen).toLocaleDateString() : "Unknown"}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// Indicators of Compromise View
const IndicatorsView = () => {
  const [indicators, setIndicators] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedType, setSelectedType] = useState("");
  const [timeRange, setTimeRange] = useState(30);

  useEffect(() => {
    const fetchIndicators = async () => {
      try {
        setLoading(true);
        
        const params = new URLSearchParams({
          days: timeRange.toString()
        });
        
        if (selectedType) {
          params.append("type", selectedType);
        }
        
        const response = await fetch(`http://localhost:8000/api/indicators?${params.toString()}`);
        
        if (!response.ok) {
          throw new Error(`HTTP Error: ${response.status}`);
        }
        
        const data = await response.json();
        setIndicators(data);
      } catch (err) {
        console.error("Error fetching indicators:", err);
        setError("Failed to load indicators of compromise. Please check if the API server is running.");
      } finally {
        setLoading(false);
      }
    };

    fetchIndicators();
  }, [selectedType, timeRange]);

  const iocTypes = ["All Types", "ip", "domain", "url", "hash", "email"];

  if (loading) {
    return <LoadingSpinner />;
  }

  if (error) {
    return <ErrorMessage message={error} />;
  }

  return (
    <div>
      <h2 className="text-3xl font-bold mb-6 text-dark-cyan">Indicators of Compromise (IOCs)</h2>
      
      {/* Filters */}
      <div className="flex flex-col md:flex-row gap-4 mb-8">
        <div className="w-full md:w-1/3">
          <label className="block text-gray-300 mb-2">IOC Type</label>
          <select
            value={selectedType}
            onChange={(e) => {
              setSelectedType(e.target.value === "All Types" ? "" : e.target.value);
            }}
            className="w-full bg-gray-800 text-white p-2 rounded border border-gray-700"
          >
            {iocTypes.map((type) => (
              <option key={type} value={type === "All Types" ? "" : type}>
                {type}
              </option>
            ))}
          </select>
        </div>
        
        <div className="w-full md:w-1/3">
          <label className="block text-gray-300 mb-2">Time Range</label>
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(Number(e.target.value))}
            className="w-full bg-gray-800 text-white p-2 rounded border border-gray-700"
          >
            <option value={7}>Last Week</option>
            <option value={30}>Last Month</option>
            <option value={90}>Last 3 Months</option>
            <option value={365}>Last Year</option>
          </select>
        </div>
      </div>
      
      {indicators.length === 0 ? (
        <div className="text-center text-gray-400 py-12">
          <p className="text-xl">No indicators of compromise found</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full bg-gray-900 rounded-lg overflow-hidden">
            <thead className="bg-gray-800">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Value</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Confidence</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">First Seen</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {indicators.map((ioc, index) => (
                <tr key={index} className="hover:bg-gray-800">
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">{ioc.type}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-white font-mono">{ioc.value}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {ioc.confidence ? `${Math.round(ioc.confidence * 100)}%` : "N/A"}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {new Date(ioc.first_seen).toLocaleString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {new Date(ioc.last_seen).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

// Reusable Components
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

const ThreatCard = ({ threat }) => {
  const getSeverityColor = (severity) => {
    switch (severity) {
      case "Critical": return "bg-red-900 text-red-100";
      case "High": return "bg-orange-800 text-orange-100";
      case "Medium": return "bg-yellow-800 text-yellow-100";
      default: return "bg-green-900 text-green-100";
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-gray-900 rounded-lg p-6 border border-dark-cyan shadow-lg"
    >
      <div className="flex flex-col md:flex-row md:justify-between md:items-start gap-4">
        <div className="flex-1">
          <h3 className="text-xl font-bold mb-2 text-white">{threat.title}</h3>
          <p className="text-gray-300 mb-4">{threat.summary}</p>
          
          <div className="grid grid-cols-2 md:grid-cols-3 gap-x-4 gap-y-2 mb-4">
            <div>
              <span className="text-gray-400 text-xs">Category:</span>
              <div className="text-white">{threat.category}</div>
            </div>
            
            <div>
              <span className="text-gray-400 text-xs">Source:</span>
              <div className="text-white">{threat.source}</div>
            </div>
            
            <div>
              <span className="text-gray-400 text-xs">Published:</span>
              <div className="text-white">{new Date(threat.published_date).toLocaleDateString()}</div>
            </div>
            
            {threat.cve && (
              <div>
                <span className="text-gray-400 text-xs">CVE:</span>
                <div className="text-white">{threat.cve}</div>
              </div>
            )}
            
            {threat.cvss_score && (
              <div>
                <span className="text-gray-400 text-xs">CVSS Score:</span>
                <div className="text-white">{threat.cvss_score.toFixed(1)}</div>
              </div>
            )}
            
            {threat.mitre_tactics && threat.mitre_tactics.length > 0 && (
              <div className="col-span-2">
                <span className="text-gray-400 text-xs">MITRE Tactics:</span>
                <div className="text-white">{threat.mitre_tactics.join(", ")}</div>
              </div>
            )}
          </div>
        </div>
        
        <div className="flex flex-col items-center gap-3">
          <div className={`px-3 py-1 rounded text-center ${getSeverityColor(threat.severity)}`}>
            <div className="text-xs font-medium">Severity</div>
            <div className="font-bold">{threat.severity}</div>
          </div>
          
          {threat.severity_score !== undefined && (
            <div className="bg-gray-800 px-3 py-1 rounded text-center">
              <div className="text-xs font-medium text-gray-400">Score</div>
              <div className="font-bold text-white">{threat.severity_score.toFixed(1)}</div>
            </div>
          )}
          
          <a 
            href={threat.url} 
            target="_blank" 
            rel="noopener noreferrer"
            className="w-full bg-dark-cyan text-white py-2 px-4 rounded text-center hover:bg-opacity-90 transition-colors"
          >
            Read More
          </a>
        </div>
      </div>
    </motion.div>
  );
};

export default Dashboard;