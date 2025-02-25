'use client'
import { useEffect, useState } from "react";
import { motion } from "framer-motion";

export default function HomePage() {
  const [news, setNews] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [selectedCategory, setSelectedCategory] = useState("All");
  const [selectedSeverity, setSelectedSeverity] = useState("All");
  const [selectedCVE, setSelectedCVE] = useState("All");

  // Time filter state
  const [timeFilter, setTimeFilter] = useState("Latest"); // Default to latest
  
  // Date range filter state
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [useDateRange, setUseDateRange] = useState(false);

  const [filteredNews, setFilteredNews] = useState([]);

  useEffect(() => {
    const fetchNews = async () => {
      try {
        const response = await fetch("http://localhost:8000/news");
        if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
        const data = await response.json();
        console.log("Fetched data:", data);
        setNews(data);
        
        // Initialize filters with actual data
        setFilteredNews(data);
      } catch (err) {
        console.error("Error fetching news:", err);
        setError("Failed to load news.");
      } finally {
        setLoading(false);
      }
    };

    fetchNews();
  }, []);
  
  // Generate filter options whenever news data changes
  useEffect(() => {
    if (news && news.length > 0) {
      // Apply default filtering on initial load
      handleSearch();
    }
  }, [news, timeFilter, useDateRange]);

  // Extract unique categories from the news data
  const categories = ["All", ...new Set(news.filter(article => article.category).map(article => article.category))];
  
  // Set standard severity levels
  const severities = ["All", "Critical", "High", "Medium", "Low"];
  
  // Extract unique CVE IDs and filter out null values
  const cveOptions = ["All", ...new Set(news.filter(article => article.cve).map(article => article.cve))];

  const handleSearch = () => {
    console.log("🔍 Applying Filters...");
    
    if (!news || news.length === 0) {
      console.log("No news data available to filter");
      return;
    }

    // Create date ranges for predefined filters
    const now = new Date();
    const oneDayAgo = new Date(now);
    const oneWeekAgo = new Date(now);
    const oneMonthAgo = new Date(now);

    oneDayAgo.setDate(now.getDate() - 1);
    oneWeekAgo.setDate(now.getDate() - 7);
    oneMonthAgo.setMonth(now.getMonth() - 1);

    // Process custom date range
    const startDateObj = startDate ? new Date(startDate) : null;
    const endDateObj = endDate ? new Date(endDate) : null;
    
    // Set end date to end of day for inclusive filtering
    if (endDateObj) {
      endDateObj.setHours(23, 59, 59, 999);
    }

    console.log(`Active filters - Category: ${selectedCategory}, Severity: ${selectedSeverity}, CVE: ${selectedCVE}, Time: ${timeFilter}`);
    
    const filtered = news.filter((article) => {
      // Skip articles without required properties
      if (!article) return false;
      
      // 1. Category filtering
      const categoryMatch = 
        selectedCategory === "All" || 
        (article.category && article.category.toLowerCase() === selectedCategory.toLowerCase());
      
      // 2. Severity filtering
      const severityMatch = 
        selectedSeverity === "All" || 
        (article.severity && article.severity.toLowerCase() === selectedSeverity.toLowerCase());
      
      // 3. CVE filtering
      const cveMatch = 
        selectedCVE === "All" || 
        (article.cve && article.cve.toLowerCase() === selectedCVE.toLowerCase());
      
      // 4. Date filtering - handle missing dates
      let dateMatch = true; // Default to showing if date is missing
      
      if (article.published_date) {
        try {
          // Parse the ISO date string to Date object
          const articleDate = new Date(article.published_date);
          
          // Debug date parsing
          console.log(`Article: ${article.title}, Raw date: ${article.published_date}, Parsed date: ${articleDate.toISOString()}`);
          
          // Apply appropriate date filter
          if (timeFilter === "Custom" && useDateRange) {
            if (startDateObj && endDateObj) {
              // Both start and end dates provided
              dateMatch = articleDate >= startDateObj && articleDate <= endDateObj;
            } else if (startDateObj) {
              // Only start date provided
              dateMatch = articleDate >= startDateObj;
            } else if (endDateObj) {
              // Only end date provided
              dateMatch = articleDate <= endDateObj;
            }
            // If neither date is provided in custom mode, show all
          } else {
            // Predefined date filters
            if (timeFilter === "Latest") {
              dateMatch = articleDate >= oneDayAgo;
            } else if (timeFilter === "Last Week") {
              dateMatch = articleDate >= oneWeekAgo;
            } else if (timeFilter === "Last Month") {
              dateMatch = articleDate >= oneMonthAgo;
            }
          }
        } catch (error) {
          console.error("Error parsing date:", article.published_date, error);
          dateMatch = false;
        }
      }
      
      // Debug filter matches
      if (!categoryMatch || !severityMatch || !cveMatch || !dateMatch) {
        console.log(`Filtered out: ${article.title} - Category: ${categoryMatch}, Severity: ${severityMatch}, CVE: ${cveMatch}, Date: ${dateMatch}`);
      }
      
      return categoryMatch && severityMatch && cveMatch && dateMatch;
    });

    console.log(`✅ Filtering complete: ${filtered.length} articles match the criteria`);
    
    // Sort by date (newest first)
    const sortedResults = [...filtered].sort((a, b) => {
      // Handle missing dates
      if (!a.published_date) return 1;
      if (!b.published_date) return -1;
      
      try {
        const dateA = new Date(a.published_date);
        const dateB = new Date(b.published_date);
        
        // Check if dates are valid
        if (isNaN(dateA.getTime())) {
          console.error("Invalid date in sorting:", a.published_date);
          return 1;
        }
        if (isNaN(dateB.getTime())) {
          console.error("Invalid date in sorting:", b.published_date);
          return -1;
        }
        
        return dateB - dateA;
      } catch (error) {
        console.error("Error sorting dates:", error);
        return 0;
      }
    });
    
    setFilteredNews(sortedResults);
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 1 }}
      className="bg-black text-white min-h-screen flex flex-col items-center p-6"
    >
      <motion.header
        initial={{ y: -50, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.8 }}
        className="bg-dark-cyan w-full py-4 text-center text-xl font-bold shadow-md"
      >
        Cyber Threat Intelligence
      </motion.header>
      
      <motion.h1
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.7 }}
        className="text-3xl font-bold my-6 text-dark-cyan"
      >
        Daily Cyber Threat Reports
      </motion.h1>
      
      <div className="mb-6 flex gap-4 flex-wrap justify-center">
        <div>
          <label className="text-gray-300 mr-2">Filter by Category:</label>
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-gray-900 text-white p-2 border border-dark-cyan rounded"
          >
            {categories.map((category, index) => (
              <option key={index} value={category}>{category}</option>
            ))}
          </select>
        </div>
        
        <div>
          <label className="text-gray-300 mr-2">Filter by Severity:</label>
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-gray-900 text-white p-2 border border-dark-cyan rounded"
          >
            {severities.map((severity, index) => (
              <option key={index} value={severity}>{severity}</option>
            ))}
          </select>
        </div>
        
        <div>
          <label className="text-gray-300 mr-2">Filter by CVE:</label>
          <select
            value={selectedCVE}
            onChange={(e) => setSelectedCVE(e.target.value)}
            className="bg-gray-900 text-white p-2 border border-dark-cyan rounded"
          >
            {cveOptions.map((cve, index) => (
              <option key={index} value={cve}>{cve}</option>
            ))}
          </select>
        </div>

        {/* Time Filter */}
        <div>
          <label className="text-gray-300 mr-2">Sort By Date:</label>
          <select
            value={timeFilter}
            onChange={(e) => {
              setTimeFilter(e.target.value);
              setUseDateRange(e.target.value === "Custom");
            }}
            className="bg-gray-900 text-white p-2 border border-dark-cyan rounded"
          >
            <option value="Latest">Latest (Last 24 Hours)</option>
            <option value="Last Week">Last Week</option>
            <option value="Last Month">Last Month</option>
            <option value="Custom">Custom Date Range</option>
          </select>
        </div>
        
        {/* Custom Date Range Picker */}
        {useDateRange && (
          <div className="flex gap-2 items-center">
            <label className="text-gray-300">From:</label>
            <input
              type="date"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              className="bg-gray-900 text-white p-2 border border-dark-cyan rounded"
            />
            <label className="text-gray-300">To:</label>
            <input
              type="date"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              className="bg-gray-900 text-white p-2 border border-dark-cyan rounded"
            />
          </div>
        )}

        {/* Search Button */}
        <button 
          onClick={handleSearch} 
          className="bg-dark-cyan text-white px-4 py-2 rounded hover:bg-cyan-700"
        >
          🔍 Search
        </button>
      </div>
      
      {loading && <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-gray-400">Loading...</motion.div>}
      {error && <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-red-500">{error}</motion.div>}
      {!loading && !error && filteredNews.length === 0 && (
        <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-gray-400">
          No news available for the selected filters.
        </motion.p>
      )}

      {/* Render News */}
      <div className="w-full max-w-4xl">
        {filteredNews.map((article, index) => (
          <motion.div
            key={index}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5 }}
            className="bg-gray-800 p-4 rounded mb-4 shadow-lg border-l-4"
            style={{ 
              borderLeftColor: article.severity === 'Critical' ? '#ff4d4d' : 
                              article.severity === 'High' ? '#ff9933' : 
                              article.severity === 'Medium' ? '#ffcc00' : 
                              article.severity === 'Low' ? '#4CAF50' : '#666'
            }}
          >
            <div className="flex justify-between items-start mb-2">
              <h2 className="text-xl font-bold">{article.title}</h2>
              <div className="flex items-center">
                {article.published_date && (
                  <span className="text-gray-400 text-sm">
                    {(() => {
                      try {
                        // Handle ISO date format with explicit parsing
                        const date = new Date(article.published_date);
                        // Check if date is valid before formatting
                        if (isNaN(date.getTime())) {
                          console.error("Invalid date:", article.published_date);
                          return "Date unavailable";
                        }
                        // Format: Feb 25, 2025
                        return date.toLocaleDateString("en-US", {
                          year: "numeric",
                          month: "short",
                          day: "numeric"
                        });
                      } catch (e) {
                        console.error("Date parsing error:", e);
                        return "Date unavailable";
                      }
                    })()}
                  </span>
                )}
              </div>
            </div>
            
            <div className="flex flex-wrap gap-2 mb-2">
              {article.category && (
                <span className="bg-dark-cyan text-white text-xs px-2 py-1 rounded">
                  {article.category}
                </span>
              )}
              {article.severity && (
                <span className={`text-white text-xs px-2 py-1 rounded ${
                  article.severity === 'Critical' ? 'bg-red-600' : 
                  article.severity === 'High' ? 'bg-orange-600' : 
                  article.severity === 'Medium' ? 'bg-yellow-600' : 
                  article.severity === 'Low' ? 'bg-green-600' : 'bg-gray-600'
                }`}>
                  {article.severity}
                </span>
              )}
              {article.cve && (
                <span className="bg-purple-700 text-white text-xs px-2 py-1 rounded">
                  {article.cve}
                </span>
              )}
            </div>
            
            <p className="text-gray-300 mb-3">{article.summary}</p>
            
            <div className="flex justify-between items-center mt-2">
              <a 
                href={article.url} 
                target="_blank" 
                className="text-blue-400 hover:text-blue-300 underline"
              >
                Read more
              </a>
              {article.source && (
                <span className="text-gray-400 text-sm">
                  Source: {article.source}
                </span>
              )}
            </div>
          </motion.div>
        ))}
      </div>
    </motion.div>
  );
}