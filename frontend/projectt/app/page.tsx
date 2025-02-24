'use client'
import { useEffect, useState } from "react";
import { motion } from "framer-motion";

export default function HomePage() {
  const [news, setNews] = useState<Array<{ title: string; summary: string; url: string; source: string; category: string; severity: string; published_date: string; cve: string | null }>>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>("All");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("All");
  const [selectedCVE, setSelectedCVE] = useState<string>("All");

  // New state variables for date range filter
  const [startDate, setStartDate] = useState<string>("");
  const [endDate, setEndDate] = useState<string>("");

  useEffect(() => {
    const fetchNews = async () => {
      try {
        const response = await fetch("http://localhost:8000/news");
        if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
        const data = await response.json();
        setNews(data);
      } catch (err) {
        setError("Failed to load news.");
      } finally {
        setLoading(false);
      }
    };

    fetchNews();
  }, []);

  const categories = ["All", ...new Set(news.map(article => article.category))];
  const severities = ["All", "Critical", "High", "Medium", "Low"];
  const cveOptions = ["All", ...new Set(news.map(article => article.cve).filter(cve => cve))];

  // Filtering logic with date range
  const filteredNews = news.filter(article => {
    const isWithinCategory = selectedCategory === "All" || article.category === selectedCategory;
    const isWithinSeverity = selectedSeverity === "All" || article.severity === selectedSeverity;
    const isWithinCVE = selectedCVE === "All" || article.cve === selectedCVE;

    // Handle undefined or null published_date
    if (!article.published_date) return false;

    const publishedDate = new Date(article.published_date);
    if (isNaN(publishedDate.getTime())) return false; // Invalid date check

    const isWithinDateRange =
        (!startDate || new Date(startDate) <= publishedDate) &&
        (!endDate || new Date(endDate) >= publishedDate);

    return isWithinCategory && isWithinSeverity && isWithinCVE && isWithinDateRange;
});

  

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

        {/* Date range filter inputs */}
        <div>
          <label className="text-gray-300 mr-2">Start Date:</label>
          <input
            type="date"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
            className="bg-gray-900 text-white p-2 border border-dark-cyan rounded"
          />
        </div>

        <div>
          <label className="text-gray-300 mr-2">End Date:</label>
          <input
            type="date"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
            className="bg-gray-900 text-white p-2 border border-dark-cyan rounded"
          />
        </div>
      </div>
      
      {loading && <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-gray-400">Loading...</motion.div>}
      {error && <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-red-500">{error}</motion.div>}
      {!loading && !error && filteredNews.length === 0 && (
        <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-gray-400">
          No news available in this category, severity level, CVE, or date range.
        </motion.p>
      )}
    </motion.div>
  );
}
